// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/control"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
	"github.com/shoon/fv-ssh-unlock/internal/securefs"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

const controlAPISchemaVersion = 1
const daemonLogSchemaVersion = 1

// Default per-operation budgets. They are both the --probe-timeout /
// --unlock-timeout flag defaults and the fallback daemonAdapter applies when it
// is constructed without an explicit budget, so a configured flag is never
// silently replaced by a shorter internal constant.
const (
	defaultProbeTimeout  = 15 * time.Second
	defaultUnlockTimeout = 45 * time.Second
	// Control requests receive a little non-network overhead for JSON handling
	// and durable state writes beyond the SSH operation budgets themselves.
	controlOperationOverhead = 10 * time.Second
)

type daemonOptions struct {
	socket            string
	identityFiles     []string
	pollInterval      time.Duration
	bootInterval      time.Duration
	probeTimeout      time.Duration
	unlockTimeout     time.Duration
	concurrency       int
	discoverInterval  time.Duration
	discoverTimeout   time.Duration
	discoverInterface string
	scanCIDRs         []string
	scanInterval      time.Duration
	scanTimeout       time.Duration
	scanConcurrency   int
	logFormat         string
	logLevel          slog.Level
	once              bool
}

// trackedHandler closes admission before shutdown and joins every request that
// was already running. http.Server.Close cancels connections but does not wait
// for their handlers, which is not sufficient for transactional enrollment.
type trackedHandler struct {
	handler http.Handler

	mu        sync.Mutex
	accepting bool
	active    sync.WaitGroup
}

func newTrackedHandler(handler http.Handler) *trackedHandler {
	return &trackedHandler{handler: handler, accepting: true}
}

func (h *trackedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if !h.accepting {
		h.mu.Unlock()
		http.Error(w, "daemon is shutting down", http.StatusServiceUnavailable)
		return
	}
	h.active.Add(1)
	h.mu.Unlock()
	defer h.active.Done()
	h.handler.ServeHTTP(w, r)
}

func (h *trackedHandler) StopAccepting() {
	h.mu.Lock()
	h.accepting = false
	h.mu.Unlock()
}

func (h *trackedHandler) Wait() {
	h.active.Wait()
}

func newDaemonCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Continuously monitor configured Macs and safely recover locked devices",
		Long: `Run the persistent foreground controller. It polls every configured Mac
without a password, automatically unlocks only devices with auto_unlock enabled
and a definitive FileVault banner, and exposes a local Unix-socket API for the
TUI and health checks. Credential and host-key failures latch until an operator
intervenes; unreachable or indeterminate hosts never cause password release.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := daemonOptionsFromFlags(cmd)
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().String("socket", "", "Local Unix control socket (or FV_SSH_UNLOCK_SOCKET)")
	cmd.Flags().StringSlice("identity", nil, "Private key used to prove normal macOS is booted (repeatable)")
	cmd.Flags().Duration("interval", 30*time.Second, "Normal device polling interval")
	cmd.Flags().Duration("boot-interval", 5*time.Second, "Polling interval while a Mac is booting or its auto-recovery SSH endpoint is down")
	cmd.Flags().Duration("probe-timeout", defaultProbeTimeout, "Timeout for each password-free status probe")
	cmd.Flags().Duration("unlock-timeout", defaultUnlockTimeout, "Timeout for a single automatic unlock operation")
	cmd.Flags().Int("concurrency", 4, "Maximum concurrent device operations")
	cmd.Flags().Duration("discover-interval", 5*time.Minute, "Bonjour candidate discovery interval; 0 disables it")
	cmd.Flags().Duration("discover-timeout", 8*time.Second, "Bonjour browse duration per discovery interval")
	cmd.Flags().String("discover-interface", "", "Only browse Bonjour on this network interface")
	cmd.Flags().StringSlice("scan-cidr", nil, "Authorized IPv4 CIDR to scan periodically for SSH candidates (repeatable)")
	cmd.Flags().Duration("scan-interval", 15*time.Minute, "Active candidate scan interval")
	cmd.Flags().Duration("scan-timeout", defaultScanTimeout, "TCP and SSH timeout per scanned address")
	cmd.Flags().Int("scan-concurrency", 32, "Maximum simultaneous candidate scan probes")
	cmd.Flags().String("log-format", "text", "Log format: text or json (use json for SIEM ingestion)")
	cmd.Flags().String("log-level", "info", "Minimum log level: debug, info, warn, or error")
	cmd.Flags().Bool("json-log", false, "Emit structured JSON logs (shorthand for --log-format json)")
	cmd.Flags().Bool("once", false, "Poll configured devices once, print a JSON snapshot, and exit; this pass can submit credentials to devices with auto_unlock enabled")
	return cmd
}

func daemonOptionsFromFlags(cmd *cobra.Command) (daemonOptions, error) {
	getDuration := func(name string) time.Duration { value, _ := cmd.Flags().GetDuration(name); return value }
	getInt := func(name string) int { value, _ := cmd.Flags().GetInt(name); return value }
	opts := daemonOptions{}
	opts.socket, _ = cmd.Flags().GetString("socket")
	opts.identityFiles, _ = cmd.Flags().GetStringSlice("identity")
	opts.pollInterval = getDuration("interval")
	opts.bootInterval = getDuration("boot-interval")
	opts.probeTimeout = getDuration("probe-timeout")
	opts.unlockTimeout = getDuration("unlock-timeout")
	opts.concurrency = getInt("concurrency")
	opts.discoverInterval = getDuration("discover-interval")
	opts.discoverTimeout = getDuration("discover-timeout")
	opts.discoverInterface, _ = cmd.Flags().GetString("discover-interface")
	opts.scanCIDRs, _ = cmd.Flags().GetStringSlice("scan-cidr")
	opts.scanInterval = getDuration("scan-interval")
	opts.scanTimeout = getDuration("scan-timeout")
	opts.scanConcurrency = getInt("scan-concurrency")
	opts.logFormat, _ = cmd.Flags().GetString("log-format")
	jsonLogs, _ := cmd.Flags().GetBool("json-log")
	if jsonLogs {
		if cmd.Flags().Changed("log-format") && !strings.EqualFold(opts.logFormat, "json") {
			return opts, errors.New("--json-log cannot be combined with a non-JSON --log-format")
		}
		opts.logFormat = "json"
	}
	opts.logFormat = strings.ToLower(strings.TrimSpace(opts.logFormat))
	if opts.logFormat != "text" && opts.logFormat != "json" {
		return opts, errors.New("--log-format must be text or json")
	}
	logLevel, _ := cmd.Flags().GetString("log-level")
	var err error
	opts.logLevel, err = parseDaemonLogLevel(logLevel)
	if err != nil {
		return opts, err
	}
	opts.once, _ = cmd.Flags().GetBool("once")
	if opts.socket == "" {
		opts.socket, err = defaultControlSocket()
		if err != nil {
			return opts, err
		}
	}
	if !filepath.IsAbs(opts.socket) {
		return opts, errors.New("--socket must be an absolute path")
	}
	if opts.pollInterval <= 0 || opts.bootInterval <= 0 || opts.probeTimeout <= 0 || opts.unlockTimeout <= 0 {
		return opts, errors.New("monitor intervals and operation timeouts must be greater than zero")
	}
	if opts.concurrency < 1 || opts.concurrency > 256 {
		return opts, errors.New("--concurrency must be between 1 and 256")
	}
	if opts.discoverInterval < 0 || (opts.discoverInterval > 0 && opts.discoverTimeout <= 0) {
		return opts, errors.New("discovery intervals must not be negative and its timeout must be positive when enabled")
	}
	if opts.scanInterval <= 0 || opts.scanTimeout <= 0 {
		return opts, errors.New("scan interval and timeout must be greater than zero")
	}
	if opts.scanConcurrency < 1 || opts.scanConcurrency > maxScanConcurrency {
		return opts, fmt.Errorf("--scan-concurrency must be between 1 and %d", maxScanConcurrency)
	}
	return opts, nil
}

func parseDaemonLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New("--log-level must be debug, info, warn, or error")
	}
}

func runDaemon(ctx context.Context, output io.Writer, opts daemonOptions) (returnErr error) {
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	logger := newDaemonLogger(output, opts)
	if !opts.once {
		defer func() {
			if returnErr != nil {
				logger.Error("daemon exited with an error", "event", "daemon.failed", "error", terminalSafeError(returnErr))
			}
		}()
	}
	dataDir, err := appDataDir()
	if err != nil {
		return err
	}
	if err := securefs.EnsurePrivateDirectory(dataDir, "data"); err != nil {
		return err
	}
	daemonLock, err := acquireDaemonLock(filepath.Join(dataDir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer releaseDaemonLock(daemonLock)
	store, err := configStore()
	if err != nil {
		return err
	}
	configured, err := store.Load()
	if err != nil {
		return err
	}
	for _, device := range configured {
		if err := assessDaemonDevice(device); err != nil {
			return fmt.Errorf("automatic unlock preflight for %q: %w", device.Name, err)
		}
	}
	// The shared RealSSHClient must be permissive enough for the longer
	// operation. Each monitor call has its own context deadline, so using the
	// maximum here cannot lengthen a probe but using the minimum would silently
	// cap an unlock at the probe budget (15s with the defaults).
	dialTimeout := max(opts.probeTimeout, opts.unlockTimeout)
	client, err := newSSHClient(false, false, false, opts.identityFiles, dialTimeout)
	if err != nil {
		return err
	}
	adapter := newDaemonAdapter(client, configured, opts.probeTimeout, opts.unlockTimeout)
	monitorOpts := monitor.DefaultOptions()
	monitorOpts.PollInterval = opts.pollInterval
	monitorOpts.BootPollInterval = opts.bootInterval
	monitorOpts.ProbeTimeout = opts.probeTimeout
	monitorOpts.UnlockTimeout = opts.unlockTimeout
	monitorOpts.Concurrency = opts.concurrency
	engine, err := monitor.New(toMonitorDevices(configured), adapter, adapter, &monitor.FileStore{Path: filepath.Join(dataDir, "monitor-state.json")}, monitorOpts)
	if err != nil {
		return err
	}
	inbox, err := candidates.Open(filepath.Join(dataDir, "candidates.json"), candidates.Options{})
	if err != nil {
		return err
	}
	if err := refreshConfiguredCandidates(inbox); err != nil {
		return err
	}

	if opts.once {
		runErrors := engine.RunOnce(runCtx)
		if err := writeJSON(output, struct {
			SchemaVersion int `json:"schema_version"`
			monitor.Snapshot
		}{SchemaVersion: controlAPISchemaVersion, Snapshot: engine.Snapshot()}); err != nil {
			return err
		}
		if len(runErrors) > 0 {
			return fmt.Errorf("one-pass monitor completed with errors for %d device(s)", len(runErrors))
		}
		return nil
	}

	listener, err := control.Listen(opts.socket)
	if err != nil {
		return fmt.Errorf("open control socket: %w", err)
	}
	defer func() { _ = listener.Close() }()
	api := &daemonAPI{
		startedAt: time.Now().UTC(), engine: engine, inbox: inbox, store: store, adapter: adapter,
		identities: opts.identityFiles, probeTimeout: opts.probeTimeout, unlockTimeout: opts.unlockTimeout,
		logger: logger,
	}
	eventBuffer := max(256, min(16384, len(configured)*8))
	events, stopEvents := engine.Subscribe(eventBuffer)
	defer stopEvents()
	var eventLogWG sync.WaitGroup
	eventLogWG.Add(1)
	go func() {
		defer eventLogWG.Done()
		logMonitorEvents(logger, events)
	}()
	handlers := newTrackedHandler(api.routes())
	server := &http.Server{
		Handler:           handlers,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      controlPollTimeout(opts.probeTimeout, opts.unlockTimeout),
		IdleTimeout:       30 * time.Second,
	}
	errCh := make(chan error, 3)
	go func() { errCh <- engine.Run(runCtx) }()
	go func() {
		runCandidateDiscovery(runCtx, inbox, opts, logger)
		errCh <- nil
	}()
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	logger.Info("daemon started", "event", "daemon.started", "devices", len(configured), "socket", terminalSafeInline(opts.socket), "data_dir", terminalSafeInline(dataDir))

	completed := 0
	var componentErr error
	select {
	case <-ctx.Done():
	case runErr := <-errCh:
		completed = 1
		if runErr != nil {
			componentErr = runErr
		} else if ctx.Err() == nil {
			componentErr = errors.New("daemon component stopped unexpectedly")
		}
	}

	// Cancel monitor/discovery work, stop accepting API mutations, and then
	// join every component before returning. Returning immediately on SIGTERM
	// could terminate the process while an unlock outcome was still being
	// written to durable episode state.
	stopRun()
	handlers.StopAccepting()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		_ = server.Close()
	}
	// Shutdown waits for ordinary HTTP handlers, but Close does not. Track and
	// join them explicitly so a timed-out shutdown cannot return midway through
	// enrollment or rollback.
	handlers.Wait()
	componentCtx, cancelComponents := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelComponents()
	for completed < cap(errCh) {
		select {
		case runErr := <-errCh:
			completed++
			if runErr != nil && componentErr == nil {
				componentErr = runErr
			}
		case <-componentCtx.Done():
			_ = server.Close()
			timeoutErr := fmt.Errorf("daemon shutdown timed out before all components stopped: %w", componentCtx.Err())
			if componentErr != nil {
				return errors.Join(componentErr, timeoutErr)
			}
			return timeoutErr
		}
	}
	// The engine is now joined, so no new monitor events can be produced.
	// Close the best-effort subscription and drain every event already queued
	// before recording the daemon stop.
	stopEvents()
	eventLogWG.Wait()
	logger.Info("daemon stopped", "event", "daemon.stopped")
	if componentErr != nil {
		return componentErr
	}
	return shutdownErr
}

func newDaemonLogger(output io.Writer, opts daemonOptions) *slog.Logger {
	loggerOptions := &slog.HandlerOptions{
		Level: opts.logLevel,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Value.Kind() {
			case slog.KindString:
				attr.Value = slog.StringValue(terminalSafeInline(attr.Value.String()))
			case slog.KindAny:
				if err, ok := attr.Value.Any().(error); ok {
					attr.Value = slog.StringValue(terminalSafeError(err))
				}
			}
			return attr
		},
	}
	var handler slog.Handler = slog.NewTextHandler(output, loggerOptions)
	if opts.logFormat == "json" {
		handler = slog.NewJSONHandler(output, loggerOptions)
	}
	return slog.New(handler).With("schema_version", daemonLogSchemaVersion, "component", "daemon", "run_id", newDaemonRunID())
}

func newDaemonRunID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		binary.BigEndian.PutUint64(value[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(value[8:], uint64(os.Getpid())) // #nosec G115 -- PIDs are non-negative
	}
	return hex.EncodeToString(value[:])
}

func acquireDaemonLock(path string) (*securefs.FileLock, error) {
	lock, err := securefs.TryAcquireLock(path, "daemon")
	if err != nil {
		if errors.Is(err, securefs.ErrLockUnavailable) {
			return nil, fmt.Errorf("another daemon is already using this data directory: %w", err)
		}
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	return lock, nil
}

func releaseDaemonLock(lock *securefs.FileLock) {
	if lock == nil {
		return
	}
	lock.Release()
}

func logMonitorEvents(logger *slog.Logger, events <-chan monitor.Event) {
	for event := range events {
		attrs := []any{
			"event", monitorLogEventName(event),
			"event_time", event.Time,
			"sequence", event.Sequence,
			"device", terminalSafeInline(event.Device),
			"state", terminalSafeInline(string(event.State)),
			"observation", terminalSafeInline(string(event.Observation)),
			"lock_episode", event.LockEpisode,
			"auto_unlock", event.AutoUnlock,
			"endpoint_down", event.EndpointDown,
			"latched", event.Latched,
		}
		if event.FailureKind != "" {
			attrs = append(attrs, "failure_kind", terminalSafeInline(string(event.FailureKind)))
		}
		if event.Message != "" {
			attrs = append(attrs, "detail", terminalSafeInline(event.Message))
		}
		switch event.Type {
		case monitor.EventProbe:
			logger.Debug("device probe completed", attrs...)
		case monitor.EventObservationChanged:
			if event.State == event.Observation {
				logger.Info(monitorStateLogMessage(event.Observation), attrs...)
			} else {
				logger.Info("password-free observation changed while safety latch remains active", attrs...)
			}
		case monitor.EventLatchChanged:
			logger.Warn("device safety latch changed", attrs...)
		case monitor.EventUnlockResult:
			if event.State == monitor.StateCredentialFailed || event.State == monitor.StateError {
				logger.Warn("automatic unlock completed with an error", attrs...)
			} else {
				logger.Info("automatic unlock result recorded", attrs...)
			}
		case monitor.EventStateChanged:
			if event.State == event.Observation {
				// The semantic observation record already carries this ordinary
				// state transition at info level; retain the raw state event for
				// detailed debugging without duplicating the default stream.
				logger.Debug("device state changed", attrs...)
			} else {
				logger.Info(monitorStateLogMessage(event.State), attrs...)
			}
		case monitor.EventUnlockStarted:
			logger.Info("automatic unlock started", attrs...)
		case monitor.EventDeviceAdded:
			logger.Info("managed device added", attrs...)
		}
	}
}

func monitorLogEventName(event monitor.Event) string {
	switch event.Type {
	case monitor.EventProbe:
		return "device.probe"
	case monitor.EventObservationChanged:
		if event.State == event.Observation {
			switch event.Observation {
			case monitor.StateBooted:
				return "device.booted"
			case monitor.StateLocked:
				return "device.filevault_locked"
			case monitor.StateUnreachable:
				return "device.unreachable"
			default:
				return "device.indeterminate"
			}
		}
		switch event.Observation {
		case monitor.StateBooted:
			return "device.observation_booted"
		case monitor.StateLocked:
			return "device.observation_filevault_locked"
		case monitor.StateUnreachable:
			return "device.observation_unreachable"
		default:
			return "device.observation_indeterminate"
		}
	case monitor.EventUnlockStarted:
		return "device.unlock_started"
	case monitor.EventUnlockResult:
		return "device.unlock_result"
	case monitor.EventLatchChanged:
		return "device.latch_changed"
	case monitor.EventDeviceAdded:
		return "device.added"
	case monitor.EventStateChanged:
		switch event.State {
		case monitor.StateBooted:
			return "device.booted"
		case monitor.StateLocked:
			return "device.filevault_locked"
		case monitor.StateUnreachable:
			return "device.unreachable"
		case monitor.StateIndeterminate:
			return "device.indeterminate"
		case monitor.StateUnlocking:
			return "device.unlocking"
		case monitor.StateBooting:
			return "device.booting"
		case monitor.StateCredentialFailed:
			return "device.credential_failed"
		default:
			return "device.error"
		}
	default:
		return "device.event"
	}
}

func monitorStateLogMessage(state monitor.State) string {
	switch state {
	case monitor.StateBooted:
		return "device verified booted"
	case monitor.StateLocked:
		return "FileVault pre-boot detected"
	case monitor.StateUnreachable:
		return "device became unreachable"
	case monitor.StateIndeterminate:
		return "device state is indeterminate"
	case monitor.StateUnlocking:
		return "device is unlocking"
	case monitor.StateBooting:
		return "device is booting"
	case monitor.StateCredentialFailed:
		return "device credential failed"
	default:
		return "device entered an error state"
	}
}

func assessDaemonDevice(device config.Device) error {
	if !device.AutoUnlock {
		return nil
	}
	source := device.CredentialSource
	if source == "" {
		if device.Cred == "" {
			source = credentials.ProviderRuntime
		} else {
			source = credentials.ProviderKeyring
		}
	}
	if source == credentials.ProviderRuntime {
		return errors.New("runtime/environment credentials are not accepted for unattended automatic unlock; use a verified keyring or memory-backed service secret")
	}
	store, err := credentialStoreForDevice(device, false)
	if err != nil {
		return err
	}
	providerStore, ok := store.(*providerStore)
	if !ok {
		return errors.New("credential provider cannot be assessed")
	}
	assessment := providerStore.provider.Assess(providerStore.reference)
	if !assessment.Available || !assessment.Secure {
		return fmt.Errorf("secure credential is unavailable: %s", assessment.Details)
	}
	return nil
}

type daemonAdapter struct {
	client       daemonSSHClient
	mu           sync.RWMutex
	devices      map[string]config.Device
	endpointDown map[string]bool
	reachability func(context.Context, string) error
	// probeTimeout and unlockTimeout are the operator-configured per-operation
	// budgets. They are carried here rather than re-derived so --probe-timeout
	// and --unlock-timeout are the values actually applied to each SSH call.
	probeTimeout  time.Duration
	unlockTimeout time.Duration
}

type daemonSSHClient interface {
	fvcore.SSHClient
	fvcore.StatusChecker
}

func newDaemonAdapter(client daemonSSHClient, devices []config.Device, probeTimeout, unlockTimeout time.Duration) *daemonAdapter {
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	if unlockTimeout <= 0 {
		unlockTimeout = defaultUnlockTimeout
	}
	adapter := &daemonAdapter{
		client:        client,
		devices:       make(map[string]config.Device, len(devices)),
		endpointDown:  make(map[string]bool),
		probeTimeout:  probeTimeout,
		unlockTimeout: unlockTimeout,
	}
	if _, realClient := client.(*fvcore.RealSSHClient); realClient {
		adapter.reachability = probeTCPEndpoint
	}
	for _, device := range devices {
		adapter.devices[device.Name] = device
	}
	return adapter
}

func (a *daemonAdapter) addDevice(device config.Device) {
	a.mu.Lock()
	a.devices[device.Name] = device
	a.mu.Unlock()
}

func (a *daemonAdapter) removeDevice(name string) {
	a.mu.Lock()
	delete(a.devices, name)
	delete(a.endpointDown, name)
	a.mu.Unlock()
}

func (a *daemonAdapter) configured(name string) (config.Device, error) {
	a.mu.RLock()
	device, ok := a.devices[name]
	a.mu.RUnlock()
	if !ok {
		return config.Device{}, fmt.Errorf("configured device not found: %s", name)
	}
	return device, nil
}

func (a *daemonAdapter) Probe(ctx context.Context, target monitor.Device) (monitor.ProbeResult, error) {
	device, err := a.configured(target.Name)
	if err != nil {
		return monitor.ProbeResult{}, monitor.NewFailure(monitor.FailureTransient, err)
	}
	if a.knownEndpointDown(target.Name) && a.reachability != nil {
		if reachErr := a.reachability(ctx, deviceEndpoint(device)); reachErr != nil {
			return monitor.ProbeResult{State: monitor.StateUnreachable, Detail: "SSH TCP endpoint is down", EndpointDown: true}, monitor.NewFailure(monitor.FailureUnreachable, reachErr)
		}
		a.setEndpointDown(target.Name, false)
	}
	state, _, err := fvcore.CheckStatus(ctx, a.client, deviceEndpoint(device), device.User, a.probeTimeout)
	switch {
	case state == fvcore.StatusLocked:
		a.setEndpointDown(target.Name, false)
		return monitor.ProbeResult{State: monitor.StateLocked, Detail: "FileVault pre-boot banner detected"}, nil
	case state == fvcore.StatusUnlockedRecently:
		a.setEndpointDown(target.Name, false)
		return monitor.ProbeResult{State: monitor.StateBooted, Detail: "normal macOS SSH accepted a public key"}, nil
	case errors.Is(err, fvcore.ErrIndeterminate):
		a.setEndpointDown(target.Name, false)
		return monitor.ProbeResult{State: monitor.StateIndeterminate, Detail: "SSH reachable; state cannot be proved without a public key"}, nil
	case errors.Is(err, fvcore.ErrHostKeyMismatch):
		a.setEndpointDown(target.Name, false)
		return monitor.ProbeResult{}, monitor.NewFailure(monitor.FailureHostKey, err)
	case err != nil:
		endpointDown := a.classifyEndpointDown(ctx, deviceEndpoint(device))
		a.setEndpointDown(target.Name, endpointDown)
		detail := "SSH probe failed"
		if endpointDown {
			detail = "SSH TCP endpoint is down"
		}
		return monitor.ProbeResult{State: monitor.StateUnreachable, Detail: detail, EndpointDown: endpointDown}, monitor.NewFailure(monitor.FailureUnreachable, err)
	default:
		a.setEndpointDown(target.Name, false)
		return monitor.ProbeResult{State: monitor.StateIndeterminate, Detail: "no conclusive password-free evidence"}, nil
	}
}

func (a *daemonAdapter) knownEndpointDown(name string) bool {
	a.mu.RLock()
	down := a.endpointDown[name]
	a.mu.RUnlock()
	return down
}

func (a *daemonAdapter) setEndpointDown(name string, down bool) {
	a.mu.Lock()
	if down {
		if a.endpointDown == nil {
			a.endpointDown = make(map[string]bool)
		}
		a.endpointDown[name] = true
	} else {
		delete(a.endpointDown, name)
	}
	a.mu.Unlock()
}

func (a *daemonAdapter) classifyEndpointDown(ctx context.Context, endpoint string) bool {
	if a.reachability == nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	return a.reachability(checkCtx, endpoint) != nil
}

func probeTCPEndpoint(ctx context.Context, endpoint string) error {
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(checkCtx, "tcp", endpoint)
	if err != nil {
		return err
	}
	_ = connection.Close()
	return nil
}

func (a *daemonAdapter) Unlock(ctx context.Context, target monitor.Device) (monitor.UnlockResult, error) {
	device, err := a.configured(target.Name)
	if err != nil {
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureTransient, err)
	}
	store, err := credentialStoreForDevice(device, false)
	if err != nil {
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureCredential, err)
	}
	password, err := store.Get(deviceCredentialID(device))
	if err != nil || password == "" {
		if err == nil {
			err = errors.New("credential is empty")
		}
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureCredential, err)
	}
	successMessage := device.SuccessMessage
	if successMessage == "" {
		successMessage = defaultSuccessMessage
	}
	result := fvcore.Unlock(ctx, a.client, &staticStore{pw: password}, deviceEndpoint(device), device.User, deviceCredentialID(device), successMessage, a.unlockTimeout)
	switch {
	case result.Status == fvcore.StatusUnlocked:
		return monitor.UnlockResult{Accepted: true, Detail: "FileVault accepted the credential"}, nil
	case result.Status == fvcore.StatusUnlockedRecently:
		return monitor.UnlockResult{Accepted: true, Detail: "normal macOS was already available"}, nil
	case errors.Is(result.Error, fvcore.ErrUnlockOutcomeUnknown):
		return monitor.UnlockResult{Accepted: true, Detail: "credential submitted; acknowledgement unavailable; verifying without resubmission"}, result.Error
	case result.Status == fvcore.StatusLocked || errors.Is(result.Error, fvcore.ErrAuthFailed):
		// Wrap rather than replace: the caller classifies this as a credential
		// failure either way, but an operator clearing the latch needs to see
		// why the credential was rejected.
		rejected := errors.New("FileVault rejected the configured credential")
		if result.Error != nil {
			rejected = fmt.Errorf("FileVault rejected the configured credential: %w", result.Error)
		}
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureCredential, rejected)
	case errors.Is(result.Error, fvcore.ErrHostKeyMismatch):
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureHostKey, result.Error)
	case result.Error != nil:
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureUnreachable, result.Error)
	default:
		return monitor.UnlockResult{}, monitor.NewFailure(monitor.FailureTransient, errors.New("unlock result was inconclusive before credential submission"))
	}
}

// durationSum adds positive duration budgets without allowing overflow to wrap
// a control timeout negative and cancel a request immediately.
func durationSum(values ...time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	var total time.Duration
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if value > maximum-total {
			return maximum
		}
		total += value
	}
	return total
}

func controlEnrollmentTimeout(probeTimeout time.Duration) time.Duration {
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	return durationSum(probeTimeout, controlOperationOverhead)
}

func controlPollTimeout(probeTimeout, unlockTimeout time.Duration) time.Duration {
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	if unlockTimeout <= 0 {
		unlockTimeout = defaultUnlockTimeout
	}
	return durationSum(probeTimeout, unlockTimeout, controlOperationOverhead)
}

func toMonitorDevice(device config.Device) monitor.Device {
	reference := deviceCredentialID(device)
	if device.CredentialSource == credentials.ProviderFile {
		reference = device.CredentialRef
	}
	return monitor.Device{Name: device.Name, Host: device.Host, User: device.User, Port: device.Port, CredentialRef: reference, AutoUnlock: device.AutoUnlock}
}

func toMonitorDevices(devices []config.Device) []monitor.Device {
	targets := make([]monitor.Device, 0, len(devices))
	for _, device := range devices {
		targets = append(targets, toMonitorDevice(device))
	}
	return targets
}

func refreshConfiguredCandidates(inbox *candidates.Inbox) error {
	pinned, err := loadPinnedTargetNames()
	if err != nil {
		return fmt.Errorf("load configured host fingerprints: %w", err)
	}
	configured := make([]candidates.ConfiguredFingerprint, 0, len(pinned))
	for fingerprint, names := range pinned {
		configured = append(configured, candidates.ConfiguredFingerprint{Fingerprint: fingerprint, DeviceNames: names})
	}
	return inbox.ReplaceConfiguredFingerprints(configured)
}

func runCandidateDiscovery(ctx context.Context, inbox *candidates.Inbox, opts daemonOptions, logger *slog.Logger) {
	var wg sync.WaitGroup
	if opts.discoverInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPeriodic(ctx, opts.discoverInterval, func(roundCtx context.Context) {
				results, err := discoverCandidates(roundCtx, inbox, opts)
				if err != nil && roundCtx.Err() == nil {
					logger.Warn("Bonjour candidate discovery failed", "event", "discovery.failed", "source", "bonjour", "error", terminalSafeError(err))
					return
				}
				logCandidateResults(logger, "bonjour", results)
				logger.Debug("candidate discovery round completed", "event", "discovery.round", "source", "bonjour", "observations", len(results))
			})
		}()
	}
	if len(opts.scanCIDRs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPeriodic(ctx, opts.scanInterval, func(roundCtx context.Context) {
				results, err := scanCandidates(roundCtx, inbox, opts)
				if err != nil && roundCtx.Err() == nil {
					logger.Warn("active candidate scan failed", "event", "discovery.failed", "source", "active-scan", "error", terminalSafeError(err))
					return
				}
				logCandidateResults(logger, "active-scan", results)
				logger.Debug("candidate discovery round completed", "event", "discovery.round", "source", "active-scan", "observations", len(results))
			})
		}()
	}
	// Expiration is independent of whether discovery is enabled or a round
	// finds anything, so stale candidates cannot live forever on a quiet LAN.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runPeriodic(ctx, time.Hour, func(roundCtx context.Context) {
			if roundCtx.Err() != nil {
				return
			}
			expired, err := inbox.Expire()
			if err != nil {
				logger.Warn("candidate expiration failed", "event", "candidate.expiration_failed", "error", terminalSafeError(err))
				return
			}
			for _, id := range expired {
				logger.Info("candidate expired", "event", "candidate.expired", "candidate_id", terminalSafeInline(id))
			}
		})
	}()
	<-ctx.Done()
	wg.Wait()
}

func logCandidateResults(logger *slog.Logger, source string, results []candidates.IngestResult) {
	for _, result := range results {
		if result.DroppedObservation != nil {
			attrs := []any{
				"event", "candidate.dropped",
				"source", terminalSafeInline(source),
				"reason", "candidate inbox is full of operator-reviewed entries",
			}
			if observation := result.DroppedObservation; observation != nil {
				attrs = append(attrs, "observed_at", terminalSafeInline(observation.ObservedAt.UTC().Format(time.RFC3339Nano)))
				if observation.Address != "" {
					attrs = append(attrs, "endpoint", terminalSafeInline(net.JoinHostPort(observation.Address, fmt.Sprint(observation.Port))))
				}
				if observation.Hostname != "" {
					attrs = append(attrs, "hostname", terminalSafeInline(observation.Hostname))
				}
				if observation.Fingerprint != "" {
					attrs = append(attrs, "fingerprint", terminalSafeInline(observation.Fingerprint))
				}
			}
			logger.Warn("SSH host candidate dropped at inbox capacity", attrs...)
			continue
		}
		candidate := result.Candidate
		for _, evictedID := range result.EvictedIDs {
			logger.Info("unreviewed SSH host candidate evicted at inbox capacity",
				"event", "candidate.evicted",
				"candidate_id", terminalSafeInline(evictedID),
				"replacement_candidate_id", terminalSafeInline(candidate.ID),
				"source", terminalSafeInline(source),
				"observed_at", terminalSafeInline(candidate.LastSeen.UTC().Format(time.RFC3339Nano)),
			)
		}
		attrs := []any{
			"candidate_id", terminalSafeInline(candidate.ID),
			"candidate_state", terminalSafeInline(string(candidate.State)),
			"source", terminalSafeInline(source),
			"observed_at", terminalSafeInline(candidate.LastSeen.UTC().Format(time.RFC3339Nano)),
		}
		if len(candidate.Endpoints) > 0 {
			attrs = append(attrs, "endpoint", terminalSafeInline(net.JoinHostPort(candidate.Endpoints[0].Address, fmt.Sprint(candidate.Endpoints[0].Port))))
		}
		if len(candidate.Hostnames) > 0 {
			attrs = append(attrs, "hostname", terminalSafeInline(candidate.Hostnames[0]))
		}
		if result.Created {
			logger.Info("SSH host candidate detected", append([]any{"event", "candidate.discovered"}, attrs...)...)
		} else {
			logger.Debug("SSH host candidate observed", append([]any{"event", "candidate.updated"}, attrs...)...)
		}
	}
}

func runPeriodic(ctx context.Context, interval time.Duration, operation func(context.Context)) {
	operation(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operation(ctx)
		}
	}
}

func discoverCandidates(ctx context.Context, inbox *candidates.Inbox, opts daemonOptions) ([]candidates.IngestResult, error) {
	ifaces := lanInterfaces(opts.discoverInterface)
	if opts.discoverInterface != "" && len(ifaces) == 0 {
		return nil, fmt.Errorf("interface %q not found", opts.discoverInterface)
	}
	found, _, err := collectBonjourDevices(ctx, opts.discoverTimeout, ifaces, false)
	if err != nil {
		return nil, err
	}
	observedAt := time.Now().UTC()
	var observations []candidates.Observation
	for _, device := range found {
		if len(device.addrs) == 0 {
			observations = append(observations, candidates.Observation{Source: "bonjour", ObservedAt: observedAt, Name: device.instance, Hostname: device.hostname, Port: device.port})
			continue
		}
		for address := range device.addrs {
			observations = append(observations, candidates.Observation{Source: "bonjour", ObservedAt: observedAt, Name: device.instance, Hostname: device.hostname, Address: address, Port: device.port})
		}
	}
	if len(observations) > 0 {
		return inbox.IngestMany(observations)
	}
	return []candidates.IngestResult{}, nil
}

func scanCandidates(ctx context.Context, inbox *candidates.Inbox, opts daemonOptions) ([]candidates.IngestResult, error) {
	addresses, err := expandScanCIDRs(opts.scanCIDRs)
	if err != nil {
		return nil, err
	}
	pinned, err := loadPinnedTargetNames()
	if err != nil {
		return nil, err
	}
	findings, err := collectActiveScan(ctx, addresses, 22, defaultScanUser, opts.scanTimeout, opts.scanConcurrency, pinned)
	if err != nil {
		return nil, err
	}
	observedAt := time.Now().UTC()
	observations := make([]candidates.Observation, 0, len(findings))
	for _, finding := range findings {
		observations = append(observations, candidates.Observation{
			Source: "active-scan", ObservedAt: observedAt, Address: finding.address.String(), Port: finding.port,
			Fingerprint: finding.fingerprint, KeyType: finding.keyType, Evidence: finding.evidence,
		})
	}
	if len(observations) > 0 {
		return inbox.IngestMany(observations)
	}
	return []candidates.IngestResult{}, nil
}

type daemonAPI struct {
	startedAt  time.Time
	engine     *monitor.Engine
	inbox      *candidates.Inbox
	store      *config.Store
	adapter    *daemonAdapter
	identities []string
	// Operation budgets mirror the daemon's configured values so enrollment and
	// control clients use the same limits as ordinary monitoring.
	probeTimeout  time.Duration
	unlockTimeout time.Duration
	logger        *slog.Logger
	mutationMu    sync.Mutex
	// enrolling reserves candidates whose enrollment probe is in flight. The
	// probe deliberately runs without mutationMu held, so this is what stops two
	// concurrent requests from probing and enrolling the same candidate.
	enrolling map[string]bool
}

func (a *daemonAPI) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", a.handleHealth)
	mux.HandleFunc("GET /v1/devices", a.handleDevices)
	mux.HandleFunc("GET /v1/candidates", a.handleCandidates)
	mux.HandleFunc("POST /v1/devices/{name}/poll", a.handlePoll)
	mux.HandleFunc("POST /v1/devices/{name}/clear-latch", a.handleClearLatch)
	mux.HandleFunc("POST /v1/candidates/{id}/ignore", a.handleIgnore)
	mux.HandleFunc("POST /v1/candidates/{id}/restore", a.handleRestore)
	mux.HandleFunc("POST /v1/candidates/{id}/enroll", a.handleEnroll)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (a *daemonAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeAPIJSON(w, http.StatusOK, healthResponse{SchemaVersion: controlAPISchemaVersion, OK: true, StartedAt: a.startedAt, CheckedAt: time.Now().UTC(), Version: version})
}

func (a *daemonAPI) handleDevices(w http.ResponseWriter, _ *http.Request) {
	writeAPIJSON(w, http.StatusOK, struct {
		SchemaVersion int           `json:"schema_version"`
		ProbeTimeout  time.Duration `json:"probe_timeout"`
		UnlockTimeout time.Duration `json:"unlock_timeout"`
		monitor.Snapshot
	}{
		SchemaVersion: controlAPISchemaVersion,
		ProbeTimeout:  a.probeTimeout,
		UnlockTimeout: a.unlockTimeout,
		Snapshot:      a.engine.Snapshot(),
	})
}

func (a *daemonAPI) handleCandidates(w http.ResponseWriter, _ *http.Request) {
	writeAPIJSON(w, http.StatusOK, struct {
		SchemaVersion int `json:"schema_version"`
		candidates.Snapshot
	}{SchemaVersion: controlAPISchemaVersion, Snapshot: a.inbox.Snapshot()})
}

func (a *daemonAPI) handlePoll(w http.ResponseWriter, r *http.Request) {
	snapshot, err := a.engine.Poll(r.Context(), r.PathValue("name"))
	if err != nil && snapshot.Name == "" {
		writeAPIError(w, http.StatusNotFound, err)
		return
	}
	writeAPIJSON(w, http.StatusOK, struct {
		SchemaVersion int                    `json:"schema_version"`
		Device        monitor.DeviceSnapshot `json:"device"`
		Error         string                 `json:"error,omitempty"`
	}{SchemaVersion: controlAPISchemaVersion, Device: snapshot, Error: errorString(err)})
}

func (a *daemonAPI) handleClearLatch(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.engine.ClearLatch(name); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	a.logger.Info("device safety latch cleared by operator", "event", "device.latch_cleared", "device", terminalSafeInline(name))
	writeAPIJSON(w, http.StatusOK, map[string]any{"schema_version": controlAPISchemaVersion, "changed": true})
}

func (a *daemonAPI) handleIgnore(w http.ResponseWriter, r *http.Request) {
	a.mutationMu.Lock()
	defer a.mutationMu.Unlock()
	id := r.PathValue("id")
	current, ok := candidateByID(a.inbox.Snapshot(), id)
	if !ok {
		writeAPIError(w, http.StatusNotFound, errors.New("candidate not found"))
		return
	}
	if len(current.ConfiguredNames) > 0 {
		writeAPIError(w, http.StatusConflict, fmt.Errorf("candidate is already managed as %s", strings.Join(current.ConfiguredNames, ", ")))
		return
	}
	if current.State == candidates.StateIgnored {
		writeAPIError(w, http.StatusConflict, errors.New("candidate is already ignored"))
		return
	}
	candidate, err := a.inbox.Ignore(id)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	a.logger.Info("candidate ignored by operator", "event", "candidate.ignored", "candidate_id", terminalSafeInline(candidate.ID))
	writeAPIJSON(w, http.StatusOK, candidate)
}

func (a *daemonAPI) handleRestore(w http.ResponseWriter, r *http.Request) {
	a.mutationMu.Lock()
	defer a.mutationMu.Unlock()
	candidate, err := a.inbox.Restore(r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	a.logger.Info("candidate restored by operator", "event", "candidate.restored", "candidate_id", terminalSafeInline(candidate.ID))
	writeAPIJSON(w, http.StatusOK, candidate)
}

type enrollCandidateRequest struct {
	Name             string `json:"name"`
	Host             string `json:"host"`
	User             string `json:"user"`
	Port             int    `json:"port,omitempty"`
	Fingerprint      string `json:"fingerprint"`
	CredentialSource string `json:"credential_source"`
	CredentialRef    string `json:"credential_ref,omitempty"`
	AutoUnlock       bool   `json:"auto_unlock"`
}

// apiStatusError carries the HTTP status a validation failure should produce,
// so precondition checks can be shared between the pre-probe and post-probe
// passes of an enrollment without either duplicating status codes.
type apiStatusError struct {
	status int
	err    error
}

func (e *apiStatusError) Error() string { return e.err.Error() }

func (e *apiStatusError) Unwrap() error { return e.err }

func apiError(status int, err error) error { return &apiStatusError{status: status, err: err} }

func writeAPIStatusError(w http.ResponseWriter, err error) {
	var statusErr *apiStatusError
	if errors.As(err, &statusErr) {
		writeAPIError(w, statusErr.status, statusErr.err)
		return
	}
	writeAPIError(w, http.StatusInternalServerError, err)
}

// validateEnrollment applies every precondition for enrolling a candidate and
// returns the device that would be created. It performs no mutation, so it can
// be run twice: once before the SSH probe and again after it, with the caller
// holding mutationMu both times.
func (a *daemonAPI) validateEnrollment(id string, request enrollCandidateRequest) (candidates.Candidate, config.Device, error) {
	candidate, ok := candidateByID(a.inbox.Snapshot(), id)
	if !ok {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusNotFound, errors.New("candidate not found"))
	}
	if candidate.State == candidates.StateIgnored {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusConflict, errors.New("candidate is ignored; restore it before enrollment"))
	}
	if len(candidate.ConfiguredNames) > 0 {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusConflict, fmt.Errorf("candidate is already managed as %s", strings.Join(candidate.ConfiguredNames, ", ")))
	}
	if candidate.Fingerprint == "" || request.Fingerprint != candidate.Fingerprint {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusBadRequest, errors.New("the independently verified fingerprint must exactly match the current candidate fingerprint"))
	}
	if request.Port == 0 {
		request.Port = 22
	}
	request.CredentialSource = strings.ToLower(strings.TrimSpace(request.CredentialSource))
	if request.CredentialSource == "" {
		request.CredentialSource = credentials.ProviderRuntime
	}
	if request.CredentialSource == credentials.ProviderKeyring {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusBadRequest, errors.New("candidate enrollment cannot create a keyring credential; use a pre-provisioned file reference, runtime for manual unlock, or config add for a known device"))
	}
	device := config.Device{
		Name: request.Name, Host: request.Host, User: request.User, Port: request.Port,
		Cred: credentials.ID(request.Name), CredentialSource: request.CredentialSource,
		CredentialRef: request.CredentialRef, SuccessMessage: defaultSuccessMessage, AutoUnlock: request.AutoUnlock,
	}
	if err := config.ValidateDevice(device); err != nil {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusBadRequest, err)
	}
	configured, err := a.store.Load()
	if err != nil {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusInternalServerError, err)
	}
	if err := config.ValidateDevices(append(configured, device)); err != nil {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusConflict, err)
	}
	if err := assessDaemonDevice(device); err != nil {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusBadRequest, err)
	}
	return candidate, device, nil
}

// beginEnrollment validates the request and reserves the candidate for the
// duration of the SSH probe. The reservation is what makes releasing mutationMu
// during the probe safe against a second request for the same candidate.
func (a *daemonAPI) beginEnrollment(id string, request enrollCandidateRequest) (candidates.Candidate, config.Device, error) {
	a.mutationMu.Lock()
	defer a.mutationMu.Unlock()
	if a.enrolling[id] {
		return candidates.Candidate{}, config.Device{}, apiError(http.StatusConflict, errors.New("an enrollment for this candidate is already in progress"))
	}
	candidate, device, err := a.validateEnrollment(id, request)
	if err != nil {
		return candidates.Candidate{}, config.Device{}, err
	}
	if a.enrolling == nil {
		a.enrolling = make(map[string]bool)
	}
	a.enrolling[id] = true
	return candidate, device, nil
}

func (a *daemonAPI) endEnrollment(id string) {
	a.mutationMu.Lock()
	delete(a.enrolling, id)
	a.mutationMu.Unlock()
}

func (a *daemonAPI) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var request enrollCandidateRequest
	if err := decodeAPIJSON(r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	id := r.PathValue("id")
	candidate, device, err := a.beginEnrollment(id, request)
	if err != nil {
		writeAPIStatusError(w, err)
		return
	}
	defer a.endEnrollment(id)

	// The probe is a full SSH round trip bounded by the configured probe
	// timeout. Running it under mutationMu would block every other control
	// mutation for that long, past the control server's write timeout, so it
	// runs unlocked and the preconditions are re-checked below. It only reads
	// the candidate's key; nothing is pinned or configured yet.
	pending, err := probeExpectedHostKey(r.Context(), device, candidate.Fingerprint, a.identities, max(a.probeTimeout, a.unlockTimeout), a.probeTimeout)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, err)
		return
	}
	if err := r.Context().Err(); err != nil {
		writeAPIError(w, http.StatusRequestTimeout, err)
		return
	}

	a.mutationMu.Lock()
	defer a.mutationMu.Unlock()
	if err := r.Context().Err(); err != nil {
		writeAPIError(w, http.StatusRequestTimeout, err)
		return
	}
	// Re-validate everything after the probe. The candidate may have been
	// ignored, re-observed with a different key, or configured by another path
	// while the probe was running; enrolling on the pre-probe view would be a
	// time-of-check/time-of-use hole around credential release.
	recheckCandidate, recheckDevice, err := a.validateEnrollment(id, request)
	if err != nil {
		writeAPIStatusError(w, err)
		return
	}
	if recheckCandidate.Fingerprint != candidate.Fingerprint || recheckDevice != device {
		writeAPIError(w, http.StatusConflict, errors.New("candidate or device details changed during enrollment; nothing was trusted or configured"))
		return
	}

	// Register first, pin second: an enrollment that fails after this point is
	// rolled back completely, so configuration and trust state never diverge.
	if err := a.store.AddContext(r.Context(), device); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeAPIError(w, http.StatusRequestTimeout, err)
			return
		}
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	if err := r.Context().Err(); err != nil {
		a.failEnrollment(w, http.StatusRequestTimeout, device, pendingHostKey{}, err)
		return
	}
	a.adapter.addDevice(device)
	knownHosts, err := knownHostsPath()
	if err != nil {
		a.failEnrollment(w, http.StatusInternalServerError, device, pendingHostKey{}, err)
		return
	}
	insertedHostKey, err := commitPendingHostKeyContext(r.Context(), knownHosts, pending)
	if err != nil {
		owned := pendingHostKey{}
		if insertedHostKey {
			owned = pending
		}
		a.failEnrollment(w, http.StatusBadGateway, device, owned, err)
		return
	}
	pinnedByEnrollment := pendingHostKey{}
	if insertedHostKey {
		pinnedByEnrollment = pending
	}
	if err := r.Context().Err(); err != nil {
		a.failEnrollment(w, http.StatusRequestTimeout, device, pinnedByEnrollment, err)
		return
	}
	if err := a.engine.AddDevice(toMonitorDevice(device)); err != nil {
		a.failEnrollment(w, http.StatusInternalServerError, device, pinnedByEnrollment, err)
		return
	}

	verified := candidate
	if updated, markErr := a.inbox.MarkVerified(candidate.ID); markErr != nil {
		a.logger.Warn("device enrolled but candidate state update failed", "event", "candidate.state_update_failed", "device", terminalSafeInline(device.Name), "candidate_id", terminalSafeInline(candidate.ID), "error", terminalSafeError(markErr))
	} else {
		verified = updated
	}
	if refreshErr := refreshConfiguredCandidates(a.inbox); refreshErr != nil {
		a.logger.Warn("device enrolled but configured-candidate labels could not refresh", "event", "candidate.label_refresh_failed", "device", terminalSafeInline(device.Name), "error", terminalSafeError(refreshErr))
	}
	a.logger.Info("candidate enrolled", "event", "candidate.enrolled", "candidate_id", terminalSafeInline(candidate.ID), "device", terminalSafeInline(device.Name), "endpoint", terminalSafeInline(deviceEndpoint(device)), "auto_unlock", device.AutoUnlock)
	writeAPIJSON(w, http.StatusCreated, struct {
		SchemaVersion int                  `json:"schema_version"`
		Device        config.Device        `json:"device"`
		Candidate     candidates.Candidate `json:"candidate"`
	}{SchemaVersion: controlAPISchemaVersion, Device: device, Candidate: verified})
}

// failEnrollment rolls a partial enrollment back and reports the failure. A
// rollback that cannot complete is reported to the caller as well as logged:
// leftover trust or configuration state needs operator attention, so it must
// not be swallowed.
func (a *daemonAPI) failEnrollment(w http.ResponseWriter, status int, device config.Device, pinned pendingHostKey, cause error) {
	if rollbackErr := a.rollbackEnrollment(device, pinned); rollbackErr != nil {
		writeAPIError(w, status, errors.Join(cause, fmt.Errorf("enrollment rollback did not complete: %w", rollbackErr)))
		return
	}
	writeAPIError(w, status, cause)
}

// rollbackEnrollment undoes the mutations handleEnroll performs, in reverse
// order. A zero pinned key means the host key was never recorded.
func (a *daemonAPI) rollbackEnrollment(device config.Device, pinned pendingHostKey) error {
	a.adapter.removeDevice(device.Name)
	ctx, cancel := context.WithTimeout(context.Background(), controlOperationOverhead)
	defer cancel()
	var errs []error
	if pinned.key != nil {
		path, err := knownHostsPath()
		if err != nil {
			errs = append(errs, fmt.Errorf("locate known_hosts: %w", err))
		} else if err := removeKnownHostContext(ctx, path, pinned.hostname, pinned.key); err != nil {
			errs = append(errs, fmt.Errorf("unpin host key: %w", err))
		}
	}
	if err := a.store.RemoveIfUnchangedContext(ctx, device); err != nil {
		errs = append(errs, fmt.Errorf("remove configuration entry: %w", err))
	}
	err := errors.Join(errs...)
	if err != nil && a.logger != nil {
		a.logger.Error("enrollment rollback did not fully complete", "event", "candidate.enroll_rollback_failed", "device", terminalSafeInline(device.Name), "error", terminalSafeError(err))
	}
	return err
}

// probeExpectedHostKey proves the candidate still presents the independently
// verified key, without recording anything. The key it observed is returned so
// the caller can pin it only after the device is registered; a zero value means
// the host was already pinned and nothing new needs recording.
func probeExpectedHostKey(ctx context.Context, device config.Device, fingerprint string, identities []string, dialTimeout, probeTimeout time.Duration) (pendingHostKey, error) {
	path, err := knownHostsPath()
	if err != nil {
		return pendingHostKey{}, err
	}
	var pending pendingHostKey
	callback, err := hostKeyCallbackFuncContext(ctx, path, true, fingerprint, func(observed pendingHostKey) error {
		pending = observed
		return nil
	})
	if err != nil {
		return pendingHostKey{}, err
	}
	signers, err := loadSigners(false, identities)
	if err != nil {
		return pendingHostKey{}, err
	}
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	client := &fvcore.RealSSHClient{DialTimeout: dialTimeout, Signers: signers, HostKeyCallback: callback}
	_, _, probeErr := fvcore.CheckStatus(ctx, client, deviceEndpoint(device), device.User, probeTimeout)
	if probeErr != nil && !errors.Is(probeErr, fvcore.ErrIndeterminate) {
		return pendingHostKey{}, probeErr
	}
	return pending, nil
}

func candidateByID(snapshot candidates.Snapshot, id string) (candidates.Candidate, bool) {
	for _, candidate := range snapshot.Candidates {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return candidates.Candidate{}, false
}

func decodeAPIJSON(r *http.Request, dst any) error {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request contains trailing data")
	}
	return nil
}

func writeAPIJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	writeAPIJSON(w, status, map[string]any{"schema_version": controlAPISchemaVersion, "error": terminalSafeInline(err.Error())})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ monitor.Prober = (*daemonAdapter)(nil)
var _ monitor.Unlocker = (*daemonAdapter)(nil)

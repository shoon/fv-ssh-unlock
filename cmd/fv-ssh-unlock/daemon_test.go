// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

type fakeDaemonSSH struct {
	probeStatus fvcore.DeviceStatus
	probeErr    error
	unlockState fvcore.DeviceStatus
	unlockErr   error
	password    string
	probeCalls  int
}

func (f *fakeDaemonSSH) ProbeStatus(context.Context, string, string) (fvcore.DeviceStatus, string, error) {
	f.probeCalls++
	return f.probeStatus, "sensitive banner must not be retained", f.probeErr
}

func TestDaemonAdapterUsesTCPPreflightOnlyAfterEndpointFailure(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, AutoUnlock: true, CredentialSource: credentials.ProviderKeyring}
	client := &fakeDaemonSSH{probeErr: context.DeadlineExceeded}
	adapter := newDaemonAdapter(client, []config.Device{device}, defaultProbeTimeout, defaultUnlockTimeout)
	checks := 0
	adapter.reachability = func(context.Context, string) error {
		checks++
		return errors.New("endpoint down")
	}

	result, err := adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureUnreachable || !result.EndpointDown || client.probeCalls != 1 || checks != 1 {
		t.Fatalf("initial failed probe = %+v, %v; SSH calls=%d TCP checks=%d", result, err, client.probeCalls, checks)
	}
	result, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureUnreachable || !result.EndpointDown || client.probeCalls != 1 || checks != 2 {
		t.Fatalf("endpoint-down preflight = %+v, %v; SSH calls=%d TCP checks=%d", result, err, client.probeCalls, checks)
	}
}

func TestDaemonLoggingOptionsAndStructuredEvent(t *testing.T) {
	cmd := newDaemonCommand()
	if err := cmd.ParseFlags([]string{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-format", "json", "--log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	opts, err := daemonOptionsFromFlags(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if opts.logFormat != "json" || opts.logLevel != slog.LevelDebug {
		t.Fatalf("logging options = %q, %v", opts.logFormat, opts.logLevel)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})).With(
		"schema_version", daemonLogSchemaVersion,
		"component", "daemon",
	)
	events := make(chan monitor.Event, 1)
	events <- monitor.Event{
		Sequence: 7, Type: monitor.EventStateChanged, Device: "mac", State: monitor.StateLocked,
		Observation: monitor.StateLocked, LockEpisode: 2, AutoUnlock: true, Message: "FileVault pre-boot banner detected",
	}
	close(events)
	logMonitorEvents(logger, events)
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"event": "device.filevault_locked", "device": "mac", "state": "locked",
		"observation": "locked", "auto_unlock": true, "schema_version": float64(daemonLogSchemaVersion),
	} {
		if got := entry[key]; got != want {
			t.Fatalf("structured log %s = %#v, want %#v; entry=%v", key, got, want, entry)
		}
	}
}

func TestDaemonStructuredLogEscapesUntrustedLineBreaks(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	events := make(chan monitor.Event, 1)
	events <- monitor.Event{
		Sequence: 1,
		Type:     monitor.EventUnlockResult,
		Device:   "mac\r\nevent=forged",
		State:    monitor.StateError,
		Message:  "dial failed\nlevel=INFO event=device.booted",
	}
	close(events)
	logMonitorEvents(logger, events)

	if got := bytes.Count(output.Bytes(), []byte{'\n'}); got != 1 {
		t.Fatalf("structured logger emitted %d physical records, want 1: %q", got, output.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if got, want := entry["device"], `mac\u000D\u000Aevent=forged`; got != want {
		t.Fatalf("device = %#v, want %#v", got, want)
	}
	if got, want := entry["detail"], `dial failed\u000Alevel=INFO event=device.booted`; got != want {
		t.Fatalf("detail = %#v, want %#v", got, want)
	}
}

func TestCandidateLogEscapesUntrustedLineBreaks(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logCandidateResults(logger, "scan\r\nlevel=ERROR", []candidates.IngestResult{{
		Created: true,
		Candidate: candidates.Candidate{
			ID:        "cand_safe\nevent=forged",
			State:     candidates.StateDiscovered,
			Hostnames: []string{"mac.local\r\nmsg=forged"},
		},
	}})

	if got := bytes.Count(output.Bytes(), []byte{'\n'}); got != 1 {
		t.Fatalf("candidate logger emitted %d physical records, want 1: %q", got, output.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"candidate_id": `cand_safe\u000Aevent=forged`,
		"source":       `scan\u000D\u000Alevel=ERROR`,
		"hostname":     `mac.local\u000D\u000Amsg=forged`,
	} {
		if got := entry[field]; got != want {
			t.Fatalf("%s = %#v, want %#v", field, got, want)
		}
	}
}

func TestDaemonLoggingOptionsRejectInvalidValues(t *testing.T) {
	for _, flags := range [][]string{
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-format", "xml"},
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-level", "trace"},
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--json-log", "--log-format", "text"},
	} {
		cmd := newDaemonCommand()
		if err := cmd.ParseFlags(flags); err != nil {
			t.Fatal(err)
		}
		if _, err := daemonOptionsFromFlags(cmd); err == nil {
			t.Fatalf("flags %v unexpectedly accepted", flags)
		}
	}
}

func (f *fakeDaemonSSH) AnalyzePrompt(_ context.Context, _, _, password, _ string) (fvcore.DeviceStatus, string, error) {
	f.password = password
	return f.unlockState, "sensitive banner must not be retained", f.unlockErr
}

func TestDaemonAdapterProbeClassification(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	client := &fakeDaemonSSH{probeStatus: fvcore.StatusLocked}
	adapter := newDaemonAdapter(client, []config.Device{device}, defaultProbeTimeout, defaultUnlockTimeout)
	result, err := adapter.Probe(context.Background(), toMonitorDevice(device))
	if err != nil || result.State != monitor.StateLocked || strings.Contains(result.Detail, "sensitive") {
		t.Fatalf("locked probe = %+v, %v", result, err)
	}
	client.probeStatus = fvcore.StatusUnknown
	client.probeErr = fvcore.ErrIndeterminate
	result, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if err != nil || result.State != monitor.StateIndeterminate {
		t.Fatalf("indeterminate probe = %+v, %v", result, err)
	}
	client.probeErr = fvcore.ErrHostKeyMismatch
	_, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureHostKey {
		t.Fatalf("host key error classification = %v", err)
	}
}

func TestDaemonAdapterUnlockReadsCredentialJustInTime(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	t.Setenv(credentials.EnvName(credentials.ID(device.Name)), "correct horse battery staple")
	client := &fakeDaemonSSH{unlockState: fvcore.StatusUnlocked}
	adapter := newDaemonAdapter(client, []config.Device{device}, defaultProbeTimeout, defaultUnlockTimeout)
	result, err := adapter.Unlock(context.Background(), toMonitorDevice(device))
	if err != nil || !result.Accepted {
		t.Fatalf("unlock = %+v, %v", result, err)
	}
	if client.password != "correct horse battery staple" {
		t.Fatal("adapter did not retrieve the scoped credential")
	}
	if strings.Contains(result.Detail, client.password) {
		t.Fatal("result leaked credential")
	}

	client.unlockState = fvcore.StatusUnknown
	client.unlockErr = fvcore.ErrUnlockOutcomeUnknown
	result, err = adapter.Unlock(context.Background(), toMonitorDevice(device))
	if !result.Accepted || !errors.Is(err, fvcore.ErrUnlockOutcomeUnknown) {
		t.Fatalf("ambiguous submitted result = %+v, %v", result, err)
	}

	client.unlockState = fvcore.StatusLocked
	client.unlockErr = fvcore.ErrAuthFailed
	result, err = adapter.Unlock(context.Background(), toMonitorDevice(device))
	if result.Accepted || monitor.FailureKindOf(err) != monitor.FailureCredential {
		t.Fatalf("wrong credential result = %+v, %v", result, err)
	}
}

func TestAssessDaemonDeviceFailsClosed(t *testing.T) {
	manual := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	if err := assessDaemonDevice(manual); err != nil {
		t.Fatalf("manual device should not require unattended credential: %v", err)
	}
	manual.AutoUnlock = true
	if err := assessDaemonDevice(manual); err == nil || !strings.Contains(err.Error(), "runtime/environment") {
		t.Fatalf("runtime auto-unlock should fail: %v", err)
	}
	diskSecret := filepath.Join(t.TempDir(), "password")
	if err := osWritePrivateForTest(diskSecret, "secret"); err != nil {
		t.Fatal(err)
	}
	manual.CredentialSource = credentials.ProviderFile
	manual.CredentialRef = diskSecret
	if err := assessDaemonDevice(manual); err == nil || !strings.Contains(err.Error(), "secure credential") {
		t.Fatalf("disk secret should fail: %v", err)
	}
}

func osWritePrivateForTest(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o600)
}

func TestDaemonLockExcludesConcurrentController(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	first, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if second, err := acquireDaemonLock(path); err == nil {
		releaseDaemonLock(second)
		releaseDaemonLock(first)
		t.Fatal("second controller acquired the same data-directory lock")
	}
	releaseDaemonLock(first)
	third, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	releaseDaemonLock(third)
}

type apiProbe struct{}

func (apiProbe) Probe(context.Context, monitor.Device) (monitor.ProbeResult, error) {
	return monitor.ProbeResult{State: monitor.StateBooted, Detail: "verified"}, nil
}

func TestDaemonAPILocalReadAndMutationRoutes(t *testing.T) {
	device := monitor.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	engine, err := monitor.New([]monitor.Device{device}, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.2", Port: 22, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		startedAt: time.Now(), engine: engine, inbox: inbox,
		store:  &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := api.routes()

	for _, endpoint := range []string{"/v1/health", "/v1/devices", "/v1/candidates"} {
		request := httptest.NewRequest(http.MethodGet, endpoint, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"schema_version":1`) {
			t.Fatalf("GET %s = %d, %q, headers=%v", endpoint, response.Code, response.Body.String(), response.Header())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/ignore", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"ignored"`) {
		t.Fatalf("ignore = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/devices/mac/poll", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"booted"`) {
		t.Fatalf("poll = %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentRejectsNetworkFingerprintAsConfirmation(t *testing.T) {
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.2", Port: 22, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{engine: engine, inbox: inbox, store: &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{"name":"mac","host":"192.0.2.2","user":"user","port":22,"fingerprint":"SHA256:not-the-observed-key","credential_source":"runtime","auto_unlock":false}`
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "independently verified") {
		t.Fatalf("enroll mismatch = %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentRejectsKeyringWithoutProvisioningPath(t *testing.T) {
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.2", Port: 22, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{engine: engine, inbox: inbox, store: &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := fmt.Sprintf(`{"name":"mac","host":"192.0.2.2","user":"user","port":22,"fingerprint":%q,"credential_source":"keyring","auto_unlock":false}`, fingerprint)
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "cannot create a keyring credential") {
		t.Fatalf("keyring enroll = %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentPinsExpectedKeyAndAddsMonitorDevice(t *testing.T) {
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	address, port, hostKey, _ := startScanTestServer(t, "")
	fingerprint := ssh.FingerprintSHA256(hostKey.PublicKey())
	inbox := candidates.New(candidates.Options{})
	ingested, err := inbox.Ingest(candidates.Observation{Source: "active-scan", Address: address.String(), Port: port, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(dataDir, "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := &config.Store{Path: filepath.Join(dataDir, "devices.json")}
	adapter := newDaemonAdapter(&fakeDaemonSSH{}, nil, defaultProbeTimeout, defaultUnlockTimeout)
	api := &daemonAPI{engine: engine, inbox: inbox, store: store, adapter: adapter, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := fmt.Sprintf(`{"name":"new-mac","host":%q,"user":"user","port":%d,"fingerprint":%q,"credential_source":"runtime","auto_unlock":false}`,
		address.String(), port, fingerprint)
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", response.Code, response.Body.String())
	}
	configured, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 1 || configured[0].Name != "new-mac" {
		t.Fatalf("configured devices = %+v", configured)
	}
	if snapshots := engine.Snapshot().Devices; len(snapshots) != 1 || snapshots[0].Name != "new-mac" {
		t.Fatalf("monitor devices = %+v", snapshots)
	}
	knownHosts, err := os.ReadFile(filepath.Join(dataDir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(knownHosts) == 0 {
		t.Fatal("expected host key to be pinned")
	}
}

func privateDaemonTestDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRemainingTimeoutHonoursTheConfiguredBudget(t *testing.T) {
	if got := remainingTimeout(context.Background(), 60*time.Second); got != 60*time.Second {
		t.Fatalf("deadline-free budget = %v, want 60s", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if got := remainingTimeout(ctx, 60*time.Second); got != 60*time.Second {
		t.Fatalf("distant deadline shortened the budget to %v, want 60s", got)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := remainingTimeout(ctx, 60*time.Second)
	if got <= 0 || got > 5*time.Second {
		t.Fatalf("near deadline budget = %v, want (0, 5s]", got)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	// An expired context must not lengthen or zero the budget; the operation
	// fails on the context instead of on a degenerate timeout.
	if got := remainingTimeout(ctx, 60*time.Second); got != 60*time.Second {
		t.Fatalf("expired-context budget = %v, want 60s", got)
	}
}

// timeoutRecordingSSH records the deadline each operation is given, so the
// budget actually applied to an SSH call can be asserted.
type timeoutRecordingSSH struct {
	probeBudget  time.Duration
	unlockBudget time.Duration
}

func (r *timeoutRecordingSSH) ProbeStatus(ctx context.Context, _, _ string) (fvcore.DeviceStatus, string, error) {
	r.probeBudget = budgetOf(ctx)
	return fvcore.StatusLocked, "", nil
}

func (r *timeoutRecordingSSH) AnalyzePrompt(ctx context.Context, _, _, _, _ string) (fvcore.DeviceStatus, string, error) {
	r.unlockBudget = budgetOf(ctx)
	return fvcore.StatusUnlocked, "", nil
}

// budgetOf rounds the remaining time up to whole seconds so the assertion does
// not depend on how long the call took to reach the client.
func budgetOf(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline).Round(time.Second)
}

func TestDaemonAdapterAppliesConfiguredProbeAndUnlockTimeouts(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	t.Setenv(credentials.EnvName(credentials.ID(device.Name)), "correct horse battery staple")
	client := &timeoutRecordingSSH{}
	adapter := newDaemonAdapter(client, []config.Device{device}, 60*time.Second, 90*time.Second)

	if _, err := adapter.Probe(context.Background(), toMonitorDevice(device)); err != nil {
		t.Fatal(err)
	}
	if client.probeBudget != 60*time.Second {
		t.Fatalf("probe budget = %v, want the configured 60s", client.probeBudget)
	}
	if _, err := adapter.Unlock(context.Background(), toMonitorDevice(device)); err != nil {
		t.Fatal(err)
	}
	if client.unlockBudget != 90*time.Second {
		t.Fatalf("unlock budget = %v, want the configured 90s", client.unlockBudget)
	}
}

func TestDaemonAdapterFallsBackToTheFlagDefaultTimeouts(t *testing.T) {
	adapter := newDaemonAdapter(&fakeDaemonSSH{}, nil, 0, -time.Second)
	if adapter.probeTimeout != defaultProbeTimeout || adapter.unlockTimeout != defaultUnlockTimeout {
		t.Fatalf("fallback timeouts = %v/%v, want %v/%v", adapter.probeTimeout, adapter.unlockTimeout, defaultProbeTimeout, defaultUnlockTimeout)
	}
}

func TestDaemonTimeoutFlagsReachTheAdapterAndDialer(t *testing.T) {
	cmd := newDaemonCommand()
	if err := cmd.ParseFlags([]string{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--probe-timeout", "60s", "--unlock-timeout", "90s"}); err != nil {
		t.Fatal(err)
	}
	opts, err := daemonOptionsFromFlags(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if opts.probeTimeout != 60*time.Second || opts.unlockTimeout != 90*time.Second {
		t.Fatalf("parsed timeouts = %v/%v", opts.probeTimeout, opts.unlockTimeout)
	}

	// This mirrors how runDaemon wires the options, so a regression that drops
	// the configured budget on the way to the SSH layer is caught here.
	dialTimeout := minDuration(opts.probeTimeout, opts.unlockTimeout)
	if dialTimeout != 60*time.Second {
		t.Fatalf("dial timeout = %v, want the shorter configured budget", dialTimeout)
	}
	adapter := newDaemonAdapter(&fakeDaemonSSH{}, nil, opts.probeTimeout, opts.unlockTimeout)
	if adapter.probeTimeout != 60*time.Second || adapter.unlockTimeout != 90*time.Second {
		t.Fatalf("adapter timeouts = %v/%v", adapter.probeTimeout, adapter.unlockTimeout)
	}

	client, err := newSSHClient(false, true, false, nil, dialTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if client.DialTimeout != 60*time.Second {
		t.Fatalf("dial timeout = %v, want 60s", client.DialTimeout)
	}
	fallback, err := newSSHClient(false, true, false, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.DialTimeout != defaultDialTimeout {
		t.Fatalf("fallback dial timeout = %v, want %v", fallback.DialTimeout, defaultDialTimeout)
	}
}

func TestDaemonTimeoutFlagDefaultsMatchTheAppliedConstants(t *testing.T) {
	cmd := newDaemonCommand()
	if got := cmd.Flags().Lookup("probe-timeout").DefValue; got != defaultProbeTimeout.String() {
		t.Fatalf("--probe-timeout default = %s, want %s", got, defaultProbeTimeout)
	}
	if got := cmd.Flags().Lookup("unlock-timeout").DefValue; got != defaultUnlockTimeout.String() {
		t.Fatalf("--unlock-timeout default = %s, want %s", got, defaultUnlockTimeout)
	}
	if got := cmd.Flags().Lookup("once").Usage; !strings.Contains(got, "submit credentials") {
		t.Fatalf("--once help does not say it can submit credentials: %q", got)
	}
}

func TestDaemonAdapterUnlockWrapsTheRejectionCause(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	t.Setenv(credentials.EnvName(credentials.ID(device.Name)), "correct horse battery staple")
	client := &fakeDaemonSSH{unlockState: fvcore.StatusLocked, unlockErr: fvcore.ErrAuthFailed}
	adapter := newDaemonAdapter(client, []config.Device{device}, defaultProbeTimeout, defaultUnlockTimeout)

	result, err := adapter.Unlock(context.Background(), toMonitorDevice(device))
	if result.Accepted || monitor.FailureKindOf(err) != monitor.FailureCredential {
		t.Fatalf("rejected credential = %+v, %v", result, err)
	}
	if !errors.Is(err, fvcore.ErrAuthFailed) {
		t.Fatalf("rejection error lost its cause: %v", err)
	}
	if !strings.Contains(err.Error(), "FileVault rejected the configured credential") {
		t.Fatalf("rejection error lost its classification text: %v", err)
	}
}

// enrollmentTestAPI builds a daemon API around a real SSH test server whose
// host key the inbox has already observed, which is the state a candidate is in
// just before an operator enrolls it.
func enrollmentTestAPI(t *testing.T, monitored []monitor.Device) (*daemonAPI, string, string, string) {
	t.Helper()
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	address, port, hostKey, _ := startScanTestServer(t, "")
	fingerprint := ssh.FingerprintSHA256(hostKey.PublicKey())
	inbox := candidates.New(candidates.Options{})
	ingested, err := inbox.Ingest(candidates.Observation{Source: "active-scan", Address: address.String(), Port: port, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := monitor.New(monitored, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(dataDir, "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		engine: engine, inbox: inbox,
		store:   &config.Store{Path: filepath.Join(dataDir, "devices.json")},
		adapter: newDaemonAdapter(&fakeDaemonSSH{}, nil, defaultProbeTimeout, defaultUnlockTimeout),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	body := fmt.Sprintf(`{"name":"new-mac","host":%q,"user":"user","port":%d,"fingerprint":%q,"credential_source":"runtime","auto_unlock":false}`,
		address.String(), port, fingerprint)
	return api, ingested.Candidate.ID, body, dataDir
}

func TestEnrollmentRollbackLeavesNoPinnedHostKeyOrConfigEntry(t *testing.T) {
	// The monitor already knows this name, so registration fails after the
	// configuration entry has been written and the host key has been pinned.
	api, candidateID, body, dataDir := enrollmentTestAPI(t, []monitor.Device{{Name: "new-mac", Host: "192.0.2.9", User: "user", Port: 22}})

	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+candidateID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed enrollment = %d %s", response.Code, response.Body.String())
	}

	knownHosts, err := os.ReadFile(filepath.Join(dataDir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(knownHosts)) != "" {
		t.Fatalf("failed enrollment left the host key pinned: %q", knownHosts)
	}
	configured, err := api.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 0 {
		t.Fatalf("failed enrollment left a configuration entry: %+v", configured)
	}
	if _, err := api.adapter.configured("new-mac"); err == nil {
		t.Fatal("failed enrollment left the device registered with the probe adapter")
	}
}

func TestEnrollmentPinsTheHostKeyOnlyOnSuccess(t *testing.T) {
	api, candidateID, body, dataDir := enrollmentTestAPI(t, nil)

	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+candidateID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", response.Code, response.Body.String())
	}
	knownHosts, err := os.ReadFile(filepath.Join(dataDir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(knownHosts)) == "" {
		t.Fatal("successful enrollment did not pin the host key")
	}
}

func TestEnrollmentProbeDoesNotHoldTheMutationLock(t *testing.T) {
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	// A listener that accepts and then stays silent keeps the enrollment probe
	// running for its whole timeout, which is the window this test needs.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		var open []net.Conn
		defer func() {
			for _, conn := range open {
				_ = conn.Close()
			}
		}()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			open = append(open, conn)
		}
	}()
	stalled := listener.Addr().(*net.TCPAddr)

	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	target, err := inbox.Ingest(candidates.Observation{Source: "test", Address: stalled.IP.String(), Port: stalled.Port, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	other, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.77", Port: 22, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(dataDir, "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		engine: engine, inbox: inbox,
		store:        &config.Store{Path: filepath.Join(dataDir, "devices.json")},
		adapter:      newDaemonAdapter(&fakeDaemonSSH{}, nil, defaultProbeTimeout, defaultUnlockTimeout),
		probeTimeout: 3 * time.Second, dialTimeout: 3 * time.Second,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := api.routes()
	body := fmt.Sprintf(`{"name":"stalled-mac","host":%q,"user":"user","port":%d,"fingerprint":%q,"credential_source":"runtime","auto_unlock":false}`,
		stalled.IP.String(), stalled.Port, fingerprint)

	enrolled := make(chan int, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+target.Candidate.ID+"/enroll", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		enrolled <- response.Code
	}()

	// Reading the reservation requires mutationMu, so reaching this point at
	// all proves the probe is not holding it.
	deadline := time.Now().Add(5 * time.Second)
	inFlight := false
	for time.Now().Before(deadline) && !inFlight {
		api.mutationMu.Lock()
		inFlight = api.enrolling[target.Candidate.ID]
		api.mutationMu.Unlock()
		if !inFlight {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !inFlight {
		t.Fatal("enrollment probe never started")
	}

	// An unrelated mutation must still complete promptly, well inside the
	// control server's write timeout.
	started := time.Now()
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+other.Candidate.ID+"/ignore", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("concurrent ignore = %d %s", response.Code, response.Body.String())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("concurrent ignore blocked for %v behind the enrollment probe", elapsed)
	}

	// A second enrollment of the same candidate must be refused rather than
	// probing and racing to configure the same device twice.
	request = httptest.NewRequest(http.MethodPost, "/v1/candidates/"+target.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "already in progress") {
		t.Fatalf("concurrent enroll = %d %s", response.Code, response.Body.String())
	}

	select {
	case code := <-enrolled:
		// The silent server never proves the key, so enrollment must fail closed.
		if code != http.StatusBadGateway {
			t.Fatalf("stalled enrollment = %d, want 502", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("enrollment probe never finished")
	}
	configured, err := api.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 0 {
		t.Fatalf("failed probe still configured a device: %+v", configured)
	}
}

// syncWriter serializes the concurrent writes runDaemon's logger and event
// pump make, so the collected output can be inspected after the join.
type syncWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func TestRunDaemonJoinsEveryComponentBeforeReturning(t *testing.T) {
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	// A short socket directory: a Unix socket path has a much smaller length
	// limit than a normal path, and the default temp directory can exceed it.
	socketDir, err := os.MkdirTemp("", "fvd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	cmd := newDaemonCommand()
	if err := cmd.ParseFlags([]string{
		"--socket", filepath.Join(socketDir, "d.sock"),
		"--discover-interval", "0",
		"--log-format", "json",
	}); err != nil {
		t.Fatal(err)
	}
	opts, err := daemonOptionsFromFlags(cmd)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	output := &syncWriter{}
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, output, opts) }()

	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(output.String(), "daemon.started") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(output.String(), "daemon.started") {
		cancel()
		<-done
		t.Fatalf("daemon never started: %s", output.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v; output: %s", err, output.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runDaemon did not return after its context was cancelled")
	}
	// daemon.stopped is only logged once every component has been joined, so
	// its presence is what proves the shutdown path ran to completion.
	if !strings.Contains(output.String(), "daemon.stopped") {
		t.Fatalf("shutdown did not join every component: %s", output.String())
	}
}

func TestRunDaemonRefusesASecondController(t *testing.T) {
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	lock, err := acquireDaemonLock(filepath.Join(dataDir, "daemon.lock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { releaseDaemonLock(lock) })

	cmd := newDaemonCommand()
	if err := cmd.ParseFlags([]string{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--once"}); err != nil {
		t.Fatal(err)
	}
	opts, err := daemonOptionsFromFlags(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := runDaemon(context.Background(), io.Discard, opts); err == nil {
		t.Fatal("a second controller started while the data directory was locked")
	}
}

func TestDaemonAPIRejectsUnknownDeviceAndCandidateMutations(t *testing.T) {
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		startedAt: time.Now(), engine: engine, inbox: candidates.New(candidates.Options{}),
		store:  &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := api.routes()

	for _, tt := range []struct {
		endpoint string
		want     int
	}{
		{"/v1/devices/missing/poll", http.StatusNotFound},
		{"/v1/devices/missing/clear-latch", http.StatusBadRequest},
		{"/v1/candidates/missing/ignore", http.StatusNotFound},
		{"/v1/candidates/missing/restore", http.StatusBadRequest},
		{"/v1/candidates/missing/enroll", http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodPost, tt.endpoint, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != tt.want {
			t.Errorf("POST %s = %d, want %d (%s)", tt.endpoint, response.Code, tt.want, response.Body.String())
		}
	}
}

func TestCandidateIgnoreAndRestoreRoundTrip(t *testing.T) {
	inbox := candidates.New(candidates.Options{})
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.5", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		startedAt: time.Now(), engine: engine, inbox: inbox,
		store:  &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := api.routes()
	id := ingested.Candidate.ID

	post := func(path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		return response
	}

	if response := post("/v1/candidates/" + id + "/ignore"); response.Code != http.StatusOK {
		t.Fatalf("ignore = %d %s", response.Code, response.Body.String())
	}
	// Ignoring twice is a conflict, not a silent no-op.
	if response := post("/v1/candidates/" + id + "/ignore"); response.Code != http.StatusConflict {
		t.Fatalf("repeat ignore = %d %s", response.Code, response.Body.String())
	}
	if response := post("/v1/candidates/" + id + "/restore"); response.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", response.Code, response.Body.String())
	}
	// An ignored candidate cannot be enrolled until it is restored.
	if response := post("/v1/candidates/" + id + "/ignore"); response.Code != http.StatusOK {
		t.Fatalf("second ignore = %d %s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+id+"/enroll",
		strings.NewReader(`{"name":"mac","host":"192.0.2.5","user":"user","port":22,"fingerprint":"SHA256:x","credential_source":"runtime"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "restore it before enrollment") {
		t.Fatalf("enroll of an ignored candidate = %d %s", response.Code, response.Body.String())
	}
}

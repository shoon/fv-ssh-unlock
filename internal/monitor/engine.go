// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var ErrAlreadyRunning = errors.New("monitor is already running")

type managedDevice struct {
	device Device
	record DeviceRecord
	opMu   sync.Mutex
	// observed is runtime-only. The first conclusive observation after every
	// daemon start is emitted even when it matches restored durable state, so
	// operators and external collectors receive a fresh baseline.
	observed bool
}

// Engine polls configured devices, enforces automatic-unlock policy, and
// publishes durable, operator-readable state.
type Engine struct {
	prober   Prober
	unlocker Unlocker
	store    Store
	opts     Options
	sem      chan struct{}

	mu          sync.RWMutex
	devices     map[string]*managedDevice
	events      []Event
	sequence    uint64
	subscribers map[uint64]chan Event
	nextSubID   uint64
	running     bool
	stopping    bool
	runCtx      context.Context
	runWG       *sync.WaitGroup

	now func() time.Time
}

// AddDevice durably enrolls a new target. The device remains hidden from
// snapshots and polls until its initial state has been saved successfully. If
// Run is active, the new target receives its own polling schedule immediately.
func (e *Engine) AddDevice(device Device) error {
	if err := validateDevice(device); err != nil {
		return err
	}
	if device.AutoUnlock && e.unlocker == nil {
		return fmt.Errorf("device %q enables automatic unlock but no unlocker is configured", device.Name)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.devices[device.Name]; exists {
		return fmt.Errorf("duplicate monitor device %q", device.Name)
	}
	now := e.now().UTC()
	managed := &managedDevice{
		device: device,
		record: DeviceRecord{State: StateIndeterminate, StateChangedAt: now},
	}
	// The entry is temporarily present only while holding the exclusive lock so
	// persistLocked can include it. On failure it is removed before any reader,
	// subscriber, or scheduler can observe it.
	e.devices[device.Name] = managed
	if err := e.persistLocked(); err != nil {
		delete(e.devices, device.Name)
		return fmt.Errorf("persist added monitor device: %w", err)
	}
	e.emitLocked(EventDeviceAdded, device.Name, "")
	if e.running {
		e.startDeviceLocked(e.runCtx, e.runWG, device.Name)
	}
	return nil
}

// New constructs an Engine and restores durable state. Unknown state entries
// are ignored, and newly configured devices begin as indeterminate.
func New(devices []Device, prober Prober, unlocker Unlocker, store Store, opts Options) (*Engine, error) {
	if prober == nil {
		return nil, errors.New("monitor prober is required")
	}
	if store == nil {
		return nil, errors.New("monitor state store is required")
	}
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	persisted, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load monitor state: %w", err)
	}
	if persisted.Version != 0 && persisted.Version != persistentStateVersion {
		return nil, fmt.Errorf("unsupported monitor state version %d", persisted.Version)
	}

	e := &Engine{
		prober:      prober,
		unlocker:    unlocker,
		store:       store,
		opts:        opts,
		sem:         make(chan struct{}, opts.Concurrency),
		devices:     make(map[string]*managedDevice, len(devices)),
		subscribers: make(map[uint64]chan Event),
		now:         time.Now,
	}
	for _, device := range devices {
		if err := validateDevice(device); err != nil {
			return nil, err
		}
		if _, exists := e.devices[device.Name]; exists {
			return nil, fmt.Errorf("duplicate monitor device %q", device.Name)
		}
		record, ok := persisted.Devices[device.Name]
		if !ok {
			record = DeviceRecord{State: StateIndeterminate}
		}
		if !validRuntimeState(record.State) {
			return nil, fmt.Errorf("device %q has invalid persisted state %q", device.Name, record.State)
		}
		record.NextCheckAt = time.Time{}
		e.devices[device.Name] = &managedDevice{device: device, record: record}
	}
	if unlocker == nil {
		for _, device := range devices {
			if device.AutoUnlock {
				return nil, fmt.Errorf("device %q enables automatic unlock but no unlocker is configured", device.Name)
			}
		}
	}
	return e, nil
}

func validateOptions(opts Options) error {
	if opts.PollInterval <= 0 || opts.BootPollInterval <= 0 {
		return errors.New("monitor poll intervals must be positive")
	}
	if opts.ProbeTimeout <= 0 || opts.UnlockTimeout <= 0 {
		return errors.New("monitor operation timeouts must be positive")
	}
	if opts.Concurrency <= 0 {
		return errors.New("monitor concurrency must be positive")
	}
	if opts.BackoffInitial <= 0 || opts.BackoffMax < opts.BackoffInitial {
		return errors.New("monitor backoff range is invalid")
	}
	if opts.JitterFraction < 0 || opts.JitterFraction > 0.5 {
		return errors.New("monitor jitter fraction must be between 0 and 0.5")
	}
	if opts.UnlockCooldown < 0 {
		return errors.New("monitor unlock cooldown cannot be negative")
	}
	if opts.EventHistory < 0 {
		return errors.New("monitor event history cannot be negative")
	}
	return nil
}

func validateDevice(device Device) error {
	if strings.TrimSpace(device.Name) == "" || strings.TrimSpace(device.Name) != device.Name {
		return errors.New("monitor device name must be non-empty with no surrounding whitespace")
	}
	if strings.TrimSpace(device.Host) == "" || strings.TrimSpace(device.User) == "" {
		return fmt.Errorf("monitor device %q requires host and user", device.Name)
	}
	if device.Port < 0 || device.Port > 65535 {
		return fmt.Errorf("monitor device %q has invalid port", device.Name)
	}
	return nil
}

func validRuntimeState(state State) bool {
	switch state {
	case StateBooted, StateLocked, StateIndeterminate, StateUnreachable,
		StateUnlocking, StateBooting, StateCredentialFailed, StateError:
		return true
	default:
		return false
	}
}

func validProbeState(state State) bool {
	switch state {
	case StateBooted, StateLocked, StateIndeterminate, StateUnreachable:
		return true
	default:
		return false
	}
}

// Poll performs one policy-controlled observation cycle for a device.
func (e *Engine) Poll(ctx context.Context, name string) (DeviceSnapshot, error) {
	e.mu.RLock()
	managed, ok := e.devices[name]
	e.mu.RUnlock()
	if !ok {
		return DeviceSnapshot{}, fmt.Errorf("monitor device not found: %s", name)
	}

	managed.opMu.Lock()
	defer managed.opMu.Unlock()
	if err := e.acquire(ctx); err != nil {
		return e.deviceSnapshot(name), err
	}
	defer e.release()

	probeCtx, cancel := context.WithTimeout(ctx, e.opts.ProbeTimeout)
	probe, probeErr := e.prober.Probe(probeCtx, managed.device)
	cancel()
	shouldUnlock, applyErr := e.applyProbe(managed, probe, probeErr)
	if applyErr != nil {
		return e.deviceSnapshot(name), applyErr
	}
	if !shouldUnlock {
		return e.deviceSnapshot(name), probeErr
	}

	started, err := e.markUnlockStarted(managed)
	if err != nil {
		return e.deviceSnapshot(name), err
	}
	if !started {
		return e.deviceSnapshot(name), nil
	}
	unlockCtx, cancelUnlock := context.WithTimeout(ctx, e.opts.UnlockTimeout)
	result, unlockErr := e.unlocker.Unlock(unlockCtx, managed.device)
	cancelUnlock()
	if err := e.applyUnlockResult(managed, result, unlockErr); err != nil {
		return e.deviceSnapshot(name), err
	}
	return e.deviceSnapshot(name), unlockErr
}

func (e *Engine) acquire(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) release() { <-e.sem }

func (e *Engine) applyProbe(managed *managedDevice, result ProbeResult, probeErr error) (bool, error) {
	now := e.now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	previous := managed.record
	before := previous.State
	wasLatched := managed.record.Latched
	firstObservation := !managed.observed
	observationProduced := false
	var invalidStateErr error
	record := &managed.record
	record.LastCheckedAt = now
	record.Detail = boundedText(result.Detail)
	record.LastError = ""
	record.EndpointDown = result.EndpointDown

	if probeErr != nil {
		kind := FailureKindOf(probeErr)
		// Reaching TCP again ends the cheap endpoint-down phase. Do not carry
		// what may be hours of five-second outage probes into the SSH handshake
		// backoff: the first reachable-but-unsuccessful handshake starts a fresh
		// failure sequence.
		if previous.EndpointDown && !result.EndpointDown {
			record.ConsecutiveFailures = 0
		}
		record.ConsecutiveFailures++
		record.LastError = boundedText(probeErr.Error())
		switch kind {
		case FailureUnreachable:
			record.State = StateUnreachable
			record.LastObservation = StateUnreachable
			observationProduced = true
		case FailureCredential:
			record.State = StateCredentialFailed
			e.latchLocked(record, kind, probeErr)
		case FailureHostKey:
			record.State = StateError
			e.latchLocked(record, kind, probeErr)
		default:
			record.State = StateError
		}
	} else if !validProbeState(result.State) {
		invalidStateErr = fmt.Errorf("prober returned invalid state %q", result.State)
		record.State = StateError
		record.ConsecutiveFailures++
		record.LastError = invalidStateErr.Error()
	} else {
		observationProduced = true
		record.LastObservation = result.State
		// An error-free unreachable observation is still a failed contact, so
		// it must escalate the backoff instead of resetting the counter the
		// arm below would immediately set back to one.
		if result.State != StateUnreachable {
			record.ConsecutiveFailures = 0
		}
		switch result.State {
		case StateBooted:
			record.State = StateBooted
			record.LockEpisodeOpen = false
			record.UnlockAttempted = false
			record.UnlockConnectFailures = 0
		case StateLocked:
			if !record.LockEpisodeOpen {
				record.LockEpisode++
				record.LockEpisodeOpen = true
				record.UnlockAttempted = false
			}
			record.State = StateLocked
		case StateIndeterminate:
			record.State = StateIndeterminate
		case StateUnreachable:
			record.State = StateUnreachable
			record.ConsecutiveFailures++
		}
	}
	// Continue password-free observation while latched, but keep the
	// operator-visible security failure until it is explicitly cleared.
	// Otherwise a routine locked or unreachable probe would obscure the latch
	// even though automatic action remains suppressed.
	if record.Latched {
		record.State = stateForLatch(record.LatchKind)
	}
	if record.State != before {
		record.StateChangedAt = now
	}
	// Avoid rewriting an SD card on every healthy poll. Routine timestamps,
	// details, and in-memory backoff counters are persisted opportunistically
	// with the next security-relevant transition; episode, attempt, cooldown,
	// and latch changes are always durable before an unlock can occur.
	if persistenceRelevantChanged(previous, *record) {
		if err := e.persistLocked(); err != nil {
			return false, fmt.Errorf("persist probe state: %w", err)
		}
	}
	e.emitLocked(EventProbe, managed.device.Name, record.Detail)
	if observationProduced {
		managed.observed = true
	}
	if observationProduced && (firstObservation || record.LastObservation != previous.LastObservation) {
		e.emitLocked(EventObservationChanged, managed.device.Name, stateEventMessage(record))
	}
	if record.State != before {
		e.emitLocked(EventStateChanged, managed.device.Name, stateEventMessage(record))
	}
	if record.Latched != wasLatched {
		e.emitLocked(EventLatchChanged, managed.device.Name, record.LatchReason)
	}
	shouldUnlock := probeErr == nil && result.State == StateLocked && managed.device.AutoUnlock &&
		!record.Latched && !record.UnlockAttempted && !now.Before(record.NextUnlockEligibleAt)
	return shouldUnlock, invalidStateErr
}

func stateForLatch(kind FailureKind) State {
	if kind == FailureCredential {
		return StateCredentialFailed
	}
	return StateError
}

func stateForObservation(observation State) State {
	if validProbeState(observation) {
		return observation
	}
	return StateIndeterminate
}

func persistenceRelevantChanged(before, after DeviceRecord) bool {
	return before.State != after.State ||
		before.LastObservation != after.LastObservation ||
		!before.StateChangedAt.Equal(after.StateChangedAt) ||
		!before.LastUnlockAttemptAt.Equal(after.LastUnlockAttemptAt) ||
		!before.NextUnlockEligibleAt.Equal(after.NextUnlockEligibleAt) ||
		before.LockEpisode != after.LockEpisode ||
		before.LockEpisodeOpen != after.LockEpisodeOpen ||
		before.UnlockAttempted != after.UnlockAttempted ||
		before.UnlockConnectFailures != after.UnlockConnectFailures ||
		before.EndpointDown != after.EndpointDown ||
		before.Latched != after.Latched ||
		before.LatchKind != after.LatchKind ||
		before.LatchReason != after.LatchReason
}

func (e *Engine) markUnlockStarted(managed *managedDevice) (bool, error) {
	now := e.now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	record := &managed.record
	// Recheck policy while holding the state lock. This is intentionally
	// fail-closed even though the per-device operation lock normally makes a
	// concurrent change impossible.
	if record.State != StateLocked || record.Latched || record.UnlockAttempted ||
		!managed.device.AutoUnlock || now.Before(record.NextUnlockEligibleAt) {
		return false, nil
	}
	record.UnlockAttempted = true
	record.LastUnlockAttemptAt = now
	record.NextUnlockEligibleAt = now.Add(e.opts.UnlockCooldown)
	record.State = StateUnlocking
	record.StateChangedAt = now
	if err := e.persistLocked(); err != nil {
		// Never release a credential if the attempt marker was not durable.
		record.State = StateError
		record.StateChangedAt = now
		record.LastError = boundedText(fmt.Sprintf("persist unlock attempt: %v", err))
		// Emit the transition like every other one: a SIEM or TUI consumer must
		// not miss a device dropping into the error state.
		e.emitLocked(EventStateChanged, managed.device.Name, stateEventMessage(record))
		return false, fmt.Errorf("persist unlock attempt: %w", err)
	}
	e.emitLocked(EventUnlockStarted, managed.device.Name, "automatic unlock authorized after definitive FileVault detection")
	return true, nil
}

func (e *Engine) applyUnlockResult(managed *managedDevice, result UnlockResult, unlockErr error) error {
	now := e.now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	record := &managed.record
	before := record.State
	record.Detail = boundedText(result.Detail)
	record.LastError = ""
	var contractErr error
	if unlockErr != nil {
		record.LastError = boundedText(unlockErr.Error())
	}

	// Explicit credential and host-key failures always beat an ambiguous
	// Accepted flag. These failures require operator acknowledgement.
	kind := FailureKindOf(unlockErr)
	switch {
	case unlockErr != nil && kind == FailureCredential:
		record.State = StateCredentialFailed
		e.latchLocked(record, kind, unlockErr)
	case unlockErr != nil && kind == FailureHostKey:
		record.State = StateError
		e.latchLocked(record, kind, unlockErr)
	case result.Accepted:
		record.State = StateBooting
		record.UnlockConnectFailures = 0
	case unlockErr != nil && kind == FailureUnreachable:
		record.State = StateUnreachable
		record.ConsecutiveFailures++
		e.markPreSubmissionRetryLocked(record, now)
	case unlockErr != nil:
		record.State = StateError
		record.ConsecutiveFailures++
		// By contract, Accepted=false means the adapter knows it did not
		// submit a credential. Unclassified errors are still delayed by the
		// same bounded backoff before another connection attempt.
		e.markPreSubmissionRetryLocked(record, now)
	default:
		record.State = StateError
		contractErr = errors.New("unlocker returned neither acceptance nor an error")
		record.LastError = contractErr.Error()
	}
	if record.State != before {
		record.StateChangedAt = now
	}
	if err := e.persistLocked(); err != nil {
		return fmt.Errorf("persist unlock result: %w", err)
	}
	resultMessage := record.LastError
	if resultMessage == "" {
		resultMessage = record.Detail
	}
	e.emitLocked(EventUnlockResult, managed.device.Name, resultMessage)
	if record.State != before {
		e.emitLocked(EventStateChanged, managed.device.Name, stateEventMessage(record))
	}
	if record.Latched {
		e.emitLocked(EventLatchChanged, managed.device.Name, record.LatchReason)
	}
	return contractErr
}

func stateEventMessage(record *DeviceRecord) string {
	if record.LastError != "" {
		return record.LastError
	}
	return record.Detail
}

func (e *Engine) markPreSubmissionRetryLocked(record *DeviceRecord, now time.Time) {
	record.UnlockAttempted = false
	record.UnlockConnectFailures++
	record.NextUnlockEligibleAt = now.Add(exponentialBackoff(
		e.opts.BackoffInitial,
		e.opts.BackoffMax,
		record.UnlockConnectFailures,
	))
}

func (e *Engine) latchLocked(record *DeviceRecord, kind FailureKind, err error) {
	record.Latched = true
	record.LatchKind = kind
	record.LatchReason = boundedText(err.Error())
}

// ClearLatch explicitly acknowledges a credential or host-key failure. It can
// also acknowledge an in-progress attempt left behind by a controller crash.
// If the device is still definitively locked, either action permits one
// deliberate retry of that episode, subject to the persisted cooldown.
func (e *Engine) ClearLatch(name string) error {
	e.mu.RLock()
	managed, ok := e.devices[name]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("monitor device not found: %s", name)
	}
	managed.opMu.Lock()
	defer managed.opMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !managed.record.Latched && (!managed.record.LockEpisodeOpen || !managed.record.UnlockAttempted) {
		return nil
	}
	previous := managed.record
	managed.record.Latched = false
	managed.record.LatchKind = ""
	managed.record.LatchReason = ""
	managed.record.LastError = ""
	nextState := stateForObservation(managed.record.LastObservation)
	if managed.record.LockEpisodeOpen {
		managed.record.UnlockAttempted = false
	}
	if managed.record.State != nextState {
		managed.record.State = nextState
		managed.record.StateChangedAt = e.now().UTC()
	}
	if err := e.persistLocked(); err != nil {
		managed.record = previous
		return fmt.Errorf("persist cleared latch: %w", err)
	}
	e.emitLocked(EventLatchChanged, name, "latch cleared by operator")
	return nil
}

// RunOnce polls every configured device with bounded concurrency and returns
// an error map keyed by device name. Policy failures remain visible even when
// another device succeeds.
func (e *Engine) RunOnce(ctx context.Context) map[string]error {
	names := e.deviceNames()
	errs := make(map[string]error)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, name := range names {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Poll(ctx, name)
			if err != nil {
				mu.Lock()
				errs[name] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errs
}

// Run starts one independent polling schedule per device and blocks until ctx
// is cancelled. All network and unlock work remains bounded by Concurrency.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.running || e.stopping {
		e.mu.Unlock()
		return ErrAlreadyRunning
	}
	e.running = true
	e.runCtx = ctx
	e.runWG = &sync.WaitGroup{}
	wg := e.runWG
	for name := range e.devices {
		e.startDeviceLocked(ctx, wg, name)
	}
	e.mu.Unlock()
	<-ctx.Done()

	// Changing running under the same lock used by AddDevice closes the gate
	// before Wait begins: every dynamic Add has either registered its goroutine
	// with wg already, or observes running=false and does not call Add.
	e.mu.Lock()
	e.running = false
	e.stopping = true
	e.mu.Unlock()
	wg.Wait()
	e.mu.Lock()
	e.stopping = false
	e.runCtx = nil
	e.runWG = nil
	e.mu.Unlock()
	return nil
}

// startDeviceLocked must be called with e.mu held while the engine is running.
// That lock serializes WaitGroup.Add with Run's transition to stopping.
func (e *Engine) startDeviceLocked(ctx context.Context, wg *sync.WaitGroup, name string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.runDevice(ctx, name)
	}()
}

func (e *Engine) runDevice(ctx context.Context, name string) {
	for {
		if ctx.Err() != nil {
			return
		}
		_, _ = e.Poll(ctx, name)
		delay := e.nextDelay(name)
		next := e.now().UTC().Add(delay)
		e.mu.Lock()
		if managed := e.devices[name]; managed != nil {
			managed.record.NextCheckAt = next
		}
		e.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (e *Engine) nextDelay(name string) time.Duration {
	e.mu.RLock()
	managed := e.devices[name]
	record := managed.record
	device := managed.device
	e.mu.RUnlock()
	base := e.opts.PollInterval
	if record.State == StateBooting || record.State == StateUnlocking {
		base = e.opts.BootPollInterval
	} else if record.State == StateUnreachable && record.EndpointDown && device.AutoUnlock {
		// A cheap TCP preflight has proved the SSH endpoint is down. Check it
		// on the boot cadence so recovery after a power event is prompt; the
		// adapter must still complete a pinned SSH probe before any credential
		// policy can run.
		base = e.opts.BootPollInterval
	} else if record.ConsecutiveFailures > 0 {
		base = exponentialBackoff(e.opts.BackoffInitial, e.opts.BackoffMax, record.ConsecutiveFailures)
	}
	if e.opts.DisableJitter || e.opts.JitterFraction == 0 {
		return base
	}
	return jitter(base, e.opts.JitterFraction)
}

func exponentialBackoff(initial, maximum time.Duration, failures int) time.Duration {
	if failures <= 1 {
		return initial
	}
	value := initial
	for i := 1; i < failures; i++ {
		if value >= maximum/2 {
			return maximum
		}
		value *= 2
	}
	if value > maximum {
		return maximum
	}
	return value
}

func jitter(base time.Duration, fraction float64) time.Duration {
	var raw [8]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return base
	}
	u := float64(binary.BigEndian.Uint64(raw[:])) / float64(math.MaxUint64)
	factor := 1 - fraction + (2 * fraction * u)
	return time.Duration(float64(base) * factor)
}

func (e *Engine) persistLocked() error {
	state := PersistentState{Version: persistentStateVersion, Devices: make(map[string]DeviceRecord, len(e.devices))}
	for name, managed := range e.devices {
		record := managed.record
		record.NextCheckAt = time.Time{}
		state.Devices[name] = record
	}
	return e.store.Save(state)
}

func (e *Engine) deviceNames() []string {
	e.mu.RLock()
	names := make([]string, 0, len(e.devices))
	for name := range e.devices {
		names = append(names, name)
	}
	e.mu.RUnlock()
	sort.Strings(names)
	return names
}

// Snapshot returns a copy with devices sorted by name.
func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	snapshot := Snapshot{GeneratedAt: e.now().UTC(), Devices: make([]DeviceSnapshot, 0, len(e.devices))}
	for _, managed := range e.devices {
		snapshot.Devices = append(snapshot.Devices, DeviceSnapshot{Device: managed.device, DeviceRecord: managed.record})
	}
	sort.Slice(snapshot.Devices, func(i, j int) bool { return snapshot.Devices[i].Name < snapshot.Devices[j].Name })
	snapshot.Events = append([]Event(nil), e.events...)
	return snapshot
}

func (e *Engine) deviceSnapshot(name string) DeviceSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	managed := e.devices[name]
	if managed == nil {
		return DeviceSnapshot{}
	}
	return DeviceSnapshot{Device: managed.device, DeviceRecord: managed.record}
}

// Subscribe returns a best-effort event stream and an idempotent cancellation
// function. A slow subscriber drops its oldest queued event rather than
// blocking monitoring or credential policy decisions.
func (e *Engine) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer < 1 {
		buffer = 1
	}
	e.mu.Lock()
	e.nextSubID++
	id := e.nextSubID
	ch := make(chan Event, buffer)
	e.subscribers[id] = ch
	e.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.mu.Lock()
			if current, ok := e.subscribers[id]; ok {
				delete(e.subscribers, id)
				close(current)
			}
			e.mu.Unlock()
		})
	}
}

func (e *Engine) emitLocked(kind EventType, name, message string) {
	e.sequence++
	managed := e.devices[name]
	record := managed.record
	event := Event{
		Sequence:     e.sequence,
		Time:         e.now().UTC(),
		Type:         kind,
		Device:       name,
		State:        record.State,
		Observation:  record.LastObservation,
		Message:      boundedText(message),
		LockEpisode:  record.LockEpisode,
		AutoUnlock:   managed.device.AutoUnlock,
		EndpointDown: record.EndpointDown,
		Latched:      record.Latched,
		FailureKind:  record.LatchKind,
	}
	if e.opts.EventHistory > 0 {
		e.events = append(e.events, event)
		if excess := len(e.events) - e.opts.EventHistory; excess > 0 {
			copy(e.events, e.events[excess:])
			e.events = e.events[:e.opts.EventHistory]
		}
	}
	for _, ch := range e.subscribers {
		select {
		case ch <- event:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- event:
			default:
			}
		}
	}
}

func boundedText(value string) string {
	const maxRunes = 4096
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes])
}

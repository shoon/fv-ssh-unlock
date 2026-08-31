// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryStore struct {
	mu      sync.Mutex
	state   PersistentState
	saves   int
	failAt  int
	loadErr error
}

func (s *memoryStore) Load() (PersistentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return PersistentState{}, s.loadErr
	}
	return clonePersistentState(s.state), nil
}

func (s *memoryStore) Save(state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.failAt > 0 && s.saves == s.failAt {
		return errors.New("injected save failure")
	}
	s.state = clonePersistentState(state)
	return nil
}

func clonePersistentState(state PersistentState) PersistentState {
	clone := PersistentState{Version: state.Version, Devices: make(map[string]DeviceRecord, len(state.Devices))}
	for name, record := range state.Devices {
		clone.Devices[name] = record
	}
	return clone
}

type scriptedOps struct {
	mu           sync.Mutex
	probes       []probeStep
	unlocks      []unlockStep
	probeCalls   int
	unlockCalls  int
	active       atomic.Int32
	maxActive    atomic.Int32
	probeGate    <-chan struct{}
	probeEntered chan<- struct{}
}

type probeStep struct {
	result ProbeResult
	err    error
}

type unlockStep struct {
	result UnlockResult
	err    error
}

func (s *scriptedOps) Probe(ctx context.Context, _ Device) (ProbeResult, error) {
	current := s.active.Add(1)
	for {
		maximum := s.maxActive.Load()
		if current <= maximum || s.maxActive.CompareAndSwap(maximum, current) {
			break
		}
	}
	defer s.active.Add(-1)
	if s.probeEntered != nil {
		select {
		case s.probeEntered <- struct{}{}:
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}
	if s.probeGate != nil {
		select {
		case <-s.probeGate:
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeCalls++
	if len(s.probes) == 0 {
		return ProbeResult{State: StateIndeterminate}, nil
	}
	step := s.probes[0]
	s.probes = s.probes[1:]
	return step.result, step.err
}

func (s *scriptedOps) Unlock(context.Context, Device) (UnlockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlockCalls++
	if len(s.unlocks) == 0 {
		return UnlockResult{Accepted: true}, nil
	}
	step := s.unlocks[0]
	s.unlocks = s.unlocks[1:]
	return step.result, step.err
}

func testOptions() Options {
	opts := DefaultOptions()
	opts.DisableJitter = true
	opts.UnlockCooldown = 0
	opts.EventHistory = 20
	return opts
}

func testDevice(autoUnlock bool) Device {
	return Device{Name: "m4alpha", Host: "192.0.2.10", User: "admin", AutoUnlock: autoUnlock, CredentialRef: "systemd:m4alpha"}
}

func newTestEngine(t *testing.T, device Device, ops *scriptedOps, store Store, opts Options) *Engine {
	t.Helper()
	engine, err := New([]Device{device}, ops, ops, store, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

func TestAutoUnlockOnlyDefinitiveLockedWithOptIn(t *testing.T) {
	states := []State{StateBooted, StateIndeterminate, StateUnreachable}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			ops := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: state}}}}
			engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
			if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
				t.Fatalf("Poll: %v", err)
			}
			if ops.unlockCalls != 0 {
				t.Fatalf("state %s caused %d unlock calls", state, ops.unlockCalls)
			}
		})
	}

	ops := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: StateLocked}}}}
	engine := newTestEngine(t, testDevice(false), ops, &memoryStore{}, testOptions())
	snapshot, err := engine.Poll(context.Background(), "m4alpha")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if snapshot.State != StateLocked || ops.unlockCalls != 0 {
		t.Fatalf("opt-out result state=%s unlocks=%d", snapshot.State, ops.unlockCalls)
	}

	ops = &scriptedOps{
		probes:  []probeStep{{result: ProbeResult{State: StateLocked}}},
		unlocks: []unlockStep{{result: UnlockResult{Accepted: true}}},
	}
	engine = newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
	snapshot, err = engine.Poll(context.Background(), "m4alpha")
	if err != nil {
		t.Fatalf("Poll locked: %v", err)
	}
	if snapshot.State != StateBooting || ops.unlockCalls != 1 {
		t.Fatalf("locked opt-in result state=%s unlocks=%d", snapshot.State, ops.unlockCalls)
	}
}

func TestOneUnlockPerObservedLockEpisode(t *testing.T) {
	ops := &scriptedOps{
		probes: []probeStep{
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateUnreachable}},
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateBooted}},
			{result: ProbeResult{State: StateLocked}},
		},
		unlocks: []unlockStep{{result: UnlockResult{Accepted: true}}, {result: UnlockResult{Accepted: true}}},
	}
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
	for i := 0; i < 6; i++ {
		if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
	}
	if ops.unlockCalls != 2 {
		t.Fatalf("unlock calls=%d, want 2 across two boot-separated episodes", ops.unlockCalls)
	}
	record := engine.Snapshot().Devices[0].DeviceRecord
	if record.LockEpisode != 2 || !record.UnlockAttempted || !record.LockEpisodeOpen {
		t.Fatalf("unexpected episode record: %+v", record)
	}
}

func TestAttemptMarkerMustPersistBeforeUnlock(t *testing.T) {
	store := &memoryStore{failAt: 2} // probe state saves first; attempt marker saves second
	ops := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: StateLocked}}}}
	engine := newTestEngine(t, testDevice(true), ops, store, testOptions())
	_, err := engine.Poll(context.Background(), "m4alpha")
	if err == nil || !strings.Contains(err.Error(), "persist unlock attempt") {
		t.Fatalf("expected attempt persistence error, got %v", err)
	}
	if ops.unlockCalls != 0 {
		t.Fatalf("unlock called %d times despite failed durable marker", ops.unlockCalls)
	}
}

func TestCooldownAndAttemptSurviveRestart(t *testing.T) {
	store := &memoryStore{}
	opts := testOptions()
	opts.UnlockCooldown = time.Hour
	firstOps := &scriptedOps{
		probes:  []probeStep{{result: ProbeResult{State: StateLocked}}, {result: ProbeResult{State: StateBooted}}},
		unlocks: []unlockStep{{result: UnlockResult{Accepted: true}}},
	}
	first := newTestEngine(t, testDevice(true), firstOps, store, opts)
	if _, err := first.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatal(err)
	}

	secondOps := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: StateLocked}}}}
	second := newTestEngine(t, testDevice(true), secondOps, store, opts)
	snapshot, err := second.Poll(context.Background(), "m4alpha")
	if err != nil {
		t.Fatal(err)
	}
	if secondOps.unlockCalls != 0 || snapshot.LockEpisode != 2 || snapshot.NextUnlockEligibleAt.IsZero() {
		t.Fatalf("restart ignored durable cooldown: unlocks=%d snapshot=%+v", secondOps.unlockCalls, snapshot)
	}
}

func TestPreSubmissionFailureRetriesWithBackoff(t *testing.T) {
	connectionErr := NewFailure(FailureUnreachable, errors.New("dial refused before credential submission"))
	ops := &scriptedOps{
		probes: []probeStep{
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateLocked}},
		},
		unlocks: []unlockStep{
			{err: connectionErr},
			{result: UnlockResult{Accepted: true}},
		},
	}
	opts := testOptions()
	opts.UnlockCooldown = time.Hour
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, opts)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	engine.now = func() time.Time { return now }

	snapshot, err := engine.Poll(context.Background(), "m4alpha")
	if !errors.Is(err, connectionErr) {
		t.Fatalf("first Poll error=%v", err)
	}
	if snapshot.UnlockAttempted || snapshot.UnlockConnectFailures != 1 {
		t.Fatalf("pre-submission failure was treated as a credential attempt: %+v", snapshot)
	}
	wantEligible := now.Add(opts.BackoffInitial)
	if !snapshot.NextUnlockEligibleAt.Equal(wantEligible) {
		t.Fatalf("next eligibility=%s, want %s", snapshot.NextUnlockEligibleAt, wantEligible)
	}

	if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatalf("locked probe during backoff: %v", err)
	}
	if ops.unlockCalls != 1 {
		t.Fatalf("connection retried before backoff elapsed: %d calls", ops.unlockCalls)
	}

	now = wantEligible
	snapshot, err = engine.Poll(context.Background(), "m4alpha")
	if err != nil || ops.unlockCalls != 2 || snapshot.State != StateBooting || !snapshot.UnlockAttempted {
		t.Fatalf("retry after backoff: err=%v calls=%d snapshot=%+v", err, ops.unlockCalls, snapshot)
	}
}

func TestAutoUnlockEndpointDownUsesBootPollingCadence(t *testing.T) {
	ops := &scriptedOps{probes: []probeStep{{
		result: ProbeResult{State: StateUnreachable, EndpointDown: true},
		err:    NewFailure(FailureUnreachable, errors.New("SSH TCP endpoint is down")),
	}}}
	opts := testOptions()
	opts.PollInterval = time.Minute
	opts.BootPollInterval = 5 * time.Second
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, opts)
	if _, err := engine.Poll(context.Background(), "m4alpha"); err == nil {
		t.Fatal("expected the endpoint-down probe error")
	}
	if delay := engine.nextDelay("m4alpha"); delay != opts.BootPollInterval {
		t.Fatalf("endpoint-down delay=%s, want %s", delay, opts.BootPollInterval)
	}

	manual := newTestEngine(t, testDevice(false), &scriptedOps{}, &memoryStore{}, opts)
	manual.devices["m4alpha"].record = DeviceRecord{State: StateUnreachable, EndpointDown: true, ConsecutiveFailures: 3}
	if delay := manual.nextDelay("m4alpha"); delay != exponentialBackoff(opts.BackoffInitial, opts.BackoffMax, 3) {
		t.Fatalf("manual endpoint-down delay=%s, want normal failure backoff", delay)
	}
}

func TestCredentialAndHostKeyFailuresLatch(t *testing.T) {
	credentialErr := NewFailure(FailureCredential, errors.New("credential rejected"))
	ops := &scriptedOps{
		probes: []probeStep{
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateUnreachable, EndpointDown: true}, err: NewFailure(FailureUnreachable, errors.New("endpoint down"))},
			{result: ProbeResult{State: StateLocked}},
			{result: ProbeResult{State: StateLocked}},
		},
		unlocks: []unlockStep{{err: credentialErr}, {result: UnlockResult{Accepted: true}}},
	}
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
	snapshot, err := engine.Poll(context.Background(), "m4alpha")
	if !errors.Is(err, credentialErr) || snapshot.State != StateCredentialFailed || !snapshot.Latched {
		t.Fatalf("credential failure not latched: err=%v snapshot=%+v", err, snapshot)
	}
	_, _ = engine.Poll(context.Background(), "m4alpha")
	if ops.unlockCalls != 1 {
		t.Fatalf("latched device retried automatically: %d", ops.unlockCalls)
	}
	if snapshot = engine.Snapshot().Devices[0]; snapshot.State != StateCredentialFailed || !snapshot.Latched || snapshot.LastObservation != StateUnreachable {
		t.Fatalf("unreachable probe obscured credential latch: %+v", snapshot)
	}
	_, _ = engine.Poll(context.Background(), "m4alpha")
	if snapshot = engine.Snapshot().Devices[0]; snapshot.State != StateCredentialFailed || snapshot.LastObservation != StateLocked {
		t.Fatalf("locked probe obscured credential latch: %+v", snapshot)
	}
	if err := engine.ClearLatch("m4alpha"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = engine.Poll(context.Background(), "m4alpha")
	if err != nil || ops.unlockCalls != 2 || snapshot.Latched {
		t.Fatalf("explicit latch clear did not allow retry: err=%v unlocks=%d snapshot=%+v", err, ops.unlockCalls, snapshot)
	}

	hostKeyErr := NewFailure(FailureHostKey, errors.New("pinned key changed"))
	hostOps := &scriptedOps{probes: []probeStep{{err: hostKeyErr}}}
	hostEngine := newTestEngine(t, testDevice(true), hostOps, &memoryStore{}, testOptions())
	snapshot, err = hostEngine.Poll(context.Background(), "m4alpha")
	if !errors.Is(err, hostKeyErr) || snapshot.State != StateError || !snapshot.Latched || snapshot.LatchKind != FailureHostKey {
		t.Fatalf("host-key failure not latched: err=%v snapshot=%+v", err, snapshot)
	}
	if hostOps.unlockCalls != 0 {
		t.Fatalf("unlock called after host-key failure")
	}
}

func TestClearLatchRollsBackWhenPersistenceFails(t *testing.T) {
	store := &memoryStore{}
	ops := &scriptedOps{
		probes:  []probeStep{{result: ProbeResult{State: StateLocked}}},
		unlocks: []unlockStep{{err: NewFailure(FailureCredential, errors.New("credential rejected"))}},
	}
	engine := newTestEngine(t, testDevice(true), ops, store, testOptions())
	if _, err := engine.Poll(context.Background(), "m4alpha"); err == nil {
		t.Fatal("expected credential failure")
	}
	store.mu.Lock()
	store.failAt = store.saves + 1
	store.mu.Unlock()
	if err := engine.ClearLatch("m4alpha"); err == nil {
		t.Fatal("ClearLatch succeeded despite persistence failure")
	}
	snapshot := engine.Snapshot().Devices[0]
	if !snapshot.Latched || snapshot.State != StateCredentialFailed || snapshot.LatchKind != FailureCredential {
		t.Fatalf("failed clear changed live policy: %+v", snapshot)
	}
}

func TestClearLatchCanAcknowledgeCrashBeforeSubmission(t *testing.T) {
	store := &memoryStore{state: PersistentState{Version: persistentStateVersion, Devices: map[string]DeviceRecord{
		"m4alpha": {
			State: StateUnreachable, LastObservation: StateUnreachable, LockEpisode: 1,
			LockEpisodeOpen: true, UnlockAttempted: true, EndpointDown: true,
		},
	}}}
	ops := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: StateLocked}}}}
	engine := newTestEngine(t, testDevice(true), ops, store, testOptions())
	if err := engine.ClearLatch("m4alpha"); err != nil {
		t.Fatal(err)
	}
	snapshot := engine.Snapshot().Devices[0]
	if snapshot.UnlockAttempted || snapshot.State != StateUnreachable || !snapshot.LockEpisodeOpen {
		t.Fatalf("crash marker was not explicitly acknowledged: %+v", snapshot)
	}
	if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatal(err)
	}
	if ops.unlockCalls != 1 {
		t.Fatalf("explicit acknowledgement did not permit retry: %d calls", ops.unlockCalls)
	}
}

func TestEndpointRecoveryRestartsHandshakeBackoff(t *testing.T) {
	downErr := NewFailure(FailureUnreachable, errors.New("endpoint down"))
	handshakeErr := NewFailure(FailureUnreachable, errors.New("TCP open; SSH not ready"))
	ops := &scriptedOps{probes: []probeStep{
		{result: ProbeResult{State: StateUnreachable, EndpointDown: true}, err: downErr},
		{result: ProbeResult{State: StateUnreachable, EndpointDown: false}, err: handshakeErr},
	}}
	opts := testOptions()
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, opts)
	_, _ = engine.Poll(context.Background(), "m4alpha")
	engine.mu.Lock()
	engine.devices["m4alpha"].record.ConsecutiveFailures = 100
	engine.mu.Unlock()
	_, _ = engine.Poll(context.Background(), "m4alpha")
	snapshot := engine.Snapshot().Devices[0]
	if snapshot.EndpointDown || snapshot.ConsecutiveFailures != 1 {
		t.Fatalf("endpoint recovery inherited outage failures: %+v", snapshot)
	}
	if delay := engine.nextDelay("m4alpha"); delay != opts.BackoffInitial {
		t.Fatalf("post-recovery delay=%s, want initial backoff %s", delay, opts.BackoffInitial)
	}
}

func TestRunOnceBoundsConcurrency(t *testing.T) {
	const deviceCount = 7
	gate := make(chan struct{})
	entered := make(chan struct{}, deviceCount)
	ops := &scriptedOps{probeGate: gate, probeEntered: entered}
	devices := make([]Device, 0, deviceCount)
	for i := 0; i < deviceCount; i++ {
		devices = append(devices, Device{Name: fmt.Sprintf("mac-%d", i), Host: fmt.Sprintf("192.0.2.%d", i+1), User: "admin"})
	}
	opts := testOptions()
	opts.Concurrency = 2
	engine, err := New(devices, ops, ops, &memoryStore{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan map[string]error, 1)
	go func() { done <- engine.RunOnce(context.Background()) }()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-entered:
		t.Fatal("more probes started than the concurrency bound")
	case <-time.After(30 * time.Millisecond):
	}
	close(gate)
	if errs := <-done; len(errs) != 0 {
		t.Fatalf("RunOnce errors: %v", errs)
	}
	if maximum := ops.maxActive.Load(); maximum > 2 {
		t.Fatalf("maximum concurrency=%d, want <=2", maximum)
	}
}

func TestSnapshotsEventsAndSubscriptionAreJSONReady(t *testing.T) {
	ops := &scriptedOps{probes: []probeStep{{result: ProbeResult{State: StateBooted, Detail: "authenticated SSH"}}}}
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
	events, unsubscribe := engine.Subscribe(1)
	defer unsubscribe()
	if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Device != "m4alpha" {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("no subscribed event")
	}
	snapshot := engine.Snapshot()
	if len(snapshot.Devices) != 1 || len(snapshot.Events) == 0 {
		t.Fatalf("incomplete snapshot: %+v", snapshot)
	}
	if _, err := json.Marshal(snapshot); err != nil {
		t.Fatalf("snapshot JSON: %v", err)
	}
}

func TestSemanticEventsIncludeSafeStateAndUnlockSummaries(t *testing.T) {
	ops := &scriptedOps{
		probes:  []probeStep{{result: ProbeResult{State: StateLocked, Detail: "FileVault pre-boot banner detected"}}},
		unlocks: []unlockStep{{result: UnlockResult{Accepted: true, Detail: "FileVault accepted the credential"}}},
	}
	engine := newTestEngine(t, testDevice(true), ops, &memoryStore{}, testOptions())
	if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
		t.Fatal(err)
	}
	var observedLocked, locked, attempt, result bool
	for _, event := range engine.Snapshot().Events {
		switch event.Type {
		case EventObservationChanged:
			if event.Message == "FileVault pre-boot banner detected" && event.Observation == StateLocked && event.LockEpisode == 1 && event.AutoUnlock {
				observedLocked = true
			}
		case EventStateChanged:
			if event.State == StateLocked && event.Message == "FileVault pre-boot banner detected" {
				locked = true
			}
		case EventUnlockStarted:
			attempt = true
		case EventUnlockResult:
			if event.State == StateBooting && event.Message == "FileVault accepted the credential" {
				result = true
			}
		}
	}
	if !observedLocked || !locked || !attempt || !result {
		t.Fatalf("missing semantic events: observed=%v locked=%v attempt=%v result=%v events=%+v", observedLocked, locked, attempt, result, engine.Snapshot().Events)
	}
}

func TestFirstObservationEachRunRefreshesPersistedBaselineOnce(t *testing.T) {
	store := &memoryStore{state: PersistentState{
		Version: persistentStateVersion,
		Devices: map[string]DeviceRecord{
			"m4alpha": {State: StateBooted, LastObservation: StateBooted},
		},
	}}
	ops := &scriptedOps{probes: []probeStep{
		{result: ProbeResult{State: StateBooted, Detail: "normal macOS SSH accepted a public key"}},
		{result: ProbeResult{State: StateBooted, Detail: "normal macOS SSH accepted a public key"}},
	}}
	engine := newTestEngine(t, testDevice(false), ops, store, testOptions())
	for range 2 {
		if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
			t.Fatal(err)
		}
	}
	observations := 0
	for _, event := range engine.Snapshot().Events {
		if event.Type == EventObservationChanged {
			observations++
		}
	}
	if observations != 1 {
		t.Fatalf("baseline observations = %d, want exactly one; events=%+v", observations, engine.Snapshot().Events)
	}
}

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	initial, maximum := 10*time.Second, 45*time.Second
	wants := []time.Duration{initial, initial, 20 * time.Second, 40 * time.Second, maximum, maximum}
	for failures, want := range wants {
		if got := exponentialBackoff(initial, maximum, failures); got != want {
			t.Fatalf("failures=%d: got %s want %s", failures, got, want)
		}
	}
	for i := 0; i < 100; i++ {
		got := jitter(time.Minute, 0.1)
		if got < 54*time.Second || got > 66*time.Second {
			t.Fatalf("jitter outside configured range: %s", got)
		}
	}
}

func TestHealthyPollsDoNotContinuouslyRewriteState(t *testing.T) {
	store := &memoryStore{}
	ops := &scriptedOps{probes: []probeStep{
		{result: ProbeResult{State: StateBooted}},
		{result: ProbeResult{State: StateBooted}},
		{result: ProbeResult{State: StateBooted}},
	}}
	engine := newTestEngine(t, testDevice(false), ops, store, testOptions())
	for i := 0; i < 3; i++ {
		if _, err := engine.Poll(context.Background(), "m4alpha"); err != nil {
			t.Fatal(err)
		}
	}
	if store.saves != 1 {
		t.Fatalf("healthy polling performed %d state writes, want only initial transition", store.saves)
	}
}

func TestRunStopsCleanlyAndRejectsConcurrentRun(t *testing.T) {
	ops := &scriptedOps{}
	opts := testOptions()
	opts.PollInterval = 5 * time.Millisecond
	opts.BootPollInterval = 5 * time.Millisecond
	engine := newTestEngine(t, testDevice(false), ops, &memoryStore{}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		engine.mu.RLock()
		running := engine.running
		engine.mu.RUnlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := engine.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Run error=%v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestAddDevicePersistsBeforeExposureAndRollsBackFailure(t *testing.T) {
	store := &memoryStore{failAt: 1}
	ops := &scriptedOps{}
	engine := newTestEngine(t, testDevice(false), ops, store, testOptions())
	added := Device{Name: "studio", Host: "192.0.2.20", User: "admin"}
	if err := engine.AddDevice(added); err == nil {
		t.Fatal("AddDevice succeeded despite state persistence failure")
	}
	if got := engine.Snapshot(); len(got.Devices) != 1 || got.Devices[0].Name != "m4alpha" {
		t.Fatalf("failed device was exposed: %+v", got.Devices)
	}
	if _, err := engine.Poll(context.Background(), "studio"); err == nil {
		t.Fatal("failed device remained pollable")
	}

	store.failAt = 0
	if err := engine.AddDevice(added); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	store.mu.Lock()
	record, persisted := store.state.Devices["studio"]
	store.mu.Unlock()
	if !persisted || record.State != StateIndeterminate {
		t.Fatalf("initial device state was not persisted: %+v", store.state)
	}
	if err := engine.AddDevice(added); err == nil {
		t.Fatal("duplicate AddDevice succeeded")
	}
}

type dynamicRunProber struct {
	addedEntered chan struct{}
	releaseAdded chan struct{}
	once         sync.Once
}

func (p *dynamicRunProber) Probe(ctx context.Context, device Device) (ProbeResult, error) {
	if device.Name != "studio" {
		return ProbeResult{State: StateBooted}, nil
	}
	p.once.Do(func() { close(p.addedEntered) })
	// Deliberately outlive cancellation until the test releases us. This proves
	// Run waits for a dynamically registered goroutine; real adapters are
	// expected to honor ctx promptly.
	<-p.releaseAdded
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	return ProbeResult{State: StateBooted}, nil
}

func (p *dynamicRunProber) Unlock(context.Context, Device) (UnlockResult, error) {
	return UnlockResult{}, errors.New("unexpected unlock")
}

func TestAddDeviceDuringRunStartsAndJoinsPollingGoroutine(t *testing.T) {
	prober := &dynamicRunProber{addedEntered: make(chan struct{}), releaseAdded: make(chan struct{})}
	engine, err := New([]Device{testDevice(false)}, prober, prober, &memoryStore{}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	waitForRunning(t, engine)
	if err := engine.AddDevice(Device{Name: "studio", Host: "192.0.2.20", User: "admin"}); err != nil {
		t.Fatalf("AddDevice while running: %v", err)
	}
	select {
	case <-prober.addedEntered:
	case <-time.After(time.Second):
		t.Fatal("dynamically added device was not polled")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Run returned before dynamic poll ended: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(prober.releaseAdded)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not join dynamically added poller")
	}
}

func TestConcurrentAddDeviceAndShutdown(t *testing.T) {
	ops := &scriptedOps{}
	opts := testOptions()
	opts.PollInterval = time.Millisecond
	engine := newTestEngine(t, testDevice(false), ops, &memoryStore{}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	waitForRunning(t, engine)

	const additions = 64
	start := make(chan struct{})
	var adds sync.WaitGroup
	for i := 0; i < additions; i++ {
		i := i
		adds.Add(1)
		go func() {
			defer adds.Done()
			<-start
			_ = engine.AddDevice(Device{
				Name: fmt.Sprintf("dynamic-%d", i), Host: fmt.Sprintf("192.0.2.%d", 30+i), User: "admin",
			})
		}()
	}
	close(start)
	cancel()
	adds.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run deadlocked with concurrent AddDevice and shutdown")
	}
}

func waitForRunning(t *testing.T, engine *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		engine.mu.RLock()
		running := engine.running
		engine.mu.RUnlock()
		if running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsInvalidDependenciesOptionsAndDevices(t *testing.T) {
	ops := &scriptedOps{}
	store := &memoryStore{}
	opts := testOptions()
	if _, err := New(nil, nil, ops, store, opts); err == nil {
		t.Fatal("nil prober was accepted")
	}
	if _, err := New(nil, ops, ops, nil, opts); err == nil {
		t.Fatal("nil store was accepted")
	}

	invalidOptions := map[string]func(*Options){
		"poll interval":     func(o *Options) { o.PollInterval = 0 },
		"boot interval":     func(o *Options) { o.BootPollInterval = 0 },
		"probe timeout":     func(o *Options) { o.ProbeTimeout = 0 },
		"unlock timeout":    func(o *Options) { o.UnlockTimeout = 0 },
		"concurrency":       func(o *Options) { o.Concurrency = 0 },
		"backoff initial":   func(o *Options) { o.BackoffInitial = 0 },
		"backoff maximum":   func(o *Options) { o.BackoffMax = o.BackoffInitial - time.Nanosecond },
		"negative jitter":   func(o *Options) { o.JitterFraction = -0.01 },
		"excessive jitter":  func(o *Options) { o.JitterFraction = 0.51 },
		"negative cooldown": func(o *Options) { o.UnlockCooldown = -time.Second },
		"negative history":  func(o *Options) { o.EventHistory = -1 },
	}
	for name, mutate := range invalidOptions {
		t.Run(name, func(t *testing.T) {
			invalid := opts
			mutate(&invalid)
			if _, err := New(nil, ops, ops, store, invalid); err == nil {
				t.Fatal("invalid monitor options were accepted")
			}
		})
	}

	invalidDevices := map[string]Device{
		"empty name":    {Host: "192.0.2.1", User: "user"},
		"spaced name":   {Name: " mac", Host: "192.0.2.1", User: "user"},
		"empty host":    {Name: "mac", User: "user"},
		"empty user":    {Name: "mac", Host: "192.0.2.1"},
		"negative port": {Name: "mac", Host: "192.0.2.1", User: "user", Port: -1},
		"large port":    {Name: "mac", Host: "192.0.2.1", User: "user", Port: 65536},
	}
	for name, device := range invalidDevices {
		t.Run(name, func(t *testing.T) {
			if _, err := New([]Device{device}, ops, ops, store, opts); err == nil {
				t.Fatal("invalid monitor device was accepted")
			}
		})
	}
	device := testDevice(false)
	if _, err := New([]Device{device, device}, ops, ops, store, opts); err == nil {
		t.Fatal("duplicate monitor devices were accepted")
	}
	if _, err := New([]Device{testDevice(true)}, ops, nil, store, opts); err == nil {
		t.Fatal("automatic unlock without an unlocker was accepted")
	}
}

func TestNewRejectsStoreFailuresAndInvalidPersistedState(t *testing.T) {
	ops := &scriptedOps{}
	want := errors.New("load failed")
	if _, err := New(nil, ops, ops, &memoryStore{loadErr: want}, testOptions()); !errors.Is(err, want) {
		t.Fatalf("load error = %v, want %v", err, want)
	}
	if _, err := New(nil, ops, ops, &memoryStore{state: PersistentState{Version: persistentStateVersion + 1}}, testOptions()); err == nil {
		t.Fatal("unsupported persisted version was accepted")
	}
	device := testDevice(false)
	store := &memoryStore{state: PersistentState{
		Version: persistentStateVersion,
		Devices: map[string]DeviceRecord{device.Name: {State: State("unknown")}},
	}}
	if _, err := New([]Device{device}, ops, ops, store, testOptions()); err == nil {
		t.Fatal("invalid persisted device state was accepted")
	}
	store.state.Devices[device.Name] = DeviceRecord{State: StateBooted, NextCheckAt: time.Now()}
	engine, err := New([]Device{device}, ops, ops, store, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Snapshot().Devices[0].NextCheckAt; !got.IsZero() {
		t.Fatalf("transient next-check time survived restart: %s", got)
	}
}

func TestPollRejectsMissingDeviceCancelledCapacityAndInvalidProbeState(t *testing.T) {
	ops := &scriptedOps{}
	engine := newTestEngine(t, testDevice(false), ops, &memoryStore{}, testOptions())
	if _, err := engine.Poll(context.Background(), "missing"); err == nil {
		t.Fatal("missing device was polled")
	}
	for range cap(engine.sem) {
		engine.sem <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Poll(ctx, "m4alpha"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled capacity wait error = %v", err)
	}
	for range cap(engine.sem) {
		<-engine.sem
	}

	ops.probes = []probeStep{{result: ProbeResult{State: StateBooting}}}
	snapshot, err := engine.Poll(context.Background(), "m4alpha")
	if err == nil || !strings.Contains(err.Error(), "invalid state") {
		t.Fatalf("invalid probe state error = %v", err)
	}
	if snapshot.State != StateError || !strings.Contains(snapshot.LastError, "invalid state") || snapshot.LastObservation != "" {
		t.Fatalf("invalid probe state snapshot = %+v", snapshot)
	}
}

func TestPollRejectsUnlockerContractViolationAfterPersistingErrorState(t *testing.T) {
	ops := &scriptedOps{
		probes:  []probeStep{{result: ProbeResult{State: StateLocked}}},
		unlocks: []unlockStep{{result: UnlockResult{Accepted: false}}},
	}
	store := &memoryStore{}
	engine := newTestEngine(t, testDevice(true), ops, store, testOptions())
	snapshot, err := engine.Poll(context.Background(), "m4alpha")
	if err == nil || !strings.Contains(err.Error(), "neither acceptance nor an error") {
		t.Fatalf("unlocker contract error = %v", err)
	}
	if snapshot.State != StateError || !strings.Contains(snapshot.LastError, "neither acceptance nor an error") || !snapshot.UnlockAttempted {
		t.Fatalf("unlocker contract snapshot = %+v", snapshot)
	}
	store.mu.Lock()
	persisted := store.state.Devices["m4alpha"]
	store.mu.Unlock()
	if persisted.State != StateError || persisted.LastError != snapshot.LastError {
		t.Fatalf("unlocker contract failure was not persisted: %+v", persisted)
	}
}

func TestBoundedTextPreservesShortTextAndTruncatesByRune(t *testing.T) {
	if got := boundedText("short"); got != "short" {
		t.Fatalf("short text = %q", got)
	}
	input := strings.Repeat("é", 4097)
	got := boundedText(input)
	if len([]rune(got)) != 4096 || !strings.HasPrefix(input, got) {
		t.Fatalf("bounded text has %d runes", len([]rune(got)))
	}
}

func TestStateForObservationRejectsNonProbeStates(t *testing.T) {
	for _, state := range []State{StateBooted, StateLocked, StateIndeterminate, StateUnreachable} {
		if got := stateForObservation(state); got != state {
			t.Fatalf("stateForObservation(%q) = %q", state, got)
		}
	}
	for _, state := range []State{StateBooting, StateUnlocking, StateCredentialFailed, StateError, State("unknown")} {
		if got := stateForObservation(state); got != StateIndeterminate {
			t.Fatalf("stateForObservation(%q) = %q, want indeterminate", state, got)
		}
	}
}

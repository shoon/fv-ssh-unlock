// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// scriptedClient returns a scripted sequence of results, repeating the last
// entry once exhausted.
type scriptedClient struct {
	mu     sync.Mutex
	calls  int
	states []DeviceStatus
	errs   []error
}

type blockingStatusChecker struct{}

func (*blockingStatusChecker) ProbeStatus(ctx context.Context, _, _ string) (DeviceStatus, string, error) {
	<-ctx.Done()
	return StatusUnknown, "", ctx.Err()
}

func (s *scriptedClient) ProbeStatus(ctx context.Context, _, _ string) (DeviceStatus, string, error) {
	select {
	case <-ctx.Done():
		return StatusUnknown, "", ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.calls
	if i >= len(s.states) {
		i = len(s.states) - 1
	}
	s.calls++
	return s.states[i], "", s.errs[i]
}

func (s *scriptedClient) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func fastVerifyOpts() VerifyOptions {
	return VerifyOptions{
		Grace:          0,
		Window:         2 * time.Second,
		Interval:       10 * time.Millisecond,
		AttemptTimeout: time.Second,
	}
}

var testDevice = Device{Host: "host:22", User: "u", Cred: "c"}

// TestVerifyUnlockConfirmsAfterBoot models the real sequence: the device is
// unreachable while booting, then answers as a normal SSH host.
func TestVerifyUnlockConfirmsAfterBoot(t *testing.T) {
	client := &scriptedClient{
		states: []DeviceStatus{StatusUnknown, StatusUnknown, StatusUnlockedRecently},
		errs:   []error{ErrConnectionRefused, ErrConnectionRefused, nil},
	}
	ok, err := VerifyUnlock(context.Background(), client, testDevice, fastVerifyOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected verification to succeed once the device booted")
	}
	if client.count() < 3 {
		t.Errorf("expected polling until booted, got %d attempts", client.count())
	}
}

// TestVerifyUnlockUnconfirmedIsNotAnError: a device that never comes back within
// the window is "not confirmed", not a failure.
func TestVerifyUnlockUnconfirmedIsNotAnError(t *testing.T) {
	client := &scriptedClient{
		states: []DeviceStatus{StatusUnknown},
		errs:   []error{ErrConnectionRefused},
	}
	opts := fastVerifyOpts()
	opts.Window = 100 * time.Millisecond

	ok, err := VerifyUnlock(context.Background(), client, testDevice, opts)
	if err != nil {
		t.Fatalf("an unconfirmed verification must not be an error, got %v", err)
	}
	if ok {
		t.Fatalf("expected verification to be unconfirmed")
	}
}

func TestVerifyUnlockWindowBoundsAnAttempt(t *testing.T) {
	opts := fastVerifyOpts()
	opts.Window = 50 * time.Millisecond
	opts.AttemptTimeout = time.Second
	started := time.Now()
	ok, err := VerifyUnlock(context.Background(), &blockingStatusChecker{}, testDevice, opts)
	if err != nil || ok {
		t.Fatalf("window expiry should be unconfirmed, got ok=%v err=%v", ok, err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("verification overran its window: %v", elapsed)
	}
}

// TestVerifyUnlockAbortsOnHostKeyMismatch: a host-key change is fatal and must
// stop the retry loop immediately.
func TestVerifyUnlockAbortsOnHostKeyMismatch(t *testing.T) {
	client := &scriptedClient{
		states: []DeviceStatus{StatusUnknown},
		errs:   []error{fmt.Errorf("%w for host: bad key", ErrHostKeyMismatch)},
	}
	ok, err := VerifyUnlock(context.Background(), client, testDevice, fastVerifyOpts())
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("expected ErrHostKeyMismatch, got %v", err)
	}
	if ok {
		t.Fatalf("must not report verified on a host-key mismatch")
	}
	if client.count() != 1 {
		t.Errorf("must not retry past a host-key mismatch; got %d attempts", client.count())
	}
}

func TestVerifyUnlockHonorsContextCancellation(t *testing.T) {
	client := &scriptedClient{
		states: []DeviceStatus{StatusUnknown},
		errs:   []error{ErrConnectionRefused},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := VerifyUnlock(ctx, client, testDevice, fastVerifyOpts())
	if err == nil {
		t.Fatalf("expected a context error")
	}
	if ok {
		t.Fatalf("must not report verified when cancelled")
	}
}

func TestVerifyUnlockStopsWhenPasswordWouldBeRequired(t *testing.T) {
	client := &scriptedClient{states: []DeviceStatus{StatusUnknown}, errs: []error{ErrIndeterminate}}
	ok, err := VerifyUnlock(context.Background(), client, testDevice, fastVerifyOpts())
	if !errors.Is(err, ErrIndeterminate) || ok {
		t.Fatalf("expected password-free indeterminate result, got ok=%v err=%v", ok, err)
	}
	if client.count() != 1 {
		t.Fatalf("indeterminate verification should stop immediately")
	}
}

func TestVerifyUnlockDisabledByZeroWindow(t *testing.T) {
	client := &scriptedClient{states: []DeviceStatus{StatusUnlockedRecently}, errs: []error{nil}}
	opts := fastVerifyOpts()
	opts.Window = 0

	ok, err := VerifyUnlock(context.Background(), client, testDevice, opts)
	if err != nil || ok {
		t.Fatalf("a zero window must disable verification cleanly, got ok=%v err=%v", ok, err)
	}
	if client.count() != 0 {
		t.Errorf("must not connect when verification is disabled")
	}
}

// TestProbeStatusIndeterminateWithoutBanner covers the case that a booted sshd
// also prompts for a password: without the locked banner we must NOT claim the
// device is locked.
func TestProbeStatusIndeterminateWithoutBanner(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "pw", noBanner: true})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if status == StatusLocked {
		t.Fatalf("a password prompt without the locked banner must not be reported as locked")
	}
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("expected ErrIndeterminate, got %v", err)
	}
	if len(ts.gotPass) != 0 {
		t.Errorf("ProbeStatus must never send a password")
	}
}

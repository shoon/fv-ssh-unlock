// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockStore struct {
	pw  string
	err error
}

func (m *mockStore) Get(name string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.pw, nil
}

type seqSSHClient struct {
	calls int
	outs  []string
	errs  []error
}

func (s *seqSSHClient) AnalyzePrompt(ctx context.Context, host, user, password, successMsg string) (DeviceStatus, string, error) {
	// Check if context is already cancelled before proceeding
	select {
	case <-ctx.Done():
		return StatusUnknown, "", ctx.Err()
	default:
	}

	i := s.calls
	if i >= len(s.outs) {
		i = len(s.outs) - 1
	}
	s.calls++
	return ParseOutput(s.outs[i]), s.outs[i], s.errs[i]
}

func (s *seqSSHClient) ProbeStatus(ctx context.Context, host, user string) (DeviceStatus, string, error) {
	select {
	case <-ctx.Done():
		return StatusUnknown, "", ctx.Err()
	default:
	}
	i := s.calls
	if i >= len(s.outs) {
		i = len(s.outs) - 1
	}
	s.calls++
	return ParseOutput(s.outs[i]), s.outs[i], s.errs[i]
}

func TestUnlockSequence(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{pw: "secret"}
	client := &seqSSHClient{
		outs: []string{"This system is locked. Enter password:", "System successfully unlocked."},
		errs: []error{nil, nil},
	}

	res := Unlock(ctx, client, store, "host1", "user", "cred", "", 5*time.Second)
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if res.Status != StatusLocked {
		t.Fatalf("expected locked status, got %v", res.Status)
	}
}

func TestUnlockCredentialError(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{err: errors.New("no cred")}
	client := &seqSSHClient{}

	res := Unlock(ctx, client, store, "host1", "user", "cred", "", 1*time.Second)
	if res.Error == nil {
		t.Fatalf("expected error due to missing credential, got nil")
	}
}

func TestCheckStatusUsesClient(t *testing.T) {
	ctx := context.Background()
	client := &seqSSHClient{
		outs: []string{"Last login: user@host"},
		errs: []error{nil},
	}

	st, out, err := CheckStatus(ctx, client, "h", "u", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st != StatusUnlockedRecently {
		t.Fatalf("unexpected status: %v", st)
	}
	if out == "" {
		t.Fatalf("expected output")
	}
}

// Additional tests for Unlock function

func TestUnlockSSHClientError(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{pw: "secret"}
	client := &seqSSHClient{
		outs: []string{"ssh connection error output"},
		errs: []error{errors.New("ssh connection failed")},
	}

	res := Unlock(ctx, client, store, "host1", "user", "cred", "", 5*time.Second)
	if res.Error == nil {
		t.Fatalf("expected ssh client error, got nil")
	}
	if res.Error.Error() != "ssh connection failed" {
		t.Errorf("unexpected error message: %v", res.Error)
	}
	if res.Status != StatusUnknown {
		t.Errorf("expected StatusUnknown, got %v", res.Status)
	}
	if res.Output == "" {
		t.Error("expected output even with error")
	}
}

func TestUnlockContextTimeout(t *testing.T) {
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel it immediately

	store := &mockStore{pw: "secret"}
	client := &seqSSHClient{
		outs: []string{""},
		errs: []error{nil},
	}

	res := Unlock(ctx, client, store, "host1", "user", "cred", "", 5*time.Second)
	// When context is cancelled, we expect an error
	if res.Error == nil {
		t.Fatalf("expected context cancelled error, got nil")
	}
}

func TestUnlockWithSuccessMessage(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{pw: "secret"}
	client := &seqSSHClient{
		outs: []string{"This system is locked. Enter password:", "successfully unlocked"},
		errs: []error{nil, nil},
	}

	res := Unlock(ctx, client, store, "host1", "user", "cred", "successfully unlocked", 5*time.Second)
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if res.Status != StatusLocked {
		t.Fatalf("expected locked status, got %v", res.Status)
	}
}

// Additional tests for DeviceStatus enum

func TestDeviceStatusString(t *testing.T) {
	cases := []struct {
		status DeviceStatus
		want   string
	}{
		{StatusUnknown, "unknown"},
		{StatusLocked, "locked"},
		{StatusUnlocked, "unlocked"},
		{StatusUnlockedRecently, "recently unlocked"},
		{DeviceStatus(999), "unknown"}, // Test default case
	}

	for _, c := range cases {
		got := c.status.String()
		if got != c.want {
			t.Errorf("DeviceStatus(%d).String() = %q, want %q", int(c.status), got, c.want)
		}
	}
}

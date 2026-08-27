// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockSSHClientForUnlock implements SSHClient for testing the Unlock functions.
type mockSSHClientForUnlock struct {
	status DeviceStatus
	output string
	err    error

	callCount int
	mu        sync.Mutex
}

func (m *mockSSHClientForUnlock) AnalyzePrompt(_ context.Context, _, _, _, _ string) (DeviceStatus, string, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	return m.status, m.output, m.err
}

func TestUnlockManySequential(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{status: StatusUnlocked, output: "System successfully unlocked."}
	store := &mockStore{pw: "secret"}

	devices := []Device{
		{Host: "host1", User: "user1", Cred: "cred1"},
		{Host: "host2", User: "user2", Cred: "cred2"},
		{Host: "host3", User: "user3", Cred: "cred3"},
	}

	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 1)
	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}
	// Results must be aligned with the input order.
	for i, device := range devices {
		if results[i].Host != device.Host {
			t.Errorf("result %d: expected host %q, got %q", i, device.Host, results[i].Host)
		}
		if results[i].Error != nil {
			t.Errorf("result for %q has unexpected error: %v", device.Host, results[i].Error)
		}
		if results[i].Status != StatusUnlocked {
			t.Errorf("result for %q expected StatusUnlocked, got %v", device.Host, results[i].Status)
		}
	}
}

func TestUnlockManyConcurrent(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{status: StatusUnlocked, output: "System successfully unlocked."}
	store := &mockStore{pw: "secret"}

	devices := []Device{
		{Host: "host1", User: "user1", Cred: "cred1"},
		{Host: "host2", User: "user2", Cred: "cred2"},
		{Host: "host3", User: "user3", Cred: "cred3"},
		{Host: "host4", User: "user4", Cred: "cred4"},
		{Host: "host5", User: "user5", Cred: "cred5"},
	}

	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 3)
	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}
	// Even under concurrency, results must be aligned with the input order.
	for i, device := range devices {
		if results[i].Host != device.Host {
			t.Errorf("result %d: expected host %q, got %q", i, device.Host, results[i].Host)
		}
		if results[i].Status != StatusUnlocked {
			t.Errorf("result for %q expected StatusUnlocked, got %v", device.Host, results[i].Status)
		}
	}
	if client.callCount != len(devices) {
		t.Errorf("expected %d client calls, got %d", len(devices), client.callCount)
	}
}

func TestUnlockManyConcurrentWithError(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{status: StatusUnknown, err: errors.New("connection failed")}
	store := &mockStore{pw: "secret"}

	devices := []Device{
		{Host: "host1", User: "user1", Cred: "cred1"},
		{Host: "host2", User: "user2", Cred: "cred2"},
	}

	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 2)
	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}
	for i := range devices {
		if results[i].Error == nil {
			t.Errorf("result for %q expected an error", results[i].Host)
		}
	}
}

func TestUnlockManyCredentialError(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{}
	store := &mockStore{err: errors.New("credential not found")}

	devices := []Device{{Host: "host1", User: "user1", Cred: "cred1"}}
	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 1)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil || results[0].Error.Error() != "credential not found" {
		t.Fatalf("expected credential error, got %v", results[0].Error)
	}
}

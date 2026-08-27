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

// TestUnlockWithDifferentStatuses tests Unlock function with different device statuses
func TestUnlockWithDifferentStatuses(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{pw: "secret"}

	cases := []struct {
		name        string
		client      *seqSSHClient
		wantStatus  DeviceStatus
		wantErr     error
		description string
	}{
		{
			name: "locked device",
			client: &seqSSHClient{
				outs: []string{"This system is locked. Enter password:"},
				errs: []error{nil},
			},
			wantStatus:  StatusLocked,
			wantErr:     nil,
			description: "Tests unlock with a locked device status",
		},
		{
			name: "unlocked device",
			client: &seqSSHClient{
				outs: []string{"System successfully unlocked."},
				errs: []error{nil},
			},
			wantStatus:  StatusUnlocked,
			wantErr:     nil,
			description: "Tests unlock with a device that reports success",
		},
		{
			name: "password prompt means locked",
			client: &seqSSHClient{
				outs: []string{"Password:"},
				errs: []error{nil},
			},
			wantStatus:  StatusLocked,
			wantErr:     nil,
			description: "A bare password prompt indicates a locked device, never unlocked",
		},
		{
			name: "recently unlocked device",
			client: &seqSSHClient{
				outs: []string{"Last login: user@host"},
				errs: []error{nil},
			},
			wantStatus:  StatusUnlockedRecently,
			wantErr:     nil,
			description: "Tests unlock with a recently unlocked device",
		},
		{
			name: "unknown status device",
			client: &seqSSHClient{
				outs: []string{"Unknown prompt"},
				errs: []error{nil},
			},
			wantStatus:  StatusUnknown,
			wantErr:     nil,
			description: "Tests unlock with an unknown device status",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := Unlock(ctx, c.client, store, "testhost", "testuser", "testcred", "", 5*time.Second)

			if c.wantErr != nil {
				if result.Error == nil {
					t.Fatalf("expected error %v, got nil", c.wantErr)
				}
				if !errors.Is(result.Error, c.wantErr) {
					t.Fatalf("expected error %v, got %v", c.wantErr, result.Error)
				}
			} else if result.Error != nil {
				t.Fatalf("unexpected error: %v", result.Error)
			}

			if result.Status != c.wantStatus {
				t.Errorf("expected status %v, got %v", c.wantStatus, result.Status)
			}

			if result.Host != "testhost" {
				t.Errorf("expected host testhost, got %q", result.Host)
			}
		})
	}
}

// TestCheckStatus tests the CheckStatus function
func TestCheckStatus(t *testing.T) {
	ctx := context.Background()
	client := &seqSSHClient{
		outs: []string{"Last login: user@host"},
		errs: []error{nil},
	}

	status, output, err := CheckStatus(ctx, client, "testhost", "testuser", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlockedRecently {
		t.Errorf("expected StatusUnlockedRecently, got %v", status)
	}
	if output != "Last login: user@host" {
		t.Errorf("expected output 'Last login: user@host', got %q", output)
	}
}

// TestCheckStatusWithError tests the CheckStatus function with errors
func TestCheckStatusWithError(t *testing.T) {
	ctx := context.Background()
	client := &seqSSHClient{
		outs: []string{""},
		errs: []error{errors.New("connection failed")},
	}

	status, output, err := CheckStatus(ctx, client, "testhost", "testuser", 5*time.Second)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if status != StatusUnknown {
		t.Errorf("expected StatusUnknown, got %v", status)
	}
	if output != "" {
		t.Errorf("expected empty output, got %q", output)
	}
}

// TestUnlockManyEmptyDevices tests UnlockMany with empty devices slice
func TestUnlockManyEmptyDevices(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{}
	store := &mockStore{}

	// Test with empty devices slice
	devices := []Device{}
	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 1)

	if len(results) != 0 {
		t.Errorf("expected empty results for empty devices slice, got %d results", len(results))
	}

	// Test with empty devices slice and concurrency
	results = UnlockMany(ctx, client, store, devices, "", 5*time.Second, 3)

	if len(results) != 0 {
		t.Errorf("expected empty results for empty devices slice with concurrency, got %d results", len(results))
	}
}

// TestUnlockManyWithZeroConcurrency tests UnlockMany with zero concurrency (should use sequential)
func TestUnlockManyWithZeroConcurrency(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{
		status: StatusUnlocked,
		output: "System successfully unlocked.",
	}
	store := &mockStore{pw: "secret"}

	devices := []Device{
		{Host: "host1", User: "user1", Cred: "cred1"},
		{Host: "host2", User: "user2", Cred: "cred2"},
	}

	// Test with zero concurrency (should use sequential path)
	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, 0)

	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}

	// Verify all results are as expected
	for _, result := range results {
		if result.Error != nil {
			t.Errorf("result for %q has unexpected error: %v", result.Host, result.Error)
		}
		if result.Status != StatusUnlocked {
			t.Errorf("result for %q expected StatusUnlocked, got %v", result.Host, result.Status)
		}
	}
}

// TestUnlockManyWithNegativeConcurrency tests UnlockMany with negative concurrency (should use sequential)
func TestUnlockManyWithNegativeConcurrency(t *testing.T) {
	ctx := context.Background()
	client := &mockSSHClientForUnlock{
		status: StatusLocked,
		output: "This system is locked. Enter password:",
	}
	store := &mockStore{pw: "secret"}

	devices := []Device{
		{Host: "host1", User: "user1", Cred: "cred1"},
		{Host: "host2", User: "user2", Cred: "cred2"},
	}

	// Test with negative concurrency (should use sequential path)
	results := UnlockMany(ctx, client, store, devices, "", 5*time.Second, -1)

	if len(results) != len(devices) {
		t.Fatalf("expected %d results, got %d", len(devices), len(results))
	}

	// Verify all results are as expected
	for _, result := range results {
		if result.Error != nil {
			t.Errorf("result for %q has unexpected error: %v", result.Host, result.Error)
		}
		if result.Status != StatusLocked {
			t.Errorf("result for %q expected StatusLocked, got %v", result.Host, result.Status)
		}
	}
}

// TestUnlockWithTimeoutContext tests Unlock with a timeout context
func TestUnlockWithTimeoutContext(t *testing.T) {
	// Use an already-expired deadline so the assertion is deterministic even on
	// platforms whose timer resolution is coarser than a nanosecond.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	store := &mockStore{pw: "secret"}
	client := &seqSSHClient{
		outs: []string{"This system is locked. Enter password:"},
		errs: []error{nil},
	}

	result := Unlock(ctx, client, store, "slow-host", "user", "cred", "", time.Second)

	// We expect a timeout error
	if result.Error == nil {
		t.Fatalf("expected timeout error, got nil")
	}
}

// TestDeviceStatusStringAdditional tests additional cases for DeviceStatus.String()
func TestDeviceStatusStringAdditional(t *testing.T) {
	// Test boundary values
	cases := []struct {
		status DeviceStatus
		want   string
	}{
		{StatusUnknown - 1, "unknown"},            // Below known range
		{StatusUnlockedRecently + 1, "unknown"},   // Above known range
		{StatusUnlockedRecently + 100, "unknown"}, // Way above known range
	}

	for _, c := range cases {
		got := c.status.String()
		if got != c.want {
			t.Errorf("DeviceStatus(%d).String() = %q, want %q", int(c.status), got, c.want)
		}
	}
}

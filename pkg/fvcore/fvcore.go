// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"time"
)

// DeviceStatus represents the parsed state of a remote device from SSH output.
// The status indicates whether a device is locked, unlocked, or recently unlocked.
type DeviceStatus int

const (
	// StatusUnknown represents an unknown device status.
	// This is typically returned when an error occurs during status detection.
	StatusUnknown DeviceStatus = iota
	// StatusLocked represents a device that is currently locked and requires a password to unlock.
	StatusLocked
	// StatusUnlocked represents a device that is unlocked and ready for use.
	StatusUnlocked
	// StatusUnlockedRecently represents a device that was already unlocked (a
	// normal SSH session is available).
	StatusUnlockedRecently
)

// String returns a string representation of the DeviceStatus.
func (d DeviceStatus) String() string {
	switch d {
	case StatusLocked:
		return "locked"
	case StatusUnlocked:
		return "unlocked"
	case StatusUnlockedRecently:
		return "recently unlocked"
	default:
		return "unknown"
	}
}

// SSHClient abstracts SSH interactions for unlock attempts. This interface
// allows mocking SSH connections in tests.
type SSHClient interface {
	// AnalyzePrompt connects to the host, supplies password over the FileVault
	// keyboard-interactive prompt, and returns the resulting DeviceStatus, the
	// decrypted banner text, and any error. successMsg, if non-empty, is the
	// banner text that indicates a successful unlock.
	AnalyzePrompt(ctx context.Context, host, user, password, successMsg string) (DeviceStatus, string, error)
}

// StatusChecker reports device status WITHOUT transmitting a password. It is a
// separate interface from SSHClient because most callers (and the unlock path)
// do not need it, and because it must never receive a password.
type StatusChecker interface {
	// ProbeStatus connects to host and classifies the device state without
	// sending any password.
	ProbeStatus(ctx context.Context, host, user string) (DeviceStatus, string, error)
}

// CredentialStore defines how credentials are retrieved.
type CredentialStore interface {
	// Get retrieves a password for the given key/name.
	Get(name string) (string, error)
}

// UnlockResult contains the outcome of an unlock attempt.
type UnlockResult struct {
	// Host is the target host that was attempted to be unlocked.
	Host string
	// Status is the device status after the unlock attempt.
	Status DeviceStatus
	// Output contains the decrypted banner text captured from the connection.
	Output string
	// Error contains any error that occurred during the unlock attempt.
	Error error
	// Verified reports whether the device was observed booting into a normal
	// SSH session after the unlock. It is only set when verification was
	// requested (see VerifyUnlock). A successful unlock with Verified == false
	// is not a failure because the device may still be booting.
	Verified bool
}

// ErrAuthFailed signals authentication failure (e.g. a wrong unlock password).
var ErrAuthFailed = errors.New("authentication failed")

// ErrConnectionRefused signals the remote host refused the connection.
var ErrConnectionRefused = errors.New("connection refused")

// ErrHostKeyMismatch signals that the remote host's SSH key did not match the
// pinned key. This is fatal: it may indicate a man-in-the-middle, so callers
// must not retry past it.
var ErrHostKeyMismatch = errors.New("host key verification failed")

// Device represents a configured target device for unlocking.
type Device struct {
	Host string
	User string
	Port int
	Cred string
}

// Unlock attempts to unlock a single device using credentials from store and
// the given SSH client.
func Unlock(ctx context.Context, client SSHClient, store CredentialStore, host, user, credName, successMsg string, timeout time.Duration) UnlockResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := effectiveContextError(ctx); err != nil {
		return UnlockResult{Host: host, Status: StatusUnknown, Error: err}
	}

	pass, err := store.Get(credName)
	if err != nil {
		return UnlockResult{Host: host, Status: StatusUnknown, Error: err}
	}

	status, out, err := client.AnalyzePrompt(ctx, host, user, pass, successMsg)
	if ctxErr := effectiveContextError(ctx); ctxErr != nil {
		return UnlockResult{Host: host, Status: StatusUnknown, Output: out, Error: ctxErr}
	}
	return UnlockResult{Host: host, Status: status, Output: out, Error: err}
}

func effectiveContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// UnlockMany attempts to unlock multiple devices with optional concurrency.
// Results are always returned in the same order as devices, regardless of
// concurrency.
func UnlockMany(ctx context.Context, client SSHClient, store CredentialStore, devices []Device, successMsg string, timeout time.Duration, concurrency int) []UnlockResult {
	results := make([]UnlockResult, len(devices))
	if len(devices) == 0 {
		return results
	}

	if concurrency <= 1 {
		for i, device := range devices {
			results[i] = Unlock(ctx, client, store, device.Host, device.User, device.Cred, successMsg, timeout)
		}
		return results
	}

	// Bounded worker pool. Each job carries its index so results stay aligned
	// with the input order.
	type job struct {
		idx    int
		device Device
	}
	jobs := make(chan job)
	type indexed struct {
		idx int
		res UnlockResult
	}
	out := make(chan indexed)

	workers := concurrency
	if workers > len(devices) {
		workers = len(devices)
	}
	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				res := Unlock(ctx, client, store, j.device.Host, j.device.User, j.device.Cred, successMsg, timeout)
				out <- indexed{idx: j.idx, res: res}
			}
		}()
	}

	go func() {
		for i, d := range devices {
			jobs <- job{idx: i, device: d}
		}
		close(jobs)
	}()

	for range devices {
		r := <-out
		results[r.idx] = r.res
	}
	return results
}

// CheckStatus queries the device status without attempting an unlock and
// without transmitting any password.
func CheckStatus(ctx context.Context, checker StatusChecker, host, user string, timeout time.Duration) (DeviceStatus, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return checker.ProbeStatus(ctx, host, user)
}

// VerifyOptions controls post-unlock verification.
type VerifyOptions struct {
	// Grace is how long to wait before the first check, giving macOS time to
	// tear down the pre-boot SSH server and begin mounting the data volume.
	Grace time.Duration
	// Window is the total time to keep polling for a booted SSH session.
	Window time.Duration
	// Interval is the delay between polls.
	Interval time.Duration
	// AttemptTimeout bounds each individual connection attempt.
	AttemptTimeout time.Duration
}

// DefaultVerifyOptions returns sensible defaults for post-unlock verification.
// The window is generous because a Mac can take several minutes to finish
// booting and bring the network back up, especially over Wi-Fi.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		Grace:          10 * time.Second,
		Window:         5 * time.Minute,
		Interval:       10 * time.Second,
		AttemptTimeout: 20 * time.Second,
	}
}

// VerifyUnlock confirms that a device finished booting after an unlock
// by probing until a normal SSH session is available. Verification never
// receives or retransmits the unlock password.
//
// It returns true once the device answers as a booted host. It returns false
// (with a nil error) if the window expires without confirmation, which means
// "not confirmed", not "the unlock failed". A non-nil error is returned only
// for conditions that make verification impossible, such as a host-key
// mismatch or a cancelled context.
func VerifyUnlock(ctx context.Context, checker StatusChecker, device Device, opts VerifyOptions) (bool, error) {
	if opts.Window <= 0 {
		return false, nil
	}
	if opts.AttemptTimeout <= 0 || opts.Interval < 0 || opts.Grace < 0 {
		return false, errors.New("invalid verification timing options")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	verifyCtx, cancelVerify := context.WithTimeout(ctx, opts.Window)
	defer cancelVerify()

	if opts.Grace > 0 {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-verifyCtx.Done():
			return false, nil
		case <-time.After(opts.Grace):
		}
	}

	for {
		attemptCtx, cancel := context.WithTimeout(verifyCtx, opts.AttemptTimeout)
		status, _, err := checker.ProbeStatus(attemptCtx, device.Host, device.User)
		cancel()

		// A completed SSH session means the machine is booted and the data
		// volume is mounted: verification succeeded.
		if status == StatusUnlockedRecently {
			return true, nil
		}
		// A host-key problem is fatal. Never keep retrying past it.
		if errors.Is(err, ErrHostKeyMismatch) {
			return false, err
		}
		// A reachable password prompt with no locked banner cannot be resolved
		// without transmitting a secret. Stop immediately and tell the caller to
		// configure a public key rather than polling with the unlock password.
		if errors.Is(err, ErrIndeterminate) {
			return false, err
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if verifyCtx.Err() != nil {
			return false, nil
		}

		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-verifyCtx.Done():
			return false, nil
		case <-time.After(opts.Interval):
		}
	}
}

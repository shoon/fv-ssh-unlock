// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Package monitor provides the long-running, policy-enforcing state machine
// used to observe and recover FileVault-protected Macs. It deliberately knows
// nothing about SSH implementations or credential providers; callers adapt
// those operations through Prober and Unlocker.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// State is the operator-visible lifecycle state of a managed device.
type State string

const (
	StateBooted           State = "booted"
	StateLocked           State = "locked"
	StateIndeterminate    State = "indeterminate"
	StateUnreachable      State = "unreachable"
	StateUnlocking        State = "unlocking"
	StateBooting          State = "booting"
	StateCredentialFailed State = "credential-failed"
	StateError            State = "error"
)

// Device describes a monitor target and its automatic recovery policy. Secret
// values must never be put in this structure; CredentialRef is an opaque
// provider reference such as "systemd:m4alpha-password".
type Device struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	User          string `json:"user"`
	Port          int    `json:"port,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	AutoUnlock    bool   `json:"auto_unlock"`
}

// ProbeResult is a password-free observation. Probers may return only booted,
// locked, indeterminate, or unreachable. A definitive StateLocked result is
// the only observation which can cause the engine to invoke Unlocker.
type ProbeResult struct {
	State        State
	Detail       string
	EndpointDown bool
}

// UnlockResult describes what was learned while submitting the configured
// credential. Accepted means that the credential was accepted or that the
// pre-boot SSH service disappeared after submission and boot verification
// should begin. It is safe to return Accepted with a non-nil error when the
// acknowledgement was ambiguous; the monitor will fail closed and verify by
// password-free probing rather than submitting the credential again. An
// adapter may return Accepted false with a FailureUnreachable or
// FailureTransient error only when it knows no credential was submitted; that
// permits a backoff-controlled connection retry in the same lock episode.
type UnlockResult struct {
	Accepted bool
	Detail   string
}

// Prober observes a device without receiving or transmitting its FileVault
// credential.
type Prober interface {
	Probe(context.Context, Device) (ProbeResult, error)
}

// Unlocker performs a single explicitly authorized unlock attempt. It is
// called only after a definitive locked observation and after durable state
// records that the current lock episode has already been attempted.
type Unlocker interface {
	Unlock(context.Context, Device) (UnlockResult, error)
}

// FailureKind allows an SSH/credential adapter to tell the monitor which
// failures must latch and which failures are ordinary availability problems.
type FailureKind string

const (
	FailureUnreachable FailureKind = "unreachable"
	FailureCredential  FailureKind = "credential"
	FailureHostKey     FailureKind = "host-key"
	FailureTransient   FailureKind = "transient"
)

// Failure wraps an operation error with a stable classification. Error text
// must not contain credential material because it can appear in state and
// operator event output.
type Failure struct {
	Kind FailureKind
	Err  error
}

func (f *Failure) Error() string {
	if f == nil {
		return "monitor operation failed"
	}
	if f.Err == nil {
		return fmt.Sprintf("monitor operation failed: %s", f.Kind)
	}
	return f.Err.Error()
}

func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Err
}

// NewFailure classifies an adapter error for monitor policy decisions.
func NewFailure(kind FailureKind, err error) error {
	if err == nil {
		err = errors.New("operation failed")
	}
	return &Failure{Kind: kind, Err: err}
}

// FailureKindOf returns the explicit classification of err. Unclassified
// errors are transient operational errors, not credential or host-key errors.
func FailureKindOf(err error) FailureKind {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureUnreachable
	}
	return FailureTransient
}

// Options controls scheduler timing and resource limits.
type Options struct {
	PollInterval     time.Duration
	BootPollInterval time.Duration
	ProbeTimeout     time.Duration
	UnlockTimeout    time.Duration
	Concurrency      int
	BackoffInitial   time.Duration
	BackoffMax       time.Duration
	JitterFraction   float64
	DisableJitter    bool
	UnlockCooldown   time.Duration
	EventHistory     int
}

// DefaultOptions returns conservative defaults suitable for an always-on
// controller. Callers can override individual fields before constructing an
// Engine.
func DefaultOptions() Options {
	return Options{
		PollInterval:     30 * time.Second,
		BootPollInterval: 5 * time.Second,
		ProbeTimeout:     15 * time.Second,
		UnlockTimeout:    45 * time.Second,
		Concurrency:      4,
		BackoffInitial:   15 * time.Second,
		BackoffMax:       15 * time.Minute,
		JitterFraction:   0.10,
		UnlockCooldown:   15 * time.Minute,
		EventHistory:     200,
	}
}

// DeviceRecord is the durable portion of a device's state. It intentionally
// contains no credentials.
type DeviceRecord struct {
	State                 State       `json:"state"`
	LastObservation       State       `json:"last_observation,omitempty"`
	Detail                string      `json:"detail,omitempty"`
	LastError             string      `json:"last_error,omitempty"`
	LastCheckedAt         time.Time   `json:"last_checked_at,omitzero"`
	StateChangedAt        time.Time   `json:"state_changed_at,omitzero"`
	LastUnlockAttemptAt   time.Time   `json:"last_unlock_attempt_at,omitzero"`
	NextUnlockEligibleAt  time.Time   `json:"next_unlock_eligible_at,omitzero"`
	LockEpisode           uint64      `json:"lock_episode,omitempty"`
	LockEpisodeOpen       bool        `json:"lock_episode_open,omitempty"`
	UnlockAttempted       bool        `json:"unlock_attempted,omitempty"`
	ConsecutiveFailures   int         `json:"consecutive_failures,omitempty"`
	UnlockConnectFailures int         `json:"unlock_connect_failures,omitempty"`
	EndpointDown          bool        `json:"endpoint_down,omitempty"`
	Latched               bool        `json:"latched,omitempty"`
	LatchKind             FailureKind `json:"latch_kind,omitempty"`
	LatchReason           string      `json:"latch_reason,omitempty"`
	NextCheckAt           time.Time   `json:"-"`
}

// PersistentState is the versioned on-disk state document.
type PersistentState struct {
	Version int                     `json:"version"`
	Devices map[string]DeviceRecord `json:"devices"`
}

const persistentStateVersion = 1

// Store persists attempt, cooldown, and latch state across process restarts.
type Store interface {
	Load() (PersistentState, error)
	Save(PersistentState) error
}

// DeviceSnapshot combines configured identity and current runtime state.
type DeviceSnapshot struct {
	Device
	DeviceRecord
}

// EventType identifies an item in the bounded operator event stream.
type EventType string

const (
	EventProbe              EventType = "probe"
	EventObservationChanged EventType = "observation-changed"
	EventStateChanged       EventType = "state-changed"
	EventUnlockStarted      EventType = "unlock-started"
	EventUnlockResult       EventType = "unlock-result"
	EventLatchChanged       EventType = "latch-changed"
	EventDeviceAdded        EventType = "device-added"
)

// Event is safe to encode as JSON or display in a TUI. Message values come
// from adapters and therefore must never contain secret material.
type Event struct {
	Sequence     uint64      `json:"sequence"`
	Time         time.Time   `json:"time"`
	Type         EventType   `json:"type"`
	Device       string      `json:"device"`
	State        State       `json:"state"`
	Observation  State       `json:"observation,omitempty"`
	Message      string      `json:"message,omitempty"`
	LockEpisode  uint64      `json:"lock_episode,omitempty"`
	AutoUnlock   bool        `json:"auto_unlock"`
	EndpointDown bool        `json:"endpoint_down,omitempty"`
	Latched      bool        `json:"latched,omitempty"`
	FailureKind  FailureKind `json:"failure_kind,omitempty"`
}

// Snapshot is a stable, sorted, JSON-ready view for a CLI, TUI, or local API.
type Snapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Devices     []DeviceSnapshot `json:"devices"`
	Events      []Event          `json:"events,omitempty"`
}

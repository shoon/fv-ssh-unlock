// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Package candidates maintains an untrusted inbox of SSH hosts observed by
// passive discovery or active scanning. It intentionally has no credential,
// host-key enrollment, or network access APIs.
package candidates

import "time"

// State is the operator-review lifecycle of a candidate.
type State string

const (
	// StateDiscovered is a host observation for which no SSH identity is known.
	StateDiscovered State = "discovered"
	// StateIdentityPending has an SSH fingerprint awaiting operator verification.
	StateIdentityPending State = "identity_pending"
	// StateVerified records operator verification of the fingerprint. It does
	// not enroll or otherwise trust the key outside this inbox.
	StateVerified State = "verified"
	// StateIgnored permanently suppresses a candidate until it is restored.
	StateIgnored State = "ignored"
)

// EventType describes a durable-state change. Event history is deliberately
// bounded and consumers must use Snapshot when ResetRequired is reported.
type EventType string

const (
	EventDiscovered        EventType = "discovered"
	EventUpdated           EventType = "updated"
	EventMerged            EventType = "merged"
	EventVerified          EventType = "verified"
	EventIgnored           EventType = "ignored"
	EventRestored          EventType = "restored"
	EventExpired           EventType = "expired"
	EventConfiguredChanged EventType = "configured_changed"
)

// Observation is a credential-free report produced by a discovery adapter.
// Fingerprint, when present, must be an OpenSSH SHA256 fingerprint. Address may
// be an IPv4 or IPv6 literal; DNS names belong in Hostname.
type Observation struct {
	Source      string    `json:"source"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
	Name        string    `json:"name,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Address     string    `json:"address,omitempty"`
	Port        int       `json:"port,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	KeyType     string    `json:"key_type,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
}

// Sink is the minimal adapter boundary for a passive browser or active scanner.
// Implementations receive observations only; discovering a host cannot enroll
// a key, read a credential, or modify managed-device configuration.
type Sink interface {
	Ingest(Observation) (IngestResult, error)
}

// BatchSink lets a scanner persist one complete discovery round atomically.
type BatchSink interface {
	IngestMany([]Observation) ([]IngestResult, error)
}

// Endpoint is one address and port observed for a candidate.
type Endpoint struct {
	Address   string    `json:"address"`
	Port      int       `json:"port"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Candidate is a JSON-safe, immutable-to-callers view of an inbox entry.
// ConfiguredNames distinguishes fingerprints already present in the caller's
// trusted configuration from newly observed identities.
type Candidate struct {
	ID              string     `json:"id"`
	State           State      `json:"state"`
	Fingerprint     string     `json:"fingerprint,omitempty"`
	KeyType         string     `json:"key_type,omitempty"`
	Names           []string   `json:"names,omitempty"`
	Hostnames       []string   `json:"hostnames,omitempty"`
	Endpoints       []Endpoint `json:"endpoints,omitempty"`
	Sources         []string   `json:"sources,omitempty"`
	LastEvidence    string     `json:"last_evidence,omitempty"`
	ConfiguredNames []string   `json:"configured_names,omitempty"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	IgnoredAt       *time.Time `json:"ignored_at,omitempty"`
}

// ConfiguredFingerprint identifies an SSH fingerprint already pinned by a
// configured device. DeviceNames are labels only; no key material is accepted.
type ConfiguredFingerprint struct {
	Fingerprint string   `json:"fingerprint"`
	DeviceNames []string `json:"device_names"`
}

// IngestResult reports the candidate produced by an observation.
type IngestResult struct {
	Candidate Candidate `json:"candidate"`
	Created   bool      `json:"created"`
	MergedIDs []string  `json:"merged_ids,omitempty"`
}

// Snapshot is a consistent point-in-time view suitable for a TUI or JSON API.
type Snapshot struct {
	Sequence   uint64      `json:"sequence"`
	Generated  time.Time   `json:"generated_at"`
	Candidates []Candidate `json:"candidates"`
}

// Event is a change notification. Candidate is omitted for expiration events.
type Event struct {
	Sequence    uint64     `json:"sequence"`
	At          time.Time  `json:"at"`
	Type        EventType  `json:"type"`
	Candidate   *Candidate `json:"candidate,omitempty"`
	CandidateID string     `json:"candidate_id"`
	MergedIDs   []string   `json:"merged_ids,omitempty"`
}

// EventBatch contains changes after a caller's sequence cursor.
type EventBatch struct {
	LatestSequence uint64  `json:"latest_sequence"`
	ResetRequired  bool    `json:"reset_required"`
	Events         []Event `json:"events"`
}

// Options controls retention and resource limits.
type Options struct {
	TTL           time.Duration
	MaxCandidates int
	MaxEvents     int
	Clock         func() time.Time
}

const (
	DefaultTTL           = 7 * 24 * time.Hour
	DefaultMaxCandidates = 4096
	DefaultMaxEvents     = 512
)

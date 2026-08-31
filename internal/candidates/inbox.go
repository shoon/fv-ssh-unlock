// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package candidates

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Inbox owns candidate lifecycle state. All methods are safe for concurrent
// use. Network scanners feed it through Ingest or IngestMany.
type Inbox struct {
	mu         sync.RWMutex
	path       string
	ttl        time.Duration
	maxEntries int
	maxEvents  int
	clock      func() time.Time
	sequence   uint64
	dropped    uint64
	entries    map[string]*Candidate
	configured map[string][]string
	events     []Event
}

// New returns an in-memory inbox. Use Open when state must survive restarts.
func New(options Options) *Inbox {
	return newInbox("", options)
}

// Open loads or creates an inbox backed by an atomically replaced, private JSON
// file. An absent file starts empty.
func Open(path string, options Options) (*Inbox, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("candidate inbox path must not be empty")
	}
	b := newInbox(path, options)
	state, err := loadState(path)
	if err != nil {
		return nil, err
	}
	if state != nil {
		b.sequence = state.Sequence
		for i, item := range state.Configured {
			fingerprint, err := normalizeFingerprint(item.Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("invalid configured fingerprint at index %d: %w", i, err)
			}
			for _, name := range item.DeviceNames {
				name, err = normalizePlain("configured device name", name, 128)
				if err != nil {
					return nil, fmt.Errorf("invalid configured fingerprint at index %d: %w", i, err)
				}
				b.configured[fingerprint] = addString(b.configured[fingerprint], name)
			}
		}
		for fingerprint := range b.configured {
			sort.Strings(b.configured[fingerprint])
		}
		fingerprints := make(map[string]string)
		for i := range state.Candidates {
			candidate := cloneCandidate(state.Candidates[i])
			if err := validateCandidate(candidate); err != nil {
				return nil, fmt.Errorf("invalid candidate at index %d: %w", i, err)
			}
			if _, exists := b.entries[candidate.ID]; exists {
				return nil, fmt.Errorf("duplicate candidate ID %q", candidate.ID)
			}
			if candidate.Fingerprint != "" {
				if prior, exists := fingerprints[candidate.Fingerprint]; exists {
					return nil, fmt.Errorf("candidates %q and %q share fingerprint %s", prior, candidate.ID, candidate.Fingerprint)
				}
				fingerprints[candidate.Fingerprint] = candidate.ID
			}
			if strings.Join(candidate.ConfiguredNames, "\x00") != strings.Join(b.configured[candidate.Fingerprint], "\x00") {
				return nil, fmt.Errorf("candidate %q has stale configured device names", candidate.ID)
			}
			b.entries[candidate.ID] = &candidate
		}
		if len(b.entries) > b.maxEntries {
			return nil, fmt.Errorf("candidate inbox contains %d entries; limit is %d", len(b.entries), b.maxEntries)
		}
	}
	return b, nil
}

func newInbox(path string, options Options) *Inbox {
	if options.TTL == 0 {
		options.TTL = DefaultTTL
	}
	if options.MaxCandidates <= 0 {
		options.MaxCandidates = DefaultMaxCandidates
	}
	if options.MaxEvents <= 0 {
		options.MaxEvents = DefaultMaxEvents
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Inbox{
		path:       path,
		ttl:        options.TTL,
		maxEntries: options.MaxCandidates,
		maxEvents:  options.MaxEvents,
		clock:      options.Clock,
		entries:    make(map[string]*Candidate),
		configured: make(map[string][]string),
	}
}

// Ingest validates and records one untrusted observation.
func (b *Inbox) Ingest(observation Observation) (IngestResult, error) {
	results, err := b.IngestMany([]Observation{observation})
	if err != nil {
		return IngestResult{}, err
	}
	return results[0], nil
}

// IngestMany records a discovery round in one durable transaction.
func (b *Inbox) IngestMany(observations []Observation) ([]IngestResult, error) {
	if len(observations) == 0 {
		return []IngestResult{}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	normalized := make([]Observation, len(observations))
	for i, observation := range observations {
		var err error
		normalized[i], err = normalizeObservation(observation, now)
		if err != nil {
			return nil, fmt.Errorf("observation %d: %w", i, err)
		}
	}

	beforeEntries := cloneEntries(b.entries)
	beforeSequence := b.sequence
	var pending []Event
	b.expireLocked(now, &pending)
	results := make([]IngestResult, 0, len(normalized))
	touched := make(map[string]struct{}, len(normalized))
	for _, observation := range normalized {
		result, events, err := b.ingestLocked(observation, touched)
		if err != nil {
			b.entries = beforeEntries
			b.sequence = beforeSequence
			return nil, err
		}
		results = append(results, result)
		pending = append(pending, events...)
	}
	if err := b.saveLocked(); err != nil {
		b.entries = beforeEntries
		b.sequence = beforeSequence
		return nil, err
	}
	b.appendEventsLocked(pending)
	return results, nil
}

// ingestLocked folds one normalized observation into the inbox. touched holds
// the candidates already produced by this round so a capacity eviction cannot
// remove an entry the same batch just wrote.
func (b *Inbox) ingestLocked(observation Observation, touched map[string]struct{}) (IngestResult, []Event, error) {
	matches := b.matchesLocked(observation)
	var candidate *Candidate
	var mergedIDs []string
	created := false

	if observation.Fingerprint != "" {
		for _, match := range matches {
			if match.Fingerprint == observation.Fingerprint {
				candidate = match
				break
			}
		}
		if candidate == nil {
			for _, match := range matches {
				if match.Fingerprint == "" {
					candidate = match
					break
				}
			}
		}
	} else if len(matches) == 1 {
		candidate = matches[0]
	} else if len(matches) > 1 {
		// A no-key observation cannot safely choose among multiple identities
		// previously seen at the same endpoint or hostname.
		for _, match := range matches {
			if match.Fingerprint == "" {
				candidate = match
				break
			}
		}
	}

	var evicted []Event
	if candidate == nil {
		// A full inbox must never fail the round: an attacker who can fabricate
		// distinct observations would otherwise freeze LastSeen and state
		// updates for every legitimate candidate already recorded. Make room by
		// evicting the least recently seen unreviewed entry, and when only
		// operator-reviewed entries remain, drop the creation instead.
		for len(b.entries) >= b.maxEntries {
			victim := b.evictionTargetLocked(touched)
			if victim == nil {
				b.dropped++
				return IngestResult{Dropped: true}, nil, nil
			}
			delete(b.entries, victim.ID)
			evicted = append(evicted, b.makeEventLocked(EventEvicted, nil, nil, observation.ObservedAt, victim.ID))
		}
		id, err := newCandidateID()
		if err != nil {
			return IngestResult{}, nil, fmt.Errorf("generate candidate ID: %w", err)
		}
		candidate = &Candidate{ID: id, State: StateDiscovered, FirstSeen: observation.ObservedAt, LastSeen: observation.ObservedAt}
		b.entries[id] = candidate
		created = true
	}

	if observation.Fingerprint != "" {
		candidate.Fingerprint = observation.Fingerprint
		if candidate.State == StateDiscovered {
			candidate.State = StateIdentityPending
		}
	}
	mergeObservation(candidate, observation)
	if names := b.configured[candidate.Fingerprint]; len(names) > 0 {
		candidate.ConfiguredNames = cloneStrings(names)
		if candidate.State != StateIgnored {
			candidate.State = StateVerified
		}
	}

	// Fold other pending aliases into a fingerprint-backed candidate. Never
	// merge two different fingerprints solely because an address was reused.
	if candidate.Fingerprint != "" {
		for _, match := range matches {
			if match.ID == candidate.ID || match.Fingerprint != "" {
				continue
			}
			mergeCandidates(candidate, match)
			delete(b.entries, match.ID)
			mergedIDs = append(mergedIDs, match.ID)
		}
	}
	sort.Strings(mergedIDs)

	typeForEvent := EventUpdated
	if created {
		typeForEvent = EventDiscovered
	} else if len(mergedIDs) > 0 {
		typeForEvent = EventMerged
	}
	event := b.makeEventLocked(typeForEvent, candidate, mergedIDs, observation.ObservedAt)
	touched[candidate.ID] = struct{}{}
	result := IngestResult{Candidate: cloneCandidate(*candidate), Created: created, MergedIDs: cloneStrings(mergedIDs)}
	return result, append(evicted, event), nil
}

// evictionTargetLocked returns the least recently seen candidate that no
// operator has reviewed, or nil when every remaining entry is pinned. Verified,
// ignored, and already configured candidates are never evicted, so a flood of
// fabricated observations cannot displace a reviewed identity.
func (b *Inbox) evictionTargetLocked(touched map[string]struct{}) *Candidate {
	var victim *Candidate
	for id, candidate := range b.entries {
		if _, recent := touched[id]; recent || candidatePinned(candidate) {
			continue
		}
		if victim == nil || candidate.LastSeen.Before(victim.LastSeen) ||
			(candidate.LastSeen.Equal(victim.LastSeen) && candidate.ID < victim.ID) {
			victim = candidate
		}
	}
	return victim
}

// candidatePinned reports whether an operator decision protects the candidate
// from capacity eviction.
func candidatePinned(candidate *Candidate) bool {
	return candidate.State == StateVerified || candidate.State == StateIgnored ||
		candidate.VerifiedAt != nil || len(candidate.ConfiguredNames) > 0
}

// Dropped reports how many observations could not create a candidate because
// the inbox was full of operator-reviewed entries. The counter is cumulative
// for the life of the process and lets a caller log or surface silent loss
// without failing a discovery round.
func (b *Inbox) Dropped() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dropped
}

// MarkVerified records that an operator verified the displayed fingerprint.
// It intentionally does not write known_hosts or enroll a key.
func (b *Inbox) MarkVerified(id string) (Candidate, error) {
	return b.transition(id, EventVerified, func(candidate *Candidate, now time.Time) error {
		if candidate.Fingerprint == "" {
			return errors.New("cannot verify a candidate without an SSH fingerprint")
		}
		candidate.State = StateVerified
		candidate.VerifiedAt = timePointer(now)
		candidate.IgnoredAt = nil
		return nil
	})
}

// Ignore permanently retains and suppresses a candidate until Restore is used.
func (b *Inbox) Ignore(id string) (Candidate, error) {
	return b.transition(id, EventIgnored, func(candidate *Candidate, now time.Time) error {
		candidate.State = StateIgnored
		candidate.IgnoredAt = timePointer(now)
		return nil
	})
}

// Restore returns an ignored candidate to its review state.
func (b *Inbox) Restore(id string) (Candidate, error) {
	return b.transition(id, EventRestored, func(candidate *Candidate, _ time.Time) error {
		if candidate.State != StateIgnored {
			return errors.New("candidate is not ignored")
		}
		candidate.IgnoredAt = nil
		if candidate.Fingerprint == "" {
			candidate.State = StateDiscovered
		} else if len(candidate.ConfiguredNames) > 0 || candidate.VerifiedAt != nil {
			candidate.State = StateVerified
		} else {
			candidate.State = StateIdentityPending
		}
		return nil
	})
}

func (b *Inbox) transition(id string, eventType EventType, mutate func(*Candidate, time.Time) error) (Candidate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	candidate, ok := b.entries[id]
	if !ok {
		return Candidate{}, fmt.Errorf("candidate not found: %s", id)
	}
	before := cloneCandidate(*candidate)
	beforeSequence := b.sequence
	now := b.now()
	if err := mutate(candidate, now); err != nil {
		return Candidate{}, err
	}
	event := b.makeEventLocked(eventType, candidate, nil, now)
	if err := b.saveLocked(); err != nil {
		*candidate = before
		b.sequence = beforeSequence
		return Candidate{}, err
	}
	b.appendEventsLocked([]Event{event})
	return cloneCandidate(*candidate), nil
}

// ReplaceConfiguredFingerprints updates the caller-supplied view of already
// pinned identities. This marks matching non-ignored candidates verified, but
// performs no configuration or key enrollment itself.
func (b *Inbox) ReplaceConfiguredFingerprints(configured []ConfiguredFingerprint) error {
	next := make(map[string][]string, len(configured))
	for i, item := range configured {
		fingerprint, err := normalizeFingerprint(item.Fingerprint)
		if err != nil {
			return fmt.Errorf("configured fingerprint %d: %w", i, err)
		}
		if len(item.DeviceNames) == 0 {
			return fmt.Errorf("configured fingerprint %d must name at least one device", i)
		}
		for _, name := range item.DeviceNames {
			name, err = normalizePlain("configured device name", name, 128)
			if err != nil {
				return fmt.Errorf("configured fingerprint %d: %w", i, err)
			}
			next[fingerprint] = addString(next[fingerprint], name)
		}
	}
	for fingerprint := range next {
		sort.Strings(next[fingerprint])
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	beforeEntries := cloneEntries(b.entries)
	beforeConfigured := cloneStringMap(b.configured)
	beforeSequence := b.sequence
	b.configured = next
	now := b.now()
	var events []Event
	for _, candidate := range b.entries {
		prior := strings.Join(candidate.ConfiguredNames, "\x00")
		candidate.ConfiguredNames = cloneStrings(next[candidate.Fingerprint])
		if len(candidate.ConfiguredNames) > 0 && candidate.State != StateIgnored {
			candidate.State = StateVerified
		} else if prior != "" && candidate.State == StateVerified && candidate.VerifiedAt == nil {
			candidate.State = StateIdentityPending
		}
		if prior != strings.Join(candidate.ConfiguredNames, "\x00") {
			events = append(events, b.makeEventLocked(EventConfiguredChanged, candidate, nil, now))
		}
	}
	configuredChanged := !equalStringMap(beforeConfigured, next)
	if len(events) == 0 && !configuredChanged {
		return nil
	}
	if err := b.saveLocked(); err != nil {
		b.entries = beforeEntries
		b.configured = beforeConfigured
		b.sequence = beforeSequence
		return err
	}
	b.appendEventsLocked(events)
	return nil
}

// Expire removes stale candidates according to TTL. Ignored entries are
// permanent until explicitly restored. A negative TTL disables expiration.
func (b *Inbox) Expire() ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	beforeEntries := cloneEntries(b.entries)
	beforeSequence := b.sequence
	var events []Event
	ids := b.expireLocked(b.now(), &events)
	if len(ids) == 0 {
		return []string{}, nil
	}
	if err := b.saveLocked(); err != nil {
		b.entries = beforeEntries
		b.sequence = beforeSequence
		return nil, err
	}
	b.appendEventsLocked(events)
	return ids, nil
}

func (b *Inbox) expireLocked(now time.Time, events *[]Event) []string {
	if b.ttl < 0 {
		return nil
	}
	var ids []string
	for id, candidate := range b.entries {
		if candidate.State == StateIgnored || now.Sub(candidate.LastSeen) <= b.ttl {
			continue
		}
		delete(b.entries, id)
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		*events = append(*events, b.makeEventLocked(EventExpired, nil, nil, now, id))
	}
	return ids
}

// Snapshot returns a deep copy sorted with most recently seen candidates first.
func (b *Inbox) Snapshot() Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	candidates := make([]Candidate, 0, len(b.entries))
	for _, candidate := range b.entries {
		candidates = append(candidates, cloneCandidate(*candidate))
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].LastSeen.Equal(candidates[j].LastSeen) {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].LastSeen.After(candidates[j].LastSeen)
	})
	return Snapshot{Sequence: b.sequence, Generated: b.now(), Candidates: candidates}
}

// EventsSince returns the retained changes after sequence. ResetRequired means
// the cursor predates the bounded event buffer or a process restart.
func (b *Inbox) EventsSince(sequence uint64) EventBatch {
	b.mu.RLock()
	defer b.mu.RUnlock()
	batch := EventBatch{LatestSequence: b.sequence, Events: []Event{}}
	if sequence >= b.sequence {
		return batch
	}
	if len(b.events) == 0 || sequence+1 < b.events[0].Sequence {
		batch.ResetRequired = true
		return batch
	}
	for _, event := range b.events {
		if event.Sequence > sequence {
			batch.Events = append(batch.Events, cloneEvent(event))
		}
	}
	return batch
}

func (b *Inbox) matchesLocked(observation Observation) []*Candidate {
	seen := make(map[string]*Candidate)
	if observation.Fingerprint != "" {
		for _, candidate := range b.entries {
			if candidate.Fingerprint == observation.Fingerprint {
				seen[candidate.ID] = candidate
			}
		}
	}
	for _, candidate := range b.entries {
		if observation.Fingerprint != "" && candidate.Fingerprint != "" && candidate.Fingerprint != observation.Fingerprint {
			continue
		}
		if observation.Address != "" && hasEndpoint(candidate.Endpoints, observation.Address, observation.Port) {
			seen[candidate.ID] = candidate
			continue
		}
		if observation.Hostname != "" && containsFold(candidate.Hostnames, observation.Hostname) {
			seen[candidate.ID] = candidate
			continue
		}
		if observation.Address == "" && observation.Hostname == "" && observation.Name != "" && containsFold(candidate.Names, observation.Name) {
			seen[candidate.ID] = candidate
		}
	}
	out := make([]*Candidate, 0, len(seen))
	for _, candidate := range seen {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mergeObservation(candidate *Candidate, observation Observation) {
	candidate.FirstSeen = earlier(candidate.FirstSeen, observation.ObservedAt)
	candidate.LastSeen = later(candidate.LastSeen, observation.ObservedAt)
	if observation.Name != "" {
		candidate.Names = addStringFold(candidate.Names, observation.Name)
	}
	if observation.Hostname != "" {
		candidate.Hostnames = addStringFold(candidate.Hostnames, observation.Hostname)
	}
	if observation.Source != "" {
		candidate.Sources = addString(candidate.Sources, observation.Source)
	}
	if observation.Address != "" {
		mergeEndpoint(candidate, Endpoint{Address: observation.Address, Port: observation.Port, FirstSeen: observation.ObservedAt, LastSeen: observation.ObservedAt})
	}
	if observation.KeyType != "" {
		candidate.KeyType = observation.KeyType
	}
	if observation.Evidence != "" {
		candidate.LastEvidence = observation.Evidence
	}
	sort.Strings(candidate.Names)
	sort.Strings(candidate.Hostnames)
	sort.Strings(candidate.Sources)
}

func mergeCandidates(target, source *Candidate) {
	target.FirstSeen = earlier(target.FirstSeen, source.FirstSeen)
	target.LastSeen = later(target.LastSeen, source.LastSeen)
	for _, value := range source.Names {
		target.Names = addStringFold(target.Names, value)
	}
	for _, value := range source.Hostnames {
		target.Hostnames = addStringFold(target.Hostnames, value)
	}
	for _, value := range source.Sources {
		target.Sources = addString(target.Sources, value)
	}
	for _, endpoint := range source.Endpoints {
		mergeEndpoint(target, endpoint)
	}
	if source.State == StateIgnored {
		target.State = StateIgnored
		target.IgnoredAt = source.IgnoredAt
	}
	if target.LastEvidence == "" {
		target.LastEvidence = source.LastEvidence
	}
	sort.Strings(target.Names)
	sort.Strings(target.Hostnames)
	sort.Strings(target.Sources)
}

func mergeEndpoint(candidate *Candidate, incoming Endpoint) {
	for i := range candidate.Endpoints {
		endpoint := &candidate.Endpoints[i]
		if endpoint.Address == incoming.Address && endpoint.Port == incoming.Port {
			endpoint.FirstSeen = earlier(endpoint.FirstSeen, incoming.FirstSeen)
			endpoint.LastSeen = later(endpoint.LastSeen, incoming.LastSeen)
			return
		}
	}
	candidate.Endpoints = append(candidate.Endpoints, incoming)
	sort.Slice(candidate.Endpoints, func(i, j int) bool {
		if candidate.Endpoints[i].Address == candidate.Endpoints[j].Address {
			return candidate.Endpoints[i].Port < candidate.Endpoints[j].Port
		}
		return candidate.Endpoints[i].Address < candidate.Endpoints[j].Address
	})
}

func normalizeObservation(observation Observation, now time.Time) (Observation, error) {
	var err error
	observation.Source, err = normalizePlain("source", observation.Source, 64)
	if err != nil {
		return Observation{}, err
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = now
	} else {
		observation.ObservedAt = observation.ObservedAt.UTC()
		if observation.ObservedAt.After(now.Add(5 * time.Minute)) {
			return Observation{}, errors.New("observed_at is too far in the future")
		}
	}
	if observation.Name != "" {
		observation.Name, err = normalizePlain("name", observation.Name, 256)
		if err != nil {
			return Observation{}, err
		}
	}
	if observation.Hostname != "" {
		observation.Hostname = strings.TrimSuffix(strings.TrimSpace(observation.Hostname), ".")
		observation.Hostname, err = normalizePlain("hostname", observation.Hostname, 253)
		if err != nil {
			return Observation{}, err
		}
	}
	if observation.Address != "" {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(observation.Address))
		if parseErr != nil {
			return Observation{}, fmt.Errorf("invalid address: %w", parseErr)
		}
		observation.Address = address.Unmap().String()
	}
	if observation.Port == 0 {
		observation.Port = 22
	}
	if observation.Port < 1 || observation.Port > 65535 {
		return Observation{}, errors.New("port must be between 1 and 65535")
	}
	if observation.Fingerprint != "" {
		observation.Fingerprint, err = normalizeFingerprint(observation.Fingerprint)
		if err != nil {
			return Observation{}, err
		}
	}
	if observation.KeyType != "" {
		observation.KeyType, err = normalizePlain("key type", observation.KeyType, 128)
		if err != nil {
			return Observation{}, err
		}
	}
	if observation.Evidence != "" {
		observation.Evidence, err = normalizePlain("evidence", observation.Evidence, 256)
		if err != nil {
			return Observation{}, err
		}
	}
	if observation.Name == "" && observation.Hostname == "" && observation.Address == "" && observation.Fingerprint == "" {
		return Observation{}, errors.New("observation must contain a name, hostname, address, or fingerprint")
	}
	return observation, nil
}

func normalizeFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "SHA256:") {
		return "", errors.New("fingerprint must use OpenSSH SHA256 format")
	}
	encoded := strings.TrimPrefix(value, "SHA256:")
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil || len(digest) != sha256.Size {
		return "", errors.New("fingerprint must contain a 32-byte SHA256 digest")
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest), nil
}

func normalizePlain(field, value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", field)
	}
	if len(value) > max {
		return "", fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	for _, r := range value {
		if unicode.Is(unicode.Categories["C"], r) {
			return "", fmt.Errorf("%s contains a control or formatting character", field)
		}
	}
	return value, nil
}

func newCandidateID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return "cand_" + hex.EncodeToString(id[:]), nil
}

func (b *Inbox) now() time.Time { return b.clock().UTC() }

func (b *Inbox) makeEventLocked(eventType EventType, candidate *Candidate, merged []string, at time.Time, ids ...string) Event {
	b.sequence++
	id := ""
	var view *Candidate
	if candidate != nil {
		copy := cloneCandidate(*candidate)
		view = &copy
		id = candidate.ID
	} else if len(ids) > 0 {
		id = ids[0]
	}
	return Event{Sequence: b.sequence, At: at.UTC(), Type: eventType, Candidate: view, CandidateID: id, MergedIDs: cloneStrings(merged)}
}

func (b *Inbox) appendEventsLocked(events []Event) {
	b.events = append(b.events, events...)
	if len(b.events) > b.maxEvents {
		b.events = append([]Event(nil), b.events[len(b.events)-b.maxEvents:]...)
	}
}

func cloneEntries(entries map[string]*Candidate) map[string]*Candidate {
	out := make(map[string]*Candidate, len(entries))
	for id, candidate := range entries {
		clone := cloneCandidate(*candidate)
		out[id] = &clone
	}
	return out
}

func cloneCandidate(candidate Candidate) Candidate {
	candidate.Names = cloneStrings(candidate.Names)
	candidate.Hostnames = cloneStrings(candidate.Hostnames)
	candidate.Endpoints = append([]Endpoint(nil), candidate.Endpoints...)
	candidate.Sources = cloneStrings(candidate.Sources)
	candidate.ConfiguredNames = cloneStrings(candidate.ConfiguredNames)
	if candidate.VerifiedAt != nil {
		candidate.VerifiedAt = timePointer(*candidate.VerifiedAt)
	}
	if candidate.IgnoredAt != nil {
		candidate.IgnoredAt = timePointer(*candidate.IgnoredAt)
	}
	return candidate
}

func cloneEvent(event Event) Event {
	if event.Candidate != nil {
		candidate := cloneCandidate(*event.Candidate)
		event.Candidate = &candidate
	}
	event.MergedIDs = cloneStrings(event.MergedIDs)
	return event
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }

func cloneStringMap(values map[string][]string) map[string][]string {
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = cloneStrings(value)
	}
	return out
}

func equalStringMap(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, left := range a {
		right, exists := b[key]
		if !exists || strings.Join(left, "\x00") != strings.Join(right, "\x00") {
			return false
		}
	}
	return true
}

func addString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func addStringFold(values []string, value string) []string {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func containsFold(values []string, value string) bool {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return true
		}
	}
	return false
}

func hasEndpoint(endpoints []Endpoint, address string, port int) bool {
	for _, endpoint := range endpoints {
		if endpoint.Address == address && endpoint.Port == port {
			return true
		}
	}
	return false
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func later(a, b time.Time) time.Time {
	if a.IsZero() || b.After(a) {
		return b
	}
	return a
}

func timePointer(value time.Time) *time.Time {
	copy := value.UTC()
	return &copy
}

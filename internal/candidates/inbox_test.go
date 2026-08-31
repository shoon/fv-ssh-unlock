// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package candidates

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBonjourCandidatePromotesAndDeduplicatesByFingerprint(t *testing.T) {
	clock := newTestClock()
	inbox := New(Options{Clock: clock.Now})

	bonjour, err := inbox.Ingest(Observation{
		Source: "bonjour", Name: "M4 Alpha", Hostname: "m4alpha.local.", Address: "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bonjour.Created || bonjour.Candidate.State != StateDiscovered || bonjour.Candidate.Fingerprint != "" {
		t.Fatalf("unexpected Bonjour result: %+v", bonjour)
	}
	if bonjour.Candidate.Endpoints[0].Port != 22 || bonjour.Candidate.Hostnames[0] != "m4alpha.local" {
		t.Fatalf("observation was not normalized: %+v", bonjour.Candidate)
	}

	clock.Advance(time.Minute)
	second, err := inbox.Ingest(Observation{
		Source: "bonjour", Name: "m4alpha", Hostname: "M4ALPHA.local", Address: "192.0.2.11", Port: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.Candidate.ID != bonjour.Candidate.ID || len(second.Candidate.Names) != 2 || len(second.Candidate.Endpoints) != 2 {
		t.Fatalf("Bonjour aliases were not deduplicated: %+v", second)
	}

	clock.Advance(time.Minute)
	fingerprint := testFingerprint("m4alpha")
	identified, err := inbox.Ingest(Observation{
		Source: "active_scan", Address: "192.0.2.11", Port: 22, Fingerprint: fingerprint,
		KeyType: "ssh-ed25519", Evidence: "SSH; no FileVault banner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if identified.Created || identified.Candidate.ID != bonjour.Candidate.ID || identified.Candidate.State != StateIdentityPending {
		t.Fatalf("candidate was not promoted in place: %+v", identified)
	}

	clock.Advance(time.Minute)
	moved, err := inbox.Ingest(Observation{
		Source: "active_scan", Address: "192.0.2.99", Port: 2222, Fingerprint: fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if moved.Created || moved.Candidate.ID != bonjour.Candidate.ID || len(moved.Candidate.Endpoints) != 3 {
		t.Fatalf("fingerprint did not deduplicate a new address: %+v", moved)
	}
	if got := len(inbox.Snapshot().Candidates); got != 1 {
		t.Fatalf("got %d candidates, want 1", got)
	}
}

func TestFingerprintObservationMergesPendingAlias(t *testing.T) {
	inbox := New(Options{})
	fingerprint := testFingerprint("same-host")
	known, err := inbox.Ingest(Observation{Source: "active_scan", Address: "192.0.2.1", Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := inbox.Ingest(Observation{Source: "bonjour", Hostname: "new-address.local", Address: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Candidate.ID == known.Candidate.ID {
		t.Fatal("setup did not create a pending alias")
	}

	merged, err := inbox.Ingest(Observation{Source: "active_scan", Address: "192.0.2.2", Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if merged.Candidate.ID != known.Candidate.ID || len(merged.MergedIDs) != 1 || merged.MergedIDs[0] != pending.Candidate.ID {
		t.Fatalf("unexpected merge: %+v", merged)
	}
	if got := inbox.Snapshot().Candidates; len(got) != 1 || len(got[0].Endpoints) != 2 {
		t.Fatalf("unexpected snapshot after merge: %+v", got)
	}
	events := inbox.EventsSince(2)
	if len(events.Events) != 1 || events.Events[0].Type != EventMerged || len(events.Events[0].MergedIDs) != 1 {
		t.Fatalf("missing merge event: %+v", events)
	}
}

func TestDifferentFingerprintsAtReusedEndpointNeverMerge(t *testing.T) {
	inbox := New(Options{})
	first, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.20", Fingerprint: testFingerprint("old")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.20", Fingerprint: testFingerprint("new")})
	if err != nil {
		t.Fatal(err)
	}
	if first.Candidate.ID == second.Candidate.ID || len(inbox.Snapshot().Candidates) != 2 {
		t.Fatal("different identities at one endpoint were merged")
	}

	// A later no-key advertisement is ambiguous and must not be attributed to
	// either cryptographic identity.
	unknown, err := inbox.Ingest(Observation{Source: "bonjour", Address: "192.0.2.20", Name: "Reused IP"})
	if err != nil {
		t.Fatal(err)
	}
	if !unknown.Created || unknown.Candidate.Fingerprint != "" || len(inbox.Snapshot().Candidates) != 3 {
		t.Fatalf("ambiguous no-key observation was unsafely attributed: %+v", unknown)
	}
}

func TestConfiguredFingerprintLifecycleAndPersistence(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "state", "candidates.json")
	fingerprint := testFingerprint("configured")
	inbox, err := Open(path, Options{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ReplaceConfiguredFingerprints([]ConfiguredFingerprint{
		{Fingerprint: fingerprint + "=", DeviceNames: []string{"m4alpha", "m4alpha"}},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.30", Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate.State != StateVerified || len(result.Candidate.ConfiguredNames) != 1 || result.Candidate.VerifiedAt != nil {
		t.Fatalf("configured identity was not distinguished: %+v", result.Candidate)
	}

	reopened, err := Open(path, Options{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Snapshot().Candidates
	if len(got) != 1 || got[0].ConfiguredNames[0] != "m4alpha" || got[0].State != StateVerified {
		t.Fatalf("configured state did not survive restart: %+v", got)
	}
	if err := reopened.ReplaceConfiguredFingerprints(nil); err != nil {
		t.Fatal(err)
	}
	got = reopened.Snapshot().Candidates
	if got[0].State != StateIdentityPending || len(got[0].ConfiguredNames) != 0 {
		t.Fatalf("removed configuration did not return to review: %+v", got[0])
	}
	verified, err := reopened.MarkVerified(got[0].ID)
	if err != nil || verified.State != StateVerified || verified.VerifiedAt == nil {
		t.Fatalf("explicit verification failed: candidate=%+v err=%v", verified, err)
	}
}

func TestConfiguredFingerprintReplacementIsValidatedAndIdempotent(t *testing.T) {
	inbox := New(Options{})
	fingerprint := testFingerprint("configured-idempotent")
	result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.31", Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range [][]ConfiguredFingerprint{
		{{Fingerprint: "invalid", DeviceNames: []string{"mac"}}},
		{{Fingerprint: fingerprint}},
		{{Fingerprint: fingerprint, DeviceNames: []string{"bad\nname"}}},
	} {
		if err := inbox.ReplaceConfiguredFingerprints(configured); err == nil {
			t.Errorf("invalid configured fingerprints were accepted: %+v", configured)
		}
	}
	configured := []ConfiguredFingerprint{{Fingerprint: fingerprint, DeviceNames: []string{"mac"}}}
	if err := inbox.ReplaceConfiguredFingerprints(configured); err != nil {
		t.Fatal(err)
	}
	sequence := inbox.Snapshot().Sequence
	if err := inbox.ReplaceConfiguredFingerprints(configured); err != nil {
		t.Fatal(err)
	}
	if got := inbox.Snapshot().Sequence; got != sequence {
		t.Fatalf("idempotent replacement advanced sequence from %d to %d", sequence, got)
	}
	if err := inbox.ReplaceConfiguredFingerprints([]ConfiguredFingerprint{{Fingerprint: fingerprint, DeviceNames: []string{"renamed"}}}); err != nil {
		t.Fatal(err)
	}
	got := inbox.Snapshot().Candidates
	if len(got) != 1 || got[0].ID != result.Candidate.ID || len(got[0].ConfiguredNames) != 1 || got[0].ConfiguredNames[0] != "renamed" {
		t.Fatalf("configured name replacement was not applied: %+v", got)
	}
}

func TestIgnoreIsPermanentAcrossTTLAndRestart(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "state", "candidates.json")
	inbox, err := Open(path, Options{Clock: clock.Now, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	result, err := inbox.Ingest(Observation{Source: "bonjour", Address: "192.0.2.40"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.MarkVerified(result.Candidate.ID); err == nil {
		t.Fatal("verified a candidate with no fingerprint")
	}
	ignored, err := inbox.Ignore(result.Candidate.ID)
	if err != nil || ignored.State != StateIgnored || ignored.IgnoredAt == nil {
		t.Fatalf("ignore failed: candidate=%+v err=%v", ignored, err)
	}
	clock.Advance(48 * time.Hour)
	if expired, err := inbox.Expire(); err != nil || len(expired) != 0 {
		t.Fatalf("ignored candidate expired: ids=%v err=%v", expired, err)
	}

	reopened, err := Open(path, Options{Clock: clock.Now, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Snapshot().Candidates
	if len(got) != 1 || got[0].State != StateIgnored {
		t.Fatalf("ignore did not survive restart: %+v", got)
	}
	if _, err := reopened.Restore(got[0].ID); err != nil {
		t.Fatal(err)
	}
	expired, err := reopened.Expire()
	if err != nil || len(expired) != 1 || expired[0] != got[0].ID || len(reopened.Snapshot().Candidates) != 0 {
		t.Fatalf("restored stale candidate did not expire: ids=%v err=%v", expired, err)
	}
}

func TestEventCursorAndSnapshotCopies(t *testing.T) {
	inbox := New(Options{MaxEvents: 2})
	for i := 1; i <= 3; i++ {
		if _, err := inbox.Ingest(Observation{Source: "scan", Address: fmt.Sprintf("192.0.2.%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if batch := inbox.EventsSince(0); !batch.ResetRequired || len(batch.Events) != 0 || batch.LatestSequence != 3 {
		t.Fatalf("expected reset for stale cursor: %+v", batch)
	}
	batch := inbox.EventsSince(1)
	if batch.ResetRequired || len(batch.Events) != 2 || batch.Events[0].Sequence != 2 || batch.Events[1].Sequence != 3 {
		t.Fatalf("unexpected retained events: %+v", batch)
	}
	batch.Events[0].Candidate.Names = append(batch.Events[0].Candidate.Names, "mutated")
	snapshot := inbox.Snapshot()
	snapshot.Candidates[0].Sources[0] = "mutated"
	if strings.Contains(mustJSON(t, inbox.Snapshot()), "mutated") || strings.Contains(mustJSON(t, inbox.EventsSince(1)), "mutated") {
		t.Fatal("caller mutated internal snapshot or event state")
	}
}

func TestIngestValidationAndBatchRollback(t *testing.T) {
	clock := newTestClock()
	inbox := New(Options{Clock: clock.Now, MaxCandidates: 1})
	invalid := []Observation{
		{},
		{Source: "bad\x1bsource", Address: "192.0.2.1"},
		{Source: "scan", Address: "example.test"},
		{Source: "scan", Address: "192.0.2.1", Port: 65536},
		{Source: "scan", Address: "192.0.2.1", Fingerprint: "MD5:aa"},
		{Source: "scan", Address: "192.0.2.1", Fingerprint: "SHA256:short"},
		{Source: "scan", Name: "bad\nname"},
		{Source: "scan", Address: "192.0.2.1", ObservedAt: clock.Now().Add(6 * time.Minute)},
	}
	for i, observation := range invalid {
		if _, err := inbox.Ingest(observation); err == nil {
			t.Errorf("invalid observation %d was accepted: %+v", i, observation)
		}
	}
	if len(inbox.Snapshot().Candidates) != 0 {
		t.Fatal("invalid observations changed state")
	}
	if _, err := inbox.IngestMany([]Observation{
		{Source: "scan", Address: "192.0.2.1"},
		{Source: "scan", Address: "bad address"},
	}); err == nil || len(inbox.Snapshot().Candidates) != 0 || inbox.Snapshot().Sequence != 0 {
		t.Fatalf("batch with an invalid observation was not rolled back: snapshot=%+v", inbox.Snapshot())
	}
}

func TestIngestAtCapacityDropsCreationWithoutFailingTheRound(t *testing.T) {
	clock := newTestClock()
	inbox := New(Options{Clock: clock.Now, MaxCandidates: 1})
	results, err := inbox.IngestMany([]Observation{
		{Source: "scan", Address: "192.0.2.1"},
		{Source: "scan", Address: "192.0.2.2"},
	})
	if err != nil {
		t.Fatalf("full inbox failed the round: %v", err)
	}
	// The first observation is recorded; the second cannot displace an entry
	// this same round wrote, so it is dropped rather than failing the batch.
	if len(results) != 2 || results[0].Dropped || results[0].Candidate.ID == "" || !results[1].Dropped {
		t.Fatalf("unexpected results: %+v", results)
	}
	if inbox.Dropped() != 1 {
		t.Fatalf("dropped counter = %d, want 1", inbox.Dropped())
	}
	snapshot := inbox.Snapshot()
	if snapshot.DroppedObservations != 1 || snapshot.EvictedCandidates != 0 || snapshot.Sequence != 2 {
		t.Fatalf("capacity counters were not surfaced in the snapshot: %+v", snapshot)
	}
	if results[1].DroppedObservation == nil || results[1].DroppedObservation.Address != "192.0.2.2" {
		t.Fatalf("dropped observation was not preserved for logging: %+v", results[1])
	}
	events := inbox.EventsSince(0).Events
	if len(events) != 2 || events[1].Type != EventDropped {
		t.Fatalf("capacity drop event missing: %+v", events)
	}
	if events[1].Candidate != nil || events[1].CandidateID != "" {
		t.Fatalf("capacity drop event incorrectly identified an admitted candidate: %+v", events[1])
	}
	candidates := snapshot.Candidates
	if len(candidates) != 1 {
		t.Fatalf("inbox holds %d candidates, want 1", len(candidates))
	}

	// A later round must still refresh the candidate that is already recorded.
	clock.Advance(time.Hour)
	updated, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
	if err != nil {
		t.Fatalf("update at capacity failed: %v", err)
	}
	if updated.Created || updated.Dropped || !updated.Candidate.LastSeen.After(candidates[0].LastSeen) {
		t.Fatalf("existing candidate was not updated at capacity: %+v", updated)
	}
}

func TestCapacityTelemetryIsJSONVisibleAndEventHistoryRemainsBounded(t *testing.T) {
	inbox := New(Options{MaxCandidates: 1, MaxEvents: 1, TTL: -1})
	first, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Ignore(first.Candidate.ID); err != nil {
		t.Fatal(err)
	}
	result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Dropped {
		t.Fatalf("capacity observation was not dropped: %+v", result)
	}
	payload := mustJSON(t, inbox.Snapshot())
	if !strings.Contains(payload, `"dropped_observations":1`) || !strings.Contains(payload, `"evicted_candidates":0`) {
		t.Fatalf("capacity counters missing from snapshot JSON: %s", payload)
	}
	batch := inbox.EventsSince(1)
	if !batch.ResetRequired || len(batch.Events) != 0 || batch.LatestSequence != inbox.Snapshot().Sequence {
		t.Fatalf("stale capacity-event cursor did not require a snapshot reset: %+v", batch)
	}
	latest := inbox.EventsSince(batch.LatestSequence)
	if latest.ResetRequired || len(latest.Events) != 0 || latest.LatestSequence != batch.LatestSequence {
		t.Fatalf("latest cursor returned unexpected capacity events: %+v", latest)
	}
}

func TestCandidateTransitionsRejectMissingAndInvalidStates(t *testing.T) {
	inbox := New(Options{})
	if _, err := inbox.Ignore("cand_missing"); err == nil {
		t.Fatal("missing candidate was ignored")
	}
	result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Restore(result.Candidate.ID); err == nil {
		t.Fatal("non-ignored candidate was restored")
	}
	if _, err := inbox.MarkVerified(result.Candidate.ID); err == nil {
		t.Fatal("candidate without a fingerprint was verified")
	}
}

func TestIngestAtCapacityEvictsOldestUnreviewedCandidate(t *testing.T) {
	clock := newTestClock()
	inbox := New(Options{Clock: clock.Now, MaxCandidates: 2, TTL: -1})
	oldest, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1", Fingerprint: testFingerprint("capacity")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.MarkVerified(oldest.Candidate.ID); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	unreviewed, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	fresh, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.3"})
	if err != nil {
		t.Fatalf("full inbox failed the round: %v", err)
	}
	if fresh.Dropped || !fresh.Created {
		t.Fatalf("new candidate was not admitted by eviction: %+v", fresh)
	}
	ids := make(map[string]bool)
	for _, candidate := range inbox.Snapshot().Candidates {
		ids[candidate.ID] = true
	}
	if !ids[oldest.Candidate.ID] {
		t.Fatal("eviction removed an operator-verified candidate")
	}
	if ids[unreviewed.Candidate.ID] {
		t.Fatal("oldest unreviewed candidate was not evicted")
	}
	if inbox.Dropped() != 0 {
		t.Fatalf("dropped counter = %d, want 0", inbox.Dropped())
	}
	if inbox.Evicted() != 1 || inbox.Snapshot().EvictedCandidates != 1 {
		t.Fatalf("evicted counter = %d snapshot=%+v, want 1", inbox.Evicted(), inbox.Snapshot())
	}
	if len(fresh.EvictedIDs) != 1 || fresh.EvictedIDs[0] != unreviewed.Candidate.ID {
		t.Fatalf("evicted ID was not returned for logging: %+v", fresh)
	}
	events := inbox.EventsSince(0).Events
	last := events[len(events)-2]
	if last.Type != EventEvicted || last.CandidateID != unreviewed.Candidate.ID {
		t.Fatalf("eviction event missing: %+v", events)
	}
}

func TestIngestAtCapacityNeverEvictsPinnedCandidates(t *testing.T) {
	clock := newTestClock()
	inbox := New(Options{Clock: clock.Now, MaxCandidates: 2, TTL: -1})
	verified, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1", Fingerprint: testFingerprint("capacity")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.MarkVerified(verified.Candidate.ID); err != nil {
		t.Fatal(err)
	}
	ignored, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Ignore(ignored.Candidate.ID); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	dropped, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.3"})
	if err != nil {
		t.Fatalf("full inbox failed the round: %v", err)
	}
	if !dropped.Dropped || dropped.Created {
		t.Fatalf("pinned candidate was displaced: %+v", dropped)
	}
	if inbox.Dropped() != 1 {
		t.Fatalf("dropped counter = %d, want 1", inbox.Dropped())
	}
	if len(inbox.Snapshot().Candidates) != 2 {
		t.Fatalf("inbox holds %d candidates, want 2", len(inbox.Snapshot().Candidates))
	}
	// Updates to the pinned candidates must keep working while at the limit.
	refreshed, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
	if err != nil || refreshed.Dropped || refreshed.Candidate.ID != verified.Candidate.ID {
		t.Fatalf("existing candidate update was blocked at capacity: result=%+v err=%v", refreshed, err)
	}
}

func TestFailedDurableWriteRollsBackMemory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "candidates.json")
	inbox, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.50"}); err == nil {
		t.Fatal("expected durable write failure")
	}
	if snapshot := inbox.Snapshot(); len(snapshot.Candidates) != 0 || snapshot.Sequence != 0 {
		t.Fatalf("memory advanced after failed write: %+v", snapshot)
	}
}

func TestFailedDurableWriteRollsBackCapacityCounters(t *testing.T) {
	t.Run("drop", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "candidates.json")
		inbox, err := Open(path, Options{MaxCandidates: 1, TTL: -1})
		if err != nil {
			t.Fatal(err)
		}
		result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1", Fingerprint: testFingerprint("pinned")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inbox.MarkVerified(result.Candidate.ID); err != nil {
			t.Fatal(err)
		}
		before := inbox.Snapshot()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.2"}); err == nil {
			t.Fatal("expected durable drop write to fail")
		}
		after := inbox.Snapshot()
		if after.DroppedObservations != before.DroppedObservations ||
			after.EvictedCandidates != before.EvictedCandidates || after.Sequence != before.Sequence {
			t.Fatalf("capacity counters advanced after failed write: before=%+v after=%+v", before, after)
		}
	})

	t.Run("eviction", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "candidates.json")
		inbox, err := Open(path, Options{MaxCandidates: 1, TTL: -1})
		if err != nil {
			t.Fatal(err)
		}
		original, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		before := inbox.Snapshot()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.2"}); err == nil {
			t.Fatal("expected durable eviction write to fail")
		}
		after := inbox.Snapshot()
		if after.EvictedCandidates != before.EvictedCandidates || after.Sequence != before.Sequence ||
			len(after.Candidates) != 1 || after.Candidates[0].ID != original.Candidate.ID {
			t.Fatalf("eviction state advanced after failed write: before=%+v after=%+v", before, after)
		}
	})
}

func TestConcurrentIngestDeduplicatesFingerprint(t *testing.T) {
	inbox := New(Options{})
	fingerprint := testFingerprint("concurrent")
	var wg sync.WaitGroup
	errors := make(chan error, 32)
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := inbox.Ingest(Observation{Source: "scan", Address: fmt.Sprintf("198.51.100.%d", i), Fingerprint: fingerprint})
			errors <- err
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot := inbox.Snapshot()
	if len(snapshot.Candidates) != 1 || len(snapshot.Candidates[0].Endpoints) != 32 {
		t.Fatalf("concurrent observations were not deduplicated: %+v", snapshot)
	}
}

func TestOpenRejectsUnsafeOrMalformedStore(t *testing.T) {
	root := t.TempDir()
	unknown := filepath.Join(root, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"version":1,"sequence":0,"candidates":[],"surprise":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unknown, Options{}); err == nil {
		t.Fatal("store with unknown field was accepted")
	}

	oversized := filepath.Join(root, "oversized.json")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxStoreSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := Open(oversized, Options{}); err == nil {
		t.Fatal("oversized store was accepted")
	}

	if runtime.GOOS != "windows" {
		loose := filepath.Join(root, "loose.json")
		if err := os.WriteFile(loose, []byte(`{"version":1,"sequence":0,"candidates":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(loose, Options{}); err == nil {
			t.Fatal("world-readable store was accepted")
		}

		target := filepath.Join(root, "target.json")
		if err := os.WriteFile(target, []byte(`{"version":1,"sequence":0,"candidates":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link, Options{}); err == nil {
			t.Fatal("symlinked store was accepted")
		}
	}
}

func TestSecureAtomicStorePermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private", "candidates.json")
	inbox, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Ingest(Observation{Source: "bonjour", Hostname: "mac.local", Address: "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Ingest(Observation{Source: "scan", Address: "2001:db8::1", Fingerprint: testFingerprint("mac")}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fileInfo, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm() != 0o600 {
			t.Fatalf("store mode = %o, want 600", fileInfo.Mode().Perm())
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode = %o, want 700", dirInfo.Mode().Perm())
		}
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".candidates-*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, err=%v", matches, err)
	}
	reopened, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Snapshot().Candidates; len(got) != 1 || got[0].Fingerprint == "" || len(got[0].Endpoints) != 1 {
		t.Fatalf("unexpected reopened state: %+v", got)
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func testFingerprint(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

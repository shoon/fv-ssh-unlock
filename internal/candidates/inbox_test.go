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
	_, err := inbox.IngestMany([]Observation{
		{Source: "scan", Address: "192.0.2.1"},
		{Source: "scan", Address: "192.0.2.2"},
	})
	if err == nil || len(inbox.Snapshot().Candidates) != 0 || inbox.Snapshot().Sequence != 0 {
		t.Fatalf("failed batch was not rolled back: err=%v snapshot=%+v", err, inbox.Snapshot())
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

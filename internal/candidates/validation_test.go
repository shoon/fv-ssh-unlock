// SPDX-License-Identifier: Apache-2.0

package candidates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateCandidateRejectsMalformedDurableFields(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	valid := Candidate{
		ID:        "cand_" + strings.Repeat("a", 32),
		State:     StateDiscovered,
		Names:     []string{"mac"},
		Sources:   []string{"scan"},
		FirstSeen: now,
		LastSeen:  now,
	}
	zero := time.Time{}
	earlier := now.Add(-time.Second)
	mutations := map[string]func(*Candidate){
		"id length":                 func(c *Candidate) { c.ID = "cand_short" },
		"id hex":                    func(c *Candidate) { c.ID = "cand_" + strings.Repeat("z", 32) },
		"state":                     func(c *Candidate) { c.State = State("unknown") },
		"fingerprint canonical":     func(c *Candidate) { c.Fingerprint = testFingerprint("key") + "=" },
		"discovered fingerprint":    func(c *Candidate) { c.Fingerprint = testFingerprint("key") },
		"pending without key":       func(c *Candidate) { c.State = StateIdentityPending },
		"verified without key":      func(c *Candidate) { c.State = StateVerified },
		"ignored without timestamp": func(c *Candidate) { c.State = StateIgnored },
		"unexpected ignored time":   func(c *Candidate) { c.IgnoredAt = &now },
		"configured without key":    func(c *Candidate) { c.ConfiguredNames = []string{"configured"} },
		"no identity": func(c *Candidate) {
			c.Names = nil
			c.Sources = nil
		},
		"zero first seen":   func(c *Candidate) { c.FirstSeen = time.Time{} },
		"last before first": func(c *Candidate) { c.LastSeen = earlier },
		"name":              func(c *Candidate) { c.Names = []string{" bad"} },
		"hostname":          func(c *Candidate) { c.Hostnames = []string{"mac.local."} },
		"source":            func(c *Candidate) { c.Sources = []string{"bad\nsource"} },
		"configured name": func(c *Candidate) {
			c.Fingerprint = testFingerprint("key")
			c.State = StateIdentityPending
			c.ConfiguredNames = []string{"bad\nname"}
		},
		"key type":           func(c *Candidate) { c.KeyType = "bad\nkey" },
		"evidence":           func(c *Candidate) { c.LastEvidence = "bad\nevidence" },
		"zero verified time": func(c *Candidate) { c.VerifiedAt = &zero },
		"zero ignored time": func(c *Candidate) {
			c.State = StateIgnored
			c.IgnoredAt = &zero
		},
		"endpoint address": func(c *Candidate) {
			c.Endpoints = []Endpoint{{Address: "host.example", Port: 22, FirstSeen: now, LastSeen: now}}
		},
		"endpoint fields": func(c *Candidate) {
			c.Endpoints = []Endpoint{{Address: "192.0.2.1", Port: 0, FirstSeen: now, LastSeen: now}}
		},
	}
	if err := validateCandidate(valid); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateCandidate(candidate); err == nil {
				t.Fatalf("malformed candidate was accepted: %+v", candidate)
			}
		})
	}
}

func TestOpenRejectsInconsistentDurableState(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	first := Candidate{
		ID:        "cand_" + strings.Repeat("a", 32),
		State:     StateDiscovered,
		Names:     []string{"first"},
		FirstSeen: now,
		LastSeen:  now,
	}
	second := first
	second.ID = "cand_" + strings.Repeat("b", 32)
	second.Names = []string{"second"}
	key := testFingerprint("durable")
	cases := map[string]struct {
		state diskState
		opts  Options
	}{
		"version":      {state: diskState{Version: storeVersion + 1, Candidates: []Candidate{}}},
		"duplicate id": {state: diskState{Version: storeVersion, Candidates: []Candidate{first, first}}},
		"duplicate fingerprint": {state: func() diskState {
			a, b := first, second
			a.State, b.State = StateIdentityPending, StateIdentityPending
			a.Fingerprint, b.Fingerprint = key, key
			return diskState{Version: storeVersion, Candidates: []Candidate{a, b}}
		}()},
		"stale configured names": {state: func() diskState {
			candidate := first
			candidate.State = StateVerified
			candidate.Fingerprint = key
			return diskState{
				Version:    storeVersion,
				Configured: []ConfiguredFingerprint{{Fingerprint: key, DeviceNames: []string{"mac"}}},
				Candidates: []Candidate{candidate},
			}
		}()},
		"entry limit": {state: diskState{Version: storeVersion, Candidates: []Candidate{first, second}}, opts: Options{MaxCandidates: 1}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidates.json")
			data, err := json.Marshal(test.state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, test.opts); err == nil {
				t.Fatalf("inconsistent %s state was accepted", name)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"candidates":[]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{}); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing state was accepted: %v", err)
	}
}

func TestSaveStateRejectsOversizedEncoding(t *testing.T) {
	state := diskState{
		Version: storeVersion,
		Candidates: []Candidate{{
			LastEvidence: strings.Repeat("x", maxStoreSize+1),
		}},
	}
	if err := saveState(filepath.Join(t.TempDir(), "candidates.json"), state); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized state was accepted: %v", err)
	}
}

func TestRestoreReturnsFingerprintedCandidatesToCorrectReviewState(t *testing.T) {
	for name, verify := range map[string]bool{"pending": false, "verified": true} {
		t.Run(name, func(t *testing.T) {
			inbox := New(Options{})
			result, err := inbox.Ingest(Observation{
				Source: "scan", Address: "192.0.2.1", Fingerprint: testFingerprint(name),
			})
			if err != nil {
				t.Fatal(err)
			}
			if verify {
				result.Candidate, err = inbox.MarkVerified(result.Candidate.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inbox.Ignore(result.Candidate.ID); err != nil {
				t.Fatal(err)
			}
			restored, err := inbox.Restore(result.Candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := StateIdentityPending
			if verify {
				want = StateVerified
			}
			if restored.State != want || restored.IgnoredAt != nil {
				t.Fatalf("restored candidate = %+v, want state %s", restored, want)
			}
		})
	}
}

func TestExpireRollsBackWhenDurableWriteFails(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "private", "candidates.json")
	inbox, err := Open(path, Options{Clock: clock.Now, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	result, err := inbox.Ingest(Observation{Source: "scan", Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour)
	before := inbox.Snapshot()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Expire(); err == nil {
		t.Fatal("expiration succeeded despite durable write failure")
	}
	after := inbox.Snapshot()
	if after.Sequence != before.Sequence || len(after.Candidates) != 1 || after.Candidates[0].ID != result.Candidate.ID {
		t.Fatalf("expiration was not rolled back: before=%+v after=%+v", before, after)
	}
}

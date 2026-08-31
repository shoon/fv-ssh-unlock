// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
)

func TestCandidateDisplayDefaults(t *testing.T) {
	candidate := candidates.Candidate{
		Names:     []string{"Editing Mac Studio"},
		Endpoints: []candidates.Endpoint{{Address: "192.0.2.40", Port: 22}},
	}
	if got := candidateDefaultName(candidate); got != "editing-mac-studio" {
		t.Fatalf("default name = %q", got)
	}
	host, port := candidateDefaultEndpoint(candidate)
	if host != "192.0.2.40" || port != 22 {
		t.Fatalf("default endpoint = %s:%d", host, port)
	}
	if got := candidateLocation(candidate); got != "192.0.2.40:22" {
		t.Fatalf("location = %q", got)
	}
}

func TestRelativeTime(t *testing.T) {
	if got := relativeTime(time.Time{}); got != "never" {
		t.Fatalf("zero relative time = %q", got)
	}
}

func TestCandidateHostKeyPathUsesDiscoveredKeyType(t *testing.T) {
	for keyType, want := range map[string]string{
		"ssh-ed25519":         "/etc/ssh/ssh_host_ed25519_key.pub",
		"ssh-rsa":             "/etc/ssh/ssh_host_rsa_key.pub",
		"rsa-sha2-512":        "/etc/ssh/ssh_host_rsa_key.pub",
		"ecdsa-sha2-nistp256": "/etc/ssh/ssh_host_ecdsa_key.pub",
	} {
		if got := candidateHostKeyPath(keyType); got != want {
			t.Errorf("candidateHostKeyPath(%q) = %q, want %q", keyType, got, want)
		}
	}
}

// hostile is a candidate-supplied string carrying terminal control sequences.
// internal/candidates strips these at ingestion; this package sanitizes again at
// every print site so the guarantee does not rest on another package's rules.
const hostile = "mac\x1b[2Kevil\r\nSUCCESS: forged"

func TestRenderDashboardEscapesNetworkDerivedText(t *testing.T) {
	snapshot := dashboardSnapshot{}
	snapshot.Devices.Devices = []monitor.DeviceSnapshot{{
		Device:       monitor.Device{Name: hostile},
		DeviceRecord: monitor.DeviceRecord{State: monitor.State(hostile)},
	}}
	snapshot.Devices.Events = []monitor.Event{{Device: hostile, State: monitor.State(hostile), Message: hostile, Time: time.Now()}}
	snapshot.Candidates.Candidates = []candidates.Candidate{{
		ID:        "cand_1",
		State:     candidates.State(hostile),
		Hostnames: []string{hostile},
	}}

	var output bytes.Buffer
	if err := renderDashboard(&output, snapshot, false, hostile); err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, output.String())
}

func TestCandidatePromptDefaultsAreEscaped(t *testing.T) {
	var output bytes.Buffer
	keys := make(chan byte, 1)
	keys <- '\r'
	value, err := promptRawLineDefault(&output, keys, "Local alias", hostile)
	if err != nil {
		t.Fatal(err)
	}
	// The raw value is still what the operator accepts; only the display is
	// sanitized.
	if value != hostile {
		t.Fatalf("accepted default = %q, want the raw candidate value", value)
	}
	assertTerminalSafe(t, output.String())
}

// assertTerminalSafe fails when rendered output carries a raw control sequence
// that a hostile candidate could use to forge or erase terminal text. The
// renderer emits its own CR/LF and cursor toggles, so those fixed sequences are
// removed before the check.
func assertTerminalSafe(t *testing.T, rendered string) {
	t.Helper()
	if !strings.Contains(rendered, `\u001B`) {
		t.Fatalf("escape sequence was not rendered in escaped form:\n%q", rendered)
	}
	stripped := rendered
	for _, own := range []string{"\x1b[?25h", "\x1b[?25l", "\x1b[H\x1b[2J", "\r\n"} {
		stripped = strings.ReplaceAll(stripped, own, " ")
	}
	for _, forbidden := range []string{"\x1b", "\r"} {
		if strings.Contains(stripped, forbidden) {
			t.Fatalf("output carries unescaped %q:\n%q", forbidden, rendered)
		}
	}
}

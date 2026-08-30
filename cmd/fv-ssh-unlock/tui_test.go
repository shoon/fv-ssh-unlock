// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
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

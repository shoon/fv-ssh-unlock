// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newTestSigner returns a throwaway SSH key for public-key probing.
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// TestProbeStatusPublicKeyProvesBooted: a successful public-key handshake is
// definitive proof the device booted past the FileVault prompt, and it resolves
// what would otherwise be an indeterminate result -- without sending a password.
func TestProbeStatusPublicKeyProvesBooted(t *testing.T) {
	signer := newTestSigner(t)
	ts := startTestServer(t, testServerConfig{
		state:         "unlocked",
		authorizedKey: signer.PublicKey(),
	})

	c := newClient(ts.fixedHostKey())
	c.Signers = []ssh.Signer{signer}

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlockedRecently {
		t.Fatalf("expected StatusUnlockedRecently via public key, got %v", status)
	}
	if len(ts.gotPass) != 0 {
		t.Errorf("no password may be sent during a status probe; server got %v", ts.gotPass)
	}
}

// TestProbeStatusPublicKeyCannotUnlockLockedDevice is the safety-critical case:
// the pre-boot server never honors public keys, so offering them must NOT cause
// a locked device to be reported as unlocked.
func TestProbeStatusPublicKeyCannotUnlockLockedDevice(t *testing.T) {
	signer := newTestSigner(t)
	ts := startTestServer(t, testServerConfig{
		state:         "locked",
		authorizedKey: signer.PublicKey(), // offered, but the locked server refuses it
	})

	c := newClient(ts.fixedHostKey())
	c.Signers = []ssh.Signer{signer}

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if status == StatusUnlockedRecently || status == StatusUnlocked {
		t.Fatalf("a locked device must never be reported unlocked; got %v (err=%v)", status, err)
	}
	if status != StatusLocked {
		t.Fatalf("expected StatusLocked, got %v (err=%v)", status, err)
	}
	if ts.pubkeyAttempts == 0 {
		t.Errorf("expected the client to offer a public key")
	}
	if len(ts.gotPass) != 0 {
		t.Errorf("no password may be sent during a status probe; server got %v", ts.gotPass)
	}
}

// TestProbeStatusUnauthorizedKeyStaysIndeterminate: a key the host does not
// accept must not change the verdict -- we still admit we cannot tell.
func TestProbeStatusUnauthorizedKeyStaysIndeterminate(t *testing.T) {
	ts := startTestServer(t, testServerConfig{
		state:         "unlocked",
		noBanner:      true,
		authorizedKey: newTestSigner(t).PublicKey(), // a DIFFERENT key is authorized
	})

	c := newClient(ts.fixedHostKey())
	c.Signers = []ssh.Signer{newTestSigner(t)} // ours is not authorized

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	// The booted test server accepts keyboard-interactive outright, so it may
	// resolve as booted; what must never happen is a "locked" verdict.
	if status == StatusLocked {
		t.Fatalf("an unauthorized key must not produce a locked verdict (err=%v)", err)
	}
}

// TestAnalyzePromptStillUnlocksWithSignersPresent guards against a regression:
// offering public keys must not disturb the real unlock path, which depends on
// the keyboard-interactive password exchange.
func TestAnalyzePromptStillUnlocksWithSignersPresent(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	c := newClient(ts.fixedHostKey())
	c.Signers = []ssh.Signer{newTestSigner(t)}

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlocked {
		t.Fatalf("expected StatusUnlocked, got %v", status)
	}
	if !ts.receivedPassword("s3cret") {
		t.Errorf("the unlock password should still be delivered over keyboard-interactive")
	}
}

// TestProbeStatusHostKeyMismatchBeatsPublicKey: host-key verification must fail
// closed even when we hold a valid key for the host.
func TestProbeStatusHostKeyMismatchBeatsPublicKey(t *testing.T) {
	signer := newTestSigner(t)
	ts := startTestServer(t, testServerConfig{
		state:         "unlocked",
		authorizedKey: signer.PublicKey(),
	})

	c := &RealSSHClient{
		DialTimeout:     5 * time.Second,
		HostKeyCallback: ssh.FixedHostKey(mustHostKey(t)), // wrong host key
		Signers:         []ssh.Signer{signer},
	}

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("expected ErrHostKeyMismatch, got %v", err)
	}
	if status != StatusUnknown {
		t.Fatalf("expected StatusUnknown on host-key mismatch, got %v", status)
	}
}

// TestHostKeyMismatchDetectedFromPlainError guards a subtle bug: host-key
// callbacks report failures inconsistently (knownhosts returns a typed error,
// ssh.FixedHostKey and custom callbacks return plain ones). All of them must be
// recognised, because VerifyUnlock aborts on ErrHostKeyMismatch and must never
// keep retrying through a possible man-in-the-middle.
func TestHostKeyMismatchDetectedFromPlainError(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})

	cases := map[string]ssh.HostKeyCallback{
		"ssh.FixedHostKey (plain error)": ssh.FixedHostKey(mustHostKey(t)),
		"custom callback wrapping the sentinel": func(string, net.Addr, ssh.PublicKey) error {
			return fmt.Errorf("%w: refused", ErrHostKeyMismatch)
		},
		"custom callback, unwrapped text": func(string, net.Addr, ssh.PublicKey) error {
			return errors.New("ssh: host key mismatch")
		},
	}
	for name, cb := range cases {
		t.Run(name, func(t *testing.T) {
			c := &RealSSHClient{DialTimeout: 5 * time.Second, HostKeyCallback: cb}
			_, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
			if !errors.Is(err, ErrHostKeyMismatch) {
				t.Fatalf("expected ErrHostKeyMismatch, got %v", err)
			}
			if ts.receivedPassword("s3cret") {
				t.Fatalf("password must never be sent to a host that failed key verification")
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLogSafeInlineEscapesControlAndFormattingCharacters(t *testing.T) {
	got := logSafeInline("host\r\nspoof\x1b]52;c;value\a\u202e")
	if strings.ContainsAny(got, "\r\n\x1b\a") || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("logSafeInline retained a control or formatting character: %q", got)
	}
}

func newClient(hostKey ssh.HostKeyCallback) *RealSSHClient {
	return &RealSSHClient{DialTimeout: 5 * time.Second, HostKeyCallback: hostKey}
}

func TestAnalyzePromptLockedCorrectPassword(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	c := newClient(ts.fixedHostKey())

	status, out, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlocked {
		t.Fatalf("expected StatusUnlocked, got %v", status)
	}
	if !ts.receivedPassword("s3cret") {
		t.Errorf("server never received the password over keyboard-interactive")
	}
	if out == "" {
		t.Errorf("expected captured banner text")
	}
}

func TestAnalyzePromptLockedWrongPassword(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "wrong", "")
	if status != StatusLocked {
		t.Fatalf("expected StatusLocked, got %v", status)
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestAnalyzePromptAlreadyUnlocked(t *testing.T) {
	ts := startTestServer(t, testServerConfig{state: "unlocked"})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "whatever", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlockedRecently {
		t.Fatalf("expected StatusUnlockedRecently, got %v", status)
	}
}

// TestAnalyzePromptEofIsNotSuccess ensures that a connection that closes
// without the success banner is NOT reported as a successful unlock.
func TestAnalyzePromptEofIsNotSuccess(t *testing.T) {
	// A raw TCP server that accepts then immediately closes: no SSH, no banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := newClient(ssh.FixedHostKey(mustHostKey(t)))
	status, _, err := c.AnalyzePrompt(context.Background(), ln.Addr().String(), "user", "pw", "")
	if status == StatusUnlocked {
		t.Fatalf("a bare connection close must not be reported as unlocked")
	}
	if err == nil {
		t.Fatalf("expected an error for a closed connection")
	}
}

func TestAnalyzePromptHostKeyMismatch(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	// Pin a DIFFERENT key than the server presents.
	c := newClient(ssh.FixedHostKey(mustHostKey(t)))

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err == nil {
		t.Fatalf("expected host-key verification to fail")
	}
	if status == StatusUnlocked {
		t.Fatalf("must not report unlocked when the host key does not match")
	}
	if ts.receivedPassword("s3cret") {
		t.Errorf("password must NOT be sent to a host that fails key verification")
	}
}

func TestAnalyzePromptNoHostKeyFailsClosed(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	// No HostKeyCallback and not insecure -> must refuse to connect.
	c := &RealSSHClient{DialTimeout: 5 * time.Second}

	_, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err == nil {
		t.Fatalf("expected fail-closed error with no host-key verification configured")
	}
	if ts.receivedPassword("s3cret") {
		t.Errorf("password must NOT be sent when host-key verification is unconfigured")
	}
}

func TestAnalyzePromptConnectionRefused(t *testing.T) {
	// Grab a free port, then close it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := newClient(ssh.FixedHostKey(mustHostKey(t)))
	_, _, err = c.AnalyzePrompt(context.Background(), addr, "user", "pw", "")
	if !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("expected ErrConnectionRefused, got %v", err)
	}
}

func TestAnalyzePromptContextCancelled(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClient(ts.fixedHostKey())
	status, _, err := c.AnalyzePrompt(ctx, ts.addr, "user", "s3cret", "")
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if status == StatusUnlocked {
		t.Fatalf("cancelled context must not report unlocked")
	}
}

// TestAnalyzePromptRefusesUnexpectedPrompts verifies the client never answers a
// multi-question challenge, so a hostile server cannot harvest the password.
func TestAnalyzePromptRefusesUnexpectedPrompts(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret", extraQuestions: 2})
	c := newClient(ts.fixedHostKey())

	status, _, _ := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if status == StatusUnlocked {
		t.Fatalf("must not report unlocked for an unexpected multi-question challenge")
	}
	if ts.receivedPassword("s3cret") {
		t.Fatalf("password must NOT be sent in answer to an unexpected challenge")
	}
}

func TestAnalyzePromptRefusesArbitraryHiddenPromptAndPasswordFallback(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret", prompt: "Enter recovery token: "})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err == nil || status == StatusUnlocked {
		t.Fatalf("unexpected prompt must fail, got status=%v err=%v", status, err)
	}
	if ts.receivedPassword("s3cret") {
		t.Fatalf("password leaked through an unexpected prompt or password-auth fallback")
	}
}

func TestAnalyzePromptIgnoresSuccessPhraseBeforePassword(t *testing.T) {
	ts := startTestServer(t, testServerConfig{
		password:      "s3cret",
		preAuthBanner: "System successfully unlocked.",
	})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "wrong", "")
	if status != StatusLocked || !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("pre-auth success text forged status=%v err=%v", status, err)
	}
}

func TestAnalyzePromptRejectsPasswordPromptAsCustomSuccess(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret", successMsg: "Password:"})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "Password:")
	if status == StatusUnlocked || err == nil {
		t.Fatalf("password prompt forged custom success: status=%v err=%v", status, err)
	}
}

func TestProbeStatusLockedSendsNoPassword(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret"})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusLocked {
		t.Fatalf("expected StatusLocked, got %v", status)
	}
	if len(ts.gotPass) != 0 {
		t.Errorf("ProbeStatus must not send any password; server received %v", ts.gotPass)
	}
}

func TestProbeStatusUnlocked(t *testing.T) {
	ts := startTestServer(t, testServerConfig{state: "unlocked"})
	c := newClient(ts.fixedHostKey())

	status, _, err := c.ProbeStatus(context.Background(), ts.addr, "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusUnlockedRecently {
		t.Fatalf("expected StatusUnlockedRecently, got %v", status)
	}
}

func TestParseOutput(t *testing.T) {
	cases := []struct {
		in   string
		want DeviceStatus
	}{
		{"This system is locked. Enter password:", StatusLocked},
		{"Password:", StatusLocked},
		{"System successfully unlocked.", StatusUnlocked},
		{"Last login: user@host", StatusUnlockedRecently},
		{"some unrelated text", StatusUnknown},
		{"", StatusUnknown},
	}
	for _, c := range cases {
		if got := ParseOutput(c.in); got != c.want {
			t.Errorf("ParseOutput(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// mustHostKey returns a fresh, unrelated public key for negative host-key tests.
func mustHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	ts := startTestServer(t, testServerConfig{})
	return ts.hostKey
}

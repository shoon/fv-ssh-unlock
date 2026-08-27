// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server that models the macOS 26 (Tahoe)
// FileVault pre-boot unlock protocol, so tests exercise the real SSH path
// rather than simulated shortcuts.
type testServer struct {
	addr    string
	hostKey ssh.PublicKey

	mu              sync.Mutex
	gotPass         []string // passwords the server received over keyboard-interactive
	gotPasswordAuth []string // passwords received through SSH password auth
	kbdCount        int
	pubkeyAttempts  int
}

type testServerConfig struct {
	state      string // "locked" (default) or "unlocked"
	password   string
	banner     string
	successMsg string
	// extraQuestions, if >0, makes the locked server ask that many questions in
	// a single challenge (used to test that the client refuses to answer
	// unexpected prompts).
	extraQuestions int
	// prompt overrides the normal Password: question.
	prompt string
	// preAuthBanner is sent before authentication starts.
	preAuthBanner string
	// noBanner suppresses the banner, modelling a booted sshd that prompts for
	// a password without any FileVault locked banner.
	noBanner bool
	// authorizedKey, when set, is accepted for public-key auth -- but ONLY in
	// the "unlocked" state. This mirrors the real device: authorized_keys lives
	// on the data volume, so the pre-boot server can never honor public keys.
	authorizedKey ssh.PublicKey
}

// startTestServer starts the server on an ephemeral loopback port and returns
// it. The listener is closed automatically when the test ends.
func startTestServer(t *testing.T, cfg testServerConfig) *testServer {
	t.Helper()
	if cfg.state == "" {
		cfg.state = "locked"
	}
	if cfg.password == "" {
		cfg.password = "correct-horse"
	}
	if cfg.banner == "" {
		cfg.banner = "This system is locked. Enter your password."
	}
	if cfg.successMsg == "" {
		cfg.successMsg = "System successfully unlocked.\r\nYou may now use SSH to authenticate normally.\r\n"
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ts := &testServer{hostKey: signer.PublicKey()}

	sc := &ssh.ServerConfig{
		ServerVersion:  "SSH-2.0-OpenSSH_10.0",
		BannerCallback: func(ssh.ConnMetadata) string { return cfg.preAuthBanner },
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ts.mu.Lock()
			ts.pubkeyAttempts++
			ts.mu.Unlock()
			// The pre-boot server cannot read authorized_keys, so public-key
			// auth only ever succeeds once the machine has booted.
			if cfg.state == "unlocked" && cfg.authorizedKey != nil &&
				string(key.Marshal()) == string(cfg.authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("publickey not accepted")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ts.mu.Lock()
			ts.gotPasswordAuth = append(ts.gotPasswordAuth, string(password))
			ts.mu.Unlock()
			if cfg.state == "unlocked" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password not accepted")
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ts.mu.Lock()
			ts.kbdCount++
			ts.mu.Unlock()
			if cfg.state == "unlocked" {
				return &ssh.Permissions{}, nil
			}
			prompt := cfg.prompt
			if prompt == "" {
				prompt = "Password: "
			}
			questions := []string{prompt}
			echos := []bool{false}
			for i := 0; i < cfg.extraQuestions; i++ {
				questions = append(questions, fmt.Sprintf("Extra %d: ", i))
				echos = append(echos, false)
			}
			instruction := cfg.banner
			if cfg.noBanner {
				instruction = ""
			}
			answers, err := challenge("", instruction, questions, echos)
			if err != nil {
				return nil, err
			}
			ts.mu.Lock()
			ts.gotPass = append(ts.gotPass, answers...)
			ts.mu.Unlock()
			if len(answers) == 1 && answers[0] == cfg.password {
				// Emit the success banner as an info-only challenge, then fail
				// auth and disconnect, as on the real device.
				_, _ = challenge("", cfg.successMsg, nil, nil)
				return nil, fmt.Errorf("unlocked; closing connection")
			}
			return nil, fmt.Errorf("permission denied")
		},
	}
	sc.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ts.addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(c, sc)
				if err != nil {
					return // expected in the locked state
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no shell provided by test server")
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ts
}

// fixedHostKey returns a callback pinning this server's real host key.
func (ts *testServer) fixedHostKey() ssh.HostKeyCallback {
	return ssh.FixedHostKey(ts.hostKey)
}

// receivedPassword reports whether the server received the password through
// any SSH authentication method.
func (ts *testServer) receivedPassword(pw string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, p := range ts.gotPass {
		if p == pw {
			return true
		}
	}
	for _, p := range ts.gotPasswordAuth {
		if p == pw {
			return true
		}
	}
	return false
}

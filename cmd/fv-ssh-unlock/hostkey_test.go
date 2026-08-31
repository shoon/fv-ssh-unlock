// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestHostKeyUnknownFailsClosed(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	cb, err := hostKeyCallback(path, false)
	if err != nil {
		t.Fatal(err)
	}
	err = cb("host.example:22", &net.TCPAddr{}, testPublicKey(t))
	if !errors.Is(err, fvcore.ErrHostKeyMismatch) {
		t.Fatalf("unknown key should fail closed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("refused key was unexpectedly recorded")
	}
}

func TestNewSSHClientRejectsConflictingHostKeyFlags(t *testing.T) {
	if _, err := newSSHClient(false, true, true, nil, 0); err == nil {
		t.Fatal("expected conflicting host-key flags to be rejected")
	}
}

func TestHostKeyPinnedImmediatelyInSameProcess(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	cb, err := hostKeyCallback(path, true)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{}
	first := testPublicKey(t)
	if err := cb("host.example:22", addr, first); err != nil {
		t.Fatalf("enroll first key: %v", err)
	}
	if err := cb("host.example:22", addr, first); err != nil {
		t.Fatalf("repeat pinned key: %v", err)
	}
	if err := cb("host.example:22", addr, testPublicKey(t)); !errors.Is(err, fvcore.ErrHostKeyMismatch) {
		t.Fatalf("changed key was not rejected: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 1 {
		t.Fatalf("expected one pinned key, got %d lines", lines)
	}
}

func TestHostKeyEnrollmentRequiresExpectedFingerprint(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	presented := testPublicKey(t)
	other := testPublicKey(t)
	callback, err := hostKeyCallbackExpected(path, true, ssh.FingerprintSHA256(other))
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host.example:22", &net.TCPAddr{}, presented); !errors.Is(err, fvcore.ErrHostKeyMismatch) {
		t.Fatalf("mismatched expected fingerprint should fail: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatal("mismatched key was recorded")
	}

	callback, err = hostKeyCallbackExpected(path, true, ssh.FingerprintSHA256(presented))
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host.example:22", &net.TCPAddr{}, presented); err != nil {
		t.Fatalf("matching expected fingerprint was rejected: %v", err)
	}
}

func TestConcurrentHostKeyEnrollmentWritesOnce(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	cb, err := hostKeyCallback(path, true)
	if err != nil {
		t.Fatal(err)
	}
	key := testPublicKey(t)
	addr := &net.TCPAddr{}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- cb("host.example:22", addr, key)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent enrollment: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 1 {
		t.Fatalf("expected one pinned key, got %d lines", lines)
	}
}

func TestConcurrentCallbacksCannotEnrollConflictingKeys(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	firstCallback, err := hostKeyCallback(path, true)
	if err != nil {
		t.Fatal(err)
	}
	secondCallback, err := hostKeyCallback(path, true)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	addr := &net.TCPAddr{}
	for _, attempt := range []struct {
		callback ssh.HostKeyCallback
		key      ssh.PublicKey
	}{
		{firstCallback, testPublicKey(t)},
		{secondCallback, testPublicKey(t)},
	} {
		go func() {
			<-start
			errs <- attempt.callback("host.example:22", addr, attempt.key)
		}()
	}
	close(start)

	accepted, rejected := 0, 0
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, fvcore.ErrHostKeyMismatch):
			rejected++
		default:
			t.Fatalf("unexpected enrollment result: %v", err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("accepted=%d rejected=%d, want one of each", accepted, rejected)
	}
}

func privateKnownHostsTestPath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "known_hosts")
}

func TestHostKeyStoreRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	td := t.TempDir()
	target := filepath.Join(td, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(td, "known_hosts")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := hostKeyCallback(path, false); err == nil {
		t.Fatal("expected symlinked known_hosts to be rejected")
	}
}

func TestDeferredHostKeyIsNotPinnedUntilCommitted(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	key := testPublicKey(t)
	var pending pendingHostKey
	callback, err := hostKeyCallbackFunc(path, true, ssh.FingerprintSHA256(key), func(observed pendingHostKey) error {
		pending = observed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host.example:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("verified key was rejected: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("verification recorded the key before it was committed: %q", data)
	}
	if pending.key == nil {
		t.Fatal("verification did not hand back the observed key")
	}

	if err := commitPendingHostKey(path, pending); err != nil {
		t.Fatalf("commit: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("commit did not pin the key")
	}
	pinned, err := hostKeyCallback(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned("host.example:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("committed key is not pinned: %v", err)
	}
	// Committing again must not duplicate the entry.
	if err := commitPendingHostKey(path, pending); err != nil {
		t.Fatalf("repeat commit: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(mustReadFile(t, path))), "\n") + 1; lines != 1 {
		t.Fatalf("expected one pinned key, got %d lines", lines)
	}

	if err := removeKnownHost(path, pending.hostname, pending.key); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := strings.TrimSpace(string(mustReadFile(t, path))); got != "" {
		t.Fatalf("rollback left %q behind", got)
	}
	// Removing an entry that is not there is not an error.
	if err := removeKnownHost(path, pending.hostname, pending.key); err != nil {
		t.Fatalf("repeat remove: %v", err)
	}
}

func TestCommitPendingHostKeyFailsClosedOnAConflictingEntry(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	verified := testPublicKey(t)
	var pending pendingHostKey
	callback, err := hostKeyCallbackFunc(path, true, ssh.FingerprintSHA256(verified), func(observed pendingHostKey) error {
		pending = observed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("host.example:22", &net.TCPAddr{}, verified); err != nil {
		t.Fatal(err)
	}

	// Another writer pins a different key for the same host before the
	// enrollment commits.
	if err := appendKnownHost(path, "host.example:22", testPublicKey(t)); err != nil {
		t.Fatal(err)
	}
	err = commitPendingHostKey(path, pending)
	if !errors.Is(err, fvcore.ErrHostKeyMismatch) {
		t.Fatalf("conflicting commit = %v, want a host-key mismatch", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(mustReadFile(t, path))), "\n") + 1; lines != 1 {
		t.Fatalf("refused commit changed known_hosts: %q", mustReadFile(t, path))
	}
}

func TestRemoveKnownHostLeavesUnrelatedEntriesAlone(t *testing.T) {
	path := privateKnownHostsTestPath(t)
	if err := prepareKnownHosts(path); err != nil {
		t.Fatal(err)
	}
	mine := testPublicKey(t)
	theirs := testPublicKey(t)
	if err := appendKnownHost(path, "other.example:22", theirs); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(path, "host.example:22", mine); err != nil {
		t.Fatal(err)
	}
	if err := removeKnownHost(path, "host.example:22", mine); err != nil {
		t.Fatal(err)
	}
	remaining := strings.TrimSpace(string(mustReadFile(t, path)))
	if strings.Count(remaining, "\n") != 0 {
		t.Fatalf("expected exactly one remaining entry: %q", remaining)
	}
	callback, err := hostKeyCallback(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("other.example:22", &net.TCPAddr{}, theirs); err != nil {
		t.Fatalf("unrelated entry was disturbed: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

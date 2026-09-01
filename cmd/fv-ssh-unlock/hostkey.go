// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/shoon/fv-ssh-unlock/internal/securefs"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

// defaultDialTimeout bounds a single SSH dial when the caller has no
// operation-specific budget of its own. Callers that do (the daemon derives one
// from --probe-timeout/--unlock-timeout) pass it explicitly so a configured
// timeout is not silently capped here.
const defaultDialTimeout = 15 * time.Second

// knownHostsPath is where trusted host keys are recorded.
func knownHostsPath() (string, error) {
	dir, err := appDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "known_hosts"), nil
}

// newSSHClient builds an SSH client with host-key verification. When insecure
// is true, verification is disabled (with a loud warning); otherwise an
// explicitly controlled known_hosts callback is used. A non-positive
// dialTimeout falls back to defaultDialTimeout.
func newSSHClient(verbose, insecure, acceptNew bool, identityFiles []string, dialTimeout time.Duration) (*fvcore.RealSSHClient, error) {
	if insecure && acceptNew {
		return nil, errors.New("--insecure-host-key and --accept-new-host-key cannot be used together")
	}
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	c := &fvcore.RealSSHClient{DialTimeout: dialTimeout, Verbose: verbose}
	signers, err := loadSigners(verbose, identityFiles)
	if err != nil {
		return nil, err
	}
	c.Signers = signers
	if insecure {
		c.InsecureIgnoreHostKey = true
		fmt.Fprintln(os.Stderr, "warning: host-key verification disabled (--insecure-host-key); the FileVault password may be exposed to a man-in-the-middle")
		return c, nil
	}
	path, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	cb, err := hostKeyCallback(path, acceptNew)
	if err != nil {
		return nil, fmt.Errorf("failed to set up host-key verification: %w", err)
	}
	c.HostKeyCallback = cb
	return c, nil
}

// hostKeyCallback returns a host-key verifier backed by a known_hosts file. An
// unknown host fails closed unless acceptNew is explicitly set; changed keys
// are always rejected. The file is re-read under a process-wide and OS-level
// lock on every verification so a key enrolled earlier in the same process is
// immediately pinned and concurrent processes cannot enroll different keys.
//
// The FileVault pre-boot SSH server presents the same host key as the fully
// booted OS, so a key pinned here is valid across the locked -> unlocked
// boundary.
func hostKeyCallback(path string, acceptNew bool) (ssh.HostKeyCallback, error) {
	return hostKeyCallbackExpected(path, acceptNew, "")
}

// hostKeyCallbackExpected is used by interactive candidate enrollment. An
// unknown key is written only when its independently verified fingerprint
// exactly matches expectedFingerprint. Existing changed-key protection always
// takes precedence.
func hostKeyCallbackExpected(path string, acceptNew bool, expectedFingerprint string) (ssh.HostKeyCallback, error) {
	return hostKeyCallbackFunc(path, acceptNew, expectedFingerprint, nil)
}

// pendingHostKey is a host key that satisfied every verification rule but has
// deliberately not been written to known_hosts yet. Candidate enrollment
// carries one so the key is pinned only once the device is actually
// registered; an enrollment that fails afterwards leaves no trust behind.
type pendingHostKey struct {
	hostname string
	remote   net.Addr
	key      ssh.PublicKey
}

// hostKeyCallbackFunc is hostKeyCallbackExpected with a pluggable action for an
// accepted unknown key. When onAccept is nil the key is recorded in known_hosts
// immediately, which is what every non-enrollment caller wants. When onAccept
// is supplied it replaces that write and the caller becomes responsible for
// pinning the key later (see commitPendingHostKey). Changed-key rejection and
// the expectedFingerprint check are identical in both modes.
func hostKeyCallbackFunc(path string, acceptNew bool, expectedFingerprint string, onAccept func(pendingHostKey) error) (ssh.HostKeyCallback, error) {
	return hostKeyCallbackFuncContext(context.Background(), path, acceptNew, expectedFingerprint, onAccept)
}

func hostKeyCallbackFuncContext(ctx context.Context, path string, acceptNew bool, expectedFingerprint string, onAccept func(pendingHostKey) error) (ssh.HostKeyCallback, error) {
	if err := prepareKnownHosts(path); err != nil {
		return nil, err
	}
	if _, err := knownhosts.New(path); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		return withKnownHostsLockContext(ctx, path, func() error {
			return verifyHostKeyLocked(path, acceptNew, expectedFingerprint, onAccept, hostname, remote, key)
		})
	}, nil
}

// verifyHostKeyLocked applies the host-key rules against a freshly re-read
// known_hosts. The caller must already hold the known_hosts lock.
func verifyHostKeyLocked(path string, acceptNew bool, expectedFingerprint string, onAccept func(pendingHostKey) error, hostname string, remote net.Addr, key ssh.PublicKey) error {
	base, err := knownhosts.New(path)
	if err != nil {
		return fmt.Errorf("read known_hosts: %w", err)
	}
	verr := base(hostname, remote, key)
	if verr == nil {
		// An existing known_hosts entry proves that this is a trusted endpoint,
		// but candidate enrollment has a second, independent invariant: the key
		// must also be the one the operator verified from the discovery inbox.
		// Do not bypass that check merely because the endpoint was pinned earlier
		// under another workflow or alias.
		if expectedFingerprint != "" && ssh.FingerprintSHA256(key) != expectedFingerprint {
			return fmt.Errorf("%w: host %q presented %s, not the independently verified %s; refusing enrollment",
				fvcore.ErrHostKeyMismatch, hostname, ssh.FingerprintSHA256(key), expectedFingerprint)
		}
		return nil
	}
	var keyErr *knownhosts.KeyError
	if errors.As(verr, &keyErr) {
		if len(keyErr.Want) == 0 {
			fingerprint := ssh.FingerprintSHA256(key)
			if !acceptNew {
				return fmt.Errorf("%w: unknown host %q presented %s; verify the fingerprint, then enroll it with the password-free status command and --accept-new-host-key",
					fvcore.ErrHostKeyMismatch, hostname, fingerprint)
			}
			if expectedFingerprint != "" && fingerprint != expectedFingerprint {
				return fmt.Errorf("%w: host %q presented %s, not the independently verified %s; refusing enrollment",
					fvcore.ErrHostKeyMismatch, hostname, fingerprint, expectedFingerprint)
			}
			if onAccept != nil {
				return onAccept(pendingHostKey{hostname: hostname, remote: remote, key: key})
			}
			if aerr := appendKnownHost(path, hostname, key); aerr != nil {
				return fmt.Errorf("failed to record host key for %s: %w", hostname, aerr)
			}
			fmt.Fprintf(os.Stderr, "warning: trusted new host key for %q (%s) and recorded it in %s\n", hostname, fingerprint, terminalSafeInline(path))
			return nil
		}
		presented := ssh.FingerprintSHA256(key)
		expected := make([]string, 0, len(keyErr.Want))
		for _, known := range keyErr.Want {
			expected = append(expected, ssh.FingerprintSHA256(known.Key))
		}
		return fmt.Errorf("%w: host key for %s has CHANGED: possible man-in-the-middle (presented %s; expected %s). "+
			"If this is expected (e.g. an OS reinstall), remove the entry from %s and retry",
			fvcore.ErrHostKeyMismatch, hostname, presented, expected, path)
	}
	return verr
}

// withKnownHostsLockContext runs fn while holding the OS-level known_hosts
// lock, so concurrent processes cannot enroll different keys for the same host
// or read a half-written file.
func withKnownHostsLockContext(ctx context.Context, path string, fn func() error) error {
	lock, err := securefs.AcquireLockContext(ctx, path+".lock", "known_hosts")
	if err != nil {
		return err
	}
	defer lock.Release()
	return fn()
}

// commitPendingHostKey pins a key that hostKeyCallbackFunc previously verified
// but deliberately did not record. known_hosts is re-checked under the lock, so
// a key another process enrolled in the meantime is neither duplicated nor
// silently replaced: an entry that now disagrees fails closed.
//
// A zero pendingHostKey means the host was already pinned during verification
// and there is nothing to record. The bool is true only when this call appended
// the line, allowing a later rollback to remove only state owned by its
// enrollment transaction.
func commitPendingHostKey(path string, pending pendingHostKey) (bool, error) {
	return commitPendingHostKeyContext(context.Background(), path, pending)
}

func commitPendingHostKeyContext(ctx context.Context, path string, pending pendingHostKey) (bool, error) {
	return commitPendingHostKeyWithAppender(ctx, path, pending, appendKnownHost)
}

func commitPendingHostKeyWithAppender(ctx context.Context, path string, pending pendingHostKey, appendEntry func(string, string, ssh.PublicKey) error) (bool, error) {
	if pending.key == nil {
		return false, nil
	}
	inserted := false
	err := withKnownHostsLockContext(ctx, path, func() error {
		base, err := knownhosts.New(path)
		if err != nil {
			return fmt.Errorf("read known_hosts: %w", err)
		}
		verr := base(pending.hostname, pending.remote, pending.key)
		if verr == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(verr, &keyErr) && len(keyErr.Want) == 0 {
			if aerr := appendEntry(path, pending.hostname, pending.key); aerr != nil {
				present, inspectErr := knownHostLinePresent(path, pending.hostname, pending.key)
				inserted = present
				if inspectErr != nil {
					return errors.Join(fmt.Errorf("failed to record host key for %s: %w", pending.hostname, aerr), fmt.Errorf("reconcile known_hosts write: %w", inspectErr))
				}
				return fmt.Errorf("failed to record host key for %s: %w", pending.hostname, aerr)
			}
			inserted = true
			return nil
		}
		return fmt.Errorf("%w: host key for %s changed while it was being enrolled; nothing was pinned: %w",
			fvcore.ErrHostKeyMismatch, pending.hostname, verr)
	})
	return inserted, err
}

// removeKnownHost unpins a key recorded by commitPendingHostKey. It removes
// only lines byte-identical to the entry that was written, so an unrelated or
// operator-authored entry for the same host is never disturbed. It is used to
// roll back an enrollment that failed after the key was pinned.
func removeKnownHost(path, hostname string, key ssh.PublicKey) error {
	return removeKnownHostContext(context.Background(), path, hostname, key)
}

func removeKnownHostContext(ctx context.Context, path, hostname string, key ssh.PublicKey) error {
	if key == nil {
		return nil
	}
	target := []byte(knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
	return withKnownHostsLockContext(ctx, path, func() error {
		content, err := securefs.ReadPrivate(path, "known_hosts", maxKnownHostsSize)
		if err != nil {
			return err
		}
		kept := make([][]byte, 0, bytes.Count(content, []byte{'\n'})+1)
		removed := false
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			if !removed && bytes.Equal(bytes.TrimRight(line, "\r"), target) {
				removed = true
				continue
			}
			kept = append(kept, line)
		}
		if !removed {
			return nil
		}
		// Replace the file atomically while the sidecar lock is held. Truncating
		// and rewriting the live file would risk losing unrelated trust entries
		// if the host ran out of space or an I/O error interrupted rollback.
		return securefs.WritePrivate(path, "known_hosts", ".known-hosts-*.tmp", bytes.Join(kept, []byte{'\n'}))
	})
}

func prepareKnownHosts(path string) error {
	dir := filepath.Dir(path)
	if err := securefs.EnsurePrivateDirectory(dir, "known_hosts"); err != nil {
		return err
	}
	if err := preparePrivateRegularFile(path, "known_hosts"); err != nil {
		return err
	}
	return preparePrivateRegularFile(path+".lock", "known_hosts lock")
}

func preparePrivateRegularFile(path, description string) error {
	f, err := securefs.OpenPrivate(path, description, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return fmt.Errorf("%s: %w", description, err)
	}
	return f.Close()
}

// appendKnownHost records a host key in OpenSSH known_hosts format.
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	content, err := securefs.ReadPrivate(path, "known_hosts", maxKnownHostsSize)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	content = append(content, line...)
	content = append(content, '\n')
	if len(content) > maxKnownHostsSize {
		return fmt.Errorf("known_hosts exceeds %d bytes", maxKnownHostsSize)
	}
	return securefs.WritePrivate(path, "known_hosts", ".known-hosts-*.tmp", content)
}

func knownHostLinePresent(path, hostname string, key ssh.PublicKey) (bool, error) {
	content, err := securefs.ReadPrivate(path, "known_hosts", maxKnownHostsSize)
	if err != nil {
		return false, err
	}
	target := []byte(knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		if bytes.Equal(bytes.TrimRight(line, "\r"), target) {
			return true, nil
		}
	}
	return false, nil
}

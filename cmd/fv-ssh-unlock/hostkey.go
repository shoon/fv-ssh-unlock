// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

// knownHostsPath is where trusted host keys are recorded.
func knownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	if home == "" {
		return "", errors.New("find home directory: empty path")
	}
	return filepath.Join(home, ".fv-ssh-unlock", "known_hosts"), nil
}

// newSSHClient builds an SSH client with host-key verification. When insecure
// is true, verification is disabled (with a loud warning); otherwise an
// explicitly controlled known_hosts callback is used.
func newSSHClient(verbose, insecure, acceptNew bool, identityFiles []string) (*fvcore.RealSSHClient, error) {
	if insecure && acceptNew {
		return nil, errors.New("--insecure-host-key and --accept-new-host-key cannot be used together")
	}
	c := &fvcore.RealSSHClient{DialTimeout: 15 * time.Second, Verbose: verbose}
	c.Signers = loadSigners(verbose, identityFiles)
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

		lock, err := openPrivateRegularFile(path+".lock", os.O_CREATE|os.O_RDWR)
		if err != nil {
			return fmt.Errorf("open known_hosts lock: %w", err)
		}
		defer lock.Close()
		if err := lockKnownHostsFile(lock); err != nil {
			return fmt.Errorf("lock known_hosts: %w", err)
		}
		defer unlockKnownHostsFile(lock)

		base, err := knownhosts.New(path)
		if err != nil {
			return fmt.Errorf("read known_hosts: %w", err)
		}
		verr := base(hostname, remote, key)
		if verr == nil {
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
	}, nil
}

func prepareKnownHosts(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("known_hosts directory is not a secure directory: %s", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := preparePrivateRegularFile(path, "known_hosts"); err != nil {
		return err
	}
	return preparePrivateRegularFile(path+".lock", "known_hosts lock")
}

func preparePrivateRegularFile(path, description string) error {
	f, err := openPrivateRegularFile(path, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return fmt.Errorf("%s: %w", description, err)
	}
	return f.Close()
}

// openPrivateRegularFile validates the opened descriptor against the path, not
// just the path before opening it. This prevents a local symlink swap from
// redirecting known_hosts reads, writes, chmods, or locks to another file.
func openPrivateRegularFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, err
	}
	openedInfo, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return fail(fmt.Errorf("not a stable regular file: %s", path))
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	return f, nil
}

// appendKnownHost records a host key in OpenSSH known_hosts format.
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	f, err := openPrivateRegularFile(path, os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, err = f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

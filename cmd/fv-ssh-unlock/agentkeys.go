// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/shoon/fv-ssh-unlock/internal/securefs"
)

const maxIdentityFileSize = 1 << 20

var defaultIdentityNames = []string{
	"id_ed25519",
	"id_ecdsa",
	"id_ecdsa_sk",
	"id_ed25519_sk",
	"id_rsa",
}

// loadSigners collects SSH keys for public-key authentication from the running
// ssh-agent and identity files. When no --identity is supplied, it follows the
// normal SSH convention of trying standard identity filenames in ~/.ssh.
//
// A successful public-key handshake proves a device has booted, because the
// FileVault pre-boot server cannot honor public-key auth. No secret is sent.
func loadSigners(verbose bool, identityFiles []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	explicitIdentities := len(identityFiles) > 0
	if !explicitIdentities {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			identityFiles = discoverDefaultIdentityFiles(home)
		}
	}
	for _, path := range identityFiles {
		path = filepath.Clean(path)
		data, err := readIdentityFile(path)
		if err != nil {
			if explicitIdentities {
				return nil, fmt.Errorf("load identity %q: %w", path, err)
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] skipping %s: %s\n", terminalSafeInline(path), terminalSafeInline(err.Error()))
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			if explicitIdentities {
				var passphraseMissing *ssh.PassphraseMissingError
				if errors.As(err, &passphraseMissing) {
					return nil, fmt.Errorf("identity %q is encrypted; add it to ssh-agent, then retry without --identity", path)
				}
				return nil, fmt.Errorf("parse identity %q: %w", path, err)
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] skipping %s: %s\n", terminalSafeInline(path), terminalSafeInline(err.Error()))
			}
			continue
		}
		signers = append(signers, signer)
	}

	// Explicit/default files go first so --identity remains deterministic and
	// standard keys are not pushed past an SSH server's authentication-attempt
	// limit by a large agent. Duplicates are removed below.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		// #nosec G704 -- SSH_AUTH_SOCK is the operator's local ssh-agent unix socket; dialing it is the standard agent protocol, not a network fetch of untrusted input.
		if conn, err := net.DialTimeout("unix", sock, 2*time.Second); err == nil {
			if s, err := agent.NewClient(conn).Signers(); err == nil {
				signers = append(signers, s...)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] ssh-agent: %s\n", terminalSafeInline(err.Error()))
			}
			// The agent connection stays open for the life of
			// the process; the signers reference it.
		} else if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] ssh-agent unreachable: %s\n", terminalSafeInline(err.Error()))
		}
	}
	unique := signers[:0]
	seen := make(map[string]struct{}, len(signers))
	for _, signer := range signers {
		key := string(signer.PublicKey().Marshal())
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, signer)
	}
	signers = unique

	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] loaded %d public key(s) for booted-state probing\n", len(signers))
	}
	return signers, nil
}

func discoverDefaultIdentityFiles(home string) []string {
	directory := filepath.Join(home, ".ssh")
	paths := make([]string, 0, len(defaultIdentityNames))
	for _, name := range defaultIdentityNames {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			paths = append(paths, path)
		}
	}
	return paths
}

func readIdentityFile(path string) ([]byte, error) {
	file, err := securefs.OpenStable(path, "identity file")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxIdentityFileSize {
		return nil, fmt.Errorf("identity exceeds %d bytes", maxIdentityFileSize)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity permissions %04o are too open; use 0600 or stricter", info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIdentityFileSize {
		return nil, fmt.Errorf("identity exceeds %d bytes", maxIdentityFileSize)
	}
	return data, nil
}

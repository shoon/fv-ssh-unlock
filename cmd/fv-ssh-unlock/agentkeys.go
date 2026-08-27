// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// loadSigners collects SSH keys for public-key authentication from the running
// ssh-agent and from identity files the user explicitly selected. Private key
// files are never searched or loaded implicitly.
//
// A successful public-key handshake proves a device has booted, because the
// FileVault pre-boot server cannot honor public-key auth. No secret is sent.
func loadSigners(verbose bool, identityFiles []string) []ssh.Signer {
	var signers []ssh.Signer

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
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

	for _, path := range identityFiles {
		path = filepath.Clean(path)
		data, err := os.ReadFile(path)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] skipping %s: %s\n", terminalSafeInline(path), terminalSafeInline(err.Error()))
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] skipping %s: %s\n", terminalSafeInline(path), terminalSafeInline(err.Error()))
			}
			continue
		}
		signers = append(signers, signer)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] loaded %d public key(s) for booted-state probing\n", len(signers))
	}
	return signers
}

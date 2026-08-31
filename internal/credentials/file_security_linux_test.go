//go:build linux

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileProviderAcceptsMemoryBackedSystemdCredentialDirectory(t *testing.T) {
	const memoryRoot = "/dev/shm"
	if secure, _ := platformSecureCredentialDirectory(memoryRoot); !secure {
		t.Skip("no writable memory-backed test filesystem is available")
	}
	directory, err := os.MkdirTemp(memoryRoot, "fv-ssh-unlock-credentials-test-")
	if err != nil {
		t.Skipf("cannot create memory-backed test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	path := filepath.Join(directory, "office-mac")
	if err := os.WriteFile(path, []byte("supersecret"), 0o400); err != nil {
		t.Fatal(err)
	}

	provider, err := NewRegistry(Options{}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	assessment := provider.Assess("systemd:office-mac")
	if !assessment.Available || !assessment.Secure || !strings.Contains(assessment.Details, "systemd") {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
	password, err := provider.Get("systemd:office-mac")
	if err != nil {
		t.Fatal(err)
	}
	if password != "supersecret" {
		t.Fatalf("password = %q, want supersecret", password)
	}
}

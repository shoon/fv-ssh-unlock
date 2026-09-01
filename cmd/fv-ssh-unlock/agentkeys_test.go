// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiscoverDefaultIdentityFilesUsesStableStandardNames(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519", "id_rsa", "not_an_identity"} {
		if err := os.WriteFile(filepath.Join(sshDirectory, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := discoverDefaultIdentityFiles(home)
	want := []string{
		filepath.Join(sshDirectory, "id_ed25519"),
		filepath.Join(sshDirectory, "id_rsa"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identity %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadSignersRejectsBadExplicitIdentity(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := filepath.Join(t.TempDir(), "bad-key")
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigners(false, []string{path}); err == nil {
		t.Fatal("expected an invalid explicit identity to fail")
	}
}

func TestReadIdentityFileRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows protects private keys with ACLs rather than Unix mode bits")
	}
	path := filepath.Join(t.TempDir(), "open-key")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readIdentityFile(path)
	if err == nil || !strings.Contains(err.Error(), "insecure identity file") {
		t.Fatalf("permission error = %v", err)
	}
}

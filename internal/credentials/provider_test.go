// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRegistryReportsStableProviderSet(t *testing.T) {
	reports := NewRegistry(Options{}).Reports()
	want := []string{ProviderKeyring, ProviderFile, ProviderRuntime, ProviderTPM2}
	if len(reports) != len(want) {
		t.Fatalf("got %d reports, want %d", len(reports), len(want))
	}
	for i, name := range want {
		if reports[i].Name != name {
			t.Fatalf("report %d = %q, want %q", i, reports[i].Name, name)
		}
	}
	if reports[len(reports)-1].Built {
		t.Fatal("TPM2 must not be advertised as built before a sealing provider exists")
	}
}

func TestFileProviderRefusesPlaintextDiskWithoutOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("supersecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	provider, err := NewRegistry(Options{}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get(path); !errors.Is(err, ErrUnsafeCredentialStorage) {
		t.Fatalf("Get() error = %v, want ErrUnsafeCredentialStorage", err)
	}

	provider, err = NewRegistry(Options{AllowUnsafeCredentialStorage: true}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	password, err := provider.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	if password != "supersecret" {
		t.Fatalf("password = %q, want supersecret", password)
	}
}

func TestFileProviderDoesNotTrustCredentialDirectoryEnvironmentAlone(t *testing.T) {
	directory := t.TempDir()
	if secure, _ := platformSecureCredentialDirectory(directory); secure {
		t.Skip("the test temporary directory is memory-backed")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	path := filepath.Join(directory, "office-mac")
	if err := os.WriteFile(path, []byte("supersecret"), 0o400); err != nil {
		t.Fatal(err)
	}

	provider, err := NewRegistry(Options{}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	assessment := provider.Assess(path)
	if !assessment.Available || assessment.Secure {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
	if _, err := provider.Get(path); !errors.Is(err, ErrUnsafeCredentialStorage) {
		t.Fatalf("Get() error = %v, want ErrUnsafeCredentialStorage", err)
	}
}

func TestPathWithinResolvesSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	directory := t.TempDir()
	outside := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	path := filepath.Join(outside, "password")
	if err := os.WriteFile(path, []byte("supersecret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	if pathWithin(directory, filepath.Join(directory, "escape", "password")) {
		t.Fatal("symlink escape was incorrectly classified inside the base directory")
	}
}

func TestFileProviderRejectsSymlinkAndOversizedFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(directory, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if assessment := assessCredentialFile(link); assessment.Available {
			t.Fatalf("symlink unexpectedly available: %+v", assessment)
		}
	}

	large := filepath.Join(directory, "large")
	if err := os.WriteFile(large, make([]byte, maxCredentialFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if assessment := assessCredentialFile(large); assessment.Available {
		t.Fatalf("oversized credential unexpectedly available: %+v", assessment)
	}
}

func TestFileProviderRequiresAbsolutePath(t *testing.T) {
	provider, err := NewRegistry(Options{AllowUnsafeCredentialStorage: true}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get("relative-secret"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestFileProviderResolvesSystemdCredentialReference(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	path := filepath.Join(directory, "office-mac")
	if err := os.WriteFile(path, []byte("supersecret"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewRegistry(Options{AllowUnsafeCredentialStorage: true}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	password, err := provider.Get("systemd:office-mac")
	if err != nil {
		t.Fatal(err)
	}
	if password != "supersecret" {
		t.Fatalf("password = %q, want supersecret", password)
	}
	for _, reference := range []string{"systemd:", "systemd:../secret", "systemd:name/secret", "relative-secret"} {
		if _, err := NormalizeFileReference(reference); err == nil {
			t.Errorf("NormalizeFileReference(%q) unexpectedly succeeded", reference)
		}
	}
}

func TestFileProviderHandlesOneLineEndingAndRejectsEmpty(t *testing.T) {
	provider, err := NewRegistry(Options{AllowUnsafeCredentialStorage: true}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"no-ending": "secret",
		"lf":        "secret\n",
		"crlf":      "secret\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "password")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			password, err := provider.Get(path)
			if err != nil {
				t.Fatal(err)
			}
			if password != "secret" {
				t.Fatalf("password = %q, want secret", password)
			}
		})
	}
	empty := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty credential error, got %v", err)
	}
}

func TestExternalProvidersAreReadOnly(t *testing.T) {
	registry := NewRegistry(Options{})
	for _, name := range []string{ProviderRuntime, ProviderFile} {
		provider, err := registry.Provider(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := provider.Store("reference", "secret"); !errors.Is(err, ErrProviderReadOnly) {
			t.Fatalf("%s Store() error = %v, want ErrProviderReadOnly", name, err)
		}
		if err := provider.Delete("reference"); !errors.Is(err, ErrProviderReadOnly) {
			t.Fatalf("%s Delete() error = %v, want ErrProviderReadOnly", name, err)
		}
	}
}

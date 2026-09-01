// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileProviderReportsUnavailableReferences(t *testing.T) {
	provider, err := NewRegistry(Options{AllowUnsafeCredentialStorage: true}).Provider(ProviderFile)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := provider.Get(missing); err == nil {
		t.Fatal("missing credential file was read")
	}
	if assessment := provider.Assess(missing); assessment.Available || assessment.Details == "" {
		t.Fatalf("missing file assessment = %+v", assessment)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if assessment := provider.Assess("systemd:missing"); assessment.Available || assessment.Details == "" {
		t.Fatalf("unresolved systemd assessment = %+v", assessment)
	}
}

func TestFileProviderReportWithOrdinaryCredentialDirectory(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(directory, "nested"), filepath.Join(directory, "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "credential"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := newFileProvider(false).Report()
	if !report.Built || !report.Available || !report.Persistent || report.Details == "" {
		t.Fatalf("incomplete file provider report: %+v", report)
	}
	if report.SecureStorage != (report.Security == SecuritySecure) {
		t.Fatalf("inconsistent file provider security report: %+v", report)
	}
}

func TestPathWithinRejectsExistingSibling(t *testing.T) {
	base := t.TempDir()
	sibling := t.TempDir()
	path := filepath.Join(sibling, "credential")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pathWithin(base, path) {
		t.Fatal("existing sibling was classified inside credential directory")
	}
}

func TestReadPasswordPropagatesEmptyPipeEOF(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = previous
		_ = reader.Close()
	})
	if password, err := ReadPassword(); !errors.Is(err, io.EOF) || password != "" {
		t.Fatalf("empty pipe result = %q, %v", password, err)
	}
}

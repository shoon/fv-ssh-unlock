//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenStableCredentialFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		file, err := openStableCredentialFile(path)
		if file != nil {
			_ = file.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO was accepted as a credential file")
		}
	case <-time.After(time.Second):
		t.Fatal("opening a credential FIFO blocked")
	}
}

func TestOpenStableCredentialFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "credential")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openStableCredentialFile(link); err == nil {
		_ = file.Close()
		t.Fatal("symlink was accepted as a credential file")
	}
}

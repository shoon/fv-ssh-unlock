//go:build unix

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinnedTargetNamesRejectsInsecureKnownHosts(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := dataDirOverride
	dataDirOverride = directory
	t.Cleanup(func() { dataDirOverride = previous })
	path, err := knownHostsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTargetNames(); err == nil || !strings.Contains(err.Error(), "insecure known_hosts") {
		t.Fatalf("loadPinnedTargetNames accepted insecure permissions: %v", err)
	}
}

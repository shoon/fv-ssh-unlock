// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

func TestSaveRejectsOversizedEncodedConfiguration(t *testing.T) {
	devices := make([]Device, 260)
	for index := range devices {
		name := fmt.Sprintf("mac-%03d", index)
		devices[index] = Device{
			Name:           name,
			Host:           fmt.Sprintf("mac-%03d.example", index),
			User:           "user",
			Port:           22,
			Cred:           credentials.ID(name),
			SuccessMessage: strings.Repeat("x", 4096),
		}
	}
	store := &Store{Path: filepath.Join(t.TempDir(), "devices.json")}
	if err := store.save(devices); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized configuration was accepted: %v", err)
	}
	if _, err := os.Stat(store.Path); !os.IsNotExist(err) {
		t.Fatalf("oversized configuration created a store: %v", err)
	}
}

func TestStoreMutationsFailWhenParentIsNotDirectory(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Store{Path: filepath.Join(parent, "devices.json")}
	device := Device{Name: "mac", Host: "mac.example", User: "user", Port: 22, Cred: credentials.ID("mac")}
	if err := store.Save([]Device{device}); err == nil {
		t.Fatal("Save succeeded beneath a regular file")
	}
	if err := store.Add(device); err == nil {
		t.Fatal("Add succeeded beneath a regular file")
	}
}

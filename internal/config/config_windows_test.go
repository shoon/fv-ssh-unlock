//go:build windows

// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLoadRejectsInsecureWindowsDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "devices.json")
	store := &Store{Path: path}
	device := Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, Cred: "fvu-mac"}
	if err := store.Save([]Device{device}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Replacing the file through the normal atomic writer restores its
		// protected DACL so TempDir cleanup retains delete access.
		_ = store.Save([]Device{device})
	})
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "insecure configuration") {
		t.Fatalf("Load accepted a configuration granting Everyone read access: %v", err)
	}
}

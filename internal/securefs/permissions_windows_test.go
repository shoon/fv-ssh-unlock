//go:build windows

// SPDX-License-Identifier: Apache-2.0

package securefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDirectoryCreatesProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDirectory(path, "test"); err != nil {
		t.Fatal(err)
	}
	file, err := openWindowsSecurityHandle(path, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := verifyWindowsACL(file, true); err != nil {
		t.Fatalf("created directory has an insecure DACL: %v", err)
	}
}

func TestWindowsPrivateDirectoryRejectsUntrustedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestDACL(t, path, "D:P(A;OICI;FA;;;WD)")
	if err := EnsurePrivateDirectory(path, "test"); err == nil {
		t.Fatal("directory granting Everyone access was accepted")
	}
	file, err := openWindowsSecurityHandle(path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := setPrivateWindowsACL(file, true); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
}

func TestWindowsPrivateFileCreatesAndValidatesProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := WritePrivate(path, "test store", ".state-*.tmp", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	file, err := OpenStable(path, "test store")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivateFile(file); err != nil {
		_ = file.Close()
		t.Fatalf("created file has an insecure DACL: %v", err)
	}
	_ = file.Close()

	setWindowsTestDACL(t, path, "D:P(A;;GR;;;WD)")
	file, err = OpenStable(path, "test store")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := VerifyPrivateFile(file); err == nil {
		t.Fatal("file granting Everyone read access was accepted")
	}
	if err := securePrivateFile(file); err != nil {
		t.Fatalf("restore private file DACL: %v", err)
	}
}

func setWindowsTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
}

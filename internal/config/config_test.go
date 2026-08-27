// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigAddRemoveList(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "devices.json")
	s := &Store{Path: path}

	d1 := Device{Name: "one", Host: "1.2.3.4", User: "u", Cred: "fvu-one"}
	if err := s.Add(d1); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	devs, err := s.Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(devs) != 1 || devs[0].Name != "one" {
		t.Fatalf("unexpected devices: %v", devs)
	}

	if err := s.Remove("one"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	devs, err = s.Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("expected empty after remove, got %v", devs)
	}

	// ensure file permissions are sensible
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// Windows security is represented by the inherited NTFS ACL rather than
	// POSIX mode bits, which os.Stat reports as 0666.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file perms too open: %v", info.Mode())
	}
}

func TestValidateDeviceRejectsAmbiguousOrUnsafeValues(t *testing.T) {
	base := Device{Name: "one", Host: "example.test", User: "user", Port: 22, Cred: "fvu-one"}
	cases := []Device{
		{Name: "bad\x1bname", Host: base.Host, User: base.User, Port: 22},
		{Name: base.Name, Host: "example.test:2222", User: base.User, Port: 22},
		{Name: base.Name, Host: base.Host, User: " bad", Port: 22},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 65536},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, Cred: "fvu-another-device"},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, MACAddress: "not-a-mac"},
	}
	for _, d := range cases {
		if err := ValidateDevice(d); err == nil {
			t.Errorf("expected validation error for %+v", d)
		}
	}
	if err := ValidateDevice(base); err != nil {
		t.Fatalf("valid device rejected: %v", err)
	}
	ipv6 := base
	ipv6.Host = "2001:db8::1"
	if err := ValidateDevice(ipv6); err != nil {
		t.Fatalf("IPv6 literal rejected: %v", err)
	}
	ipv6.Host = "fe80::1%en0"
	if err := ValidateDevice(ipv6); err != nil {
		t.Fatalf("zoned IPv6 literal rejected: %v", err)
	}
}

func TestLoadRejectsOversizedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxConfigSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := (&Store{Path: path}).Load(); err == nil {
		t.Fatalf("expected oversized configuration to be rejected")
	}
}

func TestAddDuplicate(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "devices.json")
	s := &Store{Path: path}

	d1 := Device{Name: "dup", Host: "1.2.3.4", User: "u", Cred: "fvu-dup"}
	if err := s.Add(d1); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	// second add should error
	if err := s.Add(d1); err == nil {
		t.Fatalf("expected error when adding duplicate, got nil")
	}
}

func TestRemoveNotFound(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "devices.json")
	s := &Store{Path: path}

	d1 := Device{Name: "one", Host: "1.2.3.4", User: "u", Cred: "fvu-one"}
	if err := s.Add(d1); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// attempt to remove missing device
	if err := s.Remove("nope"); err == nil {
		t.Fatalf("expected error when removing non-existent device, got nil")
	}
}

func TestConfigWithPort(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "devices.json")
	s := &Store{Path: path}

	d1 := Device{Name: "one", Host: "1.2.3.4", User: "u", Port: 2222, Cred: "fvu-one"}
	if err := s.Add(d1); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	devs, err := s.Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].Port != 2222 {
		t.Fatalf("expected port 2222, got %d", devs[0].Port)
	}
}

func TestStoreRejectsCredentialEnvironmentCollision(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "devices.json")}
	devs := []Device{
		{Name: "office-mac", Host: "mac-one.example", User: "user", Port: 22, Cred: "fvu-office-mac"},
		{Name: "office_mac", Host: "mac-two.example", User: "user", Port: 22, Cred: "fvu-office_mac"},
	}
	if err := s.Save(devs); err == nil {
		t.Fatal("expected colliding credential environment variables to be rejected")
	}
}

func TestLoadRejectsDuplicateDeviceNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	data := []byte(`[
  {"name":"same","host":"one.example","user":"user","cred":"fvu-one"},
  {"name":"same","host":"two.example","user":"user","cred":"fvu-two"}
]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Path: path}).Load(); err == nil {
		t.Fatal("expected duplicate device names to be rejected")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	data := []byte(`[{"name":"one","host":"one.example","user":"user","cred":"fvu-one","prot":2222}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Path: path}).Load(); err == nil {
		t.Fatal("expected unknown configuration field to be rejected")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	td := t.TempDir()
	target := filepath.Join(td, "target.json")
	if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(td, "devices.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Path: link}).Load(); err == nil {
		t.Fatal("expected symlinked configuration to be rejected")
	}
}

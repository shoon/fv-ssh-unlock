// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

func TestConfigAddRemoveList(t *testing.T) {
	td := privateConfigTestDir(t)
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
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, Cred: base.Cred, CredentialSource: "file"},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, Cred: base.Cred, CredentialSource: "file", CredentialRef: "relative/password"},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, Cred: base.Cred, CredentialSource: "file", CredentialRef: "systemd:../password"},
		{Name: base.Name, Host: base.Host, User: base.User, Port: 22, Cred: base.Cred, CredentialSource: "runtime", CredentialRef: "/run/secrets/password"},
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
	fileCredential := base
	fileCredential.CredentialSource = "file"
	fileCredential.CredentialRef = filepath.Join(t.TempDir(), "one")
	if err := ValidateDevice(fileCredential); err != nil {
		t.Fatalf("valid file credential rejected: %v", err)
	}
	fileCredential.CredentialRef = "systemd:one"
	if err := ValidateDevice(fileCredential); err != nil {
		t.Fatalf("valid systemd credential reference rejected: %v", err)
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

func TestValidateDeviceRejectsRuntimeCredentialForAutomaticUnlock(t *testing.T) {
	device := Device{
		Name:             "mac",
		Host:             "192.0.2.10",
		User:             "unlockuser",
		Port:             22,
		CredentialSource: credentials.ProviderRuntime,
		AutoUnlock:       true,
	}
	if err := ValidateDevice(device); err == nil || !strings.Contains(err.Error(), "persistent secure credential") {
		t.Fatalf("ValidateDevice() error = %v, want persistent-provider rejection", err)
	}

	device.CredentialSource = ""
	if err := ValidateDevice(device); err == nil || !strings.Contains(err.Error(), "persistent secure credential") {
		t.Fatalf("legacy runtime ValidateDevice() error = %v, want persistent-provider rejection", err)
	}

	device.Cred = credentials.ID(device.Name)
	if err := ValidateDevice(device); err != nil {
		t.Fatalf("legacy keyring-backed automatic unlock rejected: %v", err)
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
	td := privateConfigTestDir(t)
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

func TestConcurrentAddsDoNotLoseDevices(t *testing.T) {
	store := &Store{Path: filepath.Join(privateConfigTestDir(t), "devices.json")}
	const count = 16
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for index := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("mac-%02d", index)
			errs <- store.Add(Device{Name: name, Host: fmt.Sprintf("192.0.2.%d", index+1), User: "user", Port: 22, Cred: credentials.ID(name)})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	devices, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != count {
		t.Fatalf("concurrent adds retained %d devices, want %d", len(devices), count)
	}
}

func TestUpdateExistingDevice(t *testing.T) {
	s := &Store{Path: filepath.Join(privateConfigTestDir(t), "devices.json")}
	device := Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, Cred: "fvu-mac"}
	if err := s.Add(device); err != nil {
		t.Fatal(err)
	}
	device.AutoUnlock = true
	if err := s.Update(device); err != nil {
		t.Fatal(err)
	}
	devices, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || !devices[0].AutoUnlock {
		t.Fatalf("unexpected devices: %+v", devices)
	}
	device.Name = "missing"
	device.Cred = "fvu-missing"
	if err := s.Update(device); err == nil {
		t.Fatal("expected missing device update to fail")
	}
}

func TestRemoveNotFound(t *testing.T) {
	td := privateConfigTestDir(t)
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
	td := privateConfigTestDir(t)
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

func TestFileCredentialReferenceRoundTrip(t *testing.T) {
	path := filepath.Join(privateConfigTestDir(t), "devices.json")
	credentialPath := filepath.Join(t.TempDir(), "office-mac")
	s := &Store{Path: path}
	want := Device{
		Name:             "office-mac",
		Host:             "192.0.2.10",
		User:             "unlockuser",
		Port:             22,
		Cred:             "fvu-office-mac",
		CredentialSource: "file",
		CredentialRef:    credentialPath,
	}
	if err := s.Add(want); err != nil {
		t.Fatal(err)
	}
	devices, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0] != want {
		t.Fatalf("loaded devices = %+v, want %+v", devices, want)
	}
}

func privateConfigTestDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
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

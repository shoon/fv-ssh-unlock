// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

const maxConfigSize = 1 << 20

// Device represents a configured target device.
type Device struct {
	Name             string `json:"name"`
	Host             string `json:"host"`
	User             string `json:"user"`
	Port             int    `json:"port,omitempty"`
	Cred             string `json:"cred"`
	CredentialSource string `json:"credential_source,omitempty"`
	SuccessMessage   string `json:"success_message,omitempty"`
	MACAddress       string `json:"mac_address,omitempty"`
}

// Store manages a JSON file of devices.
type Store struct {
	Path string
}

// Load returns the list of devices from the store file.
func (s *Store) Load() ([]Device, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("configuration is not a regular file: %s", s.Path)
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("configuration exceeds %d bytes", maxConfigSize)
	}
	fh, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	f, err := io.ReadAll(io.LimitReader(fh, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(f) > maxConfigSize {
		return nil, fmt.Errorf("configuration exceeds %d bytes", maxConfigSize)
	}
	var devs []Device
	decoder := json.NewDecoder(bytes.NewReader(f))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&devs); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("configuration contains trailing data")
	}
	if err := validateDevices(devs); err != nil {
		return nil, err
	}
	return devs, nil
}

// Save writes the devices to the store file.
func (s *Store) Save(devs []Device) error {
	if err := validateDevices(devs); err != nil {
		return err
	}
	b, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxConfigSize {
		return fmt.Errorf("configuration exceeds %d bytes", maxConfigSize)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("configuration directory is not a secure directory: %s", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("configuration is not a regular file: %s", s.Path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".devices-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, s.Path); err != nil {
		return err
	}
	return os.Chmod(s.Path, 0o600)
}

// Add adds a device to the store.
func (s *Store) Add(d Device) error {
	devs, err := s.Load()
	if err != nil {
		return err
	}
	// prevent duplicate device names
	for _, ex := range devs {
		if ex.Name == d.Name {
			return fmt.Errorf("device already exists: %s", d.Name)
		}
	}
	devs = append(devs, d)
	return s.Save(devs)
}

// Remove deletes a device by name.
func (s *Store) Remove(name string) error {
	devs, err := s.Load()
	if err != nil {
		return err
	}
	out := make([]Device, 0, len(devs))
	found := false
	for _, d := range devs {
		if d.Name == name {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return fmt.Errorf("device not found: %s", name)
	}
	return s.Save(out)
}

// ValidateDevice rejects values that could redirect a credential to an
// ambiguous endpoint or inject control sequences into terminal output.
func ValidateDevice(d Device) error {
	if err := validatePlain("name", d.Name, 128); err != nil {
		return err
	}
	if err := validatePlain("host", d.Host, 253); err != nil {
		return err
	}
	if err := validatePlain("user", d.User, 256); err != nil {
		return err
	}
	if strings.Contains(d.Host, ":") {
		if _, err := netip.ParseAddr(d.Host); err != nil {
			return fmt.Errorf("host must not include a port; use the port field")
		}
	}
	if d.Port < 0 || d.Port > 65535 {
		return fmt.Errorf("port must be zero (legacy default) or between 1 and 65535")
	}
	if d.CredentialSource != "" && d.CredentialSource != "keyring" && d.CredentialSource != "runtime" {
		return fmt.Errorf("invalid credential source %q", d.CredentialSource)
	}
	if d.Cred != "" {
		if err := validatePlain("credential identifier", d.Cred, 256); err != nil {
			return err
		}
		if d.Cred != credentials.ID(d.Name) {
			return fmt.Errorf("credential identifier must match the device name")
		}
	}
	if len(d.SuccessMessage) > 4096 || strings.ContainsRune(d.SuccessMessage, '\x00') {
		return fmt.Errorf("success message is invalid or too long")
	}
	if d.MACAddress != "" {
		if err := validatePlain("MAC address", d.MACAddress, 64); err != nil {
			return err
		}
		if _, err := net.ParseMAC(d.MACAddress); err != nil {
			return fmt.Errorf("invalid MAC address")
		}
	}
	return nil
}

// validateDevices enforces invariants that involve more than one entry. In
// particular, two otherwise different names can normalize to the same
// environment variable (for example, "office-mac" and "office_mac"). Such a
// collision could cause one device's password to be sent to another device.
func validateDevices(devs []Device) error {
	names := make(map[string]int, len(devs))
	envNames := make(map[string]int, len(devs))
	for i, d := range devs {
		if err := ValidateDevice(d); err != nil {
			return fmt.Errorf("invalid device at index %d: %w", i, err)
		}
		if prior, exists := names[d.Name]; exists {
			return fmt.Errorf("duplicate device name %q at indexes %d and %d", d.Name, prior, i)
		}
		names[d.Name] = i

		credentialID := d.Cred
		if credentialID == "" {
			credentialID = credentials.ID(d.Name)
		}
		envName := credentials.EnvName(credentialID)
		if prior, exists := envNames[envName]; exists {
			return fmt.Errorf("devices %q and %q share credential environment variable %s", devs[prior].Name, d.Name, envName)
		}
		envNames[envName] = i
	}
	return nil
}

func validatePlain(field, value string, maxLen int) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be non-empty and have no surrounding whitespace", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds %d bytes", field, maxLen)
	}
	for _, r := range value {
		if unicode.Is(unicode.Categories["C"], r) {
			return fmt.Errorf("%s contains a control or formatting character", field)
		}
	}
	return nil
}

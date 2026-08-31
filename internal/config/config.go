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
	"strings"
	"sync"
	"unicode"

	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/internal/securefs"
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
	CredentialRef    string `json:"credential_ref,omitempty"`
	SuccessMessage   string `json:"success_message,omitempty"`
	MACAddress       string `json:"mac_address,omitempty"`
	AutoUnlock       bool   `json:"auto_unlock,omitempty"`
}

// Store manages a JSON file of devices. The in-process mutex orders goroutines
// inside one process; an advisory lock on a sidecar file orders the daemon
// against a separate CLI process, so a load-modify-save cycle cannot silently
// lose a device written by the other one.
type Store struct {
	Path string
	mu   sync.Mutex
}

// lockPath is the sidecar whose advisory lock guards the store. It is a
// separate file so the lock survives the atomic rename that replaces the store.
func (s *Store) lockPath() string { return s.Path + ".lock" }

// mutate serializes a read-modify-write of the store against every other
// process, re-reading the file under the lock so a concurrent writer's device
// is never overwritten from a stale in-memory copy.
func (s *Store) mutate(apply func([]Device) ([]Device, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := securefs.AcquireLock(s.lockPath(), "configuration")
	if err != nil {
		return err
	}
	defer lock.Release()
	devs, err := s.Load()
	if err != nil {
		return err
	}
	next, err := apply(devs)
	if err != nil {
		return err
	}
	return s.save(next)
}

// Load returns the list of devices from the store file.
func (s *Store) Load() ([]Device, error) {
	fh, err := securefs.OpenStable(s.Path, "configuration")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	info, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("configuration exceeds %d bytes", maxConfigSize)
	}
	if err := securefs.VerifyPrivateFile(fh); err != nil {
		return nil, fmt.Errorf("insecure configuration file %s: %w", s.Path, err)
	}
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

// Save replaces the devices in the store file. The caller-supplied inventory is
// authoritative, but the cross-process lock is still held so the replacement
// cannot interleave with another process's read-modify-write cycle.
func (s *Store) Save(devs []Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := securefs.AcquireLock(s.lockPath(), "configuration")
	if err != nil {
		return err
	}
	defer lock.Release()
	return s.save(devs)
}

func (s *Store) save(devs []Device) error {
	if err := validateDevices(devs); err != nil {
		return err
	}
	// #nosec G117 -- Device.Cred is a credential provider reference (a keyring entry or file path), never secret material; secrets live only in the OS keyring, credential file, or TPM.
	b, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxConfigSize {
		return fmt.Errorf("configuration exceeds %d bytes", maxConfigSize)
	}
	return securefs.WritePrivate(s.Path, "configuration", ".devices-*.tmp", b)
}

// Add adds a device to the store.
func (s *Store) Add(d Device) error {
	return s.mutate(func(devs []Device) ([]Device, error) {
		// prevent duplicate device names
		for _, ex := range devs {
			if ex.Name == d.Name {
				return nil, fmt.Errorf("device already exists: %s", d.Name)
			}
		}
		return append(devs, d), nil
	})
}

// Update replaces an existing device with the same name.
func (s *Store) Update(d Device) error {
	if err := ValidateDevice(d); err != nil {
		return err
	}
	return s.mutate(func(devs []Device) ([]Device, error) {
		for i := range devs {
			if devs[i].Name == d.Name {
				devs[i] = d
				return devs, nil
			}
		}
		return nil, fmt.Errorf("device not found: %s", d.Name)
	})
}

// Remove deletes a device by name.
func (s *Store) Remove(name string) error {
	return s.mutate(func(devs []Device) ([]Device, error) {
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
			return nil, fmt.Errorf("device not found: %s", name)
		}
		return out, nil
	})
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
	if d.CredentialSource != "" && d.CredentialSource != credentials.ProviderKeyring && d.CredentialSource != credentials.ProviderRuntime && d.CredentialSource != credentials.ProviderFile {
		return fmt.Errorf("invalid credential source %q", d.CredentialSource)
	}
	if d.AutoUnlock {
		source := d.CredentialSource
		if source == "" {
			if d.Cred == "" {
				source = credentials.ProviderRuntime
			} else {
				source = credentials.ProviderKeyring
			}
		}
		if source == credentials.ProviderRuntime {
			return fmt.Errorf("automatic unlock requires a persistent secure credential provider; runtime/environment credentials are not accepted")
		}
	}
	if d.CredentialSource == credentials.ProviderFile {
		if err := validatePlain("credential reference", d.CredentialRef, 4096); err != nil {
			return err
		}
		if _, err := credentials.NormalizeFileReference(d.CredentialRef); err != nil {
			return err
		}
	} else if d.CredentialRef != "" {
		return fmt.Errorf("credential reference is only valid with the file credential source")
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

// ValidateDevices validates a complete declarative device inventory, including
// cross-device constraints such as unique names and credential identifiers.
func ValidateDevices(devices []Device) error {
	return validateDevices(devices)
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

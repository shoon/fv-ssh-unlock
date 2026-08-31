//go:build keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"os"
	"runtime"
)

func keyringProviderReport() ProviderReport {
	report := ProviderReport{
		Name:       ProviderKeyring,
		Built:      true,
		Persistent: true,
		Security:   SecurityUnavailable,
	}
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat("/usr/bin/security"); err != nil {
			report.Details = "macOS Keychain client is not available: " + err.Error()
			return report
		}
		report.Available = true
		report.SecureStorage = true
		report.Security = SecuritySecure
		report.Details = "macOS Keychain client detected; actual keychain access is verified when used"
	case "windows":
		report.Available = true
		report.SecureStorage = true
		report.Security = SecuritySecure
		report.Details = "Windows Credential Manager is available for the current user"
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			report.Details = "keyring support is built, but no Secret Service D-Bus session was detected"
			return report
		}
		report.Available = true
		report.SecureStorage = true
		report.Security = SecuritySecure
		report.Details = "Secret Service D-Bus session detected; the collection must also be unlocked"
	default:
		report.Details = "keyring support is built but unavailable on this operating system"
	}
	return report
}

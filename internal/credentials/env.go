//go:build !keyring
// +build !keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import "fmt"

// envKey derives the environment variable name for a credential. A leading
// "fvu-" prefix (used internally as the keyring key) is stripped, the name is
// uppercased, and any character that is not a valid POSIX identifier character
// is replaced with an underscore. For a device named "my-mac" this yields
// FV_UNLOCK_PASSWORD_MY_MAC.
// Get retrieves a credential from an environment variable (see envKey).
func Get(name string) (string, error) {
	return GetEnvironment(name)
}

// Set is unavailable without the keyring build tag: setting an environment
// variable here would only affect the current process.
func Set(name, value string) error {
	return fmt.Errorf("credential storage is not available in this build; rebuild with -tags keyring to enable OS keychain storage")
}

// Delete is unavailable without the keyring build tag.
func Delete(name string) error {
	return fmt.Errorf("credential storage is not available in this build")
}

// CanStore reports whether this build can persist credentials.
func CanStore() bool { return false }

//go:build keyring
// +build keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

// Get retrieves a credential from the OS keyring by name.
func Get(name string) (string, error) {
	svc := "fv-ssh-unlock"
	pw, err := keyring.Get(svc, name)
	if err != nil {
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return pw, nil
}

// Set stores a credential in the OS keyring by name.
func Set(name, value string) error {
	svc := "fv-ssh-unlock"
	return keyring.Set(svc, name, value)
}

// Delete removes a credential from the OS keyring.
func Delete(name string) error {
	svc := "fv-ssh-unlock"
	if err := keyring.Delete(svc, name); err != nil {
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}

// CanStore reports whether this build includes the keyring backend.
func CanStore() bool { return true }

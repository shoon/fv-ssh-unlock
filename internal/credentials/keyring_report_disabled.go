//go:build !keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

func keyringProviderReport() ProviderReport {
	return ProviderReport{
		Name:       ProviderKeyring,
		Built:      false,
		Available:  false,
		Persistent: true,
		Security:   SecurityUnavailable,
		Details:    "not included in this build; use a release binary or build with -tags keyring",
	}
}

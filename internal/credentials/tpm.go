// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

func tpm2ProviderReport() ProviderReport {
	return ProviderReport{
		Name:          ProviderTPM2,
		Built:         false,
		Available:     false,
		Persistent:    true,
		SecureStorage: false,
		Security:      SecurityUnavailable,
		Details:       tpm2HardwareDetails(),
	}
}

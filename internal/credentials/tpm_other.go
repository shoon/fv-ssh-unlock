//go:build !linux

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

func tpm2HardwareDetails() string {
	return "TPM hardware detection is not available on this platform; the TPM2 credential provider is not implemented in this build"
}

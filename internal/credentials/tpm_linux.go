//go:build linux

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"fmt"
	"os"
)

func tpm2HardwareDetails() string {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeDevice != 0 {
			return fmt.Sprintf("TPM device detected at %s, but the TPM2 credential provider is not implemented in this build", path)
		}
	}
	return "no accessible TPM device detected; the TPM2 credential provider is not implemented in this build"
}

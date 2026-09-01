//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"fmt"
	"os"
)

func verifyPrivateFile(*os.File) error {
	return fmt.Errorf("private file permissions cannot be verified on this platform")
}

func securePrivateFile(*os.File) error {
	return fmt.Errorf("private file permissions cannot be established on this platform")
}

func verifyOrSecurePrivateDirectory(_ string, _ string, _ os.FileInfo, _ bool) error {
	return fmt.Errorf("private directory permissions cannot be verified on this platform")
}

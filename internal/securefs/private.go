// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Package securefs contains small filesystem checks shared by state stores.
package securefs

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsurePrivateDirectory creates path when absent and otherwise verifies it.
// It deliberately never chmods an existing directory: a caller typo such as
// --data-dir /tmp must fail instead of changing a shared directory's mode.
func EnsurePrivateDirectory(path, purpose string) error {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	created := false
	if os.IsNotExist(err) {
		if err := os.MkdirAll(clean, 0o700); err != nil {
			return err
		}
		created = true
		info, err = os.Lstat(clean)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s directory is not a secure directory: %s", purpose, clean)
	}
	return verifyOrSecurePrivateDirectory(clean, purpose, info, created)
}

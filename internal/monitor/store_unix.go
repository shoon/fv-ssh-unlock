//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import (
	"fmt"
	"os"
	"path/filepath"
)

func validatePrivateFile(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("permissions are %04o; expected no group or other access", info.Mode().Perm())
	}
	return nil
}

func replaceStateFile(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(newPath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

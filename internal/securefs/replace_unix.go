//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"os"
	"path/filepath"
)

// ReplaceFile renames oldPath over newPath and flushes the containing directory
// so the rename itself survives a crash.
func ReplaceFile(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(newPath))
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

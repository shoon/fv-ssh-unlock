//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package config

import (
	"os"
	"path/filepath"
)

func replaceFile(oldPath, newPath string) error {
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

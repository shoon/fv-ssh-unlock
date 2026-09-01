//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import "os"

// ReplaceFile renames oldPath over newPath. Platforms without a directory sync
// or write-through rename keep atomicity but not the durability guarantee.
func ReplaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

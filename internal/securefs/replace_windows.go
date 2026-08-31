//go:build windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import "golang.org/x/sys/windows"

// ReplaceFile renames oldPath over newPath, writing through to disk.
func ReplaceFile(oldPath, newPath string) error {
	oldPointer, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPointer, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldPointer, newPointer, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

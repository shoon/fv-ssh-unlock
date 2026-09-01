//go:build windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"os"

	"golang.org/x/sys/windows"
)

// FILE_FLAG_OPEN_REPARSE_POINT makes the opened descriptor refer to a reparse
// point itself rather than its target. openChecked then rejects it as a
// non-regular path before any read or write can occur.
func openFileNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	// #nosec G304 -- the reparse-point-safe open is followed by descriptor,
	// path, and SameFile validation in openChecked before callers can use it.
	return os.OpenFile(path, flags|windows.O_FILE_FLAG_OPEN_REPARSE_POINT, mode)
}

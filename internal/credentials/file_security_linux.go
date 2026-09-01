//go:build linux

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Kernel filesystem magic numbers are unsigned 32-bit values, but
// unix.Statfs_t.Type is int32 on 32-bit Linux and int64 on 64-bit Linux, so
// ramfsMagic (> MaxInt32) sign-extends differently per platform. Comparing
// through uint32 is the one form that is correct and compiles on both.
const (
	tmpfsMagic uint32 = 0x01021994
	ramfsMagic uint32 = 0x858458f6
)

func platformSecureCredentialFile(path string, _ os.FileInfo) (bool, string) {
	if pathWithin("/run/secrets", path) {
		if memoryBackedFilesystem(path) {
			return true, "file is in a memory-backed /run/secrets mount"
		}
		return false, ""
	}
	return false, ""
}

func platformSecureCredentialDirectory(path string) (bool, string) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return false, ""
	}
	// #nosec G703 -- this function intentionally inspects the exact absolute
	// credential directory selected by the service manager or built-in path.
	// Lstat plus the checks below reject symbolic links and non-directories.
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !memoryBackedFilesystem(clean) {
		return false, ""
	}
	return true, clean + " is a memory-backed credential directory"
}

func memoryBackedFilesystem(path string) bool {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false
	}
	// #nosec G115 -- deliberate truncation: magics are 32-bit kernel values, see the constant block.
	return uint32(stat.Type) == tmpfsMagic || uint32(stat.Type) == ramfsMagic
}

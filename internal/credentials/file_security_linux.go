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

const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
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
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || !memoryBackedFilesystem(path) {
		return false, ""
	}
	return true, filepath.Clean(path) + " is a memory-backed credential directory"
}

func memoryBackedFilesystem(path string) bool {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false
	}
	return uint64(stat.Type) == tmpfsMagic || uint64(stat.Type) == ramfsMagic
}

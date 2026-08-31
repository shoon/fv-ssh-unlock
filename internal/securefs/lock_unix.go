//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX)
}

func unlockFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"os"

	"golang.org/x/sys/unix"
)

// openFileNoFollow prevents a symlink from being followed by the open itself.
// O_NONBLOCK is harmless for regular files and makes a FIFO or device return
// promptly so openChecked can reject it instead of hanging before fstat.
func openFileNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	// #nosec G304 -- the no-follow/nonblocking open is followed by descriptor,
	// path, and SameFile validation in openChecked before callers can use it.
	return os.OpenFile(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
}

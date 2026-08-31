// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileLock is an exclusive advisory lock held on a sidecar lock file. It
// serializes a load-modify-save cycle across processes, such as the daemon
// enrolling a candidate while the CLI adds a device. Callers must still hold
// their own mutex for goroutines inside one process.
type FileLock struct {
	file *os.File
}

// AcquireLock blocks until the exclusive advisory lock on path is held. The
// lock file is created with mode 0600 when absent and is deliberately never
// removed: unlinking it would let two processes lock different inodes and both
// believe they hold the lock. purpose names the store in error messages.
func AcquireLock(path, purpose string) (*FileLock, error) {
	if err := EnsurePrivateDirectory(filepath.Dir(path), purpose); err != nil {
		return nil, err
	}
	file, err := OpenPrivate(path, purpose, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", purpose, err)
	}
	return &FileLock{file: file}, nil
}

// Release unlocks and closes the lock file. Later calls are no-ops.
func (l *FileLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	unlockFile(l.file)
	_ = l.file.Close()
	l.file = nil
}

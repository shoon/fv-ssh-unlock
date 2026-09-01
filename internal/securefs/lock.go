// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLockUnavailable means a non-blocking lock attempt found another holder.
var ErrLockUnavailable = errors.New("lock is already held")

type lockUnavailableError struct {
	purpose string
	cause   error
}

func (e *lockUnavailableError) Error() string {
	return ErrLockUnavailable.Error() + ": " + e.purpose + " (" + e.cause.Error() + ")"
}

func (e *lockUnavailableError) Unwrap() []error {
	return []error{ErrLockUnavailable, e.cause}
}

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
	return AcquireLockContext(context.Background(), path, purpose)
}

// AcquireLockContext is AcquireLock with cancellation while waiting for a
// holder in another process. This lets request-scoped mutations stop promptly
// during daemon shutdown instead of remaining stuck behind an external CLI.
func AcquireLockContext(ctx context.Context, path, purpose string) (*FileLock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("lock %s: context is required", purpose)
	}
	if err := EnsurePrivateDirectory(filepath.Dir(path), purpose); err != nil {
		return nil, err
	}
	file, err := OpenPrivate(path, purpose, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := lockFileContext(ctx, file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", purpose, err)
	}
	return &FileLock{file: file}, nil
}

// TryAcquireLock attempts to take the exclusive lock without waiting. It is
// used for singleton process locks where contention is itself the result.
func TryAcquireLock(path, purpose string) (*FileLock, error) {
	if err := EnsurePrivateDirectory(filepath.Dir(path), purpose); err != nil {
		return nil, err
	}
	file, err := OpenPrivate(path, purpose, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := tryLockFile(file); err != nil {
		_ = file.Close()
		return nil, &lockUnavailableError{purpose: purpose, cause: err}
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

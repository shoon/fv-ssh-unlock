// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileMode is the mode of every private file this package creates or repairs.
const FileMode = 0o600

// VerifyPrivatePermissions rejects POSIX permission bits that grant group or
// other access. Call VerifyPrivateFile when the platform's ACL must also be
// checked.
func VerifyPrivatePermissions(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("permissions are %04o; expected no group or other access", info.Mode().Perm())
	}
	return nil
}

// VerifyPrivateFile rejects a file that principals other than the current
// account and trusted system administrators can access. Unix uses ownership
// and mode bits; Windows inspects the file's native owner and DACL.
func VerifyPrivateFile(file *os.File) error {
	if file == nil {
		return errors.New("private file is required")
	}
	return verifyPrivateFile(file)
}

// OpenStable opens path read-only and validates the opened descriptor against
// the path rather than trusting an Lstat taken before the open. A local symlink
// swap therefore cannot redirect the read to another file. purpose names the
// store in error messages.
func OpenStable(path, purpose string) (*os.File, error) {
	return openChecked(path, purpose, os.O_RDONLY, false)
}

// OpenPrivate opens path with flags, creating it with mode 0600 when os.O_CREATE
// is present, applies the same stable-descriptor validation as OpenStable, and
// re-applies mode 0600 to the opened descriptor.
func OpenPrivate(path, purpose string, flags int) (*os.File, error) {
	return openChecked(path, purpose, flags, true)
}

// ReadPrivate reads a bounded private regular file through the descriptor that
// OpenStable validated. Callers get one consistent ordering for symlink,
// ownership, permission, size, and short-read checks.
func ReadPrivate(path, purpose string, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("%s maximum size must not be negative", purpose)
	}
	file, err := OpenStable(path, purpose)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", purpose, maximum)
	}
	if err := VerifyPrivateFile(file); err != nil {
		return nil, fmt.Errorf("insecure %s file %s: %w", purpose, path, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", purpose, maximum)
	}
	return data, nil
}

func openChecked(path, purpose string, flags int, repairMode bool) (*os.File, error) {
	file, err := openFileNoFollow(path, flags, FileMode)
	if err != nil {
		if linked, statErr := os.Lstat(path); statErr == nil &&
			(!linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0) {
			return nil, fmt.Errorf("%s is not a stable regular file: %s", purpose, path)
		}
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if !opened.Mode().IsRegular() || !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) {
		return fail(fmt.Errorf("%s is not a stable regular file: %s", purpose, path))
	}
	if repairMode {
		if err := securePrivateFile(file); err != nil {
			return fail(err)
		}
	}
	return file, nil
}

// WritePrivate atomically replaces path with data. The content is written to a
// private temporary file created from pattern in the same directory, flushed to
// stable storage, and renamed over path, so no reader observes a partial or
// group-readable file. purpose names the store in error messages.
func WritePrivate(path, purpose, pattern string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDirectory(dir, purpose); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular file: %s", purpose, path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temporary, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	failed := func(err error) error {
		_ = temporary.Close()
		return err
	}
	if err := securePrivateFile(temporary); err != nil {
		return failed(err)
	}
	if _, err := temporary.Write(data); err != nil {
		return failed(err)
	}
	if err := temporary.Sync(); err != nil {
		return failed(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := ReplaceFile(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

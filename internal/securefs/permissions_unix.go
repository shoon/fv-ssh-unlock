//go:build unix

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"fmt"
	"os"
	"syscall"
)

func verifyPrivateFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if err := VerifyPrivatePermissions(info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errorsUnverifiableOwner()
	}
	if int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("owner uid is %d; expected current uid %d", stat.Uid, os.Geteuid())
	}
	return nil
}

func securePrivateFile(file *os.File) error {
	if err := file.Chmod(FileMode); err != nil {
		return err
	}
	return verifyPrivateFile(file)
}

func verifyOrSecurePrivateDirectory(_ string, purpose string, info os.FileInfo, _ bool) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s directory must not be accessible by group or other users", purpose)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s directory owner cannot be verified", purpose)
	}
	if int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%s directory owner uid is %d; expected current uid %d", purpose, stat.Uid, os.Geteuid())
	}
	return nil
}

func errorsUnverifiableOwner() error {
	return fmt.Errorf("private file owner cannot be verified")
}

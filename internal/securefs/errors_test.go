// SPDX-License-Identifier: Apache-2.0

package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateFileChecksReportClosedDescriptors(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "state.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, FileMode)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivateFile(file); err == nil {
		t.Fatal("closed descriptor passed private-file verification")
	}
	if err := securePrivateFile(file); err == nil {
		t.Fatal("closed descriptor was secured")
	}
}

func TestAcquireLockRejectsUnsafeParentAndNonRegularTarget(t *testing.T) {
	if runtime.GOOS != "windows" {
		shared := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		if lock, err := AcquireLock(filepath.Join(shared, "state.lock"), "test store"); err == nil {
			lock.Release()
			t.Fatal("lock accepted an unsafe parent directory")
		}
	}

	private := privateTestDir(t)
	target := filepath.Join(private, "state.lock")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if lock, err := AcquireLock(target, "test store"); err == nil {
		lock.Release()
		t.Fatal("directory was accepted as a lock file")
	}
}

func TestFilesystemOperationsPropagateDeterministicPathErrors(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file-parent")
	if err := os.WriteFile(parent, nil, FileMode); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(filepath.Join(parent, "nested"), "test store"); err == nil {
		t.Fatal("directory creation beneath a regular file succeeded")
	}
	if file, err := OpenStable(filepath.Join(t.TempDir(), "missing"), "test store"); !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatalf("missing stable file error = %v", err)
	}
	if err := ReplaceFile(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing replacement source error = %v", err)
	}
}

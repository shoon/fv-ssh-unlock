// SPDX-License-Identifier: Apache-2.0

package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestVerifyPrivateFileRejectsNilAndInsecureMode(t *testing.T) {
	if err := VerifyPrivateFile(nil); err == nil {
		t.Fatal("nil file was accepted")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows private-file behavior is covered by ACL-specific tests")
	}
	path := filepath.Join(privateTestDir(t), "private.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := VerifyPrivateFile(file); err == nil {
		t.Fatal("group/world-readable file was accepted")
	}
	if err := os.Chmod(path, FileMode); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivateFile(file); err != nil {
		t.Fatalf("private file was rejected: %v", err)
	}
}

func TestOpenPrivateRepairsModeAndRejectsNonRegularPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows private-file behavior is covered by ACL-specific tests")
	}
	dir := privateTestDir(t)
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := OpenPrivate(path, "test store", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != FileMode {
		t.Fatalf("mode = %04o, want %04o", info.Mode().Perm(), FileMode)
	}
	if file, err := OpenPrivate(dir, "test store", os.O_RDONLY); err == nil {
		_ = file.Close()
		t.Fatal("directory was accepted as a private file")
	}
}

func TestWritePrivateRejectsNonRegularTargetAndUnsafeDirectory(t *testing.T) {
	dir := privateTestDir(t)
	target := filepath.Join(dir, "state.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(target, "test store", ".state-*.tmp", []byte("{}")); err == nil {
		t.Fatal("directory target was accepted")
	}

	if runtime.GOOS == "windows" {
		return
	}
	unsafeDir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := WritePrivate(filepath.Join(unsafeDir, "state.json"), "test store", ".state-*.tmp", []byte("{}"))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe directory was accepted or misreported: %v", err)
	}
}

func TestWritePrivateReplacesAtomicallyWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := WritePrivate(path, "test store", ".state-*.tmp", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, "test store", ".state-*.tmp", []byte("second")); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "second" {
		t.Fatalf("content = %q, want %q", content, "second")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != FileMode {
		t.Fatalf("mode = %04o, want %04o", info.Mode().Perm(), FileMode)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("temporary file remained after an atomic save: %v", entries)
	}
}

func TestWritePrivateAndOpenStableRefuseSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	dir := privateTestDir(t)
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("payload"), FileMode); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(link, "test store", ".state-*.tmp", []byte("overwritten")); err == nil {
		t.Fatal("WritePrivate followed a symlink")
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "payload" {
		t.Fatalf("symlink target was modified: content=%q err=%v", content, err)
	}
	file, err := OpenStable(link, "test store")
	if err == nil {
		_ = file.Close()
		t.Fatal("OpenStable followed a symlink")
	}
	if !strings.Contains(err.Error(), "stable regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyPrivatePermissionsRejectsGroupAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows security is carried by the inherited ACL")
	}
	path := filepath.Join(privateTestDir(t), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivatePermissions(info); err == nil {
		t.Fatal("group-readable file was accepted")
	}
	if err := os.Chmod(path, FileMode); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivatePermissions(info); err != nil {
		t.Fatalf("private file was rejected: %v", err)
	}
}

func TestAcquireLockSerializesHolders(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "devices.json.lock")
	lock, err := AcquireLock(path, "test store")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != FileMode {
		t.Fatalf("lock file mode = %04o, want %04o", info.Mode().Perm(), FileMode)
	}

	// A second holder in this process must observe the same lock file; the
	// advisory lock itself is per open file description, so the ordering that
	// matters across processes is exercised by the config store's test.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		second, err := AcquireLock(path, "test store")
		if err != nil {
			t.Error(err)
			return
		}
		second.Release()
	}()
	lock.Release()
	lock.Release()
	wg.Wait()
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

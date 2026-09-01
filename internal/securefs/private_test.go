// SPDX-License-Identifier: Apache-2.0

package securefs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsurePrivateDirectoryCreatesAndPreservesSecureDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "nested")
	if err := EnsurePrivateDirectory(path, "test"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("created directory mode = %o", info.Mode().Perm())
	}
	if err := EnsurePrivateDirectory(path, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePrivateDirectoryDoesNotChmodSharedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are tested on Unix")
	}
	path := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(path, "test"); err == nil {
		t.Fatal("shared directory was accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("shared directory mode changed to %o", info.Mode().Perm())
	}
}

func TestEnsurePrivateDirectoryRejectsFileAndSymlink(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(file, "test"); err == nil {
		t.Fatal("regular file was accepted as a private directory")
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(root, "private")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "private-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(link, "test"); err == nil {
		t.Fatal("symlink was accepted as a private directory")
	}
}

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

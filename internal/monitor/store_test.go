// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFileStoreRoundTripAndPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	store := &FileStore{Path: path}
	want := PersistentState{
		Version: persistentStateVersion,
		Devices: map[string]DeviceRecord{
			"m4alpha": {
				State:                StateBooting,
				LockEpisode:          7,
				LockEpisodeOpen:      true,
				UnlockAttempted:      true,
				NextUnlockEligibleAt: time.Now().UTC().Add(time.Hour).Truncate(time.Nanosecond),
			},
		},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%04o, want 0600", info.Mode().Perm())
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	gotRecord := got.Devices["m4alpha"]
	wantRecord := want.Devices["m4alpha"]
	if got.Version != want.Version || gotRecord.State != wantRecord.State ||
		gotRecord.LockEpisode != wantRecord.LockEpisode || !gotRecord.UnlockAttempted ||
		!gotRecord.NextUnlockEligibleAt.Equal(wantRecord.NextUnlockEligibleAt) {
		t.Fatalf("round trip mismatch: got=%+v want=%+v", got, want)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("temporary file remained after atomic save: %v", entries)
	}
}

func TestFileStoreRejectsSymlinkAndInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are not represented by Unix permission bits")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{\"version\":1,\"devices\":{}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	store := &FileStore{Path: link}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load accepted a symlink")
	}
	if err := store.Save(PersistentState{}); err == nil {
		t.Fatal("Save accepted a symlink")
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	store.Path = target
	if _, err := store.Load(); err == nil {
		t.Fatal("Load accepted group/world-readable state")
	}
}

func TestFileStoreRejectsTrailingOrUnknownData(t *testing.T) {
	for name, content := range map[string]string{
		"trailing": `{\"version\":1,\"devices\":{}} {}`,
		"unknown":  `{\"version\":1,\"devices\":{},\"surprise\":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (&FileStore{Path: path}).Load(); err == nil {
				t.Fatal("malformed state was accepted")
			}
		})
	}
}

func TestSnapshotJSONOmitsZeroTimestamps(t *testing.T) {
	payload, err := json.Marshal(DeviceSnapshot{
		Device:       Device{Name: "mac", Host: "192.0.2.10", User: "user"},
		DeviceRecord: DeviceRecord{State: StateIndeterminate},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("0001-01-01")) || bytes.Contains(payload, []byte("last_checked_at")) {
		t.Fatalf("zero timestamps leaked into operator JSON: %s", payload)
	}
}

// The stable-open idiom must be exercised through the opened descriptor rather
// than an Lstat taken before the open, so a swap between the check and the read
// cannot redirect Load to another file.
func TestFileStoreLoadValidatesOpenedDescriptor(t *testing.T) {
	dir := t.TempDir()
	directoryPath := filepath.Join(dir, "state-dir.json")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (&FileStore{Path: directoryPath}).Load(); err == nil {
		t.Fatal("Load accepted a directory")
	}
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"devices":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := (&FileStore{Path: link}).Load()
	if err == nil || !strings.Contains(err.Error(), "stable regular file") {
		t.Fatalf("Load accepted a symlink: %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shoon/fv-ssh-unlock/internal/securefs"
)

const maxStateSize = 4 << 20

// FileStore atomically stores monitor state in a private JSON file.
type FileStore struct {
	Path string
}

func (s *FileStore) Load() (PersistentState, error) {
	if s == nil || s.Path == "" {
		return PersistentState{}, errorsNewPath()
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return PersistentState{Version: persistentStateVersion, Devices: map[string]DeviceRecord{}}, nil
		}
		return PersistentState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return PersistentState{}, fmt.Errorf("monitor state is not a regular file: %s", s.Path)
	}
	if err := validatePrivateFile(info); err != nil {
		return PersistentState{}, fmt.Errorf("insecure monitor state file %s: %w", s.Path, err)
	}
	if info.Size() > maxStateSize {
		return PersistentState{}, fmt.Errorf("monitor state exceeds %d bytes", maxStateSize)
	}
	fh, err := os.Open(s.Path)
	if err != nil {
		return PersistentState{}, err
	}
	defer fh.Close()
	content, err := io.ReadAll(io.LimitReader(fh, maxStateSize+1))
	if err != nil {
		return PersistentState{}, err
	}
	if len(content) > maxStateSize {
		return PersistentState{}, fmt.Errorf("monitor state exceeds %d bytes", maxStateSize)
	}
	var state PersistentState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return PersistentState{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return PersistentState{}, errorsTrailingData(err)
	}
	if state.Devices == nil {
		state.Devices = map[string]DeviceRecord{}
	}
	return state, nil
}

func (s *FileStore) Save(state PersistentState) error {
	if s == nil || s.Path == "" {
		return errorsNewPath()
	}
	if state.Version == 0 {
		state.Version = persistentStateVersion
	}
	if state.Version != persistentStateVersion {
		return fmt.Errorf("unsupported monitor state version %d", state.Version)
	}
	if state.Devices == nil {
		state.Devices = map[string]DeviceRecord{}
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if len(content) > maxStateSize {
		return fmt.Errorf("monitor state exceeds %d bytes", maxStateSize)
	}

	dir := filepath.Dir(s.Path)
	if err := securefs.EnsurePrivateDirectory(dir, "monitor state"); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("monitor state is not a regular file: %s", s.Path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".monitor-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceStateFile(tmpName, s.Path); err != nil {
		return err
	}
	return os.Chmod(s.Path, 0o600)
}

func errorsNewPath() error { return fmt.Errorf("monitor state path is required") }

func errorsTrailingData(err error) error {
	if err == nil {
		return fmt.Errorf("monitor state contains trailing data")
	}
	return fmt.Errorf("monitor state contains trailing data: %w", err)
}

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
	content, err := securefs.ReadPrivate(s.Path, "monitor state", maxStateSize)
	if err != nil {
		if os.IsNotExist(err) {
			return PersistentState{Version: persistentStateVersion, Devices: map[string]DeviceRecord{}}, nil
		}
		return PersistentState{}, err
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

	return securefs.WritePrivate(s.Path, "monitor state", ".monitor-state-*.tmp", content)
}

func errorsNewPath() error { return fmt.Errorf("monitor state path is required") }

func errorsTrailingData(err error) error {
	if err == nil {
		return fmt.Errorf("monitor state contains trailing data")
	}
	return fmt.Errorf("monitor state contains trailing data: %w", err)
}

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package candidates

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/shoon/fv-ssh-unlock/internal/securefs"
)

const (
	storeVersion = 1
	maxStoreSize = 4 << 20
)

type diskState struct {
	Version    int                     `json:"version"`
	Sequence   uint64                  `json:"sequence"`
	Configured []ConfiguredFingerprint `json:"configured,omitempty"`
	Candidates []Candidate             `json:"candidates"`
}

func (b *Inbox) saveLocked() error {
	if b.path == "" {
		return nil
	}
	state := diskState{Version: storeVersion, Sequence: b.sequence, Candidates: make([]Candidate, 0, len(b.entries))}
	for fingerprint, names := range b.configured {
		state.Configured = append(state.Configured, ConfiguredFingerprint{Fingerprint: fingerprint, DeviceNames: cloneStrings(names)})
	}
	sort.Slice(state.Configured, func(i, j int) bool { return state.Configured[i].Fingerprint < state.Configured[j].Fingerprint })
	for _, candidate := range b.entries {
		state.Candidates = append(state.Candidates, cloneCandidate(*candidate))
	}
	sort.Slice(state.Candidates, func(i, j int) bool { return state.Candidates[i].ID < state.Candidates[j].ID })
	return saveState(b.path, state)
}

func loadState(path string) (*diskState, error) {
	file, err := securefs.OpenStable(path, "candidate inbox")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxStoreSize {
		return nil, fmt.Errorf("candidate inbox exceeds %d bytes", maxStoreSize)
	}
	if err := securefs.VerifyPrivatePermissions(info); err != nil {
		return nil, fmt.Errorf("insecure candidate inbox %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStoreSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStoreSize {
		return nil, fmt.Errorf("candidate inbox exceeds %d bytes", maxStoreSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state diskState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode candidate inbox: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("candidate inbox contains trailing data")
	}
	if state.Version != storeVersion {
		return nil, fmt.Errorf("unsupported candidate inbox version %d", state.Version)
	}
	return &state, nil
}

func saveState(path string, state diskState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxStoreSize {
		return fmt.Errorf("candidate inbox exceeds %d bytes", maxStoreSize)
	}
	return securefs.WritePrivate(path, "candidate inbox", ".candidates-*.tmp", data)
}

func validateCandidate(candidate Candidate) error {
	if len(candidate.ID) != len("cand_")+32 || !stringsHasHexPrefix(candidate.ID, "cand_") {
		return errors.New("invalid candidate ID")
	}
	switch candidate.State {
	case StateDiscovered, StateIdentityPending, StateVerified, StateIgnored:
	default:
		return fmt.Errorf("invalid state %q", candidate.State)
	}
	if candidate.Fingerprint != "" {
		fingerprint, err := normalizeFingerprint(candidate.Fingerprint)
		if err != nil || fingerprint != candidate.Fingerprint {
			return errors.New("invalid fingerprint")
		}
	}
	if candidate.State == StateDiscovered && candidate.Fingerprint != "" {
		return errors.New("discovered candidate must not have a fingerprint")
	}
	if candidate.State == StateIdentityPending && candidate.Fingerprint == "" {
		return errors.New("identity-pending candidate requires a fingerprint")
	}
	if candidate.State == StateVerified && candidate.Fingerprint == "" {
		return errors.New("verified candidate requires a fingerprint")
	}
	if candidate.State == StateIgnored && candidate.IgnoredAt == nil {
		return errors.New("ignored candidate requires ignored_at")
	}
	if candidate.State != StateIgnored && candidate.IgnoredAt != nil {
		return errors.New("non-ignored candidate has ignored_at")
	}
	if len(candidate.ConfiguredNames) > 0 && candidate.Fingerprint == "" {
		return errors.New("configured candidate requires a fingerprint")
	}
	if candidate.Fingerprint == "" && len(candidate.Names) == 0 && len(candidate.Hostnames) == 0 && len(candidate.Endpoints) == 0 {
		return errors.New("candidate has no observable identity")
	}
	if candidate.FirstSeen.IsZero() || candidate.LastSeen.IsZero() || candidate.LastSeen.Before(candidate.FirstSeen) {
		return errors.New("invalid candidate timestamps")
	}
	for _, value := range candidate.Names {
		if normalized, err := normalizePlain("name", value, 256); err != nil || normalized != value {
			return errors.New("invalid candidate name")
		}
	}
	for _, value := range candidate.Hostnames {
		if normalized, err := normalizePlain("hostname", value, 253); err != nil || normalized != value || strings.HasSuffix(value, ".") {
			return errors.New("invalid candidate hostname")
		}
	}
	for _, value := range candidate.Sources {
		if normalized, err := normalizePlain("source", value, 64); err != nil || normalized != value {
			return errors.New("invalid candidate source")
		}
	}
	for _, value := range candidate.ConfiguredNames {
		if normalized, err := normalizePlain("configured device name", value, 128); err != nil || normalized != value {
			return errors.New("invalid configured device name")
		}
	}
	if candidate.KeyType != "" {
		if normalized, err := normalizePlain("key type", candidate.KeyType, 128); err != nil || normalized != candidate.KeyType {
			return errors.New("invalid key type")
		}
	}
	if candidate.LastEvidence != "" {
		if normalized, err := normalizePlain("evidence", candidate.LastEvidence, 256); err != nil || normalized != candidate.LastEvidence {
			return errors.New("invalid evidence")
		}
	}
	if candidate.VerifiedAt != nil && candidate.VerifiedAt.IsZero() {
		return errors.New("invalid verified_at")
	}
	if candidate.IgnoredAt != nil && candidate.IgnoredAt.IsZero() {
		return errors.New("invalid ignored_at")
	}
	for _, endpoint := range candidate.Endpoints {
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil || address.Unmap().String() != endpoint.Address {
			return errors.New("invalid endpoint address")
		}
		if endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.FirstSeen.IsZero() || endpoint.LastSeen.Before(endpoint.FirstSeen) {
			return errors.New("invalid endpoint")
		}
	}
	return nil
}

func stringsHasHexPrefix(value, prefix string) bool {
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

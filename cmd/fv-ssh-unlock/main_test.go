// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"strings"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/config"
)

func TestCommandHelpDocumentsObservedPrebootBehavior(t *testing.T) {
	tests := map[string]struct {
		help    string
		phrases []string
	}{
		"root":       {rootLongHelp, []string{"show only Password:", "unknown", "without advertising Bonjour", "DHCP reservation"}},
		"config add": {addLongHelp, []string{"DHCP reservation", "manually assigned static", ".local", "after restart"}},
		"unlock":     {unlockLongHelp, []string{"explanation may be absent", "SUCCESS", "VERIFIED", "--identity"}},
		"status":     {statusLongHelp, []string{"only Password:", "unknown", "ssh-agent", "--identity"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, phrase := range tt.phrases {
				if !strings.Contains(tt.help, phrase) {
					t.Errorf("help is missing %q", phrase)
				}
			}
		})
	}
}

func TestIndeterminateStatusTextExplainsPromptOnlyVariant(t *testing.T) {
	for _, phrase := range []string{"prompt-only pre-boot", "password-only SSH", "ssh-agent/--identity", "prove booted"} {
		if !strings.Contains(indeterminateStatusText, phrase) {
			t.Errorf("indeterminate status text is missing %q", phrase)
		}
	}
}

func TestCredentialStoreForDevice(t *testing.T) {
	tests := []struct {
		name        string
		device      config.Device
		wantRuntime bool
	}{
		{name: "explicit runtime", device: config.Device{Cred: "fvu-mac", CredentialSource: "runtime"}, wantRuntime: true},
		{name: "explicit keyring", device: config.Device{Cred: "fvu-mac", CredentialSource: "keyring"}},
		{name: "legacy unstored", device: config.Device{}, wantRuntime: true},
		{name: "legacy stored", device: config.Device{Cred: "fvu-mac"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, isRuntime := credentialStoreForDevice(tt.device).(*environmentStore)
			if isRuntime != tt.wantRuntime {
				t.Fatalf("runtime store = %v, want %v", isRuntime, tt.wantRuntime)
			}
		})
	}
}

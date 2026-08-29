// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

func TestCommandHelpDocumentsObservedPrebootBehavior(t *testing.T) {
	tests := map[string]struct {
		help    string
		phrases []string
	}{
		"root":       {rootLongHelp, []string{"show only Password:", "indeterminate", "without advertising Bonjour", "DHCP reservation"}},
		"config add": {addLongHelp, []string{"DHCP reservation", "manually assigned static", ".local", "after restart", "systemd:<name>", "--allow-unsafe-credential-storage"}},
		"unlock":     {unlockLongHelp, []string{"explanation may be absent", "SUCCESS", "VERIFIED", "--identity", "--allow-unsafe-credential-storage"}},
		"status":     {statusLongHelp, []string{"only Password:", "indeterminate", "ssh-agent", "standard ~/.ssh", "--identity"}},
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
	for _, phrase := range []string{"indeterminate", "SSH reachable", "no proof", "booted macOS"} {
		if !strings.Contains(indeterminateStatusText, phrase) {
			t.Errorf("indeterminate status text is missing %q", phrase)
		}
	}
}

func TestSelectConfiguredDevicesPreservesRequestedOrder(t *testing.T) {
	configured := []config.Device{{Name: "alpha"}, {Name: "beta"}}
	selected, err := selectConfiguredDevices(configured, []string{"beta", "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Name != "beta" || selected[1].Name != "alpha" {
		t.Fatalf("selected = %+v", selected)
	}
}

func TestSelectConfiguredDevicesRejectsMissingOrDuplicateName(t *testing.T) {
	configured := []config.Device{{Name: "alpha"}}
	if _, err := selectConfiguredDevices(configured, []string{"missing"}); err == nil || !strings.Contains(err.Error(), "device not found") {
		t.Fatalf("missing device error = %v", err)
	}
	if _, err := selectConfiguredDevices(configured, []string{"alpha", "alpha"}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate device error = %v", err)
	}
}

func TestCredentialStoreForDevice(t *testing.T) {
	tests := []struct {
		name       string
		device     config.Device
		wantSource string
	}{
		{name: "explicit runtime", device: config.Device{Cred: "fvu-mac", CredentialSource: "runtime"}, wantSource: credentials.ProviderRuntime},
		{name: "explicit keyring", device: config.Device{Cred: "fvu-mac", CredentialSource: "keyring"}, wantSource: credentials.ProviderKeyring},
		{name: "explicit file", device: config.Device{Cred: "fvu-mac", CredentialSource: "file", CredentialRef: "/run/secrets/mac"}, wantSource: credentials.ProviderFile},
		{name: "legacy unstored", device: config.Device{}, wantSource: credentials.ProviderRuntime},
		{name: "legacy stored", device: config.Device{Cred: "fvu-mac"}, wantSource: credentials.ProviderKeyring},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := credentialStoreForDevice(tt.device, false)
			if err != nil {
				t.Fatal(err)
			}
			providerStore, ok := store.(*providerStore)
			if !ok {
				t.Fatalf("store type = %T, want *providerStore", store)
			}
			if got := providerStore.provider.Name(); got != tt.wantSource {
				t.Fatalf("provider = %q, want %q", got, tt.wantSource)
			}
		})
	}
}

func TestProviderReportOutputExplainsUnsafeFallback(t *testing.T) {
	reports := []credentials.ProviderReport{
		{
			Name:       credentials.ProviderRuntime,
			Built:      true,
			Available:  true,
			Persistent: false,
			Security:   credentials.SecurityRuntimeOnly,
			Details:    "runtime test provider",
		},
	}
	var out bytes.Buffer
	if err := writeProviderReports(&out, reports, false); err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"runtime", "runtime-only", "No verified secure persistent", "--allow-unsafe-credential-storage"} {
		if !strings.Contains(out.String(), phrase) {
			t.Fatalf("provider output is missing %q:\n%s", phrase, out.String())
		}
	}
}

func TestProviderReportJSON(t *testing.T) {
	reports := []credentials.ProviderReport{{
		Name:          credentials.ProviderKeyring,
		Built:         true,
		Available:     true,
		Persistent:    true,
		SecureStorage: true,
		Security:      credentials.SecuritySecure,
		Details:       "test keyring",
	}}
	var out bytes.Buffer
	if err := writeProviderReportsJSON(&out, reports, true); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SecureStorageAvailable bool                         `json:"secure_storage_available"`
		Providers              []credentials.ProviderReport `json:"providers"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.SecureStorageAvailable || len(decoded.Providers) != 1 || decoded.Providers[0].Name != credentials.ProviderKeyring {
		t.Fatalf("unexpected JSON report: %+v", decoded)
	}
}

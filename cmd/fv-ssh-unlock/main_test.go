// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

func TestCommandHelpDocumentsObservedPrebootBehavior(t *testing.T) {
	tests := map[string]struct {
		help    string
		phrases []string
	}{
		"root":       {rootLongHelp, []string{"show only Password:", "indeterminate", "without advertising Bonjour", "DHCP reservation"}},
		"config add": {addLongHelp, []string{"--host and --user", "optional local alias", "DHCP reservation", "manually assigned static", ".local", "after restart", "systemd:<name>", "--allow-unsafe-credential-storage"}},
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

func TestProcessEntryPointRendersRootHelpWithoutExiting(t *testing.T) {
	stdout, err := os.CreateTemp(t.TempDir(), "stdout-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()

	oldArgs, oldStdout, oldStderr := os.Args, os.Stdout, os.Stderr
	os.Args = []string{"fv-ssh-unlock", "--help"}
	os.Stdout, os.Stderr = stdout, stderr
	defer func() {
		os.Args, os.Stdout, os.Stderr = oldArgs, oldStdout, oldStderr
	}()

	main()
	if _, err := stdout.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	rendered, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"remotely unlocks FileVault-protected macOS devices", "Available Commands:", "daemon", "healthcheck", "tui"} {
		if !strings.Contains(string(rendered), phrase) {
			t.Errorf("root help missing %q:\n%s", phrase, rendered)
		}
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

func TestCredentialSourceLabelsAreExplicitAndTerminalSafe(t *testing.T) {
	for name, test := range map[string]struct {
		device config.Device
		want   string
	}{
		"keyring":        {device: config.Device{CredentialSource: credentials.ProviderKeyring}, want: "OS keyring"},
		"runtime":        {device: config.Device{CredentialSource: credentials.ProviderRuntime}, want: "runtime (environment or hidden prompt)"},
		"file":           {device: config.Device{CredentialSource: credentials.ProviderFile, CredentialRef: "/run/secret\r\nforged"}, want: `external file (/run/secret\u000D\u000Aforged)`},
		"legacy runtime": {device: config.Device{}, want: "legacy runtime (environment or hidden prompt)"},
		"legacy keyring": {device: config.Device{Cred: "fvu-mac"}, want: "legacy OS keyring"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := credentialSourceLabel(test.device); got != test.want {
				t.Fatalf("credential label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDeleteStoredCredentialSkipsNonKeyringAndUnavailableProviders(t *testing.T) {
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()
	oldStderr := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = oldStderr }()

	for _, device := range []config.Device{
		{},
		{Name: "runtime", CredentialSource: credentials.ProviderRuntime},
		{Name: "file", CredentialSource: credentials.ProviderFile, CredentialRef: "/run/secrets/file"},
		{Name: "unknown", CredentialSource: "not-a-provider"},
	} {
		deleteStoredCredential(device)
	}
	if _, err := stderr.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("skipped credential deletion emitted a warning: %q", output)
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

func TestWriteStatusJSONPreservesEmptyArray(t *testing.T) {
	var out bytes.Buffer
	if err := writeStatusJSON(&out, []statusReport{}); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion int             `json:"schema_version"`
		Devices       json.RawMessage `json:"devices"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 || string(decoded.Devices) != "[]" {
		t.Fatalf("unexpected empty status JSON: %s", out.String())
	}
}

// fakeUnlockClient scripts one response per unlock attempt and one per
// post-unlock verification, so the retry state machine can be driven through
// every terminal path without a network.
type fakeUnlockClient struct {
	unlockResponses []fakeUnlockResponse
	verifyResponses []fakeVerifyResponse
	passwords       []string
	verifyCalls     int
}

type fakeUnlockResponse struct {
	status fvcore.DeviceStatus
	banner string
	err    error
}

type fakeVerifyResponse struct {
	status fvcore.DeviceStatus
	err    error
}

func (f *fakeUnlockClient) AnalyzePrompt(_ context.Context, _, _, password, _ string) (fvcore.DeviceStatus, string, error) {
	f.passwords = append(f.passwords, password)
	response := f.unlockResponses[min(len(f.passwords)-1, len(f.unlockResponses)-1)]
	return response.status, response.banner, response.err
}

func (f *fakeUnlockClient) ProbeStatus(context.Context, string, string) (fvcore.DeviceStatus, string, error) {
	f.verifyCalls++
	if len(f.verifyResponses) == 0 {
		return fvcore.StatusUnknown, "", fvcore.ErrIndeterminate
	}
	response := f.verifyResponses[min(f.verifyCalls-1, len(f.verifyResponses)-1)]
	return response.status, "", response.err
}

func TestUnlockDeviceWithRetryOutcomes(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	tests := map[string]struct {
		client        *fakeUnlockClient
		opts          unlockRetryOptions
		wantOutcome   unlockOutcome
		wantFatal     error
		wantSubmits   int
		wantOutput    []string
		wantNotOutput []string
	}{
		"accepted banner is a success": {
			client:      &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnlocked}}},
			opts:        unlockRetryOptions{maxAttempts: 3},
			wantOutcome: unlockOutcomeUnlocked,
			wantSubmits: 1,
			wantOutput:  []string{"SUCCESS: mac accepted the unlock password."},
		},
		"already booted needs no unlock": {
			client:      &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnlockedRecently}}},
			opts:        unlockRetryOptions{maxAttempts: 3},
			wantOutcome: unlockOutcomeUnlocked,
			wantSubmits: 1,
			wantOutput:  []string{"INFO: mac is already booted"},
		},
		"rejected credential does not retry": {
			client:      &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusLocked, err: fvcore.ErrAuthFailed}}},
			opts:        unlockRetryOptions{maxAttempts: 5},
			wantOutcome: unlockOutcomeIncorrectPassword,
			wantSubmits: 1,
			wantOutput:  []string{"FAILED: mac is still locked (incorrect password)."},
		},
		"host key mismatch is fatal and never retried": {
			client:      &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrHostKeyMismatch}}},
			opts:        unlockRetryOptions{maxAttempts: 5},
			wantFatal:   fvcore.ErrHostKeyMismatch,
			wantSubmits: 1,
			wantOutput:  []string{"SECURITY ERROR: refusing mac"},
		},
		"transient failures retry to the configured limit": {
			client:      &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: errors.New("dial tcp: connection refused")}}},
			opts:        unlockRetryOptions{maxAttempts: 3},
			wantOutcome: unlockOutcomeExhausted,
			wantSubmits: 3,
			wantOutput:  []string{"Attempt 3/3 failed", "reached max retry attempts"},
		},
		"unacknowledged submission is credited only when a probe proves boot": {
			client: &fakeUnlockClient{
				unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrUnlockOutcomeUnknown}},
				verifyResponses: []fakeVerifyResponse{{status: fvcore.StatusUnlockedRecently}},
			},
			opts:        unlockRetryOptions{maxAttempts: 3, verifyWindow: time.Second},
			wantOutcome: unlockOutcomeUnlocked,
			wantSubmits: 1,
			wantOutput:  []string{"without sending the password again", "VERIFIED: mac is booted"},
		},
		"unacknowledged submission that cannot be proved fails closed": {
			client: &fakeUnlockClient{
				unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrUnlockOutcomeUnknown}},
				verifyResponses: []fakeVerifyResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrIndeterminate}},
			},
			opts:          unlockRetryOptions{maxAttempts: 1, verifyWindow: time.Second},
			wantOutcome:   unlockOutcomeExhausted,
			wantSubmits:   1,
			wantOutput:    []string{"cannot yet be proved without a public key"},
			wantNotOutput: []string{"VERIFIED"},
		},
		"a host key change during verification is fatal": {
			client: &fakeUnlockClient{
				unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrUnlockOutcomeUnknown}},
				verifyResponses: []fakeVerifyResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrHostKeyMismatch}},
			},
			opts:        unlockRetryOptions{maxAttempts: 3, verifyWindow: time.Second},
			wantFatal:   fvcore.ErrHostKeyMismatch,
			wantSubmits: 1,
		},
		"an earlier unacknowledged attempt is reported when the next probe finds it booted": {
			client: &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{
				{status: fvcore.StatusUnknown, err: fvcore.ErrUnlockOutcomeUnknown},
				{status: fvcore.StatusUnlockedRecently},
			}},
			opts:        unlockRetryOptions{maxAttempts: 2},
			wantOutcome: unlockOutcomeUnlocked,
			wantSubmits: 2,
			wantOutput:  []string{"VERIFIED: mac is booted after an earlier unlock attempt"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			store := &staticStore{pw: "correct horse battery staple"}
			result, err := unlockDeviceWithRetry(context.Background(), &output, tt.client, store, device, "mac", tt.opts)
			if tt.wantFatal != nil {
				if !errors.Is(err, tt.wantFatal) {
					t.Fatalf("fatal error = %v, want %v", err, tt.wantFatal)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected fatal error: %v", err)
				}
				if result.outcome != tt.wantOutcome {
					t.Fatalf("outcome = %v, want %v", result.outcome, tt.wantOutcome)
				}
			}
			if len(tt.client.passwords) != tt.wantSubmits {
				t.Fatalf("password submissions = %d, want %d", len(tt.client.passwords), tt.wantSubmits)
			}
			for _, password := range tt.client.passwords {
				if password != "correct horse battery staple" {
					t.Fatalf("submitted unexpected credential %q", password)
				}
			}
			for _, phrase := range tt.wantOutput {
				if !strings.Contains(output.String(), phrase) {
					t.Errorf("output is missing %q:\n%s", phrase, output.String())
				}
			}
			for _, phrase := range tt.wantNotOutput {
				if strings.Contains(output.String(), phrase) {
					t.Errorf("output unexpectedly contains %q:\n%s", phrase, output.String())
				}
			}
		})
	}
}

func TestUnlockDeviceWithRetryStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: errors.New("dial failed")}}}
	_, err := unlockDeviceWithRetry(ctx, io.Discard, client, &staticStore{pw: "secret"},
		config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}, "mac",
		unlockRetryOptions{maxAttempts: 5, retryDelay: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled unlock = %v, want context.Canceled", err)
	}
}

func TestUnlockDeviceWithRetryPropagatesContextOnTheFinalAttempt(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
		"cancelled": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		},
		"deadline exceeded": func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := makeContext()
			defer cancel()
			client := &fakeUnlockClient{unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: errors.New("dial failed")}}}
			_, err := unlockDeviceWithRetry(ctx, io.Discard, client, &staticStore{pw: "secret"}, device, "mac",
				unlockRetryOptions{maxAttempts: 1})
			if !errors.Is(err, ctx.Err()) {
				t.Fatalf("final attempt returned %v, want %v", err, ctx.Err())
			}
		})
	}
}

func TestUnlockDeviceWithRetryNeverResubmitsAfterAnUnacknowledgedAttempt(t *testing.T) {
	// The one-attempt marker is the core fail-closed property: an ambiguous
	// post-submission outcome must never cause the password to be sent again
	// within the same attempt, only on a deliberate later retry.
	client := &fakeUnlockClient{
		unlockResponses: []fakeUnlockResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrUnlockOutcomeUnknown}},
		verifyResponses: []fakeVerifyResponse{{status: fvcore.StatusUnknown, err: fvcore.ErrIndeterminate}},
	}
	var output bytes.Buffer
	result, err := unlockDeviceWithRetry(context.Background(), &output, client, &staticStore{pw: "secret"},
		config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}, "mac",
		unlockRetryOptions{maxAttempts: 1, verifyWindow: 500 * time.Millisecond})
	if err != nil || result.outcome != unlockOutcomeExhausted {
		t.Fatalf("ambiguous outcome = %v, %v; want exhausted", result.outcome, err)
	}
	if len(client.passwords) != 1 {
		t.Fatalf("password submitted %d times, want exactly 1", len(client.passwords))
	}
	if client.verifyCalls == 0 {
		t.Fatal("expected a password-free verification probe after the unacknowledged submission")
	}
}

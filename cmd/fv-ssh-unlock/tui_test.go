// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
)

type tuiRoundTripFunc func(*http.Request) (*http.Response, error)

func (f tuiRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func tuiJSONResponse(status int, value any) *http.Response {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(encoded)),
	}
}

func tuiKeys(lines ...string) <-chan byte {
	count := len(lines)
	for _, line := range lines {
		count += len(line)
	}
	keys := make(chan byte, count)
	for _, line := range lines {
		for index := range len(line) {
			keys <- line[index]
		}
		keys <- '\n'
	}
	return keys
}

func TestCandidateDisplayDefaults(t *testing.T) {
	candidate := candidates.Candidate{
		Names:     []string{"Editing Mac Studio"},
		Endpoints: []candidates.Endpoint{{Address: "192.0.2.40", Port: 22}},
	}
	if got := candidateDefaultName(candidate); got != "editing-mac-studio" {
		t.Fatalf("default name = %q", got)
	}
	host, port := candidateDefaultEndpoint(candidate)
	if host != "192.0.2.40" || port != 22 {
		t.Fatalf("default endpoint = %s:%d", host, port)
	}
	if got := candidateLocation(candidate); got != "192.0.2.40:22" {
		t.Fatalf("location = %q", got)
	}
}

func TestRelativeTime(t *testing.T) {
	if got := relativeTime(time.Time{}); got != "never" {
		t.Fatalf("zero relative time = %q", got)
	}
}

func TestCandidateHostKeyPathUsesDiscoveredKeyType(t *testing.T) {
	for keyType, want := range map[string]string{
		"ssh-ed25519":         "/etc/ssh/ssh_host_ed25519_key.pub",
		"ssh-rsa":             "/etc/ssh/ssh_host_rsa_key.pub",
		"rsa-sha2-512":        "/etc/ssh/ssh_host_rsa_key.pub",
		"ecdsa-sha2-nistp256": "/etc/ssh/ssh_host_ecdsa_key.pub",
	} {
		if got := candidateHostKeyPath(keyType); got != want {
			t.Errorf("candidateHostKeyPath(%q) = %q, want %q", keyType, got, want)
		}
	}
}

func TestFetchDashboardValidatesBothVersionedResponses(t *testing.T) {
	devices := devicesAPIResponse{
		SchemaVersion: controlAPISchemaVersion,
		ProbeTimeout:  17 * time.Second,
		UnlockTimeout: 29 * time.Second,
		Snapshot: monitor.Snapshot{Devices: []monitor.DeviceSnapshot{{
			Device: monitor.Device{Name: "mac"},
		}}},
	}
	candidateSnapshot := candidatesAPIResponse{
		SchemaVersion: controlAPISchemaVersion,
		Snapshot: candidates.Snapshot{Candidates: []candidates.Candidate{{
			ID: "candidate-1",
		}}},
	}
	requests := 0
	client := &http.Client{Transport: tuiRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			t.Errorf("dashboard request deadline = %v, present=%t", deadline, ok)
		}
		switch request.URL.Path {
		case "/v1/devices":
			return tuiJSONResponse(http.StatusOK, devices), nil
		case "/v1/candidates":
			return tuiJSONResponse(http.StatusOK, candidateSnapshot), nil
		default:
			return tuiJSONResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
	})}

	got, err := fetchDashboard(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || got.Devices.ProbeTimeout != 17*time.Second || got.Devices.UnlockTimeout != 29*time.Second ||
		len(got.Devices.Devices) != 1 || len(got.Candidates.Candidates) != 1 {
		t.Fatalf("dashboard = %+v after %d requests", got, requests)
	}

	for name, versions := range map[string][2]int{
		"device schema":    {99, controlAPISchemaVersion},
		"candidate schema": {controlAPISchemaVersion, 99},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: tuiRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/v1/devices" {
					value := devices
					value.SchemaVersion = versions[0]
					return tuiJSONResponse(http.StatusOK, value), nil
				}
				value := candidateSnapshot
				value.SchemaVersion = versions[1]
				return tuiJSONResponse(http.StatusOK, value), nil
			})}
			if _, err := fetchDashboard(context.Background(), client); err == nil || !strings.Contains(err.Error(), "unsupported daemon API schema 99") {
				t.Fatalf("schema mismatch = %v", err)
			}
		})
	}
}

func TestEnrollCandidateFromTUISendsVerifiedDefaultsAndOperationDeadline(t *testing.T) {
	fingerprint := "SHA256:independently-verified"
	candidate := candidates.Candidate{
		ID:          "candidate/one",
		Fingerprint: fingerprint,
		KeyType:     "ssh-ed25519",
		Names:       []string{"Editing Mac"},
		Endpoints:   []candidates.Endpoint{{Address: "192.0.2.40", Port: 2222}},
	}
	var request enrollCandidateRequest
	client := &http.Client{Transport: tuiRoundTripFunc(func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.Method != http.MethodPost || httpRequest.URL.EscapedPath() != "/v1/candidates/candidate%2Fone/enroll" {
			t.Fatalf("enrollment request = %s %s", httpRequest.Method, httpRequest.URL.EscapedPath())
		}
		deadline, ok := httpRequest.Context().Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 60*time.Second || remaining > controlEnrollmentTimeout(60*time.Second) {
			t.Fatalf("enrollment deadline remaining = %v, present=%t", remaining, ok)
		}
		if err := json.NewDecoder(httpRequest.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		return tuiJSONResponse(http.StatusCreated, struct {
			SchemaVersion int                  `json:"schema_version"`
			Device        config.Device        `json:"device"`
			Candidate     candidates.Candidate `json:"candidate"`
		}{controlAPISchemaVersion, config.Device{
			Name: request.Name, Host: request.Host, User: request.User, Port: request.Port,
			CredentialSource: request.CredentialSource, CredentialRef: request.CredentialRef, AutoUnlock: request.AutoUnlock,
		}, candidate}), nil
	})}
	keys := tuiKeys(
		"1", fingerprint, "", "", "", "admin", "yes", "", "/run/secrets/editing-mac",
	)
	var output bytes.Buffer
	message := enrollCandidateFromTUI(context.Background(), &output, keys, client,
		candidates.Snapshot{Candidates: []candidates.Candidate{candidate}}, 60*time.Second)
	if message != "Added editing-mac; monitoring starts immediately." {
		t.Fatalf("enrollment message = %q", message)
	}
	if request.Name != "editing-mac" || request.Host != "192.0.2.40" || request.Port != 2222 || request.User != "admin" ||
		!request.AutoUnlock || request.CredentialSource != "file" || request.CredentialRef != "/run/secrets/editing-mac" || request.Fingerprint != fingerprint {
		t.Fatalf("enrollment request = %+v", request)
	}
	if !strings.Contains(output.String(), "/etc/ssh/ssh_host_ed25519_key.pub") || !strings.Contains(output.String(), fingerprint) {
		t.Fatalf("verification instructions missing from %q", output.String())
	}
}

func TestTUIActionsUseExpectedRoutesAndPollBudget(t *testing.T) {
	candidateSnapshot := candidates.Snapshot{Candidates: []candidates.Candidate{{
		ID: "candidate/one", Fingerprint: "SHA256:012345678901234567890123456789", State: candidates.StateDiscovered,
	}}}
	deviceSnapshot := monitor.Snapshot{Devices: []monitor.DeviceSnapshot{{
		Device:       monitor.Device{Name: "editing/mac"},
		DeviceRecord: monitor.DeviceRecord{State: monitor.StateLocked},
	}}}
	var routes []string
	client := &http.Client{Transport: tuiRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		routes = append(routes, request.Method+" "+request.URL.EscapedPath())
		switch request.URL.EscapedPath() {
		case "/v1/candidates/candidate%2Fone/ignore":
			return tuiJSONResponse(http.StatusOK, candidates.Candidate{Fingerprint: candidateSnapshot.Candidates[0].Fingerprint, State: candidates.StateIgnored}), nil
		case "/v1/devices/editing%2Fmac/poll":
			deadline, ok := request.Context().Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 90*time.Second || remaining > controlPollTimeout(30*time.Second, 60*time.Second) {
				t.Fatalf("poll deadline remaining = %v, present=%t", remaining, ok)
			}
			return tuiJSONResponse(http.StatusOK, struct {
				SchemaVersion int                    `json:"schema_version"`
				Device        monitor.DeviceSnapshot `json:"device"`
				Error         string                 `json:"error,omitempty"`
			}{controlAPISchemaVersion, deviceSnapshot.Devices[0], "dial failed"}), nil
		case "/v1/devices/editing%2Fmac/clear-latch":
			return tuiJSONResponse(http.StatusOK, map[string]any{"schema_version": controlAPISchemaVersion, "changed": true}), nil
		default:
			return nil, errors.New("unexpected route")
		}
	})}

	if got := candidateActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), client, candidateSnapshot, "ignore"); !strings.Contains(got, "is now ignored") {
		t.Fatalf("ignore message = %q", got)
	}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), client, deviceSnapshot, "poll", 30*time.Second, 60*time.Second); got != "Poll completed for editing/mac: locked (dial failed)." {
		t.Fatalf("poll message = %q", got)
	}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), client, deviceSnapshot, "clear-latch", 30*time.Second, 60*time.Second); got != "clear-latch completed for editing/mac." {
		t.Fatalf("clear-latch message = %q", got)
	}
	wantRoutes := []string{
		"POST /v1/candidates/candidate%2Fone/ignore",
		"POST /v1/devices/editing%2Fmac/poll",
		"POST /v1/devices/editing%2Fmac/clear-latch",
	}
	if strings.Join(routes, "\n") != strings.Join(wantRoutes, "\n") {
		t.Fatalf("routes = %q, want %q", routes, wantRoutes)
	}
}

func TestTUIActionValidationFailsBeforeMakingARequest(t *testing.T) {
	client := &http.Client{Transport: tuiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("validation failure made an HTTP request")
		return nil, nil
	})}
	if got := enrollCandidateFromTUI(context.Background(), io.Discard, tuiKeys(), client, candidates.Snapshot{}, 0); got != "No discovered candidates to add." {
		t.Fatalf("empty enrollment = %q", got)
	}
	ignored := candidates.Snapshot{Candidates: []candidates.Candidate{{State: candidates.StateIgnored}}}
	if got := enrollCandidateFromTUI(context.Background(), io.Discard, tuiKeys("1"), client, ignored, 0); !strings.Contains(got, "ignored") {
		t.Fatalf("ignored enrollment = %q", got)
	}
	configured := candidates.Snapshot{Candidates: []candidates.Candidate{{ConfiguredNames: []string{"mac"}}}}
	if got := candidateActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), client, configured, "ignore"); !strings.Contains(got, "already managed") {
		t.Fatalf("managed ignore = %q", got)
	}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys(), client, monitor.Snapshot{}, "poll", 0, 0); got != "No managed devices available." {
		t.Fatalf("empty device action = %q", got)
	}
	if got := candidateActionFromTUI(context.Background(), io.Discard, tuiKeys("99"), client,
		candidates.Snapshot{Candidates: []candidates.Candidate{{ID: "one"}}}, "ignore"); !strings.Contains(got, "outside the displayed range") {
		t.Fatalf("invalid selection = %q", got)
	}
}

func TestEnrollCandidateFromTUIRejectsUnsafeOrIncompleteInputLocally(t *testing.T) {
	client := &http.Client{Transport: tuiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid enrollment made an HTTP request")
		return nil, nil
	})}
	const fingerprint = "SHA256:verified"
	base := candidates.Candidate{
		ID: "one", Fingerprint: fingerprint, Names: []string{"Mac"},
		Endpoints: []candidates.Endpoint{{Address: "192.0.2.1", Port: 22}},
	}
	tests := map[string]struct {
		candidate candidates.Candidate
		keys      []string
		want      string
	}{
		"already configured": {
			candidate: candidates.Candidate{ID: "one", ConfiguredNames: []string{"managed-mac"}},
			keys:      []string{"1"}, want: "already managed",
		},
		"fingerprint pending": {
			candidate: candidates.Candidate{ID: "one"}, keys: []string{"1"}, want: "no SSH fingerprint",
		},
		"fingerprint mismatch": {
			candidate: base, keys: []string{"1", "SHA256:different"}, want: "Fingerprint did not match",
		},
		"invalid port": {
			candidate: base, keys: []string{"1", fingerprint, "", "", "not-a-port"}, want: "Invalid SSH port",
		},
		"missing username": {
			candidate: base, keys: []string{"1", fingerprint, "", "", "", ""}, want: "username is required",
		},
		"keyring cannot be provisioned": {
			candidate: base, keys: []string{"1", fingerprint, "", "", "", "admin", "no", "keyring"}, want: "cannot create a keyring credential",
		},
		"runtime cannot auto unlock": {
			candidate: base, keys: []string{"1", fingerprint, "", "", "", "admin", "yes", "runtime"}, want: "cannot enable unattended",
		},
		"file provider requires reference": {
			candidate: base, keys: []string{"1", fingerprint, "", "", "", "admin", "yes", "file", ""}, want: "credential reference is required",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := enrollCandidateFromTUI(context.Background(), io.Discard, tuiKeys(test.keys...), client,
				candidates.Snapshot{Candidates: []candidates.Candidate{test.candidate}}, 0)
			if !strings.Contains(got, test.want) {
				t.Fatalf("message = %q, want it to contain %q", got, test.want)
			}
		})
	}
}

func TestTUIActionsReportTransportAndSchemaFailures(t *testing.T) {
	candidatesSnapshot := candidates.Snapshot{Candidates: []candidates.Candidate{{ID: "one"}}}
	devicesSnapshot := monitor.Snapshot{Devices: []monitor.DeviceSnapshot{{Device: monitor.Device{Name: "mac"}}}}
	failing := &http.Client{Transport: tuiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("daemon unavailable")
	})}
	if got := candidateActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), failing, candidatesSnapshot, "restore"); !strings.HasPrefix(got, "restore failed: ") || !strings.Contains(got, "daemon unavailable") {
		t.Fatalf("candidate failure = %q", got)
	}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), failing, devicesSnapshot, "clear-latch", 0, 0); !strings.HasPrefix(got, "clear-latch failed: ") || !strings.Contains(got, "daemon unavailable") {
		t.Fatalf("device failure = %q", got)
	}

	wrongSchema := &http.Client{Transport: tuiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return tuiJSONResponse(http.StatusOK, struct {
			SchemaVersion int                    `json:"schema_version"`
			Device        monitor.DeviceSnapshot `json:"device"`
		}{99, devicesSnapshot.Devices[0]}), nil
	})}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), wrongSchema, devicesSnapshot, "poll", 0, 0); got != "poll failed: unsupported daemon API schema 99" {
		t.Fatalf("poll schema failure = %q", got)
	}
	wrongClearSchema := &http.Client{Transport: tuiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return tuiJSONResponse(http.StatusOK, map[string]any{"schema_version": 99, "changed": true}), nil
	})}
	if got := deviceActionFromTUI(context.Background(), io.Discard, tuiKeys("1"), wrongClearSchema, devicesSnapshot, "clear-latch", 0, 0); got != "clear-latch failed: unsupported daemon API schema 99" {
		t.Fatalf("clear-latch schema failure = %q", got)
	}
}

func TestTUICommandAndInteractiveModeValidation(t *testing.T) {
	for name, args := range map[string][]string{
		"relative socket": {"--socket", "relative.sock", "--once"},
		"zero refresh":    {"--socket", "/tmp/fv-ssh-unlock-test.sock", "--refresh", "0s", "--once"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newTUICommand()
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid TUI flags were accepted")
			}
		})
	}
	if err := runInteractiveTUI(context.Background(), strings.NewReader("q"), io.Discard, &http.Client{}, time.Second); err == nil || !strings.Contains(err.Error(), "requires a terminal") {
		t.Fatalf("non-terminal interactive mode = %v", err)
	}
}

func TestTUICommandOnceAndJSONUseTheVersionedDashboard(t *testing.T) {
	devices := devicesAPIResponse{
		SchemaVersion: controlAPISchemaVersion,
		ProbeTimeout:  2 * time.Second,
		UnlockTimeout: 3 * time.Second,
		Snapshot: monitor.Snapshot{Devices: []monitor.DeviceSnapshot{{
			Device:       monitor.Device{Name: "mac", AutoUnlock: true},
			DeviceRecord: monitor.DeviceRecord{State: monitor.StateBooted, LastCheckedAt: time.Now()},
		}}},
	}
	candidateSnapshot := candidatesAPIResponse{
		SchemaVersion: controlAPISchemaVersion,
		Snapshot: candidates.Snapshot{Candidates: []candidates.Candidate{{
			ID: "candidate-one", State: candidates.StateDiscovered, Hostnames: []string{"new-mac.local"}, LastSeen: time.Now(),
		}}},
	}
	path := startCommandControlServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(devices)
		case "/v1/candidates":
			_ = json.NewEncoder(w).Encode(candidateSnapshot)
		default:
			http.NotFound(w, request)
		}
	}))

	for _, test := range []struct {
		flag string
		want string
	}{
		{flag: "--once", want: "1 managed Mac(s)"},
		{flag: "--json", want: `"probe_timeout":2000000000`},
	} {
		cmd := newTUICommand()
		cmd.SetArgs([]string{"--socket", path, test.flag})
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), test.want) {
			t.Fatalf("%s output = %q, want %q", test.flag, output.String(), test.want)
		}
	}
}

// hostile is a candidate-supplied string carrying terminal control sequences.
// internal/candidates strips these at ingestion; this package sanitizes again at
// every print site so the guarantee does not rest on another package's rules.
const hostile = "mac\x1b[2Kevil\r\nSUCCESS: forged"

func TestRenderDashboardEscapesNetworkDerivedText(t *testing.T) {
	snapshot := dashboardSnapshot{}
	snapshot.Devices.Devices = []monitor.DeviceSnapshot{{
		Device:       monitor.Device{Name: hostile},
		DeviceRecord: monitor.DeviceRecord{State: monitor.State(hostile)},
	}}
	snapshot.Devices.Events = []monitor.Event{{Device: hostile, State: monitor.State(hostile), Message: hostile, Time: time.Now()}}
	snapshot.Candidates.Candidates = []candidates.Candidate{{
		ID:        "cand_1",
		State:     candidates.State(hostile),
		Hostnames: []string{hostile},
	}}

	var output bytes.Buffer
	if err := renderDashboard(&output, snapshot, false, hostile); err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, output.String())
}

func TestCandidatePromptDefaultsAreEscaped(t *testing.T) {
	var output bytes.Buffer
	keys := make(chan byte, 1)
	keys <- '\r'
	value, err := promptRawLineDefault(&output, keys, "Local alias", hostile)
	if err != nil {
		t.Fatal(err)
	}
	// The raw value is still what the operator accepts; only the display is
	// sanitized.
	if value != hostile {
		t.Fatalf("accepted default = %q, want the raw candidate value", value)
	}
	assertTerminalSafe(t, output.String())
}

// assertTerminalSafe fails when rendered output carries a raw control sequence
// that a hostile candidate could use to forge or erase terminal text. The
// renderer emits its own CR/LF and cursor toggles, so those fixed sequences are
// removed before the check.
func assertTerminalSafe(t *testing.T, rendered string) {
	t.Helper()
	if !strings.Contains(rendered, `\u001B`) {
		t.Fatalf("escape sequence was not rendered in escaped form:\n%q", rendered)
	}
	stripped := rendered
	for _, own := range []string{"\x1b[?25h", "\x1b[?25l", "\x1b[H\x1b[2J", "\r\n"} {
		stripped = strings.ReplaceAll(stripped, own, " ")
	}
	for _, forbidden := range []string{"\x1b", "\r"} {
		if strings.Contains(stripped, forbidden) {
			t.Fatalf("output carries unescaped %q:\n%q", forbidden, rendered)
		}
	}
}

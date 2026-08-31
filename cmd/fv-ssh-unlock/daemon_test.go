// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

type fakeDaemonSSH struct {
	probeStatus fvcore.DeviceStatus
	probeErr    error
	unlockState fvcore.DeviceStatus
	unlockErr   error
	password    string
	probeCalls  int
}

func (f *fakeDaemonSSH) ProbeStatus(context.Context, string, string) (fvcore.DeviceStatus, string, error) {
	f.probeCalls++
	return f.probeStatus, "sensitive banner must not be retained", f.probeErr
}

func TestDaemonAdapterUsesTCPPreflightOnlyAfterEndpointFailure(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, AutoUnlock: true, CredentialSource: credentials.ProviderKeyring}
	client := &fakeDaemonSSH{probeErr: context.DeadlineExceeded}
	adapter := newDaemonAdapter(client, []config.Device{device})
	checks := 0
	adapter.reachability = func(context.Context, string) error {
		checks++
		return errors.New("endpoint down")
	}

	result, err := adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureUnreachable || !result.EndpointDown || client.probeCalls != 1 || checks != 1 {
		t.Fatalf("initial failed probe = %+v, %v; SSH calls=%d TCP checks=%d", result, err, client.probeCalls, checks)
	}
	result, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureUnreachable || !result.EndpointDown || client.probeCalls != 1 || checks != 2 {
		t.Fatalf("endpoint-down preflight = %+v, %v; SSH calls=%d TCP checks=%d", result, err, client.probeCalls, checks)
	}
}

func TestDaemonLoggingOptionsAndStructuredEvent(t *testing.T) {
	cmd := newDaemonCommand()
	if err := cmd.ParseFlags([]string{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-format", "json", "--log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	opts, err := daemonOptionsFromFlags(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if opts.logFormat != "json" || opts.logLevel != slog.LevelDebug {
		t.Fatalf("logging options = %q, %v", opts.logFormat, opts.logLevel)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})).With(
		"schema_version", daemonLogSchemaVersion,
		"component", "daemon",
	)
	events := make(chan monitor.Event, 1)
	events <- monitor.Event{
		Sequence: 7, Type: monitor.EventStateChanged, Device: "mac", State: monitor.StateLocked,
		Observation: monitor.StateLocked, LockEpisode: 2, AutoUnlock: true, Message: "FileVault pre-boot banner detected",
	}
	close(events)
	logMonitorEvents(logger, events)
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"event": "device.filevault_locked", "device": "mac", "state": "locked",
		"observation": "locked", "auto_unlock": true, "schema_version": float64(daemonLogSchemaVersion),
	} {
		if got := entry[key]; got != want {
			t.Fatalf("structured log %s = %#v, want %#v; entry=%v", key, got, want, entry)
		}
	}
}

func TestDaemonStructuredLogEscapesUntrustedLineBreaks(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	events := make(chan monitor.Event, 1)
	events <- monitor.Event{
		Sequence: 1,
		Type:     monitor.EventUnlockResult,
		Device:   "mac\r\nevent=forged",
		State:    monitor.StateError,
		Message:  "dial failed\nlevel=INFO event=device.booted",
	}
	close(events)
	logMonitorEvents(logger, events)

	if got := bytes.Count(output.Bytes(), []byte{'\n'}); got != 1 {
		t.Fatalf("structured logger emitted %d physical records, want 1: %q", got, output.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if got, want := entry["device"], `mac\u000D\u000Aevent=forged`; got != want {
		t.Fatalf("device = %#v, want %#v", got, want)
	}
	if got, want := entry["detail"], `dial failed\u000Alevel=INFO event=device.booted`; got != want {
		t.Fatalf("detail = %#v, want %#v", got, want)
	}
}

func TestCandidateLogEscapesUntrustedLineBreaks(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logCandidateResults(logger, "scan\r\nlevel=ERROR", []candidates.IngestResult{{
		Created: true,
		Candidate: candidates.Candidate{
			ID:        "cand_safe\nevent=forged",
			State:     candidates.StateDiscovered,
			Hostnames: []string{"mac.local\r\nmsg=forged"},
		},
	}})

	if got := bytes.Count(output.Bytes(), []byte{'\n'}); got != 1 {
		t.Fatalf("candidate logger emitted %d physical records, want 1: %q", got, output.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"candidate_id": `cand_safe\u000Aevent=forged`,
		"source":       `scan\u000D\u000Alevel=ERROR`,
		"hostname":     `mac.local\u000D\u000Amsg=forged`,
	} {
		if got := entry[field]; got != want {
			t.Fatalf("%s = %#v, want %#v", field, got, want)
		}
	}
}

func TestDaemonLoggingOptionsRejectInvalidValues(t *testing.T) {
	for _, flags := range [][]string{
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-format", "xml"},
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--log-level", "trace"},
		{"--socket", filepath.Join(t.TempDir(), "control.sock"), "--json-log", "--log-format", "text"},
	} {
		cmd := newDaemonCommand()
		if err := cmd.ParseFlags(flags); err != nil {
			t.Fatal(err)
		}
		if _, err := daemonOptionsFromFlags(cmd); err == nil {
			t.Fatalf("flags %v unexpectedly accepted", flags)
		}
	}
}

func (f *fakeDaemonSSH) AnalyzePrompt(_ context.Context, _, _, password, _ string) (fvcore.DeviceStatus, string, error) {
	f.password = password
	return f.unlockState, "sensitive banner must not be retained", f.unlockErr
}

func TestDaemonAdapterProbeClassification(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	client := &fakeDaemonSSH{probeStatus: fvcore.StatusLocked}
	adapter := newDaemonAdapter(client, []config.Device{device})
	result, err := adapter.Probe(context.Background(), toMonitorDevice(device))
	if err != nil || result.State != monitor.StateLocked || strings.Contains(result.Detail, "sensitive") {
		t.Fatalf("locked probe = %+v, %v", result, err)
	}
	client.probeStatus = fvcore.StatusUnknown
	client.probeErr = fvcore.ErrIndeterminate
	result, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if err != nil || result.State != monitor.StateIndeterminate {
		t.Fatalf("indeterminate probe = %+v, %v", result, err)
	}
	client.probeErr = fvcore.ErrHostKeyMismatch
	_, err = adapter.Probe(context.Background(), toMonitorDevice(device))
	if monitor.FailureKindOf(err) != monitor.FailureHostKey {
		t.Fatalf("host key error classification = %v", err)
	}
}

func TestDaemonAdapterUnlockReadsCredentialJustInTime(t *testing.T) {
	device := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	t.Setenv(credentials.EnvName(credentials.ID(device.Name)), "correct horse battery staple")
	client := &fakeDaemonSSH{unlockState: fvcore.StatusUnlocked}
	adapter := newDaemonAdapter(client, []config.Device{device})
	result, err := adapter.Unlock(context.Background(), toMonitorDevice(device))
	if err != nil || !result.Accepted {
		t.Fatalf("unlock = %+v, %v", result, err)
	}
	if client.password != "correct horse battery staple" {
		t.Fatal("adapter did not retrieve the scoped credential")
	}
	if strings.Contains(result.Detail, client.password) {
		t.Fatal("result leaked credential")
	}

	client.unlockState = fvcore.StatusUnknown
	client.unlockErr = fvcore.ErrUnlockOutcomeUnknown
	result, err = adapter.Unlock(context.Background(), toMonitorDevice(device))
	if !result.Accepted || !errors.Is(err, fvcore.ErrUnlockOutcomeUnknown) {
		t.Fatalf("ambiguous submitted result = %+v, %v", result, err)
	}

	client.unlockState = fvcore.StatusLocked
	client.unlockErr = fvcore.ErrAuthFailed
	result, err = adapter.Unlock(context.Background(), toMonitorDevice(device))
	if result.Accepted || monitor.FailureKindOf(err) != monitor.FailureCredential {
		t.Fatalf("wrong credential result = %+v, %v", result, err)
	}
}

func TestAssessDaemonDeviceFailsClosed(t *testing.T) {
	manual := config.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22, CredentialSource: credentials.ProviderRuntime}
	if err := assessDaemonDevice(manual); err != nil {
		t.Fatalf("manual device should not require unattended credential: %v", err)
	}
	manual.AutoUnlock = true
	if err := assessDaemonDevice(manual); err == nil || !strings.Contains(err.Error(), "runtime/environment") {
		t.Fatalf("runtime auto-unlock should fail: %v", err)
	}
	diskSecret := filepath.Join(t.TempDir(), "password")
	if err := osWritePrivateForTest(diskSecret, "secret"); err != nil {
		t.Fatal(err)
	}
	manual.CredentialSource = credentials.ProviderFile
	manual.CredentialRef = diskSecret
	if err := assessDaemonDevice(manual); err == nil || !strings.Contains(err.Error(), "secure credential") {
		t.Fatalf("disk secret should fail: %v", err)
	}
}

func osWritePrivateForTest(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o600)
}

func TestDaemonLockExcludesConcurrentController(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	first, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if second, err := acquireDaemonLock(path); err == nil {
		releaseDaemonLock(second)
		releaseDaemonLock(first)
		t.Fatal("second controller acquired the same data-directory lock")
	}
	releaseDaemonLock(first)
	third, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	releaseDaemonLock(third)
}

type apiProbe struct{}

func (apiProbe) Probe(context.Context, monitor.Device) (monitor.ProbeResult, error) {
	return monitor.ProbeResult{State: monitor.StateBooted, Detail: "verified"}, nil
}

func TestDaemonAPILocalReadAndMutationRoutes(t *testing.T) {
	device := monitor.Device{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}
	engine, err := monitor.New([]monitor.Device{device}, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.2", Port: 22, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{
		startedAt: time.Now(), engine: engine, inbox: inbox,
		store:  &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := api.routes()

	for _, endpoint := range []string{"/v1/health", "/v1/devices", "/v1/candidates"} {
		request := httptest.NewRequest(http.MethodGet, endpoint, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"schema_version":1`) {
			t.Fatalf("GET %s = %d, %q, headers=%v", endpoint, response.Code, response.Body.String(), response.Header())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/ignore", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"ignored"`) {
		t.Fatalf("ignore = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/devices/mac/poll", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"booted"`) {
		t.Fatalf("poll = %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentRejectsNetworkFingerprintAsConfirmation(t *testing.T) {
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(privateDaemonTestDir(t), "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	inbox := candidates.New(candidates.Options{})
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ingested, err := inbox.Ingest(candidates.Observation{Source: "test", Address: "192.0.2.2", Port: 22, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	api := &daemonAPI{engine: engine, inbox: inbox, store: &config.Store{Path: filepath.Join(privateDaemonTestDir(t), "devices.json")}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{"name":"mac","host":"192.0.2.2","user":"user","port":22,"fingerprint":"SHA256:not-the-observed-key","credential_source":"runtime","auto_unlock":false}`
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "independently verified") {
		t.Fatalf("enroll mismatch = %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentPinsExpectedKeyAndAddsMonitorDevice(t *testing.T) {
	dataDir := privateDaemonTestDir(t)
	oldDataDir := dataDirOverride
	dataDirOverride = dataDir
	t.Cleanup(func() { dataDirOverride = oldDataDir })

	address, port, hostKey, _ := startScanTestServer(t, "")
	fingerprint := ssh.FingerprintSHA256(hostKey.PublicKey())
	inbox := candidates.New(candidates.Options{})
	ingested, err := inbox.Ingest(candidates.Observation{Source: "active-scan", Address: address.String(), Port: port, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := monitor.New(nil, apiProbe{}, nil,
		&monitor.FileStore{Path: filepath.Join(dataDir, "state.json")}, monitor.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := &config.Store{Path: filepath.Join(dataDir, "devices.json")}
	adapter := newDaemonAdapter(&fakeDaemonSSH{}, nil)
	api := &daemonAPI{engine: engine, inbox: inbox, store: store, adapter: adapter, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := fmt.Sprintf(`{"name":"new-mac","host":%q,"user":"user","port":%d,"fingerprint":%q,"credential_source":"runtime","auto_unlock":false}`,
		address.String(), port, fingerprint)
	request := httptest.NewRequest(http.MethodPost, "/v1/candidates/"+ingested.Candidate.ID+"/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", response.Code, response.Body.String())
	}
	configured, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 1 || configured[0].Name != "new-mac" {
		t.Fatalf("configured devices = %+v", configured)
	}
	if snapshots := engine.Snapshot().Devices; len(snapshots) != 1 || snapshots[0].Name != "new-mac" {
		t.Fatalf("monitor devices = %+v", snapshots)
	}
	knownHosts, err := os.ReadFile(filepath.Join(dataDir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(knownHosts) == 0 {
		t.Fatal("expected host key to be pinned")
	}
}

func privateDaemonTestDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

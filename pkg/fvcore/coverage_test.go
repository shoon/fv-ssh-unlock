// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type statusCheckerFunc func(context.Context, string, string) (DeviceStatus, string, error)

func (f statusCheckerFunc) ProbeStatus(ctx context.Context, host, user string) (DeviceStatus, string, error) {
	return f(ctx, host, user)
}

type deadlineClient struct{}

func (deadlineClient) AnalyzePrompt(ctx context.Context, _, _, _, _ string) (DeviceStatus, string, error) {
	<-ctx.Done()
	return StatusUnknown, "partial banner", nil
}

type pastDeadlineContext struct{ context.Context }

func (pastDeadlineContext) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }
func (pastDeadlineContext) Err() error                  { return nil }

func TestUnlockMapsSilentDeadlineAfterPrompt(t *testing.T) {
	result := Unlock(context.Background(), deadlineClient{}, &mockStore{pw: "secret"},
		"host", "user", "credential", "", 10*time.Millisecond)
	if !errors.Is(result.Error, context.DeadlineExceeded) || result.Status != StatusUnknown {
		t.Fatalf("result = %+v, want unknown deadline", result)
	}
	if result.Output != "partial banner" {
		t.Fatalf("output = %q, want preserved partial banner", result.Output)
	}
}

func TestEffectiveContextErrorUsesExpiredDeadline(t *testing.T) {
	if err := effectiveContextError(pastDeadlineContext{Context: context.Background()}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("effectiveContextError = %v, want deadline exceeded", err)
	}
}

func TestDefaultVerifyOptionsAreOperational(t *testing.T) {
	opts := DefaultVerifyOptions()
	if opts.Grace != 10*time.Second || opts.Window != 5*time.Minute ||
		opts.Interval != 10*time.Second || opts.AttemptTimeout != 20*time.Second {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
}

func TestVerifyUnlockRejectsInvalidTiming(t *testing.T) {
	base := fastVerifyOpts()
	tests := map[string]VerifyOptions{
		"zero attempt timeout": {Window: base.Window, Interval: base.Interval},
		"negative interval":    {Window: base.Window, Interval: -time.Millisecond, AttemptTimeout: base.AttemptTimeout},
		"negative grace":       {Grace: -time.Millisecond, Window: base.Window, Interval: base.Interval, AttemptTimeout: base.AttemptTimeout},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyUnlock(context.Background(), &scriptedClient{}, testDevice, opts)
			if ok || err == nil {
				t.Fatalf("VerifyUnlock(%+v) = ok=%v err=%v, want validation error", opts, ok, err)
			}
		})
	}
}

func TestVerifyUnlockWindowCanExpireDuringGrace(t *testing.T) {
	client := &scriptedClient{states: []DeviceStatus{StatusUnlockedRecently}, errs: []error{nil}}
	opts := fastVerifyOpts()
	opts.Grace = time.Second
	opts.Window = 10 * time.Millisecond
	ok, err := VerifyUnlock(context.Background(), client, testDevice, opts)
	if err != nil || ok || client.count() != 0 {
		t.Fatalf("grace-window result ok=%v err=%v calls=%d", ok, err, client.count())
	}
}

func TestVerifyUnlockCancellationDuringGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opts := fastVerifyOpts()
	opts.Grace = time.Second
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	ok, err := VerifyUnlock(ctx, &scriptedClient{}, testDevice, opts)
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("grace cancellation = ok=%v err=%v", ok, err)
	}
}

func TestVerifyUnlockNoticesCancellationFromProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checker := statusCheckerFunc(func(context.Context, string, string) (DeviceStatus, string, error) {
		cancel()
		return StatusUnknown, "", errors.New("probe stopped")
	})
	ok, err := VerifyUnlock(ctx, checker, testDevice, fastVerifyOpts())
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("probe cancellation = ok=%v err=%v", ok, err)
	}
}

func TestAuthTraceRejectsRepeatedPasswordAndRecordsTransition(t *testing.T) {
	signal := make(chan struct{})
	trace := &authTrace{passwordAnsweredSignal: signal}
	if err := trace.recordPasswordPrompt(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signal:
	default:
		t.Fatal("answer signal was not closed")
	}
	if err := trace.recordPasswordPrompt(true); err == nil {
		t.Fatal("repeated password prompt was accepted")
	}
	trace.markTransportTransition()
	if !trace.transportTransitionSeen() {
		t.Fatal("transport transition was not retained")
	}
}

func TestClientConfigStopsOnPostPasswordBanner(t *testing.T) {
	trace := &authTrace{}
	if err := trace.recordPasswordPrompt(true); err != nil {
		t.Fatal(err)
	}
	config := (&RealSSHClient{InsecureIgnoreHostKey: true}).clientConfig("user", "secret", "", true, trace)
	if err := config.BannerCallback(realSuccessBanner); !errors.Is(err, errUnlockSucceeded) {
		t.Fatalf("post-password banner callback error = %v, want unlock sentinel", err)
	}
	_, _, succeeded := trace.state()
	if !succeeded {
		t.Fatal("post-password USERAUTH_BANNER did not record success")
	}
}

func TestUnlockManyCapsWorkersAtDeviceCount(t *testing.T) {
	client := &mockSSHClientForUnlock{status: StatusUnlocked}
	devices := []Device{{Host: "one", User: "user", Cred: "cred"}, {Host: "two", User: "user", Cred: "cred"}}
	results := UnlockMany(context.Background(), client, &mockStore{pw: "secret"}, devices, "", time.Second, 100)
	if len(results) != len(devices) || client.callCount != len(devices) {
		t.Fatalf("results=%d calls=%d, want %d", len(results), client.callCount, len(devices))
	}
}

func TestAnalyzePromptRefusesRepeatedPasswordChallenge(t *testing.T) {
	ts := startTestServer(t, testServerConfig{password: "s3cret", repeatPrompt: true})
	status, _, err := newClient(ts.fixedHostKey()).AnalyzePrompt(context.Background(), ts.addr, "user", "s3cret", "")
	if err == nil || status == StatusUnlocked {
		t.Fatalf("repeated prompt = status=%v err=%v, want fail closed", status, err)
	}
	if !ts.receivedPassword("s3cret") {
		t.Fatal("client did not answer the initial, valid password prompt")
	}
}

func TestProbeStatusTransportErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client := &RealSSHClient{InsecureIgnoreHostKey: true, DialTimeout: 100 * time.Millisecond}
	status, _, err := client.ProbeStatus(context.Background(), address, "user")
	if status != StatusUnknown || !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("refused probe = status=%v err=%v", status, err)
	}

	status, _, err = client.ProbeStatus(context.Background(), "bad::address", "user")
	if status != StatusUnknown || err == nil || errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("malformed probe = status=%v err=%v", status, err)
	}
}

func TestHandshakeClassificationHelpers(t *testing.T) {
	client := &RealSSHClient{}
	if client.dialTimeout() != 15*time.Second {
		t.Fatalf("default dial timeout = %v", client.dialTimeout())
	}
	if client.hostKeyCallback() == nil {
		t.Fatal("fail-closed host-key callback is nil")
	}
	insecure := &RealSSHClient{InsecureIgnoreHostKey: true}
	callback := insecure.hostKeyCallback()
	if callback == nil {
		t.Fatal("explicit insecure host-key callback is nil")
	}
	if err := callback("host", &net.TCPAddr{}, ssh.PublicKey(nil)); err != nil {
		t.Fatalf("explicit insecure callback rejected a key: %v", err)
	}
	status, _, err := client.classifyHandshakeErr("host", "banner", true, true, false, true, errors.New("closed"))
	if status != StatusUnknown || !errors.Is(err, ErrUnlockOutcomeUnknown) {
		t.Fatalf("transition classification = status=%v err=%v", status, err)
	}
	if isHostKeyError(nil) || !isHostKeyError(&knownhosts.KeyError{}) {
		t.Fatal("typed host-key error classification failed")
	}
	if dialError(nil) != nil || dialError(errors.New("other")) != nil {
		t.Fatal("unrecognized dial errors must remain unclassified")
	}
}

func TestWatchSSHServiceTransitionRequiresReachableBaseline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	answered := make(chan struct{})
	close(answered)
	called := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	watchSSHServiceTransition(ctx, address, answered, 5*time.Millisecond, 5*time.Millisecond, func() { called <- struct{}{} })
	select {
	case <-called:
		t.Fatal("unreachable baseline was mistaken for a service transition")
	default:
	}
}

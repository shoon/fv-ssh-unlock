// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Banner discriminators.
//
// These must be chosen carefully, because the LOCKED banner also contains the
// words "successfully" and "unlocked":
//
//	locked:  "This system is locked. To unlock it, use a local
//	          account name and password. Once successfully
//	          unlocked, you will be able to connect normally."
//	success: "System successfully unlocked.
//	          You may now use SSH to authenticate normally."
//
// A naive "successfully unlocked" match would classify the LOCKED banner as a
// success as soon as the line wrapping changed (the two words are adjacent
// there, separated only by a newline). We therefore anchor on "system
// successfully unlocked", which the locked banner cannot produce because that
// phrase is preceded by "Once", not "System". Comparison is done on
// whitespace-normalized text so re-wrapping cannot change the outcome.
const (
	// successPhrase marks a completed unlock.
	successPhrase = "system successfully unlocked"
	// lockedPhrase marks the pre-boot locked banner.
	lockedPhrase = "system is locked"
	// minCustomSuccessLen is the shortest a caller-supplied success message may
	// be before it is ignored, so a trivial value (e.g. "a") cannot be used to
	// forge a successful unlock.
	minCustomSuccessLen = 8
)

// normalizeBanner lowercases text and collapses all whitespace runs to single
// spaces so matching is insensitive to line wrapping and CRLF.
func normalizeBanner(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// RealSSHClient implements SSHClient and StatusChecker using
// golang.org/x/crypto/ssh. It connects to the FileVault pre-boot SSH prompt,
// supplies the unlock password over keyboard-interactive, and classifies the
// result from the decrypted banner/instruction text, never from raw wire bytes.
//
// Detection design (see the transcript in tools/mock-fv-ssh-server):
//   - On a successful unlock the server emits "System successfully unlocked."
//     (as a keyboard-interactive instruction or USERAUTH_BANNER) and then
//     returns an authentication failure and disconnects. There is NO
//     USERAUTH_SUCCESS. We therefore treat the decrypted success banner, not
//     the connection closing, as the positive signal. An EOF or auth failure
//     on its own is never reported as success.
//   - A wrong password yields an auth failure with only the locked banner /
//     password prompt seen -> StatusLocked.
//   - A fully booted machine completes the SSH handshake -> StatusUnlockedRecently.
type RealSSHClient struct {
	// DialTimeout bounds the TCP dial and SSH handshake when no shorter context
	// deadline is set.
	DialTimeout time.Duration
	// Verbose enables progress logging to stdout. It never prints the password.
	Verbose bool
	// HostKeyCallback verifies the server's host key. It should pin the key
	// (e.g. via knownhosts). If nil and InsecureIgnoreHostKey is false, the
	// client refuses to connect (fail closed) rather than trusting any host.
	HostKeyCallback ssh.HostKeyCallback
	// InsecureIgnoreHostKey disables host-key verification. This exposes the
	// FileVault password to a man-in-the-middle and must only be set via an
	// explicit, clearly-labelled user opt-in.
	InsecureIgnoreHostKey bool
	// Signers are optional SSH keys (e.g. from ssh-agent) offered for public-key
	// authentication. A public-key handshake CANNOT succeed at the FileVault
	// pre-boot prompt, because authorized_keys lives on the still-locked data
	// volume; so a successful public-key handshake is definitive proof that the
	// machine has finished booting. No password is ever sent for this method.
	Signers []ssh.Signer
}

func (r *RealSSHClient) dialTimeout() time.Duration {
	if r.DialTimeout > 0 {
		return r.DialTimeout
	}
	return 15 * time.Second
}

func (r *RealSSHClient) logf(format string, args ...any) {
	if r.Verbose {
		fmt.Printf("[verbose] "+format+"\n", args...)
	}
}

// hostKeyCallback returns the effective host-key verification callback, failing
// closed when none is configured.
func (r *RealSSHClient) hostKeyCallback() ssh.HostKeyCallback {
	switch {
	case r.InsecureIgnoreHostKey:
		return ssh.InsecureIgnoreHostKey()
	case r.HostKeyCallback != nil:
		return r.HostKeyCallback
	default:
		return func(hostname string, _ net.Addr, _ ssh.PublicKey) error {
			return fmt.Errorf("no host-key verification configured for %s; refusing to send the password (configure known_hosts or pass --insecure-host-key)", hostname)
		}
	}
}

// bannerBuf accumulates decrypted banner and keyboard-interactive instruction
// text seen during the handshake. Access is synchronized because the SSH
// callbacks may run on a different goroutine than the caller.
type bannerBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *bannerBuf) add(s string) {
	if s == "" {
		return
	}
	b.mu.Lock()
	b.buf.WriteString(s)
	b.buf.WriteString("\n")
	b.mu.Unlock()
}

func (b *bannerBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// authTrace records security-relevant authentication events separately from
// their display text. Keeping this state structured prevents a pre-auth banner
// or a password question from being mistaken for a post-password success
// response.
type authTrace struct {
	mu sync.Mutex

	banner           bannerBuf
	passwordPrompted bool
	passwordAnswered bool
	successAfterAuth bool
}

func (t *authTrace) addText(s string) {
	t.banner.add(s)
}

func (t *authTrace) output() string {
	return t.banner.String()
}

func (t *authTrace) recordPasswordPrompt(answer bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.passwordPrompted {
		return errors.New("unexpected repeated password challenge")
	}
	t.passwordPrompted = true
	t.passwordAnswered = answer
	return nil
}

func (t *authTrace) recordResponseText(s, successMsg string) {
	t.addText(s)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.passwordAnswered && successSeen(s, successMsg) {
		t.successAfterAuth = true
	}
}

func (t *authTrace) state() (prompted, answered, succeeded bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.passwordPrompted, t.passwordAnswered, t.successAfterAuth
}

// errStatusProbe is returned by the status-probe keyboard-interactive callback
// to abort authentication without sending the password.
var errStatusProbe = errors.New("status probe: not answering")

// ErrIndeterminate signals that the device state could not be determined
// without authenticating (a password prompt was reached, but no locked banner
// was seen, and a booted sshd prompts identically).
var ErrIndeterminate = errors.New("device state indeterminate without authenticating")

// clientConfig builds an ssh.ClientConfig. If answerPassword is true the
// keyboard-interactive callback answers exactly one hidden "Password:" prompt;
// otherwise it captures prompts without ever sending the password (used by the
// no-password status probe). SSH password authentication is not configured:
// falling through to it after rejecting a hostile interactive
// challenge would disclose the same secret the callback refused to answer.
func (r *RealSSHClient) clientConfig(user, password, successMsg string, answerPassword bool, trace *authTrace) *ssh.ClientConfig {
	kbd := ssh.KeyboardInteractive(func(_, instruction string, questions []string, echos []bool) ([]string, error) {
		// Info-only request (e.g. the success banner); nothing to answer.
		if len(questions) == 0 {
			trace.recordResponseText(instruction, successMsg)
			return nil, nil
		}
		trace.addText(instruction)
		// The FileVault prompt is a single, non-echoed "Password:" question.
		// Refuse anything else so a hostile or unexpected server can never
		// harvest the password by asking a different question.
		if len(questions) != 1 || len(echos) != 1 || echos[0] || !isPasswordPrompt(questions[0]) {
			return nil, fmt.Errorf("unexpected keyboard-interactive challenge (%d questions)", len(questions))
		}
		trace.addText(questions[0])
		if err := trace.recordPasswordPrompt(answerPassword); err != nil {
			return nil, err
		}
		if !answerPassword {
			return nil, errStatusProbe
		}
		return []string{password}, nil
	})

	// Offer public-key auth first: it never sends a secret, and it can only
	// succeed against a booted host (never the pre-boot prompt), so it is a
	// safe, positive booted-state probe.
	var auth []ssh.AuthMethod
	if len(r.Signers) > 0 {
		auth = append(auth, ssh.PublicKeys(r.Signers...))
	}
	auth = append(auth, kbd)

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: r.hostKeyCallback(),
		BannerCallback: func(msg string) error {
			trace.recordResponseText(msg, successMsg)
			return nil
		},
		Timeout: r.dialTimeout(),
	}
}

// AnalyzePrompt connects to host, supplies the password over
// keyboard-interactive, and returns the resulting DeviceStatus, the decrypted
// banner text seen, and any error.
func (r *RealSSHClient) AnalyzePrompt(ctx context.Context, host, user, password, successMsg string) (DeviceStatus, string, error) {
	trace := &authTrace{}
	cfg := r.clientConfig(user, password, successMsg, true, trace)

	sshConn, chans, reqs, err := r.handshake(ctx, host, cfg)
	out := trace.output()
	promptedForPassword, _, successAfterAuth := trace.state()
	if err != nil {
		return r.classifyHandshakeErr(host, out, promptedForPassword, successAfterAuth, err)
	}

	// A completed handshake means we reached a fully booted sshd. The machine
	// is already unlocked. (The FileVault pre-boot server never completes the
	// handshake; it fails auth after emitting the success banner.)
	defer sshConn.Close()
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	if successAfterAuth {
		return StatusUnlocked, out, nil
	}
	r.logf("SSH handshake completed; device is already unlocked")
	return StatusUnlockedRecently, out, nil
}

// ProbeStatus reports the device status WITHOUT transmitting any password. It
// connects, reads the banner and auth-method behavior, and classifies the
// state. This is the safe way to check whether a device is locked.
func (r *RealSSHClient) ProbeStatus(ctx context.Context, host, user string) (DeviceStatus, string, error) {
	trace := &authTrace{}
	cfg := r.clientConfig(user, "", "", false, trace)

	sshConn, chans, reqs, err := r.handshake(ctx, host, cfg)
	out := trace.output()
	promptedForPassword, _, _ := trace.state()
	if err != nil {
		if isHostKeyError(err) {
			return StatusUnknown, out, fmt.Errorf("%w for %s: %v", ErrHostKeyMismatch, host, err)
		}
		// We aborted keyboard-interactive on purpose (errStatusProbe). Only the
		// locked banner proves the pre-boot state: a fully booted sshd also
		// offers a keyboard-interactive password prompt, so the prompt alone is
		// not a discriminator.
		if lockedSeen(out) {
			return StatusLocked, out, nil
		}
		if de := dialError(err); de != nil {
			return StatusUnknown, out, de
		}
		if promptedForPassword {
			// Reached a password prompt with no locked banner. Without
			// authenticating we cannot tell a pre-boot prompt from a booted
			// sshd; say so rather than guessing.
			return StatusUnknown, out, ErrIndeterminate
		}
		return StatusUnknown, out, err
	}
	// Handshake completed without a password (a booted host with an open auth
	// method), so treat it as already unlocked.
	client := ssh.NewClient(sshConn, chans, reqs)
	client.Close()
	return StatusUnlockedRecently, out, nil
}

// handshake dials host and performs the SSH handshake, honoring ctx deadlines
// on both the dial and the handshake so a silent host can never wedge the call.
func (r *RealSSHClient) handshake(ctx context.Context, host string, cfg *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	r.logf("dialing %q", host)
	timeout := r.dialTimeout()
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		if de := dialError(err); de != nil {
			return nil, nil, nil, de
		}
		return nil, nil, nil, err
	}

	// Enforce the context deadline (and DialTimeout as a floor) on the SSH
	// handshake, which ssh.NewClientConn does not bind to ctx itself.
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// Abort the handshake if ctx is cancelled.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, err
	}
	// Clear the handshake deadline for the (short-lived) established connection.
	_ = conn.SetDeadline(time.Time{})
	return sshConn, chans, reqs, nil
}

// classifyHandshakeErr turns a failed handshake into a DeviceStatus using the
// decrypted banner text and typed error inspection, not string matching on
// err.Error().
func (r *RealSSHClient) classifyHandshakeErr(host, out string, promptedForPassword, successAfterAuth bool, err error) (DeviceStatus, string, error) {
	if isHostKeyError(err) {
		return StatusUnknown, out, fmt.Errorf("%w for %s: %v", ErrHostKeyMismatch, host, err)
	}
	if de := dialError(err); de != nil {
		return StatusUnknown, out, de
	}
	// The success banner is the authoritative positive signal, even though the
	// server then fails auth and disconnects.
	if successAfterAuth {
		r.logf("success banner detected; unlock succeeded")
		return StatusUnlocked, out, nil
	}
	// We answered the password prompt but did not see the success banner: the
	// device is still locked (wrong password, or authentication ended).
	if promptedForPassword {
		r.logf("password prompt seen but no success banner; still locked")
		return StatusLocked, out, ErrAuthFailed
	}
	return StatusUnknown, out, err
}

func isPasswordPrompt(question string) bool {
	return strings.EqualFold(strings.TrimSpace(question), "Password:")
}

// isHostKeyError reports whether err is a host-key verification failure.
//
// Host-key callbacks report failures inconsistently: knownhosts returns a typed
// *knownhosts.KeyError, ssh.FixedHostKey returns a plain error, and custom
// callbacks return whatever they like. Callers must be able to recognise this
// case reliably, because a changed host key is fatal (possible MITM) and must
// never be retried past. Custom callbacks should wrap ErrHostKeyMismatch; the
// final check matches x/crypto's own fixed message as a last resort.
func isHostKeyError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrHostKeyMismatch) {
		return true
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		return true
	}
	return strings.Contains(err.Error(), "host key mismatch")
}

// dialError maps common transport errors to the package's sentinel errors.
// Returns nil if err is not a recognized transport error.
func dialError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	if isConnectionRefused(err) {
		return ErrConnectionRefused
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return context.DeadlineExceeded
	}
	return nil
}

// successSeen reports whether the captured banner text indicates a successful
// unlock. Matching is whitespace-insensitive and anchored so that the locked
// banner can never be mistaken for a success (see the phrase constants).
func successSeen(out, successMsg string) bool {
	norm := normalizeBanner(out)
	if strings.Contains(norm, successPhrase) {
		return true
	}
	// A caller-supplied success message is an additional signal. It is ignored
	// when too short to be discriminating, and when it would also match the
	// locked banner (which would make it useless as a success marker).
	needle := normalizeBanner(successMsg)
	if len(needle) >= minCustomSuccessLen &&
		!strings.Contains(lockedBannerText, needle) &&
		!isPasswordPrompt(needle) {
		return strings.Contains(norm, needle)
	}
	return false
}

// lockedBannerText is the normalized macOS pre-boot locked banner, used to
// reject caller-supplied success messages that would also match it.
const lockedBannerText = "this system is locked. to unlock it, use a local account name and password. once successfully unlocked, you will be able to connect normally."

// lockedSeen reports whether the captured text contains the pre-boot locked
// banner.
func lockedSeen(out string) bool {
	return strings.Contains(normalizeBanner(out), lockedPhrase)
}

// IsFileVaultLockedBanner reports whether decrypted SSH text contains the
// complete, distinctive English FileVault locked explanation. A generic
// "system is locked" notice or Password: prompt is not sufficient because
// ordinary SSH servers can present either one.
func IsFileVaultLockedBanner(out string) bool {
	return strings.Contains(normalizeBanner(out), lockedBannerText)
}

// ParseOutput inspects SSH banner/output text and returns a DeviceStatus. It is
// a pure helper retained for testing and for classifying already-captured text.
func ParseOutput(out string) DeviceStatus {
	norm := normalizeBanner(out)
	switch {
	case strings.Contains(norm, successPhrase):
		return StatusUnlocked
	case strings.Contains(norm, "last login:"):
		return StatusUnlockedRecently
	case strings.Contains(norm, lockedPhrase) || strings.Contains(norm, "password:"):
		// A password prompt (or the locked banner) means the device is locked,
		// awaiting a password, never that it is unlocked.
		return StatusLocked
	default:
		return StatusUnknown
	}
}

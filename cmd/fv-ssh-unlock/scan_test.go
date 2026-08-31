// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/shoon/fv-ssh-unlock/internal/config"
)

const scanTestLockedBanner = "This system is locked. To unlock it, use a local\r\n" +
	"account name and password. Once successfully\r\n" +
	"unlocked, you will be able to connect normally."

func TestScanHelpExplainsEvidenceAndSafety(t *testing.T) {
	cmd := newScanCommand()
	for _, phrase := range []string{
		"password-free SSH handshake",
		"without advertising _ssh._tcp",
		"not a unique FileVault fingerprint",
		"pinned targets",
		"never reads",
		"credential",
		"authorized",
	} {
		if !strings.Contains(cmd.Long, phrase) {
			t.Errorf("scan help is missing %q", phrase)
		}
	}
}

func TestScanCommandRejectsInvalidSafetyBoundsBeforeNetworking(t *testing.T) {
	for name, args := range map[string][]string{
		"missing cidr":    nil,
		"invalid port":    {"--cidr", "192.0.2.1/32", "--port", "0"},
		"invalid timeout": {"--cidr", "192.0.2.1/32", "--timeout", "0s"},
		"zero concurrency": {
			"--cidr", "192.0.2.1/32", "--concurrency", "0",
		},
		"excess concurrency": {
			"--cidr", "192.0.2.1/32", "--concurrency", "257",
		},
		"unsafe user": {"--cidr", "192.0.2.1/32", "--user", " admin"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newScanCommand()
			cmd.SetArgs(args)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid scan arguments were accepted")
			}
		})
	}
	if err := validateScanUser("fv-ssh-probe"); err != nil {
		t.Fatalf("valid scan user rejected: %v", err)
	}
	if err := validateScanUser("admin\nforged"); err == nil {
		t.Fatal("control character in scan user was accepted")
	}
}

func TestExpandScanCIDRs(t *testing.T) {
	addresses, err := expandScanCIDRs([]string{"192.0.2.0/30", "192.0.2.1/32", "192.0.2.4/31"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.4"),
		netip.MustParseAddr("192.0.2.5"),
	}
	if !slices.Equal(addresses, want) {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
}

func TestExpandScanCIDRsRejectsIPv6AndBroadRanges(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/120", "10.0.0.0/19"} {
		if _, err := expandScanCIDRs([]string{cidr}); err == nil {
			t.Errorf("expandScanCIDRs(%q) unexpectedly succeeded", cidr)
		}
	}
}

func TestProbeScanTargetRecognizesFileVaultBannerWithoutCredentials(t *testing.T) {
	address, port, hostKey, answers := startScanTestServer(t, scanTestLockedBanner)
	finding, open := probeScanTarget(t.Context(), address, port, defaultScanUser, 5*time.Second)
	if !open {
		t.Fatal("probe reported the listening port as closed")
	}
	if finding.version != "OpenSSH_10.2" {
		t.Errorf("version = %q, want OpenSSH_10.2", finding.version)
	}
	if finding.fingerprint != ssh.FingerprintSHA256(hostKey.PublicKey()) {
		t.Errorf("fingerprint = %q, want %q", finding.fingerprint, ssh.FingerprintSHA256(hostKey.PublicKey()))
	}
	if finding.evidence != "FileVault locked banner" {
		t.Errorf("evidence = %q, want FileVault locked banner", finding.evidence)
	}
	if got := receiveScanAnswers(t, answers); len(got) != 0 {
		t.Fatalf("password-free scanner sent authentication answers: %q", got)
	}
}

func TestProbeScanTargetTreatsPromptOnlyAsIndeterminate(t *testing.T) {
	address, port, _, answers := startScanTestServer(t, "")
	finding, open := probeScanTarget(t.Context(), address, port, defaultScanUser, 5*time.Second)
	if !open {
		t.Fatal("probe reported the listening port as closed")
	}
	if finding.evidence != "Password prompt; state indeterminate" {
		t.Errorf("evidence = %q, want prompt-only indeterminate result", finding.evidence)
	}
	if got := receiveScanAnswers(t, answers); len(got) != 0 {
		t.Fatalf("password-free scanner sent authentication answers: %q", got)
	}
}

func receiveScanAnswers(t *testing.T, answers <-chan []string) []string {
	t.Helper()
	select {
	case got := <-answers:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("scan test SSH server did not receive the authentication callback")
		return nil
	}
}

func startScanTestServer(t *testing.T, banner string) (netip.Addr, int, ssh.Signer, <-chan []string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	answers := make(chan []string, 1)
	serverDone := make(chan struct{})
	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_10.2",
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			got, challengeErr := challenge("", banner, []string{"Password: "}, []bool{false})
			answers <- got
			return nil, challengeErr
		},
	}
	serverConfig.AddHostKey(hostKey)
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _, _, _ = ssh.NewServerConn(conn, serverConfig)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("scan test SSH server did not stop")
		}
	})

	tcp := listener.Addr().(*net.TCPAddr)
	return netip.MustParseAddr(tcp.IP.String()), tcp.Port, hostKey, answers
}

func TestMatchPinnedTargetNamesUsesHostKeyIdentity(t *testing.T) {
	key := testPublicKey(t)
	line := knownhosts.Line([]string{knownhosts.Normalize("192.0.2.10:22")}, key)
	devices := []config.Device{
		{Name: "lab-mac", Host: "192.0.2.10", Port: 22},
		{Name: "other-mac", Host: "192.0.2.11", Port: 22},
	}

	matches := matchPinnedTargetNames([]byte(line+"\n"), devices)
	got := matches[ssh.FingerprintSHA256(key)]
	if !slices.Equal(got, []string{"lab-mac"}) {
		t.Fatalf("fingerprint names = %v, want [lab-mac]", got)
	}
}

func TestPrintScanFindingsRendersEmptyAndDetailedResults(t *testing.T) {
	empty := captureStdout(t, func() { printScanFindings(nil, 12, false) })
	if !strings.Contains(empty, "No open target ports found after scanning 12 address(es)") {
		t.Fatalf("empty scan output = %q", empty)
	}

	finding := scanFinding{
		address: netip.MustParseAddr("192.0.2.44"), port: 22,
		version: "OpenSSH_10.2", match: "editing-mac", evidence: "FileVault locked banner",
		fingerprint: "SHA256:test", keyType: "ssh-ed25519", detail: "password prompt observed",
	}
	rendered := captureStdout(t, func() { printScanFindings([]scanFinding{finding}, 12, true) })
	for _, want := range []string{
		"192.0.2.44", "OpenSSH_10.2", "editing-mac", "FileVault locked banner",
		"ssh-ed25519 SHA256:test", "handshake: password prompt observed", "1 open port(s) across 12 address(es)",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("scan output missing %q:\n%s", want, rendered)
		}
	}
}

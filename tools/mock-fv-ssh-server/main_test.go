// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDefaultBannersMatchCapturedTranscript(t *testing.T) {
	data, err := os.ReadFile("Tahoe 26.0 FileVault SSH Real Output.txt")
	if err != nil {
		t.Fatal(err)
	}
	transcript := strings.ReplaceAll(string(data), "\r\n", "\n")
	for name, banner := range map[string]string{
		"locked":  defaultLockedBanner,
		"success": defaultSuccessBanner,
	} {
		want := strings.TrimSpace(strings.ReplaceAll(banner, "\r\n", "\n"))
		if !strings.Contains(transcript, want) {
			t.Errorf("default %s banner does not match the captured transcript", name)
		}
	}
}

func TestLockedProtocolEmitsCapturedBannersAndDisconnects(t *testing.T) {
	instructions := runLockedProtocol(t, defaultLockedBanner, false)
	output := strings.Join(instructions, "\n")
	if !strings.Contains(output, defaultLockedBanner) {
		t.Fatal("locked protocol did not emit the complete captured locked banner")
	}
	if !strings.Contains(output, defaultSuccessBanner) {
		t.Fatal("locked protocol did not emit the captured success banner")
	}
}

func TestLockedProtocolSupportsObservedPromptOnlyVariant(t *testing.T) {
	instructions := runLockedProtocol(t, defaultLockedBanner, true)
	if len(instructions) < 2 {
		t.Fatalf("got %d keyboard-interactive exchanges, want at least 2", len(instructions))
	}
	if instructions[0] != "" {
		t.Fatalf("first instruction = %q, want no locked explanation", instructions[0])
	}
	if !strings.Contains(strings.Join(instructions, "\n"), defaultSuccessBanner) {
		t.Fatal("prompt-only protocol did not emit the success banner")
	}
}

func TestFlagHelpDocumentsPromptOnlyVariant(t *testing.T) {
	for name, phrase := range map[string]string{
		"authorized-key":       "unlocked state",
		"banner":               "prompt-only variant",
		"prompt-only":          "show only Password:",
		"server-version":       "OpenSSH_10.2",
		"transition-on-unlock": "post-boot verification",
	} {
		f := flag.Lookup(name)
		if f == nil {
			t.Fatalf("flag %q is not registered", name)
		}
		if !strings.Contains(f.Usage, phrase) {
			t.Errorf("--%s help is missing %q", name, phrase)
		}
	}
}

func runLockedProtocol(t *testing.T, lockedBanner string, promptOnlyMode bool) []string {
	t.Helper()
	oldState, oldPassword, oldUsername := *state, *password, *username
	oldBanner, oldPromptOnly, oldSuccess, oldTransition := *bannerMsg, *promptOnly, *successMsg, *transition
	oldPublicKey := unlockedPublicKey
	*state, *password, *username = "locked", "test-secret", "test"
	*bannerMsg, *promptOnly, *successMsg, *transition = lockedBanner, promptOnlyMode, defaultSuccessBanner, false
	unlockedPublicKey = nil
	t.Cleanup(func() {
		*state, *password, *username = oldState, oldPassword, oldUsername
		*bannerMsg, *promptOnly, *successMsg, *transition = oldBanner, oldPromptOnly, oldSuccess, oldTransition
		unlockedPublicKey = oldPublicKey
	})

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			handleConnection(conn, serverConfig(hostKey))
		}
	}()

	var instructions []string
	validPasswordPrompt := false
	clientConfig := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, instruction string, questions []string, echos []bool) ([]string, error) {
			instructions = append(instructions, instruction)
			if len(questions) == 0 {
				return nil, nil
			}
			validPasswordPrompt = len(questions) == 1 && questions[0] == "Password: " && len(echos) == 1 && !echos[0]
			return []string{"test-secret"}, nil
		})},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("locked protocol must disconnect after the success banner, not complete authentication")
	}
	<-serverDone
	if !validPasswordPrompt {
		t.Fatal("locked protocol did not present one hidden Password: prompt")
	}
	return instructions
}

func TestTransitionOnUnlockAcceptsConfiguredPublicKey(t *testing.T) {
	oldState, oldPassword, oldUsername, oldTransition := *state, *password, *username, *transition
	oldPublicKey := unlockedPublicKey
	*state, *password, *username, *transition = "locked", "test-secret", "test", true
	t.Cleanup(func() {
		*state, *password, *username, *transition = oldState, oldPassword, oldUsername, oldTransition
		unlockedPublicKey = oldPublicKey
	})

	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	unlockedPublicKey = clientSigner.PublicKey()

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	config := serverConfig(hostKey)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for range 2 {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			handleConnection(conn, config)
		}
	}()

	unlockConfig := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			if len(questions) == 0 {
				return nil, nil
			}
			return []string{"test-secret"}, nil
		})},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}
	if client, dialErr := ssh.Dial("tcp", listener.Addr().String(), unlockConfig); dialErr == nil {
		client.Close()
		t.Fatal("locked protocol unexpectedly completed authentication")
	}

	bootedConfig := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", listener.Addr().String(), bootedConfig)
	if err != nil {
		t.Fatalf("public key was not accepted after transition: %v", err)
	}
	client.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("transition test server did not stop")
	}
}

func TestLoadAuthorizedPublicKey(t *testing.T) {
	key := testSigner(t).PublicKey()
	path := filepath.Join(t.TempDir(), "authorized.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadAuthorizedPublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), key.Marshal()) {
		t.Fatal("loaded public key does not match")
	}
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestLoopbackBindDetection(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isLoopbackBind(host) {
			t.Errorf("expected %q to be loopback", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.10"} {
		if isLoopbackBind(host) {
			t.Errorf("expected %q to be externally reachable", host)
		}
	}
}

func TestHostKeyGeneratedOnceWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-key")
	first, err := loadOrGenerateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrGenerateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Fatalf("host key changed when reloaded")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("host key permissions too open: %v", info.Mode())
		}
	}
}

func TestReadSecretFileRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSecretFileSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path); err == nil {
		t.Fatal("expected oversized secret file to be rejected")
	}
}

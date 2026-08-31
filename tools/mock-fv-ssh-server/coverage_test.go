// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func resetPasswordInputs(t *testing.T) *flag.FlagSet {
	t.Helper()
	oldFlags := flag.CommandLine
	oldPassword, oldFile := *password, *passwordFile
	*password, *passwordFile = "password", ""
	set := flag.NewFlagSet("password-test", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(password, "password", *password, "test password")
	flag.CommandLine = set
	t.Cleanup(func() {
		flag.CommandLine = oldFlags
		*password, *passwordFile = oldPassword, oldFile
	})
	return set
}

func TestResolvePasswordSourcesAndConflicts(t *testing.T) {
	t.Run("password file", func(t *testing.T) {
		resetPasswordInputs(t)
		path := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(path, []byte("file-secret\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		*passwordFile = path
		if err := resolvePassword(); err != nil {
			t.Fatal(err)
		}
		if *password != "file-secret" || !passwordWasConfigured() {
			t.Fatalf("resolved password=%q configured=%v", *password, passwordWasConfigured())
		}
	})

	t.Run("environment", func(t *testing.T) {
		resetPasswordInputs(t)
		t.Setenv("MOCK_FV_PASSWORD", "environment-secret")
		if err := resolvePassword(); err != nil {
			t.Fatal(err)
		}
		if *password != "environment-secret" || !passwordWasConfigured() {
			t.Fatalf("resolved password=%q configured=%v", *password, passwordWasConfigured())
		}
	})

	t.Run("explicit flag", func(t *testing.T) {
		set := resetPasswordInputs(t)
		if err := set.Set("password", "flag-secret"); err != nil {
			t.Fatal(err)
		}
		if err := resolvePassword(); err != nil {
			t.Fatal(err)
		}
		if *password != "flag-secret" || !flagWasSet("password") || !passwordWasConfigured() {
			t.Fatal("explicit password flag was not recognized")
		}
	})

	t.Run("default is not explicit", func(t *testing.T) {
		resetPasswordInputs(t)
		if flagWasSet("password") || passwordWasConfigured() {
			t.Fatal("default password was treated as an explicit configuration")
		}
	})

	t.Run("file conflicts with environment", func(t *testing.T) {
		resetPasswordInputs(t)
		*passwordFile = filepath.Join(t.TempDir(), "unused")
		t.Setenv("MOCK_FV_PASSWORD", "environment-secret")
		if err := resolvePassword(); err == nil {
			t.Fatal("conflicting password sources were accepted")
		}
	})

	t.Run("password file read error", func(t *testing.T) {
		resetPasswordInputs(t)
		*passwordFile = filepath.Join(t.TempDir(), "missing")
		if err := resolvePassword(); err == nil || !strings.Contains(err.Error(), "read password file") {
			t.Fatalf("missing password file error = %v", err)
		}
	})

	t.Run("flag conflicts with environment", func(t *testing.T) {
		set := resetPasswordInputs(t)
		if err := set.Set("password", "flag-secret"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("MOCK_FV_PASSWORD", "environment-secret")
		if err := resolvePassword(); err == nil {
			t.Fatal("conflicting password sources were accepted")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		resetPasswordInputs(t)
		*password = ""
		if err := resolvePassword(); err == nil {
			t.Fatal("empty password was accepted")
		}
	})
}

func TestSecretAndAuthorizedKeyFileValidation(t *testing.T) {
	t.Run("secret file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readSecretFile(path)
		if err != nil || string(got) != "secret" {
			t.Fatalf("readSecretFile = %q, %v", got, err)
		}
	})

	for name, makePath := range map[string]func(*testing.T) string{
		"missing": func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
		"directory": func(t *testing.T) string {
			return t.TempDir()
		},
	} {
		t.Run("secret rejects "+name, func(t *testing.T) {
			if _, err := readSecretFile(makePath(t)); err == nil {
				t.Fatalf("%s secret path was accepted", name)
			}
		})
	}

	if runtime.GOOS != "windows" {
		t.Run("secret rejects open permissions", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := readSecretFile(path); err == nil {
				t.Fatal("overly broad secret permissions were accepted")
			}
		})
		t.Run("secret rejects symlink", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			link := filepath.Join(dir, "link")
			if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := readSecretFile(link); err == nil {
				t.Fatal("symlink secret was accepted")
			}
		})
	}

	for name, path := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "missing.pub"),
		"directory": t.TempDir(),
		"invalid": func() string {
			path := filepath.Join(t.TempDir(), "invalid.pub")
			if err := os.WriteFile(path, []byte("not a key"), 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}(),
	} {
		t.Run("authorized key rejects "+name, func(t *testing.T) {
			if _, err := loadAuthorizedPublicKey(path); err == nil {
				t.Fatalf("%s authorized-key path was accepted", name)
			}
		})
	}
	oversize := filepath.Join(t.TempDir(), "oversize.pub")
	if err := os.WriteFile(oversize, make([]byte, maxSecretFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthorizedPublicKey(oversize); err == nil {
		t.Fatal("oversized authorized key was accepted")
	}
}

func setProtocolGlobals(t *testing.T, serverState string, accepted ssh.PublicKey) {
	t.Helper()
	oldState, oldPassword, oldUsername := *state, *password, *username
	oldBanner, oldPromptOnly, oldSuccess := *bannerMsg, *promptOnly, *successMsg
	oldTransition, oldVerbose, oldKey := *transition, *verbose, unlockedPublicKey
	*state, *password, *username = serverState, "test-secret", "allowed"
	*bannerMsg, *promptOnly, *successMsg = defaultLockedBanner, false, defaultSuccessBanner
	*transition, *verbose, unlockedPublicKey = false, false, accepted
	t.Cleanup(func() {
		*state, *password, *username = oldState, oldPassword, oldUsername
		*bannerMsg, *promptOnly, *successMsg = oldBanner, oldPromptOnly, oldSuccess
		*transition, *verbose, unlockedPublicKey = oldTransition, oldVerbose, oldKey
	})
}

func dialMockOnce(t *testing.T, user string, auth ssh.AuthMethod, openChannel bool) error {
	t.Helper()
	hostKey := testSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			handleConnection(conn, serverConfig(hostKey))
		}
	}()
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         2 * time.Second,
	}
	client, dialErr := ssh.Dial("tcp", listener.Addr().String(), config)
	if client != nil {
		if openChannel {
			if session, sessionErr := client.NewSession(); sessionErr == nil {
				_ = session.Close()
				t.Error("mock unexpectedly accepted a session channel")
			}
		}
		_ = client.Close()
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("mock connection handler did not stop")
	}
	return dialErr
}

func keyboardAnswer(answer string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) == 0 {
			return nil, nil
		}
		return []string{answer}, nil
	})
}

func keyboardError() ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
		return nil, errors.New("client refused challenge")
	})
}

func TestUnlockedAuthenticationMatrix(t *testing.T) {
	accepted := testSigner(t)
	other := testSigner(t)
	tests := []struct {
		name        string
		user        string
		auth        ssh.AuthMethod
		wantSuccess bool
		openChannel bool
	}{
		{name: "authorized public key", user: "allowed", auth: ssh.PublicKeys(accepted), wantSuccess: true, openChannel: true},
		{name: "unauthorized public key", user: "allowed", auth: ssh.PublicKeys(other)},
		{name: "public key wrong user", user: "other", auth: ssh.PublicKeys(accepted)},
		{name: "correct password", user: "allowed", auth: ssh.Password("test-secret"), wantSuccess: true},
		{name: "wrong password", user: "allowed", auth: ssh.Password("wrong")},
		{name: "password wrong user", user: "other", auth: ssh.Password("test-secret")},
		{name: "correct keyboard interactive", user: "allowed", auth: keyboardAnswer("test-secret"), wantSuccess: true},
		{name: "wrong keyboard interactive", user: "allowed", auth: keyboardAnswer("wrong")},
		{name: "keyboard client error", user: "allowed", auth: keyboardError()},
		{name: "keyboard interactive wrong user", user: "other", auth: keyboardAnswer("test-secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setProtocolGlobals(t, "unlocked", accepted.PublicKey())
			err := dialMockOnce(t, test.user, test.auth, test.openChannel)
			if test.wantSuccess && err != nil {
				t.Fatalf("authentication failed: %v", err)
			}
			if !test.wantSuccess && err == nil {
				t.Fatal("authentication unexpectedly succeeded")
			}
		})
	}
}

func TestLockedAuthenticationRejectsNonInteractivePaths(t *testing.T) {
	key := testSigner(t)
	tests := []struct {
		name string
		user string
		auth ssh.AuthMethod
	}{
		{name: "public key while locked", user: "allowed", auth: ssh.PublicKeys(key)},
		{name: "password method while locked", user: "allowed", auth: ssh.Password("test-secret")},
		{name: "wrong interactive password", user: "allowed", auth: keyboardAnswer("wrong")},
		{name: "correct interactive password still disconnects", user: "allowed", auth: keyboardAnswer("test-secret")},
		{name: "interactive client error", user: "allowed", auth: keyboardError()},
		{name: "interactive wrong user", user: "other", auth: keyboardAnswer("test-secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setProtocolGlobals(t, "locked", key.PublicKey())
			*verbose = true
			if err := dialMockOnce(t, test.user, test.auth, false); err == nil {
				t.Fatal("locked authentication unexpectedly succeeded")
			}
		})
	}
}

func TestHostKeyValidationErrorsAndExistingGenerateTarget(t *testing.T) {
	for name, path := range map[string]string{
		"directory": t.TempDir(),
		"invalid": func() string {
			path := filepath.Join(t.TempDir(), "invalid-key")
			if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadOrGenerateHostKey(path); err == nil {
				t.Fatalf("%s host-key path was accepted", name)
			}
		})
	}

	oversize := filepath.Join(t.TempDir(), "oversize-key")
	if err := os.WriteFile(oversize, make([]byte, maxSecretFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateHostKey(oversize); err == nil {
		t.Fatal("oversized host key was accepted")
	}

	path := filepath.Join(t.TempDir(), "existing-key")
	first, err := loadOrGenerateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateAndSaveHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(ssh.FingerprintSHA256(first.PublicKey()), ssh.FingerprintSHA256(second.PublicKey())) {
		t.Fatal("existing generated key was not reloaded")
	}
}

func TestProtocolStateConcurrentSafeAccess(t *testing.T) {
	state := &protocolState{}
	done := make(chan struct{})
	go func() {
		state.setUnlocked()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state update blocked")
	}
	if !state.isUnlocked() {
		t.Fatal("state update was not visible")
	}
}

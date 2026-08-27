// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Command mock-fv-ssh-server emulates the macOS 26 (Tahoe) FileVault pre-boot
// SSH unlock server for manual testing of fv-ssh-unlock.
//
// It models two observed real-device protocol variants. The default preserves
// the macOS 26.0.1 transcript in "Tahoe 26.0 FileVault SSH Real Output.txt";
// --prompt-only models a later session without the explanation:
//
//   - It advertises publickey, password, and keyboard-interactive, but only
//     keyboard-interactive can make progress.
//   - In the locked state it can send the captured explanation followed by a
//     "Password:" prompt, or only the prompt when --prompt-only is set.
//   - On the CORRECT password it emits "System successfully unlocked." as a
//     second keyboard-interactive instruction, then FAILS authentication and
//     closes the connection. There is NO USERAUTH_SUCCESS and NO
//     shell. The disconnect after the success banner is the success signal.
//   - On a WRONG password it fails authentication (the client may retry).
//   - In the unlocked state it accepts authentication, emulating a fully booted
//     sshd (an already-unlocked machine).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	port          = flag.Int("port", 8080, "TCP port to listen on")
	bind          = flag.String("bind", "127.0.0.1", "Address to bind (use 0.0.0.0 explicitly for LAN access)")
	state         = flag.String("state", "locked", "Server state: 'locked' or 'unlocked'")
	password      = flag.String("password", "password", "Correct test password (visible in process listings; prefer MOCK_FV_PASSWORD or --password-file)")
	passwordFile  = flag.String("password-file", "", "Read the test password from a file")
	username      = flag.String("username", "", "Expected username (empty = any)")
	hostKeyPath   = flag.String("host-key-path", "mock_host_key", "Path to the SSH host key file (generated if missing)")
	bannerMsg     = flag.String("banner", defaultLockedBanner, "Locked-state explanation (empty models the observed prompt-only variant)")
	promptOnly    = flag.Bool("prompt-only", false, "Omit the locked-state explanation and show only Password:")
	transition    = flag.Bool("transition-on-unlock", false, "Change to unlocked state after a correct password for post-boot verification tests")
	authorizedKey = flag.String("authorized-key", "", "Public key accepted in unlocked state (empty accepts any public key)")
	successMsg    = flag.String("success-message", defaultSuccessBanner, "Message emitted on a correct password")
	serverVersion = flag.String("server-version", "OpenSSH_10.0", "SSH server version string (OpenSSH_10.2 was observed with prompt-only pre-boot)")
	verbose       = flag.Bool("verbose", false, "Enable verbose logging")
)

const (
	maxSecretFileSize = 64 << 10

	// These are the verbatim line breaks captured from macOS 26.0.1. Keep the
	// locked banner complete: it contains "successfully unlocked" across a line
	// break and exercises a false-success regression.
	defaultLockedBanner = "This system is locked. To unlock it, use a local\r\n" +
		"account name and password. Once successfully\r\n" +
		"unlocked, you will be able to connect normally."
	defaultSuccessBanner = "System successfully unlocked.\r\n" +
		"You may now use SSH to authenticate normally.\r\n\r\n"
)

// errUnlocked is returned from the keyboard-interactive callback after the
// success banner is sent, so the client sees an auth failure and disconnect,
// matching the real device.
var errUnlocked = errors.New("unlocked; closing connection")

var unlockedPublicKey ssh.PublicKey

func main() {
	flag.Parse()

	if *state != "locked" && *state != "unlocked" {
		log.Fatalf("invalid state %q: must be 'locked' or 'unlocked'", *state)
	}
	if *port < 1 || *port > 65535 {
		log.Fatalf("invalid port %d", *port)
	}
	if err := resolvePassword(); err != nil {
		log.Fatalf("password: %v", err)
	}
	if !isLoopbackBind(*bind) {
		if !passwordWasConfigured() {
			log.Fatal("refusing non-loopback bind with the default password; set MOCK_FV_PASSWORD, --password-file, or --password")
		}
		log.Printf("WARNING: mock server is exposed beyond loopback on %q; it is not production hardened", *bind)
	}
	if *authorizedKey != "" {
		key, keyErr := loadAuthorizedPublicKey(*authorizedKey)
		if keyErr != nil {
			log.Fatalf("authorized key: %v", keyErr)
		}
		unlockedPublicKey = key
		fmt.Printf("Unlocked-state authorized key: %s\n", ssh.FingerprintSHA256(unlockedPublicKey))
	}

	hostKey, err := loadOrGenerateHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	fmt.Printf("Mock SSH host-key fingerprint: %s\n", ssh.FingerprintSHA256(hostKey.PublicKey()))

	config := serverConfig(hostKey)

	listenAddr := net.JoinHostPort(*bind, strconv.Itoa(*port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	fmt.Printf("Mock FileVault SSH server listening on %s in %q state\n", listener.Addr(), *state)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConnection(conn, config)
	}
}

func resolvePassword() error {
	passwordFlagSet := flagWasSet("password")
	if *passwordFile != "" {
		if passwordFlagSet || os.Getenv("MOCK_FV_PASSWORD") != "" {
			return errors.New("use only one of --password, --password-file, or MOCK_FV_PASSWORD")
		}
		data, err := readSecretFile(*passwordFile)
		if err != nil {
			return fmt.Errorf("read password file: %w", err)
		}
		*password = strings.TrimRight(string(data), "\r\n")
	} else if envPassword := os.Getenv("MOCK_FV_PASSWORD"); envPassword != "" {
		if passwordFlagSet {
			return errors.New("use only one of --password or MOCK_FV_PASSWORD")
		}
		*password = envPassword
	} else if passwordFlagSet {
		log.Printf("WARNING: --password is visible in shell history and process listings")
	}
	if *password == "" {
		return errors.New("password must not be empty")
	}
	return nil
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func passwordWasConfigured() bool {
	return flagWasSet("password") || *passwordFile != "" || os.Getenv("MOCK_FV_PASSWORD") != ""
}

func readSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > maxSecretFileSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSecretFileSize)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("permissions are too open; use mode 0600")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSecretFileSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSecretFileSize)
	}
	return data, nil
}

func isLoopbackBind(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadAuthorizedPublicKey(path string) (ssh.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (ssh.PublicKey, error) {
		_ = file.Close()
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return fail(fmt.Errorf("not a stable regular file: %s", path))
	}
	if openedInfo.Size() > maxSecretFileSize {
		return fail(fmt.Errorf("file exceeds %d bytes", maxSecretFileSize))
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSecretFileSize+1))
	if err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if len(data) > maxSecretFileSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSecretFileSize)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return key, nil
}

type protocolState struct {
	mu       sync.RWMutex
	unlocked bool
}

func (s *protocolState) isUnlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unlocked
}

func (s *protocolState) setUnlocked() {
	s.mu.Lock()
	s.unlocked = true
	s.mu.Unlock()
}

// serverConfig builds the SSH server configuration modeling the FileVault
// pre-boot behavior. Tests call this directly so the executable and protocol
// checks cannot drift apart.
func serverConfig(hostKey ssh.Signer) *ssh.ServerConfig {
	runtimeState := &protocolState{unlocked: *state == "unlocked"}
	expectedUsername := *username
	expectedPassword := *password
	lockedBanner := lockedExplanation()
	successBanner := *successMsg
	shouldTransition := *transition
	acceptedPublicKey := unlockedPublicKey
	verboseLogging := *verbose

	cfg := &ssh.ServerConfig{
		ServerVersion: fmt.Sprintf("SSH-2.0-%s", *serverVersion),
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if expectedUsername != "" && conn.User() != expectedUsername {
				return nil, fmt.Errorf("invalid username")
			}
			// authorized_keys lives on the locked data volume, so public keys can
			// only work after the mock enters its booted/unlocked state.
			if !runtimeState.isUnlocked() {
				return nil, fmt.Errorf("publickey not accepted while locked")
			}
			if acceptedPublicKey != nil && !bytes.Equal(acceptedPublicKey.Marshal(), key.Marshal()) {
				return nil, fmt.Errorf("publickey not authorized")
			}
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(conn ssh.ConnMetadata, supplied []byte) (*ssh.Permissions, error) {
			if expectedUsername != "" && conn.User() != expectedUsername {
				return nil, fmt.Errorf("invalid username")
			}
			if runtimeState.isUnlocked() && bytes.Equal(supplied, []byte(expectedPassword)) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password not accepted")
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if expectedUsername != "" && conn.User() != expectedUsername {
				return nil, fmt.Errorf("invalid username")
			}
			if runtimeState.isUnlocked() {
				// A booted password-only sshd presents the same generic question as
				// prompt-only pre-boot. A no-password status probe must remain
				// indeterminate unless a public key above authenticates.
				answers, err := challenge("", "", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(answers) == 1 && answers[0] == expectedPassword {
					return &ssh.Permissions{}, nil
				}
				return nil, fmt.Errorf("permission denied")
			}
			// Locked: prompt for the password.
			answers, err := challenge("", lockedBanner, []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) == 1 && answers[0] == expectedPassword {
				if verboseLogging {
					log.Printf("correct password for %q; sending success banner and disconnecting", conn.User())
				}
				// Emit the success text as an info-only instruction, then fail
				// auth so the connection closes, as it does on the real device.
				_, _ = challenge("", successBanner, nil, nil)
				if shouldTransition {
					runtimeState.setUnlocked()
				}
				return nil, errUnlocked
			}
			if verboseLogging {
				log.Printf("incorrect password for %q", conn.User())
			}
			return nil, fmt.Errorf("permission denied")
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg
}

func lockedExplanation() string {
	if *promptOnly {
		return ""
	}
	return *bannerMsg
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, channels, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		// Expected in the locked state: auth fails after the success banner (or
		// on a wrong password).
		if *verbose {
			log.Printf("handshake ended for %s: %q", conn.RemoteAddr(), err.Error())
		}
		return
	}
	defer sshConn.Close()

	// Unlocked state: emulate a booted host. Discard requests and reject
	// channels; the client only needs the handshake to complete.
	go ssh.DiscardRequests(reqs)
	for newChannel := range channels {
		_ = newChannel.Reject(ssh.Prohibited, "no shell provided by mock")
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		fmt.Printf("Host key not found; generating a new ed25519 key at %q...\n", path)
		return generateAndSaveHostKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect host key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("host key is not a regular file: %s", path)
	}
	if info.Size() > maxSecretFileSize {
		return nil, fmt.Errorf("host key exceeds %d bytes", maxSecretFileSize)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure host key: %w", err)
	}
	privateBytes, err := readSecretFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key: %v", err)
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func generateAndSaveHostKey(path string) (ssh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %v", err)
	}
	privateKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 key: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return loadOrGenerateHostKey(path)
		}
		return nil, fmt.Errorf("create host key: %w", err)
	}
	written, closed := false, false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(pem.EncodeToMemory(privateKeyPEM)); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync host key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close host key: %w", err)
	}
	closed = true
	written = true
	return ssh.NewSignerFromKey(privateKey)
}

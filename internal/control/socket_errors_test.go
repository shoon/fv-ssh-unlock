// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestListenReplacesProvenStaleSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are tested on Unix")
	}
	path := privateSocketPath(t)
	raw, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unix, ok := raw.(*net.UnixListener)
	if !ok {
		_ = raw.Close()
		t.Fatalf("listener type = %T", raw)
	}
	unix.SetUnlinkOnClose(false)
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket setup failed: info=%v err=%v", info, err)
	}
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("proven stale socket was not replaced: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenRejectsUnsafeDirectoryShapes(t *testing.T) {
	root := t.TempDir()
	directoryFile := filepath.Join(root, "directory-file")
	if err := os.WriteFile(directoryFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := Listen(filepath.Join(directoryFile, "control.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("regular file was accepted as the socket directory")
	}
	if runtime.GOOS == "windows" {
		return
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "private-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if listener, err := Listen(filepath.Join(link, "control.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("symlink was accepted as the socket directory")
	}
}

func TestDoJSONReportsEncodeAndReadFailures(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       failingResponseBody{},
		}, nil
	})}
	if err := DoJSON(context.Background(), client, http.MethodGet, "/v1/test", nil, &struct{}{}); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("response read error = %v", err)
	}
	if err := DoJSON(context.Background(), client, http.MethodPost, "/v1/test", make(chan int), nil); err == nil {
		t.Fatal("unencodable request body was accepted")
	}
}

type failingResponseBody struct{}

func (failingResponseBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingResponseBody) Close() error             { return nil }

func TestCleanupListenerReportsRemovalFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonempty")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	listener := &cleanupListener{Listener: stubListener{}, path: path}
	if err := listener.Close(); err == nil {
		t.Fatal("socket cleanup removal failure was hidden")
	}
}

var _ io.ReadCloser = failingResponseBody{}

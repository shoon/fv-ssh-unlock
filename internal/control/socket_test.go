// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestListenAndGetJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket permissions are tested on Unix")
	}
	path := privateSocketPath(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enroll" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"created":true}`)
			return
		}
		if r.URL.Path != "/v1/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})}
	go server.Serve(listener)
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		_ = listener.Close()
	})

	var response struct {
		OK bool `json:"ok"`
	}
	if err := GetJSON(context.Background(), Client(path, time.Second), "/v1/health", &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatal("unexpected health response")
	}
	var created struct {
		Created bool `json:"created"`
	}
	if err := DoJSON(context.Background(), Client(path, time.Second), http.MethodPost, "/v1/enroll", map[string]string{"name": "mac"}, &created); err != nil {
		t.Fatal(err)
	}
	if !created.Created {
		t.Fatal("201 response was not decoded")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("socket permissions too broad: %v", info.Mode())
	}
}

func TestListenRefusesRegularFileAndRelativePath(t *testing.T) {
	if _, err := Listen("relative.sock"); err == nil {
		t.Fatal("expected relative path rejection")
	}
	path := privateSocketPath(t)
	if err := os.WriteFile(path, []byte("do not delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("expected regular-file rejection")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "do not delete" {
		t.Fatalf("regular file changed: %q, %v", data, err)
	}
}

func TestListenRefusesLiveSocketWithoutUnlinkingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are tested on Unix")
	}
	path := privateSocketPath(t)
	first, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Listen(path); err == nil {
		_ = second.Close()
		t.Fatal("second listener replaced an active control socket")
	}
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("original control socket was no longer reachable: %v", err)
	}
	_ = connection.Close()
}

func privateSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "fvu-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "control.sock")
}

func TestListenDoesNotChmodSharedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions are tested on Unix")
	}
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	if listener, err := Listen(path); err == nil {
		_ = listener.Close()
		t.Fatal("listener accepted a group/world-accessible directory")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("Listen changed shared directory permissions to %o", info.Mode().Perm())
	}
}

func TestDoJSONRejectsOversizedAndTrailingResponses(t *testing.T) {
	for name, response := range map[string]string{
		"oversized": `{"ok":true,"padding":"` + strings.Repeat("x", maxResponseSize) + `"}`,
		"trailing":  `{"ok":true} {"extra":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     http.StatusText(http.StatusOK),
					Body:       io.NopCloser(strings.NewReader(response)),
				}, nil
			})}
			var decoded struct {
				OK bool `json:"ok"`
			}
			if err := GetJSON(context.Background(), client, "/v1/test", &decoded); err == nil {
				t.Fatal("expected malformed response to be rejected")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

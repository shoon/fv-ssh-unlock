// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
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
	go func() { _ = server.Serve(listener) }()
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
	defer func() { _ = first.Close() }()
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

func TestClientUsesOnlyUnixSocketTransport(t *testing.T) {
	client := Client("/private/test/control.sock", 3*time.Second)
	if client.Timeout != 3*time.Second {
		t.Fatalf("client timeout = %s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || !transport.DisableKeepAlives || transport.DialContext == nil {
		t.Fatalf("unexpected control transport: %#v", client.Transport)
	}
}

func TestDoJSONEncodesRequestsAndHandlesStatusErrors(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.URL.Path != "/v1/test" {
				t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
			}
			if request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("content type = %q", request.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "{\"message\":\"\\u003ctag\\u003e\"}\n" {
				t.Fatalf("encoded body = %q", body)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Body: io.NopCloser(strings.NewReader(""))}, nil
		})}
		if err := DoJSON(context.Background(), client, http.MethodPost, "/v1/test", map[string]string{"message": "<tag>"}, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("status", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusConflict,
				Status:     "409 Conflict",
				Body:       io.NopCloser(strings.NewReader("already exists")),
			}, nil
		})}
		err := GetJSON(context.Background(), client, "/v1/test", &struct{}{})
		if err == nil || !strings.Contains(err.Error(), "409 Conflict") || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("status error = %v", err)
		}
	})

	t.Run("transport", func(t *testing.T) {
		want := errors.New("transport unavailable")
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, want
		})}
		if err := GetJSON(context.Background(), client, "/v1/test", &struct{}{}); !errors.Is(err, want) {
			t.Fatalf("transport error = %v", err)
		}
	})
}

func TestDoJSONRejectsUnknownFieldsAndInvalidEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"ok":true,"extra":true}`)),
		}, nil
	})}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := GetJSON(context.Background(), client, "/v1/test", &decoded); err == nil {
		t.Fatal("unknown response field was accepted")
	}
	if err := GetJSON(context.Background(), client, "/bad\nendpoint", &decoded); err == nil {
		t.Fatal("invalid endpoint was accepted")
	}
}

type stubListener struct {
	closeErr error
}

func (stubListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (l stubListener) Close() error            { return l.closeErr }
func (stubListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestCleanupListenerRemovesSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	listener := &cleanupListener{Listener: stubListener{}, path: path}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup path still exists: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("repeated cleanup failed: %v", err)
	}
	want := errors.New("listener close failed")
	listener = &cleanupListener{Listener: stubListener{closeErr: want}, path: filepath.Join(t.TempDir(), "missing.sock")}
	if err := listener.Close(); !errors.Is(err, want) {
		t.Fatalf("Close error = %v, want %v", err, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shoon/fv-ssh-unlock/internal/control"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

func startCommandControlServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the local control transport uses Unix domain sockets")
	}
	directory, err := os.MkdirTemp("", "fvu-control-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.sock")
	listener, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("control test server did not stop")
		}
	})
	return path
}

func TestDefaultControlSocketHonorsAndValidatesEnvironment(t *testing.T) {
	t.Run("absolute environment override", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "..", "daemon.sock")
		t.Setenv("FV_SSH_UNLOCK_SOCKET", path)
		got, err := defaultControlSocket()
		if err != nil || got != filepath.Clean(path) {
			t.Fatalf("default socket = %q, %v", got, err)
		}
	})
	t.Run("relative environment override", func(t *testing.T) {
		t.Setenv("FV_SSH_UNLOCK_SOCKET", "relative.sock")
		if _, err := defaultControlSocket(); err == nil {
			t.Fatal("relative environment socket was accepted")
		}
	})
	t.Run("data directory default", func(t *testing.T) {
		t.Setenv("FV_SSH_UNLOCK_SOCKET", "")
		old := dataDirOverride
		dataDirOverride = t.TempDir()
		t.Cleanup(func() { dataDirOverride = old })
		got, err := defaultControlSocket()
		if err != nil || got != filepath.Join(dataDirOverride, "control.sock") {
			t.Fatalf("default socket = %q, %v", got, err)
		}
	})
}

func TestHealthcheckCommandUsesLocalControlSocket(t *testing.T) {
	started := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	path := startCommandControlServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/health" {
			http.NotFound(w, request)
			return
		}
		_ = json.NewEncoder(w).Encode(healthResponse{
			SchemaVersion: controlAPISchemaVersion, OK: true, StartedAt: started, CheckedAt: time.Now().UTC(), Version: version,
		})
	}))

	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"--socket", path}, want: "healthy\n"},
		{args: []string{"--socket", path, "--json"}, want: `"ok":true`},
	} {
		cmd := newHealthcheckCommand()
		cmd.SetArgs(test.args)
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), test.want) {
			t.Fatalf("health output = %q, want %q", output.String(), test.want)
		}
	}
}

func TestHealthcheckCommandRejectsInvalidFlagsAndUnhealthyDaemon(t *testing.T) {
	for name, args := range map[string][]string{
		"relative socket": {"--socket", "relative.sock"},
		"zero timeout":    {"--socket", "/tmp/fvu-test.sock", "--timeout", "0s"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newHealthcheckCommand()
			cmd.SetArgs(args)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid healthcheck flags were accepted")
			}
		})
	}

	path := startCommandControlServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprint(w, `{"schema_version":1,"ok":false}`); err != nil {
			t.Error(err)
		}
	}))
	cmd := newHealthcheckCommand()
	cmd.SetArgs([]string{"--socket", path})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("unhealthy daemon result = %v", err)
	}

	wrongSchemaPath := startCommandControlServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprint(w, `{"schema_version":99,"ok":true}`); err != nil {
			t.Error(err)
		}
	}))
	cmd = newHealthcheckCommand()
	cmd.SetArgs([]string{"--socket", wrongSchemaPath})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported daemon API schema 99") {
		t.Fatalf("unsupported daemon schema result = %v", err)
	}
}

func TestCredentialsProvidersCommandRendersJSONAndText(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		cmd := newCredentialsCommand()
		args := []string{"providers"}
		if jsonOutput {
			args = append(args, "--json")
		}
		cmd.SetArgs(args)
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if jsonOutput {
			var response struct {
				Providers []credentials.ProviderReport `json:"providers"`
			}
			if err := json.Unmarshal(output.Bytes(), &response); err != nil || len(response.Providers) == 0 {
				t.Fatalf("provider JSON = %q, %v", output.String(), err)
			}
		} else if !strings.Contains(output.String(), "Credential providers for") || !strings.Contains(output.String(), "SECURITY") {
			t.Fatalf("provider text = %q", output.String())
		}
	}
}

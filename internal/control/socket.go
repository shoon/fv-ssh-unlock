// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Package control provides the daemon's local-only HTTP transport over a Unix
// domain socket. It deliberately does not expose a TCP listener.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maxResponseSize = 4 << 20

// Listen creates a permission-restricted Unix socket. A stale socket may be
// replaced, but regular files and symbolic links are never removed.
func Listen(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("control socket path must be absolute")
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("control socket directory is not a secure directory: %s", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("control socket directory must not be accessible by group or other users: %s", dir)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket control path: %s", path)
		}
		connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("control socket is already in use: %s", path)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !os.IsNotExist(dialErr) {
			return nil, fmt.Errorf("refusing to replace control socket that cannot be proven stale: %s: %w", path, dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &cleanupListener{Listener: listener, path: path}, nil
}

type cleanupListener struct {
	net.Listener
	path string
}

func (l *cleanupListener) Close() error {
	err := l.Listener.Close()
	if removeErr := os.Remove(l.path); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
		err = removeErr
	}
	return err
}

// Client returns an HTTP client whose only transport is the specified Unix
// socket. Proxy environment variables and TCP fallback are not used.
func Client(socket string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// GetJSON fetches one versioned control endpoint into dst.
func GetJSON(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	return DoJSON(ctx, client, http.MethodGet, endpoint, nil, dst)
}

// DoJSON invokes one control endpoint with an optional JSON request and
// decodes its bounded JSON response.
func DoJSON(ctx context.Context, client *http.Client, method, endpoint string, src, dst any) error {
	var body io.Reader
	if src != nil {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(src); err != nil {
			return err
		}
		body = &encoded
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+endpoint, body)
	if err != nil {
		return err
	}
	if src != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control API %s: %s: %s", endpoint, resp.Status, message)
	}
	if dst != nil {
		content, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
		if err != nil {
			return err
		}
		if len(content) > maxResponseSize {
			return fmt.Errorf("control API response exceeds %d bytes", maxResponseSize)
		}
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(dst); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return fmt.Errorf("control API response contains trailing data")
		}
	}
	return nil
}

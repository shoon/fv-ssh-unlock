// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

// Package credentials provides access to stored credentials.
package credentials

import (
	"fmt"
	"os"
	"strings"
)

// ID returns the stable credential identifier for a configured device.
func ID(deviceName string) string {
	return "fvu-" + deviceName
}

// EnvName returns the environment variable used for a credential identifier.
func EnvName(name string) string {
	name = strings.TrimPrefix(strings.ToLower(name), "fvu-")
	var b strings.Builder
	b.WriteString("FV_UNLOCK_PASSWORD_")
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// GetEnvironment retrieves a credential from its canonical environment
// variable. It is available in both build variants so a keyring-enabled binary
// can still honor devices explicitly configured for runtime credentials.
func GetEnvironment(name string) (string, error) {
	env := EnvName(name)
	if value := os.Getenv(env); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("credential not found in env var %s", env)
}

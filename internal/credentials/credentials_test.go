//go:build !keyring
// +build !keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"os"
	"strings"
	"testing"
)

func TestGetEnvCredential(t *testing.T) {
	os.Setenv("FV_UNLOCK_PASSWORD_TESTDEVICE", "supersecret")
	pw, err := Get("testdevice")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if pw != "supersecret" {
		t.Fatalf("expected 'supersecret', got %q", pw)
	}
}

func TestGetEnvCredentialNotSet(t *testing.T) {
	os.Unsetenv("FV_UNLOCK_PASSWORD_NODEVICE")
	_, err := Get("nodevice")
	if err == nil || !strings.Contains(err.Error(), "FV_UNLOCK_PASSWORD_NODEVICE") {
		t.Fatalf("expected error for missing env var, got %v", err)
	}
}

func TestEnvName(t *testing.T) {
	if got := EnvName(ID("my-mac")); got != "FV_UNLOCK_PASSWORD_MY_MAC" {
		t.Fatalf("unexpected environment variable: %s", got)
	}
}

func TestEnvNameCanonicalCollisionIsVisible(t *testing.T) {
	if EnvName(ID("my-mac")) != EnvName(ID("my_mac")) {
		t.Fatalf("expected normalized names to collide so config validation can reject them")
	}
}

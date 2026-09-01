//go:build !keyring
// +build !keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"errors"
	"strings"
	"testing"
)

func TestGetEnvCredential(t *testing.T) {
	t.Setenv("FV_UNLOCK_PASSWORD_TESTDEVICE", "supersecret")
	pw, err := Get("testdevice")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if pw != "supersecret" {
		t.Fatalf("expected 'supersecret', got %q", pw)
	}
}

func TestGetEnvCredentialNotSet(t *testing.T) {
	t.Setenv("FV_UNLOCK_PASSWORD_NODEVICE", "")
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

func TestDisabledKeyringMutationMethods(t *testing.T) {
	if CanStore() {
		t.Fatal("non-keyring build reported persistent storage")
	}
	if err := Set("device", "secret"); err == nil {
		t.Fatal("Set unexpectedly succeeded without keyring support")
	}
	if err := Delete("device"); err == nil {
		t.Fatal("Delete unexpectedly succeeded without keyring support")
	}
	provider, err := NewRegistry(Options{}).Provider(ProviderKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get("device"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("keyring Get error = %v, want ErrProviderUnavailable", err)
	}
	if err := provider.Store("device", "secret"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("keyring Store error = %v, want ErrProviderUnavailable", err)
	}
	if err := provider.Delete("device"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("keyring Delete error = %v, want ErrProviderUnavailable", err)
	}
	assessment := provider.Assess("device")
	if assessment.Available || assessment.Secure || assessment.Details == "" {
		t.Fatalf("disabled keyring assessment = %+v", assessment)
	}
}

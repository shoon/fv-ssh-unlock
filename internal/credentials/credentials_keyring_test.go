//go:build keyring
// +build keyring

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"fmt"
	"testing"
	"time"
)

func TestEnvironmentCredentialInKeyringBuild(t *testing.T) {
	t.Setenv("FV_UNLOCK_PASSWORD_RUNTIME_DEVICE", "runtime-secret")
	password, err := GetEnvironment("fvu-runtime-device")
	if err != nil {
		t.Fatal(err)
	}
	if password != "runtime-secret" {
		t.Fatal("unexpected environment credential")
	}
}

func TestKeyringCredentialRoundTrip(t *testing.T) {
	name := fmt.Sprintf("test-%d", time.Now().UnixNano())
	if err := Set(name, "supersecret"); err != nil {
		t.Fatalf("unexpected error setting credential: %v", err)
	}
	t.Cleanup(func() {
		if err := Delete(name); err != nil {
			t.Errorf("clean up keyring credential: %v", err)
		}
	})

	pw, err := Get(name)
	if err != nil {
		t.Fatalf("unexpected error getting credential: %v", err)
	}
	if pw != "supersecret" {
		t.Fatalf("unexpected password returned")
	}
}

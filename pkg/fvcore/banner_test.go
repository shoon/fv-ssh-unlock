// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package fvcore

import (
	"strings"
	"testing"
)

// realLockedBanner is the verbatim macOS 26 pre-boot banner, wrapped exactly as
// the device sends it. The words in "Once successfully\nunlocked" are adjacent
// across a line break.
const realLockedBanner = "This system is locked. To unlock it, use a local\r\n" +
	"account name and password. Once successfully\r\n" +
	"unlocked, you will be able to connect normally."

// realSuccessBanner is the verbatim macOS 26 success banner.
const realSuccessBanner = "System successfully unlocked.\r\n" +
	"You may now use SSH to authenticate normally.\r\n"

// TestLockedBannerIsNeverSuccess is a regression test for a subtle and
// dangerous failure mode: the LOCKED banner contains the words "successfully"
// and "unlocked" adjacent to each other (separated only by a line break). A
// naive match on "successfully unlocked" would classify a still-locked device
// as unlocked as soon as the wrapping changed.
func TestLockedBannerIsNeverSuccess(t *testing.T) {
	variants := map[string]string{
		"as sent (CRLF wrapped)": realLockedBanner,
		"unix newlines":          strings.ReplaceAll(realLockedBanner, "\r\n", "\n"),
		"rewrapped to one line":  strings.Join(strings.Fields(realLockedBanner), " "),
		"collapsed whitespace":   strings.ReplaceAll(strings.ReplaceAll(realLockedBanner, "\r\n", " "), "  ", " "),
	}
	for name, banner := range variants {
		t.Run(name, func(t *testing.T) {
			if successSeen(banner, "") {
				t.Errorf("locked banner was classified as a successful unlock")
			}
			if got := ParseOutput(banner); got != StatusLocked {
				t.Errorf("ParseOutput(locked banner) = %v, want StatusLocked", got)
			}
			if !lockedSeen(banner) {
				t.Errorf("lockedSeen() failed to recognize the locked banner")
			}
			if !IsFileVaultLockedBanner(banner) {
				t.Errorf("IsFileVaultLockedBanner() failed to recognize the locked banner")
			}
		})
	}
}

func TestSuccessBannerIsRecognized(t *testing.T) {
	variants := map[string]string{
		"as sent (CRLF)":        realSuccessBanner,
		"unix newlines":         strings.ReplaceAll(realSuccessBanner, "\r\n", "\n"),
		"rewrapped to one line": strings.Join(strings.Fields(realSuccessBanner), " "),
	}
	for name, banner := range variants {
		t.Run(name, func(t *testing.T) {
			if !successSeen(banner, "") {
				t.Errorf("success banner was not recognized")
			}
			if got := ParseOutput(banner); got != StatusUnlocked {
				t.Errorf("ParseOutput(success banner) = %v, want StatusUnlocked", got)
			}
		})
	}
}

func TestGenericLockedNoticeIsNotAFileVaultFingerprint(t *testing.T) {
	for _, output := range []string{"System is locked", "Password:", "This system is locked by an administrator"} {
		if IsFileVaultLockedBanner(output) {
			t.Errorf("generic SSH text %q was treated as the complete FileVault banner", output)
		}
	}
}

// TestFullSessionTranscript models what the client accumulates during a
// real unlock: the locked banner first, then the success banner. Success must
// win.
func TestFullSessionTranscript(t *testing.T) {
	full := realLockedBanner + "\n(user@host) Password:\n" + realSuccessBanner
	if !successSeen(full, "") {
		t.Fatalf("a full successful session must be classified as success")
	}
	if got := ParseOutput(full); got != StatusUnlocked {
		t.Errorf("ParseOutput(full session) = %v, want StatusUnlocked", got)
	}
}

// TestCustomSuccessMessageCannotForgeSuccess ensures a short or locked-banner-
// matching custom success message cannot be used to fake an unlock.
func TestCustomSuccessMessageCannotForgeSuccess(t *testing.T) {
	cases := []struct {
		name       string
		successMsg string
	}{
		{"single letter", "a"},
		{"short word", "the"},
		{"empty", ""},
		{"whitespace only", "   "},
		{"substring of the locked banner", "this system is locked"},
		{"another locked-banner substring", "you will be able to connect normally"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if successSeen(realLockedBanner, c.successMsg) {
				t.Errorf("custom success message %q forged a success from the locked banner", c.successMsg)
			}
		})
	}
}

// TestCustomSuccessMessageStillWorks confirms a legitimate custom marker is
// honored (e.g. for a localized or customized deployment).
func TestCustomSuccessMessageStillWorks(t *testing.T) {
	out := "Das System wurde erfolgreich entsperrt."
	if !successSeen(out, "erfolgreich entsperrt") {
		t.Errorf("a legitimate custom success message was not honored")
	}
	// ...and it must not fire on unrelated text.
	if successSeen(realLockedBanner, "erfolgreich entsperrt") {
		t.Errorf("custom success message matched unrelated text")
	}
}

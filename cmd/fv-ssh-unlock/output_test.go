// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"strings"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/config"
)

func TestTerminalSafeEscapesNetworkControlledText(t *testing.T) {
	in := "device\x1b]52;c;Y2xpcGJvYXJk\a\nspoof\u202e"
	inline := terminalSafeInline(in)
	if strings.ContainsAny(inline, "\x1b\a\n") || strings.ContainsRune(inline, '\u202e') {
		t.Fatalf("inline output retained a control character: %q", inline)
	}
	multiline := terminalSafeMultiline(in)
	if !strings.Contains(multiline, "\n") || strings.ContainsAny(multiline, "\x1b\a") {
		t.Fatalf("multiline sanitization failed: %q", multiline)
	}
}

func TestTerminalSafeInlineEscapesLogForgingLineBreaks(t *testing.T) {
	got := terminalSafeInline("trusted\r\nlevel=ERROR msg=forged\nnext")
	want := `trusted\u000D\u000Alevel=ERROR msg=forged\u000Anext`
	if got != want {
		t.Fatalf("terminalSafeInline() = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("terminalSafeInline() retained a record separator: %q", got)
	}
}

func TestTerminalSafeMultilineNormalizesCarriageReturns(t *testing.T) {
	got := terminalSafeMultiline("first\r\nsecond\roverwrite")
	want := "first\nsecond\\u000Doverwrite"
	if got != want {
		t.Fatalf("terminalSafeMultiline() = %q, want %q", got, want)
	}
}

func TestDeviceIdentifiersAndIPv6Endpoint(t *testing.T) {
	device := config.Device{Name: "my-mac", Host: "2001:db8::1", Port: 22}
	if got := deviceCredentialID(device); got != "fvu-my-mac" {
		t.Fatalf("legacy empty credential ID resolved to %q", got)
	}
	if got := deviceEndpoint(device); got != "[2001:db8::1]:22" {
		t.Fatalf("IPv6 endpoint = %q", got)
	}
}

func TestReadYes(t *testing.T) {
	for _, input := range []string{"y\n", "Y\n", "y"} {
		confirmed, err := readYes(strings.NewReader(input))
		if err != nil || !confirmed {
			t.Fatalf("readYes(%q) = %v, %v", input, confirmed, err)
		}
	}
	for _, input := range []string{"\n", "n\n", ""} {
		confirmed, err := readYes(strings.NewReader(input))
		if err != nil || confirmed {
			t.Fatalf("readYes(%q) = %v, %v", input, confirmed, err)
		}
	}
}

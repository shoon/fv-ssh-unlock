// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"fmt"
	"strings"
	"unicode"
)

func terminalSafeInline(s string) string {
	return terminalSafe(s, false)
}

func terminalSafeMultiline(s string) string {
	return terminalSafe(s, true)
}

// terminalSafe makes control and formatting characters visible instead of
// emitting them to the user's terminal. This protects discovery output and SSH
// banners, both of which contain network-controlled text.
func terminalSafe(s string, multiline bool) string {
	// Preserve line-oriented output without emitting a bare carriage return,
	// which can move the cursor back and visually overwrite prior text.
	if multiline {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	var b strings.Builder
	for _, r := range s {
		if multiline && (r == '\n' || r == '\t') {
			b.WriteRune(r)
			continue
		}
		if unicode.Is(unicode.Categories["C"], r) {
			if r <= 0xffff {
				fmt.Fprintf(&b, "\\u%04X", r)
			} else {
				fmt.Fprintf(&b, "\\U%08X", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

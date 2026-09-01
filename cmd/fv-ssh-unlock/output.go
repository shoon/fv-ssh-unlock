// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Terminal redraws and progress messages are best effort. Once their writer is
// gone there is no recovery action the command can take, so these helpers make
// that policy explicit without relying on linter exclusions tied to variable
// names.
func terminalWrite(writer io.Writer, values ...any) {
	_, _ = fmt.Fprint(writer, values...)
}

func terminalWriteLine(writer io.Writer, values ...any) {
	_, _ = fmt.Fprintln(writer, values...)
}

func terminalWritef(writer io.Writer, format string, values ...any) {
	_, _ = fmt.Fprintf(writer, format, values...)
}

func terminalSafeInline(s string) string {
	// Keep these explicit replacements before the general Unicode-control
	// escaping below. Besides making the single-record invariant obvious, the
	// standard-library sanitizer is recognized by static log-injection checks.
	// The visible replacements match terminalSafe's existing rendering, so
	// callers do not see a formatting change.
	s = strings.ReplaceAll(s, "\n", `\u000A`)
	s = strings.ReplaceAll(s, "\r", `\u000D`)
	return terminalSafe(s, false)
}

func terminalSafeError(err error) string {
	if err == nil {
		return ""
	}
	return terminalSafeInline(err.Error())
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

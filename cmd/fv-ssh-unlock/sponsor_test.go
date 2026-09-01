// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestShouldPrintSponsorFooter(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		terminal   bool
		jsonOutput bool
		once       bool
		want       bool
	}{
		{name: "human terminal", mode: sponsorFooterHuman, terminal: true, want: true},
		{name: "redirected human output", mode: sponsorFooterHuman, terminal: false},
		{name: "unmarked command", terminal: true},
		{name: "JSON output", mode: sponsorFooterHuman, terminal: true, jsonOutput: true},
		{name: "interactive TUI", mode: sponsorFooterInteractiveTUI, terminal: true, want: true},
		{name: "one-shot TUI", mode: sponsorFooterInteractiveTUI, terminal: true, once: true},
		{name: "unknown mode", mode: "unknown", terminal: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			if tt.mode != "" {
				cmd.Annotations = map[string]string{sponsorFooterAnnotation: tt.mode}
			}
			cmd.Flags().Bool("json", false, "")
			cmd.Flags().Bool("once", false, "")
			if tt.jsonOutput {
				if err := cmd.Flags().Set("json", "true"); err != nil {
					t.Fatal(err)
				}
			}
			if tt.once {
				if err := cmd.Flags().Set("once", "true"); err != nil {
					t.Fatal(err)
				}
			}

			if got := shouldPrintSponsorFooter(cmd, tt.terminal); got != tt.want {
				t.Fatalf("shouldPrintSponsorFooter() = %v, want %v", got, tt.want)
			}
		})
	}

	if shouldPrintSponsorFooter(nil, true) {
		t.Fatal("nil command should not print a sponsor footer")
	}
}

func TestSponsorFooterIsShortAndIdentifiesTheSponsor(t *testing.T) {
	var output bytes.Buffer
	writeSponsorFooter(&output)

	want := "\nSupport fv-ssh-unlock by sponsoring @shoon: " + sponsorURL + "\n"
	if got := output.String(); got != want {
		t.Fatalf("writeSponsorFooter() = %q, want %q", got, want)
	}
	if lines := strings.Count(output.String(), "\n"); lines != 2 {
		t.Fatalf("sponsor footer contains %d newline characters, want 2", lines)
	}
}

func TestSponsorPostRunDoesNotWriteToRedirectedOutput(t *testing.T) {
	cmd := &cobra.Command{
		Use:         "test",
		Annotations: map[string]string{sponsorFooterAnnotation: sponsorFooterHuman},
	}
	var output bytes.Buffer
	cmd.SetOut(&output)

	sponsorPostRun(cmd, nil)
	if output.Len() != 0 {
		t.Fatalf("redirected output received sponsor footer: %q", output.String())
	}
}

func TestHumanFacingCommandsOptInToSponsorFooter(t *testing.T) {
	providers, _, err := newCredentialsCommand().Find([]string{"providers"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		cmd  *cobra.Command
		mode string
	}{
		{name: "credentials providers", cmd: providers, mode: sponsorFooterHuman},
		{name: "discover", cmd: newDiscoverCommand(), mode: sponsorFooterHuman},
		{name: "scan", cmd: newScanCommand(), mode: sponsorFooterHuman},
		{name: "TUI", cmd: newTUICommand(), mode: sponsorFooterInteractiveTUI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cmd.Annotations[sponsorFooterAnnotation]; got != tt.mode {
				t.Fatalf("annotation = %q, want %q", got, tt.mode)
			}
		})
	}
}

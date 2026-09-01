// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	sponsorURL                  = "https://github.com/sponsors/shoon"
	sponsorFooterAnnotation     = "fv-ssh-unlock.io/sponsor-footer"
	sponsorFooterHuman          = "human"
	sponsorFooterInteractiveTUI = "interactive-tui"
)

func sponsorPostRun(cmd *cobra.Command, _ []string) {
	output := cmd.OutOrStdout()
	if shouldPrintSponsorFooter(cmd, terminalWriter(output)) {
		writeSponsorFooter(output)
	}
}

func shouldPrintSponsorFooter(cmd *cobra.Command, outputIsTerminal bool) bool {
	if cmd == nil || !outputIsTerminal {
		return false
	}
	mode := cmd.Annotations[sponsorFooterAnnotation]
	if mode == "" {
		return false
	}
	if flag := cmd.Flags().Lookup("json"); flag != nil {
		jsonOutput, err := cmd.Flags().GetBool("json")
		if err != nil || jsonOutput {
			return false
		}
	}
	if mode == sponsorFooterInteractiveTUI {
		once, err := cmd.Flags().GetBool("once")
		return err == nil && !once
	}
	return mode == sponsorFooterHuman
}

func terminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func writeSponsorFooter(writer io.Writer) {
	terminalWritef(writer, "\nSupport fv-ssh-unlock by sponsoring @shoon: %s\n", sponsorURL)
}

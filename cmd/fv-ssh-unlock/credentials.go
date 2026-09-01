// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/credentials"
)

func newCredentialsCommand() *cobra.Command {
	credentialsCmd := &cobra.Command{
		Use:     "credentials",
		Aliases: []string{"credential"},
		Short:   "Inspect credential providers and machine security capabilities",
	}

	providersCmd := &cobra.Command{
		Use:         "providers",
		Short:       "Report credential providers available on this machine",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{sponsorFooterAnnotation: sponsorFooterHuman},
		RunE: func(cmd *cobra.Command, _ []string) error {
			registry := credentials.NewRegistry(credentials.Options{})
			reports := registry.Reports()
			jsonOutput, _ := cmd.Flags().GetBool("json")
			requireSecure, _ := cmd.Flags().GetBool("require-secure")
			var err error
			if jsonOutput {
				err = writeProviderReportsJSON(cmd.OutOrStdout(), reports, registry.HasSecureStorage())
			} else {
				err = writeProviderReports(cmd.OutOrStdout(), reports, registry.HasSecureStorage())
			}
			if err != nil {
				return err
			}
			if requireSecure && !registry.HasSecureStorage() {
				return fmt.Errorf("no verified secure persistent credential provider or delivery mechanism is available")
			}
			return nil
		},
	}
	providersCmd.Flags().Bool("json", false, "Write a machine-readable JSON report")
	providersCmd.Flags().Bool("require-secure", false, "Exit unsuccessfully when no secure persistent provider or delivery mechanism is detected")
	credentialsCmd.AddCommand(providersCmd)
	return credentialsCmd
}

func writeProviderReports(w io.Writer, reports []credentials.ProviderReport, secureAvailable bool) error {
	if _, err := fmt.Fprintf(w, "Credential providers for %s/%s:\n", runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tBUILT\tAVAILABLE\tPERSISTENT\tSECURITY\tDETAILS"); err != nil {
		return err
	}
	for _, report := range reports {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			report.Name,
			yesNo(report.Built),
			yesNo(report.Available),
			yesNo(report.Persistent),
			report.Security,
			terminalSafeInline(report.Details)); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if secureAvailable {
		_, err := fmt.Fprintln(w, "\nSecure persistent credential storage or delivery is available in this execution environment.")
		return err
	}
	_, err := fmt.Fprintln(w, "\nNo verified secure persistent credential storage or delivery is currently available. Runtime-only credentials remain supported. Plaintext disk files are refused unless --allow-unsafe-credential-storage is passed for the command that uses them.")
	return err
}

func writeProviderReportsJSON(w io.Writer, reports []credentials.ProviderReport, secureAvailable bool) error {
	payload := struct {
		OS                     string                       `json:"os"`
		Arch                   string                       `json:"arch"`
		SecureStorageAvailable bool                         `json:"secure_storage_available"`
		Providers              []credentials.ProviderReport `json:"providers"`
	}{
		OS:                     runtime.GOOS,
		Arch:                   runtime.GOARCH,
		SecureStorageAvailable: secureAvailable,
		Providers:              reports,
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

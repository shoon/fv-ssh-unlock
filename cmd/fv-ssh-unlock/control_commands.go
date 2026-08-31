// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/control"
)

type healthResponse struct {
	SchemaVersion int       `json:"schema_version"`
	OK            bool      `json:"ok"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	CheckedAt     time.Time `json:"checked_at,omitempty"`
	Version       string    `json:"version,omitempty"`
}

func defaultControlSocket() (string, error) {
	if value := strings.TrimSpace(os.Getenv("FV_SSH_UNLOCK_SOCKET")); value != "" {
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("FV_SSH_UNLOCK_SOCKET must be an absolute path")
		}
		return filepath.Clean(value), nil
	}
	dir, err := appDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "control.sock"), nil
}

func newHealthcheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Check the local persistent daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			socket, _ := cmd.Flags().GetString("socket")
			if socket == "" {
				var err error
				socket, err = defaultControlSocket()
				if err != nil {
					return err
				}
			}
			if !filepath.IsAbs(socket) {
				return fmt.Errorf("--socket must be an absolute path")
			}
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than zero")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			var health healthResponse
			if err := control.GetJSON(ctx, control.Client(socket, timeout), "/v1/health", &health); err != nil {
				return err
			}
			if health.SchemaVersion != controlAPISchemaVersion {
				return fmt.Errorf("unsupported daemon API schema %d", health.SchemaVersion)
			}
			if !health.OK {
				return fmt.Errorf("daemon reported unhealthy")
			}
			if jsonOutput, _ := cmd.Flags().GetBool("json"); jsonOutput {
				return writeJSON(cmd.OutOrStdout(), health)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "healthy")
			return nil
		},
	}
	cmd.Flags().String("socket", "", "Daemon Unix socket (or FV_SSH_UNLOCK_SOCKET)")
	cmd.Flags().Duration("timeout", 3*time.Second, "Health-check timeout")
	cmd.Flags().Bool("json", false, "Emit a machine-readable JSON response")
	return cmd
}

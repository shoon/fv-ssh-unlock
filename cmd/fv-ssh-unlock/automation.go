// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/config"
)

const maxDeclarativeConfigSize = 1 << 20

type configApplyReport struct {
	SchemaVersion int      `json:"schema_version"`
	Changed       bool     `json:"changed"`
	CheckMode     bool     `json:"check_mode"`
	DeviceCount   int      `json:"device_count"`
	Added         []string `json:"added,omitempty"`
	Updated       []string `json:"updated,omitempty"`
	Removed       []string `json:"removed,omitempty"`
}

func newConfigExportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export the declarative device inventory as JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := configStore()
			if err != nil {
				return err
			}
			devices, err := store.Load()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			// #nosec G117 -- Device.Cred is a credential provider reference, never secret material; `config export` deliberately emits the full declarative inventory.
			return encoder.Encode(devices)
		},
	}
}

func newAutoUnlockConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auto-unlock NAME",
		Short: "Enable or disable automatic unlock for a configured device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enable, _ := cmd.Flags().GetBool("enable")
			disable, _ := cmd.Flags().GetBool("disable")
			if enable == disable {
				return errors.New("specify exactly one of --enable or --disable")
			}
			store, err := configStore()
			if err != nil {
				return err
			}
			devices, err := store.Load()
			if err != nil {
				return err
			}
			for _, device := range devices {
				if device.Name != args[0] {
					continue
				}
				device.AutoUnlock = enable
				if err := store.Update(device); err != nil {
					return err
				}
				state := "disabled"
				if enable {
					state = "enabled"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Automatic unlock %s for %q. Restart a running daemon to load this external configuration change; startup will fail closed unless the credential provider is secure and available.\n", state, terminalSafeInline(device.Name))
				return nil
			}
			return fmt.Errorf("device not found: %s", args[0])
		},
	}
	cmd.Flags().Bool("enable", false, "Allow the daemon to unlock this device after definitive FileVault detection")
	cmd.Flags().Bool("disable", false, "Require manual unlock for this device")
	return cmd
}

func newConfigApplyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply --file PATH",
		Short: "Reconcile the complete device inventory from JSON",
		Long: `Atomically replace the complete device inventory with a validated JSON array.
The document contains credential references, never credential values. Use --check
to report the changes without writing. JSON is also valid YAML and can be
generated directly by configuration-management tools such as Ansible.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("file")
			check, _ := cmd.Flags().GetBool("check")
			jsonOutput, _ := cmd.Flags().GetBool("json")
			if path == "" {
				return errors.New("--file is required")
			}
			input, err := readDeclarativeConfig(cmd.InOrStdin(), path)
			if err != nil {
				return err
			}
			var desired []config.Device
			decoder := json.NewDecoder(bytes.NewReader(input))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&desired); err != nil {
				return fmt.Errorf("decode device inventory: %w", err)
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				return errors.New("device inventory contains trailing data")
			}
			if err := config.ValidateDevices(desired); err != nil {
				return fmt.Errorf("validate device inventory: %w", err)
			}

			store, err := configStore()
			if err != nil {
				return err
			}
			current, err := store.Load()
			if err != nil {
				return err
			}
			report := compareDeviceInventories(current, desired)
			report.CheckMode = check
			if report.Changed && !check {
				if err := store.Save(desired); err != nil {
					return err
				}
			}
			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			}
			if !report.Changed {
				fmt.Fprintf(cmd.OutOrStdout(), "Device inventory already matches (%d device(s)).\n", len(desired))
			} else if check {
				fmt.Fprintf(cmd.OutOrStdout(), "Device inventory would change: +%d ~%d -%d.\n", len(report.Added), len(report.Updated), len(report.Removed))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Applied device inventory: +%d ~%d -%d.\n", len(report.Added), len(report.Updated), len(report.Removed))
			}
			return nil
		},
	}
	cmd.Flags().String("file", "", "JSON inventory path, or - for standard input")
	cmd.Flags().Bool("check", false, "Report changes without writing configuration")
	cmd.Flags().Bool("json", false, "Emit a stable machine-readable result")
	return cmd
}

func readDeclarativeConfig(stdin io.Reader, path string) ([]byte, error) {
	reader := stdin
	var file *os.File
	if path != "-" {
		var err error
		// #nosec G304 -- path is the operator-supplied declarative config file; opening it is the point of `config apply`.
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxDeclarativeConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDeclarativeConfigSize {
		return nil, fmt.Errorf("device inventory exceeds %d bytes", maxDeclarativeConfigSize)
	}
	return data, nil
}

func compareDeviceInventories(current, desired []config.Device) configApplyReport {
	report := configApplyReport{SchemaVersion: 1, DeviceCount: len(desired)}
	currentByName := make(map[string]config.Device, len(current))
	desiredByName := make(map[string]config.Device, len(desired))
	for _, device := range current {
		currentByName[device.Name] = device
	}
	for _, device := range desired {
		desiredByName[device.Name] = device
		old, exists := currentByName[device.Name]
		switch {
		case !exists:
			report.Added = append(report.Added, device.Name)
		case old != device:
			report.Updated = append(report.Updated, device.Name)
		}
	}
	for _, device := range current {
		if _, exists := desiredByName[device.Name]; !exists {
			report.Removed = append(report.Removed, device.Name)
		}
	}
	slices.Sort(report.Added)
	slices.Sort(report.Updated)
	slices.Sort(report.Removed)
	report.Changed = len(report.Added)+len(report.Updated)+len(report.Removed) > 0
	return report
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}

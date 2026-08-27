// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

var version = "dev"

const (
	defaultSuccessMessage = "System successfully unlocked.\r\nYou may now use SSH to authenticate normally.\r\n\r\n"
	rootLongHelp          = `fv-ssh-unlock manages and remotely unlocks FileVault-protected macOS devices
over SSH.

It drives the FileVault pre-boot SSH unlock feature introduced in macOS 26
(Tahoe) on Apple silicon: when Remote Login is enabled, the locked data volume
can be unlocked over SSH after a restart. Notes on observed server behavior:

  1. The pre-boot SSH server requires interactive password input; it does not
     use SSH keys.
  2. Some versions show a FileVault explanation before the hidden Password:
     prompt; others show only Password:. Either form can be unlocked, but a
     password-free status check is unknown when the explanation is absent.
  3. A successful unlock prints the success message and then disconnects.
  4. Bonjour discovery normally works while macOS is booted. FileVault pre-boot
     may answer TCP/22 without advertising Bonjour, so discover is not a port
     scan or a recovery-time locator. Record a stable address before restart;
     a DHCP reservation (static lease) is preferred.
  5. The scan command actively checks an explicit IPv4 CIDR without sending
     credentials. A full locked banner is distinctive; a generic Password:
     prompt remains indeterminate unless its host key matches a pinned target.

This behavior is specific to recent macOS versions and may change.

Examples:
  fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser --port 22
  fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
  fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
  fv-ssh-unlock unlock
  fv-ssh-unlock discover
  fv-ssh-unlock scan --cidr 192.168.1.0/24`
	addLongHelp = `Add a device to the local configuration file. Either the [name]
argument or --host is required. If name is omitted, the host value is used.

For reliable remote unlock, configure a predictable address before restarting
the Mac. Prefer a DHCP reservation (static lease). A manually assigned static
address is a fallback that must be tested for conflicts and pre-boot behavior.
Bonjour discovery and .local names are convenient while macOS is booted, but
FileVault pre-boot may not advertise Bonjour; do not rely on discover to recover
an address after restart.`
	unlockLongHelp = `Unlock configured devices by name using a credential from the
environment, OS keyring, or an interactive prompt. With no names, unlock every
configured device.

The FileVault explanation may be absent on recent macOS versions; an exact
hidden Password: prompt is still supported. SUCCESS means the trusted server
accepted the password. VERIFIED additionally requires normal macOS SSH to
accept a public key from ssh-agent or --identity. Use --identity for predictable
post-boot verification when no suitable key is loaded in ssh-agent.`
	statusLongHelp = `Probe configured devices without retrieving or transmitting the
unlock password. A FileVault explanation proves locked; successful public-key
authentication proves normal macOS has booted.

Some FileVault pre-boot versions show only Password:, which is indistinguishable
from a password-only booted SSH server without sending a secret. In that case
unknown is the safe, expected result. Load a key into ssh-agent or use --identity
to prove the booted state.`
	indeterminateStatusText = "unknown (reachable; prompt-only pre-boot or password-only SSH; use ssh-agent/--identity to prove booted)"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootCmd := &cobra.Command{
		Use:           "fv-ssh-unlock",
		Short:         "Unlock FileVault-protected macOS devices over SSH",
		Long:          rootLongHelp,
		Version:       version,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	// We handle our own messaging; don't let Cobra print usage on every error.
	rootCmd.SilenceUsage = true
	rootCmd.SetContext(ctx)

	cfgCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage device configuration",
	}

	addCmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a device",
		Long:  addLongHelp,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, _ := cmd.Flags().GetString("host")
			user, _ := cmd.Flags().GetString("user")

			if user == "" {
				return fmt.Errorf("user is required")
			}
			if len(args) == 0 && host == "" {
				return fmt.Errorf("either [name] argument or --host flag is required")
			}

			var name string
			if len(args) == 0 {
				name = host
			} else {
				name = args[0]
			}
			if host == "" {
				return fmt.Errorf("--host flag is required")
			}

			s, err := configStore()
			if err != nil {
				return err
			}
			devs, err := s.Load()
			if err != nil {
				return err
			}
			for _, ex := range devs {
				if ex.Name == name {
					return fmt.Errorf("device already exists: %s", name)
				}
			}

			port, _ := cmd.Flags().GetInt("port")
			if port < 1 || port > 65535 {
				return fmt.Errorf("--port must be between 1 and 65535")
			}
			successMsg, _ := cmd.Flags().GetString("success-message")
			if successMsg == "" {
				successMsg = defaultSuccessMessage
			}
			cred := credentials.ID(name)
			envName := credentials.EnvName(cred)
			for _, ex := range devs {
				if credentials.EnvName(deviceCredentialID(ex)) == envName {
					return fmt.Errorf("device name %q collides with %q in environment variable %s", name, ex.Name, envName)
				}
			}

			credentialSource := "runtime"
			credentialStored := false
			d := config.Device{Name: name, Host: host, User: user, Port: port, Cred: cred, CredentialSource: credentialSource, SuccessMessage: successMsg}
			if err := config.ValidateDevice(d); err != nil {
				return err
			}
			if credentials.CanStore() {
				fmt.Print("Store password in OS keychain? [y/N]: ")
				confirmed, err := readYes(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("read confirmation: %w", err)
				}
				if confirmed {
					fmt.Printf("Enter password for %s@%s: ", terminalSafeInline(user), terminalSafeInline(host))
					password, err := credentials.ReadPassword()
					if err != nil {
						return fmt.Errorf("error reading password: %w", err)
					}
					if password == "" {
						return fmt.Errorf("password must not be empty")
					}
					if err := credentials.Set(cred, password); err != nil {
						return fmt.Errorf("store password in keychain: %w", err)
					}
					credentialSource = "keyring"
					credentialStored = true
				} else {
					fmt.Println("Password not stored. It will be read from the environment or prompted at unlock time.")
				}
			} else {
				fmt.Printf("Password will be read from %s or prompted at unlock time.\n", terminalSafeInline(envName))
			}

			d.CredentialSource = credentialSource
			if err := s.Add(d); err != nil {
				if credentialStored {
					if deleteErr := credentials.Delete(cred); deleteErr != nil {
						return errors.Join(err, fmt.Errorf("roll back keychain credential: %w", deleteErr))
					}
				}
				return err
			}
			fmt.Println("added", terminalSafeInline(name))
			return nil
		},
	}
	addCmd.Flags().String("host", "", "Stable host or IP of device (a reserved numeric IP is recommended for pre-boot)")
	addCmd.Flags().String("user", "", "SSH user (required)")
	addCmd.Flags().Int("port", 22, "SSH port")
	addCmd.Flags().String("success-message", "", "SSH output string indicating successful unlock")

	removeCmd := &cobra.Command{
		Use:   "remove [name...]",
		Short: "Remove device(s)",
		Long:  "Remove device(s) by name from the configuration. If no device names are provided, all configured devices will be removed.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := configStore()
			if err != nil {
				return err
			}

			if len(args) == 0 {
				allDevices, err := s.Load()
				if err != nil {
					return err
				}
				if len(allDevices) == 0 {
					fmt.Println("No devices configured. Nothing to remove.")
					return nil
				}
				fmt.Printf("WARNING: No device names specified. This will remove ALL %d configured devices.\n", len(allDevices))
				fmt.Print("Are you sure you want to remove all devices? [y/N]: ")
				confirmed, err := readYes(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("read confirmation: %w", err)
				}
				if !confirmed {
					fmt.Println("Operation cancelled.")
					return nil
				}
				removed := 0
				for _, device := range allDevices {
					if err := s.Remove(device.Name); err != nil {
						fmt.Printf("Error removing device '%s': %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
					} else {
						deleteStoredCredential(device)
						fmt.Printf("Removed device '%s'\n", terminalSafeInline(device.Name))
						removed++
					}
				}
				if removed != len(allDevices) {
					return fmt.Errorf("removed %d of %d devices", removed, len(allDevices))
				}
				fmt.Printf("Successfully removed all %d devices.\n", removed)
				return nil
			}

			configured, err := s.Load()
			if err != nil {
				return err
			}
			byName := make(map[string]config.Device, len(configured))
			for _, device := range configured {
				byName[device.Name] = device
			}
			atLeastOneSuccess := false
			for _, name := range args {
				if err := s.Remove(name); err != nil {
					fmt.Printf("Error removing device %q: %s\n", terminalSafeInline(name), terminalSafeInline(err.Error()))
				} else {
					deleteStoredCredential(byName[name])
					fmt.Printf("Removed device %q\n", terminalSafeInline(name))
					atLeastOneSuccess = true
				}
			}
			if !atLeastOneSuccess && len(args) > 0 {
				return fmt.Errorf("failed to remove any of the specified devices")
			}
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := configStore()
			if err != nil {
				return err
			}
			devs, err := s.Load()
			if err != nil {
				return err
			}
			if len(devs) == 0 {
				fmt.Println("No devices configured. Use 'config add' to add a device.")
				return nil
			}
			fmt.Println("\nConfigured Devices:")
			fmt.Println("------------------")
			for _, d := range devs {
				credStatus := credentialSourceLabel(d)
				fmt.Printf("Name: %s\n", terminalSafeInline(d.Name))
				fmt.Printf("Host: %s\n", terminalSafeInline(d.Host))
				if d.Port != 0 {
					fmt.Printf("Port: %d\n", d.Port)
				} else {
					fmt.Printf("Port: 22 (default)\n")
				}
				fmt.Printf("User: %s\n", terminalSafeInline(d.User))
				fmt.Printf("Auth: %s\n", credStatus)
				fmt.Println("------------------")
			}
			return nil
		},
	}

	showCmd := &cobra.Command{
		Use:   "show [name]",
		Short: "Show details of a specific device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			s, err := configStore()
			if err != nil {
				return err
			}
			devs, err := s.Load()
			if err != nil {
				return err
			}
			var d *config.Device
			for i := range devs {
				if devs[i].Name == name {
					d = &devs[i]
					break
				}
			}
			if d == nil {
				return fmt.Errorf("device not found: %s", name)
			}
			fmt.Println("\nDevice Details:")
			fmt.Println("------------------")
			fmt.Printf("Name: %s\n", terminalSafeInline(d.Name))
			fmt.Printf("Host: %s\n", terminalSafeInline(d.Host))
			if d.Port != 0 {
				fmt.Printf("Port: %d\n", d.Port)
			} else {
				fmt.Printf("Port: 22 (default)\n")
			}
			fmt.Printf("User: %s\n", terminalSafeInline(d.User))
			credStatus := credentialSourceLabel(*d)
			fmt.Printf("Auth: %s\n", credStatus)
			fmt.Println("------------------")
			return nil
		},
	}

	cfgCmd.AddCommand(addCmd, removeCmd, listCmd, showCmd)

	unlockCmd := &cobra.Command{
		Use:   "unlock [name...]",
		Short: "Unlock configured device(s)",
		Long:  unlockLongHelp,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			s, err := configStore()
			if err != nil {
				return err
			}
			allDevices, err := s.Load()
			if err != nil {
				return err
			}

			deviceMap := make(map[string]config.Device)
			for _, device := range allDevices {
				deviceMap[device.Name] = device
			}

			var devicesToUnlock []config.Device
			if len(args) == 0 {
				fmt.Println("No specific devices named. Attempting to unlock all configured devices...")
				devicesToUnlock = allDevices
			} else {
				fmt.Printf("Attempting to unlock specific devices: %q\n", args)
				for _, deviceName := range args {
					if device, found := deviceMap[deviceName]; found {
						devicesToUnlock = append(devicesToUnlock, device)
					} else {
						fmt.Printf("Warning: Device %q not found in configuration. Skipping.\n", terminalSafeInline(deviceName))
					}
				}
			}

			if len(devicesToUnlock) == 0 {
				if len(args) > 0 {
					return fmt.Errorf("none of the requested devices are configured")
				}
				fmt.Println("No devices to unlock.")
				return nil
			}

			insecure, _ := cmd.Flags().GetBool("insecure-host-key")
			identityFiles, _ := cmd.Flags().GetStringSlice("identity")
			verifyWindow, _ := cmd.Flags().GetDuration("verify-timeout")
			if verifyWindow < 0 {
				return fmt.Errorf("--verify-timeout must not be negative")
			}
			if noVerify, _ := cmd.Flags().GetBool("no-verify"); noVerify {
				verifyWindow = 0
			}
			client, err := newSSHClient(verbose, insecure, false, identityFiles)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			maxAttempts, _ := cmd.Flags().GetInt("retry-attempts")
			retryDelay, _ := cmd.Flags().GetDuration("retry-delay")
			if maxAttempts < 1 {
				return fmt.Errorf("--retry-attempts must be at least 1")
			}
			if retryDelay < 0 {
				return fmt.Errorf("--retry-delay must not be negative")
			}

			atLeastOneSuccess := false
			for _, device := range devicesToUnlock {
				credID := deviceCredentialID(device)
				deviceStore := credentialStoreForDevice(device)
				password, err := deviceStore.Get(credID)
				if err == nil && password == "" {
					err = fmt.Errorf("credential is empty")
				}
				if err != nil {
					if len(devicesToUnlock) > 1 {
						fmt.Printf("warning: failed to retrieve credential for device '%s': %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
						fmt.Printf("Skipping device '%s' due to credential retrieval failure.\n", terminalSafeInline(device.Name))
						continue
					}
					if verbose {
						fmt.Printf("[verbose] failed to retrieve credential for %q: %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
					}
					fmt.Printf("Enter password for %s@%s: ", terminalSafeInline(device.User), terminalSafeInline(device.Host))
					password, err = credentials.ReadPassword()
					if err != nil {
						return fmt.Errorf("error reading password: %w", err)
					}
					if password == "" {
						return fmt.Errorf("password must not be empty")
					}
				}
				deviceStore = &staticStore{pw: password}

				successMsg := device.SuccessMessage
				if successMsg == "" {
					successMsg = defaultSuccessMessage
				}

				attempts := 0
				for {
					attempts++
					hostWithPort := deviceEndpoint(device)
					if verbose {
						fmt.Printf("[verbose] Attempt %d/%d: Unlocking %s@%s, successMsg=%q\n", attempts, maxAttempts, terminalSafeInline(device.User), terminalSafeInline(hostWithPort), terminalSafeInline(successMsg))
					} else {
						fmt.Printf("Attempt %d/%d: Unlocking %s@%s\n", attempts, maxAttempts, terminalSafeInline(device.User), terminalSafeInline(hostWithPort))
					}

					fvDevice := fvcore.Device{
						Host: hostWithPort,
						User: device.User,
						Cred: credID,
						Port: device.Port,
					}
					results := fvcore.UnlockMany(ctx, client, deviceStore, []fvcore.Device{fvDevice}, successMsg, 20*time.Second, 1)
					res := results[0]

					if verbose {
						fmt.Printf("[verbose] banner:\n%s\n", terminalSafeMultiline(res.Output))
						if res.Error != nil {
							fmt.Printf("[verbose] Error: %s\n", terminalSafeInline(res.Error.Error()))
						}
					}

					switch res.Status {
					case fvcore.StatusUnlocked:
						fmt.Printf("SUCCESS: %s accepted the unlock password.\n", terminalSafeInline(device.Name))
						atLeastOneSuccess = true
						if verifyWindow > 0 {
							fmt.Printf("Verifying %s finished booting (up to %v)...\n", terminalSafeInline(device.Name), verifyWindow)
							opts := fvcore.DefaultVerifyOptions()
							opts.Window = verifyWindow
							ok, verr := fvcore.VerifyUnlock(ctx, client, fvDevice, opts)
							switch {
							case errors.Is(verr, fvcore.ErrHostKeyMismatch):
								return verr
							case errors.Is(verr, fvcore.ErrIndeterminate):
								fmt.Printf("WARNING: %s accepted the unlock, but no public key proved that normal macOS returned; run status later with ssh-agent or --identity.\n", terminalSafeInline(device.Name))
							case verr != nil:
								fmt.Printf("WARNING: could not verify %s: %s\n", terminalSafeInline(device.Name), terminalSafeInline(verr.Error()))
							case ok:
								fmt.Printf("VERIFIED: %s is booted and reachable over SSH.\n", terminalSafeInline(device.Name))
							default:
								fmt.Printf("NOTE: %s accepted the unlock but has not come back within %v; it may still be booting.\n", terminalSafeInline(device.Name), verifyWindow)
							}
						}
					case fvcore.StatusUnlockedRecently:
						fmt.Printf("INFO: %s is already unlocked (normal SSH session available).\n", terminalSafeInline(device.Name))
						atLeastOneSuccess = true
					case fvcore.StatusLocked:
						// Wrong password; retrying will not help.
						fmt.Printf("FAILED: %s is still locked (incorrect password).\n", terminalSafeInline(device.Name))
						if len(devicesToUnlock) == 1 {
							return fmt.Errorf("failed to unlock device '%s': incorrect password", device.Name)
						}
					default:
						if errors.Is(res.Error, fvcore.ErrHostKeyMismatch) {
							fmt.Printf("SECURITY ERROR: refusing %s: %s\n", terminalSafeInline(device.Name), terminalSafeInline(res.Error.Error()))
							return res.Error
						}
						// StatusUnknown: transient (network not up yet, dial
						// error). These are the cases worth retrying.
						if res.Error != nil {
							fmt.Printf("Attempt %d/%d failed: %s\n", attempts, maxAttempts, terminalSafeInline(res.Error.Error()))
						} else {
							fmt.Printf("Attempt %d/%d failed: device state unknown\n", attempts, maxAttempts)
						}
						if attempts < maxAttempts {
							fmt.Printf("Waiting %v before next attempt...\n", retryDelay)
							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(retryDelay):
							}
							continue
						}
						fmt.Printf("Error: reached max retry attempts for device '%s'. Giving up.\n", terminalSafeInline(device.Name))
						if res.Error != nil && len(devicesToUnlock) == 1 {
							return res.Error
						}
					}
					break
				}
			}

			if !atLeastOneSuccess && len(devicesToUnlock) > 0 {
				if len(devicesToUnlock) == 1 {
					return fmt.Errorf("failed to unlock device '%s'", devicesToUnlock[0].Name)
				}
				return fmt.Errorf("failed to unlock any of the specified devices")
			}
			return nil
		},
	}
	unlockCmd.Flags().Bool("verbose", false, "Print detailed SSH output and debug info")
	unlockCmd.Flags().Int("retry-attempts", 10, "The maximum number of times to try connecting to the device before giving up")
	unlockCmd.Flags().Duration("retry-delay", 30*time.Second, "The delay between connection attempts (e.g., 15s, 1m, 30s)")
	unlockCmd.Flags().Bool("insecure-host-key", false, "Disable SSH host-key verification (INSECURE: exposes the password to a man-in-the-middle)")
	unlockCmd.Flags().StringSlice("identity", nil, "Private key for deterministic post-boot verification (repeatable; unencrypted keys only)")
	unlockCmd.Flags().Duration("verify-timeout", 5*time.Minute, "How long to wait after unlocking for the device to boot and answer SSH normally")
	unlockCmd.Flags().Bool("no-verify", false, "Skip post-unlock verification (report success as soon as the unlock is accepted)")

	statusCmd := &cobra.Command{
		Use:   "status [name...]",
		Short: "Check whether device(s) are locked, without sending the password",
		Long:  statusLongHelp,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			insecure, _ := cmd.Flags().GetBool("insecure-host-key")
			s, err := configStore()
			if err != nil {
				return err
			}
			allDevices, err := s.Load()
			if err != nil {
				return err
			}

			var targets []config.Device
			if len(args) == 0 {
				targets = allDevices
			} else {
				m := make(map[string]config.Device)
				for _, d := range allDevices {
					m[d.Name] = d
				}
				for _, n := range args {
					if d, ok := m[n]; ok {
						targets = append(targets, d)
					} else {
						fmt.Printf("Warning: Device %q not found in configuration. Skipping.\n", terminalSafeInline(n))
					}
				}
			}
			if len(targets) == 0 {
				if len(args) > 0 {
					return fmt.Errorf("none of the requested devices are configured")
				}
				fmt.Println("No devices to check.")
				return nil
			}

			acceptNew, _ := cmd.Flags().GetBool("accept-new-host-key")
			identityFiles, _ := cmd.Flags().GetStringSlice("identity")
			client, err := newSSHClient(verbose, insecure, acceptNew, identityFiles)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			for _, d := range targets {
				hostWithPort := deviceEndpoint(d)
				st, _, perr := fvcore.CheckStatus(ctx, client, hostWithPort, d.User, 15*time.Second)
				switch {
				case st == fvcore.StatusLocked:
					fmt.Printf("%-20s locked\n", terminalSafeInline(d.Name))
				case st == fvcore.StatusUnlockedRecently:
					// A completed SSH handshake (here, via public key) proves the
					// machine has booted past the FileVault prompt.
					fmt.Printf("%-20s unlocked (booted, SSH available)\n", terminalSafeInline(d.Name))
				case errors.Is(perr, fvcore.ErrHostKeyMismatch):
					return perr
				case errors.Is(perr, fvcore.ErrIndeterminate):
					// A booted sshd prompts for a password just like the pre-boot
					// server, so without a key or password we cannot say. Supply
					// an SSH key (ssh-agent or --identity) to resolve these.
					fmt.Printf("%-20s %s\n", terminalSafeInline(d.Name), indeterminateStatusText)
				case perr != nil:
					fmt.Printf("%-20s unknown (%s)\n", terminalSafeInline(d.Name), terminalSafeInline(perr.Error()))
				default:
					fmt.Printf("%-20s %s\n", terminalSafeInline(d.Name), st)
				}
			}
			return nil
		},
	}
	statusCmd.Flags().Bool("verbose", false, "Print detailed output")
	statusCmd.Flags().Bool("insecure-host-key", false, "Disable SSH host-key verification (INSECURE)")
	statusCmd.Flags().Bool("accept-new-host-key", false, "Trust and record an unknown host key after independently verifying its fingerprint")
	statusCmd.Flags().StringSlice("identity", nil, "Private key used to prove normal macOS is booted (repeatable; unencrypted keys only)")

	rootCmd.AddCommand(cfgCmd, unlockCmd, statusCmd, newDiscoverCommand(), newScanCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", terminalSafeInline(err.Error()))
		os.Exit(1)
	}
}

func configPath() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	if homedir == "" {
		return "", fmt.Errorf("find home directory: empty path")
	}
	return filepath.Join(homedir, ".fv-ssh-unlock", "devices.json"), nil
}

func readYes(r io.Reader) (bool, error) {
	var answer strings.Builder
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				return strings.EqualFold(strings.TrimSpace(answer.String()), "y"), nil
			}
			if answer.Len() >= 16 {
				return false, errors.New("confirmation response is too long")
			}
			answer.WriteByte(one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return strings.EqualFold(strings.TrimSpace(answer.String()), "y"), nil
			}
			return false, err
		}
		if n == 0 {
			return false, io.ErrNoProgress
		}
	}
}

func configStore() (*config.Store, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	return &config.Store{Path: path}, nil
}

func deviceCredentialID(device config.Device) string {
	if device.Cred != "" {
		return device.Cred
	}
	return credentials.ID(device.Name)
}

func deviceEndpoint(device config.Device) string {
	port := device.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(device.Host, strconv.Itoa(port))
}

func credentialSourceLabel(device config.Device) string {
	switch device.CredentialSource {
	case "keyring":
		return "Credential in keychain"
	case "runtime":
		return "Environment or interactive prompt"
	default:
		if device.Cred == "" {
			return "Legacy environment or interactive prompt"
		}
		return "Legacy keychain credential"
	}
}

func credentialStoreForDevice(device config.Device) fvcore.CredentialStore {
	switch device.CredentialSource {
	case "runtime":
		return &environmentStore{}
	case "keyring":
		return &keyringStore{}
	default:
		// Before credential_source existed, an empty cred meant that the user
		// declined keychain storage. Preserve that behavior during migration.
		if device.Cred == "" {
			return &environmentStore{}
		}
		return &keyringStore{}
	}
}

func deleteStoredCredential(device config.Device) {
	if device.CredentialSource == "runtime" || !credentials.CanStore() {
		return
	}
	if err := credentials.Delete(deviceCredentialID(device)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removed device %q but could not remove its keyring credential: %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
	}
}

// keyringStore adapts internal/credentials to fvcore.CredentialStore.
type keyringStore struct{}

func (k *keyringStore) Get(name string) (string, error) {
	if strings.HasPrefix(strings.ToLower(name), "fvu-") {
		return credentials.Get(name)
	}
	return credentials.Get(fmt.Sprintf("fvu-%s", strings.ToLower(name)))
}

func (k *keyringStore) Set(name, value string) error {
	return credentials.Set(name, value)
}

// environmentStore retrieves only the explicit runtime environment variable,
// including in keyring-enabled builds.
type environmentStore struct{}

func (*environmentStore) Get(name string) (string, error) {
	return credentials.GetEnvironment(name)
}

// staticStore is an in-memory CredentialStore used when we prompt for a
// password at runtime.
type staticStore struct {
	pw string
}

func (s *staticStore) Get(name string) (string, error) {
	if s.pw == "" {
		return "", fmt.Errorf("no password available")
	}
	return s.pw, nil
}

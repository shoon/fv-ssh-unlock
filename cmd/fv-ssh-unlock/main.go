// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"context"
	"encoding/json"
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
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

var version = "dev"
var dataDirOverride string

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
     password-free status check is indeterminate when the explanation is absent.
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
  fv-ssh-unlock unlock --all
  fv-ssh-unlock credentials providers
  fv-ssh-unlock discover
  fv-ssh-unlock scan --cidr 192.168.1.0/24
  fv-ssh-unlock daemon --once --identity ~/.ssh/id_ed25519
  fv-ssh-unlock daemon --identity ~/.ssh/id_ed25519
  fv-ssh-unlock tui`
	addLongHelp = `Add a device to the local configuration file. --host and --user
are required. [name] is an optional local alias; if it is omitted, the host
value is used as the device name.

For reliable remote unlock, configure a predictable address before restarting
the Mac. Prefer a DHCP reservation (static lease). A manually assigned static
address is a fallback that must be tested for conflicts and pre-boot behavior.
Bonjour discovery and .local names are convenient while macOS is booted, but
FileVault pre-boot may not advertise Bonjour; do not rely on discover to recover
an address after restart.

Credential source "auto" offers the OS keyring only when it appears usable and
otherwise selects runtime input. Source "file" reads an externally managed
absolute path or portable systemd:<name> reference. Plaintext disk files are
refused unless the action-scoped --allow-unsafe-credential-storage flag is
supplied.`
	unlockLongHelp = `Unlock configured devices by name using a credential from the
environment, OS keyring, externally managed file, or an interactive prompt.
Specify one or more device names, or use --all explicitly. Plaintext disk
credential files are refused unless --allow-unsafe-credential-storage is
supplied for this invocation; the override is never saved.

The FileVault explanation may be absent on recent macOS versions; an exact
hidden Password: prompt is still supported. SUCCESS means the trusted server
accepted the password. VERIFIED additionally requires normal macOS SSH to
accept a public key from ssh-agent, a standard ~/.ssh identity, or --identity.
Use --identity to select a nonstandard unencrypted key. After password
submission, the client watches the SSH endpoint for the pre-boot-to-macOS
network transition; it does not depend on ICMP/ping.`
	statusLongHelp = `Probe configured devices without retrieving or transmitting the
unlock password. A FileVault explanation proves locked; successful public-key
authentication proves normal macOS has booted.

Some FileVault pre-boot versions show only Password:, which is indistinguishable
from a password-only booted SSH server without sending a secret. In that case
indeterminate is the safe, expected result. The command tries ssh-agent and
standard ~/.ssh identities automatically; use --identity to select another key.`
	indeterminateStatusText = "indeterminate (SSH reachable; no proof of FileVault pre-boot or booted macOS)"
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
	rootCmd.PersistentFlags().StringVar(&dataDirOverride, "data-dir", "", "Configuration and state directory (or FV_SSH_UNLOCK_DATA_DIR; default ~/.fv-ssh-unlock)")

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
			requestedCredentialSource, _ := cmd.Flags().GetString("credential-source")
			credentialFile, _ := cmd.Flags().GetString("credential-file")
			allowUnsafeStorage, _ := cmd.Flags().GetBool("allow-unsafe-credential-storage")
			autoUnlock, _ := cmd.Flags().GetBool("auto-unlock")

			if user == "" {
				return fmt.Errorf("--user flag is required")
			}
			if host == "" {
				return fmt.Errorf("--host flag is required")
			}

			var name string
			if len(args) == 0 {
				name = host
			} else {
				name = args[0]
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

			requestedCredentialSource = strings.ToLower(strings.TrimSpace(requestedCredentialSource))
			if requestedCredentialSource == "" {
				requestedCredentialSource = "auto"
			}
			switch requestedCredentialSource {
			case "auto", credentials.ProviderRuntime, credentials.ProviderKeyring, credentials.ProviderFile:
			default:
				return fmt.Errorf("--credential-source must be auto, runtime, keyring, or file")
			}
			if requestedCredentialSource == credentials.ProviderFile && credentialFile == "" {
				return fmt.Errorf("--credential-file is required with --credential-source file")
			}
			if requestedCredentialSource != credentials.ProviderFile && credentialFile != "" {
				return fmt.Errorf("--credential-file requires --credential-source file")
			}
			preflight := config.Device{
				Name:             name,
				Host:             host,
				User:             user,
				Port:             port,
				Cred:             cred,
				CredentialSource: credentials.ProviderRuntime,
				SuccessMessage:   successMsg,
			}
			if err := config.ValidateDevice(preflight); err != nil {
				return err
			}

			registry := credentials.NewRegistry(credentials.Options{AllowUnsafeCredentialStorage: allowUnsafeStorage})
			credentialSource := credentials.ProviderRuntime
			credentialRef := ""
			var keyringProvider credentials.Provider
			var keyringPassword string
			defer func() { keyringPassword = "" }()
			prepareKeyring := func() error {
				provider, err := registry.Provider(credentials.ProviderKeyring)
				if err != nil {
					return err
				}
				report := provider.Report()
				if !report.Available {
					return fmt.Errorf("keyring credential provider is unavailable: %s", report.Details)
				}
				fmt.Printf("Enter password for %s@%s: ", terminalSafeInline(user), terminalSafeInline(host))
				password, err := credentials.ReadPassword()
				if err != nil {
					return fmt.Errorf("error reading password: %w", err)
				}
				if password == "" {
					return fmt.Errorf("password must not be empty")
				}
				credentialSource = credentials.ProviderKeyring
				keyringProvider = provider
				keyringPassword = password
				return nil
			}

			switch requestedCredentialSource {
			case credentials.ProviderRuntime:
				fmt.Printf("Password will be read from %s or prompted at unlock time.\n", terminalSafeInline(envName))
			case credentials.ProviderKeyring:
				if err := prepareKeyring(); err != nil {
					return err
				}
			case credentials.ProviderFile:
				normalizedReference, err := credentials.NormalizeFileReference(credentialFile)
				if err != nil {
					return fmt.Errorf("invalid --credential-file: %w", err)
				}
				provider, err := registry.Provider(credentials.ProviderFile)
				if err != nil {
					return err
				}
				assessment := provider.Assess(normalizedReference)
				if assessment.Available && !assessment.Secure && !allowUnsafeStorage {
					return fmt.Errorf("%w: %s; provision the file through a verified service credential mount or pass --allow-unsafe-credential-storage for this command",
						credentials.ErrUnsafeCredentialStorage, assessment.Details)
				}
				if !assessment.Available {
					fmt.Fprintf(os.Stderr, "warning: credential file is not currently available and cannot be assessed: %s; it will be verified when unlock reads it\n", terminalSafeInline(assessment.Details))
				} else if !assessment.Secure {
					fmt.Fprintf(os.Stderr, "warning: accepting unverified plaintext credential storage for this configuration: %s\n", terminalSafeInline(assessment.Details))
				}
				credentialSource = credentials.ProviderFile
				credentialRef = normalizedReference
				fmt.Printf("Password will be read from externally managed file reference %s; the file is not copied or modified.\n", terminalSafeInline(normalizedReference))
			case "auto":
				keyringProvider, err := registry.Provider(credentials.ProviderKeyring)
				if err != nil {
					return err
				}
				if keyringProvider.Report().Available {
					fmt.Print("Store password in OS keychain? [y/N]: ")
					confirmed, err := readYes(cmd.InOrStdin())
					if err != nil {
						return fmt.Errorf("read confirmation: %w", err)
					}
					if confirmed {
						if err := prepareKeyring(); err != nil {
							return err
						}
					} else {
						fmt.Println("Password not stored. It will be read from the environment or prompted at unlock time.")
					}
				} else {
					fmt.Printf("No usable secure keyring was detected. Password will be read from %s or prompted at unlock time. Run 'credentials providers' for details.\n", terminalSafeInline(envName))
				}
			}

			d := config.Device{
				Name:             name,
				Host:             host,
				User:             user,
				Port:             port,
				Cred:             cred,
				CredentialSource: credentialSource,
				CredentialRef:    credentialRef,
				SuccessMessage:   successMsg,
				AutoUnlock:       autoUnlock,
			}
			if err := config.ValidateDevice(d); err != nil {
				return err
			}
			var prepareExternalState func() error
			if keyringProvider != nil {
				prepareExternalState = func() error {
					if err := keyringProvider.Store(cred, keyringPassword); err != nil {
						return fmt.Errorf("store password in keychain: %w", err)
					}
					return nil
				}
			}
			if err := s.AddPrepared(d, prepareExternalState); err != nil {
				return err
			}
			fmt.Printf("Added device %q.\n", terminalSafeInline(name))
			return nil
		},
	}
	addCmd.Flags().String("host", "", "Stable host or IP of device (a reserved numeric IP is recommended for pre-boot)")
	addCmd.Flags().String("user", "", "SSH user (required)")
	addCmd.Flags().Int("port", 22, "SSH port")
	addCmd.Flags().String("success-message", "", "SSH output string indicating successful unlock")
	addCmd.Flags().String("credential-source", "auto", "Credential source: auto, runtime, keyring, or file")
	addCmd.Flags().String("credential-file", "", "Absolute path or systemd:<name> reference for an externally managed credential file")
	addCmd.Flags().Bool("allow-unsafe-credential-storage", false, "Allow an unverified plaintext credential file for this command only")
	addCmd.Flags().Bool("auto-unlock", false, "Allow the persistent daemon to unlock this device after conclusively detecting FileVault pre-boot")

	removeCmd := &cobra.Command{
		Use:   "remove [name...]",
		Short: "Remove device(s)",
		Long:  "Remove configured devices by name. To remove every configured device, use --all explicitly; bulk removal asks for confirmation unless --yes is supplied.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			removeAll, _ := cmd.Flags().GetBool("all")
			yes, _ := cmd.Flags().GetBool("yes")
			if removeAll && len(args) > 0 {
				return fmt.Errorf("--all cannot be combined with device names")
			}
			if !removeAll && len(args) == 0 {
				return fmt.Errorf("specify at least one device name or use --all")
			}
			if yes && !removeAll {
				return fmt.Errorf("--yes can only be used with --all")
			}
			s, err := configStore()
			if err != nil {
				return err
			}

			if removeAll {
				allDevices, err := s.Load()
				if err != nil {
					return err
				}
				if len(allDevices) == 0 {
					fmt.Println("No devices configured. Nothing to remove.")
					return nil
				}
				if !yes {
					fmt.Printf("WARNING: This will remove ALL %d configured devices.\n", len(allDevices))
					fmt.Print("Are you sure you want to remove all devices? [y/N]: ")
					confirmed, err := readYes(cmd.InOrStdin())
					if err != nil {
						return fmt.Errorf("read confirmation: %w", err)
					}
					if !confirmed {
						fmt.Println("Operation cancelled.")
						return nil
					}
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
			devicesToRemove, err := selectConfiguredDevices(configured, args)
			if err != nil {
				return err
			}
			var failed []string
			for _, device := range devicesToRemove {
				if err := s.Remove(device.Name); err != nil {
					fmt.Printf("Error removing device %q: %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
					failed = append(failed, device.Name)
				} else {
					deleteStoredCredential(device)
					fmt.Printf("Removed device %q.\n", terminalSafeInline(device.Name))
				}
			}
			if len(failed) > 0 {
				return fmt.Errorf("failed to remove %d of %d selected device(s): %s", len(failed), len(devicesToRemove), strings.Join(failed, ", "))
			}
			return nil
		},
	}
	removeCmd.Flags().Bool("all", false, "Remove every configured device (confirmation required)")
	removeCmd.Flags().Bool("yes", false, "Skip the confirmation prompt for --all")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured devices",
		Args:  cobra.NoArgs,
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
			fmt.Println("Configured devices:")
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "NAME\tENDPOINT\tSSH USER\tCREDENTIAL\tUNLOCK"); err != nil {
				return err
			}
			for _, d := range devs {
				unlockMode := "manual"
				if d.AutoUnlock {
					unlockMode = "automatic"
				}
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					terminalSafeInline(d.Name), terminalSafeInline(deviceEndpoint(d)),
					terminalSafeInline(d.User), credentialSourceLabel(d), unlockMode); err != nil {
					return err
				}
			}
			return tw.Flush()
		},
	}

	showCmd := &cobra.Command{
		Use:   "show NAME",
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
			fmt.Printf("Device: %s\n", terminalSafeInline(d.Name))
			fmt.Printf("Endpoint: %s\n", terminalSafeInline(deviceEndpoint(*d)))
			fmt.Printf("SSH user: %s\n", terminalSafeInline(d.User))
			fmt.Printf("Credential: %s\n", credentialSourceLabel(*d))
			fmt.Printf("Automatic unlock: %t\n", d.AutoUnlock)
			return nil
		},
	}

	cfgCmd.AddCommand(addCmd, removeCmd, listCmd, showCmd, newAutoUnlockConfigCommand(), newConfigExportCommand(), newConfigApplyCommand())

	unlockCmd := &cobra.Command{
		Use:   "unlock [name...]",
		Short: "Unlock configured device(s)",
		Long:  unlockLongHelp,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			unlockAll, _ := cmd.Flags().GetBool("all")
			if unlockAll && len(args) > 0 {
				return fmt.Errorf("--all cannot be combined with device names")
			}
			if !unlockAll && len(args) == 0 {
				return fmt.Errorf("specify at least one device name or use --all")
			}
			s, err := configStore()
			if err != nil {
				return err
			}
			allDevices, err := s.Load()
			if err != nil {
				return err
			}

			var devicesToUnlock []config.Device
			if unlockAll {
				devicesToUnlock = allDevices
				if len(devicesToUnlock) > 0 {
					fmt.Printf("Attempting to unlock all %d configured device(s).\n", len(devicesToUnlock))
				}
			} else {
				devicesToUnlock, err = selectConfiguredDevices(allDevices, args)
				if err != nil {
					return err
				}
			}

			if len(devicesToUnlock) == 0 {
				fmt.Println("No configured devices to unlock.")
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
			client, err := newSSHClient(verbose, insecure, false, identityFiles, defaultDialTimeout)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			maxAttempts, _ := cmd.Flags().GetInt("retry-attempts")
			retryDelay, _ := cmd.Flags().GetDuration("retry-delay")
			allowUnsafeStorage, _ := cmd.Flags().GetBool("allow-unsafe-credential-storage")
			if maxAttempts < 1 {
				return fmt.Errorf("--retry-attempts must be at least 1")
			}
			if retryDelay < 0 {
				return fmt.Errorf("--retry-delay must not be negative")
			}

			atLeastOneSuccess := false
			var failedDevices []string
			for _, device := range devicesToUnlock {
				credID := deviceCredentialID(device)
				deviceStore, err := credentialStoreForDevice(device, allowUnsafeStorage)
				if err != nil {
					return fmt.Errorf("configure credential provider for %s: %w", device.Name, err)
				}
				password, err := deviceStore.Get(credID)
				if err == nil && password == "" {
					err = fmt.Errorf("credential is empty")
				}
				if err != nil {
					if errors.Is(err, credentials.ErrUnsafeCredentialStorage) || (device.CredentialSource == credentials.ProviderFile && len(devicesToUnlock) == 1) {
						return fmt.Errorf("retrieve credential for device %q: %w", device.Name, err)
					}
					if len(devicesToUnlock) > 1 {
						fmt.Printf("warning: failed to retrieve credential for device '%s': %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
						fmt.Printf("Skipping device '%s' due to credential retrieval failure.\n", terminalSafeInline(device.Name))
						failedDevices = append(failedDevices, device.Name)
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

				result, err := unlockDeviceWithRetry(ctx, os.Stdout, client, deviceStore, device, credID, unlockRetryOptions{
					maxAttempts: maxAttempts, retryDelay: retryDelay, verifyWindow: verifyWindow, verbose: verbose,
				})
				if err != nil {
					return err
				}
				switch result.outcome {
				case unlockOutcomeUnlocked:
					atLeastOneSuccess = true
				case unlockOutcomeIncorrectPassword:
					if len(devicesToUnlock) == 1 {
						return fmt.Errorf("failed to unlock device '%s': incorrect password", device.Name)
					}
					failedDevices = append(failedDevices, device.Name)
				default:
					if result.lastError != nil && len(devicesToUnlock) == 1 {
						return result.lastError
					}
					failedDevices = append(failedDevices, device.Name)
				}
			}

			if len(failedDevices) > 0 {
				return fmt.Errorf("failed to unlock %d of %d selected device(s): %s", len(failedDevices), len(devicesToUnlock), strings.Join(failedDevices, ", "))
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
	unlockCmd.Flags().Bool("all", false, "Unlock every configured device")
	unlockCmd.Flags().Bool("verbose", false, "Print detailed SSH output and debug info")
	unlockCmd.Flags().Int("retry-attempts", 10, "The maximum number of times to try connecting to the device before giving up")
	unlockCmd.Flags().Duration("retry-delay", 30*time.Second, "The delay between connection attempts (e.g., 15s, 1m, 30s)")
	unlockCmd.Flags().Bool("insecure-host-key", false, "Disable SSH host-key verification (INSECURE: exposes the password to a man-in-the-middle)")
	unlockCmd.Flags().StringSlice("identity", nil, "Private key for deterministic post-boot verification (repeatable; defaults to standard ~/.ssh identities)")
	unlockCmd.Flags().Duration("verify-timeout", 5*time.Minute, "How long to wait after unlocking for the device to boot and answer SSH normally")
	unlockCmd.Flags().Bool("no-verify", false, "Skip post-unlock verification (report success as soon as the unlock is accepted)")
	unlockCmd.Flags().Bool("allow-unsafe-credential-storage", false, "Allow reading an unverified plaintext credential file for this command only")

	statusCmd := &cobra.Command{
		Use:   "status [name...]",
		Short: "Check device state without sending the FileVault password",
		Long:  statusLongHelp,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			insecure, _ := cmd.Flags().GetBool("insecure-host-key")
			jsonOutput, _ := cmd.Flags().GetBool("json")
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
				targets, err = selectConfiguredDevices(allDevices, args)
				if err != nil {
					return err
				}
			}
			if len(targets) == 0 {
				if jsonOutput {
					return writeStatusJSON(cmd.OutOrStdout(), []statusReport{})
				}
				terminalWriteLine(cmd.OutOrStdout(), "No configured devices to check.")
				return nil
			}

			acceptNew, _ := cmd.Flags().GetBool("accept-new-host-key")
			if acceptNew && len(args) != 1 {
				return fmt.Errorf("--accept-new-host-key requires exactly one named device")
			}
			requireKnown, _ := cmd.Flags().GetBool("require-known")
			identityFiles, _ := cmd.Flags().GetStringSlice("identity")
			client, err := newSSHClient(verbose, insecure, acceptNew, identityFiles, defaultDialTimeout)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			var indeterminateDevices []string
			var failedDevices []string
			reports := make([]statusReport, 0, len(targets))
			for _, d := range targets {
				hostWithPort := deviceEndpoint(d)
				st, _, perr := fvcore.CheckStatus(ctx, client, hostWithPort, d.User, 15*time.Second)
				report := statusReport{Name: d.Name, Endpoint: hostWithPort, CheckedAt: time.Now().UTC()}
				switch {
				case st == fvcore.StatusLocked:
					report.State = "locked"
					report.Evidence = "FileVault pre-boot banner detected"
					if !jsonOutput {
						fmt.Printf("%-20s locked (FileVault pre-boot banner detected)\n", terminalSafeInline(d.Name))
					}
				case st == fvcore.StatusUnlockedRecently:
					// A completed SSH handshake (here, via public key) proves the
					// machine has booted past the FileVault prompt.
					report.State = "booted"
					report.Evidence = "normal macOS SSH accepted a public key"
					if !jsonOutput {
						fmt.Printf("%-20s booted (normal macOS SSH accepted a public key)\n", terminalSafeInline(d.Name))
					}
				case errors.Is(perr, fvcore.ErrHostKeyMismatch):
					report.State = "error"
					report.Error = perr.Error()
					if !jsonOutput {
						fmt.Printf("%-20s error (%s)\n", terminalSafeInline(d.Name), terminalSafeInline(perr.Error()))
					}
					failedDevices = append(failedDevices, d.Name)
				case errors.Is(perr, fvcore.ErrIndeterminate):
					// A booted sshd prompts for a password just like the pre-boot
					// server, so without a key or password we cannot say. Supply
					// an SSH key (ssh-agent or --identity) to resolve these.
					report.State = "indeterminate"
					report.Evidence = "SSH reachable; no proof of FileVault pre-boot or booted macOS"
					if !jsonOutput {
						fmt.Printf("%-20s %s\n", terminalSafeInline(d.Name), indeterminateStatusText)
					}
					indeterminateDevices = append(indeterminateDevices, d.Name)
				case perr != nil:
					report.State = "error"
					report.Error = perr.Error()
					if !jsonOutput {
						fmt.Printf("%-20s error (%s)\n", terminalSafeInline(d.Name), terminalSafeInline(perr.Error()))
					}
					failedDevices = append(failedDevices, d.Name)
				default:
					report.State = st.String()
					if !jsonOutput {
						fmt.Printf("%-20s %s\n", terminalSafeInline(d.Name), st)
					}
				}
				reports = append(reports, report)
			}
			if jsonOutput {
				if err := writeStatusJSON(cmd.OutOrStdout(), reports); err != nil {
					return err
				}
			} else if len(indeterminateDevices) > 0 {
				fmt.Println("\nStatus never sends the FileVault password. A prompt-only pre-boot server and booted password-only SSH look identical.")
				if len(client.Signers) == 0 {
					fmt.Println("No usable SSH identity was found. Add one to ssh-agent or select an unencrypted key with --identity.")
				} else {
					fmt.Println("This is expected while a prompt-only Mac is locked. To prove it is booted, authorize one of the offered public keys for the configured user.")
				}
			}
			if len(failedDevices) > 0 {
				return fmt.Errorf("status failed for %d device(s): %s", len(failedDevices), strings.Join(failedDevices, ", "))
			}
			if requireKnown && len(indeterminateDevices) > 0 {
				return fmt.Errorf("status was indeterminate for %d device(s): %s", len(indeterminateDevices), strings.Join(indeterminateDevices, ", "))
			}
			return nil
		},
	}
	statusCmd.Flags().Bool("verbose", false, "Print detailed output")
	statusCmd.Flags().Bool("insecure-host-key", false, "Disable SSH host-key verification (INSECURE)")
	statusCmd.Flags().Bool("accept-new-host-key", false, "Trust and record an unknown host key after independently verifying its fingerprint")
	statusCmd.Flags().StringSlice("identity", nil, "Private key used to prove normal macOS is booted (repeatable; defaults to standard ~/.ssh identities)")
	statusCmd.Flags().Bool("require-known", false, "Exit unsuccessfully if any reachable device remains indeterminate")
	statusCmd.Flags().Bool("json", false, "Emit a stable machine-readable JSON report")

	rootCmd.AddCommand(cfgCmd, unlockCmd, statusCmd, newCredentialsCommand(), newDiscoverCommand(), newScanCommand(), newDaemonCommand(), newTUICommand(), newHealthcheckCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", terminalSafeInline(err.Error()))
		os.Exit(1)
	}
}

type statusReport struct {
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	State     string    `json:"state"`
	Evidence  string    `json:"evidence,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

func writeStatusJSON(output io.Writer, reports []statusReport) error {
	return json.NewEncoder(output).Encode(struct {
		SchemaVersion int            `json:"schema_version"`
		Devices       []statusReport `json:"devices"`
	}{SchemaVersion: 1, Devices: reports})
}

func appDataDir() (string, error) {
	if dataDirOverride != "" {
		if !filepath.IsAbs(dataDirOverride) {
			return "", fmt.Errorf("--data-dir must be an absolute path")
		}
		return filepath.Clean(dataDirOverride), nil
	}
	if fromEnv := strings.TrimSpace(os.Getenv("FV_SSH_UNLOCK_DATA_DIR")); fromEnv != "" {
		if !filepath.IsAbs(fromEnv) {
			return "", fmt.Errorf("FV_SSH_UNLOCK_DATA_DIR must be an absolute path")
		}
		return filepath.Clean(fromEnv), nil
	}
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	if homedir == "" {
		return "", fmt.Errorf("find home directory: empty path")
	}
	return filepath.Join(homedir, ".fv-ssh-unlock"), nil
}

func configPath() (string, error) {
	dir, err := appDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "devices.json"), nil
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

// selectConfiguredDevices resolves every requested name before a command takes
// action. This avoids surprising partial operations when one name is misspelled
// and rejects accidental duplicate targets.
func selectConfiguredDevices(devices []config.Device, names []string) ([]config.Device, error) {
	byName := make(map[string]config.Device, len(devices))
	for _, device := range devices {
		byName[device.Name] = device
	}
	selected := make([]config.Device, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("device %q was specified more than once", name)
		}
		device, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("device not found: %s", name)
		}
		seen[name] = struct{}{}
		selected = append(selected, device)
	}
	return selected, nil
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
	case credentials.ProviderKeyring:
		return "OS keyring"
	case credentials.ProviderRuntime:
		return "runtime (environment or hidden prompt)"
	case credentials.ProviderFile:
		return "external file (" + terminalSafeInline(device.CredentialRef) + ")"
	default:
		if device.Cred == "" {
			return "legacy runtime (environment or hidden prompt)"
		}
		return "legacy OS keyring"
	}
}

func credentialStoreForDevice(device config.Device, allowUnsafeStorage bool) (fvcore.CredentialStore, error) {
	source := device.CredentialSource
	reference := deviceCredentialID(device)
	if source == "" {
		// Before credential_source existed, an empty cred meant that the user
		// declined keychain storage. Preserve that behavior during migration.
		if device.Cred == "" {
			source = credentials.ProviderRuntime
		} else {
			source = credentials.ProviderKeyring
		}
	}
	if source == credentials.ProviderFile {
		reference = device.CredentialRef
	}
	registry := credentials.NewRegistry(credentials.Options{AllowUnsafeCredentialStorage: allowUnsafeStorage})
	provider, err := registry.Provider(source)
	if err != nil {
		return nil, err
	}
	return &providerStore{provider: provider, reference: reference}, nil
}

func deleteStoredCredential(device config.Device) {
	source := device.CredentialSource
	if source == "" {
		if device.Cred == "" {
			return
		}
		source = credentials.ProviderKeyring
	}
	if source == credentials.ProviderRuntime || source == credentials.ProviderFile {
		return
	}
	provider, err := credentials.NewRegistry(credentials.Options{}).Provider(source)
	if err != nil || !provider.Report().Built {
		return
	}
	if err := provider.Delete(deviceCredentialID(device)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removed device %q but could not remove its keyring credential: %s\n", terminalSafeInline(device.Name), terminalSafeInline(err.Error()))
	}
}

// providerStore binds a provider reference to fvcore's name-based credential
// interface. The reference may be a keyring ID, environment-derived ID, or an
// external file reference.
type providerStore struct {
	provider  credentials.Provider
	reference string
}

func (s *providerStore) Get(string) (string, error) {
	return s.provider.Get(s.reference)
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

// unlockOutcome is the terminal state of the per-device unlock retry state
// machine. Wrong-password and gave-up are kept apart because the caller reports
// them differently, and only the latter carries a transport error worth
// surfacing.
type unlockOutcome int

const (
	// unlockOutcomeUnlocked means the device is unlocked, or was independently
	// proved already booted so no unlock was needed.
	unlockOutcomeUnlocked unlockOutcome = iota
	// unlockOutcomeIncorrectPassword means FileVault rejected the credential.
	// Retrying cannot help.
	unlockOutcomeIncorrectPassword
	// unlockOutcomeExhausted means every attempt ended transient or
	// indeterminate. This is the fail-closed outcome: the device is not known to
	// be unlocked.
	unlockOutcomeExhausted
)

// unlockRetryOptions is the retry policy for one device.
type unlockRetryOptions struct {
	maxAttempts  int
	retryDelay   time.Duration
	verifyWindow time.Duration
	verbose      bool
}

// unlockAttemptResult reports how the retry state machine ended.
type unlockAttemptResult struct {
	outcome unlockOutcome
	// lastError is the transport error of the final attempt when outcome is
	// unlockOutcomeExhausted. The caller decides whether to surface it.
	lastError error
}

// unlockDeviceWithRetry runs the unlock retry state machine for a single
// device.
//
// A non-nil error is fatal for the whole command and must be returned to the
// user unchanged: a host-key mismatch (at any point, including during
// verification), or a cancelled context.
//
// The password is submitted at most once per attempt and never re-sent to
// resolve an ambiguous outcome. When a submission is not acknowledged, the
// attempt is credited only if a password-free probe independently proves the
// device booted; otherwise the state machine keeps failing closed and, if
// attempts remain, retries under the configured policy.
func unlockDeviceWithRetry(ctx context.Context, out io.Writer, client daemonSSHClient, store fvcore.CredentialStore, device config.Device, credID string, opts unlockRetryOptions) (unlockAttemptResult, error) {
	successMsg := device.SuccessMessage
	if successMsg == "" {
		successMsg = defaultSuccessMessage
	}

	attempts := 0
	previousUnacknowledgedAttempt := false
	for {
		attempts++
		hostWithPort := deviceEndpoint(device)
		if opts.verbose {
			terminalWritef(out, "[verbose] Attempt %d/%d: Unlocking %s@%s, successMsg=%q\n", attempts, opts.maxAttempts, terminalSafeInline(device.User), terminalSafeInline(hostWithPort), terminalSafeInline(successMsg))
		} else {
			terminalWritef(out, "Attempt %d/%d: Unlocking %s@%s\n", attempts, opts.maxAttempts, terminalSafeInline(device.User), terminalSafeInline(hostWithPort))
		}

		fvDevice := fvcore.Device{
			Host: hostWithPort,
			User: device.User,
			Cred: credID,
			Port: device.Port,
		}
		results := fvcore.UnlockMany(ctx, client, store, []fvcore.Device{fvDevice}, successMsg, 20*time.Second, 1)
		res := results[0]
		// A caller cancellation is terminal for the whole command, including when
		// it lands during the final/only attempt. Keep authoritative protocol
		// results below, but never turn a canceled unknown result into an ordinary
		// exhausted outcome that lets a multi-device invocation continue.
		if res.Status == fvcore.StatusUnknown && !errors.Is(res.Error, fvcore.ErrHostKeyMismatch) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return unlockAttemptResult{}, ctxErr
			}
		}

		if opts.verbose {
			terminalWritef(out, "[verbose] banner:\n%s\n", terminalSafeMultiline(res.Output))
			if res.Error != nil {
				terminalWritef(out, "[verbose] Error: %s\n", terminalSafeInline(res.Error.Error()))
			}
		}

		switch res.Status {
		case fvcore.StatusUnlocked:
			terminalWritef(out, "SUCCESS: %s accepted the unlock password.\n", terminalSafeInline(device.Name))
			if opts.verifyWindow > 0 {
				terminalWritef(out, "Verifying %s finished booting (up to %v)...\n", terminalSafeInline(device.Name), opts.verifyWindow)
				verifyOpts := fvcore.DefaultVerifyOptions()
				verifyOpts.Window = opts.verifyWindow
				ok, verr := fvcore.VerifyUnlock(ctx, client, fvDevice, verifyOpts)
				switch {
				case errors.Is(verr, fvcore.ErrHostKeyMismatch):
					return unlockAttemptResult{}, verr
				case errors.Is(verr, fvcore.ErrIndeterminate):
					terminalWritef(out, "WARNING: %s accepted the unlock, but no public key proved that normal macOS returned; run status later with ssh-agent or --identity.\n", terminalSafeInline(device.Name))
				case verr != nil:
					terminalWritef(out, "WARNING: could not verify %s: %s\n", terminalSafeInline(device.Name), terminalSafeInline(verr.Error()))
				case ok:
					terminalWritef(out, "VERIFIED: %s is booted and reachable over SSH.\n", terminalSafeInline(device.Name))
				default:
					terminalWritef(out, "NOTE: %s accepted the unlock but has not come back within %v; it may still be booting.\n", terminalSafeInline(device.Name), opts.verifyWindow)
				}
			}
			return unlockAttemptResult{outcome: unlockOutcomeUnlocked}, nil
		case fvcore.StatusUnlockedRecently:
			if previousUnacknowledgedAttempt {
				terminalWritef(out, "VERIFIED: %s is booted after an earlier unlock attempt; the pre-boot success acknowledgement was not observed.\n", terminalSafeInline(device.Name))
			} else {
				terminalWritef(out, "INFO: %s is already booted; normal macOS SSH accepted a public key. No unlock was needed.\n", terminalSafeInline(device.Name))
			}
			return unlockAttemptResult{outcome: unlockOutcomeUnlocked}, nil
		case fvcore.StatusLocked:
			// Wrong password; retrying will not help.
			terminalWritef(out, "FAILED: %s is still locked (incorrect password).\n", terminalSafeInline(device.Name))
			return unlockAttemptResult{outcome: unlockOutcomeIncorrectPassword}, nil
		default:
			if errors.Is(res.Error, fvcore.ErrHostKeyMismatch) {
				terminalWritef(out, "SECURITY ERROR: refusing %s: %s\n", terminalSafeInline(device.Name), terminalSafeInline(res.Error.Error()))
				return unlockAttemptResult{}, res.Error
			}
			if errors.Is(res.Error, fvcore.ErrUnlockOutcomeUnknown) {
				previousUnacknowledgedAttempt = true
				if opts.verifyWindow > 0 {
					terminalWritef(out, "The password was submitted, but %s did not acknowledge the outcome. Checking for normal macOS without sending the password again (up to %v)...\n", terminalSafeInline(device.Name), opts.verifyWindow)
					verifyOpts := fvcore.DefaultVerifyOptions()
					verifyOpts.Grace = 0
					verifyOpts.Window = opts.verifyWindow
					verifyOpts.Interval = 2 * time.Second
					verifyOpts.AttemptTimeout = 5 * time.Second
					if opts.verifyWindow < verifyOpts.AttemptTimeout {
						verifyOpts.AttemptTimeout = opts.verifyWindow
					}
					ok, verr := fvcore.VerifyUnlock(ctx, client, fvDevice, verifyOpts)
					switch {
					case errors.Is(verr, fvcore.ErrHostKeyMismatch):
						return unlockAttemptResult{}, verr
					case ok:
						terminalWritef(out, "VERIFIED: %s is booted and reachable over SSH after the unlock attempt; the pre-boot success acknowledgement was not observed.\n", terminalSafeInline(device.Name))
					case errors.Is(verr, fvcore.ErrIndeterminate):
						terminalWritef(out, "NOTE: %s is still reachable but its state cannot yet be proved without a public key; continuing the configured retry policy.\n", terminalSafeInline(device.Name))
					case verr != nil:
						if errors.Is(verr, context.Canceled) {
							return unlockAttemptResult{}, verr
						}
						terminalWritef(out, "NOTE: boot verification after the unacknowledged attempt failed: %s\n", terminalSafeInline(verr.Error()))
					default:
						terminalWritef(out, "NOTE: %s did not return to normal SSH within %v; continuing the configured retry policy.\n", terminalSafeInline(device.Name), opts.verifyWindow)
					}
					if ok {
						return unlockAttemptResult{outcome: unlockOutcomeUnlocked}, nil
					}
				}
			}
			// StatusUnknown: transient (network not up yet, dial
			// error). These are the cases worth retrying.
			if res.Error != nil {
				terminalWritef(out, "Attempt %d/%d failed: %s\n", attempts, opts.maxAttempts, terminalSafeInline(res.Error.Error()))
			} else {
				terminalWritef(out, "Attempt %d/%d failed: device state unknown\n", attempts, opts.maxAttempts)
			}
			if attempts < opts.maxAttempts {
				terminalWritef(out, "Waiting %v before next attempt...\n", opts.retryDelay)
				select {
				case <-ctx.Done():
					return unlockAttemptResult{}, ctx.Err()
				case <-time.After(opts.retryDelay):
				}
				continue
			}
			terminalWritef(out, "Error: reached max retry attempts for device '%s'. Giving up.\n", terminalSafeInline(device.Name))
			return unlockAttemptResult{outcome: unlockOutcomeExhausted, lastError: res.Error}, nil
		}
	}
}

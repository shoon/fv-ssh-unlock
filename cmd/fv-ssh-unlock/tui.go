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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/shoon/fv-ssh-unlock/internal/candidates"
	"github.com/shoon/fv-ssh-unlock/internal/control"
	"github.com/shoon/fv-ssh-unlock/internal/credentials"
	"github.com/shoon/fv-ssh-unlock/internal/monitor"
)

type devicesAPIResponse struct {
	SchemaVersion int `json:"schema_version"`
	monitor.Snapshot
}

type candidatesAPIResponse struct {
	SchemaVersion int `json:"schema_version"`
	candidates.Snapshot
}

type dashboardSnapshot struct {
	Devices    devicesAPIResponse    `json:"devices"`
	Candidates candidatesAPIResponse `json:"candidates"`
}

func newTUICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Open a terminal dashboard for the persistent daemon",
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
				return errors.New("--socket must be an absolute path")
			}
			refresh, _ := cmd.Flags().GetDuration("refresh")
			if refresh <= 0 {
				return errors.New("--refresh must be greater than zero")
			}
			client := control.Client(socket, 5*time.Second)
			once, _ := cmd.Flags().GetBool("once")
			jsonOutput, _ := cmd.Flags().GetBool("json")
			if once || jsonOutput {
				snapshot, err := fetchDashboard(cmd.Context(), client)
				if err != nil {
					return err
				}
				if jsonOutput {
					return writeJSON(cmd.OutOrStdout(), snapshot)
				}
				return renderDashboard(cmd.OutOrStdout(), snapshot, false, "")
			}
			return runInteractiveTUI(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), client, refresh)
		},
	}
	cmd.Flags().String("socket", "", "Daemon Unix socket (or FV_SSH_UNLOCK_SOCKET)")
	cmd.Flags().Duration("refresh", 2*time.Second, "Dashboard refresh interval")
	cmd.Flags().Bool("once", false, "Print one dashboard snapshot without entering interactive mode")
	cmd.Flags().Bool("json", false, "Print one combined machine-readable snapshot")
	return cmd
}

func fetchDashboard(ctx context.Context, client *http.Client) (dashboardSnapshot, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var snapshot dashboardSnapshot
	if err := control.GetJSON(requestCtx, client, "/v1/devices", &snapshot.Devices); err != nil {
		return snapshot, err
	}
	if snapshot.Devices.SchemaVersion != controlAPISchemaVersion {
		return snapshot, fmt.Errorf("unsupported daemon API schema %d", snapshot.Devices.SchemaVersion)
	}
	if err := control.GetJSON(requestCtx, client, "/v1/candidates", &snapshot.Candidates); err != nil {
		return snapshot, err
	}
	if snapshot.Candidates.SchemaVersion != controlAPISchemaVersion {
		return snapshot, fmt.Errorf("unsupported daemon API schema %d", snapshot.Candidates.SchemaVersion)
	}
	return snapshot, nil
}

func runInteractiveTUI(ctx context.Context, input io.Reader, output io.Writer, client *http.Client, refresh time.Duration) error {
	inFile, inputOK := input.(*os.File)
	outFile, outputOK := output.(*os.File)
	if !inputOK || !outputOK || !term.IsTerminal(int(inFile.Fd())) || !term.IsTerminal(int(outFile.Fd())) {
		return errors.New("interactive TUI requires a terminal; use --once or --json for non-interactive output")
	}
	oldState, err := term.MakeRaw(int(inFile.Fd()))
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(int(inFile.Fd()), oldState) }()
	defer fmt.Fprint(output, "\x1b[?25h\x1b[0m\r\n")
	fmt.Fprint(output, "\x1b[?25l")

	keys := make(chan byte, 32)
	readErrors := make(chan error, 1)
	go readTerminalKeys(inFile, keys, readErrors)
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	var snapshot dashboardSnapshot
	var message string
	refreshNow := func() {
		latest, fetchErr := fetchDashboard(ctx, client)
		if fetchErr != nil {
			message = "daemon: " + terminalSafeInline(fetchErr.Error())
			return
		}
		snapshot = latest
	}
	refreshNow()
	for {
		if err := renderDashboard(output, snapshot, true, message); err != nil {
			return err
		}
		message = ""
		select {
		case <-ctx.Done():
			return nil
		case err := <-readErrors:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ticker.C:
			refreshNow()
		case key := <-keys:
			switch key {
			case 'q', 3:
				return nil
			case 'r':
				refreshNow()
			case 'a':
				message = enrollCandidateFromTUI(ctx, output, keys, client, snapshot.Candidates.Snapshot)
				refreshNow()
			case 'i':
				message = candidateActionFromTUI(ctx, output, keys, client, snapshot.Candidates.Snapshot, "ignore")
				refreshNow()
			case 'p':
				message = deviceActionFromTUI(ctx, output, keys, client, snapshot.Devices.Snapshot, "poll")
				refreshNow()
			case 'l':
				message = deviceActionFromTUI(ctx, output, keys, client, snapshot.Devices.Snapshot, "clear-latch")
				refreshNow()
			}
		}
	}
}

func readTerminalKeys(input *os.File, keys chan<- byte, errs chan<- error) {
	var buffer [1]byte
	for {
		n, err := input.Read(buffer[:])
		if n == 1 {
			keys <- buffer[0]
		}
		if err != nil {
			errs <- err
			return
		}
	}
}

func renderDashboard(output io.Writer, snapshot dashboardSnapshot, clear bool, message string) error {
	if clear {
		fmt.Fprint(output, "\x1b[H\x1b[2J")
	}
	fmt.Fprintf(output, "fv-ssh-unlock  %d managed Mac(s)  %d candidate(s)  %s\n\n",
		len(snapshot.Devices.Devices), len(snapshot.Candidates.Candidates), time.Now().Format("15:04:05"))
	tw := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tHOST\tSTATE\tLAST CHECK\tAUTO\tNEXT ACTION")
	for index, device := range snapshot.Devices.Devices {
		auto := "no"
		if device.AutoUnlock {
			auto = "yes"
		}
		next := "-"
		if !device.NextCheckAt.IsZero() {
			next = relativeTime(device.NextCheckAt)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", index+1, terminalSafeInline(device.Name), terminalSafeInline(string(device.State)),
			relativeTime(device.LastCheckedAt), auto, next)
	}
	if len(snapshot.Devices.Devices) == 0 {
		fmt.Fprintln(tw, "-\t(no configured devices)\t-\t-\t-\t-")
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(output, "\nCandidate inbox")
	tw = tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tADDRESS / NAME\tSTATE\tFINGERPRINT\tSEEN")
	for index, candidate := range snapshot.Candidates.Candidates {
		location := candidateLocation(candidate)
		fingerprint := candidate.Fingerprint
		if fingerprint == "" {
			fingerprint = "pending active scan"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", index+1, terminalSafeInline(location), terminalSafeInline(string(candidate.State)),
			terminalSafeInline(shortFingerprint(fingerprint)), relativeTime(candidate.LastSeen))
	}
	if len(snapshot.Candidates.Candidates) == 0 {
		fmt.Fprintln(tw, "-\t(no candidates discovered)\t-\t-\t-")
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(snapshot.Devices.Events) > 0 {
		fmt.Fprintln(output, "\nRecent events")
		start := max(0, len(snapshot.Devices.Events)-6)
		for _, event := range snapshot.Devices.Events[start:] {
			fmt.Fprintf(output, "%s  %-16s %-16s %s\n", event.Time.Local().Format("15:04:05"), terminalSafeInline(event.Device), terminalSafeInline(string(event.State)), terminalSafeInline(event.Message))
		}
	}
	if message != "" {
		fmt.Fprintf(output, "\n%s\n", terminalSafeInline(message))
	}
	if clear {
		fmt.Fprintln(output, "\n[a] add candidate  [i] ignore  [p] poll device  [l] clear latch  [r] refresh  [q] quit")
	}
	return nil
}

func enrollCandidateFromTUI(ctx context.Context, output io.Writer, keys <-chan byte, client *http.Client, snapshot candidates.Snapshot) string {
	if len(snapshot.Candidates) == 0 {
		return "No discovered candidates to add."
	}
	index, err := promptIndex(output, keys, "Candidate number to add", len(snapshot.Candidates))
	if err != nil {
		return err.Error()
	}
	candidate := snapshot.Candidates[index]
	if candidate.State == candidates.StateIgnored {
		return "Candidate is ignored; restore it before enrollment."
	}
	if len(candidate.ConfiguredNames) > 0 {
		return "Candidate is already managed as " + strings.Join(candidate.ConfiguredNames, ", ") + "."
	}
	if candidate.Fingerprint == "" {
		return "Candidate has no SSH fingerprint yet; wait for an authorized active scan before enrollment."
	}
	// The fingerprint and key type are network-derived. internal/candidates
	// already strips control runes at ingestion, but every print site in this
	// package sanitizes independently so the guarantee does not depend on
	// another package's ingestion rules.
	fmt.Fprintf(output, "\r\nOn the candidate Mac, run:\r\n  ssh-keygen -lf %s\r\nExpected candidate identity: %s\r\n",
		terminalSafeInline(candidateHostKeyPath(candidate.KeyType)), terminalSafeInline(candidate.Fingerprint))
	verified, err := promptRawLine(output, keys, "Enter the complete fingerprint displayed locally on the Mac")
	if err != nil {
		return err.Error()
	}
	if strings.TrimSpace(verified) != candidate.Fingerprint {
		return "Fingerprint did not match; nothing was trusted or configured."
	}
	nameDefault := candidateDefaultName(candidate)
	name, err := promptRawLineDefault(output, keys, "Local alias", nameDefault)
	if err != nil {
		return err.Error()
	}
	hostDefault, portDefault := candidateDefaultEndpoint(candidate)
	host, err := promptRawLineDefault(output, keys, "Stable host or reserved IP", hostDefault)
	if err != nil {
		return err.Error()
	}
	portText, err := promptRawLineDefault(output, keys, "SSH port", strconv.Itoa(portDefault))
	if err != nil {
		return err.Error()
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "Invalid SSH port."
	}
	user, err := promptRawLine(output, keys, "macOS/FileVault username")
	if err != nil || user == "" {
		return "A username is required."
	}
	autoText, err := promptRawLineDefault(output, keys, "Enable automatic unlock? (yes/no)", "no")
	if err != nil {
		return err.Error()
	}
	autoUnlock := strings.EqualFold(autoText, "yes") || strings.EqualFold(autoText, "y")
	sourceDefault := credentials.ProviderRuntime
	if autoUnlock {
		sourceDefault = credentials.ProviderFile
	}
	source, err := promptRawLineDefault(output, keys, "Credential source (file/runtime)", sourceDefault)
	if err != nil {
		return err.Error()
	}
	source = strings.ToLower(strings.TrimSpace(source))
	if source == credentials.ProviderKeyring {
		return "Candidate enrollment cannot create a keyring credential; use a pre-provisioned file reference, runtime for manual unlock, or config add for a known device."
	}
	var reference string
	if source == credentials.ProviderFile {
		reference, err = promptRawLine(output, keys, "Secure secret path or systemd:<name> reference")
		if err != nil || reference == "" {
			return "A credential reference is required for the file provider."
		}
	}
	if autoUnlock && source == credentials.ProviderRuntime {
		return "Runtime/environment credentials cannot enable unattended automatic unlock."
	}
	request := enrollCandidateRequest{
		Name: name, Host: host, User: user, Port: port, Fingerprint: candidate.Fingerprint,
		CredentialSource: source, CredentialRef: reference, AutoUnlock: autoUnlock,
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var response struct {
		SchemaVersion int `json:"schema_version"`
	}
	endpoint := "/v1/candidates/" + url.PathEscape(candidate.ID) + "/enroll"
	if err := control.DoJSON(requestCtx, client, http.MethodPost, endpoint, request, &response); err != nil {
		return "Enrollment failed: " + err.Error()
	}
	return fmt.Sprintf("Added %s; monitoring starts immediately.", name)
}

func candidateHostKeyPath(keyType string) string {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "ssh-ed25519":
		return "/etc/ssh/ssh_host_ed25519_key.pub"
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		return "/etc/ssh/ssh_host_rsa_key.pub"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "/etc/ssh/ssh_host_ecdsa_key.pub"
	default:
		// Candidate discovery on current macOS normally reports Ed25519. Keep
		// the fallback explicit rather than guessing a different host-key file.
		return "/etc/ssh/ssh_host_ed25519_key.pub"
	}
}

func candidateActionFromTUI(ctx context.Context, output io.Writer, keys <-chan byte, client *http.Client, snapshot candidates.Snapshot, action string) string {
	if len(snapshot.Candidates) == 0 {
		return "No candidates available."
	}
	index, err := promptIndex(output, keys, "Candidate number to "+action, len(snapshot.Candidates))
	if err != nil {
		return err.Error()
	}
	candidate := snapshot.Candidates[index]
	if action == "ignore" && len(candidate.ConfiguredNames) > 0 {
		return "Candidate is already managed as " + strings.Join(candidate.ConfiguredNames, ", ") + "; it was not ignored."
	}
	endpoint := "/v1/candidates/" + url.PathEscape(candidate.ID) + "/" + action
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response candidates.Candidate
	if err := control.DoJSON(requestCtx, client, http.MethodPost, endpoint, nil, &response); err != nil {
		return action + " failed: " + err.Error()
	}
	return fmt.Sprintf("Candidate %s is now %s.", shortFingerprint(response.Fingerprint), response.State)
}

func deviceActionFromTUI(ctx context.Context, output io.Writer, keys <-chan byte, client *http.Client, snapshot monitor.Snapshot, action string) string {
	if len(snapshot.Devices) == 0 {
		return "No managed devices available."
	}
	index, err := promptIndex(output, keys, "Device number to "+action, len(snapshot.Devices))
	if err != nil {
		return err.Error()
	}
	device := snapshot.Devices[index]
	endpoint := "/v1/devices/" + url.PathEscape(device.Name) + "/" + action
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if action == "poll" {
		var response struct {
			Device monitor.DeviceSnapshot `json:"device"`
			Error  string                 `json:"error,omitempty"`
		}
		if err := control.DoJSON(requestCtx, client, http.MethodPost, endpoint, nil, &response); err != nil {
			return "poll failed: " + err.Error()
		}
		if response.Error != "" {
			return fmt.Sprintf("Poll completed for %s: %s (%s).", device.Name, response.Device.State, terminalSafeInline(response.Error))
		}
		return fmt.Sprintf("Poll completed for %s: %s.", device.Name, response.Device.State)
	}
	var response map[string]any
	if err := control.DoJSON(requestCtx, client, http.MethodPost, endpoint, nil, &response); err != nil {
		return action + " failed: " + err.Error()
	}
	return fmt.Sprintf("%s completed for %s.", action, device.Name)
}

func promptIndex(output io.Writer, keys <-chan byte, label string, count int) (int, error) {
	value, err := promptRawLine(output, keys, fmt.Sprintf("%s (1-%d)", label, count))
	if err != nil {
		return 0, err
	}
	index, err := strconv.Atoi(value)
	if err != nil || index < 1 || index > count {
		return 0, errors.New("selection is outside the displayed range")
	}
	return index - 1, nil
}

func promptRawLineDefault(output io.Writer, keys <-chan byte, label, defaultValue string) (string, error) {
	// Defaults are candidate-derived (an advertised Bonjour name or hostname),
	// so the prompt shows a sanitized rendering while the raw value is what the
	// operator accepts by pressing return.
	value, err := promptRawLine(output, keys, fmt.Sprintf("%s [%s]", label, terminalSafeInline(defaultValue)))
	if value == "" {
		value = defaultValue
	}
	return value, err
}

func promptRawLine(output io.Writer, keys <-chan byte, label string) (string, error) {
	fmt.Fprintf(output, "\r\n%s: \x1b[?25h", label)
	var value []rune
	defer fmt.Fprint(output, "\x1b[?25l")
	for {
		key := <-keys
		switch key {
		case 3, 27:
			fmt.Fprint(output, "\r\n")
			return "", errors.New("cancelled")
		case '\r', '\n':
			fmt.Fprint(output, "\r\n")
			return string(value), nil
		case 8, 127:
			if len(value) > 0 {
				value = value[:len(value)-1]
				fmt.Fprint(output, "\b \b")
			}
		default:
			r := rune(key)
			if unicode.IsPrint(r) && len(value) < 4096 {
				value = append(value, r)
				fmt.Fprintf(output, "%c", r)
			}
		}
	}
}

func candidateLocation(candidate candidates.Candidate) string {
	if len(candidate.Endpoints) > 0 {
		return net.JoinHostPort(candidate.Endpoints[0].Address, strconv.Itoa(candidate.Endpoints[0].Port))
	}
	if len(candidate.Hostnames) > 0 {
		return candidate.Hostnames[0]
	}
	if len(candidate.Names) > 0 {
		return candidate.Names[0]
	}
	return candidate.ID
}

func candidateDefaultEndpoint(candidate candidates.Candidate) (string, int) {
	if len(candidate.Endpoints) > 0 {
		return candidate.Endpoints[0].Address, candidate.Endpoints[0].Port
	}
	if len(candidate.Hostnames) > 0 {
		return candidate.Hostnames[0], 22
	}
	return "", 22
}

func candidateDefaultName(candidate candidates.Candidate) string {
	value := "mac"
	if len(candidate.Names) > 0 {
		value = candidate.Names[0]
	} else if len(candidate.Hostnames) > 0 {
		value = strings.TrimSuffix(candidate.Hostnames[0], ".local")
	}
	value = strings.ToLower(strings.TrimSpace(value))
	var cleaned strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			cleaned.WriteRune(r)
		} else if cleaned.Len() > 0 && !strings.HasSuffix(cleaned.String(), "-") {
			cleaned.WriteByte('-')
		}
	}
	result := strings.Trim(cleaned.String(), "-")
	if result == "" {
		return "mac"
	}
	return result
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 28 {
		return fingerprint
	}
	return fingerprint[:18] + "…" + fingerprint[len(fingerprint)-7:]
}

func relativeTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	delta := time.Until(value)
	if delta > 0 {
		return "in " + delta.Round(time.Second).String()
	}
	return (-delta).Round(time.Second).String() + " ago"
}

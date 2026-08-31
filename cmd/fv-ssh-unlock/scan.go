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
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/shoon/fv-ssh-unlock/internal/config"
	"github.com/shoon/fv-ssh-unlock/internal/securefs"
	"github.com/shoon/fv-ssh-unlock/pkg/fvcore"
)

const (
	defaultScanTimeout     = 1500 * time.Millisecond
	defaultScanConcurrency = 64
	maxScanConcurrency     = 256
	maxScanAddresses       = 4096
	maxKnownHostsSize      = 1 << 20
	defaultScanUser        = "fv-ssh-probe"
)

var errScanProbeStop = errors.New("scan probe: not answering authentication challenge")

const scanLongHelp = `Actively scan an explicit IPv4 CIDR for an SSH service, then
perform a password-free SSH handshake against each open port.

Unlike discover, scan does not use Bonjour. It can find a FileVault pre-boot
server that answers TCP/22 without advertising _ssh._tcp. The probe never reads
a credential, sends a password, offers a private key, enrolls a host key, or
changes device configuration.

When the complete FileVault explanation is present, scan reports a locked
FileVault server. Some observed macOS versions show only Password:; that
prompt is not a unique FileVault fingerprint and is reported as indeterminate.
The SSH host-key fingerprint is still collected and compared with configured,
pinned targets, which can identify a known Mac after its DHCP address changes.

An active scan creates connection and authentication-failure log entries and
may trigger network monitoring. Scan only networks you own or are authorized to
test. Each invocation is limited to 4096 IPv4 addresses.`

// newScanCommand returns the explicit, active SSH subnet scanner.
func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Actively find SSH servers in an explicit IPv4 CIDR without sending credentials",
		Long:  scanLongHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cidrs, _ := cmd.Flags().GetStringSlice("cidr")
			port, _ := cmd.Flags().GetInt("port")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			concurrency, _ := cmd.Flags().GetInt("concurrency")
			user, _ := cmd.Flags().GetString("user")
			verbose, _ := cmd.Flags().GetBool("verbose")

			if len(cidrs) == 0 {
				return errors.New("at least one --cidr is required")
			}
			if port < 1 || port > 65535 {
				return errors.New("--port must be between 1 and 65535")
			}
			if timeout <= 0 {
				return errors.New("--timeout must be greater than zero")
			}
			if concurrency < 1 || concurrency > maxScanConcurrency {
				return fmt.Errorf("--concurrency must be between 1 and %d", maxScanConcurrency)
			}
			if err := validateScanUser(user); err != nil {
				return err
			}

			addresses, err := expandScanCIDRs(cidrs)
			if err != nil {
				return err
			}
			pinned, err := loadPinnedTargetNames()
			if err != nil {
				return fmt.Errorf("load pinned target fingerprints: %w", err)
			}
			return runActiveScan(cmd.Context(), addresses, port, user, timeout, concurrency, pinned, verbose)
		},
	}
	cmd.Flags().StringSlice("cidr", nil, "IPv4 CIDR to scan (required; repeatable, maximum 4096 total addresses)")
	cmd.Flags().Int("port", 22, "TCP port to probe")
	cmd.Flags().Duration("timeout", defaultScanTimeout, "TCP and SSH timeout per address")
	cmd.Flags().Int("concurrency", defaultScanConcurrency, "Maximum simultaneous probes")
	cmd.Flags().String("user", defaultScanUser, "Synthetic SSH username used only to request the authentication challenge")
	cmd.Flags().Bool("verbose", false, "Show sanitized handshake failures for open ports")
	return cmd
}

func validateScanUser(user string) error {
	if user == "" || strings.TrimSpace(user) != user || len(user) > 256 {
		return errors.New("--user must be a non-empty SSH username of at most 256 bytes with no surrounding whitespace")
	}
	for _, r := range user {
		if unicode.IsControl(r) {
			return errors.New("--user must not contain control characters")
		}
	}
	return nil
}

// expandScanCIDRs returns a sorted, deduplicated list of usable addresses.
// Network and broadcast addresses are omitted for conventional prefixes; /31
// and /32 inputs retain every address because they have no broadcast slot.
func expandScanCIDRs(inputs []string) ([]netip.Addr, error) {
	unique := make(map[netip.Addr]struct{})
	for _, input := range inputs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(input))
		if err != nil {
			return nil, fmt.Errorf("invalid --cidr %q: %w", input, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("--cidr %q is not IPv4; exhaustive IPv6 scanning is not supported", input)
		}
		prefix = prefix.Masked()
		hostBits := 32 - prefix.Bits()
		if hostBits > 12 {
			return nil, fmt.Errorf("--cidr %q contains more than %d addresses; use a /20 or smaller range", input, maxScanAddresses)
		}

		all := make([]netip.Addr, 0, 1<<hostBits)
		for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr); addr = addr.Next() {
			all = append(all, addr)
		}
		if prefix.Bits() <= 30 && len(all) >= 2 {
			all = all[1 : len(all)-1]
		}
		for _, addr := range all {
			unique[addr] = struct{}{}
			if len(unique) > maxScanAddresses {
				return nil, fmt.Errorf("combined --cidr inputs exceed the %d-address limit", maxScanAddresses)
			}
		}
	}

	addresses := make([]netip.Addr, 0, len(unique))
	for addr := range unique {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	if len(addresses) == 0 {
		return nil, errors.New("the requested CIDR contains no usable addresses")
	}
	return addresses, nil
}

type scanFinding struct {
	address     netip.Addr
	port        int
	version     string
	keyType     string
	fingerprint string
	match       string
	evidence    string
	detail      string
}

func runActiveScan(ctx context.Context, addresses []netip.Addr, port int, user string, timeout time.Duration, concurrency int, pinned map[string][]string, verbose bool) error {
	fmt.Printf("Active password-free scan of %d IPv4 address(es) on TCP/%d...\n", len(addresses), port)
	fmt.Println("No passwords, identity keys, host-key enrollments, or configuration changes are used.")
	found, err := collectActiveScan(ctx, addresses, port, user, timeout, concurrency, pinned)
	if err != nil {
		return err
	}
	printScanFindings(found, len(addresses), verbose)
	return nil
}

// collectActiveScan runs the bounded password-free worker pool without
// printing. It is shared by the one-shot scan command and daemon discovery.
func collectActiveScan(ctx context.Context, addresses []netip.Addr, port int, user string, timeout time.Duration, concurrency int, pinned map[string][]string) ([]scanFinding, error) {

	jobs := make(chan netip.Addr)
	findings := make(chan scanFinding, concurrency)
	var workers sync.WaitGroup
	for range min(concurrency, len(addresses)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for address := range jobs {
				if finding, open := probeScanTarget(ctx, address, port, user, timeout); open {
					if names := pinned[finding.fingerprint]; len(names) > 0 {
						finding.match = strings.Join(names, ",")
					}
					findings <- finding
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, address := range addresses {
			select {
			case jobs <- address:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(findings)
	}()

	var found []scanFinding
	for finding := range findings {
		found = append(found, finding)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].address.Compare(found[j].address) < 0 })
	return found, nil
}

func probeScanTarget(parent context.Context, address netip.Addr, port int, user string, timeout time.Duration) (scanFinding, bool) {
	finding := scanFinding{address: address, port: port, match: "-"}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	base, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return finding, false
	}
	defer func() { _ = base.Close() }()
	_ = base.SetDeadline(time.Now().Add(timeout))

	captured := &identificationCaptureConn{Conn: base}
	trace := &scanAuthTrace{}
	cfg := &ssh.ClientConfig{
		User:          user,
		ClientVersion: "SSH-2.0-fv-ssh-unlock_scan",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, instruction string, questions []string, echos []bool) ([]string, error) {
			trace.add(instruction)
			for _, question := range questions {
				trace.add(question)
			}
			if len(questions) == 1 && len(echos) == 1 && !echos[0] && strings.EqualFold(strings.TrimSpace(questions[0]), "Password:") {
				trace.passwordPrompt = true
			}
			return nil, errScanProbeStop
		})},
		// Accept the offered key only for this no-secret observation. It is
		// recorded as a fingerprint but is never trusted or persisted.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			finding.keyType = key.Type()
			finding.fingerprint = ssh.FingerprintSHA256(key)
			return nil
		},
		BannerCallback: func(message string) error {
			trace.add(message)
			return nil
		},
		Timeout: timeout,
	}

	sshConn, _, _, handshakeErr := ssh.NewClientConn(captured, endpoint, cfg)
	if sshConn != nil {
		finding.version = softwareVersion(string(sshConn.ServerVersion()))
		_ = sshConn.Close()
	}
	if finding.version == "" {
		finding.version = captured.softwareVersion()
	}
	output := trace.String()
	switch {
	case fvcore.IsFileVaultLockedBanner(output):
		finding.evidence = "FileVault locked banner"
	case trace.passwordPrompt:
		finding.evidence = "Password prompt; state indeterminate"
	case finding.version != "" || finding.fingerprint != "":
		finding.evidence = "SSH; no FileVault banner"
	default:
		finding.evidence = "TCP open; no SSH identification"
	}
	if handshakeErr != nil {
		finding.detail = handshakeErr.Error()
	}
	return finding, true
}

type scanAuthTrace struct {
	strings.Builder
	passwordPrompt bool
}

func (t *scanAuthTrace) add(value string) {
	if value == "" {
		return
	}
	_, _ = t.WriteString(value)
	_ = t.WriteByte('\n')
}

// identificationCaptureConn records the plaintext SSH identification line
// while leaving the byte stream unchanged for x/crypto/ssh.
type identificationCaptureConn struct {
	net.Conn
	mu      sync.Mutex
	prefix  strings.Builder
	version string
}

func (c *identificationCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.capture(p[:n])
	}
	return n, err
}

func (c *identificationCaptureConn) capture(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != "" || c.prefix.Len() >= 8192 {
		return
	}
	remaining := 8192 - c.prefix.Len()
	if len(p) > remaining {
		p = p[:remaining]
	}
	c.prefix.Write(p)
	lines := strings.Split(c.prefix.String(), "\n")
	// The final element is still an incomplete network fragment unless the
	// captured input ended in a newline. Never classify a partial "SSH-" line.
	for _, line := range lines[:len(lines)-1] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSH-") {
			c.version = softwareVersion(line)
			return
		}
	}
}

func (c *identificationCaptureConn) softwareVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func softwareVersion(identification string) string {
	identification = strings.TrimSpace(identification)
	if strings.HasPrefix(identification, "SSH-2.0-") {
		return strings.TrimPrefix(identification, "SSH-2.0-")
	}
	return identification
}

func printScanFindings(findings []scanFinding, scanned int, verbose bool) {
	if len(findings) == 0 {
		fmt.Printf("\nNo open target ports found after scanning %d address(es).\n", scanned)
		return
	}

	addressWidth, versionWidth, matchWidth := len("ADDRESS"), len("SSH VERSION"), len("MATCH")
	for _, finding := range findings {
		addressWidth = max(addressWidth, len(finding.address.String()))
		versionWidth = max(versionWidth, len(terminalSafeInline(finding.version)))
		matchWidth = max(matchWidth, len(terminalSafeInline(finding.match)))
	}
	fmt.Println()
	fmt.Printf("%-*s  %-*s  %-*s  %s\n", addressWidth, "ADDRESS", versionWidth, "SSH VERSION", matchWidth, "MATCH", "EVIDENCE")
	fmt.Println(strings.Repeat("-", addressWidth+versionWidth+matchWidth+36))
	for _, finding := range findings {
		version := finding.version
		if version == "" {
			version = "-"
		}
		fmt.Printf("%-*s  %-*s  %-*s  %s\n", addressWidth, finding.address, versionWidth, terminalSafeInline(version), matchWidth, terminalSafeInline(finding.match), finding.evidence)
		if finding.fingerprint != "" {
			fmt.Printf("  host key: %s %s\n", terminalSafeInline(finding.keyType), terminalSafeInline(finding.fingerprint))
		}
		if verbose && finding.detail != "" {
			fmt.Printf("  handshake: %s\n", terminalSafeInline(finding.detail))
		}
	}
	fmt.Printf("\nScan complete: %d open port(s) across %d address(es).\n", len(findings), scanned)
	fmt.Println("MATCH is based on a previously pinned SSH host key; scan never enrolls keys.")
}

func loadPinnedTargetNames() (map[string][]string, error) {
	store, err := configStore()
	if err != nil {
		return nil, err
	}
	devices, err := store.Load()
	if err != nil {
		return nil, err
	}
	path, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	file, err := securefs.OpenStable(path, "known_hosts")
	if os.IsNotExist(err) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxKnownHostsSize {
		return nil, fmt.Errorf("known_hosts exceeds %d bytes", maxKnownHostsSize)
	}
	if err := securefs.VerifyPrivateFile(file); err != nil {
		return nil, fmt.Errorf("insecure known_hosts file %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKnownHostsSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKnownHostsSize {
		return nil, fmt.Errorf("known_hosts exceeds %d bytes", maxKnownHostsSize)
	}
	return matchPinnedTargetNames(data, devices), nil
}

func matchPinnedTargetNames(data []byte, devices []config.Device) map[string][]string {
	endpointNames := make(map[string][]string, len(devices))
	for _, device := range devices {
		endpoint := strings.ToLower(knownhosts.Normalize(deviceEndpoint(device)))
		endpointNames[endpoint] = append(endpointNames[endpoint], device.Name)
	}

	matches := make(map[string]map[string]struct{})
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.HasPrefix(fields[0], "@") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(fields[1:], " ")))
		if err != nil {
			continue
		}
		var names []string
		for _, host := range strings.Split(fields[0], ",") {
			names = append(names, endpointNames[strings.ToLower(host)]...)
		}
		if len(names) == 0 {
			continue
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if matches[fingerprint] == nil {
			matches[fingerprint] = make(map[string]struct{})
		}
		for _, name := range names {
			matches[fingerprint][name] = struct{}{}
		}
	}

	out := make(map[string][]string, len(matches))
	for fingerprint, names := range matches {
		for name := range names {
			out[fingerprint] = append(out[fingerprint], name)
		}
		sort.Strings(out[fingerprint])
	}
	return out
}

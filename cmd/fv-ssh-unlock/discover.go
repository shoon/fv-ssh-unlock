// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"
)

// Discovery is run as several short browse rounds rather than one long one.
//
// The upstream mDNS library stops re-querying the network as soon as the first
// service replies (it calls disableProbing() after delivering one entry), and it
// silently drops any entry whose A/AAAA record has not arrived yet. Since mDNS
// runs over lossy multicast, a single round reliably finds only a subset of the
// devices on a busy network. Starting a fresh browse each round issues a new
// query. Unioning the results across rounds recovers the stragglers.
const (
	defaultDiscoverTimeout = 12 * time.Second
	discoverRound          = 3 * time.Second
)

// discoverServices are the service types browsed each round. macOS registers
// both when Remote Login is enabled, so querying both gives a device two
// chances to be heard through multicast packet loss.
var discoverServices = []string{"_ssh._tcp", "_sftp-ssh._tcp"}

// newDiscoverCommand returns the `discover` command, which browses the local
// network for SSH services advertised over mDNS/Bonjour.
func newDiscoverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "List booted, Bonjour-advertised SSH services on the local network",
		Args:  cobra.NoArgs,
		Long: `Browse the local network for SSH services advertised over mDNS/Bonjour
and print their names, hostnames, ports, and IP addresses.

Discovery does not connect to a host or inspect an SSH or login banner. It only
collects _ssh._tcp and _sftp-ssh._tcp advertisements and cannot confirm that a
device supports FileVault unlock. Results are candidates to verify with config
add and the password-free status command.

A booted Mac normally advertises these services when Remote Login is enabled;
other SSH devices may advertise them too. FileVault pre-boot may accept SSH on
TCP/22 without advertising either Bonjour service, so a locked Mac may not
appear. Discovery is not a port scan or a recovery-time address locator.

Run discover while macOS is fully booted, then save and pin each target before
restarting it. Prefer a DHCP reservation (static lease) for the saved address.
A .local hostname and Bonjour service discovery are separate network features;
neither is proof that the other will be available in pre-boot. If the address
is unknown after restart, use scan --cidr <local-subnet> for an explicit,
password-free active search.

A Mac that is asleep, on another subnet/VLAN, or has Remote Login turned off
will not appear. Increase --timeout on a busy or lossy network to give slow
responders more time.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			timeout, _ := cmd.Flags().GetDuration("timeout")
			verbose, _ := cmd.Flags().GetBool("verbose")
			iface, _ := cmd.Flags().GetString("interface")
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than zero")
			}
			return discoverDevices(cmd.Context(), timeout, iface, verbose)
		},
	}
	cmd.Flags().Duration("timeout", defaultDiscoverTimeout, "How long to spend discovering devices")
	cmd.Flags().String("interface", "", "Only browse on this network interface (e.g. en0 or Ethernet)")
	cmd.Flags().Bool("verbose", false, "Report each browse round as it completes")
	return cmd
}

// device is a single discovered SSH host, accumulated across browse rounds.
type device struct {
	instance string
	hostname string
	port     int
	addrs    map[string]struct{}
}

// discoverDevices browses the Bonjour SSH service types and prints what it
// finds.
func discoverDevices(ctx context.Context, timeout time.Duration, iface string, verbose bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultDiscoverTimeout
	}
	ifaces := lanInterfaces(iface)
	if iface != "" && len(ifaces) == 0 {
		return fmt.Errorf("interface %q not found", iface)
	}
	if verbose {
		names := make([]string, 0, len(ifaces))
		for _, i := range ifaces {
			names = append(names, terminalSafeInline(i.Name))
		}
		if len(names) == 0 {
			fmt.Println("[verbose] no LAN interface detected; using library default (all interfaces)")
		} else {
			fmt.Printf("[verbose] browsing on: %s\n", strings.Join(names, ", "))
		}
	}
	fmt.Printf("Discovering Bonjour-advertised SSH services (up to %v)...\n", timeout)
	found, rounds, err := collectBonjourDevices(ctx, timeout, ifaces, verbose)
	if err != nil {
		return err
	}
	printDevices(found, rounds)
	return nil
}

// collectBonjourDevices performs the bounded browse without printing the final
// report. The daemon reuses it to feed its untrusted candidate inbox.
func collectBonjourDevices(ctx context.Context, timeout time.Duration, ifaces []net.Interface, verbose bool) (map[string]*device, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultDiscoverTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var mu sync.Mutex
	found := make(map[string]*device)
	rounds, firstErr := 0, error(nil)
	for ctx.Err() == nil {
		rounds++
		// Browse every service type concurrently within the round.
		var wg sync.WaitGroup
		for _, svc := range discoverServices {
			wg.Add(1)
			go func(service string) {
				defer wg.Done()
				if err := browseRound(ctx, discoverRound, service, ifaces, &mu, found); err != nil {
					if verbose {
						fmt.Printf("[verbose] round %d (%s) failed: %s\n", rounds, service, terminalSafeInline(err.Error()))
					}
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}(svc)
		}
		wg.Wait()
		if verbose {
			mu.Lock()
			n := len(found)
			mu.Unlock()
			fmt.Printf("[verbose] round %d complete; %d device(s) known\n", rounds, n)
		}
		// Every service failed on the first round and nothing was found: the
		// resolver is unusable (no multicast interface, permissions, etc.).
		if rounds == 1 && len(found) == 0 && firstErr != nil {
			return nil, rounds, fmt.Errorf("failed to browse for services: %w", firstErr)
		}
	}
	return found, rounds, nil
}

// browseRound runs one bounded browse of a single service type and merges
// results into found. Each round issues a fresh mDNS query (see the note on the
// constants above).
func browseRound(ctx context.Context, d time.Duration, service string, ifaces []net.Interface, mu *sync.Mutex, found map[string]*device) error {
	var opts []zeroconf.ClientOption
	if len(ifaces) > 0 {
		opts = append(opts, zeroconf.SelectIfaces(ifaces))
	}
	resolver, err := zeroconf.NewResolver(opts...)
	if err != nil {
		return fmt.Errorf("failed to initialize resolver: %w", err)
	}

	// Buffered: the library performs a blocking send, so an unbuffered channel
	// would stall its receive loop while we process an entry.
	entries := make(chan *zeroconf.ServiceEntry, 64)

	roundCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()

	if err := resolver.Browse(roundCtx, service, "local.", entries); err != nil {
		return err
	}

	// Drain until the library closes the channel on roundCtx expiry. Ranging
	// (rather than selecting against ctx.Done) guarantees we never discard
	// entries that are still queued when the deadline fires.
	for entry := range entries {
		if entry == nil {
			continue
		}
		mu.Lock()
		merge(found, entry)
		mu.Unlock()
	}
	return nil
}

// merge folds a service entry into the accumulated results, unioning addresses
// so a later round can supply an address an earlier one was missing.
//
// Entries are keyed by hostname, which is the stable identity of a device: the
// same Mac is announced under two service types (_ssh and _sftp-ssh) and may
// advertise several addresses (e.g. Wi-Fi and Ethernet), and those must collapse
// into one row.
func merge(found map[string]*device, e *zeroconf.ServiceEntry) {
	host := strings.TrimSuffix(strings.TrimSpace(e.HostName), ".")
	name := unescapeDNS(strings.TrimSpace(e.Instance))

	key := strings.ToLower(host)
	if key == "" {
		// A partially populated Bonjour entry may not have its SRV hostname yet.
		// Instance names are display labels rather than identities and are commonly
		// duplicated (for example, two default "MacBook Pro" names), so use the
		// advertised endpoint set rather than the label. Sorting makes announcements
		// from _ssh and _sftp-ssh collapse even if their address order differs,
		// while distinct address sets remain separate devices. An entry with neither
		// hostname nor address has no usable identity or connection target, so drop it
		// instead of risking a false merge by display name.
		addresses := make([]string, 0, len(e.AddrIPv4)+len(e.AddrIPv6))
		for _, group := range [][]net.IP{e.AddrIPv4, e.AddrIPv6} {
			for _, ip := range group {
				if ip != nil && !ip.IsUnspecified() {
					addresses = append(addresses, ip.String())
				}
			}
		}
		sortAddrs(addresses)
		if len(addresses) > 0 {
			key = fmt.Sprintf("endpoint:%s:%d", strings.Join(addresses, ","), e.Port)
		}
	}
	if key == "" {
		return
	}

	d, ok := found[key]
	if !ok {
		d = &device{addrs: make(map[string]struct{})}
		found[key] = d
	}
	if name != "" {
		d.instance = name
	}
	if host != "" {
		d.hostname = host
	}
	if e.Port != 0 {
		d.port = e.Port
	}
	for _, ip := range e.AddrIPv4 {
		if ip != nil && !ip.IsUnspecified() {
			d.addrs[ip.String()] = struct{}{}
		}
	}
	for _, ip := range e.AddrIPv6 {
		// Link-local IPv6 addresses are not useful as a connection target.
		if ip != nil && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
			d.addrs[ip.String()] = struct{}{}
		}
	}
}

// lanInterfaces returns the interfaces that plausibly carry LAN multicast.
//
// By default the mDNS library queries every up+multicast interface. On a Mac
// that includes AWDL (awdl0/llw0), bridges, and every VPN tunnel, often 20+
// interfaces. This wastes queries and makes responses less reliable. We keep
// only non-loopback, non-point-to-point interfaces that hold a routable IPv4
// address. Returning an empty slice makes the caller fall back to the library
// default.
func lanInterfaces(only string) []net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, ifi := range all {
		if only != "" {
			if ifi.Name == only {
				out = append(out, ifi)
			}
			continue
		}
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		// Loopback and VPN/utun tunnels do not carry LAN service announcements.
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		// Apple Wireless Direct Link and low-latency WLAN are peer-to-peer
		// links, not the local network.
		if strings.HasPrefix(ifi.Name, "awdl") || strings.HasPrefix(ifi.Name, "llw") {
			continue
		}
		if hasRoutableIPv4(ifi) {
			out = append(out, ifi)
		}
	}
	return out
}

func hasRoutableIPv4(ifi net.Interface) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// unescapeDNS decodes DNS presentation-format escapes, which the mDNS library
// leaves in instance names: "\DDD" is a decimal byte and "\x" is a literal x.
// Without this, "Shaun's Mac mini" is displayed as
// "Shaun\226\128\153s\ Mac\ mini".
func unescapeDNS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		// "\DDD" decimal escape.
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			n := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if n <= 255 {
				b.WriteByte(byte(n)) // #nosec G115 -- guarded to <= 255 above
				i += 4
				continue
			}
		}
		// "\x" literal escape.
		b.WriteByte(s[i+1])
		i += 2
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// deviceLabel is the display name for a discovered host: its Bonjour instance
// name, falling back to the advertised hostname.
func deviceLabel(d *device) string {
	if d.instance != "" {
		return d.instance
	}
	return d.hostname
}

// printDevices renders the results as a stable, sorted table.
//
// Rows are keyed by the accumulation key, which is the host's unique identity.
// The display label is not unique: two Macs can advertise the same Bonjour
// instance name, and keying the table by the label would silently drop one of
// them from the output.
func printDevices(found map[string]*device, rounds int) {
	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := deviceLabel(found[keys[i]]), deviceLabel(found[keys[j]])
		if left != right {
			return left < right
		}
		return keys[i] < keys[j]
	})

	if len(keys) == 0 {
		fmt.Printf("\nNo Bonjour SSH services found after %d browse round(s).\n", rounds)
		fmt.Println("Services normally appear while macOS is booted with Remote Login enabled.")
		fmt.Println("FileVault pre-boot may still answer TCP/22 without advertising Bonjour.")
		fmt.Println("If authorized, try: fv-ssh-unlock scan --cidr <local-subnet>")
		return
	}

	// Size the columns to the content so long Bonjour names stay readable.
	nameW, hostW := len("NAME"), len("HOSTNAME")
	for _, key := range keys {
		nameW = max(nameW, len(terminalSafeInline(deviceLabel(found[key]))))
		hostW = max(hostW, len(terminalSafeInline(found[key].hostname)))
	}

	fmt.Println()
	fmt.Printf("%-*s  %-*s  %-5s  %s\n", nameW, "NAME", hostW, "HOSTNAME", "PORT", "ADDRESSES")
	fmt.Printf("%s\n", strings.Repeat("-", nameW+hostW+7+20))
	for _, key := range keys {
		d := found[key]
		addrs := make([]string, 0, len(d.addrs))
		for a := range d.addrs {
			addrs = append(addrs, a)
		}
		sortAddrs(addrs)
		port := ""
		if d.port != 0 {
			port = fmt.Sprintf("%d", d.port)
		}
		fmt.Printf("%-*s  %-*s  %-5s  %s\n", nameW, terminalSafeInline(deviceLabel(d)), hostW, terminalSafeInline(d.hostname), port, strings.Join(addrs, ", "))
	}

	fmt.Printf("\nDiscovery complete: %d SSH service host(s) over %d browse round(s).\n", len(keys), rounds)
	fmt.Println("These are candidates only; discovery does not test SSH or FileVault readiness.")
	fmt.Println("Record a stable address before restart; a DHCP reservation is preferred.")
	fmt.Println("\nTo add a discovered device to your configuration, use:")
	fmt.Println("  fv-ssh-unlock config add <name> --host <stable-IP> --user <username>")
}

// sortAddrs orders IPv4 before IPv6, then lexically, so output is stable.
func sortAddrs(addrs []string) {
	sort.Slice(addrs, func(i, j int) bool {
		i4 := net.ParseIP(addrs[i]).To4() != nil
		j4 := net.ParseIP(addrs[j]).To4() != nil
		if i4 != j4 {
			return i4
		}
		return addrs[i] < addrs[j]
	})
}

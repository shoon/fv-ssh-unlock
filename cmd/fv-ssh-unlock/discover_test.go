// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
)

func parseIPs(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func keysOf(m map[string]*device) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loopbackFlag() net.Flags     { return net.FlagLoopback }
func pointToPointFlag() net.Flags { return net.FlagPointToPoint }

func TestDiscoverHelpStatesDiscoveryLimitations(t *testing.T) {
	cmd := newDiscoverCommand()
	for _, phrase := range []string{
		"does not connect",
		"login banner",
		"FileVault unlock",
		"without advertising either Bonjour service",
		"not a port scan",
		"DHCP reservation",
		".local hostname",
		"scan --cidr",
	} {
		if !strings.Contains(cmd.Long, phrase) {
			t.Errorf("discover help is missing limitation %q", phrase)
		}
	}
}

func TestDiscoverCommandAndInterfaceValidationAvoidsUnboundedBrowse(t *testing.T) {
	cmd := newDiscoverCommand()
	cmd.SetArgs([]string{"--timeout", "0s"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("zero discovery timeout = %v", err)
	}
	if err := discoverDevices(context.Background(), time.Second, "definitely-not-a-real-iface0", false); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown discovery interface = %v", err)
	}
}

func TestUnescapeDNS(t *testing.T) {
	cases := []struct{ in, want string }{
		// Real Bonjour instance names as the mDNS library reports them.
		{`Shaun\226\128\153s\ Mac\ mini`, "Shaun\u2019s Mac mini"},
		{`MacBook\ Pro\ \(2\)`, "MacBook Pro (2)"},
		{"m2studioalpha", "m2studioalpha"},
		// Edge cases.
		{"", ""},
		{`plain`, "plain"},
		{`trailing\`, `trailing\`},
		{`\\`, `\`},
		{`\999`, "999"}, // out of byte range: treated as a literal escape
	}
	for _, c := range cases {
		if got := unescapeDNS(c.in); got != c.want {
			t.Errorf("unescapeDNS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMergeCollapsesOneDeviceAcrossServices verifies that the same Mac seen via
// both _ssh._tcp and _sftp-ssh._tcp, and via several addresses, collapses into a
// single row keyed by hostname.
func TestMergeCollapsesOneDeviceAcrossServices(t *testing.T) {
	found := map[string]*device{}

	e1 := &zeroconf.ServiceEntry{HostName: "lab-mac.local.", Port: 22}
	e1.Instance = `Shaun\226\128\153s\ Mac\ mini`
	e1.AddrIPv4 = parseIPs("192.0.2.30")

	// Same host, other service type, second address (e.g. Wi-Fi as well as
	// Ethernet) and a trailing-dot hostname variant.
	e2 := &zeroconf.ServiceEntry{HostName: "lab-mac.local", Port: 22}
	e2.Instance = `Shaun\226\128\153s\ Mac\ mini`
	e2.AddrIPv4 = parseIPs("192.0.2.99")

	merge(found, e1)
	merge(found, e2)

	if len(found) != 1 {
		t.Fatalf("expected the two announcements to collapse into 1 device, got %d", len(found))
	}
	d := found["lab-mac.local"]
	if d == nil {
		t.Fatalf("device not keyed by hostname; keys: %v", keysOf(found))
	}
	if d.instance != "Shaun\u2019s Mac mini" {
		t.Errorf("instance name not decoded: %q", d.instance)
	}
	if len(d.addrs) != 2 {
		t.Errorf("expected both addresses to be unioned, got %v", d.addrs)
	}
}

// TestMergeKeepsDistinctDevicesSeparate guards against over-merging: two Macs
// with similar Bonjour names but different hostnames must stay separate.
func TestMergeKeepsDistinctDevicesSeparate(t *testing.T) {
	found := map[string]*device{}

	a := &zeroconf.ServiceEntry{HostName: "lab-mac.local.", Port: 22}
	a.Instance = `Shaun\226\128\153s\ Mac\ mini`
	a.AddrIPv4 = parseIPs("192.0.2.30")

	b := &zeroconf.ServiceEntry{HostName: "m4-beta.local.", Port: 22}
	b.Instance = `Shaun\226\128\153s\ Mac\ mini\ \(2\)`
	b.AddrIPv4 = parseIPs("192.0.2.31")

	merge(found, a)
	merge(found, b)

	if len(found) != 2 {
		t.Fatalf("expected 2 distinct devices, got %d: %v", len(found), keysOf(found))
	}
}

func TestLanInterfacesExcludesTunnelsAndLoopback(t *testing.T) {
	for _, ifi := range lanInterfaces("") {
		if ifi.Flags&loopbackFlag() != 0 {
			t.Errorf("loopback interface %s must be excluded", ifi.Name)
		}
		if ifi.Flags&pointToPointFlag() != 0 {
			t.Errorf("point-to-point interface %s must be excluded", ifi.Name)
		}
	}
	// An unknown interface name must yield nothing rather than everything.
	if got := lanInterfaces("definitely-not-a-real-iface0"); len(got) != 0 {
		t.Errorf("unknown interface should yield no interfaces, got %d", len(got))
	}
}

// TestPrintDevicesKeepsHostsSharingABonjourName guards against collapsing the
// table by display label: two Macs can advertise the same instance name, and
// both must still be listed.
func TestPrintDevicesKeepsHostsSharingABonjourName(t *testing.T) {
	found := map[string]*device{}

	first := &zeroconf.ServiceEntry{HostName: "lab-mac.local.", Port: 22}
	first.Instance = `MacBook\ Pro`
	first.AddrIPv4 = parseIPs("192.0.2.30")

	second := &zeroconf.ServiceEntry{HostName: "spare-mac.local.", Port: 22}
	second.Instance = `MacBook\ Pro`
	second.AddrIPv4 = parseIPs("192.0.2.31")

	merge(found, first)
	merge(found, second)
	if len(found) != 2 {
		t.Fatalf("expected 2 accumulated hosts, got %v", keysOf(found))
	}

	rendered := captureStdout(t, func() { printDevices(found, 1) })
	for _, phrase := range []string{"lab-mac.local", "spare-mac.local", "192.0.2.30", "192.0.2.31", "2 SSH service host(s)"} {
		if !strings.Contains(rendered, phrase) {
			t.Errorf("discovery table is missing %q:\n%s", phrase, rendered)
		}
	}
}

func TestMergeKeepsSameNameSeparateWhenHostnameIsMissing(t *testing.T) {
	found := map[string]*device{}

	first := &zeroconf.ServiceEntry{Port: 22}
	first.Instance = `MacBook\ Pro`
	first.AddrIPv4 = parseIPs("192.0.2.30")

	second := &zeroconf.ServiceEntry{Port: 22}
	second.Instance = `MacBook\ Pro`
	second.AddrIPv4 = parseIPs("192.0.2.31")

	merge(found, first)
	merge(found, second)
	if len(found) != 2 {
		t.Fatalf("same display name with distinct endpoint identities collapsed: %v", keysOf(found))
	}

	rendered := captureStdout(t, func() { printDevices(found, 1) })
	for _, phrase := range []string{"192.0.2.30", "192.0.2.31", "2 SSH service host(s)"} {
		if !strings.Contains(rendered, phrase) {
			t.Errorf("discovery table is missing %q:\n%s", phrase, rendered)
		}
	}
}

func TestMergeWithoutHostnameUsesStableEndpointSet(t *testing.T) {
	found := map[string]*device{}

	first := &zeroconf.ServiceEntry{Port: 22}
	first.Instance = `MacBook\ Pro`
	first.AddrIPv4 = parseIPs("192.0.2.30", "192.0.2.31")

	second := &zeroconf.ServiceEntry{Port: 22}
	second.Instance = `MacBook\ Pro`
	second.AddrIPv4 = parseIPs("192.0.2.31", "192.0.2.30")

	merge(found, first)
	merge(found, second)
	if len(found) != 1 {
		t.Fatalf("address ordering created duplicate endpoint identities: %v", keysOf(found))
	}
}

func TestMergeDropsEntryWithoutHostnameOrAddressIdentity(t *testing.T) {
	found := map[string]*device{}
	entry := &zeroconf.ServiceEntry{Port: 22}
	entry.Instance = `MacBook\ Pro`

	merge(found, entry)
	if len(found) != 0 {
		t.Fatalf("entry without a hostname or address was accepted by display name: %v", keysOf(found))
	}
}

func TestMergeFiltersUnusableAddressesAndDisplayHelpersFallBack(t *testing.T) {
	found := map[string]*device{}
	entry := &zeroconf.ServiceEntry{HostName: "ipv6-mac.local.", Port: 22}
	entry.AddrIPv4 = parseIPs("0.0.0.0", "192.0.2.50")
	entry.AddrIPv6 = parseIPs("::", "fe80::1", "2001:db8::50")
	merge(found, entry)
	d := found["ipv6-mac.local"]
	if d == nil {
		t.Fatal("host entry was not merged")
	}
	if _, ok := d.addrs["0.0.0.0"]; ok {
		t.Fatal("unspecified IPv4 address was retained")
	}
	if _, ok := d.addrs["fe80::1"]; ok {
		t.Fatal("link-local IPv6 address was retained")
	}
	for _, want := range []string{"192.0.2.50", "2001:db8::50"} {
		if _, ok := d.addrs[want]; !ok {
			t.Errorf("usable address %s missing from %+v", want, d.addrs)
		}
	}
	if got := deviceLabel(d); got != "ipv6-mac.local" {
		t.Fatalf("hostname display fallback = %q", got)
	}

	addresses := []string{"2001:db8::2", "192.0.2.9", "192.0.2.1", "2001:db8::1"}
	sortAddrs(addresses)
	if got := strings.Join(addresses, ","); got != "192.0.2.1,192.0.2.9,2001:db8::1,2001:db8::2" {
		t.Fatalf("stable address order = %q", got)
	}
}

func TestPrintDevicesReportsAnEmptyResult(t *testing.T) {
	rendered := captureStdout(t, func() { printDevices(map[string]*device{}, 3) })
	if !strings.Contains(rendered, "No Bonjour SSH services found after 3 browse round(s)") {
		t.Fatalf("unexpected empty discovery output:\n%s", rendered)
	}
}

// captureStdout collects what fn writes to os.Stdout, which is where the
// discovery table is printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	collected := make(chan string, 1)
	go func() {
		var buffer bytes.Buffer
		_, _ = io.Copy(&buffer, reader)
		collected <- buffer.String()
	}()
	fn()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	rendered := <-collected
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return rendered
}

# Discovery and scanning

[Documentation home](index.md) | [Use cases](use-cases.md) | [Troubleshooting](troubleshooting.md)

`discover` and `scan` find network candidates without using credentials. They
use different mechanisms and answer different questions.

## Contents

- [Choose the right network check](#choose-the-right-network-check)
- [Bonjour discovery](#bonjour-discovery)
- [Why a locked Mac can disappear](#why-a-locked-mac-can-disappear)
- [Names, aliases, and addresses](#names-aliases-and-addresses)
- [Active IPv4 scanning](#active-ipv4-scanning)
- [What banner evidence proves](#what-banner-evidence-proves)
- [Pinned host-key matching](#pinned-host-key-matching)
- [Scan options and safety](#scan-options-and-safety)

## Choose the right network check

| Check | Mechanism | What it establishes |
| --- | --- | --- |
| `discover` | Browses Bonjour for `_ssh._tcp` and `_sftp-ssh._tcp`. | A device is advertising SSH. It is not a TCP/22 scan. |
| Resolve `my-mac.local` | Performs an mDNS hostname lookup. | The hostname currently maps to an address. It says nothing about a service advertisement. |
| Test TCP/22 | Uses `nc`, `Test-NetConnection`, or another connection check. | Something accepts connections at the address and port. It does not identify FileVault. |
| `scan` | Connects to TCP/22 in an explicit IPv4 CIDR and performs a password-free SSH handshake. | Which addresses answer SSH, their public host-key fingerprints, and limited banner evidence. |
| `status` | Connects to one configured target and verifies its pinned SSH key. | A locked banner, accepted public key, or conservative `unknown` state. |

## Bonjour discovery

Use `discover` while normal macOS is booted:

```bash
fv-ssh-unlock discover
fv-ssh-unlock discover --timeout 30s
fv-ssh-unlock discover --interface en0
fv-ssh-unlock discover --verbose
```

The command combines the advertised service name, hostname, port, and
addresses into a candidate list. It does not open a TCP connection, perform an
SSH handshake, read a login banner, or look for FileVault-specific text.

A result may be a suitable Mac, a Mac without FileVault-over-SSH, or a non-Mac
SSH device. Identify it independently, save a stable address with `config add`,
and use `status` to enroll and verify the target's SSH host key.

A device can be absent when:

- Remote Login is off;
- the Mac is asleep;
- it is on another subnet or VLAN;
- multicast is filtered;
- the wrong interface was selected;
- packets were lost on busy Wi-Fi; or
- the Mac restarted into FileVault pre-boot and stopped advertising Bonjour.

On macOS, compare the browse with:

```bash
dns-sd -B _ssh._tcp local.
```

Increase `--timeout` for intermittent responses.

## Why a locked Mac can disappear

Real-hardware testing showed a Mac advertising SSH while normal macOS was
booted, then disappearing from Bonjour after it restarted into FileVault
pre-boot. TCP/22 still answered at the same address.

Plan discovery as a booted-state inventory operation, not a recovery-time
locator. Before restarting:

1. identify the correct Mac;
2. create a DHCP reservation for the interface used in pre-boot;
3. save the address in the client configuration; and
4. verify and pin the SSH host key.

If the address is unknown after restart, use `scan` only on a local subnet you
own or are authorized to test.

## Names, aliases, and addresses

In this command:

```bash
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser
```

`my-mac` is only an alias stored by `fv-ssh-unlock`. It does not create a DNS
record, a Bonjour service name, or a `.local` hostname.

The Mac's advertised name may include punctuation or differ from the alias you
prefer. Use its exact working hostname while booted, or preferably store its
reserved numeric address for pre-boot recovery.

`.local` names normally use multicast DNS rather than the network's ordinary
DNS server. Name resolution and Bonjour service browsing are independent, so
either can work while the other fails. On Windows, test mDNS resolution and the
SSH port with:

```powershell
Resolve-DnsName my-mac.local
Test-NetConnection -ComputerName my-mac.local -Port 22
```

Do not add `-DnsOnly` when testing `.local`; that bypasses mDNS.

## Active IPv4 scanning

Use `scan` when Bonjour finds nothing and you know the authorized local IPv4
subnet. The CIDR is required so the scope is explicit:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24
```

Example output:

```text
Active password-free scan of 254 IPv4 address(es) on TCP/22...
No passwords, identity keys, host-key enrollments, or configuration changes are used.

ADDRESS           SSH VERSION    MATCH      EVIDENCE
---------------------------------------------------------------
192.168.1.30      OpenSSH_10.2   lab-mac    Password prompt; state indeterminate
  host key: ssh-ed25519 SHA256:ZWAU0KRhq7wzMR3tHKKSVvwmCqAEAJsgq2E3gR3lRMY

Scan complete: 1 open port(s) across 254 address(es).
MATCH is based on a previously pinned SSH host key; scan never enrolls keys.
```

Unlike `discover`, `scan` actively connects. It performs enough of an SSH
handshake to collect the public host key and request the authentication
challenge. It never answers that challenge.

## What banner evidence proves

An original captured FileVault server included this distinctive explanation:

```text
This system is locked. To unlock it, use a local
account name and password...
```

When that text is present, the scanner reports `FileVault locked banner`.

A later macOS 26 FileVault server advertised `OpenSSH_10.2` but showed only the
generic hidden `Password:` prompt. Ordinary booted SSH servers can present the
same prompt. The OpenSSH version and advertised authentication methods are not
unique FileVault fingerprints either.

For that reason, the scanner reports `Password prompt; state indeterminate`
instead of guessing. The prompt-only server can still be unlocked after the
operator selects a configured, trusted target. Ambiguous evidence affects only
password-free classification.

## Pinned host-key matching

During setup, `status --accept-new-host-key` stores the target's verified SSH
host key. A later scan compares every presented public key with those pinned
keys. The `MATCH` column can therefore identify a known Mac at a new address
without sending its FileVault password.

A match proves that the server holds the private key corresponding to the
pinned public key. It separately reports the available state evidence. A match
with `Password prompt; state indeterminate` identifies the known target but
does not claim to distinguish pre-boot from booted password-only SSH.

## Scan options and safety

| Flag | Default | Purpose |
| --- | --- | --- |
| `--cidr <range>` | required | IPv4 CIDR to scan; repeatable. Combined input is limited to 4096 addresses. |
| `--port <number>` | `22` | Probe a nonstandard SSH port. |
| `--timeout <duration>` | `1.5s` | Bound the TCP connection and SSH handshake time per address. |
| `--concurrency <number>` | `64` | Parallel probes; accepted range is 1 through 256. |
| `--user <name>` | `fv-ssh-probe` | Synthetic username used only to request an authentication challenge. |
| `--verbose` | off | Show sanitized SSH handshake failures for open ports. |

Scanning is IPv4-only because exhaustive IPv6 subnet scanning is not
practical. The tool caps combined input at 4096 addresses.

`scan` never reads the OS keyring or environment credentials, loads private
identity keys, sends a password, enrolls a host key, stores a discovered key,
or changes device configuration. It does make connection attempts that may be
logged or trigger network monitoring. Scan only networks you own or are
authorized to test.

The default synthetic username worked with the observed FileVault server. If a
server suppresses the authentication challenge for unknown users, pass the
already-known local account:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24 --user unlockuser
```

This still sends no password or identity key.

---

[Documentation home](index.md) | [Use cases](use-cases.md) | [Troubleshooting](troubleshooting.md)

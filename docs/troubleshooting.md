# Troubleshooting

[Documentation home](index.md) | [Discovery and scanning](discovery-and-scanning.md) | [Security](security.md)

Start with the exact message printed by the client. Use `--verbose` when a
command offers it; network-controlled text is sanitized before display.

## Contents

- [`unknown host ... presented SHA256:...`](#unknown-host--presented-sha256)
- [`host key ... has CHANGED`](#host-key--has-changed)
- [Connection refused or timed out](#connection-refused-or-timed-out)
- [`status` reports `unknown`](#status-reports-unknown)
- [Unlock was accepted but not verified](#unlock-was-accepted-but-not-verified)
- [Password is rejected or missing](#password-is-rejected-or-missing)
- [Discovery finds no devices](#discovery-finds-no-devices)
- [Scan finds SSH but cannot prove FileVault](#scan-finds-ssh-but-cannot-prove-filevault)
- [A `.local` name does not resolve](#a-local-name-does-not-resolve)
- [Configuration is rejected](#configuration-is-rejected)

## `unknown host ... presented SHA256:...`

This is expected on the first connection. The client fails closed until you
verify and enroll the target's SSH host key.

On the booted target Mac, obtain the Ed25519 fingerprint:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Compare the key type and complete SHA256 value with the client output. Enroll
only an exact match:

```bash
fv-ssh-unlock status my-mac --accept-new-host-key
```

Enrollment sends no password. See
[SSH host-key enrollment](security.md#ssh-host-key-enrollment).

## `host key ... has CHANGED`

Stop. Do not retry with `--insecure-host-key`.

Confirm that the configured address still belongs to the intended Mac. Check
for a macOS reinstall, hardware repair, regenerated SSH host keys, DHCP address
reuse, DNS problems, and possible interception. Remove the old pinned key only
after verifying the replacement fingerprint directly on the target through a
trusted channel.

## Connection refused or timed out

Check all of the following:

- Remote Login was enabled before the restart.
- The configured address and port are correct.
- The Mac has power and has reached the FileVault screen.
- The selected Ethernet or Wi-Fi interface works in pre-boot.
- DHCP, firewall, VLAN, routing, VPN, and access-control policies allow the
  client to reach the target.
- Another device has not received the same DHCP address.
- A nonstandard SSH port was configured consistently.

The first attempt can fail while pre-boot networking starts. `unlock` retries
ten times with a 30-second delay by default.

Prefer a DHCP reservation for the exact interface used in pre-boot. If you use
a manual static address, keep it outside the DHCP pool and test it through a
full restart. An unreserved lease can change. Host-key pinning will reject a
different machine that later receives the old address.

Basic client checks include:

```bash
nc -vz 192.0.2.10 22
```

PowerShell:

```powershell
Test-NetConnection -ComputerName 192.0.2.10 -Port 22
```

An open port proves only that something is listening, not that it is the
FileVault pre-boot service.

## `status` reports `unknown`

This is a safe evidence result, not a password-handling error. An observed
FileVault pre-boot server showed only the generic hidden `Password:` prompt.
A booted password-only SSH server can show the same prompt, so the client does
not guess.

To positively prove that normal macOS is booted, authorize a public key for the
account and either load the corresponding private key into `ssh-agent` or pass
an unencrypted key explicitly:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

An `unknown` status does not mean an explicit `unlock` will fail. The unlock
command can answer the exact supported prompt after the pinned host key is
verified.

## Unlock was accepted but not verified

`SUCCESS` proves that the trusted pre-boot server accepted the password.
Verification is a second, password-free step. It can fail or time out because:

- the Mac is still booting;
- the address changed;
- Remote Login is unavailable after boot;
- no public key is authorized for the normal macOS user;
- no suitable key is loaded in `ssh-agent` or passed with `--identity`; or
- a firewall or network transition blocks the booted SSH service.

Try normal `ssh`, increase `--verify-timeout`, or run a later status check:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

The accepted unlock is not retracted merely because the booted state could not
be proved.

## Password is rejected or missing

- Confirm that the configured username is a local account allowed to unlock
  FileVault.
- Confirm that the same account is allowed by Remote Login.
- Check the environment-variable spelling using the rules in
  [Environment variables](configuration-and-credentials.md#environment-variables).
- Remember that variables are scoped to the shell, task, or service that
  launches the client.
- A keyring-enabled binary may require an unlocked desktop keyring.
- Run one target at a time to receive an interactive prompt.
- Confirm that the password has not been rotated on only one side of your
  process.

The client does not retry a rejected password. Repeated automatic attempts
would add risk and cannot fix an invalid credential.

## Discovery finds no devices

Confirm that the Mac is awake, normal macOS is booted, and Remote Login is
enabled. Check that client and target share a multicast-capable network. Remove
`--interface` or use the correct interface name, and increase `--timeout`.

Discovery is not expected to find every Mac after it enters FileVault
pre-boot. A locked Mac can answer TCP/22 without advertising either Bonjour SSH
service. Use the stable configured address instead of treating an empty result
as a failed pre-boot SSH service.

If the address is unknown, scan an authorized local IPv4 subnet and look for a
pinned-key `MATCH` or the distinctive locked banner:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24
```

See [Discovery and scanning](discovery-and-scanning.md) for the limits of each
network check.

## Scan finds SSH but cannot prove FileVault

`Password prompt; state indeterminate` is expected when the server shows only a
generic hidden prompt. The SSH version, password prompt, and advertised
authentication methods are not unique FileVault fingerprints.

A previously pinned key in the `MATCH` column can still identify a known Mac.
Without a pinned match or distinctive locked explanation, independently
identify the host before adding or trusting it. Scanning never enrolls the key
and never sends a credential.

If the server does not present an authentication challenge for the default
synthetic user, retry with the already-known local account:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24 --user unlockuser
```

## A `.local` name does not resolve

The alias passed to `config add` is not a DNS registration. Use the exact
hostname advertised by the Mac, including punctuation and `.local`, or use its
reserved numeric address.

`.local` normally uses multicast DNS, not the network's ordinary DNS server.
On Windows, test it with:

```powershell
Resolve-DnsName my-mac.local
Test-NetConnection -ComputerName my-mac.local -Port 22
```

Do not add `-DnsOnly`; it bypasses mDNS and can report failure even when the
multicast name works. Name resolution and Bonjour service discovery are
independent, so either can work without the other. Pre-boot can also lose both
while TCP/22 remains reachable at a reserved address.

## Configuration is rejected

The parser refuses symbolic links, oversized files, unknown JSON fields,
duplicate device names, ambiguous environment-variable names, invalid ports,
malformed hosts, and hosts that include a port. Use `--port` separately.

Prefer `config add`, `config show`, and `config remove` over manual editing. If
manual recovery is unavoidable, first preserve the file and ensure it remains
owned and readable only by the intended local user.

---

[Documentation home](index.md) | [Discovery and scanning](discovery-and-scanning.md) | [Security](security.md)

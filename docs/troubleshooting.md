# Troubleshooting

[Documentation home](index.md) | [Discovery and scanning](discovery-and-scanning.md) | [Security](security.md)

Start with the exact message printed by the client. Use `--verbose` when a
command offers it; network-controlled text is sanitized before display.

## Contents

- [`unknown host ... presented SHA256:...`](#unknown-host--presented-sha256)
- [`host key ... has CHANGED`](#host-key--has-changed)
- [Connection refused or timed out](#connection-refused-or-timed-out)
- [`status` reports `indeterminate`](#status-reports-indeterminate)
- [Unlock was accepted but not verified](#unlock-was-accepted-but-not-verified)
- [Password is rejected or missing](#password-is-rejected-or-missing)
- [Credential provider or unsafe-storage error](#credential-provider-or-unsafe-storage-error)
- [The daemon will not start](#the-daemon-will-not-start)
- [Collecting daemon diagnostics](#collecting-daemon-diagnostics)
- [Understanding daemon states](#understanding-daemon-states)
- [Health check or TUI cannot reach the daemon](#health-check-or-tui-cannot-reach-the-daemon)
- [Recovering a latched device](#recovering-a-latched-device)
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

## `status` reports `indeterminate`

This is a safe evidence result, not a password-handling error. An observed
FileVault pre-boot server showed only the generic hidden `Password:` prompt.
A booted password-only SSH server can show the same prompt, so the client does
not guess.

To positively prove that normal macOS is booted, authorize a public key for the
account. The client automatically tries keys in `ssh-agent` and standard
regular identity files such as `~/.ssh/id_ed25519` and `~/.ssh/id_rsa`. Pass an
unencrypted key explicitly if it has another name:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

An `indeterminate` status does not mean an explicit `unlock` will fail. The unlock
command can answer the exact supported prompt after the pinned host key is
verified.

## Unlock was accepted but not verified

`SUCCESS` proves that the trusted pre-boot server accepted the password.
Verification is a second, password-free step. It can fail or time out because:

- the Mac is still booting;
- the address changed;
- Remote Login is unavailable after boot;
- no public key is authorized for the normal macOS user;
- no suitable key is available from `ssh-agent`, a standard `~/.ssh` identity,
  or `--identity`; or
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

## Credential provider or unsafe-storage error

Inspect capabilities as the same user and inside the same service or container
that runs the unlock command:

```bash
fv-ssh-unlock credentials providers
fv-ssh-unlock credentials providers --json
```

`built: yes` means the binary contains the provider. `available: yes` means it
appears usable in the current execution environment. For example, a
keyring-enabled Linux binary may still lack a Secret Service D-Bus session.
TPM2 hardware can be reported as detected while the provider remains
unavailable; the current binary does not claim TPM-backed protection until a
complete direct sealing backend exists. A systemd service may still use a
TPM2-encrypted systemd credential through the `file` provider.

The file provider accepts recognized service-scoped delivery without an
override when its filesystem is verified as memory-backed: systemd's
`$CREDENTIALS_DIRECTORY`, or a Linux file below `/run/secrets`. An ordinary
disk bind mount remains a plaintext disk file and fails closed. Use a Swarm
secret, systemd credential, OS keyring, or runtime injection when possible.
For systemd services, configure `systemd:<credential-name>` so the provider
resolves the unit-specific `$CREDENTIALS_DIRECTORY` at runtime.

If a plaintext file is intentional, both the configuration action and every
unlock that reads it must explicitly include
`--allow-unsafe-credential-storage`. The acknowledgement is never saved and
does not enable a fallback from another provider.

## The daemon will not start

Run the provider preflight as the same account and inside the same systemd unit
or container environment that will run the daemon:

```bash
fv-ssh-unlock credentials providers --require-secure
```

The persistent daemon validates every device with automatic unlock enabled
before opening its control socket. It refuses:

- `runtime` or environment credentials for unattended automatic unlock;
- an unavailable desktop keyring, including a Linux service with no usable
  Secret Service D-Bus session;
- an ordinary disk-backed credential file;
- a missing or insecure `systemd:<name>` or `/run/secrets` reference; and
- invalid monitor intervals, timeouts, concurrency, socket paths, or discovery
  settings.

There is intentionally no daemon `--allow-unsafe-credential-storage` flag.
Disable automatic unlock for a device while diagnosing it, or provision a
secure provider in the daemon's real runtime environment. A systemd credential
reference resolves through that unit's `$CREDENTIALS_DIRECTORY`; testing the
same reference in an unrelated shell can produce a different assessment.

For a one-cycle diagnostic that prints the resulting JSON without opening the
socket, run:

```bash
fv-ssh-unlock daemon --once
```

This is not a dry run. It applies normal automatic-unlock policy and can submit
a credential if it conclusively finds an auto-enabled device locked. Use
`status --json` with no device names instead when you require password-free
observation of all configured devices only.

Use the same global `--data-dir /absolute/path` argument as the eventual
service when its configuration is not under the current user's default
`~/.fv-ssh-unlock` directory.

## Collecting daemon diagnostics

Normal service operation uses `--log-format text --log-level info`. For a
machine-readable incident capture, restart the supervised daemon with:

```bash
fv-ssh-unlock daemon --log-format json --log-level debug
```

`debug` adds each password-free probe and candidate-discovery round and can be
noisy; return to `info` after the incident. For systemd, inspect the configured
unit rather than starting a competing daemon, add the flags to its existing
`ExecStart`, restart it, and follow the journal:

```bash
journalctl -u fv-ssh-unlock -f -o cat
```

For the supplied Compose deployment:

```bash
docker compose -f deploy/docker-compose.yml logs -f fv-ssh-unlock
```

Do not redirect a long-running daemon to an unmanaged file without retention.
Use journald, the Docker logging driver, or a host Fluent Bit/Vector collector.
JSON fields are documented in [Operational logging and SIEM
collection](daemon-and-tui.md#operational-logging-and-siem-collection).

Logs deliberately omit credential values, authentication answers, private-key
bodies, API request bodies, and raw SSH/FileVault banners. They still contain
device names, endpoints, candidate hostnames, and state changes; redact those
metadata before posting a diagnostic log publicly.

## Understanding daemon states

The TUI and `daemon --once` use these states:

| State | Meaning and automatic action |
| --- | --- |
| `booted` | Normal macOS SSH accepted a public key. No unlock action is needed. |
| `locked` | The complete supported FileVault banner was observed. Automatic unlock runs only if it is explicitly enabled and credential preflight passed. |
| `indeterminate` | SSH is reachable, but neither FileVault nor booted macOS can be proved without a password. No credential is sent. Configure a normal macOS SSH public key. |
| `unreachable` | The password-free connection failed. Ordinary failures back off. An auto-enabled endpoint specifically known down uses a short TCP preflight to wake the full SSH probe when port 22 returns; reachability alone never authorizes unlock. |
| `unlocking` | The durable attempt marker was written and one unlock operation is in progress. |
| `booting` | A credential was accepted or submitted with an unacknowledged transition. The daemon probes without the password and will not resubmit it in this lock episode. |
| `credential-failed` | Credential retrieval or FileVault authentication failed and automatic attempts are latched. Correct the provider or password before clearing the latch. |
| `error` | A host-key or other operational error occurred. Check the event text; host-key failures latch and require independent verification. |

Inspect one noninteractive dashboard snapshot with:

```bash
fv-ssh-unlock tui --once
fv-ssh-unlock tui --json
```

Use `--socket /absolute/path/control.sock` when the daemon uses a nondefault
socket. The interactive TUI requires a real terminal; `--once` and `--json`
are suitable for scripts and log collection.

## Health check or TUI cannot reach the daemon

Check the exact socket directly through the supported client:

```bash
fv-ssh-unlock healthcheck
fv-ssh-unlock healthcheck --json --timeout 5s
fv-ssh-unlock healthcheck --socket /absolute/path/control.sock
```

The default is `control.sock` inside the effective data directory. The daemon,
TUI, and health check must agree on `--data-dir`, `--socket`, or the
`FV_SSH_UNLOCK_SOCKET` environment variable. Both `--socket` and the
environment value must be absolute paths.

If startup says the data or socket directory is accessible by group or other
users, create a dedicated mode-`0700` directory owned by the service account
and point `--data-dir` or `--socket` there. The program intentionally refuses
to chmod an existing shared directory such as `/tmp`.

If the file is absent, confirm that the daemon is still running and inspect its
startup logs. If it exists but access is denied, confirm that the client is the
same account as the daemon and that the data directory and socket have modes
`0700` and `0600`. Do not replace the socket with a regular file or symbolic
link. A healthy response confirms the local API event loop is answering; it
does not claim that every Mac is reachable or booted.

## Recovering a latched device

Do not clear a latch before correcting its cause:

1. For `credential-failed`, verify the provider is available to the daemon and
   update a rotated or incorrect FileVault password at its source.
2. For a changed host key, stop and compare the complete fingerprint directly
   on the Mac. Follow [Changed host keys](security.md#changed-host-keys); never
   substitute `--insecure-host-key` in the daemon.
3. Open `fv-ssh-unlock tui`, press `[l] clear latch`, and select the device.
4. Press `[p] poll device` to request an immediate password-free observation,
   or allow the normal schedule to continue.

Clearing the latch is an explicit operator acknowledgement. If the last
definitive observation is still `locked`, it permits another automatic attempt
after the persisted cooldown. It does not bypass host-key pinning, credential
preflight, or the definitive-banner requirement.

Do not delete `monitor-state.json` to clear a latch. That also discards the
one-submission episode and cooldown record. Preserve the file and daemon logs
when investigating corruption or permissions; the state file must be a
regular, non-symbolic, private file.

## Discovery finds no devices

Confirm that the Mac is awake, normal macOS is booted, and Remote Login is
enabled. Check that client and target share a multicast-capable network. Remove
`--interface` or use the correct interface name, and increase `--timeout`.

Discovery is not expected to find every Mac after it enters FileVault
pre-boot. A locked Mac can answer TCP/22 without advertising either Bonjour SSH
service. Use the stable configured address instead of treating an empty result
as a failed pre-boot SSH service.

The daemon runs Bonjour discovery immediately and then at
`--discover-interval` (five minutes by default); set the interval to `0` to
disable it. Use `--discover-interface NAME` when multicast must be restricted
to one interface. Bonjour requires multicast to reach the daemon's network
namespace and does not cross most VLANs, routed networks, VPNs, or container
bridges without explicit support.

Periodic active scanning is disabled until at least one authorized
`--scan-cidr` is supplied. Each CIDR is scanned immediately and then at
`--scan-interval` (15 minutes by default). Active scans make SSH connections
and can appear in logs or intrusion detection. A candidate must have a public
SSH fingerprint before the TUI will enroll it; a Bonjour-only entry can remain
`pending active scan` until an authorized scan observes its SSH service.

Candidate discovery never enables management automatically. In the TUI, press
`[a] add candidate`, compare the complete fingerprint with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the Mac, and enter that
complete value. A mismatch enrolls nothing. Newly enrolled devices begin
monitoring immediately without restarting the daemon.

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

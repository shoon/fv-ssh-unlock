<p align="center">
  <img src="assets/fv-ssh-unlock.png" width="128" height="128" alt="fv-ssh-unlock icon">
</p>

<h1 align="center">fv-ssh-unlock</h1>

<p align="center">
  Securely unlock a FileVault-protected Mac over SSH after a restart.
</p>

<p align="center">
  <a href="https://github.com/shoon/fv-ssh-unlock/actions/workflows/ci.yml"><img src="https://github.com/shoon/fv-ssh-unlock/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/shoon/fv-ssh-unlock/releases/latest"><img src="https://img.shields.io/github/v/release/shoon/fv-ssh-unlock?display_name=tag&amp;sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/shoon/fv-ssh-unlock" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/Go-1.26.7-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.26.7 or newer">
  <img src="https://img.shields.io/badge/target-macOS%2026%2B-111111" alt="Targets macOS 26 or newer">
  <a href="https://github.com/sponsors/shoon"><img src="https://img.shields.io/badge/Sponsor-shoon-EA4AAA?logo=githubsponsors&amp;logoColor=white" alt="Sponsor shoon on GitHub"></a>
</p>

`fv-ssh-unlock` is a command-line client for Apple's
FileVault-over-SSH feature. Run it from another computer when an Apple silicon
Mac has restarted and is waiting at the FileVault login screen. The tool sends
the local account password through the Mac's pre-boot SSH service, confirms that
the unlock was accepted, and can then wait for normal macOS SSH to return.

The client runs on macOS, Linux, or Windows. Nothing is installed on the target
Mac, and no background service or cloud account is required.

> [!IMPORTANT]
> This works only with the FileVault SSH feature in **macOS 26 (Tahoe) or
> newer on Apple silicon**. Remote Login must be enabled before the Mac
> restarts, and the pre-boot environment must have a working network
> connection. Apple documents the feature in its
> [Platform Security guide](https://support.apple.com/en-gb/guide/security/sec8447f5049/web)
> and in `man apple_ssh_and_filevault` on macOS 26.

> [!NOTE]
> This is an independent open source project. It is not affiliated with,
> sponsored by, or endorsed by Apple Inc. See [TRADEMARKS.md](TRADEMARKS.md).

## Table of contents

- Getting started
  - [Features and benefits](#features-and-benefits)
  - [Quick start](#quick-start)
  - [Requirements](#requirements)
  - [Use cases](#use-cases)
  - [Additional installation and verification options](#additional-installation-and-verification-options)
- Using the tool
  - [Credentials](#credentials)
  - [Manage devices](#manage-devices)
  - [Unlock behavior](#unlock-behavior)
  - [Password-free status checks](#password-free-status-checks)
  - [Discover candidate Macs](#discover-candidate-macs-on-the-local-network)
  - [Actively scan for SSH](#actively-scan-for-ssh-without-credentials)
  - [Command reference](#command-reference)
  - [Shell completion](#shell-completion)
  - [Remove the tool](#remove-the-tool)
- Security and support
  - [SSH host-key safety](#ssh-host-key-safety)
  - [Files and privacy](#files-and-privacy)
  - [Troubleshooting](#troubleshooting)
  - [Security design](#security-design)
  - [Mock FileVault SSH server](#mock-filevault-ssh-server)
  - [Build and test](#build-and-test)
  - [Limitations](#limitations)
  - [Contributing](#contributing)
  - [Support development](#support-development)
  - [License](#license)

## Features and benefits

Nothing is installed on the target Mac. The client provides these commands:

| Command | Feature | Benefit |
| --- | --- | --- |
| `discover` | List booted hosts advertising `_ssh._tcp` or `_sftp-ssh._tcp` over Bonjour. | Build an inventory before a restart. Discovery does not connect, scan TCP/22, or claim a host is FileVault-ready. |
| `scan` | Probe TCP/22 across an explicit IPv4 CIDR, collect SSH host-key fingerprints, and inspect password-free banner evidence. | Find a pre-boot Mac that stopped advertising Bonjour or whose DHCP address changed. |
| `config add` | Save a target name, stable hostname or IP address, port, local username, credential source, and optional success message. | Refer to known Macs by short names and retain the recovery address needed when Bonjour may be absent. |
| `config list`, `show`, `remove` | Inspect or remove one, several, or all saved targets. | Manage a single Mac or a lab fleet from the same client. |
| `status` | Classify a trusted target as `locked`, `unlocked`, or `unknown` without loading its FileVault password. | Check availability and enroll host keys without exposing the unlock secret. |
| `unlock` | Unlock named targets or every configured target, with retry and optional boot verification. | Recover one remote Mac or an entire group after restarts and power events. |
| `completion` | Generate Bash, Zsh, Fish, or PowerShell completion. | Make repeated interactive use faster and less error-prone. |
| `--help`, `--version` | Show command-specific help and build version information. | Support scripting, troubleshooting, and reproducible operator workflows. |

Security and operational features provide the following benefits:

| Feature | Benefit |
| --- | --- |
| SSH host-key pinning | Protects the FileVault password from being sent to an impersonated host; unknown and changed keys fail closed. |
| Password-free state checks | Lets operators inspect a target or enroll its host key without retrieving or transmitting its unlock password. |
| OS keyring, environment, and prompt credential sources | Supports interactive workstations, headless automation, and one-off use without storing passwords in `devices.json`. |
| Configurable retries | Handles slow or intermittent pre-boot networking without retrying bad passwords or security failures. |
| Public-key boot verification | Confirms normal macOS SSH returned after an accepted unlock without reusing the FileVault password. |
| Multi-device operation | Unlocks a named subset or every configured Mac in one invocation. |
| IPv4, IPv6, hostnames, and custom ports | Works across common lab and remote-access network layouts. |
| Stable-address workflow | Encourages a DHCP reservation before restart so recovery does not depend on Bonjour or a changing lease. |
| Terminal-safe verbose diagnostics | Makes network and protocol failures understandable without printing passwords or trusting network-controlled terminal text. |
| macOS, Linux, and Windows clients | Allows the unlock workstation or automation host to use any supported desktop operating system. |

The workflow has four trust steps:

```mermaid
flowchart LR
    candidates["1. Find candidates<br/>discover or scan"]
    configure["2. Add target<br/>save address and user"]
    trust["3. Enroll host key<br/>no password sent"]
    operate["4. Check or unlock<br/>use the trusted target"]

    candidates --> configure --> trust --> operate
```

## Quick start

This shortest path assumes you already have an Apple silicon Mac running
macOS 26 or newer with FileVault and Remote Login configured, and that you know
its address, FileVault-enabled local username, and password. For a new Mac, see
[Use case 3](#use-case-3-prepare-a-new-target-mac-and-choose-an-account).

### 1. Install the client

Download and extract the archive for your client computer from the
[latest GitHub release](https://github.com/shoon/fv-ssh-unlock/releases/latest),
then put `fv-ssh-unlock` (or `fv-ssh-unlock.exe`) on your `PATH`.

To build from source instead:

```bash
git clone https://github.com/shoon/fv-ssh-unlock.git
cd fv-ssh-unlock
go build -tags keyring -o fv-ssh-unlock ./cmd/fv-ssh-unlock
```

PowerShell uses an `.exe` output name:

```powershell
go build -tags keyring -o fv-ssh-unlock.exe ./cmd/fv-ssh-unlock
```

The keyring build is recommended for interactive use because it can store each
password in the operating system's credential store.

### 2. Add a known Mac

Give the Mac a short local name and provide the address and existing local
username:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 \
  --user unlockuser \
  --port 22
```

A keyring-enabled build asks whether to store the password and then prompts for
it without echoing. The password is never accepted as a command-line flag. If
you choose not to store it, a single-device `unlock` prompts when needed.

Use a predictable address for recovery. A **DHCP reservation (static lease) is
the preferred choice**: reserve an address for the Ethernet or Wi-Fi interface
the Mac will use at FileVault pre-boot. A manually assigned static address is a
fallback; keep it outside the dynamic pool, check for conflicts, and test it
through a real restart. A `.local` name is convenient while macOS is booted but
should not be the only address recorded for recovery.

### 3. Verify and pin the SSH host key

From a trusted terminal on the target Mac, record its fingerprint:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

The first status check fails closed and prints the key offered by the remote
host:

```bash
fv-ssh-unlock status my-mac
```

Compare the two SHA256 fingerprints. Only if they match, enroll the key with
the password-free status command:

```bash
fv-ssh-unlock status my-mac \
  --accept-new-host-key \
  --identity ~/.ssh/id_ed25519
```

The matching public key must be authorized for the account in normal macOS.
On Windows, use a path such as
`C:\Users\you\.ssh\id_ed25519`. If the key is already loaded in `ssh-agent`,
`--identity` can be omitted.

### 4. Restart and unlock

Restart the Mac. When it is waiting at the FileVault screen, run:

```bash
fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
```

`SUCCESS` means the trusted pre-boot server accepted the password. `VERIFIED`
means normal macOS SSH subsequently returned and accepted the selected public
key. If no usable key is loaded or passed, the unlock can still succeed but its
automatic boot check reports that the state is indeterminate. Confirm later
with `status my-mac --identity <path>`. If no credential was stored, the command
prompts for the password without echoing.

## Requirements

| Item | Requirement |
| --- | --- |
| Target hardware | Apple silicon Mac. Apple's feature does not support Intel Macs. |
| Target operating system | macOS 26 (Tahoe) or newer. |
| FileVault | Enabled, with a local account authorized to unlock the volume. |
| Remote Login | Enabled before restart and permitted for the account you will use. |
| Network | The target must be reachable during pre-boot. Apple documents a previously joined open or WPA2-PSK Wi-Fi network, or open/unauthenticated Ethernet; wired Ethernet is preferred. |
| Client computer | macOS, Linux, or Windows with the `fv-ssh-unlock` binary. |
| Source builds | Go 1.26.7 or newer. |

The pre-boot network environment is more limited than normal macOS. Wi-Fi may
not reconnect at the FileVault screen even when it works after login. Apple's
[deployment guide](https://support.apple.com/en-ie/guide/deployment/dep82064ec40/web)
documents the supported pre-boot network types; networks requiring interactive
or enterprise authentication do not meet those listed requirements.

For reliable unattended recovery, use open/unauthenticated Ethernet and plan
the address before restarting:

| Address choice | Recommendation |
| --- | --- |
| DHCP reservation/static lease | **Preferred.** Reserve the address for the exact network interface used in pre-boot, then configure that numeric IP in this tool. |
| Manually assigned static IP | Fallback when the network cannot reserve a lease. Keep it outside the DHCP pool, avoid conflicts, and verify it after a restart. Apple does not document every pre-boot static-address behavior. |
| `.local` hostname | Useful for normal, booted management, but do not make it the only recovery address. Hostname resolution is separate from Bonjour service discovery. |
| Unreserved dynamic lease | Avoid for unattended recovery because the address may change at exactly the time the Mac needs unlocking. |

## Use cases

The examples below use the target name `my-mac`, address `192.0.2.10`, and
example FileVault-capable account `unlockuser`.

### Use case 1: discover candidate Macs

With the target Mac booted and Remote Login enabled, browse SSH services
advertised on the local network:

```bash
fv-ssh-unlock discover
```

This is an inventory aid, not a FileVault test. It sends mDNS/Bonjour queries
and collects advertised names, addresses, and ports. It does **not** open an SSH
connection, inspect a login banner, or determine whether a host supports
FileVault unlock. Linux systems, NAS devices, and other SSH-advertising devices
can appear in the results. Use the address as a candidate for the next steps.

Run discovery while macOS is fully booted. In real-hardware testing, a locked
macOS 26 pre-boot server accepted connections on TCP/22 but advertised neither
Bonjour SSH service, so `discover` found nothing. After the same Mac finished
booting, it advertised immediately and appeared in discovery. An empty result
at the FileVault screen therefore does **not** mean SSH is unreachable.

### Use case 2: manually add known Macs

If Remote Login and FileVault are already configured, discovery is optional.
Add each known Mac directly using its existing address and local username:

```bash
fv-ssh-unlock config add lab-1 \
  --host 192.0.2.21 \
  --user unlockuser

fv-ssh-unlock config add lab-2 \
  --host 192.0.2.22 \
  --user unlockuser
```

Use reserved numeric addresses in this inventory whenever possible. Host-key
pinning still protects against an address being reassigned: if a different host
appears at a saved IP, its key is rejected rather than receiving the password.

A keyring-enabled build prompts once for each password you choose to store. The
password is not accepted on the command line, where it would be
visible in shell history and process listings. An environment-only build uses
one variable per saved name:

| Saved name | Credential variable |
| --- | --- |
| `lab-1` | `FV_UNLOCK_PASSWORD_LAB_1` |
| `lab-2` | `FV_UNLOCK_PASSWORD_LAB_2` |

Inject those variables with a secret manager or follow the safer shell-specific
examples in [Credentials](#environment-variable).

Confirm the inventory before restarting anything:

```bash
fv-ssh-unlock config list
```

Enroll and verify each Mac's SSH host key individually so every fingerprint can
be compared with that specific Mac. See [Use case 4](#use-case-4-identify-state-and-enroll-the-ssh-host-key).

### Use case 3: prepare a new target Mac and choose an account

While the Mac is fully booted:

1. Open **System Settings**, select **Privacy & Security**, then **FileVault**,
   and confirm that FileVault is enabled.
2. Choose a local user that is enabled for FileVault.
3. In **System Settings**, select **General**, then **Sharing**. Open the details
   for **Remote Login**, and turn it on.
4. Set **Allow access for** to **Only these users**, then add the chosen user.
   Leave **Allow full disk access for remote users** off unless that user needs
   it for a separate administrative SSH workflow; this tool does not need it.
5. Test ordinary SSH from the client computer:

   ```bash
   ssh unlockuser@192.0.2.10
   ```

6. On the target Mac, confirm which users are authorized for FileVault and, on
   Apple silicon, inspect the volume owners:

   ```bash
   sudo fdesetup list -extended
   sudo diskutil apfs listUsers /
   ```

   The `fdesetup` output should include the chosen username. The `diskutil`
   output uses user UUIDs; compare them with the UUIDs shown by
   `fdesetup list -extended`. If FileVault settings shows **Enable Users**, use
   it to authorize the account before continuing. Creating a local account by
   itself is not a reason to assume that it can unlock FileVault.

7. Record the Mac's Ed25519 SSH host-key fingerprint from a trusted local
   terminal:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Keep that fingerprint available for the enrollment step. If the Mac presents
   a different host-key type, compare the fingerprint for the matching public
   key in `/etc/ssh/`.

8. Reserve a DHCP address for the network interface that will be used at
   FileVault pre-boot, or configure and test a manual static address.
   Record the numeric address before restarting; do not plan to rediscover it
   from the FileVault screen.

#### What is `unlockuser`?

`unlockuser` is only an example name. The tool does not create an account, and
macOS has no special account type just for this tool. The configured user must
be a real local account that:

- is authorized to unlock FileVault (it has a secure token and, on Apple
  silicon, volume ownership); and
- is included in Remote Login's allowed users.

The account does **not** need to be an administrator. A standard account with a
strong, unique password is the least-privilege choice. You may use an existing
FileVault-enabled standard account, or create a dedicated standard account to
isolate the stored credential from a person's everyday password.

A dedicated account has a security tradeoff: FileVault authorization is login
authorization. Apple documents that a FileVault-enabled user can start
the Mac and log in with that user's password. There is no supported
`fv-ssh-unlock` setting that makes an account "FileVault pre-boot only" while
preventing it from logging in to booted macOS. Hiding an account from the login
window is cosmetic and should not be treated as a security control.

Limit the account by making it a standard user, granting Remote Login to only
the users who need it, leaving Remote Login's Full Disk Access option disabled,
and using a unique password stored in an OS keyring or secret manager. If your
policy forbids that account from being able to log in locally, do not assume a
hidden or shell-restricted account solves the problem; use an existing approved
FileVault user or define and test the restriction through your Mac management
system.

See Apple's documentation for [FileVault-enabled users](https://support.apple.com/guide/mac-help/flvlt001/26/mac/26),
[secure tokens and volume ownership](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/1/web/1.0),
and [Remote Login access controls](https://support.apple.com/en-asia/guide/mac-help/mchlp1066/mac).

After preparing a new target, follow [Add a known Mac](#2-add-a-known-mac), then
continue with host-key enrollment.

### Use case 4: identify state and enroll the SSH host key

The first connection fails closed and prints the fingerprint of
the unknown SSH host key:

```bash
fv-ssh-unlock status my-mac
```

Compare that SHA256 fingerprint with the one recorded directly on the Mac. If
they match, enroll it with the password-free `status` command:

```bash
fv-ssh-unlock status my-mac --accept-new-host-key
```

Enrollment never sends the FileVault password and never overrides a changed-key
warning. A status of `unknown` after enrollment is normal when the booted Mac
requires password authentication and no SSH key is available; the host key is
still pinned.

`status` can also report `unknown` while the Mac is at
FileVault pre-boot. One observed macOS 26 server advertised `OpenSSH_10.2` and
showed only the hidden `Password:` prompt, without the explanatory locked
banner. The client does not infer state from a server version or a generic
password prompt. That same prompt-only server remains unlockable.

Run `status` at any time to classify the configured target without loading its
unlock password:

```bash
fv-ssh-unlock status my-mac
```

Unlike `discover`, `status` opens an SSH connection and inspects the trusted
server's behavior. It reports `locked` only when it sees the FileVault locked
banner, `unlocked` only when a public key authenticates to normal macOS SSH, and
`unknown` when the evidence is ambiguous.

### Use case 5: restart and unlock one Mac

Restart the Mac. When it is waiting at the FileVault screen, run:

```bash
fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
```

A successful run looks like:

```text
Attempt 1/10: Unlocking unlockuser@192.0.2.10:22
SUCCESS: my-mac accepted the unlock password.
Verifying my-mac finished booting (up to 5m0s)...
VERIFIED: my-mac is booted and reachable over SSH.
```

`SUCCESS` means the pre-boot server accepted the password. `VERIFIED` means the
normal booted SSH server was subsequently reached with a public key.

If no public key is available, a valid unlock still prints `SUCCESS`, followed
by a verification warning because the post-boot state cannot be proven without
sending another secret. Pass an authorized, unencrypted key using `--identity`,
or load it into `ssh-agent`, for the deterministic `VERIFIED` result shown
above. A later command such as the following can confirm the boot independently:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

### Use case 6: unlock several Macs

Unlock selected targets by name, or omit names to unlock every configured
target:

```bash
fv-ssh-unlock unlock office-mac lab-mac
fv-ssh-unlock unlock
```

For a multi-device run, configure every credential in advance. The tool reports
each result independently and skips a target whose credential is unavailable.

## Additional installation and verification options

### Release archive

Release archives are built for macOS, Linux, and Windows on both AMD64 and
ARM64. Each release publishes the archives alongside `checksums.txt`, Cosign
signature material, and SPDX SBOMs. The archives contain the binary, README,
icon, license, and notice files. Windows uses ZIP;
macOS and Linux use `tar.gz`.

Download them from [GitHub Releases](https://github.com/shoon/fv-ssh-unlock/releases).
Choose the archive whose operating system and architecture match the client
computer that will run `fv-ssh-unlock`.

To verify a downloaded archive, first check it against `checksums.txt`:

```bash
sha256sum -c checksums.txt
```

The checksum file is signed without a long-lived key through GitHub Actions and
Sigstore. Replace `vX.Y.Z` with the downloaded release tag, then verify its
bundle with:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/shoon/fv-ssh-unlock/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle checksums.txt.sigstore.json \
  checksums.txt
```

Do not use a release whose checksum or signature verification fails.

### Build script

On macOS or Linux:

```bash
./build.sh            # environment-variable credential build
./build.sh --keyring  # OS-keyring build
./build.sh --mock     # also build the local mock SSH server
```

Binaries are written to `dist/`.

### Go install

```bash
go install github.com/shoon/fv-ssh-unlock/cmd/fv-ssh-unlock@latest
```

`go install` produces the environment-variable credential build because build
tags cannot be supplied in that module path.

## Credentials

Passwords are never written to `devices.json`. Choose one of these methods.

### OS keyring

Build with `-tags keyring` or use a release binary. During `config add`, answer
`y` when asked whether to store the password. The credential is saved under a
stable per-device identifier and removed from the keyring when that device is
removed from the configuration.

The OS keyring is the recommended choice for an interactive workstation. A
headless session may not have an unlocked keyring; use a carefully scoped
environment secret in that situation.

### Environment variable

The variable is named `FV_UNLOCK_PASSWORD_<DEVICE>`. The device name is
uppercased, and characters other than letters, numbers, and `_` become `_`.
For `my-mac`, use:

```bash
export FV_UNLOCK_PASSWORD_MY_MAC='your-password'
fv-ssh-unlock unlock my-mac
unset FV_UNLOCK_PASSWORD_MY_MAC
```

PowerShell:

```powershell
$env:FV_UNLOCK_PASSWORD_MY_MAC = 'your-password'
fv-ssh-unlock.exe unlock my-mac
Remove-Item Env:FV_UNLOCK_PASSWORD_MY_MAC
```

Avoid putting a real password directly into shared scripts or shell history.
Prefer your CI system or secret manager's environment-injection feature.

### Interactive prompt or stdin

When one device is selected and no stored credential is available, the tool
prompts without echoing the password. It also accepts a password from piped
stdin, which is useful with a secret-manager command:

```bash
secret-manager read mac/my-mac | fv-ssh-unlock unlock my-mac
```

For a multi-device unlock, configure every credential in advance. Missing
credentials are skipped rather than prompting ambiguously for several devices.

## Manage devices

```bash
# Add a device
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser

# Use a nonstandard SSH port
fv-ssh-unlock config add lab-mac --host 2001:db8::20 --user admin --port 2222

# List all devices
fv-ssh-unlock config list

# Show one device
fv-ssh-unlock config show my-mac

# Remove one or several devices
fv-ssh-unlock config remove my-mac
fv-ssh-unlock config remove my-mac lab-mac

# Remove every configured device, with confirmation
fv-ssh-unlock config remove
```

IPv6 addresses are accepted without brackets in `--host`; the tool adds the
correct brackets when it constructs the SSH endpoint. Hostnames must not include
a port; use `--port` instead.

### Custom success message

If a localized or future macOS release uses different success text, configure a
specific message when adding the device:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 \
  --user unlockuser \
  --success-message 'localized success text'
```

The message must be long and distinctive enough not to match the locked banner
or password prompt. The built-in English message is preferred when it works.

## Unlock behavior

Unlock named devices or every configured device:

```bash
fv-ssh-unlock unlock my-mac
fv-ssh-unlock unlock my-mac lab-mac
fv-ssh-unlock unlock
```

Flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--retry-attempts` | `10` | Maximum connection attempts before giving up. |
| `--retry-delay` | `30s` | Delay between transient failures. |
| `--verify-timeout` | `5m` | Maximum time to wait for normal SSH after acceptance. |
| `--identity <path>` | none | Explicit unencrypted private key for booted-state probing; repeatable. |
| `--no-verify` | off | Stop after the pre-boot server accepts the password. |
| `--verbose` | off | Show sanitized SSH banners and diagnostic details. |
| `--insecure-host-key` | off | Disable host-key verification. Unsafe with real credentials. |

Example for a slow network:

```bash
fv-ssh-unlock unlock my-mac \
  --retry-attempts 15 \
  --retry-delay 45s \
  --verify-timeout 8m
```

The tool does not retry an incorrect password or a host-key failure. It retries
only failures that may be transient, such as a timeout while pre-boot networking
starts.

### Result messages

| Message | Meaning |
| --- | --- |
| `SUCCESS` | The trusted pre-boot server accepted the password and sent the success banner. |
| `VERIFIED` | Normal macOS SSH became reachable and accepted a public key. |
| `WARNING ... no public key proved ...` after `SUCCESS` | The unlock was accepted, but no usable public key was available to prove normal macOS returned. Run `status --identity <path>` later. |
| `INFO ... already unlocked` | The Mac was already booted and a normal SSH session was available. |
| `FAILED ... still locked` | The password was rejected. |
| `NOTE ... may still be booting` | Unlock was accepted, but normal SSH did not return within the verification window. |
| `SECURITY ERROR` | Host-key verification failed. The tool stopped without retrying. |

For automation that needs an exit status for each Mac, invoke one device per
process. A fleet invocation reports all results but is intended primarily for
interactive use.

## Password-free status checks

`status` checks devices without retrieving or transmitting their unlock
passwords:

```bash
fv-ssh-unlock status
fv-ssh-unlock status my-mac
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

| Status | Meaning |
| --- | --- |
| `locked` | The trusted server presented the FileVault locked banner. |
| `unlocked (booted, SSH available)` | A public key authenticated to normal macOS SSH. |
| `unknown (reachable; prompt-only pre-boot or password-only SSH...)` | No locked banner or accepted public key proves which SSH environment answered. No password was sent. |
| Host-key error | The key is unknown or changed; verification stopped. |

The pre-boot server cannot use a normal user's `authorized_keys` because the
data volume is still locked. That makes successful public-key authentication a
positive signal that normal macOS has booted. Keys are taken from `ssh-agent` or
from explicit `--identity` paths; private key files are never searched
automatically.

A prompt-only FileVault server also produces `unknown`: recent real-hardware
testing observed `OpenSSH_10.2` offering `publickey,password,keyboard-interactive`
and then showing only `Password:`. That is not enough evidence to distinguish
pre-boot from a password-only booted SSH server. This conservative result does
not prevent `unlock` from answering the exact hidden prompt when requested.

## Discover candidate Macs on the local network

The `discover` command only listens for `_ssh._tcp` and `_sftp-ssh._tcp`
mDNS/Bonjour advertisements and combines the advertised service name,
hostname, port, and addresses into a list of candidate hosts:

```bash
fv-ssh-unlock discover
fv-ssh-unlock discover --timeout 30s
fv-ssh-unlock discover --interface en0
fv-ssh-unlock discover --verbose
```

`discover` does **not** open a TCP connection, perform an SSH handshake, read a
login banner, or look for FileVault-specific text. A result means only that an
SSH service was advertised. It may be a suitable Mac, another Mac that does not
support FileVault-over-SSH, or a non-Mac device.

These network checks answer different questions:

| Check | Mechanism | What it establishes |
| --- | --- | --- |
| `discover` | Bonjour service browse for `_ssh._tcp` and `_sftp-ssh._tcp` | A device is currently advertising SSH. It is not a TCP/22 scan. |
| Resolve `my-mac.local` | mDNS hostname lookup | That hostname currently maps to an address. It says nothing about an SSH service advertisement. |
| Test TCP/22 | `nc`, `Test-NetConnection`, or another connection test | Something accepts connections at that address and port. It does not identify FileVault. |
| `status` | SSH handshake against a configured, pinned host | A locked banner, accepted public key, or conservative `unknown` result. |

Real-hardware testing demonstrated the distinction: FileVault pre-boot answered
TCP/22 but did not advertise either Bonjour service. Once normal macOS booted,
the same host advertised SSH and appeared in `discover`. Plan discovery as a
booted-state inventory operation, not as a way to locate a Mac after restart.

The discovery command has neither a configured username nor a trusted host key,
and the FileVault server does not always show its identifying banner before the
password prompt. Classification belongs in
`status`, after the operator has identified and pinned the target.

After independently identifying the host, add it to the configuration and use
the password-free `status` command to collect stronger evidence:

```bash
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser
fv-ssh-unlock status my-mac
```

Here `my-mac` is only the local alias stored by this tool. It does not create a
DNS or `.local` record. If the Mac advertises a different hostname, use that
exact hostname while booted, or preferably save its reserved numeric address
for pre-boot recovery.

`status` connects over SSH and checks the server behavior. After its host key is
trusted, it can report `locked` when the FileVault banner is present, `unlocked`
when a public key authenticates to booted macOS, or `unknown` when neither state
can be proven. It never sends the unlock password.

A Mac will not appear in discovery if Remote Login is off, it is asleep, it is
on another subnet or VLAN, multicast is blocked, or it has already restarted
into an environment that is not advertising Bonjour. The last case is expected
on at least some macOS 26 FileVault pre-boot versions even though TCP/22 works.

On macOS, compare results with:

```bash
dns-sd -B _ssh._tcp local.
```

If responses are intermittent, increase `--timeout`. mDNS uses multicast and
may lose packets on busy Wi-Fi networks.

## Actively scan for SSH without credentials

Use `scan` when Bonjour finds nothing but you know the local IPv4 subnet. You
must supply a CIDR to bound the scan:

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

Use the `MATCH` column to locate a configured Mac whose address changed. During
normal setup, the tool pins the Mac's SSH host key. The scanner compares that
key at a new address and identifies the configured target without sending its
FileVault password. A match identifies the known SSH host; the evidence column
separately describes what can be proven about its current state.

### What the scanner can and cannot identify

The original captured FileVault server included this explanation:

```text
This system is locked. To unlock it, use a local
account name and password...
```

When that text is present, the scanner reports `FileVault locked banner`.
However, the more recent `OpenSSH_10.2` server observed during real-hardware
testing showed only the generic hidden `Password:` question. Ordinary booted
SSH servers can do the same, so neither that prompt, the OpenSSH version, nor
the advertised authentication methods are a unique FileVault fingerprint. The
scanner reports `Password prompt; state indeterminate` instead of
guessing. A previously pinned host-key match can still establish which Mac
answered.

### Scan options and safety

| Flag | Default | Purpose |
| --- | --- | --- |
| `--cidr <range>` | required | IPv4 CIDR to scan; repeatable. Combined inputs are limited to 4096 addresses. |
| `--port <number>` | `22` | Probe a nonstandard SSH port. |
| `--timeout <duration>` | `1.5s` | Bound both TCP connection and SSH handshake time per address. |
| `--concurrency <number>` | `64` | Parallel probes; accepted range is 1-256. |
| `--user <name>` | `fv-ssh-probe` | Synthetic username used to request the authentication challenge. |
| `--verbose` | off | Show sanitized SSH handshake failures for open ports. |

`scan` supports IPv4 only because exhaustive IPv6 subnet scanning is not
practical. It never reads the keyring or environment credentials, never loads
private identity keys, never answers an authentication challenge, never trusts
or stores a discovered key, and never changes the configuration. It does make
active connection attempts that may be logged or trigger network monitoring;
scan only networks you own or are authorized to test.

The default synthetic username worked with the observed FileVault server. If a
server suppresses its authentication challenge for unknown users, pass the
already-known local account name with `--user unlockuser`. This still sends no
password or identity key.

## SSH host-key safety

Host-key verification protects the FileVault password from a machine pretending
to be the target Mac.

- Trusted keys are stored in `~/.fv-ssh-unlock/known_hosts`.
- Unknown keys fail closed and print their SHA256 fingerprint.
- Only `status --accept-new-host-key` can enroll an unknown key, and `status`
  never receives the unlock password.
- A changed key is always rejected, even with the enrollment flag.
- Enrollment is serialized with process and operating-system file locks so two
  concurrent clients cannot pin conflicting keys.

If a key changes after a legitimate macOS reinstall or hardware repair, stop and
verify the new fingerprint from a trusted local source before removing the old
entry. Never work around an unexplained change with `--insecure-host-key`.

> [!CAUTION]
> `--insecure-host-key` disables server identity verification. A network
> attacker could imitate the exact FileVault prompt and receive the password.
> It is intended only for isolated testing with disposable credentials.

## Files and privacy

The application stores local state under the current user's home directory:

| File | Contents |
| --- | --- |
| `~/.fv-ssh-unlock/devices.json` | Device names, hosts, ports, users, credential source, and success messages. Never passwords. |
| `~/.fv-ssh-unlock/known_hosts` | Pinned SSH host public keys. |
| `~/.fv-ssh-unlock/known_hosts.lock` | Lock file used to serialize host-key enrollment. |

On Windows, `~` is the user's profile directory. Configuration files are size
limited, schema validated, written atomically, and restricted to the current
user where the operating system supports Unix-style permissions.

The tool has no telemetry and does not contact a project-operated service.
`discover` sends standard mDNS queries on the local network; `scan` actively
connects only to the explicit CIDRs supplied by the operator; `status` and
`unlock` connect only to hosts in the local configuration.

## Troubleshooting

### `unknown host ... presented SHA256:...`

This is expected on the first connection. Compare the fingerprint with the
target Mac, then run `status my-mac --accept-new-host-key` only if it matches.

### `host key ... has CHANGED`

Do not retry with the insecure flag. Confirm that the address still belongs to
the intended Mac and investigate reinstall, repair, DHCP, DNS, or
man-in-the-middle possibilities. Remove the old entry only after independently
verifying the replacement key.

### Connection refused or timed out

Check that:

- Remote Login was enabled before restart;
- the address and port are correct;
- the Mac has power and a pre-boot network connection;
- Ethernet, DHCP, firewall, VLAN, and routing policies allow the client to
  reach the target; and
- another device has not received the same DHCP address.

The first attempt may legitimately fail while the pre-boot network starts. The
default unlock command retries ten times with a 30-second delay.

Prefer a DHCP reservation for the exact interface used in pre-boot. If you use
a manually assigned static address, keep it outside the DHCP pool and test a
full restart. An unreserved lease can change; host-key pinning will reject a
different machine that later receives the old address.

### `status` says `unknown (reachable...)`

This is a safe result, not an error in password handling. A booted SSH server
can ask the same password question as the pre-boot server, and an observed
FileVault pre-boot server showed only that prompt with no locked explanation.
Add a public key to the booted account and load it into `ssh-agent`, or pass an
unencrypted key with `--identity`, to prove that normal macOS is running without
sending a password. `unknown` does not mean `unlock` will fail.

### Unlock was accepted but not verified

The Mac may still be booting, the address may have changed, Remote Login may not
be available after boot, or no public key may be authorized. Try normal `ssh`,
increase `--verify-timeout`, and use `ssh-agent` or `--identity`. The accepted
unlock is not retracted merely because verification is unavailable.

### Password is rejected or missing

- Confirm that the configured username is a local account allowed to unlock
  FileVault.
- Check the environment variable spelling using the credential naming rules
  above.
- Remember that environment variables are scoped to the shell or service that
  launches the tool.
- A keyring-enabled binary may require an unlocked desktop keyring.
- Run one device at a time to receive an interactive prompt.

### Discovery finds no devices

Confirm Remote Login is enabled and the Mac is awake and booted. Check that the
client and target share a multicast-capable network, remove `--interface` or use
the correct interface name, and increase `--timeout`. Discovery is not expected
to find every Mac after it enters pre-boot. A locked Mac can accept SSH on
TCP/22 without advertising Bonjour, so test the stable configured address
instead of treating an empty discovery result as a failed pre-boot service. If
the address is unknown, scan the authorized local subnet and look for either a
pinned host-key `MATCH` or the distinctive locked banner:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24
```

### A `.local` name does not resolve

The name given to `config add` is a local alias, not a DNS registration. Use the
hostname advertised by the Mac, including punctuation and `.local`, or
use the reserved numeric address. `.local` normally uses multicast DNS, not the
network's ordinary DNS server. On Windows, test it with:

```powershell
Resolve-DnsName my-mac.local
Test-NetConnection -ComputerName my-mac.local -Port 22
```

Do not add `-DnsOnly` when testing `.local`; that explicitly bypasses mDNS and
can report failure even while the multicast name works. Name resolution and
Bonjour service discovery are independent, so either one can work without the
other.

### Configuration is rejected

The configuration parser refuses symbolic links, oversized files, unknown JSON
fields, duplicate device names, ambiguous environment-variable names, invalid
ports, and malformed hosts. Prefer `config add` and `config remove` over manual
JSON editing.

## Security design

This program handles a disk-encryption password, so it uses a narrow protocol:

- The password is answered only to one exact, hidden, single-question
  `Password:` keyboard-interactive challenge.
- Unexpected, echoed, repeated, or multi-question challenges are refused.
- SSH password authentication is not enabled as a fallback.
- Success text counts only after the password was submitted; a pre-auth banner
  cannot forge a successful unlock.
- A disconnect, timeout, network drop, or wrong password is never treated as
  success.
- `status` and post-unlock verification use no-password probes.
- Network-controlled banners, names, and errors are escaped before terminal
  output to prevent control-sequence injection.
- Passwords are not logged or stored in the JSON configuration.

The trust boundary is the pinned SSH host key. Once you trust a
key, the holder of its private key can present the expected password prompt.
Protect the target Mac's SSH host keys and verify fingerprints independently.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Command reference

| Command | Purpose |
| --- | --- |
| `fv-ssh-unlock config add [name] --host HOST --user USER` | Add a target. |
| `fv-ssh-unlock config list` | List targets and credential sources. |
| `fv-ssh-unlock config show NAME` | Show one target. |
| `fv-ssh-unlock config remove [name...]` | Remove targets; no names means all, after confirmation. |
| `fv-ssh-unlock discover` | List candidate hosts from local Bonjour SSH advertisements; does not connect or test FileVault. |
| `fv-ssh-unlock scan --cidr CIDR` | Actively find SSH servers, fingerprints, pinned-target matches, and password-free banner evidence. |
| `fv-ssh-unlock status [name...]` | Check state without sending a password. |
| `fv-ssh-unlock unlock [name...]` | Unlock named targets; no names means all. |
| `fv-ssh-unlock completion SHELL` | Generate completion for Bash, Zsh, Fish, or PowerShell. |
| `fv-ssh-unlock --version` | Print the build version. |

Every command supports `--help`:

```bash
fv-ssh-unlock --help
fv-ssh-unlock unlock --help
fv-ssh-unlock completion powershell --help
```

## Shell completion

Examples:

```bash
# Bash, current shell
source <(fv-ssh-unlock completion bash)

# Zsh, one common per-user location
mkdir -p ~/.zfunc
fv-ssh-unlock completion zsh > ~/.zfunc/_fv-ssh-unlock
```

PowerShell, current session:

```powershell
fv-ssh-unlock completion powershell | Out-String | Invoke-Expression
```

See the completion subcommand's help for persistent installation instructions
for your shell.

## Remove the tool

Before deleting the configuration, use a keyring-enabled binary to remove
configured devices so their stored credentials are cleaned up:

```bash
fv-ssh-unlock config remove
```

Then delete the binary and, if you no longer need the pinned keys or settings,
remove `~/.fv-ssh-unlock`. This does not change FileVault or Remote Login on the
target Mac.

## Mock FileVault SSH server

The repository includes a development-only SSH server under
[`tools/mock-fv-ssh-server`](tools/mock-fv-ssh-server). It lets contributors and
operators test host-key enrollment, password-free status checks, credential
handling, and the unlock protocol without restarting a real Mac.

By default, the mock reproduces the complete captured macOS 26.0.1 locked
banner, the single hidden `Password:` challenge, and the successful-unlock
banner followed by an authentication failure and disconnect, matching the real
FileVault SSH session. The mock also provides an `unlocked` state for testing an
already-booted handshake.

A later real-hardware session advertised `OpenSSH_10.2` and omitted the locked
explanation, showing only `Password:`. Exercise that supported prompt-only
variant with:

```bash
MOCK_FV_PASSWORD='test-only-secret' \
  ./dist/mock-fv-ssh-server --port 2222 --username test \
  --prompt-only --server-version OpenSSH_10.2
```

The SSH version is configurable test data, not a state-classification signal.
With the prompt-only mock, `status` should report `unknown` after its host
key is enrolled, while `unlock --no-verify` should still succeed.

Use `--transition-on-unlock` to test unlock acceptance followed by boot
verification. To restrict the mock's booted state to one public key, pass
`--authorized-key ~/.ssh/id_ed25519.pub`. Then pass the
matching private key to the client with `unlock --identity`. Public keys remain
unavailable while the mock is locked, matching FileVault's behavior.

Build the client and mock together on macOS, Linux, or a Windows Bash
environment:

```bash
./build.sh --mock
```

Then run a local locked-state test in one terminal:

```bash
MOCK_FV_PASSWORD='test-only-secret' \
  ./dist/mock-fv-ssh-server --port 2222 --username test
```

In a second terminal:

```bash
fv-ssh-unlock config add mock --host 127.0.0.1 --port 2222 --user test
fv-ssh-unlock status mock
fv-ssh-unlock status mock --accept-new-host-key
FV_UNLOCK_PASSWORD_MOCK='test-only-secret' fv-ssh-unlock unlock mock --no-verify
```

Before accepting the key, compare the fingerprint from the first `status`
command with the fingerprint printed by the mock at startup.

By default the mock remains locked after each connection, so `--no-verify` is
expected. `--transition-on-unlock` changes subsequent connections to the
password-only/public-key-capable booted state for verification tests. The mock
does not advertise over Bonjour, provide a shell, or emulate macOS itself.

> [!CAUTION]
> The mock is a test fixture, not a production SSH server. It binds to
> `127.0.0.1` by default, refuses a non-loopback bind with the default password,
> and must never be given real credentials.

The [mock-server guide](tools/mock-fv-ssh-server/README.md) includes native
PowerShell instructions, every flag, password-file handling, state limitations,
host-key behavior, and maintenance checks.

## Build and test

The repository contains the main module and a separate mock-server module under
`tools/mock-fv-ssh-server`. A `go.work` file connects them for development.

```bash
go build ./...
go build -tags keyring ./...
go vet ./...
go vet -tags keyring ./...
go test ./...
go test -tags keyring ./...
go test -race ./...
govulncheck ./...
govulncheck -tags keyring ./...

(cd tools/mock-fv-ssh-server && go build ./... && go vet ./... && go test -race ./... && govulncheck ./...)
```

## Limitations

- The target must be Apple silicon with macOS 26 or newer.
- Pre-boot networking is controlled by macOS. Use a previously joined open or
  WPA2-PSK Wi-Fi network or open/unauthenticated Ethernet; wired is preferred.
- Bonjour discovery may disappear in FileVault pre-boot even while SSH still
  answers on TCP/22. Record a stable address before restarting.
- Active scanning is IPv4-only, requires an explicit CIDR, and is capped at
  4096 addresses. It cannot uniquely classify a generic prompt-only SSH server.
- Banner text may vary or be absent in localized or future macOS releases. A
  prompt-only server can be unlocked but cannot be classified as locked by the
  password-free `status` command.
- Positive boot verification needs a public key accepted by the normal SSH
  server; it never falls back to the FileVault password.
- Real-hardware behavior may change across macOS releases. The integration
  tests use a protocol-faithful mock server and a redacted Tahoe transcript.

## Contributing

Focused issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for the DCO sign-off, test matrix, security boundaries, and release process.
Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Support development

`fv-ssh-unlock` is free and open source. If it helps you manage remote Macs,
consider [sponsoring @shoon on GitHub](https://github.com/sponsors/shoon).
Sponsorship helps cover test hardware, code signing, virtual machines, and the
time required to maintain this project and other security-focused utilities.

## License

Copyright 2025-2026 Shaun Murphy

Licensed under the [Apache License 2.0](LICENSE). The software is distributed on
an **AS IS** basis, without warranties or conditions of any kind. See
[NOTICE](NOTICE), [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt), and
[TRADEMARKS.md](TRADEMARKS.md) for attribution and non-affiliation information.

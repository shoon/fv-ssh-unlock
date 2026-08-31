# Configuration and credentials

[Documentation home](index.md) | [Getting started](getting-started.md) | [CLI reference](cli-reference.md)

The configuration stores how to reach each Mac. Passwords are kept separately
in an OS keyring, externally managed credential file, environment variable,
interactive prompt, or standard input.

## Contents

- [Add a device](#add-a-device)
- [Manage devices](#manage-devices)
- [Automatic unlock policy](#automatic-unlock-policy)
- [Declarative configuration](#declarative-configuration)
- [Credentials](#credentials)
- [Inspect available providers](#inspect-available-providers)
- [OS keyring](#os-keyring)
- [Externally managed credential files](#externally-managed-credential-files)
- [Unsafe plaintext files](#unsafe-plaintext-files)
- [Environment variables](#environment-variables)
- [Interactive prompt or standard input](#interactive-prompt-or-standard-input)
- [Custom success message](#custom-success-message)
- [Local files and privacy](#local-files-and-privacy)

## Add a device

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 \
  --user unlockuser \
  --port 22
```

The first argument is a local alias. It does not create a DNS or Bonjour name.
The host should be the stable hostname or address that the client can reach
while the Mac is at the FileVault screen. A DHCP-reserved numeric address is
recommended.

The user must be an existing local account that can unlock FileVault and is
allowed to use Remote Login. See
[Choose the FileVault user](getting-started.md#choose-the-filevault-user).

If the alias is omitted, `--host` becomes the device name:

```bash
fv-ssh-unlock config add --host 192.0.2.10 --user unlockuser
```

Use `--port` for a nonstandard SSH port. Do not put the port inside `--host`.
IPv6 addresses are accepted without brackets; the client adds brackets when it
constructs the endpoint.

## Manage devices

```bash
# Add a target on the default SSH port
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser

# Add an IPv6 target on a custom port
fv-ssh-unlock config add lab-mac --host 2001:db8::20 --user admin --port 2222

# List all targets and their credential sources
fv-ssh-unlock config list

# Show one target
fv-ssh-unlock config show my-mac

# Remove one or several targets
fv-ssh-unlock config remove my-mac
fv-ssh-unlock config remove my-mac lab-mac

# Remove every target, after confirmation
fv-ssh-unlock config remove --all
```

Removing a target with a keyring-enabled binary also removes that target's
stored keyring credential. It does not change the account, FileVault, Remote
Login, or network settings on the Mac.

For non-interactive teardown, `config remove --all --yes` skips the bulk-removal
confirmation. A bare `config remove` is rejected so an omitted name cannot
accidentally become a fleet-wide operation.

## Automatic unlock policy

Automatic unlock is an explicit per-device choice and defaults off:

```bash
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser \
  --credential-source file --credential-file /run/secrets/my-mac \
  --auto-unlock

fv-ssh-unlock config auto-unlock my-mac --enable
fv-ssh-unlock config auto-unlock my-mac --disable
```

A running daemon loads external configuration changes after restart. Devices
enrolled through its TUI/API are added to the live monitor immediately. Policy
authorization alone is insufficient: daemon startup and enrollment also
require the selected provider to be available and verified secure in that
exact runtime environment.

Configuration validation rejects `auto_unlock: true` with a `runtime` source
up front. A file or keyring reference can be configured before service start,
but the daemon still performs a reference-specific availability and security
preflight in its actual runtime environment.

## Declarative configuration

Export the strict, password-free JSON inventory for review or infrastructure
tooling:

```bash
fv-ssh-unlock config export > devices.json
fv-ssh-unlock config apply --file devices.json --check --json
fv-ssh-unlock config apply --file devices.json
```

`config apply` validates the complete document before atomically replacing the
inventory. `--file -` reads JSON from standard input. The JSON may contain
credential provider references but the schema has no credential-value field.
Configuration-management tools should restart the daemon only when the result
reports `changed: true`.

## Credentials

Passwords are never written to `devices.json`. Choose a source appropriate for
the client environment:

| Source | Best for | Important behavior |
| --- | --- | --- |
| OS keyring | Interactive workstations. | Recommended when an unlocked desktop keyring is available. |
| Externally managed file | Docker Swarm secrets, systemd credentials, and secret-manager agents. | Secure delivery is verified for recognized service-scoped memory mounts; the program never creates or modifies the file. |
| Environment variable | One-shot operator or CI invocations. | Set a separate, scoped variable for each target; the persistent daemon refuses it for automatic unlock. |
| Hidden prompt | One target in an interactive terminal. | Used when no configured credential is available. |
| Standard input | Piping one secret from a secret manager. | Intended for a single-device invocation. |

For a multi-device unlock, configure every credential in advance. Missing
credentials are skipped rather than prompting ambiguously for several Macs.
Environment, prompt, and standard-input credentials are for explicit manual or
one-shot operations; they cannot authorize persistent automatic unlock.

Unsafe persistent storage is never selected automatically. If no secure
persistent provider is detected, `config add` uses runtime input rather than
writing a plaintext password.

## Inspect available providers

Run the capability report in the exact user, service, or container environment
that will perform unlocks:

```bash
fv-ssh-unlock credentials providers
fv-ssh-unlock credentials providers --json
fv-ssh-unlock credentials providers --require-secure
```

The report separates `built` from `available`: a release can include keyring
support while a headless Linux session lacks an unlocked Secret Service D-Bus
session. It reports TPM2 hardware when detectable but does not advertise TPM2
as available until the binary contains a complete sealing provider.
`--require-secure` makes the command suitable for `ExecStartPre` or another
deployment check by returning a failure when no verified secure persistent
provider or delivery mechanism is detected.

The `tpm2` row describes a future direct provider in this binary. It does not
prevent the `file` provider from consuming a service credential that systemd
has independently decrypted with TPM2.

## OS keyring

Release binaries include keyring support. A source build must use
`-tags keyring`.

During `config add`, answer `y` when asked whether to store the password. The
credential is stored under a stable per-device identifier, so renaming display
details does not expose it in `devices.json`. Removing the device through a
keyring-enabled binary removes the corresponding keyring entry.

The persistent candidate wizard does not ask for or create a keyring value, so
it offers only `file` and `runtime`. For a newly discovered device, use
monitoring-only enrollment with `runtime`, or provision a secure external
credential first and select `file`. Use `config add` instead when a known new
device should store its credential in the OS keyring.

The OS keyring is the recommended source on an interactive workstation. A
headless service or SSH session may not have an unlocked desktop keyring.
Prefer a systemd credential, Docker Swarm secret, or other service-scoped
delivery there; a carefully scoped runtime environment secret is also
available.

## Externally managed credential files

The `file` provider reads one password from an absolute path or a portable
`systemd:<credential-name>` reference. It does not create, copy, rewrite, or
delete the file:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 \
  --user unlockuser \
  --credential-source file \
  --credential-file /run/secrets/my-mac
```

On Linux, files inside the systemd `$CREDENTIALS_DIRECTORY` are accepted as
service credentials when the directory is verified as memory-backed. Files
beneath `/run/secrets` are accepted without an unsafe override under the same
condition, which distinguishes a Swarm secret mount from an ordinary disk bind
mount. See the official [systemd credential
model](https://systemd.io/CREDENTIALS/) and [Docker Swarm secret
model](https://docs.docker.com/engine/swarm/secrets/) for their delivery and
access guarantees.

For a systemd unit, avoid hard-coding its runtime credential directory. Save a
portable reference instead:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 --user unlockuser \
  --credential-source file \
  --credential-file systemd:my-mac
```

Then give the service a credential with that name, for example with
`LoadCredentialEncrypted=my-mac:/etc/credstore.encrypted/my-mac.cred`.
`systemd-creds` can encrypt the on-disk blob using TPM2, systemd's local host
secret, or both; systemd decrypts it only during service activation and the
provider resolves `systemd:my-mac` beneath the unit's
`$CREDENTIALS_DIRECTORY`. This reuses the host's native implementation and
adds no Go TPM library to this project.

The provider reads at most 4096 bytes, accepts one trailing LF or CRLF, rejects
empty, oversized, symbolic-link, and unstable files, and reopens the file for
each unlock invocation so externally coordinated rotations take effect.

You may configure a reference before a service or container mounts it.
`config add` warns when it cannot assess the missing file; `unlock` still
requires the resolved file to exist and verifies its security on every
invocation.

## Unsafe plaintext files

An ordinary file may be protected by Unix permissions while still remaining
plaintext on disk. Such a file is refused by default. If encrypted storage or
another compensating control makes that intentional, acknowledge it for both
configuration and each unlock invocation:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 --user unlockuser \
  --credential-source file \
  --credential-file /srv/fv-secrets/my-mac \
  --allow-unsafe-credential-storage

fv-ssh-unlock unlock my-mac --allow-unsafe-credential-storage
```

The override is deliberately not saved in `devices.json` and never enables an
automatic fallback. Runtime environment, standard-input, and hidden-prompt
credentials do not require it because the program does not persist them.

The persistent daemon deliberately has no unsafe-storage override. An
auto-enabled device must use a keyring that is secure and available to the
service or a verified memory-backed external credential.

## Environment variables

The name is `FV_UNLOCK_PASSWORD_<DEVICE>`. The device alias is uppercased, and
characters other than letters, numbers, and `_` become `_`.

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

Avoid entering real passwords directly into shared scripts, command arguments,
or shell history. Prefer the environment-injection feature of your CI system
or secret manager. The configuration rejects aliases that would produce
ambiguous environment-variable names.

Environment variables are scoped to the process environment. A variable set in
one shell, scheduled task, or service is not automatically available to
another.

Do not pass FileVault credentials as Docker container environment variables.
They can be exposed through container configuration and are not accepted for
unattended automatic unlock. Use a Swarm secret or another memory-backed
service credential instead.

## Interactive prompt or standard input

When exactly one device is selected and no stored credential is available, the
tool prompts for a password without echoing it.

It can also accept one password from piped standard input:

```bash
secret-manager read mac/my-mac | fv-ssh-unlock unlock my-mac
```

Make sure the secret-manager command writes only the intended password and a
normal line ending. Do not use one piped value for an invocation that selects
several devices.

## Custom success message

The built-in English FileVault success message is preferred. If a localized or
future macOS version uses different success text, save a specific message when
adding the device:

```bash
fv-ssh-unlock config add my-mac \
  --host 192.0.2.10 \
  --user unlockuser \
  --success-message 'localized success text'
```

The message must be long and distinctive enough not to match the locked banner
or password prompt. Capture it from the real target and test it before remote
use. A success message counts only after the password has been submitted; a
pre-authentication banner cannot forge an accepted unlock.

## Local files and privacy

State is stored beneath the current user's home directory by default. Set the
global `--data-dir /absolute/path` or `FV_SSH_UNLOCK_DATA_DIR` for a dedicated
service/container directory:

On Unix, an existing data directory must already be private (mode `0700`). The
program creates a missing directory privately, but deliberately refuses an
existing group/world-accessible directory instead of changing its permissions.
This makes a mistaken value such as `/tmp` fail safely without chmodding a
shared system directory. Create and assign the service directory explicitly
before startup.

| File | Contents |
| --- | --- |
| `~/.fv-ssh-unlock/devices.json` | Device aliases, hosts, ports, users, credential source references, and optional success messages. Never passwords. |
| `~/.fv-ssh-unlock/known_hosts` | Pinned SSH host public keys. |
| `~/.fv-ssh-unlock/known_hosts.lock` | Lock file used to serialize host-key enrollment. |
| `~/.fv-ssh-unlock/monitor-state.json` | Durable state, lock episodes, cooldowns, and latches. Never credential values. |
| `~/.fv-ssh-unlock/candidates.json` | Untrusted discovery inbox, fingerprints, addresses, review state, and timestamps. |
| `~/.fv-ssh-unlock/daemon.lock` | Process lock that prevents two persistent controllers from sharing one data directory. |
| `~/.fv-ssh-unlock/control.sock` | Mode `0600` local daemon API socket while the service is running. |

On Windows, `~` is the current user's profile directory. Configuration files
are size limited, schema validated, written atomically, and restricted to the
current user where the operating system supports Unix-style permissions. The
parser rejects symbolic links, oversized files, unknown JSON fields, duplicate
device names, ambiguous credential names, invalid ports, and malformed hosts.
Prefer the `config` commands over manual JSON editing.

The tool has no telemetry and does not contact a project-operated service.
`discover` sends standard mDNS queries on the local network; `scan` connects
only to explicit operator-supplied CIDRs; `status` and `unlock` connect only to
configured targets.

---

[Documentation home](index.md) | [Getting started](getting-started.md) | [CLI reference](cli-reference.md)

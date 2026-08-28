# Configuration and credentials

[Documentation home](index.md) | [Getting started](getting-started.md) | [CLI reference](cli-reference.md)

The configuration stores how to reach each Mac. Passwords are kept separately
in an OS keyring, environment variable, interactive prompt, or standard input.

## Contents

- [Add a device](#add-a-device)
- [Manage devices](#manage-devices)
- [Credentials](#credentials)
- [OS keyring](#os-keyring)
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
fv-ssh-unlock config remove
```

Removing a target with a keyring-enabled binary also removes that target's
stored keyring credential. It does not change the account, FileVault, Remote
Login, or network settings on the Mac.

## Credentials

Passwords are never written to `devices.json`. Choose a source appropriate for
the client environment:

| Source | Best for | Important behavior |
| --- | --- | --- |
| OS keyring | Interactive workstations. | Recommended when an unlocked desktop keyring is available. |
| Environment variable | Headless automation and secret-manager injection. | Set a separate, scoped variable for each target. |
| Hidden prompt | One target in an interactive terminal. | Used when no configured credential is available. |
| Standard input | Piping one secret from a secret manager. | Intended for a single-device invocation. |

For a multi-device unlock, configure every credential in advance. Missing
credentials are skipped rather than prompting ambiguously for several Macs.

## OS keyring

Release binaries include keyring support. A source build must use
`-tags keyring`.

During `config add`, answer `y` when asked whether to store the password. The
credential is stored under a stable per-device identifier, so renaming display
details does not expose it in `devices.json`. Removing the device through a
keyring-enabled binary removes the corresponding keyring entry.

The OS keyring is the recommended source on an interactive workstation. A
headless service or SSH session may not have an unlocked desktop keyring. Use a
carefully scoped environment secret in that situation.

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

State is stored beneath the current user's home directory:

| File | Contents |
| --- | --- |
| `~/.fv-ssh-unlock/devices.json` | Device aliases, hosts, ports, users, credential sources, and optional success messages. Never passwords. |
| `~/.fv-ssh-unlock/known_hosts` | Pinned SSH host public keys. |
| `~/.fv-ssh-unlock/known_hosts.lock` | Lock file used to serialize host-key enrollment. |

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

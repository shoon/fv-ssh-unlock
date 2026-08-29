# CLI reference

[Documentation home](index.md) | [Configuration and credentials](configuration-and-credentials.md) | [Status and unlocking](unlocking-and-status.md)

Every command supports `--help`. The built-in help is the authoritative
reference for the installed version:

```bash
fv-ssh-unlock --help
fv-ssh-unlock unlock --help
fv-ssh-unlock completion powershell --help
```

## Top-level commands

| Command | Purpose |
| --- | --- |
| `fv-ssh-unlock config add [name] --host HOST --user USER` | Add a target. |
| `fv-ssh-unlock config list` | List targets and credential sources. |
| `fv-ssh-unlock config show NAME` | Show one target. |
| `fv-ssh-unlock config remove [name...]` | Remove named targets; use `--all` explicitly for every target. |
| `fv-ssh-unlock credentials providers` | Report provider build, availability, persistence, and security status for this machine. |
| `fv-ssh-unlock discover` | List booted hosts advertising SSH through Bonjour. It does not connect or test FileVault. |
| `fv-ssh-unlock scan --cidr CIDR` | Actively find SSH servers, public key fingerprints, pinned-target matches, and password-free banner evidence. |
| `fv-ssh-unlock status [name...]` | Check state without sending a password. No names means all targets. |
| `fv-ssh-unlock unlock [name...]` | Unlock named targets; use `--all` explicitly for every target. |
| `fv-ssh-unlock completion SHELL` | Generate Bash, Zsh, Fish, or PowerShell completion. |
| `fv-ssh-unlock --version` | Print the build version. |

## Global flags

| Flag | Purpose |
| --- | --- |
| `-h`, `--help` | Show command help. |
| `-v`, `--version` | Show the build version. |

## `config add`

```text
fv-ssh-unlock config add [name] [flags]
```

Either `[name]` or `--host` is required. If the alias is omitted, the host
value is used as the device name.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--host <host-or-address>` | none | Stable target host or address. A DHCP-reserved numeric address is recommended. |
| `--port <number>` | `22` | SSH port. |
| `--user <name>` | required | Existing local FileVault-enabled Remote Login user. |
| `--success-message <text>` | built-in English text | Exact text that indicates accepted unlock. |
| `--credential-source <source>` | `auto` | Credential source: `auto`, `runtime`, `keyring`, or `file`. |
| `--credential-file <reference>` | none | Absolute path or `systemd:<name>` reference for the externally managed `file` source. |
| `--allow-unsafe-credential-storage` | off | Permit an unverified plaintext disk credential file for this command only. |

Examples:

```bash
fv-ssh-unlock config add my-mac --host 192.0.2.10 --user unlockuser
fv-ssh-unlock config add lab-mac --host 2001:db8::20 --user admin --port 2222
fv-ssh-unlock config add rack-mac --host 192.0.2.30 --user unlockuser \
  --credential-source file --credential-file /run/secrets/rack-mac
fv-ssh-unlock config add service-mac --host 192.0.2.31 --user unlockuser \
  --credential-source file --credential-file systemd:service-mac
```

`auto` offers secure keyring storage only when that provider appears usable;
otherwise it configures runtime input. It never falls back to a plaintext file.
An external-file reference may be configured before the service mounts it, but
it is reassessed whenever `unlock` reads it.

## Other `config` commands

```text
fv-ssh-unlock config list
fv-ssh-unlock config show NAME
fv-ssh-unlock config remove [name...]
fv-ssh-unlock config remove --all [--yes]
```

`config remove --all` asks for confirmation before removing all saved targets;
`--yes` skips that prompt for automation. Omitting both names and `--all` is an
error. A keyring-enabled binary also deletes credentials associated with the
removed device identifiers.

## `credentials providers`

```text
fv-ssh-unlock credentials providers [--json] [--require-secure]
```

The report distinguishes providers included in the binary from providers that
are usable in the current session. It also reports whether secure persistent
storage or service-scoped delivery was detected. TPM2 appears in the report but
is not marked built or available until an actual sealing provider exists.

Use `--json` for machine-readable fields including `built`, `available`,
`persistent`, `security`, and `secure_storage_available`.
Use `--require-secure` as a service preflight check that exits unsuccessfully
when no verified secure persistent provider or delivery mechanism is detected.

## `discover`

```text
fv-ssh-unlock discover [flags]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--interface <name>` | all suitable interfaces | Browse only on the named interface, such as `en0` or `Ethernet`. |
| `--timeout <duration>` | `12s` | How long to collect Bonjour responses. |
| `--verbose` | off | Report each browse round as it completes. |

Discovery collects `_ssh._tcp` and `_sftp-ssh._tcp` advertisements. It does not
connect to results, read an SSH banner, or prove FileVault support.

## `scan`

```text
fv-ssh-unlock scan --cidr CIDR [flags]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--cidr <range>` | required | IPv4 CIDR; repeatable, with at most 4096 combined addresses. |
| `--concurrency <number>` | `64` | Maximum simultaneous probes, from 1 through 256. |
| `--port <number>` | `22` | TCP port to probe. |
| `--timeout <duration>` | `1.5s` | TCP and SSH timeout for each address. |
| `--user <name>` | `fv-ssh-probe` | Synthetic name used only to request the authentication challenge. |
| `--verbose` | off | Show sanitized handshake failures for open ports. |

The scan never loads or sends a credential or private identity key. It never
enrolls a host key or changes configuration.

## `status`

```text
fv-ssh-unlock status [name...] [flags]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--accept-new-host-key` | off | Trust and save an unknown key after independent fingerprint verification. Never overrides a changed key. |
| `--identity <path>` | standard `~/.ssh` identities | Select an unencrypted private key used to prove normal macOS is booted; repeatable. |
| `--insecure-host-key` | off | Disable SSH host-key verification. Unsafe. |
| `--require-known` | off | Exit unsuccessfully when any reachable target remains indeterminate. |
| `--verbose` | off | Print sanitized diagnostic detail. |

`status` never loads or sends the FileVault password. Without `--identity`, it
tries keys from `ssh-agent` and regular standard identity files such as
`~/.ssh/id_ed25519` and `~/.ssh/id_rsa`. An explicit identity must be
unencrypted; add encrypted identities to `ssh-agent` instead.

## `unlock`

```text
fv-ssh-unlock unlock [name...] [flags]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--all` | off | Unlock every configured target. Cannot be combined with names. |
| `--identity <path>` | standard `~/.ssh` identities | Select an unencrypted private key for deterministic post-boot verification; repeatable. |
| `--insecure-host-key` | off | Disable SSH host-key verification. This can expose the password to an impersonated host. |
| `--no-verify` | off | Stop after pre-boot password acceptance. |
| `--retry-attempts <number>` | `10` | Maximum connection attempts. |
| `--retry-delay <duration>` | `30s` | Delay between transient failures. |
| `--verify-timeout <duration>` | `5m` | Time to wait for normal macOS SSH after acceptance. |
| `--verbose` | off | Print sanitized SSH and diagnostic detail. |
| `--allow-unsafe-credential-storage` | off | Permit reading an unverified plaintext disk credential file for this command only. |

At least one target name or `--all` is required. Before connecting, a named
multi-target invocation verifies that every name exists and is unique.

## Credential environment variables

For a device alias, uppercase the name and replace every character other than
a letter, number, or underscore with `_`, then prefix it with
`FV_UNLOCK_PASSWORD_`.

| Device alias | Variable |
| --- | --- |
| `my-mac` | `FV_UNLOCK_PASSWORD_MY_MAC` |
| `lab_2` | `FV_UNLOCK_PASSWORD_LAB_2` |

The configuration rejects aliases that would produce ambiguous variable names.
See [Environment variables](configuration-and-credentials.md#environment-variables)
for safe usage examples.

## Shell completion

Supported shells are Bash, Zsh, Fish, and PowerShell.

Bash, current shell:

```bash
source <(fv-ssh-unlock completion bash)
```

Zsh, one common per-user installation:

```bash
mkdir -p ~/.zfunc
fv-ssh-unlock completion zsh > ~/.zfunc/_fv-ssh-unlock
```

PowerShell, current session:

```powershell
fv-ssh-unlock completion powershell | Out-String | Invoke-Expression
```

Run the selected completion subcommand with `--help` for its persistent
installation instructions.

---

[Documentation home](index.md) | [Configuration and credentials](configuration-and-credentials.md) | [Status and unlocking](unlocking-and-status.md)

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
| `fv-ssh-unlock config auto-unlock NAME` | Enable or disable automatic unlock policy. |
| `fv-ssh-unlock config export` | Export the declarative device inventory as JSON. |
| `fv-ssh-unlock config apply --file PATH` | Idempotently reconcile the complete JSON inventory. |
| `fv-ssh-unlock credentials providers` | Report provider build, availability, persistence, and security status for this machine. |
| `fv-ssh-unlock discover` | List booted hosts advertising SSH through Bonjour. It does not connect or test FileVault. |
| `fv-ssh-unlock scan --cidr CIDR` | Actively find SSH servers, public key fingerprints, pinned-target matches, and password-free banner evidence. |
| `fv-ssh-unlock status [name...]` | Check state without sending a password. No names means all targets. |
| `fv-ssh-unlock unlock [name...]` | Unlock named targets; use `--all` explicitly for every target. |
| `fv-ssh-unlock daemon` | Continuously monitor devices, apply safe automatic-unlock policy, and serve the local control API. |
| `fv-ssh-unlock tui` | Open the terminal dashboard and candidate-enrollment menu. |
| `fv-ssh-unlock healthcheck` | Verify that the local daemon API is responsive. |
| `fv-ssh-unlock completion SHELL` | Generate Bash, Zsh, Fish, or PowerShell completion. |
| `fv-ssh-unlock --version` | Print the build version. |

## Global flags

| Flag | Purpose |
| --- | --- |
| `-h`, `--help` | Show command help. |
| `-v`, `--version` | Show the build version. |
| `--data-dir <absolute-path>` | Use this configuration/state directory instead of `FV_SSH_UNLOCK_DATA_DIR` or `~/.fv-ssh-unlock`. |

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
| `--auto-unlock` | off | Authorize the daemon to unlock this device after definitive FileVault detection. |

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
fv-ssh-unlock config auto-unlock NAME --enable
fv-ssh-unlock config auto-unlock NAME --disable
fv-ssh-unlock config export
fv-ssh-unlock config apply --file devices.json --check --json
fv-ssh-unlock config remove [name...]
fv-ssh-unlock config remove --all [--yes]
```

`config remove --all` asks for confirmation before removing all saved targets;
`--yes` skips that prompt for automation. Omitting both names and `--all` is an
error. A keyring-enabled binary also deletes credentials associated with the
removed device identifiers.

`config export` writes the complete device array as JSON. `config apply`
accepts that strict JSON schema from a file or `--file -`, validates the whole
inventory before acting, and replaces it atomically. `--check` reports without
writing; `--json` returns `changed`, `added`, `updated`, and `removed` fields.
Credential references may be present, but credential values are not part of
the schema. Restart a running daemon after configuration changed outside its
TUI/API; a TUI enrollment is loaded immediately.

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
| `--json` | off | Emit the versioned device-state report as JSON. |

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

## `daemon`

```text
fv-ssh-unlock daemon [flags]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--socket <absolute-path>` | `control.sock` in the effective data directory | Local Unix control socket; also settable with `FV_SSH_UNLOCK_SOCKET`. |
| `--identity <path>` | standard identities | Private key used for proof that normal macOS is booted; repeatable. |
| `--interval <duration>` | `30s` | Normal per-device poll interval. |
| `--boot-interval <duration>` | `5s` | Poll interval during boot verification or while an auto-recovery SSH endpoint is known down. |
| `--probe-timeout <duration>` | `15s` | Timeout for a password-free status probe. |
| `--unlock-timeout <duration>` | `45s` | Timeout for one automatic unlock operation. |
| `--concurrency <number>` | `4` | Maximum concurrent device operations. |
| `--discover-interval <duration>` | `5m` | Bonjour candidate browse schedule; `0` disables it. |
| `--discover-timeout <duration>` | `8s` | Bonjour collection time per scheduled round. |
| `--discover-interface <name>` | suitable interfaces | Restrict Bonjour to one interface. |
| `--scan-cidr <range>` | disabled | Authorized IPv4 candidate-scan range; repeatable. |
| `--scan-interval <duration>` | `15m` | Active scan schedule when CIDRs are configured. |
| `--scan-timeout <duration>` | `1.5s` | Timeout per active scan address. |
| `--scan-concurrency <number>` | `32` | Maximum simultaneous scan probes. |
| `--log-format <format>` | `text` | Log as operator-oriented `text` or one-record-per-line `json`. |
| `--log-level <level>` | `info` | Minimum daemon log level: `debug`, `info`, `warn`, or `error`. |
| `--json-log` | off | Shorthand for `--log-format json`; conflicts with an explicitly non-JSON format. |
| `--once` | off | Run one monitor cycle, print JSON, and exit without a socket. This can unlock and exits unsuccessfully after printing if a device operation failed. |

The daemon has no insecure-host-key or unsafe-credential-storage override. It
refuses to start if an auto-enabled device relies on runtime/environment input,
an unavailable keyring, or a file that is not verified as memory-backed secure
service delivery. It sends a credential only for a definitive `locked` state.

Text/info logging is the default. Use
`daemon --log-format json --log-level info` for a versioned, timestamped event
stream suitable for journald, Docker logging drivers, Fluent Bit, or Vector.
`debug` includes routine probes and discovery rounds and is intentionally more
verbose. The daemon writes logs to standard output and terminal/startup errors
to standard error; it does not manage log files or send logs over the network.

## `tui`

```text
fv-ssh-unlock tui [--socket PATH] [--refresh 2s]
fv-ssh-unlock tui --once
fv-ssh-unlock tui --json
```

The interactive view refreshes device state, events, and the untrusted
candidate inbox. Keys are `[a]` add candidate, `[i]` ignore candidate, `[p]`
poll device and report its resulting state, `[l]` clear a corrected security
latch, `[r]` refresh, and `[q]` quit. Enrollment requires the complete
fingerprint independently displayed on the Mac; discovery alone never enrolls
a key or enables management. Add/ignore actions reject already-managed
candidates, and adding also rejects ignored candidates until they are restored.

`--once` prints one human-readable snapshot without terminal control. `--json`
prints one combined versioned snapshot. Both are suitable for screen captures
and automation.

## `healthcheck`

```text
fv-ssh-unlock healthcheck [--socket PATH] [--timeout 3s] [--json]
```

The check reaches `GET /v1/health` only through the selected Unix socket. A
healthy daemon does not imply that every Mac is booted or reachable.

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

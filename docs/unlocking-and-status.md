# Status and unlocking

[Documentation home](index.md) | [Use cases](use-cases.md) | [Troubleshooting](troubleshooting.md)

`status` gathers password-free evidence from a configured target. `unlock`
sends the configured credential only after the SSH host key and challenge pass
the client's security checks.

## Contents

- [Enroll the SSH host key](#enroll-the-ssh-host-key)
- [Password-free status checks](#password-free-status-checks)
- [Why status can be unknown](#why-status-can-be-unknown)
- [Unlock one or more devices](#unlock-one-or-more-devices)
- [Unlock options](#unlock-options)
- [Result messages](#result-messages)
- [Post-unlock verification](#post-unlock-verification)
- [Retries and automation](#retries-and-automation)

## Enroll the SSH host key

The first status check fails closed when the target key is not yet trusted:

```bash
fv-ssh-unlock status my-mac
```

It prints the SSH key type and SHA256 fingerprint. Compare that value with the
fingerprint obtained directly from the booted target:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

After an exact match, enroll the unknown key:

```bash
fv-ssh-unlock status my-mac --accept-new-host-key
```

Enrollment never retrieves or transmits the FileVault password. The flag can
accept an unknown key, but it never overrides a changed-key warning. See
[SSH host-key enrollment](security.md#ssh-host-key-enrollment) for the threat
model and recovery process.

## Password-free status checks

Check every configured device, selected devices, or provide an explicit
unencrypted private key for booted-state proof:

```bash
fv-ssh-unlock status
fv-ssh-unlock status my-mac
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

| Status | Meaning |
| --- | --- |
| `locked` | The trusted server presented the distinctive FileVault locked explanation. |
| `unlocked (booted, SSH available)` | Normal macOS SSH accepted a public key. |
| `unknown (reachable...)` | No locked explanation or accepted public key proves which SSH environment answered. No password was sent. |
| Host-key error | The key is unknown or changed. Verification stopped. |

The pre-boot server cannot use a normal user's `authorized_keys` because the
data volume remains locked. Successful public-key authentication is therefore
positive evidence that normal macOS has booted. Keys are taken from
`ssh-agent` or explicit `--identity` paths. Private key files are not searched
automatically, and identity files must be unencrypted.

## Why status can be unknown

One observed macOS 26 FileVault server advertised `OpenSSH_10.2` and presented
only the generic hidden `Password:` prompt. It did not include the explanatory
locked banner. A booted SSH server configured for password-only authentication
can present the same evidence.

The client does not infer state from a server version, authentication methods,
or generic password prompt. It reports `unknown` instead. This is a safe and
expected result, not a password failure. A prompt-only FileVault server remains
unlockable when the operator explicitly invokes `unlock` for the trusted
target.

## Unlock one or more devices

Unlock one target, a named group, or every configured target:

```bash
fv-ssh-unlock unlock my-mac
fv-ssh-unlock unlock office-mac lab-mac
fv-ssh-unlock unlock
```

For predictable post-boot verification, provide an unencrypted private key
authorized by normal macOS SSH:

```bash
fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
```

For multiple targets, configure all credentials in advance. The tool reports
each result independently and skips a target whose credential is unavailable.

## Unlock options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--retry-attempts <number>` | `10` | Maximum connection attempts before giving up. |
| `--retry-delay <duration>` | `30s` | Delay between transient failures. |
| `--verify-timeout <duration>` | `5m` | Maximum time to wait for normal SSH after acceptance. |
| `--identity <path>` | none | Private key for booted-state probing; repeatable and unencrypted only. |
| `--no-verify` | off | Stop after the pre-boot server accepts the password. |
| `--verbose` | off | Show sanitized SSH banners and diagnostic details. |
| `--insecure-host-key` | off | Disable host-key verification. Unsafe with real credentials. |

Example for a target with slow pre-boot networking:

```bash
fv-ssh-unlock unlock my-mac \
  --retry-attempts 15 \
  --retry-delay 45s \
  --verify-timeout 8m \
  --identity ~/.ssh/id_ed25519
```

## Result messages

| Message | Meaning |
| --- | --- |
| `SUCCESS` | The trusted pre-boot server accepted the password and sent the configured success message. |
| `VERIFIED` | Normal macOS SSH later accepted a public key. |
| `WARNING ... no public key proved ...` after `SUCCESS` | The unlock was accepted, but no usable key was available to prove normal macOS returned. |
| `INFO ... already unlocked` | The target was already booted and normal SSH accepted a public key. |
| `FAILED ... still locked` | The password was rejected. |
| `NOTE ... may still be booting` | Unlock was accepted, but normal SSH did not return within the verification window. |
| `SECURITY ERROR` | SSH host-key verification failed. The client stopped without retrying. |

`SUCCESS` and `VERIFIED` deliberately prove different events. Do not interpret
a missing `VERIFIED` message as a retraction of an accepted unlock.

## Post-unlock verification

After `SUCCESS`, the client waits for the target to disconnect, boot, and
answer as normal macOS SSH. It does not send the FileVault password again.
Instead it tries public keys supplied by `ssh-agent` and `--identity`.

```mermaid
sequenceDiagram
    participant Client as fv-ssh-unlock
    participant Preboot as FileVault pre-boot SSH
    participant macOS as Normal macOS SSH

    Client->>Preboot: Verify pinned host key
    Preboot->>Client: Hidden Password prompt
    Client->>Preboot: FileVault password
    Preboot-->>Client: Success message and disconnect
    Client->>macOS: Reconnect without FileVault password
    Client->>macOS: Offer public key
    macOS-->>Client: Public-key authentication accepted
```

If no public key is usable, a later command can independently confirm boot:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

If verification is unnecessary for a controlled test, `--no-verify` stops
after password acceptance.

## Retries and automation

The client retries only failures that may be temporary, such as a timeout while
pre-boot networking starts. It does not retry an incorrect password, an
unexpected authentication challenge, or a host-key failure.

For automation that needs an independent process exit status for each Mac,
invoke one target per process. A fleet invocation reports all results but is
primarily intended for interactive operations.

---

[Documentation home](index.md) | [Use cases](use-cases.md) | [Troubleshooting](troubleshooting.md)

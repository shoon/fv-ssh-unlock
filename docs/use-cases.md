# Use cases

[Documentation home](index.md) | [Getting started](getting-started.md) | [Status and unlocking](unlocking-and-status.md)

Choose the situation that matches your starting point. Each workflow links to
the detailed guide for decisions and failure handling.

## Contents

- [Discover candidate Macs before setup](#discover-candidate-macs-before-setup)
- [Add several known Macs](#add-several-known-macs)
- [Prepare a new Mac](#prepare-a-new-mac)
- [Enroll a host key and identify state](#enroll-a-host-key-and-identify-state)
- [Restart and unlock one Mac](#restart-and-unlock-one-mac)
- [Unlock several Macs](#unlock-several-macs)

## Discover candidate Macs before setup

Use this workflow when Remote Login is already enabled on booted Macs but you
do not know their current hostnames or addresses:

```bash
fv-ssh-unlock discover --timeout 30s
```

Discovery listens for Bonjour SSH advertisements. It does not open an SSH
connection, inspect a banner, or prove that a result supports FileVault unlock.
Treat the output as an inventory of candidates to identify independently.

FileVault pre-boot may answer TCP/22 without advertising Bonjour. Run discovery
before restarting the Mac, then configure a DHCP reservation and save the
stable address. If the target has already restarted and disappeared from
Bonjour, use its reserved address or scan an authorized IPv4 subnet:

```bash
fv-ssh-unlock scan --cidr 192.168.1.0/24
```

Read [Discovery and scanning](discovery-and-scanning.md) before treating scan
evidence or a generic password prompt as identification.

## Add several known Macs

Use this workflow when the Macs are already prepared and you know their Remote
Login users and addresses. Add each target using a short local alias:

```bash
fv-ssh-unlock config add lab-1 \
  --host 192.0.2.21 \
  --user labunlock

fv-ssh-unlock config add lab-2 \
  --host 192.0.2.22 \
  --user labunlock
```

Use reserved numeric addresses if possible. The names `lab-1` and `lab-2` are
aliases in the client configuration; they do not create DNS records.

Choose a credential source for each device when prompted. A release binary can
save each password in the client operating system's keyring. For headless
automation, inject a separate environment secret for every device:

```bash
export FV_UNLOCK_PASSWORD_LAB_1='first-device-password'
export FV_UNLOCK_PASSWORD_LAB_2='second-device-password'
```

List the saved targets:

```bash
fv-ssh-unlock config list
```

Enroll each SSH host key individually after comparing its fingerprint with the
corresponding booted Mac:

```bash
fv-ssh-unlock status lab-1 --accept-new-host-key
fv-ssh-unlock status lab-2 --accept-new-host-key
```

Never approve a fingerprint based only on the network response you are trying
to trust. See [SSH host-key enrollment](security.md#ssh-host-key-enrollment)
and [Credentials](configuration-and-credentials.md#credentials).

## Prepare a new Mac

Use this workflow when FileVault, Remote Login, the unlock account, or stable
network addressing has not been configured yet.

On the target Mac while normal macOS is running:

1. Enable FileVault.
2. Select an existing standard user or create a dedicated standard user.
3. Confirm the user can unlock FileVault.
4. Enable Remote Login only for the users that need it.
5. Test normal SSH from the future client computer.
6. Create a DHCP reservation for the pre-boot network interface.
7. Record the Ed25519 SSH host-key fingerprint.
8. Add and enroll the target from the client.
9. Test a full restart and unlock while local access is still available.

The example name `unlockuser` is not a special account. The user must be a real
local macOS account, and there is no supported FileVault pre-boot-only account.
See [Prepare a new Mac](getting-started.md#prepare-a-new-mac) and
[Choose the FileVault user](getting-started.md#choose-the-filevault-user) for
the complete setup and least-privilege guidance.

## Enroll a host key and identify state

The first status check against a target with no pinned key fails closed and
prints the presented fingerprint:

```bash
fv-ssh-unlock status my-mac
```

Compare that value with the fingerprint recorded directly from the target.
Enroll it only after an exact match:

```bash
fv-ssh-unlock status my-mac --accept-new-host-key
```

Enrollment never retrieves or sends the FileVault password and never overrides
a changed-key warning.

After enrollment, `status` reports one of three evidence-based states:

- `locked` when the trusted SSH server presents the distinctive FileVault
  locked explanation;
- `unlocked` when normal macOS SSH accepts a public key; or
- `unknown` when neither state can be proved without a password.

A recent FileVault server was observed showing only the generic hidden
`Password:` prompt. That prompt is not distinguishable from a password-only
booted SSH server, so `unknown` is correct and does not prevent an explicit
unlock. Read [Password-free status checks](unlocking-and-status.md#password-free-status-checks)
for details.

## Restart and unlock one Mac

After the Mac reaches the FileVault screen, run:

```bash
fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
```

The identity is an unencrypted private key authorized by normal macOS SSH. It
is used only after password acceptance to prove that normal macOS finished
booting. The pre-boot server still requires the FileVault password.

```text
Attempt 1/10: Unlocking unlockuser@192.0.2.10:22
SUCCESS: my-mac accepted the unlock password.
Verifying my-mac finished booting (up to 5m0s)...
VERIFIED: my-mac is booted and reachable over SSH.
```

If no public key is available, a valid unlock still reports `SUCCESS`, followed
by a warning that booted macOS could not be proved. Run this later to check:

```bash
fv-ssh-unlock status my-mac --identity ~/.ssh/id_ed25519
```

See [Status and unlocking](unlocking-and-status.md) for every result and retry
option.

## Unlock several Macs

Pass target names to unlock a selected group, or omit names to unlock every
configured target:

```bash
fv-ssh-unlock unlock office-mac lab-mac
fv-ssh-unlock unlock
```

Configure every credential in advance. The tool reports each result
independently and skips targets whose credentials are unavailable. For
automation that requires an independent exit status for each Mac, invoke one
device per process.

---

[Documentation home](index.md) | [Getting started](getting-started.md) | [Status and unlocking](unlocking-and-status.md)

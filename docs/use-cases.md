# Use cases

[Documentation home](index.md) | [Getting started](getting-started.md) | [Status and unlocking](unlocking-and-status.md)

Choose the situation that matches your starting point. Each workflow links to
the detailed guide for decisions and failure handling.

## Contents

- [Discover candidate Macs before setup](#discover-candidate-macs-before-setup)
- [Keep homelab Macs available after a power outage](#keep-homelab-macs-available-after-a-power-outage)
- [Enroll a new Mac from the persistent candidate inbox](#enroll-a-new-mac-from-the-persistent-candidate-inbox)
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

## Keep homelab Macs available after a power outage

Use an always-on Linux server or Raspberry Pi as the controller when the Macs
may lose power but the controller, switch, and router remain available. The
daemon can observe each Mac return to FileVault pre-boot, release one authorized
credential, and prove that normal macOS SSH comes back without depending on
ICMP ping.

Prepare the site before relying on unattended recovery:

1. Keep the controller and required network equipment on suitable backup power.
2. Configure each Mac to start after power is restored.
3. Give each Mac a DHCP reservation usable by FileVault pre-boot.
4. Enable FileVault and Remote Login, select the FileVault user, and authorize a
   dedicated SSH public key in normal macOS.
5. Provision a secure service credential for each target. Runtime environment
   passwords are intentionally rejected for automatic unlock.
6. Add each device with automatic unlock enabled and independently pin its host
   key while macOS is booted.

For a systemd credential reference, configuration might look like:

```bash
fv-ssh-unlock config add m4alpha \
  --host 192.168.1.42 \
  --user unlockuser \
  --credential-source file \
  --credential-file systemd:m4alpha \
  --auto-unlock

fv-ssh-unlock status m4alpha \
  --identity /var/lib/fv-ssh-unlock/id_ed25519 \
  --accept-new-host-key
```

Run the one-pass test while the Mac is booted, then supervise the foreground
daemon with systemd or a container runtime:

```bash
fv-ssh-unlock daemon --once \
  --identity /var/lib/fv-ssh-unlock/id_ed25519

fv-ssh-unlock daemon \
  --identity /var/lib/fv-ssh-unlock/id_ed25519 \
  --scan-cidr 192.168.1.0/24
```

The sequence after an outage is deliberately conservative:

```text
unreachable → locked → unlocking → booting → booted
```

`unreachable` never triggers a credential. Only the complete FileVault locked
banner can enter the automatic-unlock path. The attempt is durably recorded
before the password is retrieved, and an accepted or ambiguous submission is
followed by password-free SSH verification rather than another submission.

Reconnect to the controller and open the dashboard at any time:

```bash
fv-ssh-unlock tui
```

It is safe to leave that command displayed in `tmux`, `screen`, or `zellij`;
the separately supervised daemon continues if the terminal disconnects. If a
credential or pinned-host-key failure latches a Mac, correct and independently
verify the cause, then use `l` in the TUI to acknowledge it.

A FileVault implementation that exposes only a generic `Password:` prompt is
reported as `indeterminate` and will not auto-unlock. That target still requires
an explicit manual `unlock` operation. Read [Persistent daemon and terminal
dashboard](daemon-and-tui.md) for the full state and retry policy.

## Enroll a new Mac from the persistent candidate inbox

Use this workflow to turn “the new Mac appeared on the LAN” into a managed
target without copying a network-supplied key into configuration blindly.

On the Mac, complete the preparation steps in [Prepare a new Mac](#prepare-a-new-mac)
and leave normal macOS booted. On the controller, start the daemon with Bonjour
and an explicitly authorized active-scan range:

```bash
fv-ssh-unlock daemon \
  --identity /var/lib/fv-ssh-unlock/id_ed25519 \
  --discover-interval 5m \
  --scan-cidr 192.168.1.0/24 \
  --scan-interval 15m
```

Both discovery rounds run immediately at startup. Bonjour may first create a
`discovered` candidate with no fingerprint. The daemon's active scan—not the
one-shot `scan` command—adds the fingerprint to the persistent inbox and moves
it to `identity_pending`.

Open another terminal:

```bash
fv-ssh-unlock tui
```

Then:

1. Press `a` and select the candidate.
2. At the Mac, run the fingerprint command printed by the TUI:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

3. Type the complete locally displayed `SHA256:...` fingerprint. The shortened
   value in the table and the network scan alone are not acceptable trust
   sources.
4. Confirm the alias, reserved address, port, and macOS/FileVault username.
5. Leave automatic unlock at its default `no` for monitoring only, or select
   `yes` and reference a secure credential provisioned before enrollment.

The daemon reconnects expecting exactly that fingerprint, pins it, saves the
device, and begins monitoring it immediately. No restart is needed for a device
enrolled through the TUI. A mismatch stops before the candidate is trusted or
configured.

Press `i` instead when the SSH host is not a Mac you want to manage. Ignored
candidates persist across later scans and expiration. Persistent discovery
never enrolls a candidate or enables automatic unlock without this operator
workflow. See [Persistent candidate discovery](daemon-and-tui.md#persistent-candidate-discovery)
for intervals, CIDR limits, and API alternatives.

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
automation, prefer a Docker Swarm secret, systemd credential, or another
externally managed file and inspect the environment first:

```bash
fv-ssh-unlock credentials providers
```

Scoped runtime environment secrets also remain available for every device:

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
- `booted` when normal macOS SSH accepts a public key; or
- `indeterminate` when neither state can be proved without a password.

A recent FileVault server was observed showing only the generic hidden
`Password:` prompt. That prompt is not distinguishable from a password-only
booted SSH server, so `indeterminate` is correct and does not prevent an explicit
unlock. Read [Password-free status checks](unlocking-and-status.md#password-free-status-checks)
for details.

## Restart and unlock one Mac

After the Mac reaches the FileVault screen, run:

```bash
fv-ssh-unlock unlock my-mac --identity ~/.ssh/id_ed25519
```

The identity is an unencrypted private key authorized by normal macOS SSH. It
first lets the client detect that no unlock is needed when the Mac is already
booted, and after password acceptance it proves that normal macOS returned.
The pre-boot server cannot accept this key and still requires the FileVault
password.

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

Pass target names to unlock a selected group, or use `--all` explicitly to
unlock every configured target:

```bash
fv-ssh-unlock unlock office-mac lab-mac
fv-ssh-unlock unlock --all
```

Configure every credential in advance. The tool reports each result
independently and skips targets whose credentials are unavailable. For
automation that requires an independent exit status for each Mac, invoke one
device per process.

---

[Documentation home](index.md) | [Getting started](getting-started.md) | [Status and unlocking](unlocking-and-status.md)

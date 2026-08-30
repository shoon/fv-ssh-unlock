# Persistent daemon and terminal dashboard

[Documentation home](index.md) | [Discovery and scanning](discovery-and-scanning.md) | [Security](security.md)

The `daemon` command is a foreground, long-running controller for an always-on
Linux server, Raspberry Pi, Mac, or container host. It performs password-free
checks, applies a conservative automatic-unlock policy, maintains a candidate
inbox, and serves a local control API. A service manager or container runtime
should supervise it for unattended use.

The `tui` command is a separate client. Closing the dashboard or losing the SSH
session that displayed it does not stop the daemon.

For production supervision and packaging, continue with [Containers and
persistent services](containers-and-services.md). For declarative inventory,
Ansible, and machine-readable integration, see [Infrastructure
automation](automation.md).

## Contents

- [Start with a one-pass test](#start-with-a-one-pass-test)
- [Run the persistent controller](#run-the-persistent-controller)
- [Device states and automatic-unlock policy](#device-states-and-automatic-unlock-policy)
- [Failure backoff, cooldown, and latches](#failure-backoff-cooldown-and-latches)
- [Operational logging and SIEM collection](#operational-logging-and-siem-collection)
- [Persistent candidate discovery](#persistent-candidate-discovery)
- [Review and enroll a candidate](#review-and-enroll-a-candidate)
- [Use the terminal dashboard](#use-the-terminal-dashboard)
- [Local control API](#local-control-api)
- [Files and service identity](#files-and-service-identity)
- [Current limitations](#current-limitations)

## Start with a one-pass test

Before installing a service, verify every configured Mac from the account that
will run the daemon:

```bash
fv-ssh-unlock credentials providers --require-secure
fv-ssh-unlock daemon --once --identity /path/to/dedicated_ed25519
```

`daemon --once` polls every configured device once, prints the device snapshot
as JSON, and exits. It does not start the control socket, TUI, or periodic
candidate discovery. It prints the snapshot first and then exits unsuccessfully
when one or more device operations failed, so automation can retain the
evidence and still detect the failure.

This is an operational test, not a dry run. If a device already has automatic
unlock enabled and the probe conclusively sees the FileVault locked banner,
`daemon --once` may submit its configured credential. Disable the policy first
when you want a password-free-only test:

```bash
fv-ssh-unlock config auto-unlock m4alpha --disable
fv-ssh-unlock daemon --once --identity /path/to/dedicated_ed25519
```

The ordinary one-device `status` command remains useful for setup diagnostics:

```bash
fv-ssh-unlock status m4alpha --identity /path/to/dedicated_ed25519 --verbose
```

## Run the persistent controller

A basic foreground invocation is:

```bash
fv-ssh-unlock daemon --identity /path/to/dedicated_ed25519
```

The daemon polls each configured device immediately and then on its independent
schedule. Normal polling defaults to 30 seconds; a device in `booting` or
`unlocking` is checked every 5 seconds. At most four device operations run at
once by default.

Relevant flags are:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--identity <path>` | standard SSH identities | Private key used to prove that normal macOS SSH is back; repeatable. |
| `--interval <duration>` | `30s` | Normal polling interval. |
| `--boot-interval <duration>` | `5s` | Polling interval while booting or while an auto-recovery SSH endpoint is known down. |
| `--probe-timeout <duration>` | `15s` | Bound one password-free status probe. |
| `--unlock-timeout <duration>` | `45s` | Bound one automatic unlock operation. |
| `--concurrency <number>` | `4` | Maximum simultaneous device operations; accepted range is 1 through 256. |
| `--log-format <format>` | `text` | Select `text` for operators or `json` for structured collection. |
| `--log-level <level>` | `info` | Minimum level: `debug`, `info`, `warn`, or `error`. |
| `--json-log` | off | Compatibility shorthand for `--log-format json`. |
| `--socket <absolute-path>` | data directory's `control.sock` | Override the local control socket. |
| `--once` | off | Poll once, print JSON, and exit. |

All durations must be positive. The daemon is intentionally a foreground
process so systemd, Docker, or another supervisor can own restart and logging
policy.

Configuration is loaded at daemon startup. Changes made by separate `config`
commands require a daemon restart. Enrollment through the running daemon's TUI
or API is different: the new device begins monitoring immediately.

## Device states and automatic-unlock policy

The dashboard reports evidence, not guesses:

| State | Meaning and action |
| --- | --- |
| `booted` | Normal macOS SSH accepted a configured public key. The lock episode is closed. |
| `locked` | The pinned SSH server presented the definitive FileVault locked explanation. Automatic unlock is considered only in this state. |
| `indeterminate` | SSH answered, but neither the full locked banner nor successful public-key authentication proved the state. No credential is released. |
| `unreachable` | The endpoint could not be reached or the operation timed out. The daemon backs off and does not infer FileVault state. |
| `unlocking` | The durable attempt marker was written and the one authorized credential submission is in progress. |
| `booting` | FileVault accepted the credential, or the pre-boot endpoint disappeared after submission; the daemon now verifies normal macOS without resubmitting the password. |
| `credential-failed` | Credential retrieval or authentication failed and the device is latched for operator review. |
| `error` | A host-key or other operational failure occurred. Host-key failures latch; transient errors retry conservatively. |

Automatic unlock is per-device and defaults off. Enable it when adding a device
with `config add --auto-unlock`, through the enrollment wizard, or afterward:

```bash
fv-ssh-unlock config auto-unlock m4alpha --enable
```

Restart a running daemon after that external configuration change.

The daemon releases a credential only when all of these conditions hold:

1. the device was explicitly configured with `auto_unlock: true`;
2. its SSH host key is already pinned and still matches;
3. a password-free probe sees the complete, distinctive FileVault locked
   banner;
4. the credential provider is available and assessed as secure for unattended
   use;
5. the device is not latched, the current lock episode has not already used its
   attempt, and its persisted cooldown has elapsed; and
6. the attempt marker is durably saved before the credential is retrieved.

A generic `Password:` prompt, TCP/22 reachability, Bonjour advertisement,
hostname, IP address, ping result, or `unreachable` state is never sufficient.
Runtime and environment credentials are refused for unattended automatic
unlock. Use a verified OS keyring in a usable service session or a
service-scoped, memory-backed file such as a systemd credential or Docker Swarm
secret. See [Configuration and credentials](configuration-and-credentials.md).

After a probe establishes that TCP/22 is down, an auto-enabled target uses a
short TCP connect preflight on the boot interval. This avoids an ICMP/ping
dependency and long failure backoff when the endpoint returns. A successful
TCP connect only wakes the complete pinned, password-free SSH probe; it never
authorizes credential release by itself. SSH failures after TCP connects still
use conservative backoff.

## Failure backoff, cooldown, and latches

The monitor persists security-relevant state in `monitor-state.json`. Restarting
the process therefore cannot erase an attempt marker and cause the same locked
episode to be hammered with passwords.

- The default unlock cooldown is 15 minutes.
- A connection failure known to occur before credential submission retries
  with exponential backoff from 15 seconds up to 15 minutes.
- An auto-enabled target whose TCP endpoint is specifically known down uses
  the shorter boot interval and a cheap TCP preflight until port 22 returns.
- Repeated availability failures also slow ordinary polling, with jitter to
  avoid synchronized fleet activity.
- Once the credential may have been accepted, the daemon changes to
  password-free boot verification instead of submitting it again.
- Credential rejection or retrieval failure enters `credential-failed` and
  latches.
- A changed or mismatched pinned host key enters `error` and latches.

Fix and independently verify the underlying credential or host-key issue before
clearing a latch. In the TUI press `l`, choose the device, and let the next poll
apply policy again. Clearing a latch while the last conclusive observation is
still `locked` permits one deliberate retry, but it does not bypass the
persisted cooldown.

## Operational logging and SIEM collection

The daemon writes its foreground event stream to standard output. CLI parsing,
startup, and terminal errors are written to standard error. It does not create
or rotate log files and has no built-in network log exporter; systemd, Docker,
or another supervisor should own retention and forwarding.

`--log-format` controls the persistent event stream. `daemon --once` instead
prints its versioned device snapshot as JSON, regardless of the logging format,
and emits no persistent event stream.

The default `--log-format text --log-level info` is appropriate for a terminal
and records meaningful state transitions, unlock actions, latches, candidate
detections, and lifecycle events without recording every successful poll. Use
`debug` temporarily for per-probe and discovery-round diagnostics. `warn`
retains failures and latch changes but omits normal recovery transitions;
`error` retains only the highest-severity structured records and ordinary
command errors still appear on standard error.

The first conclusive observation for each device after daemon startup is also
logged at `info`, even when it matches restored state. This gives collectors a
fresh per-run baseline without turning routine healthy polls into log noise.

For a SIEM or log pipeline, select the versioned JSON format:

```bash
fv-ssh-unlock daemon --log-format json --log-level info
```

Each JSON record is one line. These fields provide the versioned integration
surface:

| Field | Meaning |
| --- | --- |
| `time` | RFC3339 log-emission timestamp with a zone offset. |
| `level` | `DEBUG`, `INFO`, `WARN`, or `ERROR`. |
| `msg` | Human-readable summary; do not parse it as an event identifier. |
| `schema_version` | Structured-log schema version, currently `1`. |
| `component` | Producing component, currently `daemon`. |
| `run_id` | 32-character lowercase hexadecimal identifier shared by every record from one daemon process. |
| `event` | Stable semantic name such as `device.filevault_locked`, `device.unlock_result`, or `candidate.discovered`. |

Applicable device records add `event_time`, `sequence`, `device`, `state`,
`observation`, `lock_episode`, `auto_unlock`, `endpoint_down`, `latched`,
`failure_kind`, and `detail`. Candidate and discovery records may add
`candidate_id`, `candidate_state`, `source`, `observed_at`, `endpoint`,
`hostname`, and observation counts. Route and alert on `event` and the
structured fields; `msg` and `detail` are operator explanations and may be
refined. A monitor `sequence` orders events from one running daemon and is not
a globally unique event identifier. It resets for each run. A sequence gap
means the bounded, non-blocking monitor subscription dropped local telemetry
rather than delaying device recovery.

For example, a locked-state transition resembles:

```json
{"time":"2026-08-30T18:42:15.123Z","level":"INFO","msg":"FileVault pre-boot detected","schema_version":1,"component":"daemon","run_id":"6f7f35edc08a1c425cf460ffacbe5d2a","event":"device.filevault_locked","event_time":"2026-08-30T18:42:15.120Z","sequence":42,"device":"m4alpha","state":"locked","observation":"locked","lock_episode":3,"auto_unlock":true,"endpoint_down":false,"latched":false,"detail":"FileVault pre-boot banner detected"}
```

The daemon drains queued monitor events during an orderly shutdown, but the
subscription and stdout stream remain best-effort and are not a guaranteed
audit log. Use the local API for current state and an external journald/SIEM
collector with retention for durable operational or compliance records. Alert
on sequence gaps and reconcile the affected run with a device snapshot.

Common collection paths require no sidecar inside the minimal image:

- systemd captures both streams in journald. Follow them with
  `journalctl -u fv-ssh-unlock -f -o cat`, and let the host's journal gateway or
  forwarding agent collect the unit.
- Docker captures the container streams. Use `docker logs` for local diagnosis
  and select the host's supported Docker logging driver for central delivery.
- Fluent Bit and Vector can consume journald or Docker/container standard
  output and parse each JSON line before forwarding it. Run the collector on
  the host or as separate infrastructure; do not add it to the scratch
  controller image.

JSON logs never contain credential values, SSH private-key bodies, raw SSH or
FileVault banners, authentication answers, environment-variable values, or
control-API request bodies. They do contain security-relevant metadata such as
device names, endpoints, candidate hostnames, states, and sanitized errors.
Restrict log access and configure retention accordingly.

## Persistent candidate discovery

Bonjour candidate discovery is enabled by default. One browse runs when the
daemon starts, then every five minutes:

```bash
fv-ssh-unlock daemon \
  --discover-interval 5m \
  --discover-timeout 8s \
  --discover-interface eth0
```

Set `--discover-interval 0` to disable it. `--discover-interface` is optional;
when omitted, eligible LAN interfaces are selected automatically.

Bonjour is passive and does not reveal an SSH host key. Its results enter the
candidate inbox as `discovered` and cannot be enrolled yet. It primarily finds
booted Macs advertising `_ssh._tcp` or `_sftp-ssh._tcp`; FileVault pre-boot may
not advertise either service.

For fingerprint collection, explicitly authorize one or more IPv4 CIDRs:

```bash
fv-ssh-unlock daemon \
  --scan-cidr 192.168.1.0/24 \
  --scan-cidr 192.168.20.0/24 \
  --scan-interval 15m \
  --scan-timeout 1.5s \
  --scan-concurrency 32
```

An active scan runs once at startup and then at the interval. It probes TCP/22,
performs a password-free SSH handshake, records the public host-key fingerprint
and limited banner evidence, and may create authentication-failure logs on
scanned systems. Combined CIDRs retain the 4096-address safety limit. Only scan
networks you own or are authorized to test.

Candidate states are:

- `discovered`: a name or endpoint was observed, but no SSH fingerprint is
  known;
- `identity_pending`: a SHA-256 SSH fingerprint is available for independent
  review;
- `verified`: the fingerprint was independently confirmed and enrolled, or
  already matches a configured pinned target; and
- `ignored`: the entry remains marked as intentionally ignored until restored.

The fingerprint is the primary identity. Names and addresses are untrusted,
mutable hints. Repeated sightings of the same fingerprint are combined across
address changes. Different fingerprints seen at a reused address remain
separate candidates. Non-ignored candidate observations expire after seven
days; ignored entries survive expiration.

Discovery and scanning never read a credential, load a private identity key,
send a password, pin a key, add a device, or enable automatic unlock. There is
no automatic enrollment mode.

## Review and enroll a candidate

Start the dashboard while the daemon is running:

```bash
fv-ssh-unlock tui
```

If a Bonjour result says `pending active scan`, wait for an authorized CIDR
scan or restart the daemon with `--scan-cidr` configured. Enrollment requires a
candidate fingerprint.

Press `a`, select the candidate number, then follow this trust ceremony:

1. Sit at the candidate Mac or use a separately trusted management channel.
2. Run the command printed by the current wizard on that Mac:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

3. Compare the complete `SHA256:...` value, not the address, hostname, shortened
   dashboard value, or scan result alone.
4. Type the complete locally displayed fingerprint into the TUI. Any mismatch
   stops enrollment without trusting or configuring the candidate.
5. Confirm or edit the local alias, stable host or reserved IP, SSH port, and
   macOS/FileVault username.
6. Choose whether to enable automatic unlock; the default is `no`.
7. Select `file`, `keyring`, or `runtime`. For `file`, enter the already
   provisioned secure path or a portable `systemd:<name>` reference.

For automatic unlock, the wizard defaults to `file`, rejects `runtime`, and the
daemon verifies that the provider is secure and available. The wizard does not
ask for, transmit, or create a FileVault password. Provision the referenced
secret before enrollment. For password-free monitoring only, leave automatic
unlock off; `runtime` can then remain the manual credential source.

The daemon reconnects using the exact expected fingerprint, pins that host key,
validates and saves the device, and adds it to the running monitor. A network
key that was not independently typed back exactly cannot pass this flow.

Press `i` to permanently ignore an unwanted, unconfigured candidate. The TUI
refuses to ignore an already-managed or already-ignored entry and refuses to
add an ignored or already-managed entry. The current TUI has no restore key;
use the local API's `POST /v1/candidates/{id}/restore` route.

## Use the terminal dashboard

Interactive keys are:

| Key | Action |
| --- | --- |
| `a` | Add a candidate through fingerprint verification and enrollment. |
| `i` | Permanently ignore a selected candidate. |
| `p` | Run an immediate policy-controlled poll and display the resulting state or error. |
| `l` | Clear a selected device's credential or host-key failure latch. |
| `r` | Refresh immediately. |
| `q` or `Ctrl-C` | Close only the TUI. The separately supervised daemon continues. |

The dashboard refreshes every two seconds by default. Change that interval or
print a non-interactive snapshot with:

```bash
fv-ssh-unlock tui --refresh 5s
fv-ssh-unlock tui --once
fv-ssh-unlock tui --json
```

Both `--once` and `--json` require a running daemon. `--once` prints the table
without entering raw terminal mode; `--json` returns the combined device and
candidate snapshot. Neither option polls or unlocks a device by itself.

When the daemon uses a nondefault socket, point the TUI at the same absolute
path:

```bash
fv-ssh-unlock tui --socket /run/fv-ssh-unlock/control.sock
```

`FV_SSH_UNLOCK_SOCKET` provides the same override.

## Local control API

The daemon exposes versioned HTTP semantics only over its Unix domain socket.
It does not listen on TCP, honor proxy variables, or provide a remote web API.
On Unix, the containing directory is mode `0700` and the socket is mode `0600`.

API schema version 1 provides:

| Method and route | Purpose |
| --- | --- |
| `GET /v1/health` | Daemon health, version, and start/check timestamps. |
| `GET /v1/devices` | Managed-device states and recent monitor events. |
| `GET /v1/candidates` | Candidate-inbox snapshot. |
| `POST /v1/devices/{name}/poll` | Run one immediate policy-controlled poll. This can unlock an eligible locked device. |
| `POST /v1/devices/{name}/clear-latch` | Acknowledge and clear a failure latch. |
| `POST /v1/candidates/{id}/ignore` | Permanently ignore a candidate. |
| `POST /v1/candidates/{id}/restore` | Return an ignored candidate to review. |
| `POST /v1/candidates/{id}/enroll` | Verify the exact supplied fingerprint, pin it, add the device, and start monitoring. |

For example:

```bash
curl --unix-socket ~/.fv-ssh-unlock/control.sock \
  http://localhost/v1/health

curl --unix-socket ~/.fv-ssh-unlock/control.sock \
  -X POST http://localhost/v1/devices/m4alpha/poll
```

Enrollment accepts `application/json` with these fields:

```json
{
  "name": "m4alpha",
  "host": "192.168.1.42",
  "user": "unlockuser",
  "port": 22,
  "fingerprint": "SHA256:complete-independently-verified-value",
  "credential_source": "file",
  "credential_ref": "systemd:m4alpha",
  "auto_unlock": true
}
```

The fingerprint must exactly equal the current candidate fingerprint. The API
does not accept a password value. Treat access to this socket as administrative
access: a caller can poll devices, clear safety latches, change candidate state,
and enroll a verified candidate. Do not publish or proxy it onto a network.

Use the purpose-built health check in service and container definitions:

```bash
fv-ssh-unlock healthcheck
fv-ssh-unlock healthcheck --json --timeout 3s
```

## Files and service identity

The default data directory is `~/.fv-ssh-unlock` for the account running the
process. The persistent service uses:

```text
devices.json        Configured targets and credential references
known_hosts         Pinned SSH public host keys
monitor-state.json  Durable lock episodes, attempts, cooldowns, and latches
candidates.json     Candidate inbox and ignore state
daemon.lock         Process lock preventing two controllers from sharing state
control.sock        Local API socket while the daemon is running
```

Select one absolute directory explicitly for a service or container:

```bash
fv-ssh-unlock --data-dir /var/lib/fv-ssh-unlock daemon
fv-ssh-unlock --data-dir /var/lib/fv-ssh-unlock tui
```

`FV_SSH_UNLOCK_DATA_DIR` is the environment equivalent. Run configuration,
provider checks, the daemon, and the TUI with the intended service identity and
same data directory. A desktop user's keyring, home directory, SSH agent, and
standard private keys may not be available to a headless service account.
On Unix, provision an existing service directory as mode `0700`; the program
will not chmod a shared or group/world-accessible directory on the operator's
behalf.

## Current limitations

- Automatic unlock requires the complete recognized FileVault explanation.
  FileVault versions that present only generic `Password:` evidence remain
  `indeterminate` and require an explicit manual unlock.
- Bonjour normally sees booted, advertising Macs; it may disappear in
  FileVault pre-boot and does not cross routed VLANs without multicast support.
- Periodic active scanning is IPv4-only, fixed to TCP/22, and must be scoped to
  explicitly authorized CIDRs.
- Candidate discovery finds SSH services, not necessarily Macs or machines
  configured for FileVault SSH unlock.
- The TUI prints the matching macOS host-public-key path for Ed25519, RSA, and
  ECDSA candidates. An unrecognized key type falls back to the Ed25519 command
  and requires separate verification of the correct host-key file.
- External changes to `devices.json`, including `config auto-unlock` and
  declarative configuration updates, require a daemon restart. TUI/API
  enrollment is applied live.
- The daemon and TUI currently share the same executable and local Unix socket;
  there is no remote browser dashboard or multi-user authorization layer.
- A Mac must be configured to power on after an outage, obtain a usable
  pre-boot network address, and run the supported FileVault SSH service. This
  program cannot power on hardware by itself.

---

[Documentation home](index.md) | [Discovery and scanning](discovery-and-scanning.md) | [Security](security.md)

# Logging and SIEM collection

[Documentation home](index.md) | [Persistent controller and TUI](daemon-and-tui.md) | [Containers and services](containers-and-services.md) | [Infrastructure automation](automation.md)

The persistent controller emits operational events for people, service
supervisors, and security tooling. It deliberately has no embedded exporter,
remote log sink, or bundled collector. The process writes locally; journald,
Docker, Fluent Bit, Vector, or the site's existing agent owns buffering,
retention, transport security, and delivery.

## Contents

- [Enable structured logs](#enable-structured-logs)
- [Understand the two output streams](#understand-the-two-output-streams)
- [JSON field contract](#json-field-contract)
- [Event and level catalog](#event-and-level-catalog)
- [Ordering, gaps, and current-state reconciliation](#ordering-gaps-and-current-state-reconciliation)
- [Useful alerts](#useful-alerts)
- [Inspect records with jq](#inspect-records-with-jq)
- [Collect with systemd and journald](#collect-with-systemd-and-journald)
- [Collect with Docker](#collect-with-docker)
- [Forward with Fluent Bit or Vector](#forward-with-fluent-bit-or-vector)
- [Retention and delivery guarantees](#retention-and-delivery-guarantees)
- [Security and privacy](#security-and-privacy)
- [Troubleshoot collection](#troubleshoot-collection)

## Enable structured logs

Text at `info` is the human-oriented default. Use versioned JSON at `info` for
normal collection:

```bash
fv-ssh-unlock daemon --log-format json --log-level info
```

`--json-log` is a shorthand for `--log-format json`. Use `debug` temporarily
when diagnosing individual password-free probes or discovery rounds; it is
substantially noisier. `warn` and `error` are not complete device-health
views. In particular, unreachable, indeterminate, and some device error state
records are emitted at `info`. Collect `info` and alert on structured fields.

`daemon --once` is different. It prints one versioned device snapshot as JSON
and exits; it does not start the control socket or emit the persistent event
stream. It is an operational run, not a dry run, and may unlock an eligible
device.

## Understand the two output streams

The daemon logger writes one JSON object per physical line to standard output
when JSON format is enabled. Command parsing, startup, and final CLI errors are
human-readable text on standard error. A runtime failure can therefore produce
a JSON `daemon.failed` record on stdout followed by a plain `Error: ...` line
on stderr.

journald and common Docker views show both streams together. A collector must
attempt to parse each message as JSON and preserve the original message when
parsing fails. Do not discard a non-JSON record merely because structured
logging was enabled; it may be the startup error that explains why the daemon
did not remain running.

## JSON field contract

Every structured daemon record has this envelope:

| Field | Type | Meaning |
| --- | --- | --- |
| `time` | string | RFC3339 log-emission time. |
| `level` | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`. |
| `msg` | string | Human summary. Do not use it as an event identifier. |
| `schema_version` | number | Structured-log schema version, currently `1`. |
| `component` | string | Producing component, currently `daemon`. |
| `run_id` | string | 32-character lowercase hexadecimal ID shared by one daemon process. |
| `event` | string | Stable semantic event name from the catalog below. |

Monitor/device records also contain these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `event_time` | string | RFC3339 time at which the monitor produced the event. |
| `sequence` | number | Per-run monitor sequence; it is not present on lifecycle, discovery, or candidate-action records. |
| `device` | string | Configured device alias. |
| `state` | string | Current operator-visible device state. |
| `observation` | string | Latest password-free observation, which can differ from `state` while a latch remains active. |
| `lock_episode` | number | Durable lock-episode counter. |
| `auto_unlock` | boolean | Whether automatic unlock is authorized for this device. |
| `endpoint_down` | boolean | Whether TCP preflight currently knows the SSH endpoint is down. |
| `latched` | boolean | Whether an operator-cleared safety latch is active. |
| `failure_kind` | string | Optional active latch kind, currently `credential` or `host-key`; it is not a classification of every transient error. |
| `detail` | string | Optional bounded operator explanation. Do not parse it as a stable identifier. |

Lifecycle, discovery, and candidate records use fields as applicable:

| Field | Meaning |
| --- | --- |
| `devices`, `socket`, `data_dir` | Startup inventory count and local paths. |
| `error` | Sanitized operational error. |
| `source` | Discovery source, currently `bonjour` or `active-scan`. |
| `observations` | Number of observations in a discovery round. |
| `candidate_id`, `candidate_state`, `observed_at` | Candidate identity, review state, and observation time. |
| `endpoint`, `hostname` | Untrusted network metadata when available. |
| `fingerprint` | Observed SSH fingerprint when a dropped discovery observation supplied one. |
| `replacement_candidate_id` | New candidate that displaced the unreviewed `candidate_id` on `candidate.evicted`. |
| `reason` | Human capacity explanation on `candidate.dropped`; do not use it as the routing key. |
| `auto_unlock` | Also records the selected policy on `candidate.enrolled`. |

For example, a locked baseline or transition resembles:

```json
{"time":"2026-08-30T18:42:15.123Z","level":"INFO","msg":"FileVault pre-boot detected","schema_version":1,"component":"daemon","run_id":"6f7f35edc08a1c425cf460ffacbe5d2a","event":"device.filevault_locked","event_time":"2026-08-30T18:42:15.120Z","sequence":42,"device":"m4alpha","state":"locked","observation":"locked","lock_episode":3,"auto_unlock":true,"endpoint_down":false,"latched":false,"detail":"FileVault pre-boot banner detected"}
```

The local control API also uses a field named `schema_version`, but its API
schema and this log schema are separate versioned interfaces.

## Event and level catalog

Use `event` as the routing key. Treat `level` as record severity, not as a
complete statement of device health.

### Process lifecycle

| Event | Level | Meaning and notable fields |
| --- | --- | --- |
| `daemon.started` | `INFO` | Controller is accepting local API requests; adds `devices`, `socket`, and `data_dir`. |
| `daemon.stopped` | `INFO` | Orderly shutdown completed. |
| `daemon.failed` | `ERROR` | Controller is exiting with an error; adds `error`. |

### Device monitoring and recovery

| Event | Level | Meaning |
| --- | --- | --- |
| `device.probe` | `DEBUG` | One password-free probe completed. |
| `device.booted` | `INFO`; supplemental state record at `DEBUG` | Normal macOS SSH accepted a public key. |
| `device.filevault_locked` | `INFO`; supplemental state record at `DEBUG` | Definitive FileVault pre-boot explanation was observed. |
| `device.unreachable` | `INFO`; supplemental state record at `DEBUG` | Password-free observation could not reach the endpoint. |
| `device.indeterminate` | `INFO`; supplemental state record at `DEBUG` | SSH evidence did not prove booted macOS or FileVault pre-boot. |
| `device.observation_booted` | `INFO` | Observation became booted while a failure latch kept the visible state unchanged. |
| `device.observation_filevault_locked` | `INFO` | Observation became locked while a failure latch remained active. |
| `device.observation_unreachable` | `INFO` | Observation became unreachable while a failure latch remained active. |
| `device.observation_indeterminate` | `INFO` | Observation became indeterminate while a failure latch remained active. |
| `device.unlock_started` | `INFO` | Durable authorization marker was saved and the automatic unlock operation began. |
| `device.unlock_result` | `INFO` or `WARN` | Result was recorded; it is `WARN` when the resulting state is `credential-failed` or `error`. Inspect `state`, `latched`, and `failure_kind`. |
| `device.latch_changed` | `WARN` | A credential or host-key latch was set or cleared. Inspect `latched`; a clear is not itself a new failure. |
| `device.added` | `INFO` | An enrolled device entered the running monitor. |
| `device.unlocking` | `INFO` | State-change name reserved for an unlocking state record. `device.unlock_started` is the authoritative operation-start event. |
| `device.booting` | `INFO` | Credential was accepted or its submitted outcome was ambiguous; password-free boot verification follows. |
| `device.credential_failed` | `INFO` | Visible state became `credential-failed`; related unlock-result and latch records carry warning severity. |
| `device.error` | `INFO` | Visible state became `error`; inspect associated latch or unlock-result records rather than relying on level alone. |
| `device.latch_cleared` | `INFO` | Local API/TUI operator requested latch clearance. The monitor also emits `device.latch_changed`. |

At `debug`, a supplemental state-change record can reuse a semantic name such
as `device.booted`. Do not count incidents by `event` alone when debug logging
is enabled; use `(run_id, sequence)` and the current state.

### Discovery and candidate review

| Event | Level | Meaning |
| --- | --- | --- |
| `discovery.round` | `DEBUG` | Bonjour or active-scan round completed; adds `source` and `observations`. |
| `discovery.failed` | `WARN` | Discovery round failed; adds `source` and `error`. |
| `candidate.discovered` | `INFO` | A new SSH candidate entered the review inbox. |
| `candidate.updated` | `DEBUG` | A known candidate was observed again. |
| `candidate.evicted` | `INFO` | Inbox capacity evicted the oldest unreviewed candidate to admit a new one; adds the evicted `candidate_id`, `replacement_candidate_id`, `source`, and `observed_at`. Operator-verified, ignored, and configured candidates are never evicted. |
| `candidate.dropped` | `WARN` | Inbox capacity could not admit an unmatched observation because every entry was operator-reviewed; adds `reason`, `source`, and, when available, `observed_at`, `endpoint`, `hostname`, and `fingerprint`. No existing candidate is removed. |
| `candidate.expired` | `INFO` | An unreviewed candidate aged out. |
| `candidate.expiration_failed` | `WARN` | Candidate expiration could not be saved or completed. |
| `candidate.ignored` | `INFO` | Operator marked a candidate ignored. |
| `candidate.restored` | `INFO` | Operator returned an ignored candidate to review. |
| `candidate.enrolled` | `INFO` | Independently verified candidate was pinned and added as a device. |
| `candidate.state_update_failed` | `WARN` | Device enrollment succeeded but the candidate review state did not update. |
| `candidate.label_refresh_failed` | `WARN` | Device enrollment succeeded but configured-candidate labels did not refresh. |

## Ordering, gaps, and current-state reconciliation

`run_id` changes at every daemon start. `sequence` starts over for each monitor
run and is present only on device-monitor events. Use `(run_id, sequence)` to
order those events. Candidate and daemon lifecycle records have `run_id` but no
monitor sequence.

The monitor-to-logger subscription is bounded and non-blocking. A slow stdout
consumer cannot delay credential policy; older queued telemetry can be
dropped. A sequence gap can therefore mean a local subscription drop, a
journald or Docker retention gap, or loss farther downstream. The log itself
does not distinguish those causes.

After any gap, restart, or collector outage, reconcile against the point-in-time
device snapshot on the local Unix socket:

```bash
curl --fail --silent --show-error \
  --unix-socket /run/fv-ssh-unlock/control.sock \
  http://localhost/v1/devices | jq .
```

`GET /v1/candidates` also exposes the process-lifetime
`dropped_observations` and `evicted_candidates` counters. Use them to detect
capacity pressure even if a collector missed the individual records; they
reset when the daemon restarts and do not replace retained event detail.

The API is a local administrative interface. Do not proxy it to the SIEM or
expose it on TCP; run a same-host reconciliation job and send only the required
result through the normal collector.

## Useful alerts

Start with a small, state-aware policy:

- Page on `daemon.failed`.
- Page on `device.latch_changed` when `latched` is `true` and
  `failure_kind` is `credential` or `host-key`.
- Warn on `device.unlock_result` when `state` is `credential-failed` or
  `error`; page when it also latches or repeats beyond the retry policy.
- Warn when `device.unreachable` or `device.indeterminate` remains current
  beyond the site's recovery window. A single transition is not proof of an
  outage; confirm current state through `/v1/devices`.
- Warn on repeated `discovery.failed`, `candidate.expiration_failed`,
  `candidate.state_update_failed`, or `candidate.label_refresh_failed`.
- Warn on any `candidate.dropped`, and trend `candidate.evicted`; either can
  indicate discovery noise or a candidate-inbox capacity that is too small.
- Retain `device.unlock_started`, successful `device.unlock_result`,
  `device.booted`, `device.latch_cleared`, and candidate enrollment/review
  actions as operational audit events.

`healthcheck` proves only that the daemon's local API responds. It does not
mean every Mac is booted or reachable.

## Inspect records with jq

This filter accepts mixed JSON stdout and plain stderr, preserving non-JSON
lines instead of dropping the most useful startup error:

```bash
jq -Rrc 'fromjson? // {unparsed: .}' daemon-combined.log
```

To intentionally show only structured failure and latch events:

```bash
jq -Rrc '
  fromjson?
  | select(
      .event == "daemon.failed"
      or (.event == "device.latch_changed" and .latched == true)
      or (.event == "device.unlock_result"
          and (.state == "credential-failed" or .state == "error"))
    )
' daemon-combined.log
```

List monitor ordering keys before checking a gap:

```bash
jq -Rr '
  fromjson?
  | select(.run_id != null and .sequence != null)
  | [.run_id, .sequence, .event, .device]
  | @tsv
' daemon-combined.log
```

An absent first sequence is normal when collection began after the daemon.
Within collected records for one `run_id`, a later discontinuity requires
reconciliation; it does not by itself identify which layer lost the event.

## Collect with systemd and journald

The supplied unit leaves stdout and stderr connected to journald. Enable JSON
by replacing its complete `ExecStart` in a drop-in:

```bash
sudo systemctl edit fv-ssh-unlock.service
```

For a service using the unit's base command, enter:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/fv-ssh-unlock daemon --socket /run/fv-ssh-unlock/control.sock --log-format json --log-level info
```

If the service also uses a systemd-delivered SSH verification identity,
preserve that argument in the replacement instead:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/fv-ssh-unlock daemon --socket /run/fv-ssh-unlock/control.sock --identity %d/macos-ssh-identity --log-format json --log-level info
```

Then reload, restart, and verify the local API:

```bash
sudo systemctl daemon-reload
sudo systemctl restart fv-ssh-unlock.service
sudo systemctl --no-pager --full status fv-ssh-unlock.service
sudo -u fv-ssh-unlock \
  /usr/local/bin/fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock --json
```

Follow the application messages without journald's display envelope:

```bash
sudo journalctl -u fv-ssh-unlock.service -f -o cat
```

Inspect and tolerantly parse a bounded incident window:

```bash
sudo journalctl -u fv-ssh-unlock.service --since '-30 minutes' -o cat \
  | jq -Rrc 'fromjson? // {unparsed: .}'
```

For a forwarding agent, use journald's native records rather than a process
that follows `journalctl`. Filter `_SYSTEMD_UNIT=fv-ssh-unlock.service`, parse
the `MESSAGE` field as application JSON when possible, and keep the original
journal record when parsing fails.

journald retention settings such as `SystemMaxUse=` and `MaxRetentionSec=` are
host-wide, not per unit. Review the needs of every service before changing
them. A bounded example for a dedicated controller host is:

```ini
# /etc/systemd/journald.conf.d/retention.conf
[Journal]
SystemMaxUse=512M
MaxRetentionSec=30day
```

Apply a reviewed change with `sudo systemctl restart systemd-journald`.

## Collect with Docker

Add JSON logging flags to the complete service command. Preserve its socket
and verification-identity arguments:

```yaml
services:
  fv-ssh-unlock:
    command:
      - daemon
      - --socket
      - /run/fv-ssh-unlock/control.sock
      - --identity
      - /run/secrets/macos-ssh-identity
      - --log-format
      - json
      - --log-level
      - info
    logging:
      driver: local
      options:
        max-size: "10m"
        max-file: "5"
```

The `local` driver keeps `docker logs` support while adding bounded local
retention. If the site requires a different logging driver, configure its
buffering, TLS, failure, and retention behavior explicitly.

After recreating the service, verify health and inspect a bounded window:

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs \
  --since 30m --no-color --no-log-prefix fv-ssh-unlock \
  | jq -Rrc 'fromjson? // {unparsed: .}'
```

Docker retains stdout/stderr stream metadata internally, although its combined
CLI output can contain both application JSON and plain errors. A host collector
should consume the Docker API or selected logging driver, filter the controller
container, attempt JSON parsing on its message field, and preserve the original
record on failure.

Do not install a collector, shell, CA bundle, or exporter inside the scratch
controller image. A platform-mandated sidecar must remain a separate container
with its own image, credentials, network policy, and lifecycle.

## Forward with Fluent Bit or Vector

Run the collector on the host or in the site's existing logging tier. Start
with a console output and synthetic JSON plus plain-text input; add the remote
SIEM sink only after both record forms survive parsing.

For Fluent Bit reading journald, the important pieces are a unit filter, a JSON
parser for `MESSAGE`, and preservation of the journal envelope:

```ini
# parsers.conf
[PARSER]
    Name   fv_ssh_unlock_json
    Format json

# fluent-bit.conf
[SERVICE]
    Parsers_File parsers.conf

[INPUT]
    Name            systemd
    Tag             fv_ssh_unlock
    Systemd_Filter  _SYSTEMD_UNIT=fv-ssh-unlock.service
    Read_From_Tail  On
    Strip_Underscores On

[FILTER]
    Name          parser
    Match         fv_ssh_unlock
    Key_Name      MESSAGE
    Parser        fv_ssh_unlock_json
    Reserve_Data  On
    Preserve_Key  On

[OUTPUT]
    Name  stdout
    Match fv_ssh_unlock
```

Confirm the installed Fluent Bit version leaves a record intact when parsing
plain stderr fails. For Docker input, select only the controller's records and
apply the same parser to the runtime's `log` or message field. Container-file
paths and metadata filters vary by Docker logging driver, so use the driver's
supported input instead of granting an agent broad filesystem access merely to
copy a generic example.

A minimal Vector journald preview keeps parsed application data nested so it
cannot overwrite the journal envelope:

```toml
[sources.fv_ssh_unlock]
type = "journald"
include_units = ["fv-ssh-unlock.service"]

[transforms.parse_fv_ssh_unlock]
type = "remap"
inputs = ["fv_ssh_unlock"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  .fv_ssh_unlock = parsed
} else {
  .fv_ssh_unlock_unparsed = .message
}
'''

[sinks.preview]
type = "console"
inputs = ["parse_fv_ssh_unlock"]
encoding.codec = "json"
```

For Docker, replace the journald source with Vector's `docker_logs` source and
restrict it to the controller container or its Compose labels; the transform
still parses `.message`. Collector configuration evolves independently of this
program, so validate these snippets with the deployed Fluent Bit or Vector
version before enabling a remote sink. Configure that sink's TLS trust,
authentication, queue limits, retry policy, and tenant/index at the collector,
not in `fv-ssh-unlock`.

## Retention and delivery guarantees

An orderly daemon shutdown stops device work, drains monitor events already
queued for its logger, emits `daemon.stopped`, and exits. The subscription and
stdout stream are still best-effort rather than a compliance ledger. Process
termination, host loss, full storage, supervisor rotation, collector backpressure,
or network failure can lose records.

Use a local journal or bounded Docker log as the first durable hop, monitor its
capacity, and forward from there. Alert on collector health and monitor sequence
gaps. Keep enough local history to reconcile a SIEM outage, and use `/v1/devices`
for current state rather than replaying logs as the sole source of truth.

## Security and privacy

The event stream excludes credential values, authentication answers,
environment-variable values, SSH private-key bodies, raw SSH/FileVault
banners, and control-API request bodies, including at `debug`. Tests use
sentinel values to enforce this boundary.

Logs still reveal device aliases, endpoints, candidate hostnames, controller
paths, state transitions, timestamps, and sanitized errors. The local API also
contains credential references and SSH fingerprints. Treat all of that as
sensitive infrastructure metadata. Restrict journal, Docker, collector, and
SIEM access; encrypt forwarding; set a deliberate retention period; and redact
records before sharing them publicly.

Untrusted carriage returns, line feeds, and other control characters are
rendered visibly rather than being allowed to forge a physical record. Keep
tolerant parsing anyway because stderr is intentionally a separate human-text
interface.

## Troubleshoot collection

First establish whether the controller and its local API are healthy:

```bash
fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock --json --timeout 5s
fv-ssh-unlock tui \
  --socket /run/fv-ssh-unlock/control.sock --json
```

For systemd, inspect the effective command before starting a competing daemon:

```bash
sudo systemctl cat fv-ssh-unlock.service
sudo systemctl --no-pager --full status fv-ssh-unlock.service
sudo journalctl -u fv-ssh-unlock.service --since '-30 minutes' -o cat
```

For Docker:

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs \
  --since 30m --no-color --no-log-prefix fv-ssh-unlock
```

If JSON parsing fails, check whether the line is expected stderr, confirm the
effective command contains `--log-format json`, and verify the collector is
parsing the message field rather than journald's or Docker's outer envelope.
If events stop but health remains good, inspect local retention, collector
backpressure, and sequence continuity, then reconcile `/v1/devices`.

---

[Documentation home](index.md) | [Persistent controller and TUI](daemon-and-tui.md) | [Containers and services](containers-and-services.md) | [Infrastructure automation](automation.md)

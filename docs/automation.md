# Infrastructure automation

Automation should consume versioned JSON or the local v1 API, never scrape the
human table or TUI. The default socket is `control.sock` inside the effective
data directory; the supplied systemd and container deployments select
`/run/fv-ssh-unlock/control.sock`. The daemon does not open a TCP port.

## Stable read interfaces

```bash
# With no names, status checks every configured device.
fv-ssh-unlock status --json

curl --unix-socket /run/fv-ssh-unlock/control.sock http://localhost/v1/health
curl --unix-socket /run/fv-ssh-unlock/control.sock http://localhost/v1/devices
curl --unix-socket /run/fv-ssh-unlock/control.sock http://localhost/v1/candidates
```

The binary's `healthcheck --socket ...` command provides the health request
without adding `curl` to the container image.

The API is intended for same-host callers protected by Unix ownership and mode
bits. A reverse proxy turns local authorization into a network security
problem and is not part of the recommended deployment.

## Event and SIEM integration

Use the local v1 API for point-in-time state and the daemon's JSON log stream
for transition-oriented collection:

```bash
fv-ssh-unlock daemon --log-format json --log-level info
```

Each line contains the stable `time`, `level`, `msg`, `schema_version`,
`component`, and per-process `run_id` envelope. Semantic records include
`event`; applicable fields include `event_time`, `sequence`, `device`, `state`,
`observation`, `lock_episode`, `latched`, `failure_kind`, `detail`,
`candidate_id`, `source`, and `endpoint`. Build filters and alerts around the
versioned `event` and state fields instead of parsing `msg`. A monitor
`sequence` is useful for ordering within one daemon process but is not globally
unique and resets on each run. The monitor subscription is non-blocking and
best-effort; sequence gaps mean local telemetry was dropped so monitoring work
could continue. Use `run_id` plus `sequence` for correlation and reconcile a
gap against `/v1/devices`.

The sane `info` default emits state changes, unlock actions, safety latches,
candidate detections, and process lifecycle without one event for every normal
poll. It also emits each device's first conclusive observation after startup as
a per-run baseline. Use `debug` for temporary per-probe and discovery-round diagnosis;
long-running debug collection can be noisy. `warn` and `error` intentionally
omit ordinary healthy transitions.

Collect standard output and standard error through journald, a Docker logging
driver, or a host-level Fluent Bit/Vector agent. The daemon has no network log
sink, so a SIEM outage cannot block its recovery loop and the scratch image
does not need a bundled sidecar. Apply retention, transport encryption, and
access policy in the collector. Logs exclude credentials, private-key bodies,
authentication answers, API request bodies, and raw SSH/FileVault banners, but
device names, endpoints, candidate hostnames, and states remain sensitive
operational metadata.

An orderly daemon shutdown drains its queued monitor events, but the stdout
stream is not a guaranteed audit ledger. Durable or compliance retention
requires an external journal/SIEM collector; current device state remains
available from the local versioned API.

## Ansible

The example in `contrib/ansible` installs the binary and hardened systemd unit,
then retrieves JSON status without reporting a change. Inventory contains
hostnames and credential *references*, never FileVault passwords or private
keys.

```bash
ansible-playbook -i contrib/ansible/inventory.example.yml \
  contrib/ansible/controller.yml
```

Ansible can query the Unix API directly with `ansible.builtin.uri` and its
`unix_socket` parameter. Use `changed_when: false` for health/status checks and
`no_log: true` for any task that delivers secret material.

Use the implemented declarative command for idempotent, non-secret
configuration:

```bash
fv-ssh-unlock config apply --file devices.json --check --json
fv-ssh-unlock config apply --file devices.json --json
```

The document is a strict JSON array using the fields documented in
[Configuration and credentials](configuration-and-credentials.md#declarative-configuration).
It accepts credential references but has no credential-value field. Restart the
daemon only when the result reports `changed: true`; enrollment through the
daemon API is applied live.

## Recovery orchestration

A controller should remain responsible only for recognizing FileVault,
unlocking once under policy, and proving normal macOS SSH has returned. Ansible,
AWX, Rundeck, or another system can wait for `state == "booted"` and then apply
the workload's desired state. They should not receive the FileVault password.

For larger installations, place one controller inside each trusted site or
rack and export status/events to the central system. Keep raw credentials at
the site controller, use bounded unlock concurrency, and add jitter after a
site-wide power restoration.

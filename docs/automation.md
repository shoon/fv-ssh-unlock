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

The JSON daemon stream on stdout and the local API are complementary. Only
device-monitor records have a per-run `sequence`; lifecycle, discovery, and
candidate-action records do not. A gap can result from the bounded local
subscription or any downstream collector, so reconcile it against
`GET /v1/devices`. Command and final errors remain plain text on stderr and
must survive a tolerant collector parser.

Use [Logging and SIEM collection](logging-and-siem.md) as the canonical field
and event contract. It includes the exact event/level matrix, alert examples,
journald and Docker retention, mixed-stream `jq` filters, and external Fluent
Bit and Vector patterns. The daemon intentionally has no network log exporter.

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

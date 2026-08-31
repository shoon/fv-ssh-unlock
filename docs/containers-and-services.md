# Containers and persistent services

The controller is a foreground process. Run it under systemd or Docker so it
keeps monitoring when the terminal or TUI disconnects. The TUI is a client of
the local Unix socket; exiting it does not stop the daemon.

## Minimal image

The production `Dockerfile` is a multi-stage build whose final stage is
`FROM scratch`. Its filesystem payload is the statically linked
`/fv-ssh-unlock` binary plus required license/notice text: no shell, package
manager, libc, CA bundle, or OS packages are present. It runs as numeric
UID/GID `65532`, defaults to the daemon command, and contains an internal health
check rather than `curl`.

The container deliberately omits the desktop keyring build tag and its D-Bus
integration. Use a Linux service secret under `/run/secrets`; run the native
keyring-enabled binary when macOS or Windows credential-store integration is
required.

Build and inspect it from a source checkout:

```bash
docker build --tag fv-ssh-unlock:test .
./hack/verify-container-image.sh fv-ssh-unlock:test
docker image history fv-ssh-unlock:test
```

The verification script asserts the non-root identity, single filesystem
layer, entrypoint, command, health check, shell absence, read-only operation,
disabled networking, and capability-free operation. The SBOM will still list
the Go application and its embedded modules; “zero OS packages” must not be
misrepresented as “zero software components.”

The release workflow builds `linux/amd64` and `linux/arm64`, attaches SPDX SBOM
and maximal provenance attestations, and signs the resulting digest with
keyless Sigstore. Publishing is manual, requires an explicit non-`latest` tag,
and requires `DOCKERHUB_USERNAME` plus a narrowly scoped `DOCKERHUB_TOKEN` in
GitHub Actions. Create `shoonimages/fv-ssh-unlock` as a private Docker Hub
repository before the first run. Changing repository visibility is a separate
Docker Hub operation and is not performed by the workflow.

Keyless Sigstore signing is publicly auditable: it does not make private image
layers public, but the signing identity and artifact digest are recorded in the
transparency system. Review that metadata boundary before publishing a private
candidate. See Sigstore's [keyless signing
overview](https://docs.sigstore.dev/cosign/signing/overview/).

## Runtime filesystem

The image never contains passwords, SSH private keys, device configuration, or
pinned host keys. Its runtime mounts are:

| Path | Purpose | Mount |
| --- | --- | --- |
| `/data` | Device configuration, pinned keys, candidate inbox, and durable retry state. | Persistent, writable, owned by 65532. |
| `/run/fv-ssh-unlock` | Local control socket. | Small writable tmpfs owned by 65532. |
| `/run/secrets` | Passwords and a dedicated macOS verification key. | Read-only service secret mount. |

Run the root filesystem read-only, drop every Linux capability, set
`no-new-privileges`, and do not publish a network port. Administrators reach
the API and TUI through the permission-restricted Unix socket.

## Service logs

Keep log collection outside the minimal controller image. Add
`--log-format json --log-level info` to the daemon arguments when a structured
pipeline is desired. The daemon writes one event per line to standard output
and writes command/startup errors to standard error; it does not create log
files or connect to a remote collector.

The supplied systemd unit leaves both streams connected to journald. Inspect
them locally with:

```bash
journalctl -u fv-ssh-unlock -f -o cat
```

When enabling JSON in a systemd drop-in, preserve every existing `ExecStart`
argument, including the control socket and any dedicated verification
identity, and append the two logging flags.

Docker and Swarm capture the same standard streams through the host's selected
logging driver. For example, the Compose service can be inspected with:

```bash
docker compose -f deploy/docker-compose.yml logs -f fv-ssh-unlock
```

Configure retention and remote delivery in Docker or on the host. Fluent Bit
and Vector can read the Docker stream or journald and parse JSON records before
forwarding them to a SIEM. If a sidecar is required by the platform, deploy it
as a separate collector container; do not add a shell, agent, certificates, or
network exporter to the scratch controller image.

The daemon's non-blocking event subscription and stdout stream are best-effort,
not a durable compliance ledger. A normal shutdown drains queued monitor
events, but reliable retention still belongs in journald, the Docker logging
driver, or the external SIEM pipeline. Monitor sequence gaps and reconcile
with a local API snapshot.

Logs contain device and network metadata but never credential values, private
key bodies, authentication answers, or raw SSH/FileVault banners. Treat the
metadata as sensitive and restrict access to the journal and container logs.

## Docker Swarm

Swarm secrets are the recommended Docker credential mechanism. Create a
single-purpose SSH key and one password secret per Mac without putting either
value in a Compose file:

```bash
systemd-ask-password "FileVault password for m4alpha:" | \
  docker secret create m4alpha-password -
docker secret create macos-ssh-identity /secure/input/path
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/fv-ssh-unlock
docker node update --label-add fv-ssh-unlock-controller=true self

FV_SSH_UNLOCK_IMAGE='shoonimages/fv-ssh-unlock@sha256:REPLACE_WITH_DIGEST' \
  docker stack deploy --compose-file deploy/docker-stack.yml fv
```

The first command obtains the password without terminal echo and passes it on
standard input. A password-manager CLI can be used the same way. Avoid putting
the value in a command argument, environment variable, or shell history. The
stack grants the container UID
read-only `0400` access to each secret. Configure the target with
`/run/secrets/m4alpha-password` as its file credential reference.

Swarm secrets are mounted in memory on Linux. The credential provider verifies
either a memory-backed `/run/secrets` directory or an individually mounted
memory-backed secret file before treating it as secure. It therefore fails
closed if a disk-backed file is merely placed at the same path.

Individual file mounts are how the tested Docker Desktop Swarm exposes
secrets, and they pass the provider check. Run `fv-ssh-unlock credentials
providers --require-secure` inside the exact service task because its result
remains authoritative across Docker versions and platforms. Use a native
Linux controller if a different implementation fails closed.

The stack pins its bind-mounted configuration and durable attempt state to the
explicitly labeled node. On a multi-node Swarm, apply the label to exactly the
controller node whose `/var/lib/fv-ssh-unlock` directory you prepared.

## Standalone Compose

`deploy/docker-compose.yml` is a hardened standalone example. Compose
file-backed secrets do not encrypt the source file on the host, so the example
does not declare them. Instead, `FV_SSH_UNLOCK_SECRET_DIR` must name a
secret-agent directory already backed by `tmpfs`/`ramfs` on a native Linux
Docker host, accessible to UID 65532. It must also contain the dedicated
unencrypted verification key as
`macos-ssh-identity`; the example passes that file explicitly with
`--identity`. Verify the deployment from inside its actual service environment:

```bash
docker compose -f deploy/docker-compose.yml run --rm \
  fv-ssh-unlock credentials providers --require-secure
```

An ordinary bind-mounted password file is intentionally rejected. Do not add
`--allow-unsafe-credential-storage` to a persistent service merely to make a
deployment start.

Docker Desktop bind mounts on macOS and Windows are not reported to the Linux
container as a native `tmpfs`/`ramfs` credential filesystem and therefore fail
this secure-delivery check. Prefer the native keyring-enabled binary there, or
use a secret manager whose Linux-side mount satisfies the check.

Registered numeric IP addresses work through ordinary outbound container
networking. Bonjour/mDNS discovery normally needs host networking on Linux;
enable it only when discovery is required and accept the broader network
boundary explicitly.

## Native systemd

For a Raspberry Pi, the simplest and strongest default is the native unit in
`deploy/systemd/fv-ssh-unlock.service`. Install the static binary, create its
service account, copy the unit, and add one `LoadCredentialEncrypted=` line per
`systemd:<name>` credential reference. The service uses systemd-managed state
and runtime directories and a restrictive sandbox.

Review every hardening directive on the target distribution: older Raspberry
Pi OS/systemd releases may not implement all of them. Do not silently delete a
hardening setting; document any compatibility exception.

The FileVault credential can use `systemd:<name>`, which resolves inside the
unit's memory-backed credential directory. Deliver a dedicated macOS SSH
verification key as another encrypted systemd credential and add a drop-in
that passes its runtime path without writing the cleartext key into the unit:

```ini
[Service]
LoadCredentialEncrypted=macos-ssh-identity:/etc/credstore.encrypted/macos-ssh-identity.cred
ExecStart=
ExecStart=/usr/local/bin/fv-ssh-unlock daemon --socket /run/fv-ssh-unlock/control.sock --identity %d/macos-ssh-identity
```

`%d` is systemd's credential-directory specifier. The SSH identity proves that
normal macOS is booted; it is not sent to the FileVault password prompt.

## Local operator access

With either deployment, point the full CLI at the daemon socket:

```bash
fv-ssh-unlock healthcheck --socket /run/fv-ssh-unlock/control.sock
fv-ssh-unlock tui --socket /run/fv-ssh-unlock/control.sock
```

The supplied Compose deployment keeps the socket in a private tmpfs. Run the
dashboard inside that same container:

```bash
docker compose -f deploy/docker-compose.yml exec fv-ssh-unlock \
  /fv-ssh-unlock tui --socket /run/fv-ssh-unlock/control.sock
```

Sharing the socket with a host CLI requires replacing the private tmpfs with a
deliberate bind mount whose directory is owned by UID 65532. Never expose the
Unix-socket API directly on an unauthenticated TCP port.

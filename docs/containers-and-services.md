# Containers and persistent services

The controller is a foreground process. Run it under systemd or Docker so it
keeps monitoring when the terminal or TUI disconnects. The TUI is a client of
the local Unix socket; exiting it does not stop the daemon.

Choose the deployment whose credential delivery matches the host:

| Host | Recommended deployment | Credential protection |
| --- | --- | --- |
| Raspberry Pi or native Linux | systemd unit | `LoadCredentialEncrypted=` and the systemd credential directory |
| Linux Docker host | Single-node or managed Swarm | Docker Swarm secrets |
| Linux host with an existing secret agent | Standalone Compose | Agent-populated `tmpfs`/`ramfs` directory |
| macOS or Windows desktop | Native release binary | OS keyring |

Compose file-backed secrets and ordinary bind-mounted files remain plaintext
on the host. They are not a substitute for Swarm secrets or systemd
credentials, and the persistent daemon refuses them.

## Public minimal image

The public image is
[`shoonimages/fv-ssh-unlock`](https://hub.docker.com/r/shoonimages/fv-ssh-unlock).
Release tags such as `v0.2.0-rc.1` are available for `linux/amd64` and
`linux/arm64`. There is no 32-bit ARM/ARMv7 image and no `latest` tag. A
Raspberry Pi must run a 64-bit OS:

```bash
uname -m
docker info --format '{{.Architecture}}'
```

Expect `aarch64` from `uname` and `aarch64` or `arm64` from Docker. A Pi running
a 32-bit operating system will report that no matching image manifest exists.

The production `Dockerfile` is a multi-stage build whose final stage is
`FROM scratch`. Its filesystem payload is the statically linked
`/fv-ssh-unlock` binary plus required license and notice text: no shell,
package manager, libc, CA bundle, or OS packages are present. It runs as
numeric UID/GID `65532`, defaults to the daemon command, and uses the binary's
internal health check rather than `curl`.

The image deliberately omits the desktop keyring build tag and its D-Bus
integration. Use a Linux service secret under `/run/secrets`; use the native
keyring-enabled binary for macOS or Windows credential-store integration.

### Pull, verify, and pin a release

Use the exact release tag you intend to deploy. A tag is convenient but can be
changed if registry policy is disabled or bypassed; the repository currently
protects `v*` tags with Docker Hub's immutable-tag policy. The resolved digest
remains the deployment identity you can verify independently of registry
settings.

```bash
IMAGE=shoonimages/fv-ssh-unlock
TAG=v0.2.0-rc.1

DIGEST="$(docker buildx imagetools inspect "$IMAGE:$TAG" \
  --format '{{.Manifest.Digest}}')"
PINNED_IMAGE="$IMAGE@$DIGEST"
printf 'Verified image pin: %s\n' "$PINNED_IMAGE"
```

Install Cosign, then verify that GitHub Actions signed that exact multi-platform
digest from the matching tag ref:

```bash
cosign verify \
  --certificate-identity "https://github.com/shoon/fv-ssh-unlock/.github/workflows/container.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$PINNED_IMAGE"

docker pull "$PINNED_IMAGE"
```

Do not deploy if signature verification fails. The Sigstore bundle for
`checksums.txt` on GitHub Releases authenticates the native release archives;
it does not authenticate the separately published container image.

The signed index contains two runnable manifests and an attestation manifest
for each one. Inspect the index, SPDX SBOM, and maximal BuildKit provenance:

```bash
docker buildx imagetools inspect "$PINNED_IMAGE" \
  --format '{{json .Manifest}}' | jq -e '
    ([.manifests[]
      | select(.platform.os == "linux")
      | .platform.architecture] | sort) == ["amd64", "arm64"]
    and
    ([.manifests[]
      | select(.annotations["vnd.docker.reference.type"]
        == "attestation-manifest")] | length) == 2
  '

docker buildx imagetools inspect "$PINNED_IMAGE" \
  --format '{{json (index .SBOM "linux/arm64").SPDX}}' | \
  jq -e '.spdxVersion != null and (.packages | length > 0)'

docker buildx imagetools inspect "$PINNED_IMAGE" \
  --format '{{json (index .Provenance "linux/arm64").SLSA}}' | \
  jq -e '.buildDefinition.buildType != null and .runDetails.builder != null'
```

Repeat the last two commands with `linux/amd64` when auditing that platform.
Keyless signing is publicly auditable: the signing identity and artifact
digest are recorded in Sigstore's transparency system.

Use deployment files from the same Git tag as the image. They are included in
the signed release archives, or can be obtained from a matching source
checkout:

```bash
git clone --branch "$TAG" --depth 1 \
  https://github.com/shoon/fv-ssh-unlock.git
cd fv-ssh-unlock
```

### Build and inspect locally

Maintainers and source-build users can run the same runtime-contract verifier:

```bash
docker build --tag fv-ssh-unlock:test .
./hack/verify-container-image.sh fv-ssh-unlock:test
docker image history fv-ssh-unlock:test
```

The verifier asserts the non-root identity, single filesystem layer,
entrypoint, command, health check, shell absence, read-only operation, disabled
networking, and capability-free operation. The SBOM still lists the Go
application and embedded modules; "zero OS packages" does not mean "zero
software components."

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

Use a dedicated, unencrypted SSH key for password-free proof that normal macOS
has booted. Authorize only its public half on the managed Macs. The private half
must be delivered as a service secret; it is never sent to the FileVault
password prompt.

## Docker Swarm

Swarm secrets are the recommended Docker credential mechanism. The following
single-node flow also works as the controller node of a larger Swarm.

### Prepare the node and secrets

Initialize Swarm only if this host is not already a member:

```bash
docker info --format '{{.Swarm.LocalNodeState}}'
docker swarm init
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/fv-ssh-unlock
docker node update --label-add fv-ssh-unlock-controller=true self
```

Create a dedicated SSH key, authorize its `.pub` half for normal macOS SSH, and
place the private half in a secure temporary input path. Then create one
password secret per Mac and the verification-key secret without putting either
value in the stack file, an environment variable, or shell history:

```bash
ssh-keygen -t ed25519 -N '' -f /secure/input/path/macos-ssh-identity
ssh-copy-id -i /secure/input/path/macos-ssh-identity.pub \
  unlockuser@192.0.2.10

systemd-ask-password "FileVault password for m4alpha:" | \
  docker secret create m4alpha-password -
docker secret create macos-ssh-identity \
  /secure/input/path/macos-ssh-identity
```

Protect or remove the temporary private-key input after the Swarm secret is
created. A password-manager CLI can replace `systemd-ask-password`; it must
write only the intended password and a normal line ending.

The supplied stack names one example target `m4alpha`. Rename its password
secret and add another `0400`, UID/GID `65532` secret entry for every managed
Mac.

### Deploy and configure the first Mac

Export the digest verified earlier. The explicit shell check is required
because `docker stack` uses a legacy Compose interpolator:

```bash
export FV_SSH_UNLOCK_IMAGE="$PINNED_IMAGE"
: "${FV_SSH_UNLOCK_IMAGE:?set a verified digest-pinned image}"
docker stack config --compose-file deploy/docker-stack.yml >/dev/null
docker stack deploy --compose-file deploy/docker-stack.yml fv
docker stack services fv
docker service ps fv_controller
```

Find the task container and verify secure credential delivery inside the exact
service environment:

```bash
CONTROLLER_ID="$(docker ps \
  --filter label=com.docker.swarm.service.name=fv_controller \
  --format '{{.ID}}' | head -n 1)"
test -n "$CONTROLLER_ID"

docker exec "$CONTROLLER_ID" /fv-ssh-unlock \
  credentials providers --require-secure
```

Add the device to the persistent data volume and authorize automatic unlock:

```bash
docker exec "$CONTROLLER_ID" /fv-ssh-unlock config add m4alpha \
  --host 192.0.2.10 \
  --user unlockuser \
  --credential-source file \
  --credential-file /run/secrets/m4alpha-password \
  --auto-unlock
```

Record the target's Ed25519 host-key fingerprint directly on the Mac, compare
it with the fingerprint reported by this next command, and only then accept it:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

docker exec "$CONTROLLER_ID" /fv-ssh-unlock status m4alpha \
  --accept-new-host-key \
  --identity /run/secrets/macos-ssh-identity
```

Restart the daemon after configuration written by a separate CLI process:

```bash
docker service update --force fv_controller
```

### Operate, update, and rotate

```bash
docker service logs --follow fv_controller
docker service ps fv_controller

CONTROLLER_ID="$(docker ps \
  --filter label=com.docker.swarm.service.name=fv_controller \
  --format '{{.ID}}' | head -n 1)"
docker exec "$CONTROLLER_ID" /fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock
docker exec -it "$CONTROLLER_ID" /fv-ssh-unlock tui \
  --socket /run/fv-ssh-unlock/control.sock
```

For an upgrade, resolve and verify the new release tag, assign its new digest
to `FV_SSH_UNLOCK_IMAGE`, and run `docker stack deploy` again. Never replace a
verified digest merely because a mutable tag changed.

Swarm secrets are immutable. To rotate a password, create a new versioned
secret such as `m4alpha-password-v2`, update both the service secret target and
the device's `/run/secrets/...` reference, redeploy, verify the new task, and
only then remove the old secret.

Swarm mounts secrets in memory on Linux. The provider verifies either a
memory-backed `/run/secrets` directory or an individually mounted memory-backed
secret file before treating it as secure. It fails closed if a disk-backed file
is merely placed at the same path. Run `credentials providers
--require-secure` after Docker upgrades because the observed mount remains
authoritative.

The stack pins its bind-mounted state and durable attempt markers to the
explicitly labeled node. In a multi-node Swarm, label exactly the controller
node whose `/var/lib/fv-ssh-unlock` directory was prepared. The example stops
retrying after ten consecutive startup failures; inspect `docker service ps`
and correct the underlying configuration before forcing a new update.

## Standalone Compose

`deploy/docker-compose.yml` is a hardened standalone example for a native
Linux Docker host that already has a secret agent. Compose file-backed secrets
do not encrypt their host files, so the example intentionally does not declare
them.

`FV_SSH_UNLOCK_SECRET_DIR` must name a directory populated by the secret agent
on `tmpfs` or `ramfs`, readable by UID 65532. It must contain
`macos-ssh-identity` plus one password file per configured Mac. The agent must
repopulate this volatile directory before Docker starts after a reboot.

### Prepare and configure

```bash
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/fv-ssh-unlock

export FV_SSH_UNLOCK_IMAGE="$PINNED_IMAGE"
export FV_SSH_UNLOCK_DATA_DIR=/var/lib/fv-ssh-unlock
export FV_SSH_UNLOCK_SECRET_DIR=/run/fv-ssh-unlock-secrets

findmnt --noheadings --output FSTYPE --target "$FV_SSH_UNLOCK_SECRET_DIR"
docker compose -f deploy/docker-compose.yml config --quiet
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml run --rm fv-ssh-unlock \
  credentials providers --require-secure
```

The provider report, not the directory name alone, determines whether delivery
is secure. Add and enroll the target through one-shot containers sharing the
same persistent data and service secrets:

```bash
docker compose -f deploy/docker-compose.yml run --rm fv-ssh-unlock \
  config add m4alpha \
  --host 192.0.2.10 \
  --user unlockuser \
  --credential-source file \
  --credential-file /run/secrets/m4alpha-password \
  --auto-unlock

docker compose -f deploy/docker-compose.yml run --rm fv-ssh-unlock \
  status m4alpha \
  --accept-new-host-key \
  --identity /run/secrets/macos-ssh-identity
```

Compare the reported host key with the fingerprint obtained directly from the
target Mac before accepting it.

### Start, operate, and update

```bash
docker compose -f deploy/docker-compose.yml up --detach
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs --follow fv-ssh-unlock

docker compose -f deploy/docker-compose.yml exec fv-ssh-unlock \
  /fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock
docker compose -f deploy/docker-compose.yml exec fv-ssh-unlock \
  /fv-ssh-unlock tui \
  --socket /run/fv-ssh-unlock/control.sock
```

To upgrade, verify a new tag and digest, update `FV_SSH_UNLOCK_IMAGE`, then run:

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up --detach
docker compose -f deploy/docker-compose.yml ps
```

An ordinary bind-mounted password file is intentionally rejected. Do not add
`--allow-unsafe-credential-storage` to a persistent service merely to make it
start. Docker Desktop bind mounts on macOS and Windows are not reported to the
Linux container as native `tmpfs`/`ramfs` credential files and fail the secure
delivery check. Prefer the native keyring-enabled binary there.

Registered numeric IP addresses work through ordinary outbound bridge
networking. Bonjour/mDNS discovery normally needs host networking on Linux. If
discovery is required, review and accept that broader network boundary and add
an override file:

```yaml
services:
  fv-ssh-unlock:
    network_mode: host
```

Start Compose with both `--file deploy/docker-compose.yml` and `--file` pointing
to that override. No TCP control port needs to be published.

## Native systemd

For a Raspberry Pi, the simplest recommended deployment is the native unit in
`deploy/systemd/fv-ssh-unlock.service`. The service uses systemd-managed state
and runtime directories and a restrictive sandbox, without requiring a
container runtime.

### Install the service

Use the Linux ARM64 archive on a 64-bit Raspberry Pi OS installation. From the
matching extracted release directory:

```bash
getent passwd fv-ssh-unlock >/dev/null || \
  sudo useradd --system --home-dir /var/lib/fv-ssh-unlock \
    --shell /usr/sbin/nologin fv-ssh-unlock

sudo install -o root -g root -m 0755 fv-ssh-unlock \
  /usr/local/bin/fv-ssh-unlock
sudo install -o root -g root -m 0644 \
  deploy/systemd/fv-ssh-unlock.service \
  /etc/systemd/system/fv-ssh-unlock.service
sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
```

Review every hardening directive on the target distribution: older Raspberry
Pi OS/systemd releases may not implement all of them. Do not silently delete a
hardening setting; document each compatibility exception.

### Encrypt and attach credentials

Create a dedicated, unencrypted SSH key, authorize only its public half on the
Macs, and encrypt its private half for this service. Create one separately
named FileVault credential per Mac:

```bash
umask 077
ssh-keygen -t ed25519 -N '' -f ./macos-ssh-identity
ssh-copy-id -i ./macos-ssh-identity.pub unlockuser@192.0.2.10

sudo -v
systemd-ask-password 'FileVault password for m4alpha:' | \
  sudo systemd-creds encrypt --name=m4alpha - \
    /etc/credstore.encrypted/m4alpha.cred
sudo systemd-creds encrypt --name=macos-ssh-identity \
  ./macos-ssh-identity \
  /etc/credstore.encrypted/macos-ssh-identity.cred
```

Protect or remove the temporary cleartext private key after independently
confirming that the encrypted credential can start the service. Repeat the
password command with a distinct credential name for each Mac.

`systemd-creds` uses TPM2 when the host and systemd build support it and can
otherwise protect the encrypted blob with the systemd host key. A typical
Raspberry Pi has no TPM, so this does not create hardware-backed storage by
itself. It still avoids a cleartext password file and delivers the decrypted
value to the service in a protected runtime credential directory. Protect the
controller's root account and boot chain; add a supported TPM2 device or
encrypted host storage when the threat model requires hardware-backed data at
rest.

Create a service drop-in with one `LoadCredentialEncrypted=` line per
`systemd:<name>` device reference. Preserve the complete `ExecStart` while
adding the verification key and structured service logging:

```ini
[Service]
LoadCredentialEncrypted=m4alpha:/etc/credstore.encrypted/m4alpha.cred
LoadCredentialEncrypted=macos-ssh-identity:/etc/credstore.encrypted/macos-ssh-identity.cred
ExecStart=
ExecStart=/usr/local/bin/fv-ssh-unlock daemon --socket /run/fv-ssh-unlock/control.sock --identity %d/macos-ssh-identity --log-format json --log-level info
```

`%d` is systemd's credential-directory specifier. The SSH identity proves that
normal macOS is booted; it is not sent to the FileVault password prompt.

Save that drop-in with `sudo systemctl edit fv-ssh-unlock.service`. Then add
and pin devices under the service account exactly as shown in the [homelab
power-outage workflow](use-cases.md#keep-homelab-macs-available-after-a-power-outage).

### Start and operate

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fv-ssh-unlock.service
sudo systemctl --no-pager --full status fv-ssh-unlock.service

sudo -u fv-ssh-unlock /usr/local/bin/fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock --json
sudo -u fv-ssh-unlock /usr/local/bin/fv-ssh-unlock tui \
  --socket /run/fv-ssh-unlock/control.sock
```

The runtime directory is mode `0700` and its socket is mode `0600`, so run the
operator clients as `fv-ssh-unlock`; an ordinary login user is intentionally
denied. Follow startup and recovery events with `sudo journalctl -u
fv-ssh-unlock.service -f -o cat`.

To upgrade, verify the new native release, stop the unit, replace only the
binary, and start it again. Keep the previous verified binary available for
rollback and do not delete `/var/lib/fv-ssh-unlock`: it contains the pinned
keys and durable one-attempt safety state.

## Service logs

Keep log collection outside the minimal controller image. Add
`--log-format json --log-level info` to the daemon arguments for structured
logs. The daemon writes events to standard output and startup errors to
standard error; it does not create log files or connect to a remote collector.

The systemd unit leaves both streams connected to journald:

```bash
journalctl -u fv-ssh-unlock -f -o cat
```

Docker and Swarm capture the same streams through the host logging driver.
The supplied Compose and stack files use Docker's `local` driver with a
10 MiB, five-file rotation limit per task so an unattended controller cannot
grow its local log without bound. Change those limits deliberately to match
the site's incident window and storage budget.
Fluent Bit or Vector can read those streams as a separate collector; do not add
a shell, agent, certificates, or network exporter to the scratch controller
image.

Logs contain device and network metadata but never credential values, private
key bodies, authentication answers, or raw SSH/FileVault banners. Treat the
metadata as sensitive and restrict access to the journal and container logs.

## Local operator access

The Unix socket is the local trust boundary. The supplied Docker deployments
keep it in a private tmpfs and run the TUI inside the controller container.
Sharing it with a host CLI requires a deliberate bind mount owned by UID 65532.
Never expose the unauthenticated Unix-socket API through a TCP proxy.

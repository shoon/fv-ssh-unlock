#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

image="${1:-fv-ssh-unlock:test}"
container="fv-ssh-unlock-verify-$$"
audit_dir="$(mktemp -d "${TMPDIR:-/tmp}/fv-ssh-unlock-image.XXXXXX")"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$audit_dir"
}
trap cleanup EXIT
fail() { printf 'container verification failed: %s\n' "$*" >&2; exit 1; }
expect() {
  local actual="$1" expected="$2" label="$3"
  [[ "$actual" == "$expected" ]] || fail "$label: expected '$expected', got '$actual'"
}

expect "$(docker image inspect --format '{{.Config.User}}' "$image")" "65532:65532" "runtime user"
expect "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")" '["/fv-ssh-unlock"]' "entrypoint"
expect "$(docker image inspect --format '{{json .Config.Cmd}}' "$image")" '["daemon","--socket","/run/fv-ssh-unlock/control.sock"]' "default command"
expect "$(docker image inspect --format '{{len .RootFS.Layers}}' "$image")" "1" "filesystem layer count"
expect "$(docker image inspect --format '{{json .Config.ExposedPorts}}' "$image")" "null" "exposed ports"
expect "$(docker image inspect --format '{{json .Config.Volumes}}' "$image")" "null" "implicit volumes"
expect "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.authors"}}' "$image")" "Shaun Murphy (@shoon)" "author metadata"
expect "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "$image")" "Apache-2.0" "license metadata"
expect "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image")" "https://github.com/shoon/fv-ssh-unlock" "source metadata"
expect "$(docker image inspect --format '{{index .Config.Labels "io.github.shoon.sponsors"}}' "$image")" "https://github.com/sponsors/shoon" "sponsor metadata"

health="$(docker image inspect --format '{{json .Config.Healthcheck.Test}}' "$image")"
expect "$health" '["CMD","/fv-ssh-unlock","healthcheck","--socket","/run/fv-ssh-unlock/control.sock"]' "healthcheck"

# Inspect the image layer rather than a running-container export, which would
# contain Docker-injected /etc, /dev, and mountpoint entries.
docker image save --output "$audit_dir/image.tar" "$image"
manifest="$(tar -xOf "$audit_dir/image.tar" manifest.json)"
layer="$(printf '%s\n' "$manifest" | sed -nE 's/.*"Layers":\["([^"]+)"\].*/\1/p')"
[[ -n "$layer" ]] || fail "could not identify the sole image layer"
rootfs_entries="$(tar -xOf "$audit_dir/image.tar" "$layer" | tar -tf - | sed 's#^\./##; s#/$##' | LC_ALL=C sort -u)"
expected_entries="$(printf '%s\n' \
  fv-ssh-unlock \
  licenses \
  licenses/fv-ssh-unlock \
  licenses/fv-ssh-unlock/LICENSE \
  licenses/fv-ssh-unlock/NOTICE \
  licenses/fv-ssh-unlock/THIRD_PARTY_NOTICES.txt)"
expect "$rootfs_entries" "$expected_entries" "scratch filesystem entries"

docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint /fv-ssh-unlock \
  "$image" credentials providers --json >/dev/null

if docker run --rm --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then
  fail "a shell exists in the scratch image"
fi

# Exercise the actual daemon, Unix-socket client, and JSON dashboard with no
# network, writable root filesystem, capabilities, or host data. Empty tmpfs
# state is enough because the daemon safely supports an empty inventory.
docker run --detach --name "$container" --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /data:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
  --tmpfs /run/fv-ssh-unlock:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
  "$image" daemon --socket /run/fv-ssh-unlock/control.sock --discover-interval 0 >/dev/null

for _ in {1..20}; do
  if docker exec "$container" /fv-ssh-unlock healthcheck \
      --socket /run/fv-ssh-unlock/control.sock >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
docker exec "$container" /fv-ssh-unlock healthcheck \
  --socket /run/fv-ssh-unlock/control.sock >/dev/null
snapshot="$(docker exec "$container" /fv-ssh-unlock tui \
  --socket /run/fv-ssh-unlock/control.sock --json)"
[[ "$snapshot" == *'"schema_version":1'* && "$snapshot" == *'"devices":[]'* ]] || \
  fail "daemon/TUI end-to-end snapshot is invalid"

printf 'container verification passed: %s\n' "$image"

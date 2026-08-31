# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Project-owned Homebrew and Scoop sources for prerelease installation, plus
  release-built DEB and RPM packages for Linux AMD64 and ARM64.
- Package CI that builds, inspects, installs, executes, and removes native
  packages before release.
- DEB and RPM packages now include the hardened systemd unit with its command
  path adjusted to the packaged `/usr/bin/fv-ssh-unlock` binary.
- CI now runs CodeQL for Go and GitHub Actions, dependency review, golangci-lint
  across the default and keyring variants, and a Linux Secret Service keyring
  round trip in addition to the macOS and Windows keyring tests.
- The local API now reports configured probe/unlock budgets and process-lifetime
  candidate drop/eviction counters; structured logs expose the corresponding
  `candidate.dropped` and `candidate.evicted` capacity events.
- Container author and GitHub Sponsors metadata exposed as OCI labels without
  adding files or packages to the scratch image.

### Changed

- Bound native releases to the pushed semantic-version tag, exact checkout,
  GitHub event commit, and `main` ancestry, matching the container release
  gate, while manual dispatch performs read-only verification without
  publishing. Container signature verification now tolerates bounded registry
  referrer propagation without weakening the expected workflow identity.
- Release builds and CI now resolve the checked-in module graph with
  `GOWORK=off`, preventing a local workspace dependency from silently changing
  a shipped build.
- Pinned the dormant Bonjour dependency's attacker-reachable DNS parser to
  `github.com/miekg/dns` v1.1.73 instead of its 2019 minimum.

### Fixed

- Daemon probe and unlock timeout flags now reach the SSH layer instead of
  being silently limited by internal fallback values.
- Candidate enrollment now commits the verified host key only after device
  registration, rolls configuration, monitoring, and trust state back together
  on failure, and no longer blocks unrelated control requests during its SSH
  probe.
- Private configuration, candidate, monitor, known-hosts, lock, and identity
  reads now use no-follow stable opens with native owner/permission validation;
  application-written state and trust files use atomic replacement. Device
  mutations reload under a cross-process lock so concurrent daemon and CLI
  updates cannot silently overwrite each other.
- A full discovery inbox now evicts only the oldest unreviewed entry, or drops
  only the new observation when every entry is operator-pinned, rather than
  failing an entire discovery round. Duplicate Bonjour instance names also no
  longer hide distinct hosts.
- Consecutive clean unreachable observations now increase monitor backoff, and
  a failed one-attempt-marker write emits the error-state event expected by TUI
  and SIEM consumers.
- Candidate-derived terminal output is escaped at its print sites, credential
  and host-key errors preserve their wrapped causes, and CLI validation/help is
  consistent with the action each command performs.

## [0.2.0-rc.2] - 2026-08-31

### Added

- Public, multi-platform Docker Hub releases at
  `shoonimages/fv-ssh-unlock:<version>`, with automatic semantic-tag
  publication, anonymous-access verification, SPDX SBOM and provenance
  attestations, keyless signing, exact workflow-identity verification, and
  immutable `v*` registry tags.
- A canonical logging and SIEM guide covering the JSON event contract,
  severity and sequence semantics, alerting, bounded retention, and external
  Fluent Bit or Vector collection.

### Changed

- Reorganized and audited the user documentation around known-Mac onboarding,
  always-on Raspberry Pi/Linux operation, public container deployment,
  hosting-service workflows, Ansible integration, and secure credential
  delivery.
- Hardened the Compose and Swarm examples with bounded local log rotation,
  explicit digest inputs, and safer host-directory handling.
- Candidate enrollment now rejects the keyring source because that workflow
  cannot create the required keyring credential; known devices can still use
  `config add` to provision an OS-keyring entry.
- Corrected `config add` help to state that `--host` and `--user` are required
  and that the positional device name is an optional local alias.

## [0.2.0-rc.1] - 2026-08-30

### Added

- Foreground `daemon` with explicit per-device automatic unlock, bounded
  concurrency, jittered polling, durable lock episodes, one-submission guards,
  cooldowns, failure latches, and password-free post-boot verification.
- Lightweight `tui`, local Unix-socket v1 API, built-in `healthcheck`, and
  versioned JSON status/dashboard output.
- Persistent Bonjour and opt-in CIDR candidate discovery with fingerprint-first
  deduplication, review/ignore state, exact out-of-band fingerprint enrollment,
  and immediate monitoring of newly approved devices.
- Declarative `config export`, `config apply --check --json`, and per-device
  `config auto-unlock` commands for infrastructure automation.
- A single-layer, non-root `FROM scratch` container for Linux AMD64 and ARM64,
  hardened Compose/Swarm/systemd examples, an image/runtime verifier, and a
  manual private-image workflow with SBOM, provenance, and keyless signing.
- An example Ansible controller role, inventory, local-API query, and
  non-secret device-inventory reconciliation.
- Timestamped daemon logs with text/JSON formats, configurable levels, stable
  versioned event fields, and stdout/stderr collection suitable for journald,
  Docker logging drivers, Fluent Bit, Vector, and SIEM pipelines.
- Credential-provider registry with runtime, OS-keyring, and externally managed
  file providers.
- `credentials providers` human-readable and JSON capability reports, including
  keyring availability, secure file-delivery detection, and honest TPM2 backend
  status.
- Docker Swarm secret and systemd credential-file integration without new
  runtime dependencies, including portable `systemd:<name>` references.
- An action-scoped `--allow-unsafe-credential-storage` override for plaintext
  disk credential files; unsafe storage is otherwise refused and is never an
  automatic fallback.

### Changed

- Automatic-recovery targets use a short TCP/22 preflight after an endpoint is
  known down, avoiding ICMP while waking the pinned SSH probe promptly when the
  network returns. TCP reachability alone never releases a credential.
- `status` now follows normal SSH expectations by trying standard private-key
  filenames in `~/.ssh` when `--identity` is omitted, reports positive booted
  state as `booted`, and calls ambiguous password-free evidence
  `indeterminate`.
- `unlock` and `config remove` now require explicit `--all` for fleet-wide
  actions. Named multi-target operations validate every name before making a
  change and return an unsuccessful exit status for partial failures.
- Status operational failures now produce an unsuccessful exit status;
  `status --require-known` also makes an indeterminate state unsuccessful for
  automation.
- Unlock classification now returns success immediately when FileVault emits
  its authoritative post-password success banner, even if the pre-boot SSH
  server keeps the connection open instead of disconnecting promptly.
- When FileVault accepts a password but does not acknowledge the outcome before
  the SSH timeout, `unlock` now performs password-free boot verification before
  considering a retry and reports the distinction explicitly.
- Unlock attempts watch the configured SSH TCP endpoint after password
  submission and begin boot verification as soon as the pre-boot service goes
  away. This provides event-driven transition detection without depending on
  ICMP/ping; only pinned public-key SSH authentication can prove success.

## [0.1.0] - 2026-08-27

Initial public release.

### Added

- FileVault unlock over the macOS 26 pre-boot SSH service, with retries and
  optional public-key verification after normal macOS finishes booting.
- Password-free `status`, Bonjour-based `discover`, and explicit-CIDR `scan`
  commands.
- SSH host-key pinning, terminal-safe output, strict protocol checks, and
  credential support for OS keyrings, environment variables, and interactive
  prompts.
- Named-device configuration for individual Macs and lab fleets.
- A protocol test server that models the captured FileVault banner, prompt-only
  behavior, and locked-to-unlocked transitions.
- Cross-platform release archives for macOS, Linux, and Windows on AMD64 and
  ARM64, with checksums, Sigstore signing bundles, and SPDX SBOMs.
- GitHub Actions CI, Dependabot updates, private vulnerability reporting, and
  GitHub Sponsors integration.

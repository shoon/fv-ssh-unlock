# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

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

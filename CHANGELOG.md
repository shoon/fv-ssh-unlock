# Changelog

All notable changes to this project are documented here.

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

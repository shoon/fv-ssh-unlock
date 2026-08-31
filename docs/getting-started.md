# Getting started

[Documentation home](index.md) | [Use cases](use-cases.md) | [Security](security.md)

This guide covers client installation and the one-time work needed to make a
Mac available for FileVault-over-SSH recovery.

## Contents

- [Requirements](#requirements)
- [Install the client](#install-the-client)
- [Verify a release download](#verify-a-release-download)
- [Prepare a new Mac](#prepare-a-new-mac)
- [Choose the FileVault user](#choose-the-filevault-user)
- [Choose a stable address](#choose-a-stable-address)
- [Record the SSH host-key fingerprint](#record-the-ssh-host-key-fingerprint)
- [Finish client setup](#finish-client-setup)
- [Remove the tool](#remove-the-tool)

## Requirements

| Component | Requirement |
| --- | --- |
| Target hardware | Apple silicon Mac. |
| Target operating system | macOS 26 (Tahoe) or newer. |
| Disk encryption | FileVault enabled. |
| SSH service | Remote Login enabled before restart. |
| Network | A pre-boot-compatible connection between the client and target. |
| Client operating system | macOS, Linux, or Windows. |
| Source build only | Go 1.26.7 or newer. Release archives do not require Go. |

Pre-boot networking is more restricted than normal macOS networking. Wired
Ethernet is preferred. Apple documents previously joined open or WPA2-Personal
Wi-Fi and open Ethernet as supported pre-boot options; enterprise Wi-Fi and
networks requiring browser authentication are not suitable. Test the exact
interface and network through a full restart before depending on it remotely.

See Apple's [Platform Security guide](https://support.apple.com/en-gb/guide/security/sec8447f5049/web)
and `man apple_ssh_and_filevault` on a macOS 26 Mac for platform details.

## Install the client

### Release archive

Download the current archive from
[GitHub Releases](https://github.com/shoon/fv-ssh-unlock/releases/latest).
Choose the file matching the client computer's operating system and
architecture, extract it, and place the binary on your `PATH`.

Release archives are available for macOS, Linux, and Windows on AMD64 and
ARM64. Windows uses ZIP; macOS and Linux use `tar.gz`. Each archive contains the
binary, README, icon, license, notice, and attribution files. Release binaries
include OS-keyring support.

### Build from a source checkout

```bash
git clone https://github.com/shoon/fv-ssh-unlock.git
cd fv-ssh-unlock
go build -tags keyring -o fv-ssh-unlock ./cmd/fv-ssh-unlock
```

On Windows, name the output `fv-ssh-unlock.exe`.

The build script provides the common variants on macOS, Linux, or a Windows
Bash environment:

```bash
./build.sh            # runtime and external-file providers
./build.sh --keyring  # OS-keyring build
./build.sh --mock     # client and local mock SSH server
```

Binaries are written to `dist/`.

### Go install

```bash
go install github.com/shoon/fv-ssh-unlock/cmd/fv-ssh-unlock@latest
```

`go install` produces a binary with runtime and external-file providers because
build tags cannot be supplied in that module path. Use a release binary or
build with `-tags keyring` if you also want OS-keyring storage.

## Verify a release download

Each release publishes the archives with `checksums.txt`, a keyless Sigstore
bundle for that checksum file, and SPDX SBOMs.

Calculate the archive's SHA256 digest and compare the complete value with the
line for that exact filename in `checksums.txt`. Replace `X.Y.Z` below with the
release version without its leading `v`.

Linux:

```bash
sha256sum fv-ssh-unlock_X.Y.Z_linux_amd64.tar.gz
```

macOS:

```bash
shasum -a 256 fv-ssh-unlock_X.Y.Z_darwin_arm64.tar.gz
```

PowerShell:

```powershell
(Get-FileHash fv-ssh-unlock_X.Y.Z_windows_amd64.zip -Algorithm SHA256).Hash
```

The checksum file is signed through GitHub Actions and Sigstore without a
long-lived signing key. Replace `vX.Y.Z` with the release tag, then run:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/shoon/fv-ssh-unlock/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle checksums.txt.sigstore.json \
  checksums.txt
```

Do not install or run a release whose checksum or signature verification
fails.

## Prepare a new Mac

Complete these steps locally while normal macOS is running:

1. Enable FileVault in **System Settings > Privacy & Security > FileVault**.
2. Choose or create the local user that will perform the unlock.
3. Enable **Remote Login** in **System Settings > General > Sharing**.
4. Limit Remote Login to only the users that need SSH access.
5. Leave Full Disk Access off for the unlock account unless another unrelated
   workflow requires it.
6. Test a normal SSH login from the future client computer.
7. Confirm that the chosen user is a FileVault-enabled APFS cryptographic user.
8. Configure and test a stable address for the interface used in pre-boot.
9. Record the target's Ed25519 SSH host-key fingerprint.

Useful checks on the target include:

```bash
fdesetup list -extended
diskutil apfs listUsers /
```

Before restarting, test normal SSH from the client:

```bash
ssh unlockuser@192.0.2.10
```

The target user must appear among the users allowed to unlock FileVault and
must be allowed by the Remote Login settings.

## Choose the FileVault user

`unlockuser` is an example in this documentation. It has no built-in meaning,
and `fv-ssh-unlock` never creates or modifies a macOS account.

The configured user must be all of the following:

- a real local macOS account;
- enabled to unlock the FileVault volume; and
- allowed to use Remote Login.

A standard, non-administrator account is preferred. You can use an existing
FileVault-enabled standard user or create a dedicated standard user with a
unique password. A dedicated account can make credential rotation and audit
logs easier to understand.

There is no supported FileVault pre-boot-only account. A FileVault-enabled
account is a real macOS login account and can normally appear at, and log into,
the booted Mac UI. Hiding it from the login window is cosmetic, not a security
boundary. Do not try to turn it into an artificial pre-boot-only identity by
removing services required by macOS or by relying on unsupported account
changes.

Reduce the account's exposure with normal macOS controls:

- keep it a standard user rather than an administrator;
- allow Remote Login only for the specific account or group that needs it;
- use a long, unique password stored in the client OS keyring or an approved
  secret manager;
- do not grant Full Disk Access merely for FileVault-over-SSH;
- do not share the password between Macs; and
- review the account and rotate its credential using your normal operations
  process.

Apple's documentation on FileVault users, secure tokens, and Remote Login is
the authority for macOS account behavior.

## Choose a stable address

FileVault pre-boot may answer SSH on TCP/22 without advertising Bonjour.
Address planning must happen while the Mac is still booted.

| Address choice | Recommendation |
| --- | --- |
| DHCP reservation or static lease | Preferred. Reserve the address for the exact Ethernet or Wi-Fi interface used in pre-boot. |
| Manually assigned static address | Acceptable fallback. Keep it outside the DHCP pool, check for conflicts, and test a full restart. |
| `.local` hostname | Convenient while booted, but do not make it the only recovery path. mDNS availability can differ in pre-boot. |
| Unreserved DHCP lease | Avoid for unattended recovery. It can change, and the old address can later belong to another host. |

SSH host-key pinning prevents a different machine at the old address from
receiving the password, but it cannot tell you the target's new address unless
you scan an authorized subnet and match the pinned key.

## Record the SSH host-key fingerprint

On the target Mac, run:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Store the SHA256 fingerprint through a trusted channel. During client setup,
compare it exactly with the fingerprint printed by the first `status` command.
See [SSH host-key enrollment](security.md#ssh-host-key-enrollment) for the full
procedure.

## Finish client setup

Follow the [README quick start](../README.md#quick-start) to add the target,
enroll the verified host key, restart, and perform the first unlock. For
multiple existing Macs, use [Add several known Macs](use-cases.md#add-several-known-macs).

## Remove the tool

Before deleting the configuration, use a keyring-enabled binary to remove the
configured devices so their keyring entries are cleaned up:

```bash
fv-ssh-unlock config remove --all
```

Then delete the client binary. If you no longer need any pinned keys or
settings, remove `~/.fv-ssh-unlock`. Removing the client does not change
FileVault, Remote Login, network settings, or user accounts on a target Mac.

---

[Documentation home](index.md) | [Use cases](use-cases.md) | [Security](security.md)

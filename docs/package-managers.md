# Package-manager installation

[Documentation home](index.md) | [Getting started](getting-started.md) | [Release verification](getting-started.md#verify-a-release-download)

Use a project-owned package source when you want normal install and upgrade
commands. Release archives remain the reference distribution and include the
signed checksum file and per-archive SBOMs.

## Availability

| Channel | Status | Architectures | Update behavior |
| --- | --- | --- | --- |
| Homebrew tap | Available for the current prerelease | macOS and Linux, AMD64 and ARM64 | `brew update` and `brew upgrade` |
| Scoop bucket | Available for the current prerelease | Windows AMD64 and ARM64 | `scoop update` and `scoop update fv-ssh-unlock` |
| GitHub release archives | Available | macOS, Linux, and Windows on AMD64 and ARM64 | Download each version explicitly |
| DEB and RPM release assets | Available for the current prerelease | Linux AMD64 and ARM64 | Install each downloaded package explicitly; this is not an APT or DNF repository |
| WinGet community repository | Planned for stable `v0.2.0` | Windows AMD64 and ARM64 | Normal WinGet upgrades after Microsoft accepts the initial manifest |
| Docker Hub | Available | Linux AMD64 and ARM64 | Pull an explicit version or digest |

The project-owned Homebrew tap and Scoop bucket intentionally carry the
prerelease because users must opt into those sources. WinGet's normal community
catalog does not provide a reliable separate prerelease channel, so the
project will submit its first public WinGet manifest only for stable `v0.2.0`.
The current prerelease is not being presented as a stable package.

## Homebrew

Install directly from the project tap:

```bash
brew install shoon/tap/fv-ssh-unlock
```

The formula builds the immutable tagged source with the `keyring` build tag.
Homebrew installs Go only as a build dependency. The same formula supports
Apple silicon and Intel macOS as well as 64-bit ARM and Intel Linux.

Upgrade or remove it with normal Homebrew commands:

```bash
brew update
brew upgrade fv-ssh-unlock
brew uninstall fv-ssh-unlock
```

This is a third-party tap, not `homebrew/core`. Homebrew requires upstream to
designate a stable release before a formula is eligible for core, and new
projects must also meet Homebrew's notability requirements. The project tap is
the supported Homebrew source during the prerelease.

## Scoop

Add the project bucket and install the manifest:

```powershell
scoop bucket add shoon https://github.com/shoon/scoop-bucket
scoop install shoon/fv-ssh-unlock
```

Scoop selects the AMD64 or ARM64 release ZIP and checks its SHA-256 digest.
Upgrade or remove it with:

```powershell
scoop update
scoop update fv-ssh-unlock
scoop uninstall fv-ssh-unlock
```

## DEB and RPM files

The release workflow produces `.deb` and `.rpm` files for Linux AMD64 and
ARM64. These packages are available on the current prerelease page. The older
`v0.2.0-rc.2` release predates native package publication and contains archives
only.

Install a downloaded Debian or Ubuntu package:

```bash
sudo dpkg -i fv-ssh-unlock_X.Y.Z_linux_arm64.deb
```

Install a downloaded Fedora or RHEL-family package:

```bash
sudo rpm -i fv-ssh-unlock_X.Y.Z_linux_arm64.rpm
```

Use `amd64` instead of `arm64` on an Intel or AMD controller. The packages
install the binary as `/usr/bin/fv-ssh-unlock` and place the license and notices
under `/usr/share/doc/fv-ssh-unlock`. They also install a systemd unit at
`/usr/lib/systemd/system/fv-ssh-unlock.service` whose `ExecStart` already points
at the packaged `/usr/bin` path, so do not copy the unit from the repository
over it. The tracked `deploy/systemd/fv-ssh-unlock.service` uses
`/usr/local/bin` for source and archive installs. The packages do not create a
user, write a credential, install configuration, or enable the daemon. Follow
the [native systemd guide](containers-and-services.md#native-systemd) after
installation. Use its shared service-account and credential steps, skip the
archive-only binary/unit installation block, and select `/usr/bin` in every
drop-in and operator command.

These files are installable packages, not hosted APT or DNF repositories.
`apt upgrade` and `dnf upgrade` cannot discover newer GitHub release assets.
Repository metadata signing, hosting, retention, and rollback will be added
only if demand justifies operating those services.

## WinGet

The planned stable package identifier is `Shoon.fv-ssh-unlock`. It will use the
existing AMD64 and ARM64 Windows ZIPs as a portable package, so no MSI or custom
installer is required. Do not run the command below until the stable release
documentation confirms that Microsoft has accepted the manifest:

```powershell
winget install Shoon.fv-ssh-unlock
```

The initial stable manifest will be validated and installed in Windows Sandbox
before submission to the Microsoft community repository. Microsoft then runs
its own automated validation, malware scanning, and moderation; acceptance is
outside this project's control.

## Integrity and credential behavior

Package managers verify a source or archive checksum, but that is not a
substitute for independently checking the project's Sigstore bundle when your
threat model requires it. Follow [Verify a release download](getting-started.md#verify-a-release-download)
for the strongest direct verification path.

Every packaged binary includes OS-keyring support. Provider availability still
depends on the account and session that runs it. In particular, a headless
Linux service usually has no Secret Service D-Bus session even though keyring
support is compiled in. Run this as the final service account before enabling
automatic unlock:

```bash
fv-ssh-unlock credentials providers
```

Package installation never weakens the credential-provider checks and never
enables unsafe credential storage.

---

[Documentation home](index.md) | [Getting started](getting-started.md) | [Security](security.md)

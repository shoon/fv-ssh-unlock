# Contributing to fv-ssh-unlock

Thanks for your interest in contributing! This project is licensed under the
**Apache License 2.0**, and all contributions are accepted under that license.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. It is a lightweight way for you to certify that you wrote, or
otherwise have the right to submit, the code you are contributing.

Add a `Signed-off-by` line to your commits by committing with `-s`:

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

<details>
<summary>Developer Certificate of Origin 1.1 (full text)</summary>

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or
(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or
(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.
(d) I understand and agree that this project and the contribution are public and
    that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may be
    redistributed consistent with this project or the open source license(s)
    involved.
```
</details>

## Building & testing

This repository contains two Go modules (the main module and
`tools/mock-fv-ssh-server`); a `go.work` file ties them together for local
development. Requires Go 1.26.7+.

```bash
go build ./...
go vet ./...
go test ./...
go test -tags keyring ./...   # exercise the keyring credential backend
go test -race ./...
govulncheck ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

Please make sure `go build`, `go vet`, and `go test` all pass before opening a
pull request. New code should include tests where practical.

### Build script

```bash
./build.sh            # default binary
./build.sh --keyring  # with OS keyring support
./build.sh --mock     # also build the mock test server
```

## License headers

New source files should carry the standard SPDX header:

```go
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy
```

## Submitting changes

- Fork the repo and create a feature branch.
- Make your changes and add tests.
- Run `go build`, `go vet`, `go test -race`, and `govulncheck` (with and
  without `-tags keyring`).
- Sign off your commits (`git commit -s`).
- Open a PR with a clear description of your changes.

## Reporting security issues

Because this tool handles disk-encryption passwords, please report security
issues privately rather than in a public issue. Follow the contact and
disclosure guidance in [SECURITY.md](SECURITY.md).

## Release signing

Tags matching `v*` run the GitHub release workflow. GoReleaser builds archives
for macOS, Linux, and Windows on AMD64 and ARM64, creates checksums and SBOMs,
and publishes the GitHub release. Cosign signs the checksum file through GitHub
OIDC, so no long-lived signing key is stored in repository secrets.

Dependabot checks the main Go module, mock-server Go module, and GitHub Actions
weekly. CI also scans every build variant for reachable vulnerabilities.

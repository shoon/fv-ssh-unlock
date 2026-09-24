# Tagged releases

The project supports GitHub-driven tagged releases, like Takeout Helper. The
preparation workflow creates a **lightweight version tag** on an exact tested
`main` commit, then explicitly dispatches the existing Release and Container
workflows on that tag. No personal signing key or new cross-repository token is
needed. Existing manually pushed signed tags remain supported.

Git tag signing and artifact signing are different controls. CI-created tags
are not signed Git tag objects. Native checksum files and container digests
remain signed with Cosign using GitHub OIDC; SBOMs, provenance, source/ref
binding, and Docker Hub immutable-tag protections remain in place. Never move,
delete/recreate, or reuse a published version tag.

## Before requesting a release

Merge release notes, version-pinned documentation updates, and any code changes
first. Choose an unused semantic version, such as `v0.2.0-rc.4`, and record the
**full 40-character commit SHA of current main** after those merges. Wait for
that exact commit's CI to succeed, including builds, race tests, both keyring
and default variants, lint, coverage, packages, and security. Other commit
checks and legacy statuses must not be pending or failing; neutral CodeQL
coverage warnings are not treated as successful scans. The preparation
workflow refuses a stale SHA, missing required CI jobs, and an existing tag or
release. It never creates a version/changelog commit on your behalf.

## Start from the GitHub website or CLI

Run **Actions -> Prepare tagged release -> Run workflow** on `main`, supplying
`tag` and `expected_sha`. The selected `main` commit must still equal that SHA.
For example, after replacing the placeholder with the actual tested SHA:

```bash
gh workflow run prepare-release.yml --repo shoon/fv-ssh-unlock --ref main \
  -f tag=v0.2.0-rc.4 -f expected_sha=FULL_TESTED_MAIN_SHA
```

## Start through a connector that can create branches and files

A release does not require a direct tag-creation or dispatch tool in the
connector. After this workflow is merged, create a new branch named
`release/request/v0.2.0-rc.4` **from the exact tested main SHA**, then make one
commit adding only `.github/release-request.json`:

```json
{
  "tag": "v0.2.0-rc.4",
  "expected_sha": "FULL_TESTED_MAIN_SHA"
}
```

The placeholder is explanatory and will be rejected; use the actual full SHA.
That branch push starts Prepare tagged release. Do **not** open or merge the
request branch into `main`: it contains request data, not release source. The
workflow requires its single parent to be the requested current `main` SHA and
its entire diff to contain only this JSON file. Edits to workflows or source
on a request branch are rejected. The workflow leaves the request branch for
an audit trail; it can be deleted after the outcome is verified.

Preparation first checks with read-only permissions. A separate job checks out
only the validated main commit, repeats the readiness checks, creates the new
tag without force, and uses its repository-scoped `GITHUB_TOKEN` to dispatch
`release.yml` and `container.yml` on the tag, passing the exact expected SHA.
Only that job has `contents: write` and `actions: write`; no repository settings
or protection rules are changed. Anyone allowed to write such a branch can
request a release; this path does not introduce an extra human approval gate.

The explicit dispatch is necessary because tag writes made using
`GITHUB_TOKEN` do not start another push workflow. Authenticated
`workflow_dispatch` is the supported exception. The temporary-workflow
approach used for Takeout Helper is therefore replaced here with a permanent,
reviewed workflow and a data-only request branch.

## Validation, publication, and recovery

Release and Container support both a version-tag push and a manual dispatch
**on an existing version tag**. A manual tag dispatch must supply
`expected_sha`; a dispatch on a branch remains verification-only and cannot
publish. Each publisher checks that the event SHA, checkout, refreshed remote
tag, and a commit on `origin/main` identify the same source. The native Release
workflow reruns build/test/vulnerability checks before GoReleaser publishes.
Container verification and both-platform image builds remain required before
registry publication. Cosign signing and verification remain enabled.

A successful Prepare run means the tag was created and publisher workflows
were queued, **not** that release publication has finished. Check the exact-tag
Release and Container runs, their publish jobs, and the resulting native
archives/packages, checksums, Sigstore checksum bundle, SBOMs, and signed image
digest. A failed publisher does not cause the tag to be deleted or moved.

If a dispatch failed after tag creation, do not rerun Prepare expecting it to
reuse the tag. Inspect the existing release and runs first. A still-unpublished
workflow can be explicitly dispatched on the **same tag and same SHA**:

```bash
gh workflow run release.yml --repo shoon/fv-ssh-unlock --ref v0.2.0-rc.4 \
  -f expected_sha=FULL_TESTED_MAIN_SHA
# Only if the container publication also needs starting:
gh workflow run container.yml --repo shoon/fv-ssh-unlock --ref v0.2.0-rc.4 \
  -f expected_sha=FULL_TESTED_MAIN_SHA
```

Do not rerun a publisher that already completed successfully, overwrite a
release asset, or disable immutable tags. A code fix requires a new commit and
an unused next version; infrastructure-only retries must preserve tag/source.

## Homebrew and Scoop

The preparation workflow intentionally has no write access to the separate
package repositories. After successful publication, update
`shoon/homebrew-tap/Formula/fv-ssh-unlock.rb` with the real source-archive SHA256
and rebuild bottles (or remove obsolete bottle metadata for a validated source
build). Update `shoon/scoop-bucket/bucket/fv-ssh-unlock.json` with the actual
Windows AMD64 and ARM64 archive URLs and verified hashes. Do not retain old
bottle hashes under a new version or invent checksums before assets exist.

The current Scoop updater follows stable releases only. An `rc` release needs
an explicit package update; publishing the GitHub prerelease does not by itself
update either feed. WinGet remains stable-only as documented in CONTRIBUTING.

## Tests

```bash
python3 -m unittest discover -s hack -p 'test_tagged_release.py' -v
```

These offline tests cover release request validation, stale commits, missing or
failing security checks, neutral CodeQL warnings, tag reuse, source changes on
request branches, and tag/checkout/main binding. They do not publish anything.
CI's security job runs them before workflow linting and vulnerability scanning.

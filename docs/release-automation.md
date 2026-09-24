# From dependency PR to published packages

## Normal operation

1. Review and merge passing source PRs, including Dependabot updates. Related
   `golang.org/x/*` updates share one group across both Go modules; Actions
   minor/patch updates are grouped. Major Actions updates stay separate.
   Automatic rebasing is enabled, but no automatic approval or merge is enabled.
2. Wait for the resulting **main commit**, not just its PR merge simulation, to
   pass CI/security. Choose an unused semantic version. Open Actions → Prepare
   tagged release on `main` and enter only `tag` (for example `v0.2.0-rc.5`).
   The optional SHA defaults to the workflow event's exact commit, never a
   moving branch. A changed main or incomplete/failed check still refuses release.
   The existing data-only `release/request/<tag>` path also works from chat.
3. Release and Container publish and sign exactly that tag/source. Verify
   published release automatically waits for both publishers, downloads all
   native payloads/SBOMs, checks the signed checksum manifest, matches the source
   archive against Git objects, and verifies the container's source labels,
   platforms, attestation descriptors and Cosign identity. Its JSON report is an
   Actions artifact, not a replacement release artifact.
4. Each package repo's Sync fv-ssh-unlock release workflow checks hourly, or can
   be run manually on its `main` for an explicit tag. It verifies upstream before
   opening a version-only PR. No personal token or new cross-repository secret
   is needed. `.github/fv-release-channel.json` controls selection: `preview`
   includes stable and prerelease versions; `stable` excludes prereleases.
   Version order, not publication time, is used. Neither channel downgrades.
5. Review the generated package PRs. GitHub may display **Approve workflows to
   run** for a PR created with `GITHUB_TOKEN`; approve those runs. This is not a
   skipped check and the automation does not approve them for you.
   - Scoop: merge the manifest PR after validation. No extra publish step.
   - Homebrew: after both bottle tests pass, comment `/publish FULL_HEAD_SHA`
     on the formula PR. Only a current repository writer can authorize it.
     The guarded existing publisher incorporates the exact approved PR, uploads
     its tested bottles and pushes the formula. Do not ordinary-squash the
     formula PR when using this path. Other Homebrew PRs, including Dependabot
     workflow updates, continue to use ordinary merges.
6. Clean-feed installation tests run on package main. Homebrew must pour the
   published bottles and pass `brew test`; Scoop installs from the actual bucket
   and verifies the installed version. Release distribution status updates one
   issue per version only when its status changes and closes it when both feeds
   and their current-main installation tests are successful.

Hourly schedules are best-effort GitHub scheduling, not a real-time SLA. Manual
workflow runs provide the immediate/recovery path. PR creation may require the
repository administrator to enable Actions' **Allow GitHub Actions to create
and approve pull requests** setting. The code never approves reviews despite
that combined setting's name. No repository protection settings are modified.

## Trust boundaries and retries

The shared action is SHA-pinned by the package repositories. Review action-pin
updates like other dependency updates. It executes neither PR workflow code in
an elevated context nor downloaded source as part of release verification.
Public cross-repository reads use GitHub's API; each write token remains confined
to its own repository. Only generated package branches/PRs are updated by sync.
Main is never force-pushed. Existing tags/assets are never moved or overwritten.

Generated branches carry a content-integrity marker in their PR description.
Sync can incorporate a newer main and request fresh tests, but refuses to
silently overwrite manual branch edits, unrelated files, or a closed PR decision.
A closed unmerged generated PR requires deliberate maintainer follow-up; it is
not repeatedly reopened. Approvals name a full SHA so edits invalidate approval.

A successful release verification is **not** proof of package distribution.
A published bottle asset is **not** proof of a clean installation test. Those
states are reported separately. A neutral CodeQL or pending security check is
not treated as a pass.

Rerun **Sync**, **Verify published release**, **Release distribution status**, or
**Feed installation smoke test** to finish/check distribution. Do not rerun a
successful Release/Container publisher. If a bottle upload succeeds but pushing
main fails, preserve the published assets and inspect/reconcile the metadata;
do not force a new upload or recreate the tag. A code fix requires a new version.

For `fv-ssh-unlock`, update release notes and version-pinned documentation before
starting the release. CI-created Git tags remain lightweight, while released
checksums and container digests remain Cosign-signed. Nothing automatically
promotes a release candidate to stable or releases every dependency merge.

## Tests

```sh
python3 -m unittest discover -s .github/actions/release-tools -p 'test_*.py' -v
```

Tests cover version ordering, channel selection, token/redirect isolation,
checksum completeness, tag ancestry, latest-attempt gates, missing publishers,
package-only edits, stale main, changed generated branches, and exact-head human
publication authorization. CI also runs the verifier read-only against the
existing immutable `v0.2.0-rc.4` release as an integration regression test.

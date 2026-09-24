# SPDX-License-Identifier: Apache-2.0
"""Guard and start tagged releases using only the repository's Actions token.

No tag is ever moved/deleted. `request` is read-only; `create` is the only
command that writes remotely; `bind` only verifies the checked-out tag.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "shoon/fv-ssh-unlock"
REQUEST_PATH = ".github/release-request.json"
CI_PATH = ".github/workflows/ci.yml"
REQUIRED_JOBS = {
    "security", "Coverage regression gate", "packages",
    "Lint default build", "Lint keyring build",
    *(f"build-test ({os}-latest)" for os in ("ubuntu", "macos", "windows")),
    *(f"keyring-test ({os}-latest)" for os in ("ubuntu", "macos", "windows")),
}


class ReleaseError(RuntimeError):
    """A release prerequisite was not satisfied."""


def validate(tag: str, sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ReleaseError("expected_sha must be a full lowercase commit SHA")
    if len(tag) > 128 or not re.fullmatch(
        r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", tag
    ):
        raise ReleaseError("tag must be a canonical vMAJOR.MINOR.PATCH[-prerelease] version")
    if "-" in tag:
        for part in tag.split("-", 1)[1].split("."):
            if part.isdigit() and len(part) > 1 and part.startswith("0"):
                raise ReleaseError("numeric prerelease identifiers cannot have leading zeroes")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward the Actions token to a redirected host.
        return None


class API:
    def __init__(self) -> None:
        self.token = os.environ["GH_TOKEN"]
        self.opener = urllib.request.build_opener(NoRedirect)

    def call(self, path: str, payload=None, *, missing_ok: bool = False):
        if not path.startswith("/") or path.startswith("//"):
            raise ReleaseError("invalid repository API path")
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"https://api.github.com/repos/{REPOSITORY}{path}", data=data,
            headers={"Authorization": f"Bearer {self.token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            # Neither credentials nor response bodies are logged.
            raise ReleaseError(f"GitHub API returned HTTP {error.code} for {path}") from None

    def pages(self, path: str, key: str | None = None) -> list:
        result = []
        for page in range(1, 21):
            sep = "&" if "?" in path else "?"
            body = self.call(f"{path}{sep}per_page=100&page={page}")
            batch = body[key] if key else body
            if not isinstance(batch, list):
                raise ReleaseError("unexpected paginated GitHub response")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ReleaseError("pagination limit reached; refusing an incomplete check")


def check_ci(api, sha: str) -> None:
    runs = api.pages(f"/actions/runs?head_sha={sha}", "workflow_runs")
    ci = [r for r in runs if r["head_sha"] == sha and r["path"] == CI_PATH
          and r["head_branch"] == "main" and r["event"] in ("push", "workflow_dispatch")]
    if not ci:
        raise ReleaseError("no CI run on this exact main commit; wait for main CI")
    run = max(ci, key=lambda r: r["id"])
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise ReleaseError("the latest CI attempt on this main commit has not passed")
    jobs = api.pages(f"/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
    by_name = {j["name"]: j for j in jobs}
    if not REQUIRED_JOBS <= by_name.keys():
        raise ReleaseError("CI is missing a required build, test, lint, package, or security job")
    if any(j["status"] != "completed" or j["conclusion"] != "success"
           or j["head_sha"] != sha for j in jobs):
        raise ReleaseError("CI contains an incomplete, skipped, or failing job")
    checks = api.pages(f"/commits/{sha}/check-runs?filter=latest", "check_runs")
    if not checks:
        raise ReleaseError("no commit checks were returned")
    # Preparation is orchestration, not a source-verification check. In a
    # manual run its own in-progress checks are attached to this same SHA.
    preparation_suites = {r["check_suite_id"] for r in runs
                          if r["path"] == ".github/workflows/prepare-release.yml"}
    for check in checks:
        if check["check_suite"]["id"] in preparation_suites:
            continue
        allowed = check["conclusion"] == "success" or (
            check["name"] == "publish" and check["conclusion"] == "skipped")
        if check["status"] != "completed" or not allowed:
            raise ReleaseError(f"commit check is not successful: {check['name']}")
    # Legacy commit statuses are separate from check runs. The newest status
    # for each context wins; a newer failure must never inherit an old pass.
    statuses = api.pages(f"/commits/{sha}/statuses")
    latest = {}
    for status in statuses:
        latest.setdefault(status["context"], status)
    if any(status["state"] != "success" for status in latest.values()):
        raise ReleaseError("a legacy commit status is pending or failing")


def check_target(api, tag: str, sha: str) -> None:
    validate(tag, sha)
    if api.call("/git/ref/heads/main")["object"]["sha"] != sha:
        raise ReleaseError("main changed; create a new request for the new tested commit")
    if api.call(f"/git/ref/tags/{tag}", missing_ok=True) is not None:
        raise ReleaseError("tag already exists; never move or reuse a release tag")
    if api.call(f"/releases/tags/{tag}", missing_ok=True) is not None:
        raise ReleaseError("a release already exists for this tag")
    check_ci(api, sha)
    # Compare again after potentially slow CI API reads.
    if api.call("/git/ref/heads/main")["object"]["sha"] != sha:
        raise ReleaseError("main changed while checking release readiness")


def request(api) -> tuple[str, str]:
    event = os.environ["GITHUB_EVENT_NAME"]
    ref = os.environ["GITHUB_REF"]
    event_sha = os.environ["GITHUB_SHA"]
    if git("rev-parse", "HEAD") != event_sha:
        raise ReleaseError("checkout does not match the workflow event")
    if event == "workflow_dispatch":
        tag, sha = os.environ["RELEASE_TAG"], os.environ["EXPECTED_SHA"]
        validate(tag, sha)
        if ref != "refs/heads/main" or event_sha != sha:
            raise ReleaseError("manual preparation must run on the exact requested main commit")
    elif event == "push":
        path = Path(REQUEST_PATH)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
            raise ReleaseError("invalid release request file")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"tag", "expected_sha"}:
            raise ReleaseError("request must contain exactly tag and expected_sha")
        tag, sha = data["tag"], data["expected_sha"]
        if not isinstance(tag, str) or not isinstance(sha, str):
            raise ReleaseError("release request values must be strings")
        validate(tag, sha)
        if ref != f"refs/heads/release/request/{tag}":
            raise ReleaseError("request branch does not match the requested tag")
        if git("show", "-s", "--format=%P", event_sha) != sha:
            raise ReleaseError("request must be one commit directly on the requested main")
        if git("diff", "--name-only", sha, event_sha) != REQUEST_PATH:
            raise ReleaseError("request branch must change only the release request JSON")
        remote = api.call("/git/ref/" + ref.removeprefix("refs/"))
        if remote["object"]["sha"] != event_sha:
            raise ReleaseError("request branch changed since this event")
    else:
        raise ReleaseError("unsupported preparation event")
    check_target(api, tag, sha)
    return tag, sha


def create(api, tag: str, sha: str) -> None:
    if git("rev-parse", "HEAD") != sha:
        raise ReleaseError("publishing checkout is not the validated main commit")
    check_target(api, tag, sha)
    # This is a create-only API: an existing ref produces an error, never an
    # update. Use a lightweight tag, matching the Takeout Helper CI process.
    api.call("/git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
    summary(f"Created `{tag}` at `{sha}`. Publication is NOT complete yet.")
    for workflow in ("release.yml", "container.yml"):
        # A GITHUB_TOKEN-created tag does not trigger push workflows. Explicit
        # dispatch is the documented exception, using this repo's token only.
        if api.call(f"/git/ref/tags/{tag}")["object"]["sha"] != sha:
            raise ReleaseError("release tag changed; refusing dispatch")
        api.call(f"/actions/workflows/{workflow}/dispatches", {
            "ref": tag, "inputs": {"expected_sha": sha},
        })
        summary(f"Dispatched `{workflow}` for `{tag}` / `{sha}`.")
    summary("Check BOTH Release and Container publish jobs and the resulting assets before "
            "calling this release complete. Update Homebrew/Scoop only after verifying their hashes.")


def bind() -> None:
    tag = os.environ["GITHUB_REF_NAME"]
    sha = os.environ["GITHUB_SHA"]
    validate(tag, sha)
    event = os.environ["GITHUB_EVENT_NAME"]
    if event not in ("push", "workflow_dispatch") or os.environ["GITHUB_REF"] != f"refs/tags/{tag}":
        raise ReleaseError("publishing requires a version-tag push or explicit tag dispatch")
    if event == "workflow_dispatch" and os.environ.get("EXPECTED_SHA") != sha:
        raise ReleaseError("tag dispatch requires expected_sha matching the event commit")
    if git("rev-parse", "HEAD") != sha:
        raise ReleaseError("checkout and event commit differ")
    # Refresh refs, rather than assuming the tag or main remained unchanged
    # after the workflow was queued. These operations are remote reads only.
    git("fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main",
        f"+refs/tags/{tag}:refs/tags/{tag}")
    if git("rev-parse", f"refs/tags/{tag}^{{commit}}") != sha:
        raise ReleaseError("remote tag no longer points to the event commit")
    if subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"],
                      check=False).returncode != 0:
        raise ReleaseError("release commit is not on origin/main")


def summary(message: str) -> None:
    print(message, flush=True)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write(message + "\n\n")


def main() -> None:
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ReleaseError("release automation is restricted to the upstream repository")
    if len(sys.argv) != 2:
        raise ReleaseError("usage: tagged_release.py request|create|bind")
    if sys.argv[1] == "request":
        tag, sha = request(API())
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"tag={tag}\nsha={sha}\n")
        summary(f"Validated release request `{tag}` for tested main `{sha}`.")
    elif sys.argv[1] == "create":
        create(API(), os.environ["RELEASE_TAG"], os.environ["EXPECTED_SHA"])
    elif sys.argv[1] == "bind":
        bind()
    else:
        raise ReleaseError("unknown release command")


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Release refused: {error}", file=sys.stderr)
        sys.exit(1)

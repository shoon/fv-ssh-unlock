# SPDX-License-Identifier: Apache-2.0
"""Repository-scoped release verification and approval-gated package updates.

Verification never executes downloaded source. No command moves release tags,
overwrites assets, approves reviews, or merges a PR. Package writes are confined
to generated branches; Homebrew's existing publisher remains the only writer to
its main branch. All network and process operations fail closed.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SOURCE = "shoon/fv-ssh-unlock"
TAP = "shoon/homebrew-tap"
BUCKET = "shoon/scoop-bucket"
FORMULA = "Formula/fv-ssh-unlock.rb"
MANIFEST = "bucket/fv-ssh-unlock.json"
IMAGE = "shoonimages/fv-ssh-unlock"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
MARKER = re.compile(r"<!-- release-sync (\{[^\n]+\}) -->")
BOT = "github-actions[bot]"


class Refused(RuntimeError):
    """A required identity, integrity or readiness condition was not satisfied."""


class Pending(Refused):
    """A publisher has not completed yet; no partial release is distributed."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def version_key(tag):
    match = VERSION.fullmatch(tag)
    require(match is not None and len(tag) <= 128, "Invalid canonical version tag")
    major, minor, patch, prerelease = match.groups()
    parts = []
    if prerelease:
        for part in prerelease.split("."):
            require(not (part.isdigit() and len(part) > 1 and part[0] == "0"), "Noncanonical prerelease")
            parts.append((0, int(part)) if part.isdigit() else (1, part))
    return (int(major), int(minor), int(patch), 0 if prerelease else 1, tuple(parts))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password,
                "Unsafe download redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected:
            redirected.remove_header("Authorization")
            redirected.remove_header("Cookie")
        return redirected


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download(url, *, limit=100_000_000, headers=None):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and not parsed.username and not parsed.password,
            "Downloads must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "shoon-release-tools", **(headers or {})})
    with urllib.request.build_opener(SafeRedirect).open(request, timeout=60) as response:
        data = response.read(limit + 1)
    require(len(data) <= limit, "Download exceeds the configured size limit")
    return data


class API:
    def __init__(self, repo, *, write=False):
        require(repo in (SOURCE, TAP, BUCKET, "shoon/audio-fade-fixer", "shoon/takeout-helper-gphotos"), "Repository is not allowlisted")
        self.repo = repo
        self.write = write
        self.token = os.environ.get("GH_TOKEN", "")

    def call(self, path, payload=None, *, method=None, missing=False):
        require(path.startswith("/") and not path.startswith("//"), "Invalid API path")
        method = method or ("GET" if payload is None else "POST")
        if method != "GET":
            require(self.write and os.environ.get("GITHUB_REPOSITORY") == self.repo,
                    "Cross-repository or read-only write refused")
        headers = {"Accept": "application/vnd.github+json", "Content-Type": "application/json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "shoon-release-tools"}
        # Public cross-repository reads do not need a cross-repository secret.
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request("https://api.github.com/repos/" + self.repo + path,
                                         data=None if payload is None else json.dumps(payload).encode(),
                                         headers=headers, method=method)
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=45) as response:
                data = response.read(10_000_001)
            require(len(data) <= 10_000_000, "API response is too large")
            return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing:
                return None
            suffix = " Check Actions' permission to create PRs." if error.code == 403 and path == "/pulls" else ""
            raise Refused(f"GitHub HTTP {error.code}: {self.repo}{path}.{suffix}") from None

    def pages(self, path, key=None):
        result = []
        for page in range(1, 21):
            sep = "&" if "?" in path else "?"
            response = self.call(f"{path}{sep}per_page=100&page={page}")
            batch = response[key] if key else response
            require(isinstance(batch, list), "Unexpected pagination response")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise Refused("Incomplete paginated result; refusing to guess")

    def main(self):
        return self.call("/git/ref/heads/main")["object"]["sha"]

    def file(self, path, ref):
        entry = self.call("/contents/" + path + "?ref=" + urllib.parse.quote(ref, safe=""))
        require(entry.get("type") == "file" and entry.get("encoding") == "base64", "Expected an ordinary text file")
        return base64.b64decode(entry["content"]).decode("utf-8")


def summary(text):
    print(text, flush=True)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(text + "\n\n")


def outputs(**values):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for name, value in values.items():
                require("\n" not in str(value) and "\r" not in str(value), "Multiline output refused")
                stream.write(f"{name}={value}\n")


def resolve_tag(api, tag, expected=""):
    version_key(tag)
    require(not expected or SHA.fullmatch(expected), "Expected SHA must contain 40 lowercase hex characters")
    obj = api.call("/git/ref/tags/" + tag)["object"]
    for _ in range(8):
        if obj["type"] == "commit":
            break
        require(obj["type"] == "tag", "Version ref is not a commit or annotated tag")
        obj = api.call("/git/tags/" + obj["sha"])["object"]
    require(obj["type"] == "commit" and SHA.fullmatch(obj["sha"]), "Invalid tag target")
    sha = obj["sha"]
    require(not expected or sha == expected, "Tag does not match the approved commit")
    main = api.main()
    comparison = api.call(f"/compare/{sha}...{main}")
    require(comparison["merge_base_commit"]["sha"] == sha, "Released commit is not on main")
    return sha


def publisher_runs(api, tag, sha):
    runs = api.pages(f"/actions/runs?head_sha={sha}", "workflow_runs")
    result = {}
    for workflow in ("release.yml", "container.yml"):
        matches = [r for r in runs if r["path"] == ".github/workflows/" + workflow
                   and r["head_sha"] == sha and r["head_branch"] == tag
                   and r["event"] in ("push", "workflow_dispatch")]
        if not matches:
            raise Pending(f"No {workflow} run for {tag}/{sha}")
        run = max(matches, key=lambda r: r["id"])
        if run["status"] != "completed":
            raise Pending(f"{workflow} is still {run['status']}")
        require(run["conclusion"] == "success", f"Latest {workflow} attempt did not pass")
        jobs = api.pages(f"/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
        names = {j["name"] for j in jobs if j["head_sha"] == sha
                 and j["status"] == "completed" and j["conclusion"] == "success"}
        require({"verify", "publish"} <= names, f"{workflow} did not verify AND publish this exact source")
        require(all(j["conclusion"] == "success" for j in jobs), "Publisher contains a failed or skipped job")
        result[workflow] = {"run_id": run["id"], "attempt": run["run_attempt"], "url": run["html_url"]}
    return result


def expected_assets(tag):
    version_key(tag)
    version = tag[1:]
    archives = [f"fv-ssh-unlock_{version}_{system}_{arch}." + ("zip" if system == "windows" else "tar.gz")
                for system in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]
    packages = [f"fv-ssh-unlock_{version}_linux_{arch}.{ext}"
                for arch in ("amd64", "arm64") for ext in ("deb", "rpm")]
    payloads = archives + packages
    return set(payloads + [p + ".sbom.json" for p in payloads])


def checksum_entries(data, required):
    entries = {}
    for line in data.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None and match[2] not in entries, "Invalid or duplicate checksum entry")
        entries[match[2]] = match[1]
    require(set(entries) == required, "Incomplete or unexpected release checksum manifest")
    return entries


def verify_source(api, tag, sha):
    url = f"https://github.com/{SOURCE}/archive/refs/tags/{tag}.tar.gz"
    data = download(url)
    tree = api.call(f"/git/trees/{sha}?recursive=1")
    require(not tree.get("truncated"), "Source tree was truncated")
    expected = {x["path"]: x for x in tree["tree"] if x["type"] != "tree"}
    actual = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            path = member.name.partition("/")[2]
            require(path in expected and path not in actual, "Unexpected source archive member")
            entry = expected[path]
            require(entry["type"] == "blob", "Unsupported source-tree entry")
            if entry["mode"] == "120000" and member.issym():
                content = member.linkname.encode()
            else:
                require(entry["mode"] in ("100644", "100755") and member.isfile()
                        and member.size <= 20_000_000, "Unsupported source member type or size")
                content = archive.extractfile(member).read()
            blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            require(blob == entry["sha"], "Source archive differs from approved Git tree")
            actual.add(path)
    require(actual == set(expected), "Source archive omits tracked files")
    return {"url": url, "sha256": sha256(data), "files_verified": len(actual)}


def verify_container(tag, sha):
    token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + IMAGE + ":pull"
    token = json.loads(download(token_url, limit=100_000))["token"]
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"}
    root = "https://registry-1.docker.io/v2/" + IMAGE

    def object_bytes(kind, ref):
        require(ref == tag or re.fullmatch(r"sha256:[0-9a-f]{64}", ref), "Invalid registry reference")
        data = download(f"{root}/{kind}/{ref}", headers=headers, limit=5_000_000)
        digest = "sha256:" + sha256(data)
        require(ref == tag or ref == digest, "Registry content digest mismatch")
        return data, digest

    raw, digest = object_bytes("manifests", tag)
    index = json.loads(raw)
    manifests = index.get("manifests", [])
    images = [m for m in manifests if m.get("platform", {}).get("os") == "linux"]
    require(sorted(m["platform"]["architecture"] for m in images) == ["amd64", "arm64"], "Missing release image platform")
    attestations = [m for m in manifests if m.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"]
    require(len(attestations) == 2 and {m["annotations"].get("vnd.docker.reference.digest") for m in attestations}
            == {m["digest"] for m in images}, "Missing per-platform attestations")
    for image in images:
        raw, _ = object_bytes("manifests", image["digest"])
        manifest = json.loads(raw)
        config, _ = object_bytes("blobs", manifest["config"]["digest"])
        labels = json.loads(config).get("config", {}).get("Labels", {})
        require(labels.get("org.opencontainers.image.revision") == sha, "Container source revision does not match tag")
    subprocess.run(["cosign", "verify", "--certificate-identity",
                    f"https://github.com/{SOURCE}/.github/workflows/container.yml@refs/tags/{tag}",
                    "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", IMAGE + "@" + digest],
                   check=True, stdout=subprocess.DEVNULL, timeout=120)
    return digest


def verify_release(tag, expected="", *, full=True, wait=0, api=None):
    api = api or API(SOURCE)
    sha = resolve_tag(api, tag, expected)
    deadline = time.monotonic() + wait
    while True:
        try:
            runs = publisher_runs(api, tag, sha)
            break
        except Pending:
            if time.monotonic() >= deadline:
                raise
            time.sleep(15)
    release = api.call("/releases/tags/" + tag)
    require(not release["draft"] and release.get("immutable") is True and release["tag_name"] == tag,
            "Release is not a published immutable upstream release")
    require(release["prerelease"] == (version_key(tag)[3] == 0), "Release channel and tag disagree")
    required = expected_assets(tag)
    assets = {a["name"]: a for a in release["assets"]}
    require(required | {"checksums.txt", "checksums.txt.sigstore.json"} <= assets.keys(), "Release assets are incomplete")
    base = f"https://github.com/{SOURCE}/releases/download/{tag}/"

    def asset_bytes(name):
        asset = assets[name]
        require(asset["browser_download_url"] == base + name and asset["state"] == "uploaded", "Unexpected release asset")
        data = download(base + name)
        require(len(data) == asset["size"] and asset.get("digest") == "sha256:" + sha256(data), "Release asset digest mismatch")
        return data

    checksums = asset_bytes("checksums.txt")
    signature = asset_bytes("checksums.txt.sigstore.json")
    entries = checksum_entries(checksums, required)
    with tempfile.TemporaryDirectory(prefix="verified-release-") as directory:
        path = Path(directory)
        (path / "checksums.txt").write_bytes(checksums)
        (path / "bundle.json").write_bytes(signature)
        subprocess.run(["cosign", "verify-blob", "--bundle", str(path / "bundle.json"),
                        "--certificate-identity", f"https://github.com/{SOURCE}/.github/workflows/release.yml@refs/tags/{tag}",
                        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", str(path / "checksums.txt")],
                       check=True, timeout=120)
    for name, digest in entries.items():
        require(assets[name].get("digest") == "sha256:" + digest, "Signed checksum differs from release metadata")
        if full:
            data = asset_bytes(name)
            require(sha256(data) == digest, "Downloaded bytes differ from signed checksum")
            if name.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    require("fv-ssh-unlock.exe" in archive.namelist(), "Windows archive is missing its executable")
            elif name.endswith(".sbom.json"):
                require(isinstance(json.loads(data), dict), "SBOM is not a JSON object")
    source = verify_source(api, tag, sha)
    image = verify_container(tag, sha)
    require(resolve_tag(api, tag, sha) == sha, "Release tag changed during verification")
    return {"schema": 1, "tag": tag, "version": tag[1:], "commit": sha, "release_id": release["id"],
            "release_url": release["html_url"], "source": source, "sha256": entries, "image_digest": image,
            "publishers": runs, "payloads_downloaded": full,
            "verified_at": datetime.now(timezone.utc).isoformat()}


def candidate_release(api, channel, tag=""):
    require(channel in ("stable", "preview"), "Channel must be stable or preview")
    releases = [api.call("/releases/tags/" + tag)] if tag else api.pages("/releases")
    eligible = []
    for release in releases:
        if release["draft"] or not VERSION.fullmatch(release["tag_name"]):
            continue
        key = version_key(release["tag_name"])
        require(release["prerelease"] == (key[3] == 0), "Release channel mismatch")
        if channel == "preview" or not release["prerelease"]:
            eligible.append(release)
    require(eligible, "No published release matches the requested channel")
    return max(eligible, key=lambda r: version_key(r["tag_name"]))


def formula_version(text):
    match = re.search(r'^  url "https://github.com/shoon/fv-ssh-unlock/archive/refs/tags/(v[^"/]+)\.tar\.gz"$', text, re.M)
    require(match is not None, "Unrecognized fv-ssh-unlock formula source")
    version_key(match[1])
    return match[1]


def bump_formula(text, report):
    formula_version(text)
    require(DIGEST.fullmatch(report["source"]["sha256"]), "Invalid source hash")
    text, count = re.subn(r'^  url "[^"\n]+"$', '  url "' + report["source"]["url"] + '"', text, count=1, flags=re.M)
    require(count == 1, "Formula source is ambiguous")
    text, count = re.subn(r'^  sha256 "[0-9a-f]{64}"$', '  sha256 "' + report["source"]["sha256"] + '"', text, count=1, flags=re.M)
    require(count == 1, "Formula checksum is ambiguous")
    text, _ = re.subn(r'\n  bottle do\n(?:    [^\n]*\n)*  end\n', "", text)
    require("  bottle do" not in text, "Unrecognized bottle block; manual review required")
    return text


def bump_manifest(text, report):
    data = json.loads(text)
    require(data.get("bin") == "fv-ssh-unlock.exe" and set(data["architecture"]) == {"64bit", "arm64"}, "Unexpected manifest layout")
    for key, arch in (("64bit", "amd64"), ("arm64", "arm64")):
        filename = f"fv-ssh-unlock_{report['version']}_windows_{arch}.zip"
        data["architecture"][key]["url"] = f"https://github.com/{SOURCE}/releases/download/{report['tag']}/{filename}"
        data["architecture"][key]["hash"] = report["sha256"][filename]
    data["version"] = report["version"]
    return json.dumps(data, indent=4) + "\n"


def good_checks(api, sha):
    checks = api.pages(f"/commits/{sha}/check-runs?filter=latest", "check_runs")
    require(checks and all(c["head_sha"] == sha and c["status"] == "completed"
                           and c["conclusion"] == "success" for c in checks), "Missing, pending, neutral, or failed commit check")
    statuses = api.pages(f"/commits/{sha}/statuses")
    newest = {}
    for status in statuses:
        newest.setdefault(status["context"], status)
    require(all(s["state"] == "success" for s in newest.values()), "Pending or failed legacy status")


def create_package_pr(api, main, branch, changes, title, instructions):
    require(api.repo in (TAP, BUCKET) and api.main() == main, "Package main changed; sync again")
    allowed = {FORMULA} if api.repo == TAP else {MANIFEST, "bucket/audio-fade-fixer.json", "bucket/takeout-helper-gphotos.json"}
    require(changes and set(changes) <= allowed, "Unexpected generated PR file")
    prs = api.pages("/pulls?state=all&base=main&head=shoon:" + urllib.parse.quote(branch, safe=""))
    require(len(prs) <= 1, "Multiple PRs claim the managed branch")
    pr = prs[0] if prs else None
    if pr and pr["state"] != "open":
        summary("The generated PR was already closed; not reopening or overriding that decision.")
        return pr
    old = api.call("/git/ref/heads/" + branch, missing=True)
    parents = [main]
    if old:
        old_sha = old["object"]["sha"]
        if pr:
            require(pr["user"]["login"] == BOT and pr["head"]["repo"]["full_name"] == api.repo, "Managed PR identity changed")
            marker = MARKER.search(pr.get("body") or "")
            require(marker is not None, "Managed PR lacks its integrity marker")
            state = json.loads(marker[1])
            require(set(state["files"]) == set(changes), "Managed PR file set changed")
            for path, digest in state["files"].items():
                require(sha256(api.file(path, old_sha).encode()) == digest, "Generated branch was edited; not overwriting it")
            comparison = api.call(f"/compare/{state['base']}...{old_sha}")
            require({f["filename"] for f in comparison.get("files", [])} <= allowed, "Generated branch contains unrelated edits")
            if state["base"] == main and all(api.file(path, old_sha) == content for path, content in changes.items()):
                summary(f"Existing update: {pr['html_url']} — approve its workflows if GitHub requests approval.")
                return pr
            parents = [old_sha, main]
        else:
            # Recover only our exact orphaned first commit after PR creation failed.
            commit = api.call("/git/commits/" + old_sha)
            require([p["sha"] for p in commit["parents"]] == [main], "Unmanaged branch already exists")
            comparison = api.call(f"/compare/{main}...{old_sha}")
            require({f["filename"] for f in comparison.get("files", [])} == set(changes)
                    and all(api.file(path, old_sha) == content for path, content in changes.items()), "Unmanaged branch content differs")
            parents = []
    state = {"base": main, "files": {path: sha256(content.encode()) for path, content in changes.items()}}
    body = instructions + "\n\n<!-- release-sync " + json.dumps(state, sort_keys=True) + " -->\n"
    require(api.main() == main, "Package main changed during preparation")
    if parents:
        tree = api.call("/git/trees", {"base_tree": api.call("/git/commits/" + main)["tree"]["sha"],
                                     "tree": [{"path": path, "type": "blob", "mode": "100644", "content": text}
                                              for path, text in changes.items()]})
        commit = api.call("/git/commits", {"message": title, "tree": tree["sha"], "parents": list(dict.fromkeys(parents))})
        require(api.main() == main, "Package main changed before branch update")
        if old:
            require(api.call("/git/ref/heads/" + branch)["object"]["sha"] == old_sha, "Managed branch changed concurrently")
            api.call("/git/refs/heads/" + branch, {"sha": commit["sha"], "force": False}, method="PATCH")
        else:
            api.call("/git/refs", {"ref": "refs/heads/" + branch, "sha": commit["sha"]})
    if pr:
        pr = api.call(f"/pulls/{pr['number']}", {"title": title, "body": body}, method="PATCH")
    else:
        pr = api.call("/pulls", {"title": title, "head": branch, "base": "main", "body": body})
    summary(f"Prepared {pr['html_url']}. No main branch was changed. Approve PR workflows if GitHub requests approval.")
    if api.repo == BUCKET:
        # This is an exact managed branch made only of allowlisted manifest data.
        # Explicit read-only validation avoids relying on a token-authored push.
        api.call("/actions/workflows/validate.yml/dispatches", {"ref": branch})
    return pr


def sync_package(tag="", channel="", *, dry_run=False):
    repo = os.environ["GITHUB_REPOSITORY"]
    require(repo in (TAP, BUCKET) and (dry_run or os.environ["GITHUB_REF"] == "refs/heads/main"), "Sync must run on package main")
    api = API(repo, write=not dry_run)
    main = api.main()
    if not dry_run:
        require(os.environ["GITHUB_SHA"] == main, "Sync workflow is stale; run it again on main")
    config = json.loads(api.file(".github/fv-release-channel.json", main)) if not channel else {"channel": channel}
    channel = config["channel"]
    release = candidate_release(API(SOURCE), channel, tag)
    tag = release["tag_name"]
    path = FORMULA if repo == TAP else MANIFEST
    original = api.file(path, main)
    current = formula_version(original) if repo == TAP else "v" + json.loads(original)["version"]
    if version_key(tag) <= version_key(current):
        summary(f"{repo} already has {current}; no downgrade or same-version rewrite.")
        outputs(changed="false", tag=tag)
        return
    report = verify_release(tag)
    content = bump_formula(original, report) if repo == TAP else bump_manifest(original, report)
    if dry_run:
        summary(f"Dry run: verified {tag}; would update only {repo}/{path}.")
        outputs(changed="true", tag=tag)
        return
    instructions = (f"Upstream: {report['release_url']}\n\nVerified source `{report['commit']}`, signed checksums, downloaded assets, "
                    "and the signed multi-platform container. This PR changes only package metadata.\n\n"
                    "Approve GitHub's PR workflow runs if prompted. Never merge with failed or pending checks.\n\n")
    instructions += ("For prebuilt Homebrew bottles, comment `/publish FULL_CURRENT_HEAD_SHA` after both test-bot jobs pass. "
                     "Do not squash this formula PR: the guarded publisher incorporates it with its tested bottles. "
                     "Ordinary Dependabot/workflow PRs still use normal merges."
                     if repo == TAP else "Merge this manifest PR normally after validation. No separate Scoop publication is required.")
    pr = create_package_pr(api, main, "automation/fv-ssh-unlock-" + tag, {path: content},
                           "fv-ssh-unlock: update to " + tag[1:], instructions)
    outputs(changed="true", tag=tag, pr=pr["number"], pr_url=pr["html_url"])



def staged_package_pr(*, dry_run=False):
    """Retain other existing Scoop updaters, but put their changes through PRs."""
    require(os.environ.get("GITHUB_REPOSITORY") == BUCKET and os.environ["GITHUB_REF"] == "refs/heads/main",
            "Staged updates must run on Scoop main")
    api = API(BUCKET, write=not dry_run)
    main = api.main()
    require(os.environ["GITHUB_SHA"] == main, "Staged-update workflow is stale")
    changes = {}
    for project in ("audio-fade-fixer", "takeout-helper-gphotos"):
        path = "bucket/" + project + ".json"
        original = json.loads(api.file(path, main))
        text = Path(path).read_text(encoding="utf-8-sig")
        proposed = json.loads(text)
        if original == proposed:
            continue
        tag = "v" + proposed["version"]
        require(version_key(tag)[3] == 1 and version_key(tag) > version_key("v" + original["version"]),
                "Legacy stable updates cannot promote previews or downgrade")
        release = API("shoon/" + project).call("/releases/tags/" + tag)
        require(not release["draft"] and not release["prerelease"] and release["tag_name"] == tag,
                "Expected a published stable release")
        assets = {a["browser_download_url"]: a for a in release["assets"]}
        expected = json.loads(json.dumps(original))
        require(set(proposed["architecture"]) == set(original["architecture"]), "Architecture set changed")
        for arch in original["architecture"]:
            entry = proposed["architecture"][arch]
            prefix = f"https://github.com/shoon/{project}/releases/download/{tag}/"
            require(entry["url"].startswith(prefix) and entry["url"] in assets and DIGEST.fullmatch(entry["hash"]),
                    "Unexpected stable release URL/hash")
            asset = assets[entry["url"]]
            data = download(entry["url"])
            require(asset["state"] == "uploaded" and asset.get("digest") == "sha256:" + entry["hash"]
                    and sha256(data) == entry["hash"], "Stable release integrity check failed")
            expected["architecture"][arch]["url"] = entry["url"]
            expected["architecture"][arch]["hash"] = entry["hash"]
        expected["version"] = proposed["version"]
        require(expected == proposed, "Stable updater modified fields other than version, URLs and hashes")
        changes[path] = json.dumps(proposed, indent=4) + "\n"
    if not changes:
        summary("Other Scoop manifests are current; no PR needed.")
        return
    if dry_run:
        summary("Dry run: verified staged stable manifests without writing anything.")
        return
    suffix = sha256(json.dumps(changes, sort_keys=True).encode())[:12]
    create_package_pr(api, main, "automation/stable-packages-" + suffix, changes, "Update stable Scoop packages",
                      "Existing Audio Fade Fixer/Takeout Helper updates, now through a PR rather than direct main writes. "
                      "All staged manifests passed validation and their assets were downloaded and hashed. "
                      "Merge after the exact-head Validate bucket check passes.")



def approval_request(api, event):
    kind = os.environ["GITHUB_EVENT_NAME"]
    require(api.repo == TAP and os.environ["GITHUB_REF"] == "refs/heads/main", "Publishing authorization must run on tap main")
    if kind == "issue_comment":
        require(event.get("action") == "created" and "pull_request" in event.get("issue", {}), "Not a new PR comment")
        comment = event["comment"]
        require(comment["user"]["type"] == "User", "Bots cannot authorize publication")
        match = re.fullmatch(r"/publish ([0-9a-f]{40})", comment["body"].strip())
        require(match is not None, "Use /publish FULL_CURRENT_HEAD_SHA")
        number, head, actor = event["issue"]["number"], match[1], comment["user"]["login"]
        fresh = api.call(f"/issues/comments/{comment['id']}")
        require(fresh["body"] == comment["body"] and fresh["user"]["login"] == actor, "Approval comment changed")
    else:
        require(kind == "workflow_dispatch", "Unsupported approval event")
        inputs = event["inputs"]
        require(re.fullmatch(r"[1-9][0-9]*", str(inputs["pull_request"])), "Invalid PR number")
        number, head, actor = int(inputs["pull_request"]), inputs["head_sha"], os.environ["GITHUB_ACTOR"]
    require(SHA.fullmatch(head), "Approval must name the full current head SHA")
    permission = api.call("/collaborators/" + urllib.parse.quote(actor, safe="") + "/permission")
    require(permission.get("permission") in ("admin", "maintain", "write"), "Only a current repository writer may authorize publication")
    return number, head


def publish_check(event):
    api = API(TAP)
    require(os.environ.get("GITHUB_REPOSITORY") == TAP, "Wrong publishing repository")
    number, head = approval_request(api, event)
    pr = api.call(f"/pulls/{number}")
    main = api.main()
    require(os.environ["GITHUB_SHA"] == main, "Tap main changed; issue a fresh publication request")
    require(pr["state"] == "open" and not pr["draft"] and pr["head"]["sha"] == head
            and pr["head"]["repo"]["full_name"] == TAP and pr["base"]["ref"] == "main", "PR identity or approved head changed")
    comparison = api.call(f"/compare/{main}...{head}")
    require(comparison["merge_base_commit"]["sha"] == main, "PR needs updating and fresh tests against current main")
    files = api.pages(f"/pulls/{number}/files")
    require(len(files) == 1 and files[0]["filename"] == FORMULA and files[0]["status"] == "modified", "Only an fv-ssh-unlock formula version update may use this publisher")
    good_checks(api, head)
    reviews = api.pages(f"/pulls/{number}/reviews")
    latest = {}
    for review in reviews:
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[review["user"]["login"]] = review["state"]
    require("CHANGES_REQUESTED" not in latest.values(), "An unresolved change-request review blocks publishing")
    require(pr.get("mergeable") is True and pr.get("mergeable_state") == "clean", "GitHub does not report a clean, unblocked PR")
    runs = api.pages(f"/actions/runs?head_sha={head}", "workflow_runs")
    candidates = [r for r in runs if r["path"] == ".github/workflows/tests.yml" and r["event"] == "pull_request" and r["head_sha"] == head]
    require(candidates, "Missing PR bottle-build workflow")
    run = max(candidates, key=lambda r: r["id"])
    require(run["status"] == "completed" and run["conclusion"] == "success", "Latest bottle workflow has not passed")
    jobs = api.pages(f"/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
    require({"test-bot (macos-26)", "test-bot (ubuntu-latest, ghcr.io/homebrew/brew:main, --privileged)"}
            <= {j["name"] for j in jobs if j["conclusion"] == "success" and j["head_sha"] == head}, "Missing a successful bottle platform")
    artifacts = api.pages(f"/actions/runs/{run['id']}/artifacts", "artifacts")
    expected = {"bottles_macos-26", "bottles_ubuntu-latest"}
    selected = [a for a in artifacts if a["name"] in expected]
    require(len(selected) == 2 and {a["name"] for a in selected} == expected
            and all(not a["expired"] and a["workflow_run"]["head_sha"] == head for a in selected), "Missing, expired, or wrong-source bottle artifacts")
    proposed = api.file(FORMULA, head)
    tag = formula_version(proposed)
    original = api.file(FORMULA, main)
    require(version_key(tag) > version_key(formula_version(original)), "Not a new formula version")
    report = verify_release(tag)
    require(proposed == bump_formula(original, report), "Formula contains changes other than the verified version/hash update")
    require(api.call("/releases/tags/fv-ssh-unlock-" + tag[1:], missing=True) is None, "Bottles already published; do not overwrite or republish")
    require(api.main() == main and api.call(f"/pulls/{number}")["head"]["sha"] == head, "Source changed during publication preflight")
    outputs(pr=number, head=head, base=main, tag=tag)
    summary(f"Authorized Homebrew PR #{number} at `{head}`, tested against `{main}`, for `{tag}`. Publication has not run yet.")


def distribution_status(report):
    tag, version = report["tag"], report["version"]
    rows = []
    for repo, path in ((TAP, FORMULA), (BUCKET, MANIFEST)):
        api = API(repo)
        main = api.main()
        content = api.file(path, main)
        ready = False
        if repo == BUCKET:
            manifest = json.loads(content)
            # Formatting is not an integrity condition.
            ready = manifest == json.loads(bump_manifest(content, report)) and manifest["version"] == version
        elif formula_version(content) == tag:
            source_ok = '  sha256 "' + report["source"]["sha256"] + '"' in content
            bottle = api.call("/releases/tags/fv-ssh-unlock-" + version, missing=True)
            if source_ok and bottle and not bottle["draft"]:
                assets = {a["name"]: a for a in bottle["assets"]}
                ready = True
                for platform in ("arm64_tahoe", "x86_64_linux"):
                    match = re.search(platform + r':\s+"([0-9a-f]{64})"', content)
                    name = f"fv-ssh-unlock-{version}.{platform}.bottle.tar.gz"
                    ready = ready and match is not None and name in assets and assets[name].get("digest") == "sha256:" + match[1]
        smoke = api.pages(f"/actions/runs?head_sha={main}", "workflow_runs")
        matches = [r for r in smoke if r["path"] == ".github/workflows/feed-smoke.yml" and r["head_branch"] == "main"]
        passed = bool(matches) and max(matches, key=lambda r: r["id"])["conclusion"] == "success"
        rows.append({"repository": repo, "main": main, "feed_current": bool(ready), "install_test_passed": passed})
    return rows


def write_status_issue(report, rows):
    require(os.environ.get("GITHUB_REPOSITORY") == SOURCE and os.environ["GITHUB_REF"] == "refs/heads/main", "Status reports must run on source main")
    api = API(SOURCE, write=True)
    complete = all(row["feed_current"] and row["install_test_passed"] for row in rows)
    title = "Release distribution: " + report["tag"]
    marker = "<!-- release-distribution:" + report["tag"] + " -->"
    body = marker + "\n\n" + ("**Distribution complete.**" if complete else "**Native release verified; package distribution or installation tests pending.**")
    body += f"\n\nSource: `{report['commit']}`\nRelease: {report['release_url']}\nContainer: `{IMAGE}@{report['image_digest']}`\n\n"
    body += "| Feed | Version and hashes | Clean installation test | Main |\n|---|---|---|---|\n"
    for row in rows:
        body += f"| {row['repository']} | {'Current' if row['feed_current'] else 'Pending'} | {'Passed' if row['install_test_passed'] else 'Pending / failed'} | `{row['main']}` |\n"
    body += "\nThis read-only verification report never merges package PRs or republishes artifacts.\n"
    issues = [i for i in api.pages("/issues?state=all&creator=github-actions%5Bbot%5D")
              if "pull_request" not in i and marker in (i.get("body") or "")]
    require(len(issues) <= 1, "Multiple release status issues found")
    state = "closed" if complete else "open"
    if issues:
        issue = issues[0]
        if issue["body"] != body or issue["state"] != state:
            api.call(f"/issues/{issue['number']}", {"body": body, "state": state}, method="PATCH")
    else:
        issue = api.call("/issues", {"title": title, "body": body})
        if complete:
            api.call(f"/issues/{issue['number']}", {"state": "closed"}, method="PATCH")
    summary(body.replace(marker, ""))


def main():
    operation = os.environ.get("OPERATION", "verify")
    tag = os.environ.get("RELEASE_TAG", "")
    expected = os.environ.get("EXPECTED_SHA", "")
    channel = os.environ.get("RELEASE_CHANNEL", "")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()) if os.environ.get("GITHUB_EVENT_PATH") else {}
    if operation in ("verify", "status"):
        if not tag and event.get("workflow_run"):
            tag, expected = event["workflow_run"]["head_branch"], event["workflow_run"]["head_sha"]
        if not tag:
            tag = candidate_release(API(SOURCE), channel or "preview")["tag_name"]
        report = verify_release(tag, expected, full=operation == "verify", wait=900 if event.get("workflow_run") else 0)
        destination = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / ("verified-" + tag + ".json")
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        outputs(tag=tag, commit=report["commit"], report_path=str(destination))
        if operation == "status":
            write_status_issue(report, distribution_status(report))
        else:
            summary(f"Verified native release `{tag}` at `{report['commit']}`; all signed payloads downloaded and the signed multi-platform image verified.\n\nRelease: {report['release_url']}\n\nPackage approval/distribution is separate; consult Release distribution status.")
    elif operation == "sync":
        sync_package(tag, channel, dry_run=os.environ.get("DRY_RUN", "true") != "false")
    elif operation == "stage-pr":
        staged_package_pr(dry_run=os.environ.get("DRY_RUN", "true") != "false")
    elif operation == "publish-check":
        publish_check(event)
    else:
        raise Refused("Unknown release operation")


if __name__ == "__main__":
    try:
        main()
    except (Refused, KeyError, ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Release operation refused: {error}", file=sys.stderr)
        sys.exit(1)

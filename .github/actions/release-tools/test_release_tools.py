# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release_tools", Path(__file__).with_name("release_tools.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
A, B, C = "a" * 40, "b" * 40, "c" * 40
H = "a" * 64
TAG = "v0.2.0-rc.5"
FORMULA = '''class FvSshUnlock < Formula
  desc "A test formula"
  url "https://github.com/shoon/fv-ssh-unlock/archive/refs/tags/v0.2.0-rc.4.tar.gz"
  sha256 "''' + H + '''"
  bottle do
    root_url "https://old.example"
    sha256 cellar: :any_skip_relocation, arm64_tahoe: "''' + H + '''"
  end
  def install
    system "go", "build"
  end
end
'''
REPORT = {"tag": TAG, "version": TAG[1:], "commit": A,
          "source": {"url": f"https://github.com/{t.SOURCE}/archive/refs/tags/{TAG}.tar.gz", "sha256": "b" * 64},
          "sha256": {f"fv-ssh-unlock_{TAG[1:]}_windows_{arch}.zip": "b" * 64 for arch in ("amd64", "arm64")}}


class FakeAPI:
    def __init__(self, responses=None, repo=t.TAP):
        self.responses = responses or {}
        self.repo = repo
        self.writes = []
        self.mains = [A]
        self.files = {}
        self.prs = []

    def main(self):
        return self.mains.pop(0) if len(self.mains) > 1 else self.mains[0]

    def file(self, path, ref):
        return self.files[path, ref]

    def pages(self, path, key=None):
        if path.startswith("/pulls?state=all"):
            return self.prs
        return copy.deepcopy(self.responses[path])

    def call(self, path, payload=None, **kwargs):
        if payload is not None:
            self.writes.append((path, payload, kwargs))
            if path == "/git/trees":
                return {"sha": B}
            if path == "/git/commits":
                return {"sha": C}
            if path == "/pulls" or path == "/pulls/7":
                return {"number": 7, "html_url": "https://github.com/shoon/homebrew-tap/pull/7"}
            return None
        if path == "/git/commits/" + A:
            return {"tree": {"sha": B}}
        if path in self.responses:
            return copy.deepcopy(self.responses[path])
        if kwargs.get("missing"):
            return None
        raise AssertionError("Unexpected API call " + path)


def release(tag, *, draft=False, prerelease=None):
    return {"tag_name": tag, "draft": draft, "prerelease": "-" in tag if prerelease is None else prerelease}


class Versions(unittest.TestCase):
    def test_order(self):
        tags = ["v0.1.0", "v0.2.0-alpha.1", "v0.2.0-beta.1", "v0.2.0-rc.4", "v0.2.0-rc.10", "v0.2.0", "v1.0.0"]
        self.assertEqual(sorted(tags, key=t.version_key), tags)

    def test_invalid_versions(self):
        for tag in ("v01.0.0", "v1.0", "v1.0.0-rc.01", "v1.0.0\n", "v1.0.0;id", "v1.0.0/../../x", "1.0.0", "v1.0.0+build"):
            with self.subTest(tag=tag), self.assertRaises(t.Refused):
                t.version_key(tag)

    def test_stable_excludes_preview_and_drafts(self):
        api = FakeAPI({"/releases": [release("v0.2.0-rc.5"), release("v0.1.0"), release("v9.0.0", draft=True)]})
        self.assertEqual(t.candidate_release(api, "stable")["tag_name"], "v0.1.0")
        self.assertEqual(t.candidate_release(api, "preview")["tag_name"], "v0.2.0-rc.5")

    def test_channel_mismatch_refused(self):
        with self.assertRaises(t.Refused):
            t.candidate_release(FakeAPI({"/releases": [release("v1.0.0", prerelease=True)]}), "preview")

    def test_manual_prerelease_requires_preview(self):
        with self.assertRaises(t.Refused):
            t.candidate_release(FakeAPI({"/releases/tags/" + TAG: release(TAG)}), "stable", TAG)

    def test_unknown_channel_refused(self):
        with self.assertRaises(t.Refused):
            t.candidate_release(FakeAPI(), "anything")


class Integrity(unittest.TestCase):
    def test_asset_matrix(self):
        names = t.expected_assets(TAG)
        self.assertEqual(len(names), 20)
        self.assertIn("fv-ssh-unlock_0.2.0-rc.5_windows_arm64.zip", names)
        self.assertIn("fv-ssh-unlock_0.2.0-rc.5_linux_arm64.rpm.sbom.json", names)

    def test_checksum_manifest(self):
        self.assertEqual(t.checksum_entries((H + "  a.zip\n").encode(), {"a.zip"}), {"a.zip": H})

    def test_invalid_checksum_manifests(self):
        for text in (H + "  ../a.zip\n", H + " a.zip\n", H + "  a.zip\n" + H + "  a.zip\n", "", H + "  unexpected.zip\n"):
            with self.subTest(text=text), self.assertRaises(t.Refused):
                t.checksum_entries(text.encode(), {"a.zip"})

    def test_unsafe_download_rejected_before_network(self):
        for url in ("http://example.com", "https://user:pass@example.com", "file:///etc/passwd"):
            with self.subTest(url=url), patch("urllib.request.build_opener") as opener, self.assertRaises(t.Refused):
                t.download(url)
            opener.assert_not_called()

    def test_redirect_strips_secrets(self):
        req = t.urllib.request.Request("https://github.com/a", headers={"Authorization": "Bearer secret", "Cookie": "secret"})
        redirected = t.SafeRedirect().redirect_request(req, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/a")
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertIsNone(redirected.get_header("Cookie"))

    def test_redirect_downgrade_refused(self):
        req = t.urllib.request.Request("https://github.com/a")
        with self.assertRaises(t.Refused):
            t.SafeRedirect().redirect_request(req, None, 302, "Found", {}, "http://example.com/a")

    def test_readonly_and_crossrepo_writes_refused(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": t.TAP}):
            with self.assertRaises(t.Refused):
                t.API(t.TAP).call("/git/refs", {"anything": "write"})
            with self.assertRaises(t.Refused):
                t.API(t.SOURCE, write=True).call("/git/refs", {"anything": "write"})

    def test_repository_allowlist(self):
        with self.assertRaises(t.Refused):
            t.API("attacker/repo")

    def test_tag_binding(self):
        api = FakeAPI({"/git/ref/tags/" + TAG: {"object": {"type": "commit", "sha": A}},
                       f"/compare/{A}...{A}": {"merge_base_commit": {"sha": A}}})
        self.assertEqual(t.resolve_tag(api, TAG, A), A)
        with self.assertRaises(t.Refused):
            t.resolve_tag(api, TAG, B)

    def test_nonmain_tag_refused(self):
        api = FakeAPI({"/git/ref/tags/" + TAG: {"object": {"type": "commit", "sha": B}},
                       f"/compare/{B}...{A}": {"merge_base_commit": {"sha": C}}})
        with self.assertRaises(t.Refused):
            t.resolve_tag(api, TAG)

    def test_annotated_tag_is_peeled(self):
        api = FakeAPI({"/git/ref/tags/" + TAG: {"object": {"type": "tag", "sha": B}},
                       "/git/tags/" + B: {"object": {"type": "commit", "sha": A}},
                       f"/compare/{A}...{A}": {"merge_base_commit": {"sha": A}}})
        self.assertEqual(t.resolve_tag(api, TAG), A)


class PackageFiles(unittest.TestCase):
    def test_formula_only_version_hash_and_bottle_block(self):
        result = t.bump_formula(FORMULA, REPORT)
        self.assertNotIn("bottle do", result)
        self.assertIn(TAG, result)
        self.assertIn('system "go", "build"', result)
        self.assertIn(REPORT["source"]["sha256"], result)

    def test_noncanonical_formula_requires_review(self):
        with self.assertRaises(t.Refused):
            t.bump_formula(FORMULA.replace("  bottle do", "  bottle do # edited"), REPORT)

    def test_foreign_source_formula_rejected(self):
        with self.assertRaises(t.Refused):
            t.bump_formula(FORMULA.replace("shoon/fv-ssh-unlock", "attacker/fv-ssh-unlock"), REPORT)

    def test_manifest_preserves_unrelated_metadata(self):
        manifest = {"version": "0.2.0-rc.4", "bin": "fv-ssh-unlock.exe", "notes": "retain me",
                    "architecture": {"64bit": {}, "arm64": {}}, "autoupdate": {"unchanged": True}}
        result = json.loads(t.bump_manifest(json.dumps(manifest), REPORT))
        self.assertEqual(result["notes"], "retain me")
        self.assertEqual(result["autoupdate"], manifest["autoupdate"])
        self.assertEqual(result["version"], "0.2.0-rc.5")
        for entry in result["architecture"].values():
            self.assertTrue(entry["url"].startswith("https://github.com/shoon/fv-ssh-unlock/"))
            self.assertEqual(entry["hash"], "b" * 64)

    def test_manifest_unknown_architecture_refused(self):
        with self.assertRaises(t.Refused):
            t.bump_manifest(json.dumps({"bin": "fv-ssh-unlock.exe", "architecture": {"32bit": {}}}), REPORT)


class Checks(unittest.TestCase):
    def test_success(self):
        api = FakeAPI({f"/commits/{A}/check-runs?filter=latest": [{"head_sha": A, "status": "completed", "conclusion": "success"}],
                       f"/commits/{A}/statuses": []})
        t.good_checks(api, A)

    def test_missing_neutral_skipped_pending_and_wrong_sha_rejected(self):
        cases = [[], [{"head_sha": B, "status": "completed", "conclusion": "success"}]]
        cases += [[{"head_sha": A, "status": status, "conclusion": conclusion}]
                  for status, conclusion in (("completed", "neutral"), ("completed", "skipped"), ("in_progress", None), ("completed", "failure"))]
        for checks in cases:
            with self.subTest(checks=checks), self.assertRaises(t.Refused):
                t.good_checks(FakeAPI({f"/commits/{A}/check-runs?filter=latest": checks}), A)

    def test_new_status_failure_wins(self):
        api = FakeAPI({f"/commits/{A}/check-runs?filter=latest": [{"head_sha": A, "status": "completed", "conclusion": "success"}],
                       f"/commits/{A}/statuses": [{"context": "scan", "state": "failure"}, {"context": "scan", "state": "success"}]})
        with self.assertRaises(t.Refused):
            t.good_checks(api, A)

    def test_publishers_require_tag_and_actual_publish_jobs(self):
        runs = [{"id": i, "path": ".github/workflows/" + name, "head_sha": A, "head_branch": TAG, "event": "workflow_dispatch",
                 "status": "completed", "conclusion": "success", "run_attempt": 1, "html_url": "url"}
                for i, name in enumerate(("release.yml", "container.yml"), 1)]
        jobs = [{"name": name, "head_sha": A, "status": "completed", "conclusion": "success"} for name in ("verify", "publish")]
        api = FakeAPI({f"/actions/runs?head_sha={A}": runs, "/actions/runs/1/jobs?filter=latest": jobs, "/actions/runs/2/jobs?filter=latest": jobs})
        self.assertEqual(len(t.publisher_runs(api, TAG, A)), 2)
        api.responses["/actions/runs/1/jobs?filter=latest"] = [jobs[0]]
        with self.assertRaises(t.Refused):
            t.publisher_runs(api, TAG, A)

    def test_latest_failed_publisher_is_not_hidden_by_old_green(self):
        runs = [{"id": i, "path": ".github/workflows/release.yml", "head_sha": A, "head_branch": TAG,
                 "event": "workflow_dispatch", "status": "completed", "conclusion": status}
                for i, status in ((1, "success"), (2, "failure"))]
        with self.assertRaises(t.Refused):
            t.publisher_runs(FakeAPI({f"/actions/runs?head_sha={A}": runs}), TAG, A)

    def test_missing_publisher_is_pending(self):
        with self.assertRaises(t.Pending):
            t.publisher_runs(FakeAPI({f"/actions/runs?head_sha={A}": []}), TAG, A)


class PRWrites(unittest.TestCase):
    def test_writes_only_new_branch_and_pr(self):
        api = FakeAPI()
        t.create_package_pr(api, A, "automation/fv-ssh-unlock-" + TAG, {t.FORMULA: "new"}, "title", "body")
        paths = [p for p, _, _ in api.writes]
        self.assertEqual(paths, ["/git/trees", "/git/commits", "/git/refs", "/pulls"])
        self.assertEqual(api.writes[2][1]["ref"], "refs/heads/automation/fv-ssh-unlock-" + TAG)
        self.assertNotIn("refs/heads/main", json.dumps(api.writes))

    def test_workflow_edits_cannot_be_generated(self):
        api = FakeAPI()
        with self.assertRaises(t.Refused):
            t.create_package_pr(api, A, "automation/x", {".github/workflows/a.yml": "bad"}, "title", "body")
        self.assertEqual(api.writes, [])

    def test_stale_main_never_updates_ref(self):
        api = FakeAPI()
        api.mains = [A, B]
        with self.assertRaises(t.Refused):
            t.create_package_pr(api, A, "automation/x", {t.FORMULA: "new"}, "title", "body")
        self.assertEqual(api.writes, [])

    def test_closed_pr_not_reopened(self):
        api = FakeAPI()
        api.prs = [{"state": "closed", "number": 7}]
        t.create_package_pr(api, A, "automation/x", {t.FORMULA: "new"}, "title", "body")
        self.assertEqual(api.writes, [])

    def test_manual_edits_not_overwritten(self):
        api = FakeAPI({"/git/ref/heads/automation/x": {"object": {"sha": B}}})
        api.prs = [{"state": "open", "user": {"login": t.BOT}, "head": {"repo": {"full_name": t.TAP}},
                    "body": '<!-- release-sync ' + json.dumps({"base": A, "files": {t.FORMULA: t.sha256(b"original")}}) + ' -->'}]
        api.files[t.FORMULA, B] = "human edit"
        with self.assertRaises(t.Refused):
            t.create_package_pr(api, A, "automation/x", {t.FORMULA: "new"}, "title", "body")
        self.assertEqual(api.writes, [])

    def test_orphan_branch_must_match_exact_generated_changes(self):
        api = FakeAPI({"/git/ref/heads/automation/x": {"object": {"sha": B}},
                       "/git/commits/" + B: {"parents": [{"sha": A}]},
                       f"/compare/{A}...{B}": {"files": [{"filename": t.FORMULA}]}})
        api.files[t.FORMULA, B] = "new"
        t.create_package_pr(api, A, "automation/x", {t.FORMULA: "new"}, "title", "body")
        self.assertEqual([x[0] for x in api.writes], ["/pulls"])


class Approvals(unittest.TestCase):
    def event(self, body="/publish " + B, user_type="User"):
        return {"action": "created", "issue": {"number": 7, "pull_request": {}},
                "comment": {"id": 123, "body": body, "user": {"type": user_type, "login": "shoon"}}}

    def api(self, event, permission="admin"):
        return FakeAPI({"/issues/comments/123": event["comment"], "/collaborators/shoon/permission": {"permission": permission}})

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/main"})
    def test_exact_authorized_comment(self):
        event = self.event()
        self.assertEqual(t.approval_request(self.api(event), event), (7, B))

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/main"})
    def test_public_comment_cannot_publish(self):
        event = self.event()
        with self.assertRaises(t.Refused):
            t.approval_request(self.api(event, "read"), event)

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/main"})
    def test_bot_cannot_approve(self):
        event = self.event(user_type="Bot")
        with self.assertRaises(t.Refused):
            t.approval_request(self.api(event), event)

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/main"})
    def test_injection_and_short_sha_refused(self):
        for text in ("/publish abc123", "/publish " + B + "; echo secret", "/publish " + B + "\nrun this", "please publish"):
            event = self.event(text)
            with self.subTest(text=text), self.assertRaises(t.Refused):
                t.approval_request(self.api(event), event)

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/main"})
    def test_edited_comment_refused(self):
        event = self.event()
        api = self.api(event)
        api.responses["/issues/comments/123"] = {**event["comment"], "body": "/publish " + C}
        with self.assertRaises(t.Refused):
            t.approval_request(api, event)

    @patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REF": "refs/heads/untrusted"})
    def test_branch_context_refused(self):
        event = self.event()
        with self.assertRaises(t.Refused):
            t.approval_request(self.api(event), event)


if __name__ == "__main__":
    unittest.main()

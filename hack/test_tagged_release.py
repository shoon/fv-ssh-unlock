# SPDX-License-Identifier: Apache-2.0
"""Offline release-safety regression tests; no GitHub token or network needed."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tagged_release as release

SHA = "a" * 40
OTHER = "b" * 40
TAG = "v0.2.0-rc.4"


class FakeAPI:
    def __init__(self):
        self.main = SHA
        self.tag = None
        self.existing_release = None
        self.writes = []
        self.runs = [{"id": 10, "path": release.CI_PATH, "head_sha": SHA,
                      "head_branch": "main", "event": "push",
                      "status": "completed", "conclusion": "success",
                      "check_suite_id": 20}]
        self.jobs = [{"name": name, "head_sha": SHA, "status": "completed",
                      "conclusion": "success"} for name in release.REQUIRED_JOBS]
        self.checks = [{"name": "security", "status": "completed",
                        "conclusion": "success", "check_suite": {"id": 20}}]
        self.statuses = []

    def call(self, path, payload=None, *, missing_ok=False):
        if payload is not None:
            self.writes.append((path, payload))
            if path == "/git/refs":
                self.tag = payload["sha"]
            return None
        if path == "/git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if path.startswith("/git/ref/heads/release/request/"):
            return {"object": {"sha": OTHER}}
        if path.startswith("/git/ref/tags/"):
            return {"object": {"sha": self.tag}} if self.tag else None
        if path.startswith("/releases/tags/"):
            return self.existing_release
        raise AssertionError(path)

    def pages(self, path, key=None):
        if path.startswith("/actions/runs?"):
            return self.runs
        if "/jobs?" in path:
            return self.jobs
        if "/check-runs?" in path:
            return self.checks
        if path.endswith("/statuses"):
            return self.statuses
        raise AssertionError(path)


class ReleaseTests(unittest.TestCase):
    def test_valid_tags(self):
        for tag in ("v0.2.0", TAG, "v1.0.0-alpha.0", "v1.2.3-01a"):
            with self.subTest(tag=tag):
                release.validate(tag, SHA)

    def test_invalid_tags(self):
        for tag in ("0.2.0", "v01.2.3", "v1.2.3-rc.04", "v1.2.3+meta",
                    "v1.2.3/other", "v1.2.3\n", "v1.2.3;echo bad", "main",
                    "v1.2.3-" + "a" * 130):
            with self.subTest(tag=tag), self.assertRaises(release.ReleaseError):
                release.validate(tag, SHA)

    def test_invalid_sha(self):
        for sha in ("main", "a" * 7, "A" * 40, SHA + "\n"):
            with self.subTest(sha=sha), self.assertRaises(release.ReleaseError):
                release.validate(TAG, sha)

    def test_good_ci(self):
        release.check_ci(FakeAPI(), SHA)

    def test_missing_ci(self):
        api = FakeAPI()
        api.runs = []
        with self.assertRaises(release.ReleaseError):
            release.check_ci(api, SHA)

    def test_pr_run_is_not_main_validation(self):
        api = FakeAPI()
        api.runs[0]["event"] = "pull_request"
        with self.assertRaises(release.ReleaseError):
            release.check_ci(api, SHA)

    def test_new_failure_or_pending_run_overrides_old_success(self):
        for conclusion in ("failure", None, "cancelled"):
            api = FakeAPI()
            newest = copy.deepcopy(api.runs[0])
            newest.update(id=11, conclusion=conclusion)
            api.runs.append(newest)
            with self.subTest(conclusion=conclusion), self.assertRaises(release.ReleaseError):
                release.check_ci(api, SHA)

    def test_missing_or_failed_security_is_blocking(self):
        for remove in (True, False):
            api = FakeAPI()
            if remove:
                api.jobs = [j for j in api.jobs if j["name"] != "security"]
            else:
                next(j for j in api.jobs if j["name"] == "security")["conclusion"] = "failure"
            with self.subTest(remove=remove), self.assertRaises(release.ReleaseError):
                release.check_ci(api, SHA)

    def test_neutral_codeql_is_not_a_successful_scan(self):
        api = FakeAPI()
        api.checks[0].update(name="CodeQL", conclusion="neutral")
        with self.assertRaises(release.ReleaseError):
            release.check_ci(api, SHA)

    def test_legacy_latest_failure_blocks(self):
        api = FakeAPI()
        api.statuses = [{"context": "extra", "state": "failure"},
                        {"context": "extra", "state": "success"}]
        with self.assertRaises(release.ReleaseError):
            release.check_ci(api, SHA)
        api.statuses.reverse()
        release.check_ci(api, SHA)

    def test_expected_publish_skip_is_allowed(self):
        api = FakeAPI()
        api.checks[0].update(name="publish", conclusion="skipped")
        release.check_ci(api, SHA)
        api.checks[0]["name"] = "security"
        with self.assertRaises(release.ReleaseError):
            release.check_ci(api, SHA)

    def test_manual_preparation_does_not_block_itself(self):
        api = FakeAPI()
        api.runs.append({"id": 11, "path": ".github/workflows/prepare-release.yml",
                         "head_sha": SHA, "check_suite_id": 21})
        api.checks.append({"name": "preflight", "status": "in_progress",
                           "conclusion": None, "check_suite": {"id": 21}})
        release.check_ci(api, SHA)

    def test_stale_main_or_existing_tag_never_writes(self):
        for field, value in (("main", OTHER), ("tag", SHA), ("existing_release", {"id": 1})):
            api = FakeAPI()
            setattr(api, field, value)
            with patch.object(release, "git", return_value=SHA), self.subTest(field=field):
                with self.assertRaises(release.ReleaseError):
                    release.create(api, TAG, SHA)
                self.assertEqual(api.writes, [])

    def test_create_only_and_explicit_dispatches(self):
        api = FakeAPI()
        with patch.object(release, "git", return_value=SHA), patch.object(release, "summary"):
            release.create(api, TAG, SHA)
        self.assertEqual(api.writes[0], ("/git/refs", {"ref": f"refs/tags/{TAG}", "sha": SHA}))
        self.assertEqual([p for p, _ in api.writes[1:]], [
            "/actions/workflows/release.yml/dispatches",
            "/actions/workflows/container.yml/dispatches"])
        for _, payload in api.writes[1:]:
            self.assertEqual(payload, {"ref": TAG, "inputs": {"expected_sha": SHA}})

    def test_manual_request_exact_main(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
               "GITHUB_SHA": SHA, "RELEASE_TAG": TAG, "EXPECTED_SHA": SHA}
        with patch.dict(os.environ, env), patch.object(release, "git", return_value=SHA):
            self.assertEqual(release.request(FakeAPI()), (TAG, SHA))
            os.environ["GITHUB_REF"] = "refs/heads/feature"
            with self.assertRaises(release.ReleaseError):
                release.request(FakeAPI())

    def test_request_branch_cannot_smuggle_code_changes(self):
        env = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": f"refs/heads/release/request/{TAG}",
               "GITHUB_SHA": OTHER}
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text(json.dumps({"tag": TAG, "expected_sha": SHA}))
            with patch.dict(os.environ, env), patch.object(release, "Path", return_value=request):
                with patch.object(release, "git", side_effect=[OTHER, SHA, release.REQUEST_PATH]):
                    self.assertEqual(release.request(FakeAPI()), (TAG, SHA))
                with patch.object(release, "git", side_effect=[OTHER, SHA, "hack/tagged_release.py"]):
                    with self.assertRaises(release.ReleaseError):
                        release.request(FakeAPI())
                with patch.object(release, "git", side_effect=[OTHER, "c" * 40]):
                    with self.assertRaises(release.ReleaseError):
                        release.request(FakeAPI())

    def test_request_wrong_branch_or_schema_is_rejected(self):
        env = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feature", "GITHUB_SHA": OTHER}
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            for data in ({"tag": TAG, "expected_sha": SHA}, {"tag": TAG},
                         {"tag": TAG, "expected_sha": SHA, "code": "unexpected"}):
                request.write_text(json.dumps(data))
                with patch.dict(os.environ, env), patch.object(release, "Path", return_value=request):
                    with patch.object(release, "git", return_value=OTHER):
                        with self.assertRaises(release.ReleaseError):
                            release.request(FakeAPI())

    def test_bind_requires_tag_and_exact_dispatch_sha(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": f"refs/tags/{TAG}",
               "GITHUB_REF_NAME": TAG, "GITHUB_SHA": SHA, "EXPECTED_SHA": SHA}
        with patch.dict(os.environ, env), patch.object(release, "git", side_effect=[SHA, "", SHA]):
            with patch.object(release.subprocess, "run") as run:
                run.return_value.returncode = 0
                release.bind()
        for change in ({"EXPECTED_SHA": OTHER}, {"GITHUB_REF": "refs/heads/main"}):
            with patch.dict(os.environ, env | change), self.assertRaises(release.ReleaseError):
                release.bind()

    def test_moved_tag_or_non_main_source_is_rejected(self):
        env = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": f"refs/tags/{TAG}",
               "GITHUB_REF_NAME": TAG, "GITHUB_SHA": SHA}
        with patch.dict(os.environ, env), patch.object(release, "git", side_effect=[SHA, "", OTHER]):
            with self.assertRaises(release.ReleaseError):
                release.bind()
        with patch.dict(os.environ, env), patch.object(release, "git", side_effect=[SHA, "", SHA]):
            with patch.object(release.subprocess, "run") as run:
                run.return_value.returncode = 1
                with self.assertRaises(release.ReleaseError):
                    release.bind()

    def test_wrong_repository_is_rejected_before_api_access(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "someone/fork"}):
            with self.assertRaises(release.ReleaseError):
                release.main()


if __name__ == "__main__":
    unittest.main()

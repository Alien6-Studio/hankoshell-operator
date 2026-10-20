import base64
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("support_window", ROOT / 'tools/qualification/checks/support_window.py')
window = importlib.util.module_from_spec(spec)
spec.loader.exec_module(window)
NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)
SHA = "a" * 40
PINS = {"kubernetes": {"versions": ["1.35.0", "1.36.2", "1.37.0"]}, "keycloak": {"versions": ["26.7.5", "26.8.0"]}}


def release(tag, **kwargs):
    return {"tag_name": tag, "draft": False, "prerelease": False, "published_at": "2026-10-01T00:00:00Z", **kwargs}


def packet():
    return window.propose({"kubernetes": [release("v1.35.2")], "keycloak": []}, PINS, SHA, NOW)


class SupportWindowTests(unittest.TestCase):
    def fixture(self, root):
        for name in (window.POLICY, "versions.json", ".github/workflows/ci.yml", "README.md", "SECURITY.md", "charts/hankoshell-operator/README.md", "CHANGELOG.md"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(window.ROOT / name, target)

    def test_current_window_and_full_weekly_matrix(self):
        self.assertEqual(len(window.check()["kubernetes"]["versions"]), 3)
        self.assertEqual(len(window.check()["keycloak"]["versions"]), 2)

    def test_policy_matrix_and_document_drift_fail(self):
        for change in ("count", "nonconsecutive", "default", "matrix", "links", "review"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / "versions.json"
                data = json.loads(path.read_text())
                if change == "count":
                    data["keycloak"]["versions"].pop()
                elif change == "nonconsecutive":
                    data["kubernetes"]["versions"][0] = "1.31.0"
                elif change == "default":
                    data["keycloak"]["default"] = "26.7.5"
                elif change == "matrix":
                    file = root / ".github/workflows/ci.yml"
                    file.write_text(file.read_text().replace('version: ["26.8.0", "26.7.5"]', 'version: ["26.8.0"]'))
                elif change == "links":
                    file = root / "SECURITY.md"
                    file.write_text(file.read_text().replace("support-window.md", "missing.md"))
                else:
                    file = root / window.POLICY
                    policy = json.loads(file.read_text())
                    policy["review"]["state"] = "accepted"
                    file.write_text(json.dumps(policy))
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    window.check(root)

    def test_proposals_do_not_promote_minor_prerelease_draft_or_future(self):
        catalog = {"kubernetes": [release("v1.35.2"), release("v1.38.0"), release("v1.37.99", draft=True),
                                  release("v1.37.88", prerelease=True), release("v1.37.77", published_at="2099-01-01T00:00:00Z"), release("v1.37.0-rc.1")],
                   "keycloak": [release("26.8.3"), release("26.9.0")]}
        result = window.propose(catalog, PINS, SHA, NOW)
        self.assertEqual([(c["family"], c["to"]) for c in result["changes"]], [("kubernetes", "1.35.2"), ("keycloak", "26.8.3")])
        self.assertFalse(result["automatically_qualified"])
        self.assertEqual(len(result["new_minor_candidates"]), 2)
        self.assertNotIn("images", result)

    def test_catalog_and_revision_are_bounded(self):
        for catalog in ({}, {"kubernetes": [release("v1.35.2")] * 101, "keycloak": []},
                        {"kubernetes": [release("v1.35.2", published_at="not-a-date")], "keycloak": []}):
            with self.assertRaises(ValueError):
                window.propose(catalog, PINS, SHA, NOW)
        with self.assertRaises(ValueError):
            window.propose({"kubernetes": [], "keycloak": []}, PINS, "branch-name", NOW)

    def test_default_and_scheduled_execution_cannot_create_prs(self):
        for env in ({}, {"GITHUB_EVENT_NAME": "schedule", "HANKO_CREATE_SUPPORT_PR": "true"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"}):
            with patch.dict("os.environ", env, clear=True), patch.object(window, "gh") as api:
                with self.assertRaises(ValueError):
                    window.create_draft("Alien6-Studio/hankoshell-operator", packet())
                api.assert_not_called()

    def test_manual_draft_has_verified_commit_no_pin_changes_and_dco(self):
        responses = [{"default_branch": "main"}, {"object": {"sha": SHA}}, [], {},
                     {"data": {"createCommitOnBranch": {"commit": {"oid": "b"*40, "signature": {"isValid": True}}}}}, {"html_url": "https://github.com/example/pr"}]
        with patch.dict("os.environ", {"GITHUB_EVENT_NAME": "workflow_dispatch", "HANKO_CREATE_SUPPORT_PR": "true"}), patch.object(window, "gh", side_effect=responses) as api:
            self.assertEqual(window.create_draft("Alien6-Studio/hankoshell-operator", packet())["result"], "created")
            inputs = api.call_args_list[4].args[1]["variables"]["input"]
            self.assertEqual(inputs["expectedHeadOid"], SHA)
            self.assertIn("Signed-off-by:", inputs["message"]["body"])
            files = inputs["fileChanges"]["additions"]
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0]["path"].startswith("docs/support-proposals/"))
            self.assertEqual(json.loads(base64.b64decode(files[0]["contents"]))["state"], "review-required")
            self.assertTrue(api.call_args_list[-1].args[1]["draft"])

    def test_existing_review_stale_source_and_unsigned_commit_are_refused(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "HANKO_CREATE_SUPPORT_PR": "true"}
        with patch.dict("os.environ", env):
            with patch.object(window, "gh", side_effect=[{"default_branch": "main"}, {"object": {"sha": "b"*40}}]):
                with self.assertRaisesRegex(ValueError, "default-branch"):
                    window.create_draft("Alien6-Studio/hankoshell-operator", packet())
            responses = [{"default_branch": "main"}, {"object": {"sha": SHA}}, [{"html_url": "existing"}]]
            with patch.object(window, "gh", side_effect=responses) as api:
                self.assertEqual(window.create_draft("Alien6-Studio/hankoshell-operator", packet())["result"], "existing")
                self.assertEqual(api.call_count, 3)
            responses = [{"default_branch": "main"}, {"object": {"sha": SHA}}, [], {}, {"data": {"createCommitOnBranch": {"commit": {"signature": {"isValid": False}}}}}]
            with patch.object(window, "gh", side_effect=responses) as api:
                with self.assertRaisesRegex(ValueError, "verify"):
                    window.create_draft("Alien6-Studio/hankoshell-operator", packet())
                self.assertEqual(api.call_count, 5)

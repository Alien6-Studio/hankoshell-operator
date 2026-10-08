import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "release_eligibility", Path(__file__).with_name("release-eligibility.py"))
eligibility = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eligibility)


class ReleaseEligibilityTests(unittest.TestCase):
    def setUp(self):
        self.repository = "Alien6-Studio/hankoshell-operator"
        self.revision = "a" * 40
        self.tag_object = "b" * 40
        self.tag = "v0.1.0"
        self.ref = "refs/tags/" + self.tag
        self.base = "repos/" + self.repository
        self.ref_path = self.base + "/git/ref/tags/" + self.tag
        self.commit_path = self.base + "/git/commits/" + self.revision
        self.object_path = self.base + "/git/tags/" + self.tag_object
        self.responses = {
            self.base: {"private": False},
            self.base + "/private-vulnerability-reporting": {"enabled": True},
            self.commit_path: {"sha": self.revision,
                "verification": {"verified": True}},
            self.ref_path: {"ref": self.ref, "object": {
                "type": "tag", "sha": self.tag_object}},
            self.object_path: {"sha": self.tag_object, "tag": self.tag,
                "object": {"type": "commit", "sha": self.revision},
                "verification": {"verified": True}},
        }
        self.api_calls = []
        self.git_calls = []

    def api(self, path):
        self.api_calls.append(path)
        return copy.deepcopy(self.responses[path])

    def git(self, *args):
        self.git_calls.append(args)
        if args == ("rev-parse", self.ref):
            return self.tag_object + "\n"
        if args == ("rev-parse", self.ref + "^{commit}"):
            return self.revision + "\n"
        if args == ("merge-base", "--is-ancestor", self.revision, "origin/main"):
            return ""
        self.fail("Unexpected Git operation: " + repr(args))

    def verify(self, **kwargs):
        arguments = dict(repository=self.repository, tag=self.tag,
                         revision=self.revision, ref=self.ref,
                         api=self.api, git=self.git)
        arguments.update(kwargs)
        return eligibility.verify(**arguments)

    def test_annotated_tag_binds_exact_source_and_protected_main(self):
        self.assertEqual(self.verify(expected_tag_object=self.tag_object), {
            "revision": self.revision, "tag": self.tag, "tag_object": self.tag_object})
        self.assertEqual(self.api_calls.count(self.ref_path), 2)
        self.assertIn(("merge-base", "--is-ancestor", self.revision, "origin/main"), self.git_calls)

    def test_lightweight_tag_binds_unsigned_root_and_protected_main(self):
        self.tag_object = self.revision
        self.responses[self.ref_path]["object"] = {"type": "commit", "sha": self.revision}
        self.responses[self.commit_path]["verification"] = {"verified": False, "reason": "unsigned"}
        self.assertEqual(self.verify(expected_tag_object=self.revision), {
            "revision": self.revision, "tag": self.tag, "tag_object": self.revision})
        self.assertNotIn(self.object_path, self.api_calls)
        self.assertEqual(self.api_calls.count(self.ref_path), 2)
        self.assertIn(("merge-base", "--is-ancestor", self.revision, "origin/main"), self.git_calls)

    def test_git_signatures_are_optional_for_commit_and_annotated_tag(self):
        for path in (self.object_path, self.commit_path):
            for verification in (False, None, True):
                with self.subTest(path=path, verification=verification):
                    document = self.responses[path]
                    document["verification"] = {"verified": verification}
                    self.verify()
            del document["verification"]
            self.verify()

    def test_tag_with_wrong_target_or_nested_tag_is_rejected(self):
        for target in ({"type": "commit", "sha": "c" * 40},
                       {"type": "tag", "sha": self.revision}):
            self.responses[self.object_path]["object"] = target
            with self.assertRaisesRegex(ValueError, "exact release commit"):
                self.verify()
        self.responses[self.ref_path]["object"] = {"type": "commit", "sha": "c" * 40}
        with self.assertRaisesRegex(ValueError, "exact release commit"):
            self.verify()

    def test_non_commit_or_tag_ref_and_malformed_identity_are_rejected(self):
        for obj in ({"type": "tree", "sha": self.revision},
                    {"type": "blob", "sha": self.revision},
                    {"type": "commit", "sha": "invalid"}, {}):
            self.responses[self.ref_path]["object"] = obj
            with self.subTest(obj=obj), self.assertRaisesRegex(ValueError, "commit or annotated tag"):
                self.verify()

    def test_real_unsigned_root_and_lightweight_tag_resolve_to_same_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True)
            git("init", "--quiet", "--initial-branch=main")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Initial commit")
            revision = git("rev-parse", "HEAD").strip()
            git("update-ref", "refs/remotes/origin/main", revision)
            git("tag", "--no-sign", self.tag, revision)
            self.assertEqual(git("rev-list", "--count", "HEAD").strip(), "1")
            self.assertEqual(git("cat-file", "-t", self.ref).strip(), "commit")
            self.responses[self.base + "/git/commits/" + revision] = {
                "sha": revision, "verification": {"verified": False, "reason": "unsigned"}}
            self.responses[self.ref_path]["object"] = {"type": "commit", "sha": revision}
            self.assertEqual(self.verify(revision=revision, git=git, expected_tag_object=revision), {
                "revision": revision, "tag": self.tag, "tag_object": revision})

    def test_missing_ancestry_fails_closed(self):
        def off_main(*args):
            if args[0] == "merge-base":
                raise ValueError("Release identity API or protected-main ancestry check failed")
            return self.git(*args)
        with self.assertRaisesRegex(ValueError, "ancestry"):
            self.verify(git=off_main)

    def test_malformed_semver_is_rejected_before_api_access(self):
        for tag in ("0.1.0", "v01.1.0", "v0.01.0", "v0.1.00", "v0.1.0-01",
                    "v0.1.0-rc..1", "v0.1.0+", "v0.1.0\n", "v0.1.0/other"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "SemVer"):
                self.verify(tag=tag, ref="refs/tags/" + tag)
        self.assertEqual(self.api_calls, [])
        for tag in ("v0.1.0", "v1.2.3-rc.1", "v1.2.3-alpha01+build.001"):
            self.assertIsNotNone(eligibility.SEMVER.fullmatch(tag))

    def test_branch_dispatch_cannot_substitute_for_the_tag(self):
        with self.assertRaisesRegex(ValueError, "tag itself"):
            self.verify(ref="refs/heads/main")
        self.assertEqual(self.api_calls, [])

    def test_moved_ref_is_rejected_within_and_between_stages(self):
        def moved(path):
            value = self.api(path)
            if path == self.ref_path and self.api_calls.count(path) == 2:
                value["object"]["sha"] = "c" * 40
            return value
        with self.assertRaisesRegex(ValueError, "moved"):
            self.verify(api=moved)
        with self.assertRaisesRegex(ValueError, "changed after eligibility"):
            self.verify(expected_tag_object="c" * 40)

    def test_conflicting_api_objects_are_rejected(self):
        for path, field, conflicting in (
            (self.commit_path, "sha", "c" * 40),
            (self.ref_path, "ref", "refs/tags/v0.2.0"),
            (self.object_path, "tag", "v0.2.0"),
            (self.object_path, "sha", "c" * 40),
        ):
            original = self.responses[path][field]
            self.responses[path][field] = conflicting
            with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                self.verify()
            self.responses[path][field] = original

    def test_conflicting_local_tag_object_or_commit_is_rejected(self):
        for query in (self.ref, self.ref + "^{commit}"):
            def conflict(*args):
                if args == ("rev-parse", query):
                    return "c" * 40
                return self.git(*args)
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, "conflicts"):
                self.verify(git=conflict)

    def test_public_launch_and_private_reporting_remain_required(self):
        self.responses[self.base]["private"] = True
        with self.assertRaisesRegex(ValueError, "public repository"):
            self.verify()
        self.responses[self.base]["private"] = False
        self.responses[self.base + "/private-vulnerability-reporting"]["enabled"] = False
        with self.assertRaisesRegex(ValueError, "vulnerability reporting"):
            self.verify()

    def test_metadata_endpoint_avoids_root_diffs_without_weakening_response_bound(self):
        self.verify()
        self.assertIn(self.base + "/git/commits/" + self.revision, self.api_calls)
        self.assertNotIn(self.base + "/commits/" + self.revision, self.api_calls)
        oversized = SimpleNamespace(returncode=0, stdout="x" * ((1 << 20) + 1))
        with patch.object(eligibility.subprocess, "run", return_value=oversized), \
                self.assertRaisesRegex(ValueError, "size limit"):
            eligibility.command("gh", "api", self.commit_path)

    def test_identity_api_failure_does_not_fall_back_to_local_git(self):
        def unavailable(path):
            raise ValueError("GitHub identity lookup failed")
        with self.assertRaisesRegex(ValueError, "lookup failed"):
            self.verify(api=unavailable)
        self.assertEqual(self.git_calls, [])


if __name__ == "__main__":
    unittest.main()

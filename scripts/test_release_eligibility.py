import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


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

    def test_verified_annotated_tag_binds_verified_source_and_protected_main(self):
        self.assertEqual(self.verify(expected_tag_object=self.tag_object), {
            "revision": self.revision, "tag": self.tag, "tag_object": self.tag_object})
        self.assertEqual(self.api_calls.count(self.ref_path), 2)
        self.assertIn(("merge-base", "--is-ancestor", self.revision, "origin/main"), self.git_calls)

    def test_lightweight_release_tag_is_rejected_even_for_verified_commit(self):
        self.responses[self.ref_path]["object"] = {"type": "commit", "sha": self.revision}
        with self.assertRaisesRegex(ValueError, "annotated tag"):
            self.verify()
        self.assertNotIn(self.object_path, self.api_calls)
        self.assertEqual(self.git_calls, [])

    def test_missing_unsigned_invalid_or_unverified_signatures_are_rejected(self):
        for path, description in ((self.commit_path, "Release commit"),
                                  (self.object_path, "Release tag")):
            document = self.responses[path]
            for verification in (None, {}, [], "true", {"verified": None},
                                 {"verified": "true"}, {"verified": 1},
                                 {"verified": False, "reason": "unsigned"},
                                 {"verified": False, "reason": "invalid"},
                                 {"verified": False, "reason": "unknown_key"}):
                with self.subTest(path=path, verification=verification):
                    document["verification"] = verification
                    with self.assertRaisesRegex(ValueError, description + ".*GitHub Verified"):
                        self.verify()
            del document["verification"]
            with self.assertRaisesRegex(ValueError, description + ".*GitHub Verified"):
                self.verify()
            document["verification"] = {"verified": True}

    def test_tag_with_wrong_target_or_nested_tag_is_rejected(self):
        for target in ({"type": "commit", "sha": "c" * 40},
                       {"type": "tag", "sha": self.revision}):
            self.responses[self.object_path]["object"] = target
            with self.assertRaisesRegex(ValueError, "exact release commit"):
                self.verify()
    def test_non_annotated_tag_ref_and_malformed_identity_are_rejected(self):
        for obj in ({"type": "tree", "sha": self.revision},
                    {"type": "blob", "sha": self.revision},
                    {"type": "commit", "sha": self.revision},
                    {"type": "tag", "sha": "invalid"},
                    {"type": "tag", "sha": None}, None, [], {}):
            self.responses[self.ref_path]["object"] = obj
            with self.subTest(obj=obj), self.assertRaisesRegex(ValueError, "annotated tag"):
                self.verify()

    def test_large_signed_root_uses_verified_metadata_without_the_commit_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True)
            git("init", "--quiet", "--initial-branch=main")
            key = Path(directory) / "fixture-key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "gpg.format", "ssh")
            git("config", "user.signingkey", str(key))
            allowed = Path(directory) / "allowed-signers"
            allowed.write_text("fixture@example.invalid " + key.with_suffix(".pub").read_text())
            git("config", "gpg.ssh.allowedSignersFile", str(allowed))
            for index in range(300):
                (Path(directory) / f"source-{index}.txt").write_text("root fixture\n" * 400)
            git("add", "source-*.txt")
            git("commit", "-S", "--quiet", "-m", "Initial commit")
            revision = git("rev-parse", "HEAD").strip()
            git("verify-commit", revision)
            git("update-ref", "refs/remotes/origin/main", revision)
            git("tag", "-s", "-m", "Fixture release", self.tag, revision)
            git("verify-tag", self.tag)
            tag_object = git("rev-parse", self.ref).strip()
            self.assertEqual(git("rev-list", "--count", "HEAD").strip(), "1")
            self.assertEqual(git("cat-file", "-t", self.ref).strip(), "tag")
            self.assertGreater(len(git("show", "--format=", revision).encode()), 1 << 20)
            # GitHub verification is an independent API fixture, never inferred
            # from local verification. The real signing bootstrap checks GitHub.
            metadata = {"sha": revision, "parents": [], "verification": {"verified": True}}
            self.assertLess(len(json.dumps(metadata).encode()), 1 << 20)
            metadata_path = self.base + "/git/commits/" + revision
            self.responses[metadata_path] = metadata
            self.responses[self.ref_path]["object"] = {"type": "tag", "sha": tag_object}
            self.responses[self.base + "/git/tags/" + tag_object] = {
                "sha": tag_object, "tag": self.tag,
                "object": {"type": "commit", "sha": revision},
                "verification": {"verified": True}}
            self.assertEqual(self.verify(revision=revision, git=git, expected_tag_object=tag_object), {
                "revision": revision, "tag": self.tag, "tag_object": tag_object})
            self.assertIn(metadata_path, self.api_calls)
            self.assertNotIn(self.base + "/commits/" + revision, self.api_calls)
            self.responses[metadata_path]["verification"] = {"verified": False}
            with self.assertRaisesRegex(ValueError, "Release commit.*GitHub Verified"):
                self.verify(revision=revision, git=git)

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

    def test_metadata_limit_counts_utf8_bytes(self):
        oversized = SimpleNamespace(returncode=0, stdout="é" * ((1 << 19) + 1))
        with patch.object(eligibility.subprocess, "run", return_value=oversized), \
                self.assertRaisesRegex(ValueError, "size limit"):
            eligibility.command("gh", "api", self.commit_path)

    def test_malformed_api_documents_fail_closed(self):
        for path in self.responses:
            original = self.responses[path]
            for malformed in (None, [], True, "not an object"):
                self.responses[path] = malformed
                with self.subTest(path=path, malformed=malformed), \
                        self.assertRaisesRegex(ValueError, "Malformed"):
                    self.verify()
            self.responses[path] = original
        for target in (None, [], "commit"):
            self.responses[self.object_path]["object"] = target
            with self.assertRaisesRegex(ValueError, "exact release commit"):
                self.verify()

    def test_malformed_json_and_nonzero_api_command_cannot_pass(self):
        with patch.object(eligibility.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")), \
                self.assertRaisesRegex(ValueError, "API.*failed"):
            eligibility.command("gh", "api", self.commit_path)
        with patch.object(eligibility.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="{broken")):
            with self.assertRaises(ValueError):
                self.verify(api=lambda path: json.loads(eligibility.command("gh", "api", path)))

    def test_identity_api_failure_does_not_fall_back_to_local_git(self):
        def unavailable(path):
            raise ValueError("GitHub identity lookup failed")
        with self.assertRaisesRegex(ValueError, "lookup failed"):
            self.verify(api=unavailable)
        self.assertEqual(self.git_calls, [])

    def test_release_workflow_requires_identity_before_quality_and_publication(self):
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/release.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(jobs["quality"]["needs"], "eligibility")
        self.assertEqual(set(jobs["publish"]["needs"]), {"eligibility", "quality"})
        for name in ("eligibility", "quality", "publish"):
            self.assertNotIn("if", jobs[name], "Identity and quality failures must stop publication")
        for name in ("eligibility", "publish"):
            checks = [step for step in jobs[name]["steps"]
                      if "python3 scripts/release-eligibility.py" in step.get("run", "")]
            self.assertEqual(len(checks), 1)
            self.assertEqual(checks[0]["env"]["TAG"], "${{ inputs.tag }}")
            self.assertEqual(checks[0]["env"]["REF"], "${{ github.ref }}")
            if name == "publish":
                self.assertEqual(checks[0]["env"]["EXPECTED_TAG_OBJECT"],
                                 "${{ needs.eligibility.outputs.tag_object }}")


if __name__ == "__main__":
    unittest.main()

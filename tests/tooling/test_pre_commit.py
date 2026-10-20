import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


checks = module("pre_commit_checks", "tools/quality/pre_commit_checks.py")
installer = module("install_hook_tools", "tools/bootstrap/install_hook_tools.py")


class HookChecksTests(unittest.TestCase):
    def test_vet_deduplicates_changed_packages_and_dependency_changes_select_everything(self):
        self.assertEqual(checks.packages(["internal/b/b.go", "internal/a/a.go", "internal/b/b_test.go"]),
                         ["./internal/a", "./internal/b"])
        self.assertEqual(checks.packages(["root.go"]), ["./."])
        for filename in ("go.mod", "go.sum"):
            self.assertEqual(checks.packages(["internal/a/a.go", filename]), ["./..."])
        self.assertEqual(checks.packages(["README.md", "tests/tooling/test_fixture.py"]), [])

    def test_vet_rejects_paths_outside_the_repository_without_running_go(self):
        for filename in ("../outside.go", "/outside.go", "internal/../../outside.go"):
            with self.subTest(filename=filename), patch.object(checks.subprocess, "run") as run, self.assertRaises(ValueError):
                checks.run("vet", [filename])
            run.assert_not_called()

    def test_vet_runs_once_and_preserves_the_failed_exit_status(self):
        with patch.object(checks.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(checks.run("vet", ["internal/a/a.go", "internal/a/a_test.go"]), 7)
            run.assert_called_once_with(["go", "vet", "./internal/a"], cwd=checks.ROOT, check=False)
        with patch.object(checks.subprocess, "run") as run:
            self.assertEqual(checks.run("vet", []), 0)
            run.assert_not_called()

    def test_staged_secret_check_uses_reviewed_binary_and_redacts_findings(self):
        version = checks.versions.get("tools", "gitleaks", "version")
        with patch.object(checks.subprocess, "check_output", return_value=version + "\n"), \
                patch.object(checks.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            self.assertEqual(checks.run("secrets", []), 1)
            run.assert_called_once_with([str(checks.ROOT / ".tools/bin/hooks/gitleaks"), "protect", "--staged",
                                         "--redact", "--no-banner"], cwd=checks.ROOT, check=False)
        with patch.object(checks.subprocess, "check_output", return_value="unreviewed"), \
                patch.object(checks.subprocess, "run") as run, self.assertRaisesRegex(ValueError, "reviewed version"):
            checks.run("secrets", [])
        run.assert_not_called()

    def test_frozen_config_and_both_ci_entry_points_preserve_the_hooks(self):
        config = yaml.safe_load((checks.ROOT / ".pre-commit-config.yaml").read_text())
        remote, local = config["repos"]
        self.assertEqual(remote["repo"], "https://github.com/pre-commit/pre-commit-hooks")
        self.assertRegex(remote["rev"], r"^[a-f0-9]{40}$")
        self.assertEqual(config["minimum_pre_commit_version"], checks.versions.get("tools", "pre_commit", "version"))
        hooks = {hook["id"]: hook for hook in remote["hooks"]}
        self.assertEqual(set(hooks), {"check-added-large-files", "detect-private-key", "check-merge-conflict",
                                    "check-yaml", "check-toml", "check-json", "end-of-file-fixer"})
        self.assertNotIn("exclude", config)
        self.assertNotIn("exclude", hooks["detect-private-key"])
        self.assertIn("--assume-in-merge", hooks["check-merge-conflict"]["args"])
        self.assertEqual(hooks["check-yaml"]["exclude"], "^charts/hankoshell-operator/templates/")
        self.assertEqual(local["repo"], "local")
        local_hooks = {hook["id"]: hook for hook in local["hooks"]}
        self.assertEqual(local_hooks["go-format"]["entry"], "make fmt-check")
        self.assertEqual(local_hooks["go-architecture"]["entry"], "make arch")
        self.assertTrue(local_hooks["go-vet"]["require_serial"])
        self.assertTrue(local_hooks["staged-secrets"]["always_run"])
        self.assertEqual(local_hooks["python-tests"]["files"], r"^(tools/.*\.py|tools/requirements\.txt|tests/(tooling|chart)/.*\.(py|sh))$")
        jobs = yaml.safe_load((checks.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        hook_step = next(step for step in jobs["source"]["steps"] if step.get("run") == "make hooks-check")
        self.assertNotIn("if", hook_step)
        self.assertFalse(hook_step.get("continue-on-error", False))
        self.assertEqual(hook_step["env"]["PRE_COMMIT_HOME"], "${{ runner.temp }}/hankoshell-pre-commit")
        self.assertIn("PRE_COMMIT_HOME ?=", (checks.ROOT / "Makefile").read_text())
        development = yaml.safe_load((checks.ROOT / ".github/workflows/development.yml").read_text())
        self.assertTrue(any(step.get("run") == "make preflight hooks-check"
                            for step in development["jobs"]["preflight"]["steps"]))


class HookInstallerTests(unittest.TestCase):
    def archive(self, kind="file"):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo("gitleaks")
            binary = b"reviewed fixture executable"
            if kind == "link":
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                archive.addfile(member)
            elif kind == "empty":
                archive.addfile(member)
            else:
                member.size = len(binary)
                archive.addfile(member, io.BytesIO(binary))
                if kind == "duplicate":
                    archive.addfile(member, io.BytesIO(binary))
        return output.getvalue()

    def test_verified_cache_is_reused_and_tampered_cache_is_revalidated(self):
        data = b"reviewed download"
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache"
            cache.write_bytes(data)
            with patch.object(installer, "urlopen") as download:
                self.assertEqual(installer.payload("https://official.invalid", digest, cache), data)
                download.assert_not_called()
            cache.write_bytes(b"tampered")
            with patch.object(installer, "urlopen", return_value=io.BytesIO(data)) as download:
                self.assertEqual(installer.payload("https://official.invalid", digest, cache), data)
                download.assert_called_once()
                self.assertEqual(cache.read_bytes(), data)

    def test_unverified_or_oversized_downloads_are_not_written_or_executed(self):
        for digest in ("malformed", "0" * 64):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as directory:
                cache = Path(directory) / "cache"
                with patch.object(installer, "urlopen", return_value=io.BytesIO(b"untrusted")), self.assertRaises(ValueError):
                    installer.payload("https://official.invalid", digest, cache)
                self.assertFalse(cache.exists())
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "LIMIT", 4), \
                patch.object(installer, "urlopen", return_value=io.BytesIO(b"large")), self.assertRaisesRegex(ValueError, "size limit"):
            installer.payload("https://official.invalid", hashlib.sha256(b"large").hexdigest(), Path(directory) / "cache")

    def test_archive_member_types_ambiguity_and_unsupported_hosts_fail_before_execution(self):
        for kind in ("link", "empty", "duplicate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, \
                    patch.object(installer, "payload", side_effect=[b"zipapp", self.archive(kind)]), \
                    patch.object(installer.subprocess, "check_output") as command, self.assertRaises(ValueError):
                installer.install(Path(directory), "linux-amd64")
            command.assert_not_called()
        with patch.object(installer, "payload") as download, self.assertRaises(KeyError):
            installer.install(Path("/unused"), "unsupported")
        download.assert_not_called()

    def test_installed_versions_are_checked_after_extracting_only_the_binary(self):
        pre_commit = installer.versions.get("tools", "pre_commit", "version")
        gitleaks = installer.versions.get("tools", "gitleaks", "version")
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "payload", side_effect=[b"zipapp", self.archive()]), \
                patch.object(installer.subprocess, "check_output", side_effect=["pre-commit " + pre_commit, gitleaks]) as command:
            root = Path(directory)
            installer.install(root, "linux-amd64")
            self.assertEqual((root / "gitleaks").read_bytes(), b"reviewed fixture executable")
            self.assertTrue((root / "gitleaks").stat().st_mode & 0o111)
            self.assertEqual(command.call_count, 2)
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "payload", side_effect=[b"zipapp", self.archive()]), \
                patch.object(installer.subprocess, "check_output", return_value="wrong"), self.assertRaisesRegex(ValueError, "version"):
            installer.install(Path(directory), "linux-amd64")

    def test_hook_tool_checksum_policy_is_validated(self):
        for tool in ("pre_commit", "gitleaks"):
            data = copy.deepcopy(installer.versions.DATA)
            if tool == "pre_commit":
                data["tools"][tool]["sha256"] = "bad"
            else:
                data["tools"][tool]["sha256"]["linux-amd64"] = "bad"
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "checksum"):
                installer.versions.validate(data)


if __name__ == "__main__":
    unittest.main()

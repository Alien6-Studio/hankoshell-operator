import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

import importlib.util
spec = importlib.util.spec_from_file_location("release_publish", Path(__file__).with_name("release-publish.py"))
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)
installer = publish.contract.module("system_tools", "install-system-tools.py")
system = publish.contract.module("installed_system", "system-test.py")


class ReleaseResumeTests(unittest.TestCase):
    def test_installed_authorization_cleanup_requires_preserved_client_and_absent_server(self):
        fixture = object.__new__(system.System)
        client = {"id": "fixture-id", "authorizationServicesEnabled": False, "attributes": {}}
        with patch.object(fixture, "client", return_value=client), patch.object(fixture, "api") as api:
            fixture.authorization_cleaned("fixture-id")
            api.assert_called_once_with("GET", "/admin/realms/managed/clients/fixture-id/authz/resource-server", expected=(404,))
            api.reset_mock()
            del client["authorizationServicesEnabled"]
            fixture.authorization_cleaned("fixture-id")
            api.assert_called_once_with("GET", "/admin/realms/managed/clients/fixture-id/authz/resource-server", expected=(404,))
            client["authorizationServicesEnabled"] = False
            api.reset_mock()
            for field, invalid in (("id", "replacement"), ("authorizationServicesEnabled", True),
                                   ("authorizationServicesEnabled", None),
                                   ("attributes", {"hanko.sh/resource-server-ownership": "{}"})):
                original = client[field]
                client[field] = invalid
                with self.assertRaises(ValueError):
                    fixture.authorization_cleaned("fixture-id")
                api.assert_not_called()
                client[field] = original

    def test_installed_iam_requires_applied_and_complete_readback_evidence(self):
        fixture = object.__new__(system.System)
        digest = "sha256:" + "a" * 64
        status = {"phase": "Ready", "contractVersion": "hanko.sh/iam-contract/v1alpha1", "backendKind": "keycloak",
                  "observationComplete": True, "driftState": "InSync", "conditions": [
                      {"type": "Synced", "status": "True", "reason": "Reconciled", "observedGeneration": 2}]}
        for field in ("observedGeneration", "evaluatedGeneration", "appliedGeneration", "observationGeneration"):
            status[field] = 2
        for field in ("intentHash", "evaluatedPlanHash", "appliedPlanHash", "observedStateHash", "observationPlanHash"):
            status[field] = digest
        value = {"metadata": {"generation": 2}, "status": status}
        with patch.object(fixture, "get", return_value=value):
            for kind in ("hankorole", "hankoresourceserver"):
                self.assertTrue(fixture.iam_reconciled(kind, "fixture"))
                for field in ("observedGeneration", "evaluatedGeneration", "appliedGeneration", "observationGeneration"):
                    status[field] = 1
                    self.assertFalse(fixture.iam_reconciled(kind, "fixture"))
                    status[field] = 2
                for field, invalid in (("observationComplete", False), ("driftState", "Drifted"), ("appliedPlanHash", "raw-data")):
                    original = status[field]
                    status[field] = invalid
                    self.assertFalse(fixture.iam_reconciled(kind, "fixture"))
                    status[field] = original
            self.assertTrue(fixture.ready("hankoapplication", "fixture"))
            status["observedGeneration"] = 1
            self.assertFalse(fixture.ready("hankoapplication", "fixture"))
            status["observedGeneration"] = 2
            for condition_status, reason in (("False", "Reconciled"), ("True", "Observed")):
                status["conditions"][0].update(status=condition_status, reason=reason)
                self.assertFalse(fixture.role_reconciled("fixture"))
            status["conditions"] = []
            self.assertFalse(fixture.role_reconciled("fixture"))

    def test_complete_nonempty_or_published_assets_are_never_deleted(self):
        github = publish.GitHub("synthetic-fixture-token")
        for draft, state, size in ((False, "starter", 0), (True, "uploaded", 0), (True, "uploaded", 100), (True, "starter", 1)):
            with patch.object(github, "request") as request, self.assertRaises(ValueError):
                github.delete_incomplete({"draft": draft}, {"id": 1, "state": state, "size": size})
            request.assert_not_called()
        with patch.object(github, "request") as request:
            github.delete_incomplete({"draft": True}, {"id": 1, "state": "starter", "size": 0})
            request.assert_called_once_with("DELETE", "/repos/Alien6-Studio/hankoshell-operator/releases/assets/1")

    def test_github_token_is_never_sent_to_an_arbitrary_upload_endpoint(self):
        github = publish.GitHub("synthetic-fixture-token")
        for endpoint in ("https://evil.example/upload", "https://user@uploads.github.com/upload", "https://uploads.github.com:444/upload"):
            with self.assertRaises(ValueError):
                github.request("POST", endpoint, b"payload")

    def test_registry_errors_are_not_silently_treated_as_missing_tags(self):
        registry = publish.Registry(Path("oras"), Path("helm"))
        for message in (b"401 Unauthorized", b"403 Forbidden", b"TLS certificate error", b"connection refused", b"429 Too Many Requests", b"404 Not Found", b"authentication token: not found"):
            with patch.object(publish.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", message)), self.assertRaises(RuntimeError):
                registry.resolve("example.test/operator:0.2.0")
        for message in (b"Error response from registry: failed to resolve digest: example.test/operator:0.2.0: not found\n",):
            with patch.object(publish.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", message)):
                self.assertIsNone(registry.resolve("example.test/operator:0.2.0"))
        for output in (b"latest", b"sha256:abc", b"sha256:" + b"a" * 64 + b"\nextra"):
            with patch.object(publish.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, b"")), self.assertRaises(ValueError):
                registry.resolve("example.test/operator:0.2.0")

    def test_checkpoint_archive_rejects_traversal_links_duplicates_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("traversal", "absolute", "symlink", "duplicate", "oversize"):
                archive = root / (kind + ".tar")
                with tarfile.open(archive, "w") as package:
                    member = tarfile.TarInfo({"traversal": "../escape", "absolute": "/escape"}.get(kind, "dist/checksums.txt"))
                    member.size = 1
                    if kind == "symlink":
                        member.type, member.linkname, member.size = tarfile.SYMTYPE, "outside", 0
                    package.addfile(member, io.BytesIO(b"x"))
                    if kind == "duplicate":
                        package.addfile(member, io.BytesIO(b"x"))
                with patch.object(publish, "MAX_CHECKPOINT", 0 if kind == "oversize" else publish.MAX_CHECKPOINT), self.assertRaises(ValueError):
                    publish.extract(archive, root / kind)
                self.assertFalse((root / kind).exists())

    def test_release_default_does_not_allow_mutable_source_or_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version, revision, image in (("0.1.1", "a" * 40, publish.IMAGE + "@sha256:" + "b" * 64),
                                            ("0.2.0", "main", publish.IMAGE + "@sha256:" + "b" * 64),
                                            ("0.2.0", "a" * 40, publish.IMAGE + ":0.2.0")):
                with self.assertRaises(ValueError):
                    publish.checkpoint(root, version, revision, image)

    def test_hash_manifest_rejects_private_or_nonregular_files_and_content_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "image.tar"
            file.write_bytes(b"original archive")
            before = publish.checkpoint(root, "0.2.0", "a" * 40, publish.IMAGE + "@sha256:" + "b" * 64)
            file.write_bytes(b"changed archive")
            after = publish.checkpoint(root, "0.2.0", "a" * 40, publish.IMAGE + "@sha256:" + "b" * 64)
            self.assertNotEqual(before["files"], after["files"])
            (root / "link").symlink_to(file)
            with self.assertRaises(ValueError):
                publish.hashes(root)

    def test_system_tools_have_committed_checksums_and_refuse_unverified_bytes(self):
        self.assertEqual(set(installer.KIND_HASHES), {"linux-amd64", "darwin-arm64"})
        self.assertEqual(set(installer.KIND_HASHES), set(installer.KUBECTL_HASHES))
        self.assertTrue(all(len(value) == 64 for value in [*installer.KIND_HASHES.values(), *installer.KUBECTL_HASHES.values()]))
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "urlopen", return_value=io.BytesIO(b"changed executable")):
            destination = Path(directory) / "tool"
            with self.assertRaises(ValueError):
                installer.acquire("https://example.test/tool", hashlib.sha256(b"reviewed executable").hexdigest(), destination)
            self.assertFalse(destination.exists())

    def test_system_and_release_resume_cannot_skip_the_aggregate_gate(self):
        root = publish.ROOT / ".github/workflows"
        ci = yaml.safe_load((root / "ci.yml").read_text())["jobs"]
        system = ci["system"]
        self.assertIn("system", ci["checks"]["needs"])
        self.assertEqual(system["needs"], ["source", "oci"])
        self.assertNotIn("if", system)
        self.assertNotIn("continue-on-error", system)
        download = next(step for step in system["steps"] if "download-artifact@" in step.get("uses", ""))
        self.assertEqual(download["with"]["artifact-ids"], "${{ needs.oci.outputs.artifact_id }}")
        release = yaml.safe_load((root / "release.yml").read_text())["jobs"]
        self.assertIs(release["quality"]["with"]["release"], True)
        oci = yaml.safe_load((root / "oci-security.yml").read_text())["jobs"]["image"]
        self.assertEqual(oci["outputs"]["digest"], "${{ steps.selection.outputs.digest }}")
        self.assertEqual(oci["outputs"]["candidate_digest"], "${{ steps.checkpoint.outputs.candidate_digest }}")
        image = next(step for step in oci["steps"] if step.get("id") == "image")
        self.assertEqual(image["if"], "steps.checkpoint.outputs.restored != 'true'")
        selection = next(step for step in oci["steps"] if step.get("id") == "selection")
        for restored, built, expected in (("true", "sha256:new", "sha256:committed"), ("false", "sha256:new", "sha256:new")):
            import os
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "output"
                env = dict(os.environ, RESTORED=restored, RESTORED_DIGEST="sha256:committed", BUILT_DIGEST=built, GITHUB_OUTPUT=str(output))
                subprocess.run(["bash", "-c", selection["run"]], env=env, check=True)
                self.assertEqual(output.read_text(), "digest=" + expected + "\n")
        steps = release["publish"]["steps"]
        commands = {mode: next(i for i, step in enumerate(steps) if f"scripts/release-publish.py {mode}" in step.get("run", ""))
                    for mode in ("restore", "verify-attest", "save", "promote")}
        self.assertLess(commands["restore"], commands["verify-attest"])
        self.assertLess(commands["verify-attest"], commands["save"])
        self.assertLess(commands["save"], commands["promote"])
        for mode in commands:
            self.assertNotIn("if", steps[commands[mode]])
            self.assertFalse(steps[commands[mode]].get("continue-on-error", False))
        fresh = steps[commands["verify-attest"]]["run"]
        self.assertIn('scripts/oci-security.py scan --archive "$RUNNER_TEMP/hankoshell-delivery/image.tar"', fresh)
        self.assertIn('--output "$RUNNER_TEMP/fresh-scan"', fresh)
        self.assertNotIn("fresh=False", fresh)


if __name__ == "__main__":
    unittest.main()

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("release_contract", Path(__file__).with_name("release-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
dry_run = contract.module("release_dry_run", "release-dry-run.py")


class ReleaseContractTests(unittest.TestCase):
    def test_reviewed_versions_maturity_and_curated_notes(self):
        notes = contract.check()
        self.assertNotIn("Unreleased", notes)
        self.assertNotIn("release-notes:", notes)
        for requirement in ("26.8.0", "26.7.5", "1.35.0", "1.36.2", "1.37.0",
                            "v1alpha1", "initial development", "HTTPS", "HMAC",
                            "backup/restore", "security/advisories/new", "oci://", "https://hanko.sh"):
            self.assertIn(requirement, notes)
        with self.assertRaises(ValueError):
            contract.check("0.1.0-beta.1")

    def test_note_drift_or_missing_markers_cannot_be_published(self):
        with patch.object(Path, "read_text", return_value="no curated release notes"), self.assertRaises(ValueError):
            contract.notes()
        with self.assertRaises(ValueError):
            contract.notes("99.0.0")

    def test_release_and_rehearsal_use_the_same_packaging_and_immutable_image(self):
        workflows = contract.ROOT / ".github/workflows"
        release = yaml.safe_load((workflows / "release.yml").read_text())["jobs"]
        ci = yaml.safe_load((workflows / "ci.yml").read_text())["jobs"]
        steps = release["publish"]["steps"]
        package = next(step["run"] for step in steps if "scripts/release-contract.py prepare" in step.get("run", ""))
        for binding in ('--image "$IMAGE@$DIGEST"', '--revision "$GITHUB_SHA"', '--archive ', '--evidence '):
            self.assertIn(binding, package)
        self.assertIn("contract.prepare(", (contract.ROOT / "scripts/release-dry-run.py").read_text())
        download = next(step for step in ci["rehearsal"]["steps"] if "download-artifact@" in step.get("uses", ""))
        self.assertEqual(download["with"]["artifact-ids"], "${{ needs.oci.outputs.artifact_id }}")
        publish = next(step["run"] for step in steps if "gh release create" in step.get("run", ""))
        self.assertIn("--notes-file dist/release-notes.md", publish)
        self.assertIn("--prerelease=false", publish)
        self.assertIn("--verify-tag --draft", publish)
        self.assertNotIn("--generate-notes", publish)
        eligibility = "\n".join(step.get("run", "") for step in release["eligibility"]["steps"])
        self.assertIn('git merge-base --is-ancestor "$GITHUB_SHA" origin/main', eligibility)

    def test_actions_are_immutable_checkouts_do_not_persist_and_writes_are_scoped(self):
        for path in (contract.ROOT / ".github/workflows").glob("*.yml"):
            workflow = yaml.safe_load(path.read_text())
            self.assertEqual(workflow["permissions"], {"contents": "read"}, path)
            for name, job in workflow["jobs"].items():
                if "permissions" in job:
                    if path.name == "release.yml" and name == "publish":
                        self.assertEqual(job["permissions"], {"contents": "write", "packages": "write", "id-token": "write"})
                    else:
                        self.assertTrue(all(value == "read" for value in job["permissions"].values()), (path, name))
                for step in job.get("steps", []):
                    action = step.get("uses", "")
                    if action and not action.startswith("./"):
                        self.assertRegex(action, r"^[\w./-]+@[0-9a-f]{40}$")
                    if action.startswith("actions/checkout@"):
                        self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertNotRegex(step.get("run", ""), r"curl[^\n]*\|\s*(?:sh|bash)")
        ci = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        self.assertNotIn("environment", ci["rehearsal"])
        self.assertNotIn("secrets.", yaml.safe_dump(ci["rehearsal"]))

    def test_embedded_cosign_and_native_verifier_use_the_same_reviewed_dependency_pins(self):
        dockerfile = (contract.ROOT / "Dockerfile").read_text()
        installer = (contract.ROOT / "scripts/install-cosign.sh").read_text()
        pins = re.findall(r"[a-zA-Z0-9./-]+@v[0-9][a-zA-Z0-9.+-]*", dockerfile)
        self.assertIn("github.com/sigstore/cosign/v3/cmd/cosign@v3.1.3", pins)
        for pin in pins:
            self.assertIn(pin, installer)

    def test_leader_election_boolean_reaches_the_manager(self):
        chart = contract.ROOT / "charts/hankoshell-operator"
        for value in ("true", "false"):
            rendered = subprocess.check_output(["helm", "template", "test", str(chart), "--kube-version", "1.37.0",
                "--set-string", "image.tag=test", "--set", "leaderElect=" + value], text=True)
            deployment = next(item for item in yaml.safe_load_all(rendered) if item and item["kind"] == "Deployment")
            args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
            self.assertIn("--leader-elect=" + value, args)
        result = subprocess.run(["helm", "template", "test", str(chart), "--kube-version", "1.37.0",
            "--set-string", "image.tag=test", "--set-string", "leaderElect=false"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("leaderElect must be a boolean", result.stderr)

    def test_fixture_blob_digest_tampering_and_public_transparency_entries_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload, bundle = root / "payload", root / "bundle.json"
            payload.write_text("synthetic checksums\n")
            document = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                        "verificationMaterial": {}, "messageSignature": {
                            "messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(hashlib.sha256(payload.read_bytes()).digest()).decode()},
                            "signature": base64.b64encode(b"synthetic signature").decode()}}
            bundle.write_text(json.dumps(document))
            with patch.object(dry_run, "run") as crypto:
                dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")
                crypto.assert_called_once()
                payload.write_text("changed")
                with self.assertRaises(ValueError):
                    dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")
                payload.write_text("synthetic checksums\n")
                document["verificationMaterial"]["tlogEntries"] = [{"logIndex": "1"}]
                bundle.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")


if __name__ == "__main__":
    unittest.main()

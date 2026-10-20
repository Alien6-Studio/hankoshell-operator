"""Authenticity, privacy and preservation boundaries for public upgrade qualification."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile
import yaml
from tools.qualification.reporting import public_release_corpus as corpus
from tools.release import public_release_verify as public
from tools.qualification.scenarios import cross_version_installed_test as upgrade
ROOT = Path(__file__).resolve().parents[2]
SHA, DIGEST = "a" * 40, "sha256:" + "b" * 64
IMAGE = "ghcr.io/alien6-studio/hankoshell-operator@" + DIGEST
REPO = "Alien6-Studio/hankoshell-operator"

def fixture(name="public-app", kind="HankoApplication"):
    return {"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
        "metadata": {"name": name, "namespace": "auth", "uid": "synthetic-uid", "generation": 2,
                     "labels": {"hanko-fixture": "public-contract"}}, "spec": {"realmRef": "managed", "clientID": "synthetic"},
        "status": {"phase": "Ready", "observedGeneration": 2, "appliedPlanHash": "sha256:" + "c" * 64,
                   "observationPlanHash": "sha256:" + "c" * 64, "observationComplete": True}}

class PublicCompatibilityTests(unittest.TestCase):
    def test_capture_rejects_tenant_data_stale_readback_and_credentials(self):
        obj = fixture()
        captured = corpus.capture([obj], {obj["kind"]: {}}, "1.0.0-rc.1", SHA, IMAGE)
        self.assertFalse(captured["published"])
        self.assertNotIn("labels", captured["fixtures"][0]["metadata"])
        referenced = copy.deepcopy(obj)
        referenced["status"]["clientSecret"] = {"secretRef": {"name": "hanko-app-synthetic", "key": "client_secret"}}
        corpus.capture([referenced], {obj["kind"]: {}}, "1.0.0-rc.1", SHA, IMAGE)
        for mutation in ("tenant", "unlabelled", "stale", "partial", "raw-secret", "camel-secret", "known-secret", "duplicate"):
            bad = copy.deepcopy(obj)
            sensitive = ()
            if mutation == "tenant": bad["metadata"]["namespace"] = "production"
            if mutation == "unlabelled": bad["metadata"]["labels"] = {}
            if mutation == "stale": bad["status"]["observedGeneration"] = 1
            if mutation == "partial": bad["status"]["observationComplete"] = False
            if mutation == "raw-secret": bad["spec"]["client_secret"] = "synthetic-value"
            if mutation == "camel-secret": bad["spec"]["clientSecret"] = "synthetic-value"
            if mutation == "known-secret": bad["spec"]["description"] = "sentinel-synthetic-value"; sensitive = ("sentinel-synthetic-value",)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                corpus.capture([bad, bad] if mutation == "duplicate" else [bad], {obj["kind"]: {}}, "1.0.0-rc.1", SHA, IMAGE, sensitive)

    def test_rc_capture_cannot_be_promoted_into_an_invented_public_predecessor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            path.write_text(json.dumps(corpus.capture([fixture()], {"HankoApplication": {}}, "1.0.0-rc.1", SHA, IMAGE)))
            proof = Path(directory) / "proof.json"
            proof.write_text("{}")
            with self.assertRaisesRegex(ValueError, "actual public 0.x"):
                corpus.approve(path, proof, ["EVID-0001"], "https://github.com/" + REPO + "/pull/1")

    def test_installed_artifact_binds_actual_actions_commit_digest_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            path.write_text('{"synthetic": true}')
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("system-test.corpus.json", path.read_bytes())
            raw = stream.getvalue()
            metadata = {"id": 12, "expired": False, "size_in_bytes": len(raw), "workflow_run": {"head_sha": SHA}, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
            def fetch(endpoint, binary=False):
                return raw if binary else metadata
            self.assertEqual(public.capture_identity(path, 12, SHA, fetch)["artifact_id"], 12)
            for field, value in (("expired", True), ("size_in_bytes", 4 * 1024**2 + 1), ("digest", "sha256:" + "0" * 64), ("workflow_run", {"head_sha": "d" * 40})):
                original = metadata[field]
                metadata[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError): public.capture_identity(path, 12, SHA, fetch)
                metadata[field] = original
            path.write_text('{"substituted": true}')
            with self.assertRaisesRegex(ValueError, "differs"): public.capture_identity(path, 12, SHA, fetch)

    def test_draft_and_rc_assets_cannot_become_public_predecessors(self):
        for version in ("1.0.0-rc.1", "1.0.0", "0.1.0-dev.0"):
            with self.assertRaises(ValueError): public.verify(version, SHA, IMAGE, None, {}, None, None)
        with self.assertRaises(ValueError):
            public.verify("0.1.0", SHA, IMAGE, None, {}, None, None, fetch=lambda _: {"tag_name": "v0.1.0", "draft": True, "prerelease": False})

    def test_historical_verification_requires_both_exact_cosign_identities_and_native_attest_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            version, chart_name = "0.1.0", "hankoshell-operator-0.1.0.tgz"
            def add(archive, name, data):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            with tarfile.open(assets / chart_name, "w:gz") as archive:
                add(archive, "hankoshell-operator/Chart.yaml", yaml.safe_dump({"version": version, "appVersion": version}).encode())
                add(archive, "hankoshell-operator/values.yaml", yaml.safe_dump({"image": {"repository": IMAGE.split("@")[0], "digest": DIGEST, "tag": ""}}).encode())
            (assets / "image-digest.txt").write_text(IMAGE + "\n")
            (assets / "source-revision.txt").write_text(SHA + "\n")
            (assets / "checksums.sigstore.json").write_text('{"synthetic-verifier-transport": true}')
            (assets / "checksums.txt").write_text("".join(hashlib.sha256((assets / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in (chart_name, "image-digest.txt", "source-revision.txt")))
            delivery = {path.name: path.read_bytes() for path in assets.iterdir()}
            manifest = {"repository": REPO, "version": version, "source_revision": SHA, "image": IMAGE,
                        "artifacts": {name: hashlib.sha256(data).hexdigest() for name, data in delivery.items()}}
            with tarfile.open(assets / "hankoshell-operator-attest.tar.gz", "w:gz") as archive:
                add(archive, "attest.yaml", (ROOT / "attest.yaml").read_bytes())
                add(archive, "receipt.yaml", b"synthetic native verifier transport fixture")
                add(archive, "delivery/manifest.json", json.dumps(manifest).encode())
                for name, data in delivery.items(): add(archive, "delivery/" + name, data)
            release = {"draft": False, "prerelease": False, "tag_name": "v0.1.0", "published_at": "2026-10-01T00:00:00Z",
                "assets": [{"name": path.name, "size": path.stat().st_size, "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()} for path in assets.iterdir()]}
            commands = []
            def transport(command, **kwargs):
                commands.append([str(arg) for arg in command])
                if command[0] == "attest":
                    return json.dumps({"receipt": str(command[2]), "verdict": "pass", "signed_by": "c" * 64, "warnings": [],
                        "checks": [{"name": name, "status": "pass", "detail": "synthetic verifier transport"} for name in public.attestation.CHECKS]}).encode()
                return b""
            trust = {"KEY_ID": "d" * 32, "PUBLIC_KEY": "c" * 64, "TSA_CERTIFICATE": "synthetic public TSA anchor"}
            with patch.object(public.eligibility, "verify_tag", return_value={"tag_object": "e" * 40}), patch.object(public.attestation, "validate_public_identity"), patch.object(public, "run", side_effect=transport):
                self.assertTrue(public.verify(version, SHA, IMAGE, assets, trust, "cosign", "attest", fetch=lambda _: release)["verified"])
                self.assertEqual([command[1] for command in commands], ["verify-blob", "verify", "verify"])
                for command in commands[:2]:
                    self.assertIn("https://github.com/" + REPO + "/.github/workflows/release.yml@refs/tags/v0.1.0", command)
                    self.assertIn("https://token.actions.githubusercontent.com", command)
                self.assertIn("--recompute", commands[-1])
                self.assertIn("--offline", commands[-1])
                (assets / "source-revision.txt").write_text("f" * 40)
                with self.assertRaisesRegex(ValueError, "actual GitHub Release asset"):
                    public.verify(version, SHA, IMAGE, assets, trust, "cosign", "attest", fetch=lambda _: release)

    def test_upgrade_detects_uid_rotation_receipt_loss_native_changes_and_extra_secrets(self):
        before = {"objects": {"app": {"uid": "old", "receipt": {"state": "Verified"}}}, "secrets": {"credential": {"uid": "same", "data": "digest"}}, "native": {"realm": "native-digest"}}
        upgrade.preserve(before, copy.deepcopy(before))
        for surface in before:
            after = copy.deepcopy(before)
            after[surface]["unexpected"] = "changed"
            with self.subTest(surface=surface), self.assertRaises(ValueError): upgrade.preserve(before, after)
        self.assertNotEqual(upgrade.fingerprint({"roles": [{"id": 1}, {"id": 2}]}), upgrade.fingerprint({"roles": [{"id": 2}, {"id": 1}]}))

    def test_ordered_spec_changes_are_not_hidden_by_fingerprints(self):
        self.assertNotEqual(upgrade.fingerprint({"x": [1, 2]}), upgrade.fingerprint({"x": [2, 1]}))

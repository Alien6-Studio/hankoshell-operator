import copy
import hashlib
import importlib.util
import io
import json
import os
import itertools
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("attest_release", Path(__file__).with_name("attest-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class QualificationGateTests(unittest.TestCase):
    def test_ci_aggregate_fails_on_any_failed_cancelled_or_skipped_matrix(self):
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text())
        aggregate = workflow["jobs"]["checks"]
        self.assertEqual(aggregate["name"], "Source and chart checks")
        self.assertEqual(aggregate["if"], "always()")
        self.assertEqual(set(aggregate["needs"]), {"source", "kubernetes", "keycloak", "oci", "rehearsal", "system"})
        step = aggregate["steps"][0]
        dependencies = {f"${{{{ needs.{job}.result }}}}" for job in aggregate["needs"]}
        self.assertEqual(set(step["env"].values()), dependencies)
        for results in itertools.product(("success", "failure", "cancelled", "skipped"), repeat=len(aggregate["needs"])):
            with self.subTest(results=results):
                environment = dict(os.environ, **dict(zip(step["env"], results)))
                result = subprocess.run(["bash", "-c", step["run"]], env=environment,
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, all(value == "success" for value in results))

    def test_release_reuses_the_full_required_qualification_gate(self):
        root = Path(__file__).parents[1] / ".github/workflows"
        ci = yaml.safe_load((root / "ci.yml").read_text())
        delivery = yaml.safe_load((root / "release.yml").read_text())
        self.assertEqual(ci["jobs"]["keycloak"]["strategy"]["matrix"]["version"], ["26.8.0", "26.7.5"])
        self.assertFalse(ci["jobs"]["keycloak"].get("continue-on-error", False))
        self.assertEqual(delivery["jobs"]["quality"]["uses"], "./.github/workflows/ci.yml")
        self.assertEqual(delivery["jobs"]["publish"]["needs"], ["eligibility", "quality"])


class AttestVerdictTests(unittest.TestCase):
    def setUp(self):
        self.receipt = Path("/delivery/receipt.yaml")
        self.signer = "b" * 64
        self.verdict = {
            "receipt": str(self.receipt), "signed_by": self.signer,
            "verdict": "pass", "warnings": [],
            "checks": [{"name": name, "status": "pass", "detail": "verified"}
                       for name in sorted(release.CHECKS)],
        }

    def test_expected_native_verdict_passes(self):
        release.validate_verdict(self.verdict, self.signer, self.receipt)

    def test_pass_with_skipped_or_missing_timestamp_is_refused(self):
        for status in ("skipped", "fail"):
            report = copy.deepcopy(self.verdict)
            next(check for check in report["checks"] if check["name"] == "timestamp")["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                release.validate_verdict(report, self.signer, self.receipt)
        report = copy.deepcopy(self.verdict)
        report["checks"] = [check for check in report["checks"] if check["name"] != "timestamp"]
        with self.assertRaises(ValueError):
            release.validate_verdict(report, self.signer, self.receipt)

    def test_warnings_wrong_signer_and_wrong_receipt_are_refused(self):
        for field, value in (("warnings", ["revocation warning"]), ("signed_by", "c" * 64),
                             ("receipt", "/other/receipt.yaml"), ("verdict", "fail")):
            report = copy.deepcopy(self.verdict)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.validate_verdict(report, self.signer, self.receipt)

    def test_duplicate_check_and_unknown_native_fields_are_refused(self):
        report = copy.deepcopy(self.verdict)
        report["checks"][-1] = report["checks"][0]
        with self.assertRaises(ValueError):
            release.validate_verdict(report, self.signer, self.receipt)
        report = copy.deepcopy(self.verdict)
        report["trusted"] = True
        with self.assertRaises(ValueError):
            release.validate_verdict(report, self.signer, self.receipt)


class DeliveryArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dist = Path(self.temp.name)
        self.version = "0.2.0"
        self.revision = "1" * 40
        self.image = "ghcr.io/alien6-studio/hankoshell-operator@sha256:" + "a" * 64
        self.chart = self.dist / f"hankoshell-operator-{self.version}.tgz"
        with tarfile.open(self.chart, "w:gz") as archive:
            documents = {
                "values.yaml": {"image": {"repository": self.image.split("@")[0], "digest": self.image.split("@")[1], "tag": ""}},
                "Chart.yaml": {"version": self.version, "appVersion": self.version},
            }
            for name, document in documents.items():
                data = yaml.safe_dump(document).encode()
                member = tarfile.TarInfo("hankoshell-operator/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        from test_oci_security import write_evidence
        write_evidence(self.dist, self.revision, self.version, self.image.split("@")[1])
        (self.dist / "oci-vulnerability-policy.json").write_bytes(release.oci_security.POLICY.read_bytes())
        (self.dist / "image-digest.txt").write_text(self.image + "\n")
        (self.dist / "source-revision.txt").write_text(self.revision + "\n")
        (self.dist / "artifacthub-repo.yml").write_text("repositoryID: 8d452bd5-e2f7-47b6-94f1-c3b2ac7b4aac\n")
        (self.dist / release.PUBLIC_KEY_FILE).write_text(release.public_key_pem("b" * 64))
        (self.dist / "checksums.sigstore.json").write_text(json.dumps({"fixture": True}))
        (self.dist / "release-notes.md").write_text(release.contract.notes(self.version))
        names = [self.chart.name, "image-digest.txt", "source-revision.txt", "artifacthub-repo.yml", release.PUBLIC_KEY_FILE,
                 "oci-security.json", "trivy-amd64.json", "trivy-arm64.json", "oci-vulnerability-policy.json", "release-notes.md"]
        (self.dist / "checksums.txt").write_text("".join(
            hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in names))

    def check(self):
        return release.delivery_files(self.dist, self.version, self.revision, self.image)

    def test_exact_delivery_is_accepted(self):
        self.assertEqual(len(self.check()), 12)

    def test_modified_publisher_metadata_or_public_key_is_refused(self):
        for name in ("artifacthub-repo.yml", release.PUBLIC_KEY_FILE, "release-notes.md"):
            path = self.dist / name
            original = path.read_bytes()
            path.write_bytes(b"changed after signing")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check()
            path.write_bytes(original)

    def test_published_key_different_from_trusted_signer_is_refused(self):
        args = SimpleNamespace(attest=Path("/synthetic/attest"), dist=self.dist,
                               version=self.version, revision=self.revision, image=self.image)
        with patch.object(release.subprocess, "check_output", return_value="attest 0.1.0\n"), \
                self.assertRaisesRegex(ValueError, "Published Attest key"):
            release.sign_delivery(args, {"PUBLIC_KEY": "c" * 64})

    def test_modified_chart_is_refused(self):
        self.chart.write_bytes(b"changed after build")
        with self.assertRaises(ValueError):
            self.check()

    def test_chart_cannot_select_another_digest_or_tag_even_with_matching_checksums(self):
        original = self.chart.read_bytes()
        for field, value in (("digest", "sha256:" + "f" * 64), ("tag", "0.2.0"),
                             ("repository", "ghcr.io/another/operator")):
            self.chart.write_bytes(original)
            with tarfile.open(self.chart) as archive:
                documents = {member.name: archive.extractfile(member).read() for member in archive}
            name = "hankoshell-operator/values.yaml"
            values = yaml.safe_load(documents[name])
            values["image"][field] = value
            documents[name] = yaml.safe_dump(values).encode()
            with tarfile.open(self.chart, "w:gz") as archive:
                for name, data in documents.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            checksums = self.dist / "checksums.txt"
            lines = checksums.read_text().splitlines(keepends=True)
            checksums.write_text("".join(
                hashlib.sha256(self.chart.read_bytes()).hexdigest() + "  " + self.chart.name + "\n"
                if line.endswith("  " + self.chart.name + "\n") else line for line in lines))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Packaged chart"):
                self.check()

    def test_another_source_or_image_is_refused(self):
        with self.assertRaises(ValueError):
            release.delivery_files(self.dist, self.version, "2" * 40, self.image)
        with self.assertRaises(ValueError):
            release.delivery_files(self.dist, self.version, self.revision, self.image[:-1] + "f")

    def test_unexpected_private_material_and_symlinks_are_refused(self):
        private = self.dist / "signer.key"
        private.write_text("synthetic private material")
        with self.assertRaises(ValueError):
            self.check()
        private.unlink()
        self.chart.unlink()
        self.chart.symlink_to(self.dist / "source-revision.txt")
        with self.assertRaises(ValueError):
            self.check()

    def test_partial_or_duplicate_checksums_are_refused(self):
        path = self.dist / "checksums.txt"
        lines = path.read_text().splitlines(keepends=True)
        for contents in ("".join(lines[:-1]), "".join([*lines, lines[0]])):
            path.write_text(contents)
            with self.subTest(contents=contents), self.assertRaises(ValueError):
                self.check()

    def test_missing_signer_configuration_refuses_unsigned_delivery(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            release.configuration()


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("attest_release", Path(__file__).with_name("attest-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


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
        self.version = "0.1.0-alpha.1"
        self.revision = "1" * 40
        self.image = "ghcr.io/alien6-studio/hankoshell-operator@sha256:" + "a" * 64
        self.chart = self.dist / f"hankoshell-operator-{self.version}.tgz"
        self.chart.write_bytes(b"synthetic chart")
        (self.dist / "image-digest.txt").write_text(self.image + "\n")
        (self.dist / "source-revision.txt").write_text(self.revision + "\n")
        (self.dist / "artifacthub-repo.yml").write_text("repositoryID: 8d452bd5-e2f7-47b6-94f1-c3b2ac7b4aac\n")
        (self.dist / release.PUBLIC_KEY_FILE).write_text(release.public_key_pem("b" * 64))
        (self.dist / "checksums.sigstore.json").write_text(json.dumps({"fixture": True}))
        names = [self.chart.name, "image-digest.txt", "source-revision.txt", "artifacthub-repo.yml", release.PUBLIC_KEY_FILE]
        (self.dist / "checksums.txt").write_text("".join(
            hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in names))

    def check(self):
        return release.delivery_files(self.dist, self.version, self.revision, self.image)

    def test_exact_delivery_is_accepted(self):
        self.assertEqual(len(self.check()), 7)

    def test_modified_publisher_metadata_or_public_key_is_refused(self):
        for name in ("artifacthub-repo.yml", release.PUBLIC_KEY_FILE):
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

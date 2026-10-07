import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("release_metadata", Path(__file__).with_name("release-metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class ReleaseMetadataTests(unittest.TestCase):
    repository_id = "8d452bd5-e2f7-47b6-94f1-c3b2ac7b4aac"
    public_key = "b" * 64
    image = metadata.IMAGE + "@sha256:" + "a" * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.chart = self.root / "chart/hankoshell-operator"
        self.dist = self.root / "dist"
        self.version = yaml.safe_load((metadata.ROOT / "charts/hankoshell-operator/Chart.yaml").read_text())["version"]

    def prepare(self, version=None, image=None):
        metadata.prepare(version or self.version, image or self.image, self.chart,
                         self.dist, self.repository_id, self.public_key)

    def test_release_chart_pins_image_and_links_the_delivered_public_key(self):
        source = (metadata.ROOT / "charts/hankoshell-operator/Chart.yaml").read_bytes()
        self.prepare()
        chart = yaml.safe_load((self.chart / "Chart.yaml").read_text())
        annotations = chart["annotations"]
        self.assertEqual(yaml.safe_load(annotations["artifacthub.io/images"])[0]["image"], self.image)
        self.assertEqual(annotations["artifacthub.io/prerelease"], "true" if "-" in self.version else "false")
        self.assertEqual(yaml.safe_load(annotations["artifacthub.io/signKey"])["url"],
                         f"{metadata.REPOSITORY}/releases/download/v{self.version}/{metadata.PUBLIC_KEY_FILE}")
        self.assertEqual(yaml.safe_load((self.dist / "artifacthub-repo.yml").read_text()),
                         {"repositoryID": self.repository_id})
        self.assertTrue((self.dist / metadata.PUBLIC_KEY_FILE).read_text().startswith("-----BEGIN PUBLIC KEY-----\n"))
        self.assertTrue((self.chart / "icon.svg").is_file())
        self.assertEqual((metadata.ROOT / "charts/hankoshell-operator/Chart.yaml").read_bytes(), source)

    def test_unsigned_image_another_repository_and_version_drift_are_refused(self):
        for version, image in ((self.version, metadata.IMAGE + ":latest"),
                               (self.version, self.image.replace("alien6-studio", "another-publisher")),
                               ("99.0.0", self.image)):
            with self.subTest(version=version, image=image), self.assertRaises(ValueError):
                self.prepare(version, image)
            self.assertFalse(self.chart.exists())
            self.assertFalse(self.dist.exists())

    def test_missing_invalid_and_placeholder_publisher_ids_are_refused(self):
        for repository_id in ("", "not-an-id", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(repository_id=repository_id), patch.dict(os.environ, {
                "HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID": repository_id,
                "HANKOSHELL_ATTEST_PUBLIC_KEY": self.public_key,
            }, clear=True), self.assertRaises(ValueError):
                metadata.configuration()

    def test_real_id_and_explicit_trusted_signer_are_required(self):
        with patch.dict(os.environ, {
            "HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID": self.repository_id,
            "HANKOSHELL_ATTEST_PUBLIC_KEY": self.public_key,
        }, clear=True):
            self.assertEqual(metadata.configuration(), (self.repository_id, self.public_key))
            del os.environ["HANKOSHELL_ATTEST_PUBLIC_KEY"]
            with self.assertRaises(ValueError):
                metadata.configuration()


if __name__ == "__main__":
    unittest.main()

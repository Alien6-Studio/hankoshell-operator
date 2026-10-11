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
                         self.dist, self.repository_id, self.public_key, "1" * 40)

    def test_release_chart_pins_image_and_links_the_delivered_public_key(self):
        source = (metadata.ROOT / "charts/hankoshell-operator/Chart.yaml").read_bytes()
        self.prepare()
        chart = yaml.safe_load((self.chart / "Chart.yaml").read_text())
        annotations = chart["annotations"]
        self.assertEqual(yaml.safe_load(annotations["artifacthub.io/images"])[0]["image"], self.image)
        self.assertEqual(annotations["artifacthub.io/prerelease"], "true" if "-" in self.version else "false")
        self.assertNotIn("artifacthub.io/signKey", annotations)
        self.assertFalse(any(link["name"] == "Attest delivery verification key"
                             for link in yaml.safe_load(annotations["artifacthub.io/links"])))
        self.assertEqual(chart["icon"],
                         "https://raw.githubusercontent.com/Alien6-Studio/hankoshell-operator/" + "1" * 40 + "/charts/hankoshell-operator/icon.svg")
        self.assertEqual(yaml.safe_load((self.dist / "artifacthub-repo.yml").read_text()),
                         {"repositoryID": self.repository_id})
        self.assertTrue((self.dist / metadata.PUBLIC_KEY_FILE).read_text().startswith("-----BEGIN PUBLIC KEY-----\n"))
        self.assertTrue((self.chart / "icon.svg").is_file())
        image_values = yaml.safe_load((self.chart / "values.yaml").read_text())["image"]
        self.assertEqual(image_values["repository"] + "@" + image_values["digest"], self.image)
        self.assertEqual(image_values["tag"], "")
        self.assertEqual((metadata.ROOT / "charts/hankoshell-operator/Chart.yaml").read_bytes(), source)

    def test_development_icon_cannot_use_an_uncreated_version_tag(self):
        for revision in (None, "main", "v0.1.0-dev.0", "short"):
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "source revision"):
                metadata.prepare(self.version, self.image, self.chart, self.dist,
                                 self.repository_id, self.public_key, revision)
        self.assertFalse(self.chart.exists())

    def test_future_stable_candidate_uses_normal_tag_assets(self):
        source = self.root / "source"
        import shutil
        shutil.copytree(metadata.ROOT / "charts", source / "charts")
        path = source / "charts/hankoshell-operator/Chart.yaml"
        chart = yaml.safe_load(path.read_text())
        chart.update(version="0.1.0", appVersion="0.1.0")
        path.write_text(yaml.safe_dump(chart))
        with patch.object(metadata, "ROOT", source), \
                patch.object(metadata.versioning, "VERSION", "0.1.0"), \
                patch.object(metadata.versioning, "RELEASE_STATUS", "candidate"):
            metadata.prepare("0.1.0", self.image, self.chart, self.dist,
                             self.repository_id, self.public_key, "1" * 40)
        result = yaml.safe_load((self.chart / "Chart.yaml").read_text())
        self.assertEqual(result["annotations"]["artifacthub.io/prerelease"], "false")
        key = yaml.safe_load(result["annotations"]["artifacthub.io/links"])[0]
        self.assertEqual(key["url"], metadata.REPOSITORY + "/releases/download/v0.1.0/" + metadata.PUBLIC_KEY_FILE)
        self.assertIn("/v0.1.0/charts/", result["icon"])

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

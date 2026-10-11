import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


path = Path(__file__).with_name("release-version.py")
spec = importlib.util.spec_from_file_location("release_version", path)
versioning = importlib.util.module_from_spec(spec)
spec.loader.exec_module(versioning)


class PublicReleaseVersionTests(unittest.TestCase):
    def test_public_namespace_extracts_product_semver_without_checkpoint_alias(self):
        for version in ("0.1.0", "0.1.1", "0.2.0", "1.2.3-rc.1", "1.2.3-alpha01+build.001"):
            with self.subTest(version=version):
                self.assertEqual(versioning.from_tag("release/v" + version), version)
                self.assertEqual(versioning.public_tag(version), "release/v" + version)

    def test_historical_wrong_namespaces_and_invalid_semver_are_rejected(self):
        for tag in ("v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0", "v0.5.0", "v0.5.1",
                    "main", "refs/heads/main", "refs/tags/release/v0.1.0", "0.1.0", "public/v0.1.0",
                    "release/0.1.0", "release/v01.0.0", "release/v0.01.0", "release/v0.1.00",
                    "release/v0.1", "release/v0.1.0/foo", "release/v0.1.0%2Ffoo",
                    "release/v0.1.0-01", "release/v0.1.0-rc..1", "release/v0.1.0+",
                    "release/v0.1.0+build..1", "release/v0.1.0\n", " release/v0.1.0",
                    "release/v0.١.0", "release/v0.1.0" + "a" * 256, "", None, 1):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                versioning.from_tag(tag)
        for version in ("01.0.0", "0.1", "0.1.0-01", "0.1.0/foo", "v0.1.0", "0.1.0\n", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                versioning.public_tag(version)

    def test_workflow_cli_derives_exact_version_and_fails_closed(self):
        result = subprocess.run([sys.executable, str(path), "release/v0.1.0"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "0.1.0\n")
        for tag in ("v0.1.0", "main", "release/v0.1.0/foo"):
            with self.subTest(tag=tag):
                result = subprocess.run([sys.executable, str(path), tag], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

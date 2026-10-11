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
    def test_normal_tags_extract_product_semver(self):
        for version in ("0.1.0", "0.1.1", "0.2.0", "1.2.3-rc.1", "1.2.3-alpha01+build.001"):
            with self.subTest(version=version):
                self.assertEqual(versioning.from_tag("v" + version), version)
                self.assertEqual(versioning.public_tag(version), "v" + version)

    def test_wrong_namespaces_and_invalid_semver_are_rejected(self):
        for tag in ("release/v0.1.0", "main", "refs/heads/main", "refs/tags/v0.1.0", "0.1.0", "public/v0.1.0",
                    "release/0.1.0", "v01.0.0", "v0.01.0", "v0.1.00", "v0.1",
                    "v0.1.0/foo", "v0.1.0%2Ffoo", "v0.1.0-01", "v0.1.0-rc..1", "v0.1.0+",
                    "v0.1.0+build..1", "v0.1.0\n", " v0.1.0", "v0.١.0", "v0.1.0" + "a" * 256, "", None, 1):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                versioning.from_tag(tag)
        for version in ("01.0.0", "0.1", "0.1.0-01", "0.1.0/foo", "v0.1.0", "0.1.0\n", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                versioning.public_tag(version)

    def test_workflow_cli_derives_exact_version_and_fails_closed(self):
        result = subprocess.run([sys.executable, str(path), "v0.1.0"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "0.1.0\n")
        for tag in ("release/v0.1.0", "main", "v0.1.0/foo"):
            with self.subTest(tag=tag):
                result = subprocess.run([sys.executable, str(path), tag], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

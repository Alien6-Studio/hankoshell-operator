"""Verifier overrides accept exact fixes while rejecting mutable or unsafe pins."""
import copy
import unittest

from tools import versions


class VerifierPinsTest(unittest.TestCase):
    def test_exact_stable_and_security_fix_versions(self):
        for pin in ("v0.58.0", "v0.58.1-0.20261009181718-2f1f834330b2"):
            with self.subTest(pin=pin):
                data = copy.deepcopy(versions.DATA)
                data["tools"]["cosign"]["dependencies"]["golang.org/x/crypto"] = pin
                generated = versions.generated(data=data)
                self.assertIn("golang.org/x/crypto@" + pin, generated["tools/bootstrap/cosign_pins.sh"])

    def test_mutable_incomplete_and_shell_pins_are_rejected(self):
        for pin in ("latest", "master", "v0.58", "v0.58.1-0.20261009181718-2f1f834330b",
                    "v0.58.1-0.20261009181718-2f1f834330b2;id", "v0.58.0\nother@v1.0.0"):
            with self.subTest(pin=pin):
                data = copy.deepcopy(versions.DATA)
                data["tools"]["cosign"]["dependencies"]["golang.org/x/crypto"] = pin
                with self.assertRaisesRegex(ValueError, "pinned cosign dependency"):
                    versions.generated(data=data)

    def test_verifier_itself_still_requires_a_stable_release(self):
        data = copy.deepcopy(versions.DATA)
        data["tools"]["cosign"]["version"] = "v3.1.5-0.20261009181718-2f1f834330b2"
        with self.assertRaisesRegex(ValueError, "pinned cosign release"):
            versions.generated(data=data)


if __name__ == "__main__":
    unittest.main()

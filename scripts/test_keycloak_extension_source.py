import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import keycloak_extension_source as source


class ExtensionSourceTests(unittest.TestCase):
    def test_pin_rejects_moving_foreign_and_unknown_sources(self):
        reviewed = source.pin()
        changes = [{"revision": "main"}, {"revision": "a" * 39}, {"revision": "a" * 40 + "\n"},
                   {"repository": "foreign/provider"}, {"contract": "different"}, {"extra": True}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "extensions").mkdir()
            for change in changes:
                (root / "extensions/keycloak-bounded-delegation.json").write_text(json.dumps({**reviewed, **change}))
                with self.subTest(change=change), patch.object(source, "ROOT", root), self.assertRaises(ValueError):
                    source.pin()

    def test_sdk_artifact_binds_the_exact_source_revision(self):
        for version in source.versions.get("keycloak", "versions"):
            path = source.artifact(version)
            self.assertIn(source.pin()["revision"], path.parts)
            self.assertEqual(path.name, "bounded-delegation-keycloak-" + version + ".jar")
        for version in ("latest", "26.8.1", "../26.8.0"):
            with self.assertRaises(ValueError):
                source.artifact(version)

    def test_cached_source_refuses_drift_without_repair_or_network(self):
        reviewed = source.pin()
        url = "https://github.com/" + reviewed["repository"] + ".git"
        with tempfile.TemporaryDirectory() as temporary, patch.object(source, "ROOT", Path(temporary)):
            path = source.directory(reviewed)
            path.mkdir(parents=True)
            with patch.object(source, "pin", return_value=reviewed):
                for metadata in (["b" * 40], [reviewed["revision"], "https://example.invalid/foreign.git"],
                                 [reviewed["revision"], url, " M src/main/java/Provider.java"]):
                    with self.subTest(metadata=metadata), patch.object(source.subprocess, "check_output", side_effect=metadata), \
                            patch.object(source.subprocess, "run") as mutate, self.assertRaises(ValueError):
                        source.checkout()
                    mutate.assert_not_called()
                with patch.object(source.subprocess, "check_output", side_effect=[reviewed["revision"], url, ""]), \
                        patch.object(source.subprocess, "run") as mutate:
                    self.assertEqual(source.checkout(), path)
                    mutate.assert_not_called()

    def test_qualification_refuses_replaced_artifacts_and_foreign_build_identity(self):
        reviewed = source.pin()
        version = source.versions.get("keycloak", "default")
        with tempfile.TemporaryDirectory() as temporary, patch.object(source, "ROOT", Path(temporary)), \
                patch.object(source, "pin", return_value=reviewed):
            jar = source.artifact(version)
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b"synthetic test artifact")
            manifest = jar.parent / "build.json"
            built = {"extension": reviewed, "keycloak": version, "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest()}
            manifest.write_text(json.dumps(built))
            source.verify_artifact(version, jar)
            for changed in ({"keycloak": "99.0.0"}, {"extension": {**reviewed, "revision": "b" * 40}}, {"jar_sha256": "0" * 64}):
                manifest.write_text(json.dumps({**built, **changed}))
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    source.verify_artifact(version, jar)
            manifest.write_text(json.dumps(built))
            jar.write_bytes(b"modified after the successful build")
            with self.assertRaises(ValueError):
                source.verify_artifact(version, jar)


if __name__ == "__main__":
    unittest.main()

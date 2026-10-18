"""Keep delegation qualification evidence narrow and exercise genuine attenuation."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


installed = module("installed_delegation", "delegation-installed-test.py")
proxy = module("delegation_proxy", "workload-fault-proxy.py")


class DelegationEvidenceTests(unittest.TestCase):
    def test_ordinary_inputs_are_broader_than_the_delegation(self):
        spec = installed.server_spec()
        ordinary, bounded = spec["permissions"]
        self.assertEqual(set(ordinary["resources"]), {"allowed", "denied"})
        self.assertEqual(set(ordinary["scopes"]), {"read", "write"})
        self.assertEqual(bounded["resources"], ["allowed"])
        self.assertEqual(bounded["scopes"], ["read"])
        self.assertEqual(bounded["delegation"]["maxDepth"], 2)
        self.assertNotEqual(bounded["delegation"]["actor"], bounded["delegation"]["subject"])
        self.assertIn({"kind": "service_account", "ref": "delegation-foreign"}, ordinary["principals"])
        self.assertNotIn({"kind": "service_account", "ref": "delegation-foreign"}, bounded["principals"])
        withdrawn = installed.server_spec(delegated=False)
        self.assertEqual(withdrawn["permissions"], [ordinary])

    def test_evidence_drops_all_private_representations_even_on_failure(self):
        fixture = installed.Delegation.__new__(installed.Delegation)
        fixture.report = {"complete": False, "active_phase": "native_flows", "checks": {"real_pod": True},
                          "actor_token": "private", "subject": {"access_token": "private"}, "native": {"secret": "private"}, "kubeconfig": "private"}
        public = fixture.public_evidence()
        self.assertEqual(public, {"complete": False, "active_phase": "native_flows", "checks": {"real_pod": True}})
        self.assertNotIn("private", json.dumps(public))

    def test_phase_faults_ignore_other_native_documents_and_malformed_attributes(self):
        rule = {"method": "PUT", "path": "/native/client", "document_attribute": installed.ATTRIBUTE, "phase": "Applied"}
        valid = {"attributes": {installed.ATTRIBUTE: json.dumps({"phase": "Applied"})}}
        self.assertTrue(proxy.matches(rule, "PUT", "/native/client", json.dumps(valid).encode()))
        for body in ({}, {"attributes": []}, {"attributes": {installed.ATTRIBUTE: "invalid"}},
                     {"attributes": {installed.ATTRIBUTE: json.dumps({"phase": "Verified"})}},
                     {"attributes": {"foreign": valid["attributes"][installed.ATTRIBUTE]}}):
            with self.subTest(body=body):
                self.assertFalse(proxy.matches(rule, "PUT", "/native/client", json.dumps(body).encode()))
        self.assertFalse(proxy.matches(rule, "PUT", "/other/client", json.dumps(valid).encode()))
        self.assertFalse(proxy.matches(rule, "POST", "/native/client", json.dumps(valid).encode()))

    def test_incoming_provider_artifact_cannot_come_from_another_or_dirty_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "provider.jar"
            jar.write_bytes(b"synthetic-provider")
            pin = installed.extension.pin()
            baseline = {"revision": "a" * 40, "worktree_dirty": False, "java_tests": ["case-" + str(i) for i in range(16)],
                        "extension": pin, "keycloak": "26.8.0", "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest()}
            with patch.object(installed.extension, "artifact", return_value=jar):
                (root / "build.json").write_text(json.dumps(baseline))
                installed.validate_build("26.8.0", "a" * 40)
                for change in ({"revision": "b" * 40}, {"worktree_dirty": True}, {"java_tests": ["same"] * 16},
                               {"java_tests": []}, {"java_tests": "not-an-inventory"}, {"jar_sha256": "0" * 64}):
                    with self.subTest(change=change):
                        build = copy.deepcopy(baseline)
                        build.update(change)
                        (root / "build.json").write_text(json.dumps(build))
                        with self.assertRaises(ValueError):
                            installed.validate_build("26.8.0", "a" * 40)


if __name__ == "__main__":
    unittest.main()

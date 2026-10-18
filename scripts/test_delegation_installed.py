"""Keep delegation qualification evidence narrow and exercise genuine attenuation."""

import base64
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
probe = module("delegation_pod_probe", "delegation-pod-probe.py")


class DelegationEvidenceTests(unittest.TestCase):
    def test_pod_input_reports_permission_presence_without_expanding_host_claims(self):
        def token(claims):
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
            return "e30." + payload + ".fixture"

        issuer = installed.native.REALM_ISSUER
        settings = {"action": "input", "issuer": issuer, "endpoint": issuer + "/protocol/openid-connect/token",
                    "audience": "other-api", "client": "delegation-actor", "account": "worker", "uid": "worker-uid", "permissions": ["allowed#read"]}
        assertion = token({"aud": [issuer], "iat": 100, "exp": 700, "sub": "system:serviceaccount:workload:worker",
                           "kubernetes.io": {"serviceaccount": {"uid": "worker-uid"}}})
        cases = (({"permissions": [{"rsid": "other-resource", "scopes": ["read"]}]}, True),
                 ({"permissions": []}, False), (None, False), ({"permissions": "invalid"}, False))
        for authorization, present in cases:
            with self.subTest(authorization=authorization):
                rpt = token({"iss": issuer, "aud": "other-api", "exp": 900, "authorization": authorization})
                with patch.object(probe.ssl, "create_default_context"), patch.object(probe.Path, "read_text", return_value=assertion), \
                        patch.object(probe, "request", side_effect=[(200, {"access_token": token({})}), (200, {"access_token": rpt})]):
                    result = probe.execute(settings)
                self.assertEqual(result["http_status"], 200)
                self.assertIs(result["permissions_present"], present)
                self.assertNotIn("authorization", installed.native.claims(result["access_token"]))

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

    def test_post_commit_failure_refuses_only_the_verified_ready_status(self):
        path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankoresourceservers/installed-server/status"
        rule = installed.post_commit_status_fault(path)
        self.assertTrue(proxy.matches(rule, "PATCH", path, json.dumps({"status": {"phase": "Ready"}}).encode()))
        for body in ({"status": {"phase": "Error"}}, {"status": {"phase": "Pending"}}, {"status": {}}, {}, [], {"status": None}):
            with self.subTest(body=body):
                self.assertFalse(proxy.matches(rule, "PATCH", path, json.dumps(body).encode()))
        body = json.dumps({"status": {"phase": "Ready"}}).encode()
        self.assertFalse(proxy.matches(rule, "PUT", path, body))
        self.assertFalse(proxy.matches(rule, "PATCH", path.replace("installed-server", "foreign-server"), body))

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

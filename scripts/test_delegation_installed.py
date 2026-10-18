"""Keep delegation qualification evidence narrow and exercise genuine attenuation."""

import base64
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


installed = module("installed_delegation", "delegation-installed-test.py")
proxy = module("delegation_proxy", "workload-fault-proxy.py")
probe = module("delegation_pod_probe", "delegation-pod-probe.py")


class DelegationEvidenceTests(unittest.TestCase):
    def test_failure_ownership_summary_retains_only_fixed_decisions_and_counts(self):
        attributes = {"hanko.sh/application-owner": "private-app-uid", "private-key": "private-value",
            installed.ATTRIBUTE: json.dumps({"ownerUID": "private-server-uid", "phase": "Prepared",
                "audience": {"id": "private-native-id", "attribute": "hanko.sh/application-owner", "value": "private-app-uid"}}),
            "hanko.sh/resource-server-ownership": json.dumps({"ownerUID": "private-server-uid", "objects": {"scopes": [{"id": "private-scope"}]}})}
        current = {"id": "private-native-id", "secret": "private-secret", "attributes": attributes}
        result = installed.ownership_summary(current, "HankoApplication", "private-app-uid", "private-server-uid")
        self.assertTrue(result["uid_matches"])
        self.assertTrue(result["delegation_owner_matches"])
        self.assertTrue(result["delegation_audience_matches"])
        self.assertEqual(result["delegation_phase"], "Prepared")
        self.assertEqual(result["journal_counts"], {"scopes": 1, "resources": 0, "policies": 0, "permissions": 0})
        self.assertNotIn("private", json.dumps(result))
        for malformed in ("private-invalid-json", "[]", "null", json.dumps({"objects": None})):
            attributes["hanko.sh/resource-server-ownership"] = malformed
            result = installed.ownership_summary(current, "HankoApplication", "private-app-uid", "private-server-uid")
            self.assertFalse(result["authorization_json_object"])
            self.assertNotIn("private", json.dumps(result))

    def test_failure_snapshot_stops_on_budget_or_refused_reads_without_private_exceptions(self):
        for mode in ("deadline", "provider"):
            with self.subTest(mode=mode):
                fixture = installed.Delegation.__new__(installed.Delegation)
                fixture.report = {}
                fixture.args = SimpleNamespace(kubectl="kubectl")
                fixture.config = Path("private-kubeconfig")
                fixture.password, fixture.endpoint, fixture.http, fixture.sensitive = "private-password", "https://fixture.invalid", None, []
                with patch.object(installed.time, "monotonic", side_effect=[0, 26] if mode == "deadline" else lambda: 0), \
                        patch.object(installed.system.diagnostics, "bounded_command", return_value='{"metadata":{"uid":"private-server-uid"}}'), \
                        patch.object(installed, "urlopen", side_effect=RuntimeError("private-provider-response")) as request:
                    fixture.capture_ownership_failure()
                result = fixture.public_evidence()
                self.assertFalse(result["failure_ownership"]["complete"])
                self.assertNotIn("private", json.dumps(result))
                if mode == "deadline":
                    request.assert_not_called()
                else:
                    self.assertEqual(request.call_args.kwargs["timeout"], 2)

    def test_complete_failure_snapshot_uses_only_bounded_reads_and_omits_native_values(self):
        fixture = installed.Delegation.__new__(installed.Delegation)
        fixture.report, fixture.config = {}, Path("private-kubeconfig")
        fixture.args = SimpleNamespace(kubectl="kubectl")
        fixture.password, fixture.endpoint, fixture.http, fixture.sensitive = "private-password", "https://fixture.invalid", None, []
        names = ["installed-api", *installed.IDENTITIES]

        def native(path):
            if "/authz/" in path:
                return [{"id": "private-native-value", "secret": "private-secret"}] * 2
            if "?" in path:
                return [{"clientId": name, "id": "native-" + str(index)} for index, name in enumerate(names)]
            audience = path.endswith("native-0")
            return {"id": "private-native-id", "secret": "private-secret", "attributes": {
                "hanko.sh/application-owner" if audience else "hanko.sh/client-owner-uid": "private-uid",
                "hanko.sh/client-owner-kind": "HankoServiceAccount"}}

        @contextlib.contextmanager
        def response(request, context, timeout):
            self.assertEqual(timeout, 2)
            if request.get_method() == "POST":
                self.assertTrue(request.full_url.endswith("/realms/master/protocol/openid-connect/token"))
                data = {"access_token": "private-admin-token"}
            else:
                self.assertEqual(request.get_method(), "GET")
                data = native(request.full_url)
            yield SimpleNamespace(read=lambda _: json.dumps(data).encode())

        with patch.object(installed.time, "monotonic", return_value=0), \
                patch.object(installed.system.diagnostics, "bounded_command", return_value='{"metadata":{"uid":"private-uid"}}') as kube, \
                patch.object(installed, "urlopen", side_effect=response) as request:
            fixture.capture_ownership_failure()
        snapshot = fixture.public_evidence()["failure_ownership"]
        self.assertTrue(snapshot["complete"])
        self.assertEqual(len(snapshot["clients"]), 4)
        self.assertTrue(all(value["uid_matches"] for value in snapshot["clients"]))
        self.assertEqual(snapshot["native_counts"], {kind: 2 for kind in ("scope", "resource", "policy", "permission")})
        self.assertEqual(snapshot["journal_coverage"]["scope"], {"recorded": 0, "recorded_missing_live": 0, "live_unrecorded": 1})
        self.assertNotIn("private", json.dumps(snapshot))
        self.assertEqual(request.call_count, 10)
        self.assertIn("private-admin-token", fixture.sensitive)
        for call in kube.call_args_list:
            self.assertIn("get", call.args[0])
            self.assertEqual(call.args[1], 2)

    def test_failure_snapshot_refuses_oversized_admin_token_or_native_document(self):
        for target in ("token", "native"):
            with self.subTest(target=target):
                fixture = installed.Delegation.__new__(installed.Delegation)
                fixture.report, fixture.config, fixture.args = {}, Path("private-config"), SimpleNamespace(kubectl="kubectl")
                fixture.password, fixture.endpoint, fixture.http, fixture.sensitive = "private-password", "https://fixture.invalid", None, []

                @contextlib.contextmanager
                def response(request, **kwargs):
                    token = request.get_method() == "POST"
                    raw = b"x" * (65_537 if token else 1_048_577) if target == ("token" if token else "native") else b'{"access_token":"private-admin-token"}'
                    yield SimpleNamespace(read=lambda limit: raw[:limit])

                with patch.object(installed.time, "monotonic", return_value=0), \
                        patch.object(installed.system.diagnostics, "bounded_command", return_value='{"metadata":{"uid":"private-uid"}}'), \
                        patch.object(installed, "urlopen", side_effect=response):
                    fixture.capture_ownership_failure()
                self.assertFalse(fixture.report["failure_ownership"]["complete"])
                self.assertNotIn("private", json.dumps(fixture.public_evidence()))

    def test_application_refresh_preserves_authority_across_plan_revisions(self):
        for mutation in ("revision", "grant", "objects"):
            with self.subTest(mutation=mutation):
                fixture = installed.Delegation.__new__(installed.Delegation)
                fixture.report = {"checks": {}}
                before = {"phase": "Committed", "revision": "old", "ownerUID": "owner", "grants": [{"maxDepth": 2}]}
                after = copy.deepcopy(before)
                after["revision"] = "fresh"
                if mutation == "grant":
                    after["grants"][0]["maxDepth"] = 3
                fixture.document = Mock(side_effect=[before, after])
                fixture.native_inventory = Mock(side_effect=[{"resources": ["owned"]}, {"resources": ["foreign" if mutation == "objects" else "owned"]}])
                fixture.get = Mock(side_effect=[{"status": {"appliedPlanHash": "old"}}, {"status": {"appliedPlanHash": "fresh"}}])
                fixture.patch, fixture.ready = Mock(), Mock(return_value=True)
                fixture.server_ready, fixture.positive = Mock(), Mock()
                with contextlib.redirect_stdout(io.StringIO()):
                    if mutation == "revision":
                        fixture.application_coexistence()
                        fixture.positive.assert_called_once_with()
                    else:
                        with self.assertRaisesRegex(ValueError, "application_update_preserves_native_delegation"):
                            fixture.application_coexistence()
                        fixture.positive.assert_not_called()

    def test_positive_flow_enforces_the_declared_lifetime(self):
        payload = base64.urlsafe_b64encode(json.dumps({"exp": 1000}).encode()).decode().rstrip("=")
        for declared, issued in ((8, 8), (8, 9), (30, 30), (30, 31), (300, 300), (300, 301)):
            with self.subTest(declared=declared, issued=issued):
                fixture = installed.Delegation.__new__(installed.Delegation)
                fixture.report = {"checks": {"independent_broad_input_allows_more_authority": True}}
                fixture.get = Mock(return_value={"spec": installed.server_spec(declared)})
                fixture.input = Mock(return_value="e30." + payload + ".fixture")
                fixture.exchange = Mock(return_value={"http_status": 200, "depth": 1, "issuer_matches": True,
                    "ordinary_claims_absent": True, "refresh_token_absent": True, "expires_at": 100 + issued,
                    "checked_at": 100, "access_token": "synthetic-delegated-token"})
                fixture.access = Mock(side_effect=lambda token, resource="allowed", scope="read": {
                    "http_status": 200 if resource == "allowed" and scope == "read" else 403,
                    "allowed": resource == "allowed" and scope == "read"})
                with contextlib.redirect_stdout(io.StringIO()):
                    if issued <= declared:
                        fixture.positive()
                    else:
                        with self.assertRaisesRegex(ValueError, "native_token_boundaries"):
                            fixture.positive()

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

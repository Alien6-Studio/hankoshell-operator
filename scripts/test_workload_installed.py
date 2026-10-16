"""Protect installed evidence and require genuine independent UMA denials."""

import importlib.util
import copy
import hashlib
import json
from io import BytesIO
from email.message import Message
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


installed = module("installed_fixture", "workload-installed-test.py")
probe = module("pod_probe", "workload-pod-probe.py")
proxy = module("fault_proxy", "workload-fault-proxy.py")


class InstalledEvidenceTests(unittest.TestCase):
    def test_snapshot_fixture_explicitly_enables_lifecycle(self):
        args = SimpleNamespace(keycloak_version="26.8.0", kubernetes_version="1.37.0",
                               deep_migration=False, revision="a"*40, digest="sha256:"+"b"*64)
        with tempfile.TemporaryDirectory() as directory:
            fixture = installed.Installed(args, Path(directory))
            self.assertIs(fixture.install_values["lifecycle"]["enabled"], True)

    def test_every_scope_is_independently_approved_before_capture(self):
        fixture = MagicMock()
        fixture.args.deep_migration = False
        fixture.get.return_value = {"status": {"configMapRef": "capture"}}
        with patch.object(installed, "wait"), patch.object(installed, "snapshot_capture_valid", return_value=True):
            installed.Installed.snapshot_isolation(fixture)
        self.assertEqual(fixture.approve_lifecycle.call_count, 4)
        for scope in ("unlabelled", "empty", "tenant-a", "tenant-b"):
            fixture.approve_lifecycle.assert_any_call("hankosnapshot", "snapshot-"+scope, "auth", operator_name="system-operator")


    def test_snapshot_evidence_requires_exact_scope_for_every_configuration_kind(self):
        for scope in (None, "", "tenant-a"):
            labels = {} if scope is None else {"hanko.sh/tenant": scope}
            snapshot = {"metadata": {"namespace": "auth", "labels": labels},
                        "status": {"phase": "Done", "configMapUID": "capture-uid"}}
            payload = {kind: [{"metadata": {"name": "selected", "namespace": "auth", "labels": labels}}]
                       for kind in ("realms", "applications", "serviceAccounts", "issuers")}

            def capture(document):
                raw = json.dumps(document)
                snapshot["status"]["configHash"] = hashlib.sha256(raw.encode()).hexdigest()
                return {"metadata": {"uid": "capture-uid"}, "immutable": True, "data": {"snapshot.json": raw}}

            self.assertTrue(installed.snapshot_capture_valid(snapshot, capture(payload), "selected"))
            for kind in payload:
                for foreign in ({}, {"hanko.sh/tenant": ""}, {"hanko.sh/tenant": "tenant-b"}):
                    if foreign == labels:
                        continue
                    document = copy.deepcopy(payload)
                    document[kind].append({"metadata": {"name": "foreign", "namespace": "auth", "labels": foreign}})
                    with self.subTest(scope=scope, kind=kind, foreign=foreign):
                        self.assertFalse(installed.snapshot_capture_valid(snapshot, capture(document), "selected"))
                document = copy.deepcopy(payload)
                document[kind][0]["metadata"]["namespace"] = "another"
                self.assertFalse(installed.snapshot_capture_valid(snapshot, capture(document), "selected"))
                document = copy.deepcopy(payload)
                document[kind] = []
                self.assertFalse(installed.snapshot_capture_valid(snapshot, capture(document), "selected"))

    def test_snapshot_evidence_rejects_stale_or_unbound_capture_even_with_safe_content(self):
        raw = json.dumps({kind: [{"metadata": {"name": "selected", "namespace": "auth"}}]
                          for kind in ("realms", "applications", "serviceAccounts", "issuers")})
        snapshot = {"metadata": {"namespace": "auth"}, "status": {
            "phase": "Done", "configMapUID": "capture-uid", "configHash": hashlib.sha256(raw.encode()).hexdigest()}}
        capture = {"metadata": {"uid": "capture-uid"}, "immutable": True, "data": {"snapshot.json": raw}}
        for change in ("phase", "uid", "digest", "mutable", "malformed", "missing-kind"):
            current, stored = copy.deepcopy(snapshot), copy.deepcopy(capture)
            if change == "phase":
                current["status"]["phase"] = "Running"
            elif change == "uid":
                stored["metadata"]["uid"] = "replacement"
            elif change == "digest":
                current["status"]["configHash"] = "0" * 64
            elif change == "mutable":
                stored["immutable"] = False
            else:
                stored["data"]["snapshot.json"] = "invalid" if change == "malformed" else "{}"
                current["status"]["configHash"] = hashlib.sha256(stored["data"]["snapshot.json"].encode()).hexdigest()
            with self.subTest(change=change):
                self.assertFalse(installed.snapshot_capture_valid(current, stored, "selected"))

    def test_outage_waits_past_partial_and_stale_status_until_binding_is_invalidated(self):
        def account(binding, runtime, generation=2, binding_status="False"):
            return {"metadata": {"generation": 2}, "status": {
                "phase": "Pending", "workloadBinding": binding, "runtimeMetadata": runtime,
                "conditions": [{"type": name, "status": binding_status if name == "WorkloadBindingReady" else "False",
                                "observedGeneration": generation}
                               for name in ("WorkloadBindingReady", "FederatedModeApplied", "Synced")]}}
        fixture = installed.Installed.__new__(installed.Installed)
        # Reproduce the failed CI snapshot: Synced=False with a previously
        # validated binding, then stale and partially cleared status snapshots.
        pending = [account({"bindingRevision": "old"}, {"metadataHash": "old"}, binding_status="True"),
                   account(None, None, generation=1), account(None, {"metadataHash": "old"}),
                   account(None, None, binding_status="True")]
        fixture.get = MagicMock(side_effect=pending + [account(None, None)])
        with patch.object(installed.system.time, "sleep"):
            fixture.wait_binding_invalidated("federated-b")
        self.assertEqual(fixture.get.call_count, 5)
        fixture.get = MagicMock(return_value=pending[0])
        with patch.object(installed.system.time, "sleep"), \
             patch.object(installed.system.time, "monotonic", side_effect=[0, 0, 181, 181]), \
             self.assertRaises(installed.system.diagnostics.DeadlineExceeded):
            fixture.wait_binding_invalidated("federated-b")

    def test_failure_status_reuses_bounded_snapshot_without_new_api_waits(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "installed.json"
            snapshot = output.with_suffix(".diagnostics")
            snapshot.mkdir()
            (snapshot / "hankoserviceaccounts.hanko.sh.yaml").write_text(json.dumps({"items": [{
                "metadata": {"name": "same-client", "namespace": "auth", "generation": 4},
                "status": {"phase": "Pending", "observedGeneration": 3,
                           "conditions": [{"type": "Synced", "status": "False", "reason": "StatusWriteFailed", "message": "private-detail"}]},
            }]}))
            fixture = installed.Installed.__new__(installed.Installed)
            fixture.args = SimpleNamespace(output=output)
            fixture.sensitive, fixture.report = ["private-detail"], {}
            fixture.kubectl = MagicMock(side_effect=AssertionError("must not query a failed cluster again"))
            fixture.failure_evidence()
            fixture.kubectl.assert_not_called()
            self.assertEqual(fixture.report["failure_status"]["same-client"]["phase"], "Pending")
            self.assertEqual(fixture.report["failure_status"]["same-client"]["conditions"][0]["reason"], "StatusWriteFailed")
            self.assertEqual(fixture.report["failure_status"]["secret-a"], {"unavailable": True})
            self.assertNotIn("private-detail", json.dumps(fixture.report))

    def test_evidence_never_includes_native_representations_or_private_inputs(self):
        fixture = installed.Installed.__new__(installed.Installed)
        fixture.report = {"checks": {"real_pod": True}, "complete": False,
                          "provider": {"private": "credential"}, "discovery": {}, "kubeconfig": "private",
                          "client": {"secret": "credential"}, "projected_assertion": "private"}
        self.assertEqual(fixture.public_evidence(), {"checks": {"real_pod": True}, "complete": False})

    def test_both_decisions_use_the_same_live_workload_bearer(self):
        settings = {"issuer": "https://fixture/realms/managed", "client": "worker", "endpoint": "https://fixture/token",
                    "audience": "api", "resources": {"allowed": "resource-a", "denied": "resource-b"}}
        token = "fixture-private-access"
        responses = [(200, {"access_token": token}), (200, {"result": True}), (403, {"error": "access_denied"})]
        with patch.object(probe, "request", side_effect=responses) as request, patch.object(probe.time, "time", return_value=900), \
             patch.object(probe, "decode", return_value={"iss": settings["issuer"], "azp": "worker", "exp": 1000}):
            result = probe.decisions("private-assertion", settings, None)
        self.assertTrue(result["resource_allowed"] and result["resource_denied"])
        self.assertEqual(request.call_args_list[1].args[3], token)
        self.assertEqual(request.call_args_list[2].args[3], token)
        self.assertEqual(request.call_args_list[1].args[1]["permission"], "resource-a#read")
        self.assertEqual(request.call_args_list[2].args[1]["permission"], "resource-b#read")
        self.assertNotIn(token, json.dumps(result))

    def test_network_or_invalid_token_is_never_an_authorization_denial(self):
        settings = {"issuer": "https://fixture/realms/managed", "client": "worker", "endpoint": "https://fixture/token",
                    "audience": "api", "resources": {"allowed": "resource-a", "denied": "resource-b"}}
        with patch.object(probe, "authenticate", return_value=(200, {"access_token": "private"})), \
             patch.object(probe, "decode", return_value={"iss": settings["issuer"], "azp": "worker", "exp": 1000}), \
             patch.object(probe.time, "time", return_value=900):
            for status, body in ((401, {"error": "invalid_token"}), (503, {}), (403, {"error": "invalid_token"})):
                with self.subTest(status=status, body=body), patch.object(probe, "request", side_effect=[(200, {"result": True}), (status, body)]):
                    with self.assertRaises(ValueError):
                        probe.decisions("private", settings, None)

    def test_fault_step_matching_ignores_unrelated_checkpoint_and_route(self):
        rule = {"method": "PATCH", "path": "/fixture/hsa", "step": "OutputsCleaned"}
        body = json.dumps({"metadata": {"annotations": {installed.JOURNAL: json.dumps({"step": "AuthReviewed"})}}}).encode()
        self.assertFalse(proxy.matches(rule, "PATCH", "/fixture/hsa", body))
        body = json.dumps({"metadata": {"annotations": {installed.JOURNAL: json.dumps({"step": "OutputsCleaned"})}}}).encode()
        self.assertTrue(proxy.matches(rule, "PATCH", "/fixture/hsa", body))
        self.assertFalse(proxy.matches(rule, "PUT", "/fixture/hsa", body))
        self.assertFalse(proxy.matches(rule, "PATCH", "/other/hsa", body))

    def test_proxy_preserves_native_media_type_without_forwarding_gzip(self):
        handler = proxy.Proxy.__new__(proxy.Proxy)
        handler.headers = Message()
        handler.headers["Accept-Encoding"] = "gzip"
        handler.headers["Accept"] = "application/vnd.kubernetes.protobuf"
        handler.rfile = BytesIO()
        handler.command, handler.path = "GET", "/api/v1/namespaces"
        handler.server = SimpleNamespace(upstream="https://fixture", context=None)
        handler.reply = MagicMock()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {"Content-Type": "application/vnd.kubernetes.protobuf"}
        response.read.return_value = b"protobuf-fixture"
        with patch.dict(proxy.STATE, {"rule": None, "blocked": False, "triggered": False, "counts": {}, "upstream_status": None}, clear=True), \
             patch.object(proxy, "urlopen", return_value=response) as upstream:
            handler.handle_request()
        self.assertNotIn("accept-encoding", {key.lower() for key, _ in upstream.call_args.args[0].header_items()})
        handler.reply.assert_called_once_with(200, b"protobuf-fixture", "application/vnd.kubernetes.protobuf")

    def test_lost_ack_requires_upstream_acceptance_before_downstream_drop(self):
        handler = proxy.Proxy.__new__(proxy.Proxy)
        handler.headers = Message()
        handler.headers["Content-Length"] = "2"
        handler.rfile = BytesIO(b"{}")
        handler.command, handler.path = "POST", "/fixture/clients"
        handler.server = SimpleNamespace(upstream="https://fixture", context=None)
        handler.reply, handler.connection = MagicMock(), MagicMock()
        events = []
        handler.connection.shutdown.side_effect = lambda *_: events.append("downstream-dropped")
        response = MagicMock()
        response.__enter__.return_value = response
        response.status, response.headers = 201, {"Content-Type": "application/json"}
        response.read.side_effect = lambda *_: events.append("upstream-accepted") or b"{}"
        rule = {"method": "POST", "path": "/fixture/clients", "action": "lost-ack"}
        with patch.dict(proxy.STATE, {"rule": rule, "blocked": False, "triggered": False, "counts": {}, "upstream_status": None}, clear=True), \
             patch.object(proxy, "urlopen", return_value=response):
            handler.handle_request()
            self.assertEqual(proxy.STATE["counts"], {"POST /fixture/clients": 1})
            self.assertEqual(proxy.STATE["upstream_status"], 201)
        self.assertEqual(events, ["upstream-accepted", "downstream-dropped"])
        handler.reply.assert_not_called()

    def test_rejected_write_does_not_consume_ack_loss_or_checkpoint_gate(self):
        for action in ("lost-ack", "gate"):
            with self.subTest(action=action):
                handler = proxy.Proxy.__new__(proxy.Proxy)
                handler.headers = Message()
                handler.headers["Content-Length"] = "2"
                handler.command, handler.path = "PUT", "/fixture/hsa"
                handler.server = SimpleNamespace(upstream="https://fixture", context=None)
                handler.reply, handler.connection = MagicMock(), MagicMock()
                response = MagicMock()
                response.__enter__.return_value = response
                response.status, response.headers = 200, {"Content-Type": "application/json"}
                response.read.return_value = b"{}"
                rule = {"method": "PUT", "path": "/fixture/hsa", "action": action}
                conflict = HTTPError("https://fixture/hsa", 409, "Conflict", response.headers, BytesIO(b"{}"))
                with patch.dict(proxy.STATE, {"rule": rule, "blocked": False, "triggered": False, "counts": {}, "attempted_counts": {}, "upstream_status": None}, clear=True), \
                     patch.object(proxy, "urlopen", side_effect=[conflict, response]):
                    handler.rfile = BytesIO(b"{}")
                    handler.handle_request()
                    handler.reply.assert_called_once_with(409, b"{}", "application/json")
                    handler.connection.shutdown.assert_not_called()
                    self.assertFalse(proxy.STATE["triggered"] or proxy.STATE["blocked"])
                    self.assertEqual(proxy.STATE["counts"], {})
                    handler.reply.reset_mock()
                    handler.rfile = BytesIO(b"{}")
                    handler.handle_request()
                    self.assertTrue(proxy.STATE["triggered"] and proxy.STATE["blocked"])
                    self.assertEqual(proxy.STATE["upstream_status"], 200)
                    self.assertEqual(proxy.STATE["counts"], {"PUT /fixture/hsa": 1})
                    self.assertEqual(proxy.STATE["attempted_counts"], {"PUT /fixture/hsa": 2})
                    if action == "lost-ack":
                        handler.reply.assert_not_called()
                        handler.connection.shutdown.assert_called_once()
                    else:
                        handler.reply.assert_called_once_with(200, b"{}", "application/json")
                        handler.connection.shutdown.assert_not_called()

    def test_explicit_resource_version_conflict_still_gates_the_real_rejection(self):
        handler = proxy.Proxy.__new__(proxy.Proxy)
        handler.headers = Message()
        handler.headers["Content-Length"] = "2"
        handler.rfile = BytesIO(b"{}")
        handler.command, handler.path = "PATCH", "/fixture/configmap"
        handler.server = SimpleNamespace(upstream="https://fixture", context=None)
        handler.reply, handler.connection = MagicMock(), MagicMock()
        rule = {"method": "PATCH", "path": handler.path, "action": "resource-version-conflict"}
        conflict = HTTPError("https://fixture/configmap", 409, "Conflict", {"Content-Type": "application/json"}, BytesIO(b"{}"))
        with patch.dict(proxy.STATE, {"rule": rule, "blocked": False, "triggered": False, "counts": {}, "attempted_counts": {}, "upstream_status": None}, clear=True), \
             patch.object(proxy, "urlopen", side_effect=conflict) as upstream:
            handler.handle_request()
            self.assertEqual(json.loads(upstream.call_args.args[0].data)["metadata"]["resourceVersion"], "1")
            self.assertEqual(proxy.STATE["upstream_status"], 409)
            self.assertTrue(proxy.STATE["triggered"] and proxy.STATE["blocked"])
            self.assertEqual(proxy.STATE["counts"], {})
            handler.reply.assert_called_once_with(409, b"{}", "application/json")
            handler.connection.shutdown.assert_not_called()

    def test_late_response_cannot_retrigger_or_consume_a_replacement_rule(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                handler = proxy.Proxy.__new__(proxy.Proxy)
                handler.headers = Message()
                handler.headers["Content-Length"] = "2"
                handler.rfile = BytesIO(b"{}")
                handler.command, handler.path = "PUT", "/fixture/hsa"
                handler.server = SimpleNamespace(upstream="https://fixture", context=None)
                handler.reply, handler.connection = MagicMock(), MagicMock()
                response = MagicMock()
                response.__enter__.return_value = response
                response.status, response.headers = 200, {"Content-Type": "application/json"}
                rule = {"method": "PUT", "path": handler.path, "action": "lost-ack"}
                def finish_upstream(*_):
                    # A concurrent response consumed this rule, or control
                    # replaced it, while this request was still upstream.
                    proxy.STATE.update({"rule": dict(rule) if replaced else rule, "triggered": not replaced, "blocked": not replaced})
                    return b"{}"
                response.read.side_effect = finish_upstream
                with patch.dict(proxy.STATE, {"rule": rule, "blocked": False, "triggered": False, "counts": {}, "attempted_counts": {}, "upstream_status": None}, clear=True), \
                     patch.object(proxy, "urlopen", return_value=response):
                    handler.handle_request()
                    self.assertEqual(proxy.STATE["triggered"], not replaced)
                    self.assertIsNone(proxy.STATE["upstream_status"])
                handler.reply.assert_called_once_with(200, b"{}", "application/json")
                handler.connection.shutdown.assert_not_called()


if __name__ == "__main__":
    unittest.main()

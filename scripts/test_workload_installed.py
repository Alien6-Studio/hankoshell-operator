"""Protect installed evidence and require genuine independent UMA denials."""

import importlib.util
import json
from io import BytesIO
from email.message import Message
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


installed = module("installed_fixture", "workload-installed-test.py")
probe = module("pod_probe", "workload-pod-probe.py")
proxy = module("fault_proxy", "workload-fault-proxy.py")


class InstalledEvidenceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("transactions", Path(__file__).with_name("transactions-installed-test.py"))
transactions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transactions)


class TransactionEvidenceTests(unittest.TestCase):
    def test_rotation_recovery_requires_current_ready_same_request_and_exact_status_time(self):
        journal = {"requestID": "reviewed-request", "rotatedAt": "2026-10-17T12:00:00.123456789Z"}
        value = {"metadata": {"generation": 2, "annotations": {transactions.ROTATION: json.dumps({
            "step": "Committed", "requestID": journal["requestID"]})}}, "status": {"phase": "Ready", "observedGeneration": 2,
            "lastRotated": "2026-10-17T12:00:00Z", "conditions": [{"type": "Synced", "status": "True"}]}}
        self.assertTrue(transactions.rotation_recovered(value, journal))
        for field in ("generation", "phase", "time", "request", "step", "synced"):
            current = copy.deepcopy(value)
            if field == "generation":
                current["status"]["observedGeneration"] = 1
            elif field == "phase":
                current["status"]["phase"] = "Error"
            elif field == "time":
                current["status"]["lastRotated"] = "2026-10-17T12:00:01Z"
            elif field == "synced":
                current["status"]["conditions"] = []
            else:
                altered = {"step": "Committed", "requestID": journal["requestID"]}
                altered["requestID" if field == "request" else "step"] = "another"
                current["metadata"]["annotations"][transactions.ROTATION] = json.dumps(altered)
            with self.subTest(field=field):
                self.assertFalse(transactions.rotation_recovered(current, journal))

    def test_semantic_comparison_keeps_identity_and_unknown_native_fields(self):
        before = {"id": "physical", "name": "reviewed", "attributes": {"locale": "fr", "unrelated": "preserved"}}
        after = copy.deepcopy(before)
        after["attributes"].update({"hanko.sh/role-owner": ["owner"], "hanko.sh/adoption-receipt": ["receipt"]})
        self.assertEqual(transactions.native_semantics(before), transactions.native_semantics(after))
        after["attributes"]["unrelated"] = "changed"
        self.assertNotEqual(transactions.native_semantics(before), transactions.native_semantics(after))
        after = {**before, "id": "replacement"}
        self.assertNotEqual(transactions.native_semantics(before), transactions.native_semantics(after))

    def test_fault_release_requires_confirmed_old_pod_deletion(self):
        fixture = transactions.Transactions.__new__(transactions.Transactions)
        trace = []
        fixture.get = MagicMock(side_effect=[{"spec": {"holderIdentity": "old_nonce"}}, {"spec": {"holderIdentity": "new_nonce"}}])
        fixture.stop_log_capture, fixture.start_log_capture, fixture.scraper = MagicMock(), MagicMock(), MagicMock()
        fixture.kubectl = lambda *args: trace.append(("kubectl", *args))
        fixture.control = lambda *args: trace.append(("control", *args))
        with patch.object(transactions.scale.Scale, "await_leader"):
            fixture.replace_leader()
        self.assertEqual(trace[0], ("kubectl", "delete", "pod", "old", "-n", "auth", "--wait=true", "--timeout=90s"))
        self.assertEqual(trace[1:3], [("control", "api", None), ("control", "keycloak", None)])
        fixture.get = MagicMock(return_value={"spec": {"holderIdentity": "old_nonce"}})
        with patch.object(transactions.scale.Scale, "await_leader"), self.assertRaisesRegex(ValueError, "lease holder"):
            fixture.replace_leader()

    def test_report_retains_only_fixed_checkpoint_decisions_and_counts(self):
        fixture = transactions.Transactions.__new__(transactions.Transactions)
        fixture.report = {"checks": {}, "checkpoints": {}, "private_native_document": "secret-sentinel"}
        fixture.checkpoint("verified_plan", accepted_child_creates=1)
        public = fixture.public_evidence()
        self.assertNotIn("sentinel", json.dumps(public))
        self.assertEqual(public["checkpoints"]["verified_plan"]["accepted_child_creates"], 1)
        for name, counts in (("unknown", {}), ("verified_plan", {}), ("client_acquisition", {"bad": "secret-sentinel"})):
            with self.assertRaises(ValueError):
                fixture.checkpoint(name, **counts)

    def test_wrong_scanned_graph_prevents_cluster_and_fixture_creation(self):
        args = ["transaction-test"]
        for key in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl", "digest", "revision"):
            args += ["--" + key, "fixture"]
        args += ["--keycloak-version", "26.8.0", "--kubernetes-version", "1.37.0"]
        with patch.object(transactions.scale, "checkout"), patch.object(transactions, "Transactions") as fixture, \
             patch("sys.argv", args), patch.object(transactions.system.publication.publish.contract.security, "verify", side_effect=ValueError("wrong OCI")):
            with self.assertRaisesRegex(ValueError, "wrong OCI"):
                transactions.main()
        fixture.assert_not_called()


if __name__ == "__main__":
    unittest.main()

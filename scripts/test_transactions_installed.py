import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import yaml

spec = importlib.util.spec_from_file_location("transactions", Path(__file__).with_name("transactions-installed-test.py"))
transactions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transactions)


class TransactionEvidenceTests(unittest.TestCase):
    def test_force_trigger_is_already_due_and_after_the_last_rotation_second(self):
        before = {"metadata": {}, "status": {"lastRotated": "2026-10-20T09:00:00Z"}}
        now = datetime(2026, 10, 20, 9, 0, 0, 900000, tzinfo=timezone.utc)
        self.assertIsNone(transactions.forced_rotation_trigger(before, now))
        now = now.replace(second=1)
        trigger = transactions.forced_rotation_trigger(before, now)
        self.assertEqual(trigger, "2026-10-20T09:00:01Z")
        self.assertLess(datetime.fromisoformat(trigger.replace("Z", "+00:00")), now)

    def test_unknown_initial_rotation_does_not_add_a_future_second_request(self):
        before = {"metadata": {"creationTimestamp": "2026-10-20T09:00:00Z"}, "status": {}}
        now = datetime(2026, 10, 20, 9, 0, 1, 100000, tzinfo=timezone.utc)
        self.assertEqual(transactions.forced_rotation_trigger(before, now), "2026-10-20T09:00:01Z")
        before["metadata"]["creationTimestamp"] = "2026-10-20T09:00:02Z"
        self.assertIsNone(transactions.forced_rotation_trigger(before, now))

    def test_ha_matrix_is_required_on_full_ci_and_does_not_repeat_the_scale_job(self):
        jobs = yaml.safe_load((transactions.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        ha = jobs["installed-transactions"]
        self.assertNotIn("if", ha)
        self.assertFalse(ha["strategy"]["fail-fast"])
        self.assertEqual(ha["strategy"]["matrix"], {"keycloak": ["26.7.5", "26.8.0"], "kubernetes": ["1.35.0", "1.36.2", "1.37.0"]})
        self.assertEqual(ha["needs"], ["source", "oci", "keycloak-extension"])
        self.assertFalse(ha.get("continue-on-error", False))
        run = next(s for s in ha["steps"] if "scripts/transactions-installed-test.py" in s.get("run", ""))
        self.assertIn('--revision "$GITHUB_SHA"', run["run"])
        self.assertEqual(run["env"]["OCI_DIGEST"], "${{ needs.oci.outputs.digest }}")
        self.assertNotIn("if", run)
        self.assertNotIn("continue-on-error", run)
        delegation = next(s for s in ha["steps"] if "--ha-only" in s.get("run", ""))
        self.assertIn('scripts/delegation-installed-test.py --ha-only', delegation["run"])
        self.assertIn('--revision "$GITHUB_SHA"', delegation["run"])
        self.assertEqual(delegation["if"], "${{ !cancelled() }}")
        self.assertNotIn("continue-on-error", delegation)
        restore = next(s for s in ha["steps"] if s.get("with", {}).get("path") == ".tools/keycloak-bounded-delegation/")
        self.assertIn("${{ matrix.keycloak }}-${{ github.run_id }}-${{ github.run_attempt }}", restore["with"]["name"])
        self.assertEqual(ha["steps"][-1]["if"], "always()")
        for job in ("checks", "schedule-report"):
            self.assertIn("installed-transactions", jobs[job]["needs"])
        gate = jobs["checks"]["steps"][0]
        self.assertEqual(gate["env"]["INSTALLED_TRANSACTIONS_RESULT"], "${{ needs.installed-transactions.result }}")
        self.assertIn('test "$INSTALLED_TRANSACTIONS_RESULT" = success', gate["run"])
        self.assertFalse(any("transactions-installed-test.py" in s.get("run", "") for s in jobs["installed-scale-qualification"]["steps"]))

    def test_process_liveness_requires_the_exact_running_container_epoch(self):
        pod = {"metadata": {"uid": "pod-uid"}, "status": {"containerStatuses": [{"name": "manager", "containerID": "container-id",
               "restartCount": 0, "state": {"running": {"startedAt": "fixed-start"}}}]}}
        self.assertEqual(transactions.process_epoch(pod), ("pod-uid", "container-id", 0, "fixed-start"))
        for field in ("containerID", "restartCount", "state"):
            changed = copy.deepcopy(pod)
            del changed["status"]["containerStatuses"][0][field]
            self.assertIsNone(transactions.process_epoch(changed))
        changed = copy.deepcopy(pod)
        changed["metadata"]["deletionTimestamp"] = "fixed-delete"
        self.assertIsNone(transactions.process_epoch(changed))

    def test_reader_permissions_are_version_specific_and_never_a_generic_200_success(self):
        fixture = transactions.Transactions.__new__(transactions.Transactions)
        fixture.reader_token, fixture.report = "independent-reader", {"checks": {}}
        for version, expected in (("26.7.5", 200), ("26.8.0", 403)):
            fixture.args = SimpleNamespace(keycloak_version=version)
            fixture.api = MagicMock(return_value={"value": "private-sentinel"})
            fixture.inspect_reader_permissions("/fixture/client", {"id": "physical"}, "private-sentinel")
            fixture.api.assert_any_call("PUT", "/fixture/client", {"id": "physical"}, token="independent-reader", expected=(403,))
            fixture.api.assert_any_call("GET", "/fixture/client/client-secret", token="independent-reader", expected=(expected,))
            self.assertEqual(fixture.report["reader_profile"]["provider_credential_read_separation"], expected == 403)
            self.assertNotIn("private-sentinel", json.dumps(fixture.public_evidence()))
        fixture.args = SimpleNamespace(keycloak_version="26.7.5")
        fixture.api.return_value = {"message": "generic HTTP success"}
        with self.assertRaisesRegex(ValueError, "did not prove"):
            fixture.inspect_reader_permissions("/fixture/client", {}, "private-sentinel")

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

    def test_acquisition_observes_the_target_without_borrowing_other_clients_reads(self):
        path = "/admin/realms/managed/clients/reviewed"
        before = {"id": "reviewed", "attributes": {"locale": "fr"}}
        after = copy.deepcopy(before)
        after["attributes"].update({"hanko.sh/client-owner-uid": "owner", "hanko.sh/adoption-receipt": "receipt"})
        acquired = {"metadata": {}, "status": {}}
        state = {"counts": {"PUT " + path: 1}, "attempted_counts": {"PUT " + path: 1},
            "traffic": {"credential_read_requests": 7},
            "credential_reads": {"/admin/realms/managed/clients/unrelated/client-secret": 7}}
        receipt = {"targetUID": "owner"}
        def checks(current=state, obj=after, cr=acquired):
            return transactions.acquisition_checks(receipt, receipt, before, obj, cr, current, path)
        self.assertTrue(all(checks().values()))
        read_target = copy.deepcopy(state)
        read_target["credential_reads"][path + "/client-secret"] = 1
        self.assertFalse(checks(read_target)["no_target_credential_read"])
        duplicate = copy.deepcopy(state); duplicate["attempted_counts"]["PUT " + path] = 2
        self.assertFalse(checks(duplicate)["single_attempted_receipt_write"])
        changed = copy.deepcopy(after); changed["attributes"]["locale"] = "changed"
        self.assertFalse(checks(obj=changed)["native_semantics_preserved"])
        self.assertFalse(checks(cr={"metadata": {"finalizers": ["unexpected"]}})["observe_remains_unmanaged"])
        missing = copy.deepcopy(state); del missing["credential_reads"]
        with self.assertRaisesRegex(ValueError, "target-scoped"):
            checks(missing)

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

    def test_live_partition_requires_natural_handoff_without_old_holder_writes(self):
        for scenario in ("pass", "old-write", "late-old-write", "late-fault-release", "late-lease-loss", "wall-clock-gap",
                         "lease-renewal", "no-live-process", "wrong-peer", "duplicate-new-write"):
            with self.subTest(scenario=scenario):
                fixture = transactions.Transactions.__new__(transactions.Transactions)
                fixture.report = {"checks": {}}
                clock = SimpleNamespace(now=0, fault=False, rule=None)
                old, new, route = "10.0.0.1", "10.0.0.2", "PUT /admin/realms/managed/roles/ha-partition-role"
                def get(kind, name):
                    if kind == "lease":
                        if scenario == "late-lease-loss" and clock.now >= 60:
                            return {"spec": {"holderIdentity": "old_nonce", "renewTime": 1}}
                        return {"spec": {"holderIdentity": "new_nonce" if clock.now >= 6 else "old_nonce",
                                         "renewTime": 2 if scenario == "lease-renewal" and clock.now >= 4 else 1}}
                    if kind == "pod":
                        status = {} if scenario == "no-live-process" and clock.fault else {"running": {"startedAt": "fixed-start"}}
                        return {"metadata": {"uid": name + "-uid"}, "status": {"podIP": old if name == "old" else new,
                            "containerStatuses": [{"name": "manager", "containerID": name, "restartCount": 0, "state": status}]}}
                    return {"metadata": {"generation": 2}, "status": {"phase": "Ready", "observedGeneration": 2, "conditions": [{"type": "Synced", "status": "True"}]}}
                def observed(target):
                    if target == "api":
                        return {"traffic": {"refused_requests": 4}, "rule": None if scenario == "late-fault-release" and clock.now >= 60 else clock.rule}
                    count = 2 if scenario == "duplicate-new-write" else 1
                    writes = {old: {route: 1}} if (scenario == "old-write" and clock.now >= 4 or scenario == "late-old-write" and clock.now >= 60) else {}
                    if clock.now >= 6:
                        writes[new] = {route: count}
                    return {"peer_requests": {} if scenario == "wrong-peer" else {old: 5},
                            "peer_counts": copy.deepcopy(writes), "peer_attempted_counts": copy.deepcopy(writes)}
                fixture.get, fixture.observe_control = get, observed
                fixture.api = lambda *_: {"id": "native-role", "description": "after-partition" if clock.now >= 6 else "before-partition"}
                for name in ("apply", "patch", "await_fault", "kubectl"):
                    setattr(fixture, name, MagicMock())
                fixture.scraper = MagicMock()
                def control(target, rule, **_):
                    if target == "api":
                        clock.fault = rule is not None
                        clock.rule = rule
                fixture.control = MagicMock(side_effect=control)
                fixture.record = lambda name, value=True: fixture.report["checks"].update({name: value})
                def wait(_, check, _seconds):
                    self.assertTrue(check())
                with patch.object(transactions, "wait", side_effect=wait), patch.object(transactions.time, "monotonic", side_effect=lambda: clock.now), \
                        patch.object(transactions.time, "time", side_effect=lambda: clock.now + (60 if scenario == "wall-clock-gap" and clock.now >= 60 else 0)), \
                        patch.object(transactions.time, "sleep", side_effect=lambda seconds: setattr(clock, "now", clock.now + seconds)), \
                        patch.object(transactions.scale.Scale, "await_leader"):
                    if scenario == "pass":
                        fixture.lease_partition()
                        self.assertTrue(fixture.report["lease_partition"]["complete"])
                        self.assertTrue(fixture.report["lease_partition"]["old_process_observed_alive"])
                        self.assertEqual(fixture.report["lease_partition"]["old_provider_write_attempts"], 0)
                        self.assertEqual(transactions.PARTITION_SECONDS, 300)
                        self.assertGreaterEqual(fixture.report["lease_partition"]["isolated_seconds"], 300)
                        self.assertNotIn(old, json.dumps(fixture.public_evidence()))
                        self.assertNotIn("native-role", json.dumps(fixture.public_evidence()))
                        self.assertTrue(all(call.args[0] != "delete" for call in fixture.kubectl.call_args_list))
                    else:
                        with self.assertRaises(ValueError):
                            fixture.lease_partition()
                        self.assertFalse(fixture.report.get("lease_partition", {}).get("complete", False))


if __name__ == "__main__":
    unittest.main()

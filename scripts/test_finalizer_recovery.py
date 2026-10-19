import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import yaml

import finalizer_recovery as recovery


class Cluster:
    def __init__(self):
        self.actor = "executor"
        self.groups = [recovery.EXECUTORS, recovery.APPROVERS]
        self.records = {}
        self.writes = []
        self.running = False
        self.fail = None
        self.lost_patch = False
        self.race = False
        self.obj = {"metadata": {"name": "blocked", "namespace": "auth", "uid": "target-uid", "resourceVersion": "10",
            "generation": 3, "deletionTimestamp": "2026-10-19T00:00:00Z", "finalizers": ["foreign.example/hold", "hanko.sh/role-cleanup"]}}
        self.policy = {}
        for obj in yaml.safe_load_all((recovery.ROOT / "config/recovery/approval-policy.yaml").read_text()):
            actual = copy.deepcopy(obj)
            actual["metadata"].update(uid=obj["kind"] + "-uid", generation=1)
            actual["status"] = {"observedGeneration": 1, "typeChecking": {}}
            self.policy[obj["kind"]] = actual

    def request(self, method, path, value=None, *, optional=False, probe=False):
        if probe:
            return None
        base = path.split("?", 1)[0]
        if method == "POST" and base.endswith("selfsubjectreviews"):
            return {"status": {"userInfo": {"username": self.actor, "groups": self.groups}}}
        if method == "GET":
            if base.endswith("/validatingadmissionpolicies/" + recovery.POLICY_NAME):
                return copy.deepcopy(self.policy["ValidatingAdmissionPolicy"])
            if base.endswith("/validatingadmissionpolicybindings/" + recovery.POLICY_NAME):
                return copy.deepcopy(self.policy["ValidatingAdmissionPolicyBinding"])
            if base == "/api/v1/namespaces/" + recovery.AUDIT_NAMESPACE:
                return copy.deepcopy(self.policy["Namespace"])
            if "/configmaps/" in base:
                result = self.records.get(base.rsplit("/", 1)[1])
                if result is None and not optional:
                    raise recovery.Refused("NotFound")
                return copy.deepcopy(result)
            if base.startswith("/api/v1/namespaces/"):
                return {"metadata": {"uid": base.rsplit("/", 1)[1] + "-uid"}}
            if base.endswith("/deployments"):
                return {"items": [{"spec": {"replicas": int(self.running)}}]}
            if base.endswith("/pods"):
                return {"items": []}
            if "/hankoroles/" in base:
                return copy.deepcopy(self.obj)
        if method == "POST" and base == recovery.RECORDS:
            phase = value["data"]["phase"]
            if self.fail == phase:
                raise recovery.Refused("AuditUnavailable")
            self.writes.append(phase)
            result = copy.deepcopy(value)
            result["metadata"]["uid"] = phase + "-uid"
            self.records[result["metadata"]["name"]] = result
            return result
        if method == "PATCH":
            if self.race:
                self.obj["metadata"]["resourceVersion"] = "11"
            self.writes.append("patch-attempt")
            for operation in value[:-1]:
                field = operation["path"].rsplit("/", 1)[1]
                if self.obj["metadata"][field] != operation["value"]:
                    raise recovery.Refused("ConcurrentModification")
            self.obj["metadata"]["finalizers"].pop(int(value[-1]["path"].rsplit("/", 1)[1]))
            self.obj["metadata"]["resourceVersion"] = "11"
            if self.lost_patch:
                raise recovery.Refused("KubernetesWriteOutcomeUnknown")
            return copy.deepcopy(self.obj)
        raise AssertionError((method, path))


class FinalizerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.cluster = Cluster()
        self.plan = recovery.plan(self.cluster, "HankoRole", "auth", "blocked", "hanko.sh/role-cleanup", now=1000)

    def approved(self):
        recovery.request(self.cluster, self.plan, now=1001)
        self.cluster.actor = "approver"
        recovery.approve(self.cluster, self.plan, now=1002)
        self.cluster.actor = "executor"

    def test_independent_flow_preserves_foreign_finalizer_and_records_before_patch(self):
        self.approved()
        receipt = recovery.execute(self.cluster, self.plan, now=1003)
        self.assertEqual(receipt["observation"], "SelectedFinalizerAbsent")
        self.assertEqual(self.cluster.obj["metadata"]["finalizers"], ["foreign.example/hold"])
        self.assertEqual(self.cluster.writes, ["request", "approval", "intent", "patch-attempt", "receipt"])

    def test_self_approval_is_refused_even_with_both_groups(self):
        recovery.request(self.cluster, self.plan, now=1001)
        with self.assertRaisesRegex(recovery.Refused, "IndependentApproverRequired"):
            recovery.approve(self.cluster, self.plan, now=1002)
        self.assertEqual(self.cluster.writes, ["request"])

    def test_current_identity_and_human_groups_are_required(self):
        for actor, groups in (("system:serviceaccount:auth:operator", [recovery.EXECUTORS]), ("executor", []), ("other-executor", [recovery.EXECUTORS])):
            with self.subTest(actor=actor, groups=groups):
                self.cluster.actor, self.cluster.groups = actor, groups
                with self.assertRaises(recovery.Refused):
                    recovery.request(self.cluster, self.plan, now=1001)
                self.assertEqual(self.cluster.writes, [])

    def test_stale_or_replaced_target_never_writes_intent(self):
        for field, changed in (("uid", "replacement"), ("resourceVersion", "11"), ("generation", 4), ("deletionTimestamp", "changed"),
                               ("finalizers", ["hanko.sh/role-cleanup", "foreign.example/changed"])):
            with self.subTest(field=field):
                self.setUp()
                self.approved()
                self.cluster.obj["metadata"][field] = changed
                with self.assertRaisesRegex(recovery.Refused, "TargetChanged"):
                    recovery.execute(self.cluster, self.plan, now=1003)
                self.assertNotIn("intent", self.cluster.writes)

    def test_audit_record_failure_prevents_target_write(self):
        self.approved()
        self.cluster.fail = "intent"
        with self.assertRaisesRegex(recovery.Refused, "AuditUnavailable"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertNotIn("patch-attempt", self.cluster.writes)

    def test_expiry_and_running_operator_refuse_release(self):
        self.approved()
        with self.assertRaisesRegex(recovery.Refused, "PlanExpiredOrInvalid"):
            recovery.execute(self.cluster, self.plan, now=2000)
        self.cluster.running = True
        with self.assertRaisesRegex(recovery.Refused, "OperatorNotQuiescent"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertNotIn("intent", self.cluster.writes)

    def test_policy_replacement_or_weakening_is_refused(self):
        self.approved()
        for kind, field, replacement in (("Namespace", "uid", "replaced"), ("ValidatingAdmissionPolicy", "uid", "replaced"),
                                          ("ValidatingAdmissionPolicyBinding", "uid", "replaced")):
            with self.subTest(kind=kind):
                original = self.cluster.policy[kind]["metadata"][field]
                self.cluster.policy[kind]["metadata"][field] = replacement
                with self.assertRaisesRegex(recovery.Refused, "AuditGuardChanged"):
                    recovery.execute(self.cluster, self.plan, now=1003)
                self.cluster.policy[kind]["metadata"][field] = original
        self.cluster.policy["ValidatingAdmissionPolicy"]["spec"]["failurePolicy"] = "Ignore"
        with self.assertRaisesRegex(recovery.Refused, "AuditGuardChanged"):
            recovery.execute(self.cluster, self.plan, now=1003)

    def test_forged_approval_binding_is_refused(self):
        self.approved()
        approval = self.cluster.records[recovery.record_name(self.plan, "approval")]
        approval["data"]["payload"] = recovery.canonical({"requestUID": "other-request", "decision": recovery.CONSENT})
        with self.assertRaisesRegex(recovery.Refused, "AuditRecordMissingOrChanged"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertNotIn("intent", self.cluster.writes)

    def test_cas_race_preserves_all_finalizers(self):
        self.approved()
        self.cluster.race = True
        with self.assertRaisesRegex(recovery.Refused, "ConcurrentModification"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertEqual(self.cluster.obj["metadata"]["finalizers"], ["foreign.example/hold", "hanko.sh/role-cleanup"])
        with self.assertRaisesRegex(recovery.Refused, "IntentAlreadyRecordedUseObserve"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertEqual(self.cluster.writes.count("patch-attempt"), 1)

    def test_lost_patch_ack_is_observed_without_replay_even_after_expiry(self):
        self.approved()
        self.cluster.lost_patch = True
        with self.assertRaisesRegex(recovery.Refused, "KubernetesWriteOutcomeUnknown"):
            recovery.execute(self.cluster, self.plan, now=1003)
        with self.assertRaisesRegex(recovery.Refused, "IntentAlreadyRecordedUseObserve"):
            recovery.execute(self.cluster, self.plan, now=1004)
        receipt = recovery.observe(self.cluster, self.plan, now=2000)
        self.assertEqual(receipt["observation"], "SelectedFinalizerAbsent")
        recovery.observe(self.cluster, self.plan, now=2001)
        self.assertEqual(self.cluster.writes.count("patch-attempt"), 1)
        self.assertEqual(self.cluster.writes.count("receipt"), 1)

    def test_receipt_failure_keeps_durable_intent_and_can_resume_read_only(self):
        self.approved()
        self.cluster.fail = "receipt"
        with self.assertRaisesRegex(recovery.Refused, "AuditUnavailable"):
            recovery.execute(self.cluster, self.plan, now=1003)
        self.assertIn(recovery.record_name(self.plan, "intent"), self.cluster.records)
        self.cluster.fail = None
        recovery.observe(self.cluster, self.plan, now=1004)
        self.assertEqual(self.cluster.writes.count("patch-attempt"), 1)

    def test_observation_does_not_claim_provider_cleanup_or_causality(self):
        self.approved()
        recovery.record(self.cluster, self.plan, "intent", "executor", recovery.approved(self.cluster, self.plan), create=True)
        for target, expected in ((None, "TargetAbsent"), ({"metadata": {"uid": "replacement"}}, "TargetReplaced"),
                                 (self.cluster.obj, "SelectedFinalizerPresent")):
            with self.subTest(expected=expected):
                self.cluster.records.pop(recovery.record_name(self.plan, "receipt"), None)
                self.cluster.obj = target
                self.assertEqual(recovery.observe(self.cluster, self.plan, now=1004)["observation"], expected)
        self.assertNotIn("patch-attempt", self.cluster.writes)

    def test_nonterminating_and_unknown_finalizers_are_refused(self):
        for kind, finalizer in (("HankoRole", "foreign.example/hold"), ("HankoKeycloakInstance", "hanko.sh/instance-cleanup")):
            with self.assertRaisesRegex(recovery.Refused, "InvalidRecoveryRequest"):
                recovery.plan(self.cluster, kind, "auth", "blocked", finalizer, now=1000)
        del self.cluster.obj["metadata"]["deletionTimestamp"]
        with self.assertRaisesRegex(recovery.Refused, "TerminatingObjectRequired"):
            recovery.plan(self.cluster, "HankoRole", "auth", "blocked", "hanko.sh/role-cleanup", now=1000)

    def test_private_plan_never_overwrites_or_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            recovery.private_output(path, self.plan)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                recovery.private_output(path, {})
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                recovery.private_output(link, {})

    def test_ambiguous_oversize_and_deep_inputs_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[' * 65 + b'0' + b']' * 65, b' ' * (recovery.MAX_BYTES + 1)):
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(recovery.Refused):
                recovery.decode(raw)

    def test_transport_refuses_unrelated_endpoints_and_nonselective_patch(self):
        kube = recovery.Kubernetes("unused")
        kube.opener = Mock()
        for method, path, body in (("GET", "/api/v1/namespaces/auth/secrets", None), ("DELETE", recovery.target_path(self.plan), None),
                                   ("POST", "/apis/apps/v1/deployments", {}), ("PATCH", recovery.target_path(self.plan), [{"op": "replace", "path": "/metadata/finalizers", "value": []}])):
            with self.subTest(method=method, path=path), self.assertRaises(recovery.Refused):
                kube.request(method, path, body)
        kube.opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()

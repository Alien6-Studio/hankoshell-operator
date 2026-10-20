import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import claim_existing as claim


class Cluster:
    context = "explicit-cluster"

    def __init__(self):
        self.uid = "cluster-uid"
        self.objects = {}
        self.writes = []
        self.fault = None
        self.source = self.object("HankoKeycloakInstance", "inventory")
        self.source["spec"] = {"mode": "external", "adminRef": {"name": "reader"}}
        self.objects[("HankoKeycloakInstance", "inventory")] = self.source

    @staticmethod
    def object(kind, name):
        return {"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
                "metadata": {"namespace": "auth", "name": name, "uid": kind + "-" + name, "generation": 4,
                             "resourceVersion": "10", "annotations": {claim.SOURCE: "inventory", "example/preserve": "original"}},
                "spec": {"mode": "Observe", "realmRef": "realm"}}

    def target(self, kind="HankoApplication", name="target"):
        obj = self.object(kind, name)
        obj["status"] = {"adoptionCandidate": {"contractVersion": claim.CONTRACT,
            "target": claim.target_identity(obj), "providerIdentity": {"instance": claim.identity(self.source)},
            "candidateHash": "sha256:" + "a" * 64, "complete": True, "truncated": False, "approvable": True,
            "diff": [{"code": "equal"}]}}
        self.objects[(kind, name)] = obj
        return obj

    def cluster_uid(self):
        return self.uid

    def get(self, target):
        return copy.deepcopy(self.objects[(target["kind"], target["name"])])

    def patch(self, target, operations):
        obj = self.objects[(target["kind"], target["name"])]
        if self.fault == "conflict":
            self.fault = None
            obj["metadata"]["resourceVersion"] = "11"
            raise claim.Refused("KubernetesRequestUnconfirmed")
        for operation in operations:
            if operation["op"] == "test":
                self_key = operation["path"].split("/")[-1]
                if obj["metadata"][self_key] != operation["value"]:
                    raise claim.Refused("KubernetesRequestUnconfirmed")
        self.writes.append(copy.deepcopy(operations))
        last = operations[-1]
        if last["path"] == "/spec/mode":
            obj["spec"]["mode"] = last["value"]
            obj["metadata"]["generation"] += 1
        else:
            obj["metadata"]["annotations"] = copy.deepcopy(last["value"])
        obj["metadata"]["resourceVersion"] = str(int(obj["metadata"]["resourceVersion"]) + 1)
        if self.fault == "lost-ack":
            self.fault = None
            raise claim.Refused("KubernetesRequestUnconfirmed")
        return copy.deepcopy(obj)


class ClaimExistingTests(unittest.TestCase):
    def make_plan(self, cluster, objects, resume=False):
        return claim.plan(cluster, "auth", "inventory", [claim.identity(obj) for obj in objects], resume)

    def test_batch_only_approves_exact_reviewed_uids_and_preserves_observe_alias(self):
        cluster = Cluster()
        objects = [cluster.target(kind, kind.lower()) for kind in claim.KINDS]
        alias = cluster.target(name="passive-alias")
        alias_before = copy.deepcopy(alias)
        value = self.make_plan(cluster, objects)
        result = claim.execute(cluster, value, value["approvalHash"])
        self.assertEqual(result["phase"], "AcquisitionRequested")
        self.assertFalse(result["providerOwnershipVerifiedByThisTool"])
        self.assertEqual(len(cluster.writes), 5)
        for obj in objects:
            self.assertEqual(obj["spec"]["mode"], "Observe")
            self.assertEqual(obj["metadata"]["annotations"]["example/preserve"], "original")
            self.assertEqual(obj["metadata"]["annotations"][claim.CANDIDATE], "sha256:" + "a" * 64)
        self.assertEqual(alias, alias_before)
        claim.execute(cluster, value, value["approvalHash"])
        self.assertEqual(len(cluster.writes), 5)

    def test_stale_batch_member_holds_entire_invocation_before_any_patch(self):
        for change in ("cluster", "source", "uid", "spec", "metadata", "candidate", "deletion", "legacy", "approval"):
            with self.subTest(change=change):
                cluster = Cluster()
                first, last = cluster.target(name="first"), cluster.target(name="last")
                value = self.make_plan(cluster, [first, last])
                if change == "cluster": cluster.uid = "other-cluster"
                elif change == "source": cluster.source["metadata"]["uid"] = "other-source"
                elif change == "uid": last["metadata"]["uid"] = "replacement"
                elif change == "spec": last["spec"]["clientID"] = "changed-without-generation"
                elif change == "metadata": last["metadata"]["annotations"]["example/preserve"] = "changed"
                elif change == "candidate": last["status"]["adoptionCandidate"]["candidateHash"] = "sha256:" + "b" * 64
                elif change == "deletion": last["metadata"]["deletionTimestamp"] = "now"
                elif change == "legacy": last["metadata"]["annotations"][next(iter(claim.LEGACY))] = "legacy"
                elif change == "approval": last["metadata"]["annotations"][claim.APPROVAL] = "other-contract"
                with self.assertRaises(claim.Refused):
                    claim.execute(cluster, value, value["approvalHash"])
                self.assertFalse(cluster.writes)

    def test_cas_conflict_and_lost_ack_resume_without_duplicate_mutation(self):
        for fault in ("conflict", "lost-ack"):
            with self.subTest(fault=fault):
                cluster = Cluster()
                obj = cluster.target()
                value = self.make_plan(cluster, [obj])
                cluster.fault = fault
                claim.execute(cluster, value, value["approvalHash"])
                self.assertEqual(len(cluster.writes), 1)

    def test_manage_requires_plan_consent_and_every_verified_receipt(self):
        cluster = Cluster()
        obj = cluster.target()
        value = self.make_plan(cluster, [obj], resume=True)
        claim.execute(cluster, value, value["approvalHash"])
        for state in (None, "Partial", "Conflict", "Pending", "wrong-hash"):
            with self.subTest(state=state):
                obj["status"]["adoptionReceipt"] = {"contractVersion": claim.CONTRACT,
                    "candidateHash": "sha256:" + ("b" if state == "wrong-hash" else "a") * 64,
                    "state": "Verified" if state == "wrong-hash" else state}
                with self.assertRaisesRegex(claim.Refused, "ClaimNotVerified"):
                    claim.execute(cluster, value, value["approvalHash"], finish=True)
                self.assertEqual(obj["spec"]["mode"], "Observe")
        obj["status"]["adoptionReceipt"] = {"contractVersion": claim.CONTRACT,
            "candidateHash": "sha256:" + "a" * 64, "state": "Verified"}
        claim.execute(cluster, value, value["approvalHash"], finish=True)
        claim.execute(cluster, value, value["approvalHash"], finish=True)
        self.assertEqual(obj["spec"]["mode"], "Manage")
        self.assertEqual(len(cluster.writes), 2)
        self.assertEqual(obj["metadata"]["uid"], value["targets"][0]["uid"])

    def test_deferred_targets_never_become_implicit_manage_consent(self):
        for problem in ("incomplete", "truncated", "unapprovable", "changed-target", "changed-source", "drift", "imported"):
            with self.subTest(problem=problem):
                cluster = Cluster()
                good, bad = cluster.target(name="good"), cluster.target(name="bad")
                candidate = bad["status"]["adoptionCandidate"]
                if problem == "incomplete": candidate["complete"] = False
                elif problem == "truncated": candidate["truncated"] = True
                elif problem == "unapprovable": candidate["approvable"] = False
                elif problem == "changed-target": candidate["target"]["uid"] = "other"
                elif problem == "changed-source": candidate["providerIdentity"]["instance"]["uid"] = "other"
                elif problem == "drift": candidate["diff"] = [{"code": "would-change"}]
                elif problem == "imported": bad["metadata"]["labels"] = {"hanko.sh/imported-by": "catalog"}; candidate["target"] = claim.target_identity(bad)
                value = self.make_plan(cluster, [good, bad], resume=True)
                self.assertEqual(len(value["targets"]), 1)
                self.assertEqual(len(value["deferred"]), 1)
                claim.execute(cluster, value, value["approvalHash"])
                self.assertNotIn(claim.APPROVAL, bad["metadata"]["annotations"])
        with self.assertRaisesRegex(claim.Refused, "ManageNotApproved"):
            claim.execute(cluster, self.make_plan(cluster, [good]), self.make_plan(cluster, [good])["approvalHash"], finish=True)

    def test_private_plan_integrity_and_duplicate_selection(self):
        cluster = Cluster()
        obj = cluster.target()
        with self.assertRaisesRegex(claim.Refused, "DuplicateClaimTarget"):
            self.make_plan(cluster, [obj, obj])
        value = self.make_plan(cluster, [obj])
        changed = copy.deepcopy(value)
        changed["resumeManage"] = True
        with self.assertRaisesRegex(claim.Refused, "ClaimPlanChanged"):
            claim.execute(cluster, changed, value["approvalHash"])
        self.assertFalse(cluster.writes)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            claim.private_write(path, value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(claim.private_read(path), value)
            with self.assertRaises(FileExistsError): claim.private_write(path, value)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError): claim.private_read(link)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(claim.Refused, "PrivateClaimFileRequired"): claim.private_read(path)
            os.chmod(path, 0o600)
            path.write_text('{"private":1,"private":2}')
            with self.assertRaisesRegex(claim.Refused, "AmbiguousJSON"): claim.private_read(path)

    def test_manage_readback_accepts_only_the_controller_cleanup_finalizer(self):
        for kind, finalizer in claim.MANAGED_FINALIZERS.items():
            for prior in (None, [], ["example/preserve"]):
                with self.subTest(kind=kind, prior=prior):
                    cluster = Cluster()
                    obj = cluster.target(kind)
                    if prior is not None:
                        obj["metadata"]["finalizers"] = copy.deepcopy(prior)
                    value = self.make_plan(cluster, [obj], resume=True)
                    claim.execute(cluster, value, value["approvalHash"])
                    obj["status"]["adoptionReceipt"] = {"contractVersion": claim.CONTRACT,
                        "candidateHash": obj["metadata"]["annotations"][claim.CANDIDATE], "state": "Verified"}
                    original_patch = cluster.patch
                    def controller_patch(target, operations):
                        result = original_patch(target, operations)
                        obj["metadata"].setdefault("finalizers", []).append(finalizer)
                        return result
                    cluster.patch = controller_patch
                    self.assertEqual(claim.execute(cluster, value, value["approvalHash"], finish=True)["phase"], "ManageRequested")
                    claim.execute(cluster, value, value["approvalHash"], finish=True)
                    self.assertEqual(obj["metadata"]["finalizers"], (prior or []) + [finalizer])
                    self.assertEqual(len(cluster.writes), 2)

    def test_manage_readback_refuses_other_metadata_changes(self):
        for change in ("foreign-finalizer", "removed-original", "annotation", "before-consent", "old-plan"):
            with self.subTest(change=change):
                cluster = Cluster()
                obj = cluster.target("HankoRole")
                obj["metadata"]["finalizers"] = ["example/preserve"]
                value = self.make_plan(cluster, [obj], resume=True)
                if change == "old-plan":
                    value["targets"][0].pop("finalizers")
                    value.pop("approvalHash")
                    value["approvalHash"] = claim.digest(value)
                claim.execute(cluster, value, value["approvalHash"])
                obj["status"]["adoptionReceipt"] = {"contractVersion": claim.CONTRACT,
                    "candidateHash": obj["metadata"]["annotations"][claim.CANDIDATE], "state": "Verified"}
                original_patch = cluster.patch
                def racing_patch(target, operations):
                    result = original_patch(target, operations)
                    obj["metadata"]["finalizers"].append(claim.MANAGED_FINALIZERS["HankoRole"])
                    if change == "foreign-finalizer": obj["metadata"]["finalizers"].append("example/foreign")
                    if change == "removed-original": obj["metadata"]["finalizers"].remove("example/preserve")
                    if change == "annotation": obj["metadata"]["annotations"]["example/preserve"] = "changed"
                    return result
                cluster.patch = racing_patch
                if change == "before-consent":
                    obj["metadata"]["finalizers"].append(claim.MANAGED_FINALIZERS["HankoRole"])
                with self.assertRaisesRegex(claim.Refused, "ClaimTargetChanged"):
                    claim.execute(cluster, value, value["approvalHash"], finish=True)

    def test_transport_uses_conditional_patch_stdin_and_suppresses_api_error_text(self):
        cluster = Cluster()
        obj = cluster.target()
        kube = claim.Kubernetes(Path("kubectl"), cluster.context)
        with patch.object(claim.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"private-body", b"private-credential")) as run:
            with self.assertRaisesRegex(claim.Refused, "KubernetesRequestUnconfirmed"):
                kube.patch(claim.identity(obj), claim.patch_operations(obj, reviewed_hash="sha256:" + "a" * 64))
            args = run.call_args
            self.assertIn("--patch-file=/dev/stdin", args.args[0])
            self.assertNotIn("example/preserve", " ".join(args.args[0]))
            patch_data = json.loads(args.kwargs["input"])
            self.assertEqual([operation["path"] for operation in patch_data[:3]],
                             ["/metadata/uid", "/metadata/generation", "/metadata/resourceVersion"])


if __name__ == "__main__":
    unittest.main()

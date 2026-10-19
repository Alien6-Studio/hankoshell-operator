import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import yaml

import api_conversion_contract as conversion
import storage_migration as migration

spec = importlib.util.spec_from_file_location("storage_installed", Path(__file__).with_name("storage-migration-installed-test.py"))
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)


class NativeCluster:
    """Stateful API fixture; storage rewrites and controller work stay distinct."""
    def __init__(self):
        self.contract = conversion.load()
        self.crds, self.objects, self.jobs, self.journals, self.writes = {}, {}, {}, {}, []
        self.active_operator = False
        self.behavior, self.interrupt, self.session_reads = None, False, 0
        for kind, entry in self.contract["resources"].items():
            crd = yaml.safe_load((conversion.ROOT / "charts/hankoshell-operator/crds" / ("hanko.sh_" + entry["plural"] + ".yaml")).read_text())
            crd["metadata"].update(uid="crd-" + kind, resourceVersion="10", generation=1)
            crd["status"] = {"storedVersions": ["v1alpha1"]}
            self.crds[entry["plural"]] = crd
            obj = {"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
                "metadata": {"name": "owned", "namespace": "auth", "uid": "object-" + kind, "resourceVersion": "20", "generation": 1,
                    "annotations": {"hanko.sh/runtime-bindings-journal": "preserve-opaque-journal"},
                    "finalizers": ["hanko.sh/provider-cleanup"], "managedFields": [{"manager": "gitops", "fieldsType": "FieldsV1", "fieldsV1": {"f:spec": {}}}]},
                "spec": {"realmRef": "managed"}, "status": {"phase": "Ready", "observedGeneration": 1, "appliedGeneration": 1, "observationComplete": True, "driftState": "InSync",
                    "adoptionReceipt": {"state": "Verified"}, "managedObjects": {"permissions": [{"id": "private-native-id"}]}}}
            self.objects[entry["plural"]] = [obj]

    def request(self, method, path, value=None, *, optional=False):
        route = urlsplit(path).path
        if method == "GET":
            if route == "/version": return {"gitVersion": "v1.37.0"}
            if route == "/api/v1/namespaces/kube-system": return {"metadata": {"uid": "cluster-uid"}}
            if route == "/apis/apps/v1/deployments": return {"items": [{"spec": {"replicas": int(self.active_operator)}, "status": {"replicas": int(self.active_operator)}}]}
            if route == "/api/v1/pods": return {"items": [{}] if self.active_operator else []}
            if route == "/apis/storagemigration.k8s.io":
                return None if self.behavior == "no-migrator" else {"versions": [{"version": "v1"}]}
            if route == "/apis/storagemigration.k8s.io/v1":
                return {"resources": [{"name": "storageversionmigrations", "kind": "StorageVersionMigration", "namespaced": False, "verbs": ["get", "list", "create"]}]}
            if route in ("/apis/hanko.sh/v1alpha1", "/apis/hanko.sh/v1beta1"):
                resources = []
                for plural, crd in self.crds.items():
                    version = next(v["name"] for v in crd["spec"]["versions"] if v["storage"])
                    digest = hashlib.sha256(("hanko.sh/" + version + "/" + crd["spec"]["names"]["kind"]).encode()).digest()[:8]
                    resources.append({"name": plural, "storageVersionHash": base64.b64encode(digest).decode()})
                return {"resources": resources}
            if route.startswith(migration.CRDS):
                return copy.deepcopy(self.crds[route.removeprefix(migration.CRDS).removesuffix("/status").removesuffix(".hanko.sh")])
            if route.startswith("/apis/hanko.sh/v1alpha1/"):
                return {"items": copy.deepcopy(self.objects[route.rsplit("/", 1)[1]]), "metadata": {}}
            if "/configmaps/" in route:
                result = self.journals.get(route)
                if result is None and not optional: raise migration.Refused("KubernetesRequestRefused")
                return copy.deepcopy(result)
            if route.endswith("/storageversionmigrations"): return {"items": copy.deepcopy(list(self.jobs.values())), "metadata": {}}
            if "/storageversionmigrations/" in route:
                job = self.jobs[route.rsplit("/", 1)[1]]
                if self.behavior == "failed-native":
                    job["status"] = {"conditions": [{"type": "Failed", "status": "True"}]}
                elif self.behavior == "stale-native":
                    job["metadata"]["generation"] = 2
                    job["status"] = {"resourceVersion": "100", "conditions": [{"type": "Succeeded", "status": "True", "observedGeneration": 1}]}
                else:
                    job["status"] = {"resourceVersion": "100", "conditions": [{"type": "Succeeded", "status": "True", "observedGeneration": 1}]}
                    if self.behavior == "native-without-generation":
                        job["metadata"].pop("generation", None)
                        job["status"]["conditions"][0].pop("observedGeneration")
                    plural = job["spec"]["resource"]["resource"]
                    for obj in self.objects[plural]: obj["metadata"]["resourceVersion"] = str(int(obj["metadata"]["resourceVersion"]) + 1)
                    if self.behavior == "lost-authority": self.objects[plural][0]["metadata"]["annotations"] = {}
                    if self.behavior == "crd-flip": self.crds[plural]["metadata"]["generation"] += 2
                    if self.behavior == "operator-started": self.active_operator = True
                return copy.deepcopy(job)
        self.writes.append((method, route))
        if route.startswith(migration.CRDS) and method == "PUT":
            plural = route.removeprefix(migration.CRDS).removesuffix("/status").removesuffix(".hanko.sh")
            current = self.crds[plural]
            if route.endswith("/status"):
                current["status"] = copy.deepcopy(value["status"])
            else:
                current["metadata"]["generation"] += int(current["spec"] != value["spec"])
                current["spec"] = copy.deepcopy(value["spec"])
                target = next(v["name"] for v in current["spec"]["versions"] if v["storage"])
                current["status"]["storedVersions"] = list(dict.fromkeys([*current["status"]["storedVersions"], target]))
            return copy.deepcopy(current)
        if method == "POST" and route.endswith("/storageversionmigrations"):
            job = copy.deepcopy(value)
            job["metadata"].update(uid="native-" + str(len(self.jobs)), generation=1)
            self.jobs[job["metadata"]["name"]] = job
            if self.interrupt:
                self.interrupt = False
                raise migration.Refused("KubernetesWriteOutcomeUnknown")
            return copy.deepcopy(job)
        if method == "POST" and route.endswith("/configmaps"):
            value = copy.deepcopy(value); value["metadata"].update(uid="journal-uid", resourceVersion="1")
            self.journals[route + "/" + value["metadata"]["name"]] = value
            return copy.deepcopy(value)
        if method == "PUT" and "/configmaps/" in route:
            self.journals[route] = copy.deepcopy(value)
            return copy.deepcopy(value)
        raise AssertionError("Unexpected API operation: " + method + " " + route)


class StorageMigrationTests(unittest.TestCase):
    def fixture(self):
        kube = NativeCluster()
        plan = migration.plan(kube, kube.contract, "v1beta1", "hanko-migrations")
        return kube, plan

    def execute(self, kube, plan):
        with patch.object(migration.time, "sleep"), patch.object(migration.time, "monotonic", side_effect=iter(range(0, 10_000))):
            return migration.Migration(kube, kube.contract, plan, conversion.digest(plan), timeout=30).execute()

    def test_forward_rollback_and_resume_preserve_approvals_journals_and_field_managers(self):
        kube, plan = self.fixture()
        original = {p: [migration.semantic_hash(obj) for obj in values] for p, values in kube.objects.items()}
        self.assertTrue(self.execute(kube, plan)["complete"])
        self.assertEqual(len(kube.jobs), 3)
        self.assertTrue(all(v["status"]["storedVersions"] == ["v1beta1"] for v in kube.crds.values()))
        # A second run never treats a journal as a rewrite proof; a fresh native
        # request remains required even if someone forged its completed phase.
        self.assertTrue(self.execute(kube, plan)["complete"])
        self.assertEqual(len(kube.jobs), 6)
        back = migration.plan(kube, kube.contract, "v1alpha1", "hanko-migrations")
        self.assertTrue(self.execute(kube, back)["complete"])
        self.assertTrue(all(v["status"]["storedVersions"] == ["v1alpha1"] for v in kube.crds.values()))
        self.assertEqual(original, {p: [migration.semantic_hash(obj) for obj in values] for p, values in kube.objects.items()})
        self.assertFalse(any("secret" in path or "client" in path for _, path in kube.writes))

    def test_lost_create_ack_resumes_without_trusting_old_progress_or_replacing_native_objects(self):
        kube, plan = self.fixture(); kube.interrupt = True
        with self.assertRaisesRegex(migration.Refused, "KubernetesWriteOutcomeUnknown"):
            self.execute(kube, plan)
        self.assertFalse(any(path.endswith("/status") for _, path in kube.writes))
        preserved = {name: job["metadata"]["uid"] for name, job in kube.jobs.items()}
        self.assertTrue(self.execute(kube, plan)["complete"])
        self.assertTrue(all(kube.jobs[name]["metadata"]["uid"] == uid for name, uid in preserved.items()))
        self.assertEqual(len(kube.jobs), 4)

    def test_native_immutable_rest_resource_can_omit_generation(self):
        kube, plan = self.fixture(); kube.behavior = "native-without-generation"
        self.assertTrue(self.execute(kube, plan)["complete"])
        self.assertEqual(len(kube.jobs), 3)

    def test_resuming_cannot_widen_approval_to_a_changed_declaration(self):
        kube, plan = self.fixture(); kube.interrupt = True
        with self.assertRaisesRegex(migration.Refused, "KubernetesWriteOutcomeUnknown"):
            self.execute(kube, plan)
        value = kube.objects["hankoapplications"][0]
        value["metadata"].update(generation=2, resourceVersion="40")
        value["status"].update(observedGeneration=2, appliedGeneration=2)
        value["spec"]["clientID"] = "changed"
        writes = list(kube.writes)
        with self.assertRaisesRegex(migration.Refused, "ObjectIdentityChanged"):
            self.execute(kube, plan)
        self.assertEqual(kube.writes, writes)

    def test_observe_and_imported_objects_preserve_read_only_semantics(self):
        for imported in (False, True):
            kube = NativeCluster()
            for values in kube.objects.values():
                obj = values[0]
                obj["status"].update(appliedGeneration=0, observationGeneration=1)
                if imported: obj["metadata"]["labels"] = {"hanko.sh/imported-by": "inventory"}
                else: obj["spec"]["mode"] = "Observe"
            plan = migration.plan(kube, kube.contract, "v1beta1", "hanko-migrations")
            self.assertTrue(self.execute(kube, plan)["complete"])
            self.assertTrue(all(values[0]["status"]["appliedGeneration"] == 0 for values in kube.objects.values()))

    def test_pending_or_mismatched_adoption_receipt_is_not_idle(self):
        for behavior in ("pending-without-annotation", "different-candidate"):
            kube, plan = self.fixture()
            value = kube.objects["hankoapplications"][0]
            if behavior == "pending-without-annotation": value["status"]["adoptionReceipt"]["state"] = "Pending"
            else: value["metadata"]["annotations"]["hanko.sh/adoption-candidate"] = "changed-candidate"
            with self.assertRaisesRegex(migration.Refused, "PendingAdoption"):
                self.execute(kube, plan)
            self.assertEqual(kube.writes, [])

    def test_pending_or_foreign_state_blocks_before_any_write(self):
        for behavior in ("operator", "delete", "not-ready", "rotation", "delegation", "adoption", "replacement", "changed-review", "foreign-schema", "unknown-storage", "no-migrator", "wrong-cluster"):
            with self.subTest(behavior=behavior):
                kube, plan = self.fixture()
                value = kube.objects["hankoapplications"][0]
                if behavior == "operator": kube.active_operator = True
                elif behavior == "delete": value["metadata"]["deletionTimestamp"] = "current"
                elif behavior == "not-ready": value["status"]["phase"] = "Error"
                elif behavior == "rotation": value["spec"]["secretRotationPolicy"] = {"enabled": True}
                elif behavior == "delegation": value["spec"]["permissions"] = [{"delegation": {"maxDepth": 2}}]
                elif behavior == "adoption":
                    value["metadata"]["annotations"]["hanko.sh/adoption-contract"] = "reviewed"
                    value["status"].pop("adoptionReceipt")
                elif behavior == "replacement": value["metadata"]["uid"] = "replacement"
                elif behavior == "changed-review": value["metadata"]["resourceVersion"] = "changed"
                elif behavior == "foreign-schema": kube.crds["hankoroles"]["spec"]["versions"][1]["schema"]["openAPIV3Schema"]["properties"].pop("status")
                elif behavior == "unknown-storage": kube.crds["hankoroles"]["status"]["storedVersions"] = ["v0"]
                elif behavior == "no-migrator": kube.behavior = "no-migrator"
                elif behavior == "wrong-cluster": plan["cluster_uid"] = "different-cluster"
                with self.assertRaises(migration.Refused): self.execute(kube, plan)
                self.assertEqual(kube.writes, [])

    def test_native_failure_stale_success_or_changed_authority_never_clears_stored_versions(self):
        for behavior in ("failed-native", "stale-native", "lost-authority", "crd-flip", "operator-started"):
            with self.subTest(behavior=behavior):
                kube, plan = self.fixture(); kube.behavior = behavior
                with self.assertRaises(migration.Refused): self.execute(kube, plan)
                self.assertFalse(any(path.endswith("/status") for _, path in kube.writes))
                self.assertTrue(all("v1alpha1" in c["status"]["storedVersions"] for c in kube.crds.values()))

    def test_forged_completed_journal_still_needs_fresh_native_success(self):
        kube, plan = self.fixture()
        fixture = migration.Migration(kube, kube.contract, plan, conversion.digest(plan), timeout=30)
        kube.journals[fixture.journal_path] = {"metadata": {"uid": "foreign-journal"}, "data": {migration.JOURNAL_KEY: json.dumps({"format": migration.FORMAT, "plan": fixture.identity, "phase": "Committed"})}}
        kube.behavior = "failed-native"
        with self.assertRaisesRegex(migration.Refused, "NativeMigrationFailed"):
            self.execute(kube, plan)
        self.assertEqual(len(kube.jobs), 1)
        self.assertFalse(any(path.endswith("/status") for _, path in kube.writes))

    def test_plan_and_journal_do_not_capture_sensitive_state_or_payload_hashes(self):
        kube, plan = self.fixture()
        kube.objects["hankoapplications"][0]["status"]["legacyField"] = "private-credential-sentinel"
        # A fresh plan authorizes metadata identity, not a digest of credentials.
        plan = migration.plan(kube, kube.contract, "v1beta1", "hanko-migrations")
        self.assertTrue(self.execute(kube, plan)["complete"])
        output = json.dumps({"plan": plan, "journals": kube.journals})
        self.assertNotIn("private-credential-sentinel", output)
        self.assertNotIn(hashlib.sha256(b"private-credential-sentinel").hexdigest(), output)
        self.assertNotIn("private-native-id", output)

    def test_ambiguous_or_oversized_json_and_unreviewed_plan_are_refused(self):
        for raw in ('{"plan":1,"plan":2}', 'NaN', '{"a":NaN}', 'not-json'):
            with self.subTest(raw=raw), self.assertRaises(migration.Refused): migration.decode(raw)
        kube, plan = self.fixture()
        with self.assertRaisesRegex(migration.Refused, "PlanApprovalMismatch"):
            migration.Migration(kube, kube.contract, plan, "0" * 64)
        self.assertEqual(kube.writes, [])


class InstalledEvidenceTests(unittest.TestCase):
    def test_cleanup_failures_retain_bounded_failure_evidence_and_remove_credentials(self):
        for failed_step in (None, "cluster_delete", "image_delete", "cluster_inspect"):
            with self.subTest(failed_step=failed_step), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                kubeconfig = output / "kubeconfig"
                kubeconfig.write_text("private-credential-sentinel")
                report = {"complete": False, "cleanup": False, "active_phase": "resume_commit", "failure_type": "RuntimeError"}
                calls = []

                def execute(command, **kwargs):
                    label = "image_delete" if command[0] == "docker" else "cluster_inspect" if command[1] == "get" else "cluster_delete"
                    calls.append(label)
                    if label == failed_step:
                        raise subprocess.TimeoutExpired(command, 120, stderr=b"private-credential-sentinel")
                    return b""

                with patch.object(installed, "execute", side_effect=execute):
                    installed.cleanup("kind", "owned-fixture", "owned-image", kubeconfig, output, report)
                self.assertEqual(calls, ["cluster_delete", "image_delete", "cluster_inspect"])
                retained = json.loads((output / "report.json").read_text())
                self.assertFalse(retained["complete"])
                self.assertEqual(retained["active_phase"], "resume_commit")
                self.assertEqual(retained["failure_type"], "RuntimeError")
                self.assertEqual(retained["cleanup_failures"], [failed_step] if failed_step else [])
                self.assertNotIn("private-credential-sentinel", json.dumps(retained))
                self.assertFalse(kubeconfig.exists())


if __name__ == "__main__":
    unittest.main()

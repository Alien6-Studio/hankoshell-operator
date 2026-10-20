"""Isolation and continuity boundaries of the persistent qualification runner."""

import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.qualification.runners import cluster_job
from tools.qualification.scenarios import cluster_campaign, soak_observer


class ClusterCampaignTests(unittest.TestCase):
    def state(self):
        return {"namespace": "hanko-qualification-test", "release": "qualification",
                "operator_image": "registry.example/operator@sha256:" + "a" * 64, "revision": "b" * 40,
                "runner": "python@sha256:" + "c" * 64, "counts": dict.fromkeys(soak_observer.RESOURCES, 10),
                "workers": dict.fromkeys(soak_observer.measure.WORKER_KINDS, 4)}

    def test_job_is_persistent_namespaced_and_never_restarts_a_failed_interval(self):
        state = self.state()
        config = {"provider": "https://keycloak." + state["namespace"] + ".svc:8443",
                  "objects": [{"metadata": {"namespace": state["namespace"]}}]}
        docs = cluster_job.manifests(state, config)
        self.assertFalse(any(doc["kind"].startswith("Cluster") for doc in docs))
        role = next(doc for doc in docs if doc["kind"] == "Role")
        self.assertFalse(any("secrets" in rule["resources"] for rule in role["rules"]))
        job = next(doc for doc in docs if doc["kind"] == "Job")["spec"]
        self.assertEqual(job["backoffLimit"], 0)
        self.assertEqual(job["template"]["spec"]["restartPolicy"], "Never")
        self.assertTrue(any("persistentVolumeClaim" in v for v in job["template"]["spec"]["volumes"]))
        for mutation in ("namespace", "image", "runner"):
            bad = copy.deepcopy(state)
            bad[{"namespace": "namespace", "image": "operator_image", "runner": "runner"}[mutation]] = "auth" if mutation == "namespace" else "mutable:latest"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                cluster_job.manifests(bad, config)
        with self.assertRaises(ValueError):
            cluster_job.manifests(state, dict(config, provider="https://production.example"))

    def test_campaign_cannot_write_another_namespace_or_cluster_scope(self):
        campaign = object.__new__(cluster_campaign.Campaign)
        campaign.args = SimpleNamespace(namespace="hanko-qualification-test")
        for path in ("/api/v1/namespaces/auth/pods/leader", "/apis/hanko.sh/v1alpha1/namespaces/auth/hankorealms",
                     "/api/v1/namespaces/hanko-qualification-test-other/pods", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"):
            with self.subTest(path=path), patch.object(Path, "read_text", side_effect=AssertionError("credentials read")), self.assertRaisesRegex(ValueError, "escaped"):
                campaign.request("DELETE", path)

    def test_ready_requires_current_success_and_actual_read_back_for_plan_resources(self):
        obj = {"kind": "HankoApplication", "metadata": {"generation": 2}, "status": {
            "phase": "Ready", "observedGeneration": 2, "appliedGeneration": 2,
            "appliedPlanHash": "hash", "observationPlanHash": "hash", "observationComplete": True,
            "conditions": [{"type": "Synced", "status": "True"}]}}
        self.assertTrue(cluster_campaign.current_ready(obj))
        for field, value in (("observedGeneration", 1), ("appliedGeneration", 1), ("observationComplete", False),
                             ("observationPlanHash", "stale"), ("appliedPlanHash", ""), ("conditions", [])):
            bad = copy.deepcopy(obj)
            bad["status"][field] = value
            self.assertFalse(cluster_campaign.current_ready(bad), field)
        obj["kind"] = "HankoOrganization"
        obj["status"] = {k: v for k, v in obj["status"].items() if k in ("phase", "observedGeneration", "conditions")}
        self.assertTrue(cluster_campaign.current_ready(obj))

    def test_measurement_rejects_gaps_clock_rollback_and_short_endurance(self):
        for before, after in ((0, 46), (10, 9)):
            with self.assertRaises(ValueError):
                soak_observer.measure.sampling_gap(before, after)
        state = self.state()
        args = SimpleNamespace(namespace=state["namespace"], release=state["release"], image=state["operator_image"],
            revision=state["revision"], metrics_hostname="metrics.hanko-qualification-test.svc",
            counts=state["counts"], workers=state["workers"], seconds=86399, warmup=3600, interval=10)
        with self.assertRaises(ValueError):
            soak_observer.validate(args)


if __name__ == "__main__":
    unittest.main()

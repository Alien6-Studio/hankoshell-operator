import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml

SPEC = importlib.util.spec_from_file_location("portable_installed", Path(__file__).with_name("portable-installed-test.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class PortableInstalledTests(unittest.TestCase):
    def setUp(self):
        self.corpus = fixture.read_corpus()
        self.spa = next(f for f in self.corpus["fixtures"] if f["name"] == "spa")
        digest = "sha256:" + "a" * 64
        self.value = {"metadata": {"generation": 7}, "status": {
            "phase": "Ready", "backendKind": "authentik", "observedGeneration": 7, "evaluatedGeneration": 7,
            "appliedGeneration": 7, "observationGeneration": 7, "observationComplete": True, "driftState": "InSync",
            "intentHash": self.spa["intentIdentity"], "evaluatedPlanHash": digest, "appliedPlanHash": digest,
            "observationPlanHash": digest, "observedStateHash": digest}}

    def test_lossless_requires_current_bound_execution_evidence(self):
        expected = self.spa["expected"]["authentik"]
        valid = lambda value: fixture.observation_valid(value, expected, "authentik", self.spa["intentIdentity"])
        self.assertTrue(valid(self.value))
        for key, bad in (("backendKind", "keycloak"), ("intentHash", "sha256:" + "b" * 64),
                         ("observationPlanHash", "sha256:" + "b" * 64), ("appliedGeneration", 6),
                         ("observedGeneration", 6), ("observationComplete", False), ("driftState", "Unknown")):
            with self.subTest(key=key):
                value = copy.deepcopy(self.value)
                value["status"][key] = bad
                self.assertFalse(valid(value))

    def test_unsupported_requires_current_finding_and_no_applied_claim(self):
        expected = self.corpus["fixtures"][0]["expected"]["authentik"]
        value = {"metadata": {"generation": 2}, "status": {"phase": "Error", "observedGeneration": 2,
            "conditions": [{"type": "Synced", "status": "False", "reason": "ExperimentalUnsupported", "observedGeneration": 2}]}}
        valid = lambda value: fixture.observation_valid(value, expected, "authentik")
        self.assertTrue(valid(value))
        for key, bad in (("appliedPlanHash", "sha256:" + "a" * 64), ("observationComplete", True), ("conditions", [])):
            with self.subTest(key=key):
                changed = copy.deepcopy(value)
                changed["status"][key] = bad
                self.assertFalse(valid(changed))

    def test_corpus_refuses_unclassified_losses_and_findings(self):
        for key, value in (("classification", "lossy"), ("statusReason", ""), ("reason", ""), ("planEvidence", True)):
            data = copy.deepcopy(self.corpus)
            data["fixtures"][0]["expected"]["authentik"][key] = value
            with self.subTest(key=key), patch.object(fixture, "CORPUS") as path:
                path.read_bytes.return_value = json.dumps(data).encode()
                with self.assertRaises(ValueError):
                    fixture.read_corpus()

    def test_read_only_realm_status_does_not_satisfy_manage_fixture(self):
        expected = self.corpus["fixtures"][0]["expected"]["keycloak"]
        value = {"kind": "HankoRealm", "metadata": {"generation": 1}, "status": {
            "phase": "Ready", "observedGeneration": 1, "conditions": [{"type": "Synced", "status": "True", "reason": "Observed"}]}}
        self.assertFalse(fixture.observation_valid(value, expected, "keycloak"))
        value["status"]["conditions"][0]["reason"] = "Reconciled"
        self.assertTrue(fixture.observation_valid(value, expected, "keycloak"))

    def test_report_allowlist_withholds_bootstrap_and_native_documents(self):
        target = object.__new__(fixture.Portable)
        target.report = {key: [] for key in ("differences", "bindings", "approved_losses")}
        target.report.update({key: "public" for key in ("corpus_sha256", "authentik_image", "postgres_image")})
        target.report.update(hub_enabled=False, complete=False, bootstrap_token="PRIVATE-SENTINEL", native_provider={"client_secret": "PRIVATE-SENTINEL"})
        report = target.public_evidence()
        self.assertFalse(report["complete"])
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(report))

    def test_both_providers_are_mandatory_in_all_six_runtime_cells(self):
        jobs = yaml.safe_load((fixture.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        job = jobs["installed-portable"]
        self.assertEqual(job["needs"], ["source", "oci"])
        self.assertNotIn("if", job)
        self.assertFalse(job.get("continue-on-error", False))
        self.assertEqual(job["strategy"]["matrix"], {"keycloak": ["26.7.5", "26.8.0"], "kubernetes": ["1.35.0", "1.36.2", "1.37.0"]})
        command = next(s for s in job["steps"] if "portable-installed-test.py" in s.get("run", ""))
        self.assertNotIn("if", command)
        self.assertNotIn("--deep-migration", command["run"])
        upload = next(s for s in job["steps"] if s.get("with", {}).get("name", "").startswith("NONPUBLISHABLE-installed-portable-"))
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertIn("installed-portable", jobs["checks"]["needs"])
        self.assertIn('test "$INSTALLED_PORTABLE_RESULT" = success', jobs["checks"]["steps"][0]["run"])

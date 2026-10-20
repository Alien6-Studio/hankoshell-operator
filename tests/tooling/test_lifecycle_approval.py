import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("lifecycle", ROOT / 'tools/operations/lifecycle_approval.py')
approval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(approval)


class LifecycleApprovalTests(unittest.TestCase):
    def fixture(self):
        return {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOperation", "metadata": {"uid": "object-uid", "generation": 4},
                "status": {"conditions": [{"type": "Authorized", "status": "False", "reason": "ApprovalRequired", "observedGeneration": 4,
                                           "message": "Approval required: v1|object-uid|4|instance-uid|sha256:" + "a" * 64}]}}

    def test_only_the_current_reviewed_request_becomes_a_patch(self):
        fixture = self.fixture()
        original = copy.deepcopy(fixture)
        patch = approval.prepare(fixture)
        self.assertEqual(patch, {"metadata": {"annotations": {"hanko.sh/lifecycle-approval": fixture["status"]["conditions"][0]["message"].removeprefix("Approval required: ")}}})
        self.assertEqual(fixture, original)

    def test_stale_ambiguous_foreign_or_malformed_requests_are_refused(self):
        for mutation in ("uid", "generation", "condition", "duplicate", "kind", "version", "digest", "deleting", "instance"):
            with self.subTest(mutation=mutation):
                value = self.fixture()
                if mutation in ("uid", "generation"):
                    value["metadata"][mutation] = "replacement" if mutation == "uid" else 5
                elif mutation == "condition":
                    value["status"]["conditions"][0]["observedGeneration"] = 3
                elif mutation == "duplicate":
                    value["status"]["conditions"] *= 2
                elif mutation == "kind":
                    value["kind"] = "HankoRealm"
                elif mutation == "version":
                    value["status"]["conditions"][0]["message"] = value["status"]["conditions"][0]["message"].replace("v1|", "v2|")
                elif mutation == "digest":
                    value["status"]["conditions"][0]["message"] += "untrusted"
                elif mutation == "deleting":
                    value["metadata"]["deletionTimestamp"] = "2026-10-16T00:00:00Z"
                elif mutation == "instance":
                    value["status"]["conditions"][0]["message"] = value["status"]["conditions"][0]["message"].replace("instance-uid", "")
                with self.assertRaises(ValueError):
                    approval.prepare(value)

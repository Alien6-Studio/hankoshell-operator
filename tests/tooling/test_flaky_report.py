import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("flaky_report", ROOT / 'tools/qualification/reporting/flaky_report.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)

SHA = "a" * 40
PACKAGE = "github.com/Alien6-Studio/hankoshell-operator/internal/controller"


def outcome(status="passed", revision=SHA, suite="unit"):
    return {"schema": 1, "suite": suite, "revision": revision, "worktree_dirty": False, "returncode": 1 if status == "failed" else 0,
            "tests": [{"package": PACKAGE, "name": "TestOne", "outcome": status}]}


def archive(report, duplicate=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        bundle.writestr("unit/results.json", json.dumps(report))
        bundle.writestr("unit/junit.xml", "not consumed; may contain test output")
        if duplicate:
            bundle.writestr("duplicate/results.json", json.dumps(report))
    return stream.getvalue()


class FlakyReportTests(unittest.TestCase):
    def test_authentik_history_uses_the_actual_runner_suite_identity(self):
        self.assertEqual(reporter.artifact_suites()["authentik-2026.8.4"], "authentik-2026.8.4")
        report = outcome(suite="authentik-2026.8.4")
        self.assertEqual(reporter.read_artifact(archive(report), reporter.artifact_suites()["authentik-2026.8.4"], SHA), report)

    def test_mixed_outcomes_require_same_revision_suite_and_identity(self):
        records = [{"run": 1, "attempt": 2, "report": outcome()}, {"run": 1, "attempt": 1, "report": outcome("failed")}]
        result = reporter.aggregate(records)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["passed_runs"], ["1/attempts/2"])
        self.assertEqual(result[0]["failed_runs"], ["1/attempts/1"])
        for changed in (outcome("failed", revision="b" * 40), outcome("failed", suite="keycloak/26.7.5/core"), outcome("skipped")):
            self.assertEqual(reporter.aggregate([records[0], {"run": 2, "attempt": 1, "report": changed}]), [])

    def test_archive_is_bound_to_expected_commit_and_suite(self):
        data = archive(outcome())
        self.assertEqual(reporter.read_artifact(data, "unit", SHA), outcome())
        for revision, suite in (("b" * 40, "unit"), (SHA, "keycloak/26.7.5/core")):
            with self.assertRaises(ValueError):
                reporter.read_artifact(data, suite, revision)
        for data in (archive(outcome(), duplicate=True), b"not a zip"):
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                reporter.read_artifact(data, "unit", SHA)

    def test_invalid_outcomes_never_count_as_passes(self):
        for field, value in (("schema", 2), ("tests", []), ("returncode", True), ("worktree_dirty", True), ("worktree_dirty", None)):
            bad = dict(outcome(), **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                reporter.read_artifact(archive(bad), "unit", SHA)
        for field, value in (("outcome", "unknown"), ("package", "foreign/package"), ("name", "")):
            bad = outcome()
            bad["tests"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                reporter.read_artifact(archive(bad), "unit", SHA)
        bad = outcome("failed")
        bad["returncode"] = 0
        with self.assertRaises(ValueError):
            reporter.read_artifact(archive(bad), "unit", SHA)
        bad = outcome()
        bad["tests"] *= 2
        with self.assertRaises(ValueError):
            reporter.read_artifact(archive(bad), "unit", SHA)

    def fixture(self, artifacts=None):
        artifacts = artifacts if artifacts is not None else [{"name": "go-tests-unit-1-2", "id": 10, "expired": False, "size_in_bytes": 100}]
        run = {"id": 1, "run_attempt": 2, "head_sha": SHA, "head_branch": "main", "status": "completed"}
        data = {"workflow_runs": [run]}
        inventory = {"total_count": len(artifacts), "artifacts": artifacts}

        def fetch(endpoint, binary=False):
            if "/workflows/ci.yml/runs?" in endpoint:
                return copy.deepcopy(data)
            if "/runs/1/artifacts?" in endpoint:
                return copy.deepcopy(inventory)
            self.assertTrue(binary)
            self.assertTrue(endpoint.endswith("/artifacts/10/zip"))
            return archive(outcome())

        return data, inventory, fetch

    def test_collect_is_get_only_and_missing_evidence_remains_visible(self):
        _, _, fetch = self.fixture()
        records, gaps, count = reporter.collect("Alien6-Studio/hankoshell-operator", 20, fetch)
        self.assertEqual(count, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(gaps), len(reporter.artifact_suites()) - 1)
        result, summary = reporter.summarize("Alien6-Studio/hankoshell-operator", records, gaps, count, 20)
        self.assertEqual(result["gaps"], gaps)
        self.assertIn("1/20", summary)
        self.assertIn("do not establish stability", summary)

    def test_expired_and_missing_reports_are_not_reused(self):
        for artifacts in ([],
                          [{"name": "go-tests-unit-1-2", "id": 10, "expired": True, "size_in_bytes": 100}]):
            _, _, fetch = self.fixture(artifacts)
            records, gaps, _ = reporter.collect("Alien6-Studio/hankoshell-operator", 20, fetch)
            self.assertEqual(records, [])
            self.assertEqual(len(gaps), len(reporter.artifact_suites()))

    def test_previous_attempt_is_compared_without_hiding_missing_current_reports(self):
        artifacts = [{"name": "go-tests-unit-1-1", "id": 10, "expired": False, "size_in_bytes": 100}]
        _, _, fetch = self.fixture(artifacts)
        records, gaps, _ = reporter.collect("Alien6-Studio/hankoshell-operator", 20, fetch)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["attempt"], 1)
        self.assertEqual(len(gaps), len(reporter.artifact_suites()))
        self.assertTrue(all(gap["attempt"] == 2 for gap in gaps))

    def test_wrong_run_duplicate_artifacts_and_truncated_inventory_fail(self):
        for mutation in ("branch", "revision", "duplicate", "truncated"):
            data, inventory, fetch = self.fixture()
            if mutation == "branch":
                data["workflow_runs"][0]["head_branch"] = "feature"
            if mutation == "revision":
                data["workflow_runs"][0]["head_sha"] = "untrusted"
            if mutation == "duplicate":
                inventory["artifacts"] *= 2
                inventory["total_count"] = 2
            if mutation == "truncated":
                inventory["total_count"] = 101
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                reporter.collect("Alien6-Studio/hankoshell-operator", 20, fetch)

    def test_weekly_history_workflow_has_no_write_permission_or_test_retry(self):
        workflow = yaml.safe_load((Path(__file__).parents[2] / ".github/workflows/test-history.yml").read_text())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertIn("schedule", workflow[True])
        job = workflow["jobs"]["report"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
        commands = [step["run"] for step in job["steps"] if "run" in step]
        self.assertEqual(commands, ['python3 -m tools.qualification.reporting.flaky_report --runs 20 --output "$RUNNER_TEMP/go-test-history"'])
        self.assertNotIn("continue-on-error", job)


if __name__ == "__main__":
    unittest.main()

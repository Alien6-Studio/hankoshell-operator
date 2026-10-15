import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("flaky_report", Path(__file__).with_name("flaky-report.py"))
flaky = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flaky)

REVISIONS = {7: "a" * 40, 8: "b" * 40}


def archive(suite, tests):
    report = {"schema": 1, "suite": suite, "revision": None, "returncode": 0, "worktree_dirty": False,
              "suite_errors": 0, "counts": {}, "tests": tests}
    def build(revision):
        payload = dict(report, revision=revision)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            bundle.writestr("keycloak-26.7.5-core/results.json", json.dumps(payload))
            bundle.writestr("keycloak-26.7.5-core/junit.xml", "<testsuites/>")
        return buffer.getvalue()
    return build


class FakeGitHub:
    def __init__(self, runs, artifacts, archives, issues=()):
        self.runs, self.artifacts, self.archives = runs, artifacts, archives
        self.issues = list(issues)
        self.writes = []

    def __call__(self, endpoint, payload=None, method=None):
        if method is not None:
            self.writes.append((method, endpoint, payload))
            return {}
        if "/workflows/ci.yml/runs" in endpoint:
            return {"workflow_runs": self.runs}
        if "/artifacts?" in endpoint:
            run_id = int(endpoint.split("/runs/")[1].split("/")[0])
            return {"artifacts": self.artifacts.get(run_id, [])}
        return self.issues

    def archive(self, endpoint):
        artifact_id = int(endpoint.split("/artifacts/")[1].split("/")[0])
        return self.archives[artifact_id]


def fixture(outcome_by_run):
    runs = [{"id": run, "head_sha": REVISIONS[run]} for run in sorted(outcome_by_run)]
    artifacts, archives = {}, {}
    for index, (run, outcome) in enumerate(sorted(outcome_by_run.items()), start=100):
        tests = [{"package": "internal/controller", "name": "TestRealKeycloakAdoptionCharacterization",
                  "outcome": outcome, "seconds": 35.0},
                 {"package": "internal/controller", "name": "TestStable", "outcome": "passed", "seconds": 1.0}]
        artifacts[run] = [{"id": index, "name": f"go-tests-keycloak-{run}", "expired": False},
                          {"id": index + 50, "name": "NONPUBLISHABLE-workload", "expired": False}]
        archives[index] = archive("keycloak/26.7.5/core", tests)(REVISIONS[run])
    return FakeGitHub(runs, artifacts, archives), archives


class FlakyWindowTests(unittest.TestCase):
    def test_a_test_with_both_outcomes_in_the_window_is_flaky(self):
        github, archives = fixture({7: "failed", 8: "passed"})
        with patch.object(flaky, "github_archive", github.archive):
            found, inspected = flaky.flaky_tests("owner/repo", "main", 20, github)
        self.assertEqual(inspected, 2)
        self.assertEqual(list(found), [("keycloak/26.7.5/core", "internal/controller",
                                        "TestRealKeycloakAdoptionCharacterization")])
        record = next(iter(found.values()))
        self.assertEqual((record["failed"], record["passed"]), ({7}, {8}))

    def test_consistent_failures_and_skips_are_not_flaky(self):
        github, _ = fixture({7: "failed", 8: "skipped"})
        with patch.object(flaky, "github_archive", github.archive):
            found, _ = flaky.flaky_tests("owner/repo", "main", 20, github)
        self.assertEqual(found, {})

    def test_reports_bound_to_a_foreign_revision_are_refused(self):
        github, _ = fixture({7: "failed", 8: "passed"})
        github.runs[0]["head_sha"] = "c" * 40
        with patch.object(flaky, "github_archive", github.archive), self.assertRaises(ValueError):
            flaky.flaky_tests("owner/repo", "main", 20, github)

    def test_expired_and_foreign_artifacts_are_skipped(self):
        github, _ = fixture({7: "failed", 8: "passed"})
        for artifact in github.artifacts[7]:
            artifact["expired"] = True
        with patch.object(flaky, "github_archive", github.archive):
            found, _ = flaky.flaky_tests("owner/repo", "main", 20, github)
        self.assertEqual(found, {})

    def test_invalid_run_identities_are_refused(self):
        github, _ = fixture({7: "failed"})
        github.runs[0]["id"] = "7"
        with self.assertRaises(ValueError):
            flaky.flaky_tests("owner/repo", "main", 20, github)


class RenderTests(unittest.TestCase):
    def test_clean_window_names_the_inspected_run_count(self):
        text = flaky.render("owner/repo", {}, 20)
        self.assertIn("last 20 completed qualification runs", text)
        self.assertIn("No test both passed and failed", text)

    def test_flaky_identities_carry_counts_last_run_and_escaping(self):
        found = {("suite", "pkg", "Test<img>"): {"failed": {7, 9}, "passed": {8}}}
        text = flaky.render("owner/repo", found, 20)
        self.assertIn("failed 2x, passed 1x", text)
        self.assertIn("https://github.com/owner/repo/actions/runs/9", text)
        self.assertNotIn("<img>", text)

    def test_listing_is_bounded(self):
        found = {("s", "p", f"Test{i:03}"): {"failed": {7}, "passed": {8}} for i in range(60)}
        text = flaky.render("owner/repo", found, 20)
        self.assertIn("Test049", text)
        self.assertNotIn("Test050", text)
        self.assertIn("Additional flaky tests not listed: 10.", text)


class ReconcileTests(unittest.TestCase):
    def test_clean_window_closes_an_open_issue_and_otherwise_writes_nothing(self):
        github, _ = fixture({})
        self.assertEqual(flaky.reconcile("owner/repo", "text", {}, github), "clean")
        self.assertEqual(github.writes, [])
        github.issues = [{"number": 4, "title": flaky.TITLE}]
        self.assertEqual(flaky.reconcile("owner/repo", "text", {}, github), "closed")
        self.assertEqual([(m, e) for m, e, _ in github.writes],
                         [("POST", "repos/owner/repo/issues/4/comments"), ("PATCH", "repos/owner/repo/issues/4")])

    def test_flaky_window_opens_or_updates_one_labelled_issue(self):
        found = {("s", "p", "TestA"): {"failed": {7}, "passed": {8}}}
        github, _ = fixture({})
        self.assertEqual(flaky.reconcile("owner/repo", "text", found, github), "opened")
        self.assertEqual(github.writes[0][2], {"title": flaky.TITLE, "body": "text", "labels": [flaky.LABEL]})
        github.writes.clear()
        github.issues = [{"number": 4, "title": flaky.TITLE},
                         {"number": 5, "title": flaky.schedule_report.TITLE}]
        self.assertEqual(flaky.reconcile("owner/repo", "text", found, github), "updated")
        self.assertEqual([(m, e) for m, e, _ in github.writes],
                         [("POST", "repos/owner/repo/issues/4/comments")])


if __name__ == "__main__":
    unittest.main()

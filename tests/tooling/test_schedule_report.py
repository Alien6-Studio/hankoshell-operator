import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("schedule_report", ROOT / 'tools/qualification/reporting/schedule_report.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

REVISION = "a" * 40
GREEN = {"checks": {"result": "success"}, "keycloak": {"result": "success"}}
RED = {"checks": {"result": "failure"}, "keycloak": {"result": "failure"}}


def outcome_report(revision=REVISION, tests=(), **overrides):
    payload = {"schema": 1, "suite": "keycloak/26.7.5/core", "revision": revision,
               "returncode": 1, "worktree_dirty": False, "suite_errors": 0,
               "counts": {"passed": 0, "failed": len(tests), "skipped": 0}, "tests": list(tests)}
    payload.update(overrides)
    return payload


class FakeGitHub:
    def __init__(self, issues=()):
        self.issues = list(issues)
        self.writes = []

    def __call__(self, endpoint, payload=None, method=None):
        if method is None:
            return self.issues
        self.writes.append((method, endpoint, payload))
        return {}


class JobResultTests(unittest.TestCase):
    def test_valid_needs_context_is_reduced_to_results(self):
        raw = json.dumps({"checks": {"result": "success", "outputs": {}},
                          "installed-workload": {"result": "skipped"}})
        self.assertEqual(report.job_results(raw),
                         {"checks": "success", "installed-workload": "skipped"})

    def test_results_without_the_gate_or_with_foreign_content_are_refused(self):
        for raw in ("[]", "{}", json.dumps({"keycloak": {"result": "success"}}),
                    json.dumps({"checks": {"result": "green"}}),
                    json.dumps({"checks": {"result": "success"}, "Bad Job": {"result": "success"}}),
                    json.dumps({"checks": {"result": "success"}, "oci": "failure"}),
                    json.dumps({f"job-{i}": {"result": "success"} for i in range(32)} | {"checks": {"result": "success"}})):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                report.job_results(raw)


class FailedTestTests(unittest.TestCase):
    def test_failures_are_collected_sorted_and_bound_to_the_revision(self):
        tests = [{"package": "internal/controller", "name": "TestRealKeycloakAdoptionCharacterization",
                  "outcome": "failed", "seconds": 35.0},
                 {"package": "internal/controller", "name": "TestGreen", "outcome": "passed", "seconds": 1.0}]
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "go-tests-keycloak" / "keycloak-26.7.5-core"
            nested.mkdir(parents=True)
            (nested / "results.json").write_text(json.dumps(outcome_report(tests=tests)))
            self.assertEqual(report.failed_tests(Path(tmp), REVISION),
                             ["keycloak/26.7.5/core / internal/controller / TestRealKeycloakAdoptionCharacterization"])
            self.assertEqual(report.failed_tests(Path(tmp) / "absent", REVISION), [])
            with self.assertRaises(ValueError):
                report.failed_tests(Path(tmp), "b" * 40)

    def test_foreign_schema_or_invalid_outcomes_are_refused(self):
        for broken in (outcome_report(schema=2), outcome_report(suite=7), outcome_report(tests=[7]),
                       outcome_report(tests=[{"package": "p", "name": "T", "outcome": "flaky"}]),
                       outcome_report(tests=[{"package": "p", "name": "", "outcome": "failed"}]),
                       outcome_report(tests=[{"package": 3, "name": "T", "outcome": "failed"}])):
            with tempfile.TemporaryDirectory() as tmp, self.subTest(broken=broken):
                (Path(tmp) / "results.json").write_text(json.dumps(broken))
                with self.assertRaises(ValueError):
                    report.failed_tests(Path(tmp), REVISION)


class ReconcileTests(unittest.TestCase):
    def test_green_run_without_an_issue_writes_nothing(self):
        github = FakeGitHub()
        outcome = report.reconcile("owner/repo", "7", REVISION,
                                   report.job_results(json.dumps(GREEN)), [], fetch=github)
        self.assertEqual(outcome, "green")
        self.assertEqual(github.writes, [])

    def test_green_run_comments_and_closes_the_lowest_matching_issue(self):
        github = FakeGitHub(issues=[{"number": 9, "title": report.TITLE},
                                    {"number": 4, "title": report.TITLE},
                                    {"number": 2, "title": report.TITLE, "pull_request": {}},
                                    {"number": 1, "title": "Unrelated ci issue"}])
        outcome = report.reconcile("owner/repo", "7", REVISION,
                                   report.job_results(json.dumps(GREEN)), [], fetch=github)
        self.assertEqual(outcome, "closed")
        self.assertEqual([(m, e) for m, e, _ in github.writes],
                         [("POST", "repos/owner/repo/issues/4/comments"),
                          ("PATCH", "repos/owner/repo/issues/4")])
        self.assertIn("green again", github.writes[0][2]["body"])
        self.assertEqual(github.writes[1][2], {"state": "closed"})

    def test_failed_run_opens_one_labelled_issue_with_bounded_content(self):
        github = FakeGitHub()
        failures = [f"keycloak/26.7.5/core / internal/controller / Test{i:03}" for i in range(60)]
        outcome = report.reconcile("owner/repo", "7", REVISION,
                                   report.job_results(json.dumps(RED)), failures, fetch=github)
        self.assertEqual(outcome, "opened")
        method, endpoint, payload = github.writes[0]
        self.assertEqual((method, endpoint), ("POST", "repos/owner/repo/issues"))
        self.assertEqual(payload["title"], report.TITLE)
        self.assertEqual(payload["labels"], [report.LABEL])
        self.assertIn("https://github.com/owner/repo/actions/runs/7", payload["body"])
        self.assertIn("Commit: " + REVISION, payload["body"])
        self.assertIn("- `checks`: failure", payload["body"])
        self.assertIn("Test049", payload["body"])
        self.assertNotIn("Test050", payload["body"])
        self.assertIn("Additional failing tests not listed: 10.", payload["body"])

    def test_failed_run_with_an_open_issue_comments_instead_of_duplicating(self):
        github = FakeGitHub(issues=[{"number": 4, "title": report.TITLE}])
        outcome = report.reconcile("owner/repo", "7", REVISION,
                                   report.job_results(json.dumps(RED)), [], fetch=github)
        self.assertEqual(outcome, "updated")
        self.assertEqual([(m, e) for m, e, _ in github.writes],
                         [("POST", "repos/owner/repo/issues/4/comments")])

    def test_markup_in_test_identities_is_escaped(self):
        github = FakeGitHub()
        report.reconcile("owner/repo", "7", REVISION, report.job_results(json.dumps(RED)),
                         ["suite / pkg / Test<img src=x>\r\nBroken"], fetch=github)
        body = github.writes[0][2]["body"]
        self.assertNotIn("<img", body)
        self.assertNotIn("\r", body)

    def test_invalid_run_identities_are_refused_before_any_fetch(self):
        github = FakeGitHub()
        for repo, run_id, revision in (("owner", "7", REVISION), ("owner/repo", "0", REVISION),
                                       ("owner/repo", "7", "HEAD"), ("o nasty/repo", "7", REVISION)):
            with self.subTest(repo=repo, run_id=run_id), self.assertRaises(ValueError):
                report.reconcile(repo, run_id, revision,
                                 report.job_results(json.dumps(GREEN)), [], fetch=github)
        self.assertEqual(github.writes, [])

    def test_truncated_issue_inventory_is_refused(self):
        github = FakeGitHub(issues=[{"number": n, "title": "x"} for n in range(1, 101)])
        with self.assertRaises(ValueError):
            report.reconcile("owner/repo", "7", REVISION,
                             report.job_results(json.dumps(RED)), [], fetch=github)


if __name__ == "__main__":
    unittest.main()

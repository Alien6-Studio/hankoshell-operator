import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location("flaky_issue", Path(__file__).with_name("flaky-issue.py"))
poster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poster)

REPO = "Alien6-Studio/hankoshell-operator"
SHA = "a" * 40


def mixed(name="TestOne"):
    return {"revision": SHA, "suite": "keycloak/26.7.5/core",
            "package": "github.com/Alien6-Studio/hankoshell-operator/internal/controller", "name": name,
            "passed_runs": ["2/attempts/1"], "failed_runs": ["1/attempts/1"]}


def report(mixed_outcomes=(), gaps=()):
    return {"schema": 1, "requested_runs": 20, "examined_runs": 20, "reports": 100,
            "gaps": list(gaps), "mixed_outcomes": list(mixed_outcomes)}


def written(directory, document):
    (directory / "flaky.json").write_text(json.dumps(document))
    return directory


class FakeGitHub:
    def __init__(self, issues=()):
        self.issues = list(issues)
        self.writes = []

    def __call__(self, endpoint, payload=None, method=None):
        if method is None:
            return self.issues
        self.writes.append((method, endpoint, payload))
        return {}


class LoadReportTests(unittest.TestCase):
    def test_valid_report_round_trips(self):
        with tempfile.TemporaryDirectory() as scratch:
            document = report([mixed()])
            self.assertEqual(poster.load_report(written(Path(scratch), document)), document)

    def test_malformed_reports_are_refused(self):
        damaged = [dict(report(), schema=2), dict(report(), mixed_outcomes="all"), dict(report(), gaps=None),
                   dict(report(), requested_runs="20"), report([dict(mixed(), revision="untrusted")]),
                   report([dict(mixed(), name="")]), report([dict(mixed(), failed_runs=[])]),
                   report([dict(mixed(), failed_runs=["../evil"])])]
        for document in damaged:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as scratch:
                with self.assertRaises(ValueError):
                    poster.load_report(written(Path(scratch), document))


class ReconcileTests(unittest.TestCase):
    def test_clean_window_without_issue_writes_nothing(self):
        github = FakeGitHub()
        self.assertEqual(poster.reconcile(REPO, "7", report(), fetch=github), "clean")
        self.assertEqual(github.writes, [])

    def test_clean_window_closes_the_existing_issue_with_a_note(self):
        github = FakeGitHub(issues=[{"number": 4, "title": poster.TITLE}])
        self.assertEqual(poster.reconcile(REPO, "7", report(), fetch=github), "closed")
        comment, patch = github.writes
        self.assertEqual(comment[0:2], ("POST", f"repos/{REPO}/issues/4/comments"))
        self.assertIn("no mixed outcome; closing.", comment[2]["body"])
        self.assertEqual(patch, ("PATCH", f"repos/{REPO}/issues/4", {"state": "closed"}))

    def test_mixed_outcomes_open_a_labelled_issue_with_bounded_escaped_body(self):
        entries = [dict(mixed(f"Test<{i}>\nX")) for i in range(60)]
        github = FakeGitHub()
        self.assertEqual(poster.reconcile(REPO, "7", report(entries, gaps=[{"reason": "expired"}]), fetch=github), "opened")
        method, endpoint, payload = github.writes[0]
        self.assertEqual((method, endpoint), ("POST", f"repos/{REPO}/issues"))
        self.assertEqual(payload["title"], poster.TITLE)
        self.assertEqual(payload["labels"], ["ci"])
        body = payload["body"]
        self.assertIn(f"https://github.com/{REPO}/actions/runs/7", body)
        self.assertIn("missing suite reports: 1.", body)
        self.assertIn("do not establish stability", body)
        self.assertIn("Test&lt;0&gt; X", body)
        self.assertIn("Additional mixed outcomes not listed: 10.", body)
        self.assertNotIn("<Test", body)
        self.assertNotIn("\r", body)

    def test_existing_issue_gets_a_comment_instead_of_a_duplicate(self):
        github = FakeGitHub(issues=[{"number": 4, "title": poster.TITLE}])
        self.assertEqual(poster.reconcile(REPO, "7", report([mixed()]), fetch=github), "updated")
        self.assertEqual(len(github.writes), 1)
        self.assertEqual(github.writes[0][0:2], ("POST", f"repos/{REPO}/issues/4/comments"))

    def test_other_titles_and_invalid_identities_are_refused_before_writes(self):
        github = FakeGitHub(issues=[{"number": 4, "title": "Scheduled qualification failed on main"}])
        self.assertEqual(poster.reconcile(REPO, "7", report([mixed()]), fetch=github), "opened")
        for repo, run in (("evil repo", "7"), (REPO, "0"), (REPO, "7; rm")):
            with self.subTest(repo=repo, run=run), self.assertRaises(ValueError):
                poster.reconcile(repo, run, report(), fetch=FakeGitHub())


class WorkflowContractTests(unittest.TestCase):
    def test_weekly_issue_job_is_the_only_writer_and_reads_this_runs_report(self):
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/test-history.yml").read_text())
        job = workflow["jobs"]["issue"]
        self.assertEqual(job["needs"], ["report"])
        self.assertEqual(job["permissions"], {"contents": "read", "issues": "write"})
        self.assertLessEqual(job["timeout-minutes"], 10)
        download = next(step for step in job["steps"] if "download-artifact" in step.get("uses", ""))
        self.assertEqual(download["with"]["name"], "go-test-history-${{ github.run_id }}-${{ github.run_attempt }}")
        poster_step = next(step for step in job["steps"] if "flaky-issue.py" in step.get("run", ""))
        self.assertEqual(poster_step["env"], {"GH_TOKEN": "${{ github.token }}"})
        self.assertNotIn("${{", poster_step["run"])
        for argument in ('--repository "$GITHUB_REPOSITORY"', '--run-id "$GITHUB_RUN_ID"',
                         '--report "$RUNNER_TEMP/go-test-history"'):
            self.assertIn(argument, poster_step["run"])


if __name__ == "__main__":
    unittest.main()

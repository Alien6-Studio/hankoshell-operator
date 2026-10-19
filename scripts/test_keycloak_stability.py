import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("stability", Path(__file__).with_name("keycloak-stability.py"))
stability = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stability)

SHA = "a" * 40
ROOT = stability.runner.STABILITY_ROOTS[0]


class StabilityTests(unittest.TestCase):
    def qualify(self, output, failure=None, skipped=False, dirty=False):
        calls = []

        def run(suite, gotestsum, attempt, root):
            calls.append(attempt)
            attempt.mkdir()
            failed = len(calls) == failure
            report = {"revision": SHA, "worktree_dirty": dirty, "returncode": int(failed), "suite_errors": 0,
                      "counts": {"passed": int(not failed), "failed": int(failed), "skipped": int(skipped)},
                      "tests": [{"name": root, "outcome": "failed" if failed else "passed"}]}
            (attempt / "results.json").write_text(json.dumps(report))
            return int(failed)

        with patch.dict(os.environ, KEYCLOAK_VERSION="26.7.5"), \
                patch.object(stability, "identity", return_value=SHA), \
                patch.object(stability.runner, "run", side_effect=run):
            code = stability.qualify(ROOT, 20, "gotestsum", output)
        return code, calls, json.loads((output / "stability.json").read_text())

    def test_twenty_separate_successes_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            code, calls, report = self.qualify(Path(directory) / "series")
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 20)
            self.assertTrue(report["complete"])
            self.assertEqual(report["revision"], SHA)

    def test_first_failure_skip_or_dirty_outcome_stops_without_retry(self):
        for failure, skipped, dirty, expected in ((3, False, False, 3), (None, True, False, 1), (None, False, True, 1)):
            with self.subTest(failure=failure, skipped=skipped, dirty=dirty), tempfile.TemporaryDirectory() as directory:
                code, calls, report = self.qualify(Path(directory) / "series", failure, skipped, dirty)
                self.assertEqual(code, 1)
                self.assertEqual(len(calls), expected)
                self.assertFalse(report["complete"])

    def test_existing_output_cannot_be_reused_to_hide_attempts(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, KEYCLOAK_VERSION="26.7.5"), \
                patch.object(stability, "identity", return_value=SHA), self.assertRaises(FileExistsError):
            stability.qualify(ROOT, 20, "gotestsum", Path(directory))

    def test_revision_change_never_completes_the_series(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, KEYCLOAK_VERSION="26.7.5"), \
                patch.object(stability, "identity", side_effect=[SHA, "b" * 40]), \
                self.assertRaisesRegex(ValueError, "Revision changed"):
            stability.qualify(ROOT, 20, "gotestsum", Path(directory) / "series")
        with patch.object(stability.subprocess, "check_output", side_effect=[SHA, "M source.go"]), \
                self.assertRaisesRegex(ValueError, "clean exact revision"):
            stability.identity()

    def test_unreviewed_target_version_or_count_is_rejected(self):
        for root, count, version in (("TestOther", 20, "26.7.5"), (ROOT, 19, "26.7.5"), (ROOT, 101, "26.7.5"), (ROOT, 20, "26.8.0")):
            with self.subTest(root=root, count=count, version=version), patch.dict(os.environ, KEYCLOAK_VERSION=version), \
                    self.assertRaises(ValueError):
                stability.qualify(root, count, "gotestsum", Path("unused"))


if __name__ == "__main__":
    unittest.main()

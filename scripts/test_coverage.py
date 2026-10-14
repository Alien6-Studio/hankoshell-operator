import copy
from decimal import Decimal
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


spec = importlib.util.spec_from_file_location("coverage_gate", Path(__file__).with_name("check-coverage.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

PROFILE = (f"mode: atomic\n{gate.MODULE}internal/a/a.go:1.1,1.2 1 1\n"
           f"{gate.MODULE}internal/b/b.go:1.1,1.2 1 1\n"
           f"{gate.MODULE}internal/b/b.go:2.1,2.2 8 0\n")
FUNCTIONS = (f"{gate.MODULE}internal/a/a.go:1:\tSmall\t100.0%\n"
             f"{gate.MODULE}internal/b/b.go:1:\tVerify\t11.1%\n"
             "total:\t(statements)\t20.0%\n")
POLICY = {"schema": 1, "global": 20, "packages": {"internal/a": 100, "internal/b": 11},
          "functions": {"internal/b/b.go:Verify": 11.1}}


def measurements(profile=PROFILE, function_text=FUNCTIONS):
    packages, files = gate.parse_profile(profile)
    functions, overall = gate.parse_functions(function_text, files, packages)
    return packages, functions, overall


class CoverageTests(unittest.TestCase):
    def test_zero_statement_package_cannot_manufacture_full_coverage(self):
        packages, functions, overall = measurements()
        packages["internal/a"] = {"covered": 0, "statements": 0}
        failures = gate.evaluate(packages, functions, overall, POLICY)
        self.assertIn("internal/a: 0.00% is below 100%", failures)

    def test_statement_weighting_does_not_average_package_or_function_percentages(self):
        packages, functions, overall = measurements()
        self.assertEqual(overall, {"covered": 2, "statements": 10})
        self.assertEqual(gate.percentage(overall), Decimal(20))
        self.assertEqual(gate.evaluate(packages, functions, overall, POLICY), [])
        policy = copy.deepcopy(POLICY)
        policy["packages"]["internal/b"] = 11.12
        failures = gate.evaluate(packages, functions, overall, policy)
        self.assertEqual(len(failures), 1)
        self.assertIn("internal/b: 11.11% is below 11.12%", failures[0])

    def test_regression_reports_global_package_and_named_security_function(self):
        profile = PROFILE.replace("b.go:1.1,1.2 1 1", "b.go:1.1,1.2 1 0")
        functions = FUNCTIONS.replace("11.1%", "0.0%").replace("20.0%", "10.0%")
        failures = gate.evaluate(*measurements(profile, functions), POLICY)
        self.assertEqual(len(failures), 3)
        for name in ("global", "internal/b:", "internal/b/b.go:Verify"):
            self.assertTrue(any(name in failure for failure in failures), name)

    def test_missing_packages_and_new_unreviewed_packages_fail(self):
        packages, functions, overall = measurements()
        del packages["internal/b"]
        packages["internal/new"] = {"covered": 1, "statements": 1}
        failures = gate.evaluate(packages, functions, overall, POLICY)
        self.assertIn("Missing package coverage: internal/b", failures)
        self.assertIn("Package needs a reviewed coverage floor: internal/new", failures)

    def test_renamed_or_ambiguous_security_function_does_not_drop_the_floor(self):
        packages, functions, overall = measurements()
        for replacement in ({"internal/b/b.go:Renamed": [Decimal(100)]},
                            {"internal/b/b.go:Verify": [Decimal(100), Decimal(100)]}):
            failures = gate.evaluate(packages, replacement, overall, POLICY)
            self.assertIn("Missing or ambiguous security function: internal/b/b.go:Verify", failures)

    def test_malformed_empty_duplicate_foreign_and_negative_profiles_fail(self):
        for invalid in ("", "mode: atomic\n", PROFILE.replace("atomic", "set"), PROFILE + PROFILE.splitlines()[1] + "\n",
                        PROFILE.replace("1 1\n", "1 -1\n"), PROFILE.replace("1.1,1.2", "2.1,1.2"),
                        PROFILE.replace("1.1,1.2", "0.1,1.2"), PROFILE.replace("1 1\n", "NaN 1\n"),
                        PROFILE.replace(gate.MODULE, "foreign/module/"), PROFILE.replace("internal/a/", "internal/../"),
                        PROFILE.replace("1.1,1.2 1 1", "1.1,1.2 0 1").replace("2.1,2.2 8 0", "2.1,2.2 0 0")):
            with self.subTest(profile=invalid[:80]), self.assertRaises(ValueError):
                gate.parse_profile(invalid)

    def test_invalid_or_inconsistent_function_reports_fail(self):
        packages, files = gate.parse_profile(PROFILE)
        for invalid in ("", FUNCTIONS.replace("20.0%", "90.0%"), FUNCTIONS + "total: (statements) 20.0%\n",
                        FUNCTIONS.replace("11.1%", "NaN%"), FUNCTIONS.replace("11.1%", "101.0%"),
                        FUNCTIONS.replace("b.go:1:", "missing.go:1:"), FUNCTIONS + FUNCTIONS.splitlines()[0] + "\n",
                        FUNCTIONS.replace(gate.MODULE, "foreign/module/")):
            with self.subTest(report=invalid[:80]), self.assertRaises(ValueError):
                gate.parse_functions(invalid, files, packages)

    def test_policy_rejects_nonfinite_boolean_out_of_range_and_unscoped_floors(self):
        for value in (True, "80", None, -1, 101, float("nan"), float("inf")):
            policy = copy.deepcopy(POLICY)
            policy["global"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.validate_policy(policy)
        for change in ({"schema": True}, {"global": 20, "unexpected": True}, {"functions": {}},
                       {"packages": {}}, {"functions": {"../outside.go:Verify": 80}},
                       {"functions": {"internal/other/x.go:Verify": 80}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.validate_policy({**POLICY, **change})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            json.loads('{"global":80,"global":0}', object_pairs_hook=gate.unique_object)

    def test_report_budget_is_checked_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile"
            path.write_text(PROFILE)
            with patch.object(gate, "MAX_REPORT", 10), self.assertRaisesRegex(ValueError, "budget"):
                gate.bounded_text(path)

    def test_make_test_clears_stale_coverage_before_success_or_failure(self):
        for exit_code in (0, 23):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reports = root / "reports with spaces"
                output = reports / "unit"
                output.mkdir(parents=True)
                names = ("coverage.out", "coverage-functions.txt", "coverage-summary.md", "coverage.json")
                for name in names:
                    (output / name).write_text("stale success")
                binary = root / "go"
                binary.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
if sys.argv[1:] == ["env", "GOVERSION"]:
    print("go1.27.2")
    sys.exit(0)
output = Path(os.environ["COVERAGE_TEST_OUTPUT"])
names = ("coverage.out", "coverage-functions.txt", "coverage-summary.md", "coverage.json")
(output.parent / "invocation.json").write_text(json.dumps({
    "args": sys.argv[1:], "stale": [name for name in names if (output / name).exists()]}))
sys.exit(int(os.environ["COVERAGE_TEST_EXIT"]))
""")
                binary.chmod(0o755)
                env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                       "COVERAGE_TEST_OUTPUT": str(output), "COVERAGE_TEST_EXIT": str(exit_code)}
                result = subprocess.run(["make", "test", "TEST_REPORT_DIR=" + str(reports)], cwd=gate.ROOT,
                                        env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, exit_code == 0, result.stderr)
                invocation = json.loads((reports / "invocation.json").read_text())
                self.assertEqual(invocation["stale"], [])
                for flag in ("test", "-race", "-count=1", "-covermode=atomic", "./...",
                             "-coverprofile=" + str(output / "coverage.out")):
                    self.assertIn(flag, invocation["args"])

    def test_cli_writes_artifacts_and_step_summary_even_when_a_floor_fails(self):
        for floor in (20, 21):
            with self.subTest(floor=floor), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "coverage.out").write_text(PROFILE)
                (root / "policy.json").write_text(json.dumps({**POLICY, "global": floor}))
                args = ["check-coverage.py", "--profile", str(root / "coverage.out"), "--policy", str(root / "policy.json")]
                with patch("sys.argv", args), patch("sys.stdout", new_callable=io.StringIO), \
                        patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "step.md")}), \
                        patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, FUNCTIONS.encode())) as run:
                    self.assertEqual(gate.main(), int(floor > 20))
                self.assertEqual(run.call_args.args[0], ["go", "tool", "cover", "-func=" + str((root / "coverage.out").resolve())])
                self.assertTrue(run.call_args.kwargs["check"])
                self.assertEqual((root / "step.md").read_text(), (root / "coverage-summary.md").read_text())
                report = json.loads((root / "coverage.json").read_text())
                self.assertEqual(bool(report["failures"]), floor > 20)
                self.assertIn("internal/b", report["packages"])
                self.assertEqual((root / "coverage-functions.txt").read_text(), FUNCTIONS)

    def test_committed_baseline_and_reviewed_security_targets(self):
        baseline = json.loads((gate.ROOT / "scripts/coverage-baseline.json").read_text())
        policy = gate.validate_policy(json.loads((gate.ROOT / "scripts/coverage-floors.json").read_text()))
        self.assertRegex(baseline["revision"], r"^[a-f0-9]{40}$")
        for field in ("profile_sha256", "functions_sha256"):
            self.assertRegex(baseline[field], r"^[a-f0-9]{64}$")
        for name, counts in baseline["packages"].items():
            self.assertAlmostEqual(float(gate.percentage(counts)), counts["percent"], places=3)
            if name in policy["packages"]:
                self.assertGreaterEqual(policy["packages"][name], max(0, counts["percent"] - 1.1))
        self.assertGreaterEqual(policy["global"], baseline["global"]["percent"] - 1.1)
        for name in ("httpsecurity", "imagevalidator", "workloadtrust", "workloadauth", "hub", "selfupdate"):
            self.assertGreaterEqual(policy["packages"]["internal/" + name], 85)
        for name, floor in policy["functions"].items():
            self.assertGreaterEqual(floor, 90, name)

    def test_source_gate_enforces_floors_and_preserves_profiles(self):
        jobs = yaml.safe_load((gate.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        steps = jobs["source"]["steps"]
        check = next(step for step in steps if "check-coverage.py" in step.get("run", ""))
        self.assertEqual(check["run"], "python3 scripts/check-coverage.py --profile .tools/test-results/unit/coverage.out")
        self.assertNotIn("if", check)
        self.assertFalse(check.get("continue-on-error", False))
        tests = next(step for step in steps if step.get("run") == "make test chart-test arch lint vuln")
        self.assertLess(steps.index(tests), steps.index(check))
        for job in ("source", "kubernetes"):
            upload = next(step for step in jobs[job]["steps"] if step.get("name") == "Preserve Go coverage")
            self.assertEqual(upload["if"], "always()")
            self.assertEqual(upload["with"]["path"], ".tools/test-results/")
        makefile = (gate.ROOT / "Makefile").read_text()
        self.assertIn("coverage: test\n\tpython3 scripts/check-coverage.py", makefile)
        self.assertIn("check: fmt-check vet test chart-test coverage", makefile)


if __name__ == "__main__":
    unittest.main()

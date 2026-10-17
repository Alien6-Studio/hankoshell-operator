import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("security_fuzz", Path(__file__).with_name("security-fuzz.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def events(action="pass", executions=10, baseline="3/3"):
    package, name = "internal/fixture", "FuzzFixture"
    rows = [{"Action": "output", "Package": gate.MODULE + package, "Test": name,
             "Output": "fuzz: elapsed: 0s, gathering baseline coverage: " + baseline + " completed\n"},
            {"Action": "output", "Package": gate.MODULE + package, "Test": name,
             "Output": "fuzz: elapsed: 1s, execs: " + str(executions) + " (10/sec), new interesting: 1 (total: 4)\n"},
            {"Action": action, "Package": gate.MODULE + package, "Test": name},
            {"Action": action, "Package": gate.MODULE + package}]
    return "\n".join(json.dumps(r) for r in rows)


class FuzzGateTests(unittest.TestCase):
    def test_only_a_completed_campaign_counts(self):
        for code, data, expected in ((0, events(), True), (1, events(), False),
                                      (0, events("skip"), False), (0, events("fail"), False),
                                      (0, events(executions=0), False), (0, events(baseline="2/3"), False),
                                      (0, "", False), (0, events().replace("FuzzFixture", "FuzzOther"), False)):
            with self.subTest(code=code, data=data):
                result = gate.outcome(code, data, "internal/fixture", "FuzzFixture")
                self.assertEqual(result["passed"], expected)
        with self.assertRaises(ValueError):
            gate.outcome(0, "compiler failure", "internal/fixture", "FuzzFixture")

    def test_campaign_cannot_use_unit_tests_or_skip_mutation(self):
        self.assertEqual(gate.command("internal/fixture", "FuzzFixture", 15),
                         ["go", "test", "-json", "-run=^$", "-fuzz=^FuzzFixture$", "-fuzztime=15s",
                          "-timeout=60s", "-parallel=2", "./internal/fixture"])

    def test_compiled_inventory_drift_fails(self):
        with patch.object(gate.subprocess, "check_output", return_value="FuzzUnreviewed\n"):
            with self.assertRaisesRegex(ValueError, "inventory drift"):
                gate.target_inventory()

    def test_reviewed_inventory_has_each_parser_family(self):
        inventory = json.loads(gate.MANIFEST.read_text())
        self.assertEqual(set(inventory), {"internal/" + p for p in (
            "adoption", "applications", "fleetplan", "httpsecurity", "hub", "imagevalidator",
            "keycloak", "workloadauth", "workloadbinding", "workloadtrust")})
        self.assertEqual(sum(map(len, inventory.values())), 20)
        for package, names in inventory.items():
            source = "\n".join(p.read_text() for p in (gate.ROOT / package).glob("*_test.go"))
            for name in names:
                self.assertIn("func " + name + "(f *testing.F)", source)

    def test_fuzz_is_required_on_full_ci_and_runs_on_development_push(self):
        for workflow in ("ci.yml", "development.yml"):
            jobs = yaml.safe_load((gate.ROOT / ".github/workflows" / workflow).read_text())["jobs"]
            job = jobs["security-fuzz"]
            self.assertNotIn("if", job)
            self.assertFalse(job.get("continue-on-error", False))
            self.assertEqual(job["needs"], ["preflight"])
            run = next(s for s in job["steps"] if s.get("run", "").startswith("make security-fuzz"))
            self.assertNotIn("if", run)
            upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
            self.assertEqual(upload["if"], "always()")
            self.assertEqual(upload["with"]["if-no-files-found"], "error")
            if workflow == "ci.yml":
                self.assertIn("security-fuzz", jobs["checks"]["needs"])
                self.assertIn("security-fuzz", jobs["schedule-report"]["needs"])
                self.assertIn('test "$FUZZ_RESULT" = success', jobs["checks"]["steps"][0]["run"])

    def test_failed_or_changed_campaign_keeps_incomplete_report(self):
        identity = {"revision": "a" * 40, "dirty": False, "sha256": "b" * 64}
        for changed, passed in ((False, True), (False, False), (True, True)):
            with self.subTest(changed=changed, passed=passed), tempfile.TemporaryDirectory() as directory:
                later = {**identity, "sha256": "c" * 64} if changed else identity
                def runner(args, output, seconds):
                    output.write_text(events("pass" if passed else "fail"))
                    return 0 if passed else 1
                with patch("sys.argv", ["security-fuzz.py", "--seconds", "1", "--output", directory]), \
                     patch.object(gate, "source_identity", side_effect=[identity, later]), \
                     patch.object(gate, "target_inventory", return_value=[("internal/fixture", "FuzzFixture")]), \
                     patch.object(gate, "run_target", side_effect=runner), patch.object(gate, "preserve_corpus"):
                    self.assertEqual(gate.main(), 0 if passed and not changed else 1)
                report = json.loads((Path(directory) / "results.json").read_text())
                self.assertEqual(report["complete"], passed and not changed)
                self.assertEqual(report["source_changed"], changed)

    def test_process_failure_still_writes_evidence(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("sys.argv", ["security-fuzz.py", "--output", directory]), \
             patch.object(gate, "source_identity", return_value={}), \
             patch.object(gate, "target_inventory", side_effect=subprocess.TimeoutExpired("go", 180)), \
             patch.object(gate, "preserve_corpus"):
            self.assertEqual(gate.main(), 1)
            report = json.loads((Path(directory) / "results.json").read_text())
            self.assertFalse(report["complete"])
            self.assertIn("TimeoutExpired", report["error"])


if __name__ == "__main__":
    unittest.main()

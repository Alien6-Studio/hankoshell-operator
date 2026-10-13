import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("go_tests", Path(__file__).with_name("go-tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class GoTestGateTests(unittest.TestCase):
    def test_shards_are_an_exhaustive_disjoint_partition(self):
        ordinary = {"TestUnit", "FuzzSeed", "ExampleContract"}
        tagged = ordinary | {"TestCore", "TestAdoption", "TestProtocol"}
        manifest = {"core": ["TestCore"], "adoption": ["TestAdoption"], "protocols": ["TestProtocol"]}
        groups = runner.partition(tagged, ordinary, manifest)
        self.assertEqual(set.union(*groups.values()), tagged)
        self.assertEqual(sum(map(len, groups.values())), len(tagged))
        self.assertTrue(ordinary <= groups["core"])
        for bad in (
            dict(manifest, other=[]),
            dict(manifest, adoption=["TestCore"]),
            dict(manifest, adoption=[]),
            dict(manifest, adoption=["TestRemoved"]),
            dict(manifest, adoption=["TestAdoption", "TestUnit"]),
            dict(manifest, adoption=["TestAdoption|TestUnexpected"]),
            dict(manifest, adoption="TestAdoption"),
        ):
            with self.subTest(manifest=bad), self.assertRaises(ValueError):
                runner.partition(tagged, ordinary, bad)
        with self.assertRaisesRegex(ValueError, "unassigned"):
            runner.partition(tagged | {"TestNew"}, ordinary, manifest)
        with self.assertRaises(ValueError):
            runner.partition(tagged - {"TestUnit"}, ordinary, manifest)

    def test_compiled_inventory_includes_examples_and_fuzz_seeds(self):
        with patch.object(runner.subprocess, "check_output", return_value="TestOne\nExampleTwo\nFuzzThree\nok package\n") as command:
            self.assertEqual(runner.test_inventory(True), {"TestOne", "ExampleTwo", "FuzzThree"})
            self.assertIn("-tags=keycloak_integration", command.call_args.args[0])
        for output in ("ok package\n", "TestOne\nTestOne\n"):
            with patch.object(runner.subprocess, "check_output", return_value=output), self.assertRaises(ValueError):
                runner.test_inventory(False)

    def junit(self, path, cases, errors=0):
        path.write_text(f'<testsuites><testsuite name="pkg" errors="{errors}">{cases}</testsuite></testsuites>')

    def test_summary_contains_outcomes_but_no_test_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.junit(output / "junit.xml", '<testcase classname="pkg" name="TestPass" time="1"/>'
                       '<testcase classname="pkg" name="TestFail/&lt;script&gt;" time="2"><failure>secret-sentinel</failure></testcase>'
                       '<testcase classname="pkg" name="TestSkip"><skipped>private-sentinel</skipped></testcase>')
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(output / "step.md")}):
                runner.write_summary(output, "keycloak/26.7.5/adoption", 1)
            result = json.loads((output / "results.json").read_text())
            self.assertEqual(result["counts"], {"passed": 1, "failed": 1, "skipped": 1})
            summary = (output / "summary.md").read_text()
            self.assertEqual(summary, (output / "step.md").read_text())
            self.assertIn("TestFail/&lt;script&gt;", summary)
            self.assertNotIn("<script>", summary)
            for text in (summary, json.dumps(result)):
                self.assertNotIn("sentinel", text)
            with self.assertRaisesRegex(ValueError, "contradicts"):
                runner.write_summary(output, "unit", 0)

    def test_successful_shard_must_report_every_selected_root(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.junit(output / "junit.xml", '<testcase classname="pkg" name="TestOne/child"/>')
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
                runner.write_summary(output, "keycloak", 0, ["TestOne"])
            for selected in ([], ["TestOne", "TestMissing"], ["TestWrong"]):
                with self.assertRaisesRegex(ValueError, "every selected"):
                    runner.write_summary(output, "keycloak", 0, selected)

    def test_malformed_or_empty_reports_never_become_success(self):
        values = ['<testsuites/>', '<testcase/>', '<testsuites><testsuite/></testsuites>',
                  '<!DOCTYPE testsuites [<!ENTITY x "expanded">]><testsuites/>']
        for content in ('<testcase name="TestOne"/>', '<testcase classname="pkg"/>',
                        '<testcase classname="pkg" name="TestOne" time="NaN"/>',
                        '<testcase classname="pkg" name="TestOne" time="-1"/>',
                        '<testcase classname="pkg" name="TestOne"/>' * 2):
            values.append('<testsuites><testsuite>' + content + '</testsuite></testsuites>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "junit.xml"
            for value in values:
                path.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    runner.parse_junit(path)

    def test_gotestsum_package_build_failure_has_a_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "junit.xml").write_text('<testsuites tests="0" failures="1" errors="1">'
                '<testsuite name="pkg" tests="0"><testcase name="TestMain" classname="">'
                '<failure>build failed</failure></testcase></testsuite></testsuites>')
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
                runner.write_summary(output, "unit", 1)
            report = json.loads((output / "results.json").read_text())
            self.assertEqual(report["counts"]["failed"], 1)
            self.assertEqual(report["suite_errors"], 1)
            self.assertIn("pkg / TestMain", (output / "summary.md").read_text())

    def test_runner_preserves_exit_status_without_retry_and_discards_old_reports(self):
        for exit_code in (0, 1, 23):
            with self.subTest(code=exit_code), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                for name in ("junit.xml", "results.json", "summary.md"):
                    (output / name).write_text("stale sentinel")

                def execute(command, **kwargs):
                    self.assertFalse((output / "results.json").exists())
                    self.assertFalse((output / "junit.xml").exists())
                    self.assertNotIn("--rerun-fails", command)
                    self.assertIn("-count=1", command)
                    self.assertIn("-race", command)
                    failure = '<failure>withheld</failure>' if exit_code else ''
                    self.junit(output / "junit.xml", '<testcase classname="pkg" name="TestOne">' + failure + '</testcase>')
                    return subprocess.CompletedProcess(command, exit_code)

                version = "gotestsum version " + runner.versions.get("tools", "gotestsum")

                def metadata(command, **kwargs):
                    if command[0] == "gotestsum":
                        return version
                    return "a" * 40 if command[1] == "rev-parse" else ""

                with patch.object(runner.subprocess, "check_output", side_effect=metadata), \
                        patch.object(runner.subprocess, "run", side_effect=execute) as run, \
                        patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
                    self.assertEqual(runner.run("unit", "gotestsum", output), exit_code)
                    self.assertEqual(run.call_count, 1)

    def test_missing_report_and_wrong_tool_pin_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for version in ("gotestsum version unknown", "gotestsum version v0.0.0"):
                with patch.object(runner.subprocess, "check_output", return_value=version), self.assertRaises(ValueError):
                    runner.run("unit", "gotestsum", output)
            version = "gotestsum version " + runner.versions.get("tools", "gotestsum")
            with patch.object(runner.subprocess, "check_output", return_value=version), \
                    patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                self.assertEqual(runner.run("unit", "gotestsum", output), 1)

    def test_workflows_preserve_all_matrices_and_upload_reports_on_failure(self):
        ci = yaml.safe_load((runner.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        keycloak = ci["keycloak"]
        self.assertEqual(set(keycloak["strategy"]["matrix"]["shard"]), set(runner.SHARDS))
        self.assertEqual(keycloak["strategy"]["matrix"]["version"], runner.versions.get("keycloak", "versions"))
        self.assertFalse(keycloak["strategy"]["fail-fast"])
        for name in ("source", "kubernetes", "keycloak"):
            job = ci[name]
            self.assertFalse(job.get("continue-on-error", False))
            upload = next(step for step in job["steps"] if step.get("name") == "Preserve Go test outcomes")
            self.assertEqual(upload["if"], "always()")
            self.assertEqual(upload["with"]["path"], ".tools/test-results/")
            self.assertTrue(upload["with"]["include-hidden-files"])
            self.assertEqual(upload["with"]["if-no-files-found"], "error")
            self.assertIn(name, ci["checks"]["needs"])
        commands = "\n".join(step.get("run", "") for step in keycloak["steps"])
        self.assertIn("KEYCLOAK_SHARD=${{ matrix.shard }}", commands)
        self.assertNotIn("--rerun-fails", commands)
        manifest = json.loads((runner.ROOT / "scripts/keycloak-shards.json").read_text())
        self.assertEqual(set(manifest), set(runner.SHARDS))


if __name__ == "__main__":
    unittest.main()

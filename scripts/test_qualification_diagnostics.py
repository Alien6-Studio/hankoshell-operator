import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("diagnostics", Path(__file__).with_name("qualification-diagnostics.py"))
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class QualificationDiagnosticsTests(unittest.TestCase):
    def test_command_output_and_runtime_are_bounded_without_partial_credentials(self):
        command = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1024)"]
        with patch.object(diagnostics, "READ_LIMIT", 128):
            self.assertIsNone(diagnostics.bounded_command(command, 2))
        command = [sys.executable, "-c", "import time; print('private-prefix', flush=True); time.sleep(10)"]
        self.assertIsNone(diagnostics.bounded_command(command, 0.05))
        command = [sys.executable, "-c", "import sys; print('private'); sys.exit(1)"]
        self.assertIsNone(diagnostics.bounded_command(command, 2))
        self.assertEqual(diagnostics.bounded_command([sys.executable, "-c", "print('public')"], 2), "public\n")

    def test_redaction_covers_structured_values_encoded_sentinels_jwts_and_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = "private-fixture-sentinel"
            collector = diagnostics.Collector(directory, [sentinel])
            encoded = base64.b64encode(sentinel.encode()).decode()
            jwt = ".".join(base64.urlsafe_b64encode(value).decode().rstrip("=")
                           for value in (b'{"alg":"RS256"}', b'{"sub":"fixture"}', b"signature-fixture"))
            value = {"metadata": {"annotations": {"private": "unknown-private-value"}},
                     "spec": {"hubToken": "another-private-value", "privateKey": "unknown-key", "sourceRef": "reader"},
                     "status": {"phase": "Scanning", "message": f"{sentinel} {encoded} {jwt}"}}
            collector.write("resource.yaml", yaml.safe_dump(collector.public_object(value)))
            collector.write("logs.txt", 'password="untracked-password" client_secret=untracked-secret Authorization: Bearer untracked-bearer\n'
                            'secret=untracked-generic privateKey=untracked-key\n'
                            '-----BEGIN ' 'PRIVATE KEY-----\nprivate-key-content\n-----END PRIVATE KEY-----\n')
            text = "".join(path.read_text() for path in Path(directory).iterdir())
            for private in (sentinel, encoded, jwt, "unknown-private-value", "another-private-value", "unknown-key",
                            "untracked-password", "untracked-secret", "untracked-bearer", "private-key-content", "untracked-generic", "untracked-key"):
                self.assertNotIn(private, text)
            resource = yaml.safe_load((Path(directory) / "resource.yaml").read_text())
            self.assertEqual(resource["status"]["phase"], "Scanning")
            self.assertEqual(resource["spec"]["sourceRef"], "reader")
            self.assertEqual(collector.public_object({"kind": "Secret", "data": {"private": "unknown"}}), {"kind": "Withheld"})

    def test_capture_keeps_status_logs_events_and_failed_wait_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "private-kubeconfig"
            config.touch()
            fixture = SimpleNamespace(args=SimpleNamespace(output=root / "system.json", kubectl="kubectl"),
                                      config=config, sensitive=["sentinel-token"], scanned_operators=[("auth", "system-operator")])
            pod = {"metadata": {"name": "system-operator-fixture", "namespace": "auth"},
                   "spec": {"containers": [{"env": [{"value": "unregistered-private-env"}]}]}, "status": {"phase": "Running"}}
            def command(args, *_positional, **_kwargs):
                if "api-resources" in args:
                    return "hankoimports.hanko.sh\nhankorealms.hanko.sh\nsecrets\n"
                if "logs" in args:
                    return "safe log sentinel-token password=unregistered-password\n"
                if "pods" in args:
                    return json.dumps({"items": [pod]})
                if "events" in args:
                    return json.dumps({"items": [{"type": "Warning", "reason": "Failed", "message": "sentinel-token"}] * 8})
                if "nodes" in args:
                    return json.dumps({"items": [{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}]})
                return json.dumps({"items": [{"kind": "HankoImport", "status": {"phase": "Scanning"}}]})
            summary = root / "summary.md"
            with patch.object(diagnostics, "bounded_command", side_effect=command) as run, patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                diagnostics.capture(fixture, diagnostics.DeadlineExceeded("inventory | <wait>", 2, 2.1))
            files = list((root / "system.diagnostics").iterdir())
            self.assertTrue(any(path.name.endswith("previous.log") for path in files))
            self.assertTrue(any(path.name == "hankoimports.hanko.sh.yaml" for path in files))
            self.assertLessEqual(sum(path.stat().st_size for path in files), diagnostics.TOTAL_LIMIT)
            for path in files:
                self.assertLessEqual(path.stat().st_size, diagnostics.FILE_LIMIT)
            text = "".join(path.read_text() for path in files) + summary.read_text()
            for private in ("sentinel-token", "unregistered-private-env", "unregistered-password"):
                self.assertNotIn(private, text)
            self.assertEqual(summary.read_text().count("| Failed |"), 5)
            self.assertEqual(summary.read_text().count("### Qualification failure"), 1)
            self.assertIn("&#124; &lt;wait&gt;", summary.read_text())
            report = json.loads((root / "system.diagnostics/failure.json").read_text())
            self.assertEqual((report["deadline_seconds"], report["elapsed_seconds"]), (2, 2.1))
            for call in run.call_args_list:
                self.assertNotIn("secrets", call.args[0])
                self.assertNotIn("configmaps", call.args[0])

    def test_file_total_and_collection_budgets_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = diagnostics.Collector(directory, [])
            collector.write("large.log", "x" * (diagnostics.FILE_LIMIT + 1))
            self.assertLessEqual((Path(directory) / "large.log").stat().st_size, diagnostics.FILE_LIMIT)
            with patch.object(diagnostics, "TOTAL_LIMIT", collector.written + 2):
                collector.write("extra.log", "too large")
                self.assertFalse((Path(directory) / "extra.log").exists())
            collector.deadline = 0
            with patch.object(diagnostics, "bounded_command") as command:
                self.assertIsNone(collector.command(["never-start"]))
                command.assert_not_called()

    def test_collection_failure_does_not_replace_original_failure(self):
        fixture = SimpleNamespace(args=SimpleNamespace(output=Path("unused")), sensitive=[])
        original = RuntimeError("private failed command")
        with patch.object(diagnostics, "Collector", side_effect=PermissionError("private diagnostic error")):
            try:
                try:
                    raise original
                except RuntimeError as error:
                    diagnostics.capture(fixture, error)
                    raise
            except RuntimeError as error:
                self.assertIs(error, original)

    def test_registry_timeout_never_serializes_failed_command_or_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            error = subprocess.TimeoutExpired(["private-command", "private-token"], 600, output="private-body")
            with patch.object(diagnostics, "bounded_command", return_value="registry ready\n") as command:
                diagnostics.capture_registry(Path(directory), "fixture", error)
            text = "".join(path.read_text() for path in Path(directory).rglob("*.*"))
            self.assertNotIn("private-", text)
            self.assertIn("600", text)
            self.assertTrue(command.call_args.kwargs["include_stderr"])

    def test_ci_failure_artifacts_are_separate_short_lived_and_nonpublishable(self):
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text())
        for name in ("workload", "system", "installed-workload", "installed-fleet", "rehearsal"):
            steps = [step for step in workflow["jobs"][name]["steps"]
                     if step.get("with", {}).get("name", "").startswith("NONPUBLISHABLE-diagnostics-")]
            self.assertEqual(len(steps), 1, name)
            self.assertEqual(steps[0]["if"], "failure()")
            self.assertEqual(steps[0]["with"]["retention-days"], 7)
            self.assertNotIn("*", steps[0]["with"]["path"])


if __name__ == "__main__":
    unittest.main()

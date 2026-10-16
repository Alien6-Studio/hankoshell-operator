import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import yaml

SPEC = importlib.util.spec_from_file_location("authentik_fixture", Path(__file__).with_name("authentik-fixture.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class AuthentikFixtureTests(unittest.TestCase):
    def test_failed_bootstrap_withholds_private_output_and_always_cleans_owned_resources(self):
        secret = "PRIVATE-fixture-output-sentinel"
        failed = SimpleNamespace(returncode=1, stdout=secret)
        with tempfile.TemporaryDirectory() as directory, patch.object(fixture.subprocess, "run", return_value=failed) as run:
            with self.assertRaises(RuntimeError) as failure:
                fixture.qualify(Path(directory), "/nonexistent/gotestsum")
        self.assertNotIn(secret, str(failure.exception))
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(calls), 4)
        network = calls[0][-1]
        self.assertTrue(network.startswith("hanko-authentik-"))
        self.assertEqual(calls[1], ["docker", "rm", "-f", "-v", network + "-server"])
        self.assertEqual(calls[2], ["docker", "rm", "-f", "-v", network + "-db"])
        self.assertEqual(calls[3], ["docker", "network", "rm", network])

    def test_real_provider_gate_is_required_and_uploads_only_bounded_test_outputs(self):
        for image in (fixture.SERVER, fixture.POSTGRES):
            self.assertRegex(image, r"^[a-z0-9./-]+@sha256:[a-f0-9]{64}$")
        jobs = yaml.safe_load((fixture.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        source = jobs["source"]
        step = next(s for s in source["steps"] if "make authentik-integration-test" in s.get("run", ""))
        self.assertNotIn("if", step)
        self.assertFalse(step.get("continue-on-error", False))
        self.assertIn("make lint LINT_BUILD_TAGS=authentik_integration", step["run"])
        artifact = next(s for s in source["steps"] if s.get("with", {}).get("name", "").startswith("go-tests-authentik-"))
        self.assertEqual(artifact["if"], "always()")
        self.assertEqual(artifact["with"]["path"], ".tools/test-results/authentik-2026.8.4/")
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")

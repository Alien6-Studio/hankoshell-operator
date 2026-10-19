import importlib.util
import json
import os
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
    def connection(self):
        return {"schemaVersion": 1, "provider": "authentik", "version": "2026.8.4", "endpoint": "", "realm": "portable", "tokenSecret": "provider-token",
                "authorizationFlow": "00000000-0000-0000-0000-000000000001", "invalidationFlow": "00000000-0000-0000-0000-000000000002",
                "signingKey": "00000000-0000-0000-0000-000000000003", "scopeMappings": ["00000000-0000-0000-0000-000000000004"]}

    def test_only_validated_public_connection_metadata_can_reach_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "connection.json"
            self.assertEqual(fixture.connection_file(path, self.connection()), path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): fixture.connection_file(path, self.connection())
            for mutation in ("password", "identifier", "provider", "boolean-version"):
                config = self.connection()
                if mutation == "password": config["password"] = "private-sentinel"
                elif mutation == "identifier": config["signingKey"] = "private-sentinel"
                elif mutation == "provider": config["provider"] = "private-sentinel"
                else: config["schemaVersion"] = True
                other = Path(directory) / (mutation + ".json")
                with self.subTest(mutation=mutation), self.assertRaises(ValueError) as failure:
                    fixture.connection_file(other, config)
                self.assertFalse(other.exists())
                self.assertNotIn("private-sentinel", str(failure.exception))

    def test_bootstrap_credentials_remain_in_child_environments_not_files_or_arguments(self):
        private_values = ["private-db-password", "private-server-key", "private-api-token", "private-denied-token"]
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs.get("env", {})))
            if command[0] == "/fixture/gotestsum":
                child = kwargs["env"]
                directory = Path(child["AUTHENTIK_FIXTURE_DIRECTORY"])
                self.assertEqual({p.name for p in directory.iterdir()}, {"connection.json"})
                stored = (directory / "connection.json").read_text()
                self.assertTrue(all(value not in stored for value in private_values))
                self.assertEqual(child["HANKO_FIXTURE_TOKEN"], private_values[2])
                self.assertEqual(child["HANKO_FIXTURE_DENIED_TOKEN"], private_values[3])
                self.assertNotIn("AUTHENTIK_POSTGRESQL__PASSWORD", child)
                self.assertNotIn("AUTHENTIK_SECRET_KEY", child)
                raise RuntimeError("StoppedAfterBootstrap")
            stdout = ""
            if command[1] == "port": stdout = "127.0.0.1:19000"
            if command[1] == "exec": stdout = "HANKO_FIXTURE_CONFIG=" + json.dumps(self.connection())
            return SimpleNamespace(returncode=0, stdout=stdout)

        response = SimpleNamespace(status=200)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True), \
                patch.object(fixture.secrets, "token_urlsafe", side_effect=private_values), \
                patch.object(fixture.urllib.request, "urlopen") as health, patch.object(fixture.subprocess, "run", side_effect=run):
            health.return_value.__enter__.return_value = response
            with self.assertRaisesRegex(RuntimeError, "StoppedAfterBootstrap"):
                fixture.qualify(Path(directory), "/fixture/gotestsum")
        for command, _ in calls:
            self.assertNotIn("--env-file", command)
            self.assertTrue(all(value not in " ".join(command) for value in private_values))
        launches = [(command, child) for command, child in calls if command[:2] == ["docker", "run"]]
        self.assertEqual(len(launches), 2)
        self.assertEqual(launches[0][1]["POSTGRES_PASSWORD"], private_values[0])
        self.assertEqual(launches[1][1]["AUTHENTIK_POSTGRESQL__PASSWORD"], private_values[0])
        self.assertEqual(launches[1][1]["AUTHENTIK_SECRET_KEY"], private_values[1])
        self.assertEqual([call[0][1] for call in calls[-3:]], ["rm", "rm", "network"])

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

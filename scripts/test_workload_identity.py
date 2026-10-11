"""Guard against credential publication and ambiguous workload subjects."""

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("workload_fixture", Path(__file__).with_name("workload-identity-probe.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class WorkloadIdentityBoundaryTests(unittest.TestCase):
    def test_no_default_implicit_or_ambiguous_subject(self):
        for namespace, name in (("workloads", "default"), ("", "worker"), ("other:name", "worker"),
                                ("workloads", ""), ("workloads", "worker:other"), ("workloads", "../worker"),
                                ("a" * 64, "worker"), ("workloads", "a" * 254)):
            with self.subTest(namespace=namespace, name=name), self.assertRaises(ValueError):
                fixture.binding_subject(namespace, name)
        self.assertNotEqual(fixture.binding_subject("workloads", "worker"), fixture.binding_subject("other", "worker"))
        self.assertEqual(fixture.binding_subject("workloads", "worker.one"), "system:serviceaccount:workloads:worker.one")

    def test_report_withholds_credentials_even_in_provider_error_fields(self):
        for credential, sensitive in (("fixture-secret-credential", ["fixture-secret-credential"]),
                                      (".".join(("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ3b3JrZXIifQ", "c2lnbmF0dXJl")), [])):
            with self.subTest(credential=credential), self.assertRaises(ValueError) as error:
                fixture.safe_report({"checks": {"denied": {"oauth_error": credential}}}, sensitive)
            self.assertNotIn(credential, str(error.exception))
        self.assertIn('"complete": false', fixture.safe_report({"complete": False, "http_status": 401}, []))

    def test_failure_and_timeout_do_not_render_commands_or_token_outputs(self):
        credential = "credential-that-must-never-appear"
        failed = subprocess.CompletedProcess(["fixture-tool", credential], 1, stdout=credential.encode(), stderr=credential.encode())
        for result in (failed, subprocess.TimeoutExpired(["fixture-tool", credential], 1, output=credential.encode())):
            with self.subTest(result=type(result).__name__), patch.object(fixture.subprocess, "run") as command:
                if isinstance(result, subprocess.TimeoutExpired):
                    command.side_effect = result
                else:
                    command.return_value = result
                with self.assertRaises(RuntimeError) as error:
                    fixture.run(["fixture-tool", credential], input=credential.encode())
                self.assertNotIn(credential, str(error.exception))


if __name__ == "__main__":
    unittest.main()

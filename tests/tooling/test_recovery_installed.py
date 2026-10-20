"""Protect actual outage duration, fail-closed observations and fixture authority."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("recovery_fixture_test", ROOT / 'tools/qualification/scenarios/recovery_installed_test.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryFixtureTests(unittest.TestCase):
    def test_outage_requires_five_minutes_of_continuous_fail_closed_observation(self):
        for scenario in ("pass", "suspended", "provider-write", "lease-renewal", "stale-ready"):
            with self.subTest(scenario=scenario):
                fixture = recovery.Recovery.__new__(recovery.Recovery)
                fixture.report, fixture.args = {}, SimpleNamespace(revision="fixture")
                clock = SimpleNamespace(now=0, fault=False, lease_reads=0)
                def control(target, rule):
                    if target == "api":
                        clock.fault = rule is not None
                        if rule:
                            self.assertEqual(rule["path"], "/api")
                            self.assertTrue(rule["path_prefix"])
                            self.assertEqual(rule["status"], 503)
                        return {"traffic": {"refused_requests": 0 if rule else 10}}
                    return {"counts": {}}
                def api(*_):
                    return {"description": "after-api-outage" if not clock.fault and clock.now else
                            "unexpected-write" if scenario == "provider-write" and clock.now else "before"}
                def get(kind, *_):
                    if kind == "lease":
                        clock.lease_reads += 1
                        return {"spec": {"renewTime": clock.lease_reads if scenario == "lease-renewal" else 1}}
                    return {"metadata": {"generation": 2}, "status": {"phase": "Ready", "observedGeneration": 2 if scenario == "stale-ready" else 1}}
                fixture.control, fixture.api, fixture.get = control, api, get
                fixture.snapshot_clients = MagicMock(return_value={"client": "identity"})
                for name in ("patch", "await_fault", "persist_progress", "kubectl", "await_leader", "await_converged"):
                    setattr(fixture, name, MagicMock())
                fixture.scraper = MagicMock()
                fixture.record = lambda name, value=True: self.assertTrue(value, name)
                with patch.object(recovery.time, "monotonic", side_effect=lambda: clock.now), \
                        patch.object(recovery.time, "sleep", side_effect=lambda seconds: setattr(clock, "now", clock.now + (80 if scenario == "suspended" else seconds))), \
                        patch.object(recovery.scale, "checkout"):
                    if scenario == "pass":
                        fixture.api_outage()
                        self.assertGreaterEqual(fixture.report["outage"]["observed_seconds"], 300)
                        self.assertGreaterEqual(fixture.report["outage"]["samples"], 29)
                        fixture.await_converged.assert_called_once_with(phase="api_outage_recovery")
                    else:
                        with self.assertRaises(ValueError):
                            fixture.api_outage()
                        fixture.await_converged.assert_not_called()
                        self.assertFalse(fixture.report["outage"]["complete"])

    def test_wrong_oci_is_refused_before_fixture_or_output_creation(self):
        args = ["recovery"]
        for key in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl", "digest", "revision"):
            args += ["--" + key, "fixture"]
        args += ["--keycloak-version", "26.8.0", "--kubernetes-version", "1.37.0"]
        with patch("sys.argv", args), patch.object(recovery.scale, "checkout"), \
                patch.object(recovery.system.publication.publish.contract.security, "verify", side_effect=ValueError("wrong scanned graph")), \
                patch.object(recovery, "Recovery") as fixture, patch.object(recovery.Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(ValueError, "wrong scanned graph"):
                recovery.main()
            fixture.assert_not_called()
            mkdir.assert_not_called()

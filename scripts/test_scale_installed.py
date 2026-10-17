"""Guard measurement integrity, bounded scenarios and exact-image authority."""
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import yaml


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


scale = module("scale_test_fixture", "scale-installed-test.py")
measure = scale.measure
proxy = module("scale_fault_proxy", "workload-fault-proxy.py")


def frame(leader=1, started=10, requests=100, reconciles=3):
    return {"leader": leader, "rss_bytes": 1000, "process_started": started, "api_requests": requests, "provider_requests": requests,
            "cpu_seconds": 1, "reconciles": {"HankoOrganization": reconciles}, "latency": {},
            "workers": {controller: 4 for kind, controller in measure.KINDS.items() if kind in measure.WORKER_KINDS},
            "active": {"hankoapplication": 3}}


class ScaleMeasurementTests(unittest.TestCase):
    def test_continuous_measurement_cannot_count_a_long_unsampled_pause(self):
        for gap in (0, 10, 45):
            self.assertEqual(measure.sampling_gap(100, 100 + gap), gap)
        for gap in (-1, 45.01, 86400, float("nan"), float("inf")):
            with self.assertRaisesRegex(ValueError, "sampling bound"):
                measure.sampling_gap(100, 100 + gap)

    def test_metrics_retain_only_numeric_allowlisted_measurements(self):
        text = '''# private-comment-sentinel
process_resident_memory_bytes 1000
process_start_time_seconds 123
rest_client_requests_total{code="200",host="private-host-sentinel",method="GET"} 10
rest_client_requests_total{code="429",host="private-host-sentinel",method="PATCH"} 2
hanko_operator_provider_requests_total{provider="keycloak",method="GET",outcome="2xx"} 30
hanko_operator_leader 1
hanko_operator_reconcile_total{kind="HankoOrganization",outcome="requeue"} 4
controller_runtime_max_concurrent_reconciles{controller="hankoapplication"} 4
controller_runtime_active_workers{controller="hankoapplication"} 3
hanko_operator_reconcile_duration_seconds_bucket{kind="HankoOrganization",le="0.5"} 19
hanko_operator_reconcile_duration_seconds_bucket{kind="HankoOrganization",le="+Inf"} 20
unreviewed_metric{token="private-token-sentinel"} 42
'''
        result = measure.metrics(text)
        self.assertEqual(result["api_requests"], 12)
        self.assertEqual(result["reconciles"], {"HankoOrganization": 4})
        self.assertEqual(result["active"]["hankoapplication"], 3)
        self.assertEqual(measure.quantile_upper_bound(result["latency"]["HankoOrganization"]), .5)
        self.assertNotIn("sentinel", json.dumps(result))
        for original, changed in ((" 1000", " NaN"), (" 1000", " -1"), (" 1000", " private-value-sentinel")):
            with self.subTest(changed=changed), self.assertRaises(ValueError) as caught:
                measure.metrics(text.replace(original, changed))
            self.assertNotIn("private-value-sentinel", str(caught.exception))
        with self.assertRaisesRegex(ValueError, "missing"):
            measure.metrics("hanko_operator_leader 1\n")
        with self.assertRaisesRegex(ValueError, "budget"):
            measure.metrics("#" * (2 * 1024**2 + 1))

    def test_histograms_do_not_invent_quantiles_without_observations_or_finite_bounds(self):
        self.assertIsNone(measure.quantile_upper_bound({"0.5": 0, "+Inf": 0}))
        self.assertIsNone(measure.quantile_upper_bound({"0.5": 1, "+Inf": 100}))
        with self.assertRaisesRegex(ValueError, "cumulative"):
            measure.quantile_upper_bound({"0.5": 95, "1": 80, "+Inf": 100})

    def test_ledger_handles_leader_replacement_but_rejects_it_inside_steady_window(self):
        ledger = measure.Ledger()
        ledger.observe({"leader": frame(), "standby": frame(leader=0, requests=2, reconciles=0)}, 4)
        checkpoint = ledger.checkpoint()
        ledger.observe({"leader": frame(requests=110, reconciles=5), "standby": frame(leader=0, requests=3, reconciles=0)}, 4)
        ledger.observe({"leader": frame(requests=120, reconciles=7), "standby": frame(leader=0, requests=4, reconciles=0)}, 4)
        report = ledger.window(checkpoint, 90, {"HankoOrganization": 2})
        self.assertEqual(report["reconciles"]["HankoOrganization"], 4)
        self.assertAlmostEqual(report["api_request_starts_per_second"], 22 / 90)
        ledger.observe({"standby": frame(requests=5, reconciles=1), "replacement": frame(leader=0, started=20, requests=1, reconciles=0)}, 4)
        with self.assertRaisesRegex(ValueError, "disappeared"):
            ledger.window(checkpoint, 90, {"HankoOrganization": 2})
        self.assertEqual(ledger.lost_processes, 1)

    def test_hot_loops_counter_resets_split_brain_and_wrong_worker_configuration_fail(self):
        for mutation in ("counter-reset", "hot-loop", "split-brain", "no-leader", "configured-workers", "active-workers"):
            with self.subTest(mutation=mutation):
                ledger = measure.Ledger()
                ledger.observe({"a": frame(), "b": frame(leader=0)}, 4)
                checkpoint = ledger.checkpoint()
                frames = {"a": frame(requests=110, reconciles=6), "b": frame(leader=0)}
                if mutation == "counter-reset":
                    frames["a"]["api_requests"] = 1
                elif mutation == "hot-loop":
                    frames["a"]["reconciles"]["HankoOrganization"] = 10000
                elif mutation == "split-brain":
                    frames["b"]["leader"] = 1
                elif mutation == "no-leader":
                    frames["a"]["leader"] = 0
                elif mutation == "configured-workers":
                    frames["a"]["workers"]["hankoapplication"] = 1
                else:
                    frames["a"]["active"]["hankoapplication"] = 9
                with self.assertRaises(ValueError):
                    ledger.observe(frames, 4)
                    ledger.observe(frames, 4)
                    ledger.window(checkpoint, 90, {"HankoOrganization": 2})


class ScaleScenarioTests(unittest.TestCase):
    def args(self, **kwargs):
        return SimpleNamespace(profile="smoke", workers=4, seconds=None, **kwargs)

    def test_soak_cannot_be_shortened_into_a_passing_24_hour_report(self):
        args = self.args()
        counts, seconds = scale.parameters(args)
        self.assertEqual(seconds, 90)
        self.assertEqual(counts["applications"], 40)
        args.profile, args.seconds = "soak", 86399
        with self.assertRaisesRegex(ValueError, "86400"):
            scale.parameters(args)
        args.seconds = 86400
        self.assertEqual(scale.parameters(args)[1], 86400)
        for workers in (0, 9):
            args.workers = workers
            with self.assertRaises(ValueError):
                scale.parameters(args)

    def test_burst_manifest_uses_managed_parents_and_complete_references(self):
        counts = {"realms": 2, "applications": 1000, "roles": 100, "organizations": 100, "grants": 20}
        objects = scale.objects(counts)
        indexed = {(obj["kind"], obj["metadata"]["name"]): obj for obj in objects}
        self.assertEqual(len(indexed), 1222)
        for obj in objects:
            self.assertEqual(obj["metadata"]["labels"]["hanko-fixture"], "scale")
            self.assertEqual(obj["metadata"]["namespace"], "auth")
            if obj["kind"] == "HankoRealm":
                self.assertNotIn("hanko.sh/imported-by", obj["metadata"]["labels"])
            else:
                self.assertIn(("HankoRealm", obj["spec"]["realmRef"]), indexed)
            if obj["kind"] == "HankoResourceServer":
                app = indexed[("HankoApplication", obj["spec"]["applicationRef"])]
                role = indexed[("HankoRole", obj["spec"]["permissions"][0]["principals"][0]["ref"])]
                self.assertEqual(app["spec"]["type"], "m2m")
                self.assertEqual(role["spec"]["realmRef"], app["spec"]["realmRef"])

    def test_public_report_omits_inputs_and_private_base_fixture_metadata(self):
        fixture = scale.Scale.__new__(scale.Scale)
        fixture.report = {"complete": False, "layer": "installed-scale", "counts": {"applications": 1000}, "password": "private",
                          "discovery": {"issuer": "private"}, "cluster_namespace_uid": "private", "native": {"secret": "private"}}
        self.assertEqual(fixture.public_evidence(), {"complete": False, "layer": "installed-scale", "counts": {"applications": 1000}})

    def test_progress_is_atomic_numeric_and_requires_complete_current_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = scale.Scale.__new__(scale.Scale)
            fixture.args = SimpleNamespace(output=Path(directory))
            fixture.report = {"complete": False, "password": "private-status-sentinel"}
            fixture.sensitive, fixture.started = ["private-status-sentinel"], time.monotonic()
            fixture.counts_by_kind = MagicMock(return_value={"HankoApplication": 2})
            ready = {"metadata": {"generation": 2, "name": "private-status-sentinel"},
                     "status": {"phase": "Ready", "observedGeneration": 2, "appliedGeneration": 2, "observationComplete": True, "driftState": "InSync"}}
            stale = copy.deepcopy(ready)
            stale["status"].update(phase="private-status-sentinel", observedGeneration=1)
            fixture.current = MagicMock(return_value=[ready, stale])
            self.assertFalse(fixture.converged())
            fixture.persist_progress()
            progress = json.loads((Path(directory) / "progress.json").read_text())
            self.assertEqual(progress["convergence_progress"]["HankoApplication"]["current"], 1)
            self.assertNotIn("private-status-sentinel", json.dumps(progress))
            self.assertFalse((Path(directory) / "progress.json.tmp").exists())
            for key, value in (("appliedGeneration", 1), ("observationComplete", False), ("driftState", "Drifted")):
                invalid = copy.deepcopy(ready)
                invalid["status"][key] = value
                fixture.current.return_value = [ready, invalid]
                self.assertFalse(fixture.converged())
            fixture.current.return_value = [ready, ready]
            self.assertTrue(fixture.converged())

    def test_phase_times_include_queueing_and_cannot_accept_late_completion(self):
        for outcome in ("pass", "timeout", "late"):
            with self.subTest(outcome=outcome):
                fixture = scale.Scale.__new__(scale.Scale)
                fixture.args = SimpleNamespace(converge_timeout=3)
                fixture.report = {}
                fixture.persist_progress = MagicMock()
                clock = SimpleNamespace(now=0)
                fixture.observe = MagicMock(side_effect=lambda: setattr(clock, "now", 4 if outcome == "late" else 2 if outcome == "pass" else clock.now))
                fixture.converged = MagicMock(return_value=outcome != "timeout")
                with patch.object(scale.time, "monotonic", side_effect=lambda: clock.now), \
                        patch.object(scale.time, "sleep", side_effect=lambda _: setattr(clock, "now", clock.now + 2)):
                    if outcome == "pass":
                        fixture.await_converged(phase="keycloak_429_recovery")
                    else:
                        with self.assertRaises(scale.system.diagnostics.DeadlineExceeded):
                            fixture.await_converged(phase="keycloak_429_recovery")
                measurement = fixture.report["convergence"]["keycloak_429_recovery"]
                self.assertEqual(measurement["complete"], outcome == "pass")
                self.assertEqual(measurement["budget_seconds"], 3)
                self.assertEqual(measurement["seconds"], 2 if outcome == "pass" else 4)
                fixture.persist_progress.assert_called_once()
                with self.assertRaisesRegex(ValueError, "fixed scale"):
                    fixture.await_converged(phase="private-input-sentinel")
                self.assertNotIn("private-input-sentinel", json.dumps(fixture.report))

    def test_startup_waits_for_reconciliation_leadership_but_refuses_split_brain_and_stale_holder(self):
        fixture = scale.Scale.__new__(scale.Scale)
        fixture.scraper = SimpleNamespace(pod_names={"a": "leader", "b": "standby"}, sample=MagicMock(side_effect=[
            {"a": frame(leader=0), "b": frame(leader=0)}, {"a": frame(), "b": frame(leader=0)}]))
        fixture.get = MagicMock(return_value={"spec": {"holderIdentity": "leader_nonce"}})
        with patch.object(scale.time, "sleep") as sleep:
            fixture.await_leader()
            sleep.assert_called_once_with(1)
        fixture.scraper.sample = MagicMock(return_value={"a": frame(), "b": frame()})
        with self.assertRaisesRegex(ValueError, "Multiple"):
            fixture.await_leader()
        fixture.scraper.sample = MagicMock(return_value={"a": frame(), "b": frame(leader=0)})
        fixture.get.return_value = {"spec": {"holderIdentity": "standby_nonce"}}
        with self.assertRaisesRegex(ValueError, "differs"):
            fixture.await_leader()

    def test_wrong_image_graph_is_refused_before_any_cluster_or_output_directory(self):
        fixture_type = MagicMock()
        args = ["scale-test"]
        for key in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl", "digest", "revision"):
            args += ["--" + key, "fixture"]
        args += ["--keycloak-version", "26.8.0", "--kubernetes-version", "1.37.0"]
        with patch.object(scale, "checkout"), patch.object(scale, "Scale", fixture_type), patch("sys.argv", args), \
                patch.object(scale.system.publication.publish.contract.security, "verify", side_effect=ValueError("wrong scanned graph")):
            with self.assertRaisesRegex(ValueError, "wrong scanned graph"):
                scale.main()
        fixture_type.assert_not_called()

    def test_manual_matrix_retains_six_cells_pinned_oci_and_failure_artifacts(self):
        workflow = yaml.safe_load((scale.ROOT / ".github/workflows/scale-qualification.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(jobs["oci"]["uses"], "./.github/workflows/oci-security.yml")
        self.assertEqual(jobs["installed-scale"]["needs"], ["preflight", "oci"])
        self.assertFalse(jobs["installed-scale"]["strategy"]["fail-fast"])
        self.assertEqual(jobs["installed-scale"]["strategy"]["matrix"], {
            "keycloak": sorted(scale.system.PINS["keycloak"]["versions"]), "kubernetes": scale.system.PINS["kubernetes"]["versions"]})
        upload = jobs["installed-scale"]["steps"][-1]
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertEqual(workflow[True]["workflow_dispatch"]["inputs"]["profile"]["options"], ["smoke", "scale"])


class ScaleFaultTests(unittest.TestCase):
    def test_actual_http_overload_has_retry_after_and_only_bounded_traffic_counts(self):
        server = proxy.FixtureServer(("127.0.0.1", 0), proxy.Proxy)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:" + str(server.server_port)
        for status in (429, 503):
            with proxy.LOCK:
                proxy.STATE.update(rule={"method": "GET", "path": "/admin/realms/", "path_prefix": True, "action": "http-status", "status": status, "retry_after": 2},
                                   triggered=False, blocked=False, traffic={})
            def request(_):
                try:
                    urlopen(Request(url + "/admin/realms/private-realm-sentinel", headers={"Authorization": "Bearer private-token-sentinel"}), timeout=5)
                    self.fail("overload unexpectedly accepted")
                except HTTPError as error:
                    self.assertEqual(error.code, status)
                    self.assertEqual(error.headers["Retry-After"], "2")
                    error.close()
            with ThreadPoolExecutor(max_workers=8) as workers:
                list(workers.map(request, range(16)))
            with proxy.LOCK:
                self.assertEqual(proxy.STATE["traffic"], {"requests": 16, "refused_requests": 16})
                self.assertNotIn("sentinel", json.dumps(proxy.STATE["traffic"]))
        with proxy.LOCK:
            proxy.STATE.update(rule=None, blocked=False, triggered=False, traffic={})


if __name__ == "__main__":
    unittest.main()

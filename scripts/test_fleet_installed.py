"""Exercise fixture authority and ensure public evidence excludes private inputs."""

import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
import threading
import subprocess
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fleet = module("installed_fleet", "fleet-installed-test.py")
hub = module("fleet_hub", "fleet-hub-fixture.py")


class FleetInstalledTests(unittest.TestCase):
    def test_command_approval_matches_the_operator_canonical_identity(self):
        target = {"tenantID": "tenant-id", "clusterID": "cluster-id", "namespace": "auth",
                  "tenantName": "tenant", "tenantUID": "tenant-uid"}
        command = {"requestedAt": "2026-10-15T12:00:00Z", "deadline": "2026-10-15T12:01:00Z"}
        # Compare with the actual Go implementation, including struct field
        # order and UTC timestamp encoding; a self-consistent fixture is not proof.
        (fleet.ROOT / ".tools").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fleet-approval-oracle-", dir=fleet.ROOT / ".tools") as directory:
            source = Path(directory) / "main.go"
            source.write_text('''package main
import ("fmt"; "time"; "github.com/Alien6-Studio/hankoshell-operator/internal/fleetplan")
func main() {
 target:=fleetplan.Target{Scope:fleetplan.Scope{TenantID:"tenant-id",ClusterID:"cluster-id",Namespace:"auth",TenantName:"tenant"},TenantUID:"tenant-uid"}
 at:=time.Date(2026,10,15,12,0,0,0,time.UTC)
 fmt.Print(fleetplan.DecommissionIdentity(target,at,at.Add(time.Minute)))
}
''')
            result = subprocess.run(["go", "run", "-mod=readonly", source], cwd=fleet.ROOT, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fleet.command_identity(target, command), result.stdout)

    def test_inspection_handles_replaced_or_malformed_cache_without_trusting_it(self):
        for raw in ('{}', 'not-json', '{"payload":7}', '{"payload":"%%%"}', '[]'):
            with self.subTest(raw=raw):
                self.assertEqual(fleet.inspected_envelope(raw), "")
        self.assertEqual(fleet.inspected_envelope(json.dumps({"payload": fleet.encoded(b"private-fixture")})), "private-fixture")

    def test_public_evidence_and_state_exclude_private_metadata(self):
        fixture = fleet.Fleet.__new__(fleet.Fleet)
        fixture.report = {"checks": {"authority": True}, "complete": False, "layer": "installed-fleet",
                          "private_key": "private", "token": "private", "provider": {"secret": "private"}}
        self.assertEqual(fixture.public_evidence(), {"checks": {"authority": True}, "complete": False, "layer": "installed-fleet"})
        obj = {"metadata": {"uid": "uid", "annotations": {"private": "withheld"}, "managedFields": ["private"]},
               "spec": {"displayName": "fixture"}, "status": {"clientSecret": "private"}}
        self.assertEqual(fleet.public_state(obj), {"uid": "uid", "spec": obj["spec"], "tenant": None})

    def test_hub_control_requires_independent_secret_and_reports_only_counts(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), hub.Hub)
        server.settings = {"control": "control-fixture-secret", "tokens": {"tenant": "tenant-fixture-secret"}, "canary": "private-person@example.invalid"}
        server.tenants = {"tenant": {"envelope": "{}", "status": 503, "ack": {"ok": True}, "fetches": 0,
                                    "reports": 0, "confirmations": 0, "reports_safe": True}}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:" + str(server.server_port)

        def request(path, token, data=None, tenant=None):
            headers = {"Authorization": "Bearer " + token}
            if tenant:
                headers["X-Tenant-ID"] = tenant
                headers["Accept"] = "application/vnd.hanko.fleet-plan+json"
            with urlopen(Request(url + path, headers=headers, data=None if data is None else json.dumps(data).encode()), timeout=5) as response:
                return json.load(response)

        with self.assertRaises(HTTPError) as refused:
            request("/__fixture/control", "tenant-fixture-secret")
        self.assertEqual(refused.exception.code, 403)
        public = request("/__fixture/control", "control-fixture-secret", {"tenant": "tenant", "envelope": "{}", "status": 200})
        self.assertNotIn("envelope", json.dumps(public))
        self.assertNotIn("fixture-secret", json.dumps(public))
        self.assertEqual(request("/api/v1/bundles/latest", "tenant-fixture-secret", tenant="tenant"), {})
        request("/__fixture/control", "control-fixture-secret", {"tenant": "tenant", "hold": True, "envelope": '{"sequence":1}'})
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request, "/api/v1/bundles/latest", "tenant-fixture-secret", None, "tenant")
            try:
                fleet.wait("held fixture response", lambda: request("/__fixture/control", "control-fixture-secret")["tenant"]["waiting"], 3)
            finally:
                request("/__fixture/control", "control-fixture-secret", {"tenant": "tenant", "hold": False, "envelope": '{"sequence":2}'})
            self.assertEqual(pending.result(timeout=3), {"sequence": 1})
        self.assertEqual(request("/api/v1/bundles/latest", "tenant-fixture-secret", tenant="tenant"), {"sequence": 2})
        request("/api/v1/operators/status", "tenant-fixture-secret", {"detail": "public"}, "tenant")
        self.assertTrue(request("/__fixture/control", "control-fixture-secret")["tenant"]["reports_safe"])
        request("/api/v1/operators/status", "tenant-fixture-secret", {"detail": "private-person@example.invalid"}, "tenant")
        self.assertFalse(request("/__fixture/control", "control-fixture-secret")["tenant"]["reports_safe"])


if __name__ == "__main__":
    unittest.main()

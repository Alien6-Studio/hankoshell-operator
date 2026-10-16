"""Disposable installed scale, overload recovery and >=24h soak qualification.

Uses an exact scanned OCI, real API server and verified HTTPS Keycloak. Reports
contain only numeric measurements, versions, hashes and fixed assertions. A
smoke/scale run never becomes 24-hour or production-HA evidence.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import signal
import ssl
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


installed = module("scale_installed_base", "workload-installed-test.py")
measure = module("scale_measure", "scale-evidence.py")
native, system, run, wait = installed.native, installed.system, installed.run, installed.wait
RESOURCE = {"HankoRealm": "hankorealms", "HankoApplication": "hankoapplications", "HankoRole": "hankoroles",
            "HankoOrganization": "hankoorganizations", "HankoResourceServer": "hankoresourceservers"}
DEFAULTS = {"smoke": (2, 40, 8, 8, 2), "scale": (10, 1000, 100, 100, 20), "soak": (10, 1000, 100, 100, 20)}
SELECTOR = "hanko-fixture=scale"


def parameters(args):
    keys = ("realms", "applications", "roles", "organizations", "grants")
    counts = dict(zip(keys, DEFAULTS[args.profile]))
    for key in keys:
        value = getattr(args, key, None)
        if value is not None:
            counts[key] = value
    if not 1 <= counts["realms"] <= 100 or any(not counts["realms"] <= counts[k] <= 2000 for k in keys[1:]) or counts["organizations"] > 1000:
        raise ValueError("Fixture counts exceed reviewed realm/object bounds")
    if counts["grants"] > counts["applications"] or not 1 <= args.workers <= 8:
        raise ValueError("Grants need distinct applications and workers must be 1..8")
    seconds = args.seconds if args.seconds is not None else (90 if args.profile == "smoke" else 300 if args.profile == "scale" else 86400)
    if not 60 <= seconds <= 604800 or args.profile == "soak" and seconds < 86400:
        raise ValueError("Soak requires at least 86400 measured seconds; short runs remain smoke/scale")
    return counts, seconds


def objects(counts):
    def value(kind, name, spec, labels=None):
        return installed.object_value(kind, name, spec, labels={"hanko-fixture": "scale", **(labels or {})})
    realms = [f"scale-{index:03d}" for index in range(counts["realms"])]
    # New leaf creation requires a managed parent. An Observe parent permits
    # only independently acquired/owned leaves, not this fresh-object burst.
    result = [value("HankoRealm", name, {}) for name in realms]
    for index in range(counts["roles"]):
        name = f"scale-role-{index:06d}"
        result.append(value("HankoRole", name, {"realmRef": realms[index % len(realms)], "name": name, "description": "scale baseline"}))
    for index in range(counts["organizations"]):
        name, root = f"scale-org-{index:06d}", index % len(realms)
        spec = {"realmRef": realms[root], "name": name, "slug": name}
        if index >= len(realms):
            spec["parentRef"] = f"scale-org-{root:06d}"
        result.append(value("HankoOrganization", name, spec))
    for index in range(counts["applications"]):
        name = f"scale-app-{index:06d}"
        result.append(value("HankoApplication", name, {"realmRef": realms[index % len(realms)], "clientID": name,
            "type": "m2m" if index < counts["grants"] else "spa", "redirectURIs": [] if index < counts["grants"] else ["https://scale.example.test/callback"]}))
    for index in range(counts["grants"]):
        realm = index % len(realms)
        result.append(value("HankoResourceServer", f"scale-grant-{index:06d}", {
            "realmRef": realms[realm], "applicationRef": f"scale-app-{index:06d}", "audience": f"urn:scale:{index}",
            "scopes": [{"name": "read"}], "resources": [{"name": "document", "scopes": ["read"]}],
            "permissions": [{"name": "readers", "scopes": ["read"], "resources": ["document"],
                             "principals": [{"kind": "realm_role", "ref": f"scale-role-{realm:06d}"}]}]}))
    return result


def checkout(revision):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, timeout=10).strip()
    if head != revision or dirty:
        raise ValueError("Scale qualification requires the exact clean source; use an isolated worktree for soak")


class Metrics:
    def __init__(self, fixture):
        self.fixture, self.forwards = fixture, {}
        self.pod_names = {}
        self.directory = fixture.private / "scale-metrics"
        self.directory.mkdir(mode=0o700)
        ca, key = self.directory / "ca.crt", self.directory / "ca.key"
        run([fixture.args.openssl, "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", key, "-out", ca, "-days", str(fixture.certificate_days), "-subj", "/CN=scale-fixture", "-addext", "basicConstraints=critical,CA:true"])
        identity = "spiffe://qualification.example/scale/observer"

        def issue(name, san, usage):
            private, cert, csr, ext = (self.directory / (name + suffix) for suffix in (".key", ".crt", ".csr", ".ext"))
            run([fixture.args.openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", private, "-out", csr, "-subj", "/CN=" + name])
            ext.write_text("subjectAltName=" + san + "\nextendedKeyUsage=" + usage + "\nkeyUsage=critical,digitalSignature\n")
            run([fixture.args.openssl, "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", key, "-CAcreateserial", "-out", cert,
                 "-days", str(fixture.certificate_days), "-extfile", ext])
            fixture.sensitive.append(private.read_text().strip())
            return cert, private

        server, server_key = issue("server", "DNS:localhost,DNS:system-operator-metrics.auth.svc", "serverAuth")
        client, client_key = issue("client", "URI:" + identity, "clientAuth")
        fixture.sensitive.append(key.read_text().strip())
        fixture.apply(fixture.secret("scale-metrics-server", {"tls.crt": server.read_text(), "tls.key": server_key.read_text()}),
                      fixture.secret("scale-metrics-ca", {"ca.crt": ca.read_text()}))
        self.context = ssl.create_default_context(cafile=str(ca))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(client, client_key)
        fixture.install_values["metrics"] = {"enabled": True,
            "tls": {"serverSecret": "scale-metrics-server", "clientCASecret": "scale-metrics-ca", "allowedClientURIs": [identity]},
            "networkPolicy": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}},
                              "podSelector": {"matchLabels": {"app.kubernetes.io/name": "prometheus"}}}}

    def close(self):
        for process, stream, _ in self.forwards.values():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stream.close()
        self.forwards.clear()

    def sample(self):
        fixture = self.fixture
        pods = json.loads(fixture.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"]
        ready = [p for p in pods if not p["metadata"].get("deletionTimestamp") and any(c.get("type") == "Ready" and c.get("status") == "True" for c in p.get("status", {}).get("conditions", []))]
        if len(ready) != 2:
            raise ValueError("A measured sample requires two Ready replicas")
        result = {}
        names = {}
        for pod in ready:
            uid, name = pod["metadata"]["uid"], pod["metadata"]["name"]
            names[uid] = name
            if uid not in self.forwards:
                log = self.directory / (name + ".log")
                stream = log.open("wb")
                process = subprocess.Popen([str(fixture.args.kubectl), "--kubeconfig", str(fixture.config), "port-forward", "-n", "auth", "pod/" + name,
                                            ":8080", "--address", "127.0.0.1"], stdout=stream, stderr=subprocess.STDOUT)
                self.forwards[uid] = (process, stream, log)
                wait("scale metrics forwarding", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()), 30)
            process, _, log = self.forwards[uid]
            port = re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]
            if process.poll() is not None:
                raise ValueError("Metrics port-forward stopped")
            request = Request("https://localhost:" + port + "/metrics", headers={"Accept": "text/plain; version=0.0.4"})
            with urlopen(request, context=self.context, timeout=10) as response:
                raw = response.read(2 * 1024**2 + 1).decode()
            if any(value and value in raw for value in fixture.sensitive):
                raise ValueError("Credential in metrics; response withheld")
            result[uid] = measure.metrics(raw)
        # A replaced pod's counters are never stitched to its successor.
        for uid in set(self.forwards) - set(result):
            process, stream, _ = self.forwards.pop(uid)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stream.close()
        self.pod_names = names
        return result


class Scale(installed.Installed):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.name = self.name.replace("workload", "scale")
        self.registry_name = self.name + "-registry"
        self.counts, self.seconds = parameters(args)
        self.certificate_days = math.ceil((self.seconds + 3600) / 86400) + 1
        self.install_values = {"replicaCount": 2, "reconciliation": {"maxConcurrent": args.workers},
            "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "2", "memory": "512Mi"}}}
        self.workload_grants = []
        self.ledger, self.scraper, self.burst = measure.Ledger(), None, None
        self.objects = objects(self.counts)
        self.report.update({"layer": "installed-scale", "profile": args.profile, "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "measurement_sha256": hashlib.sha256((ROOT / "scripts/scale-evidence.py").read_bytes()).hexdigest(), "counts": self.counts,
            "workers": args.workers, "steady_seconds_requested": self.seconds, "samples": 0, "faults": {}, "complete": False,
            "resources": self.install_values["resources"], "limitations": ["single disposable kind node and dev-file provider",
                "realms are preprovisioned and managed during load, then switched to Observe; owned realm cascade deletion unqualified",
                "counter gaps during leader replacement are lower bounds; steady phase rejects gaps",
                "worker setting covers four IAM controllers only; journaled transaction HA remains separate",
                "not a production capacity recommendation or full six-cell/24-hour qualification"]})

    def counts_by_kind(self):
        return {kind: sum(obj["kind"] == kind for obj in self.objects) for kind in RESOURCE}

    def await_leader(self):
        # Serving readiness deliberately excludes reconciliation leadership.
        # A rollout can finish before the previous holder's lease expires.
        # Wait only at these explicit startup/replacement boundaries; measured
        # windows continue to reject zero leaders immediately.
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            frames = self.scraper.sample()
            leaders = [uid for uid, frame in frames.items() if frame["leader"]]
            if len(leaders) > 1:
                raise ValueError("Multiple observed leaders during fixture startup or replacement")
            if leaders:
                holder = self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity", "").rsplit("_", 1)[0]
                if self.scraper.pod_names[leaders[0]] != holder:
                    raise ValueError("Observed metrics leader differs from the current lease holder")
                return
            time.sleep(1)
        raise ValueError("No reconciliation leader after startup or replacement budget")

    def observe(self):
        frame = self.ledger.observe(self.scraper.sample(), self.args.workers)
        frame["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        with (self.args.output / "samples.jsonl").open("a") as stream:
            stream.write(native.safe_report(frame, self.sensitive).replace("\n", "") + "\n")
        self.report["samples"] = self.ledger.frames
        return frame

    def provision(self):
        self.api("POST", "/admin/realms/master/clients", {"clientId": "system-operator", "secret": self.credential, "protocol": "openid-connect",
            "enabled": True, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False, "fullScopeAllowed": False})
        identity = self.client("master", "system-operator")
        user = self.api("GET", f'/admin/realms/master/clients/{identity["id"]}/service-account-user')
        for index in range(self.counts["realms"]):
            realm = f"scale-{index:03d}"
            self.api("POST", "/admin/realms", {"realm": realm, "enabled": True, "organizationsEnabled": True})
            proxy = self.client("master", realm + "-realm")
            roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{permission}') for permission in
                     ("view-realm", "manage-realm", "manage-clients", "manage-users", "manage-organizations", "manage-authorization", "manage-events")]
            self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
            self.api("POST", f'/admin/realms/master/clients/{identity["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        self.apply(self.secret("operator-credentials", {"client-id": "system-operator", "client-secret": self.credential}),
                   self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}))
        token = self.access_token({"client_id": "system-operator", "client_secret": self.credential, "grant_type": "client_credentials"})
        self.api("GET", "/admin/realms/master/clients", token=token, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "forbidden-scale"}, token=token, expected=(403,))
        self.record("scoped_writer_has_no_global_or_master_administration")

    def current(self, kind):
        return json.loads(self.kubectl("get", RESOURCE[kind], "-n", "auth", "-l", SELECTOR, "-o", "json"))["items"]

    def converged(self, kinds=None):
        for kind, count in self.counts_by_kind().items():
            if kinds and kind not in kinds:
                continue
            values = self.current(kind)
            if len(values) != count:
                return False
            for obj in values:
                status, generation = obj.get("status", {}), obj["metadata"]["generation"]
                if status.get("phase") != "Ready" or status.get("observedGeneration") != generation:
                    return False
                if kind in ("HankoApplication", "HankoRole", "HankoResourceServer") and (
                        status.get("appliedGeneration") != generation or status.get("observationComplete") is not True or status.get("driftState") != "InSync"):
                    return False
        return True

    def await_converged(self, kinds=None):
        deadline = time.monotonic() + self.args.converge_timeout
        while time.monotonic() < deadline:
            self.observe()
            if self.converged(kinds):
                return
            time.sleep(2)
        raise system.diagnostics.DeadlineExceeded("scale current-generation convergence", self.args.converge_timeout, self.args.converge_timeout)

    def snapshot_clients(self):
        identities = {}
        for index in range(self.counts["realms"]):
            realm, first = f"scale-{index:03d}", 0
            while True:
                page = self.api("GET", f"/admin/realms/{realm}/clients?first={first}&max=100")
                for obj in page:
                    name = obj.get("clientId", "")
                    if name.startswith("scale-app-"):
                        if name in identities or not obj.get("id"):
                            raise ValueError("Duplicate or missing native client identity")
                        identities[name] = obj["id"]
                if len(page) < 100:
                    break
                first += 100
                if first > 2200:
                    raise ValueError("Native client inventory exceeds fixture budget")
        if len(identities) != self.counts["applications"]:
            raise ValueError("Native client inventory differs from created object count")
        return identities

    def create_load(self):
        base = [o for o in self.objects if o["kind"] in ("HankoRealm", "HankoRole", "HankoOrganization")]
        self.apply(*base)
        self.await_converged({"HankoRealm", "HankoRole", "HankoOrganization"})
        old_holder = self.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"]
        leader = old_holder.rsplit("_", 1)[0]
        path = self.private / "burst.yaml"
        path.write_text(yaml.safe_dump_all(o for o in self.objects if o["kind"] == "HankoApplication"))
        self.burst_stream = path.open("rb")
        self.burst_log = (self.private / "burst.log").open("wb")
        self.burst = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "create", "-f", "-"],
                                      stdin=self.burst_stream, stdout=self.burst_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 120
        active = False
        while time.monotonic() < deadline:
            sample = self.observe()
            if len(self.current("HankoApplication")) >= min(10, self.counts["applications"]) and sample["peak_workers"].get("HankoApplication", 0) > 0:
                active = True
                break
            time.sleep(1)
        if not active:
            raise ValueError("No measured application load before leader removal")
        self.kubectl("delete", "pod", leader, "-n", "auth", "--wait=false")
        self.scraper.close()
        wait("scale leader replacement", lambda: bool(self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity")) and
             self.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"] != old_holder, 120)
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.await_leader()
        try:
            code = self.burst.wait(timeout=240)
        except subprocess.TimeoutExpired:
            raise ValueError("Resource burst did not finish within its budget") from None
        if code:
            raise ValueError("Resource burst failed; raw command output withheld")
        self.await_converged({"HankoApplication", "HankoRole", "HankoOrganization", "HankoRealm"})
        self.apply(*(o for o in self.objects if o["kind"] == "HankoResourceServer"))
        self.await_converged()
        self.report["client_ids_sha256"] = hashlib.sha256(json.dumps(self.snapshot_clients(), sort_keys=True).encode()).hexdigest()
        self.record("burst_and_leader_replacement_converge_without_duplicate_native_clients")

    def overload(self, target, status):
        before = self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")
        rule = {"method": "GET", "path": "/apis/hanko.sh/" if target == "api" else "/admin/realms/",
                "path_prefix": True, "action": "http-status", "status": status, "retry_after": 2}
        armed = self.control(target, rule)
        description = "recovered-" + target + "-" + str(status)
        self.patch("hankorole", "scale-role-000000", {"spec": {"description": description}})
        triggered = self.await_fault(target)
        time.sleep(3)
        current = self.get("hankorole", "scale-role-000000")
        self.record(target + "_" + str(status) + "_does_not_report_current_ready",
                    not (current.get("status", {}).get("phase") == "Ready" and current["status"].get("observedGeneration") == current["metadata"]["generation"]))
        if target == "api":
            self.record("api_throttle_preserves_provider_until_authority_recovers", self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")["description"] == before["description"])
        state = self.control(target, None)
        self.report["faults"][target + "_" + str(status)] = {"triggered": triggered["triggered"],
            "refused_requests": state["traffic"].get("refused_requests", 0) - armed["traffic"].get("refused_requests", 0)}
        self.await_converged()
        self.record(target + "_" + str(status) + "_recovers_without_manual_status_reset",
                    self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")["description"] == description)

    def steady(self):
        before = self.ledger.checkpoint()
        started = time.monotonic()
        self.observe()
        previous = time.monotonic()
        max_gap = measure.sampling_gap(started, previous)
        while time.monotonic() - started < self.seconds:
            time.sleep(max(0, min(10, self.seconds - (time.monotonic() - started))))
            self.observe()
            observed = time.monotonic()
            max_gap = max(max_gap, measure.sampling_gap(previous, observed))
            previous = observed
            if not self.converged():
                raise ValueError("Steady-state object lost current applied/read-back readiness")
            checkout(self.args.revision)
        elapsed = time.monotonic() - started
        max_gap = max(max_gap, measure.sampling_gap(previous, started + elapsed))
        self.report["steady"] = self.ledger.window(before, elapsed, self.counts_by_kind())
        self.report["steady"]["max_sample_gap_seconds"] = round(max_gap, 3)
        self.report["soak"] = {"required_seconds": 86400, "observed_seconds": round(elapsed, 3),
                               "qualified": self.args.profile == "soak" and elapsed >= 86400}
        self.record("steady_samples_have_no_status_echo_hot_loop_or_process_gap")

    def qualify(self):
        self.started = time.monotonic()
        self.create_cluster()
        self.mirror_scanned_image()
        self.keycloak()
        self.provider_url = "https://keycloak.auth.svc:8443"
        self.record("exact_keycloak_version", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.provision()
        self.fault_proxies()
        self.scraper = Metrics(self)
        self.install()
        self.configure_api_proxy()
        self.await_leader()
        self.create_load()
        for target, status in (("keycloak", 429), ("keycloak", 503), ("api", 429)):
            self.overload(target, status)
        self.steady()
        current = self.snapshot_clients()
        self.record("native_client_ids_preserved_after_faults_and_steady_state",
                    hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest() == self.report["client_ids_sha256"])
        traffic = self.control("keycloak", None)
        creates = sum(traffic["counts"].get(f"POST /admin/realms/scale-{index:03d}/clients", 0) for index in range(self.counts["realms"]))
        self.record("one_accepted_native_client_create_per_application", creates == self.counts["applications"])
        self.report["provider_traffic"] = {"accepted_client_creates": creates, **traffic["traffic"]}
        self.kubectl("label", "hankorealm", "scale-000", "-n", "auth", "hanko.sh/imported-by=scale-preservation")
        def observed_parent():
            parent = self.get("hankorealm", "scale-000")
            return not parent["metadata"].get("finalizers") and any(
                condition.get("type") == "Synced" and condition.get("reason") == "Observed" for condition in parent.get("status", {}).get("conditions", []))
        wait("scale parent explicitly becomes Observe before preservation deletion", observed_parent, 90)
        self.kubectl("delete", "hankorealm", "scale-000", "-n", "auth", "--wait=true", "--timeout=60s")
        self.record("observe_realm_deletion_preserves_native_dependents", self.snapshot_clients() == current)
        self.report["complete"] = True
        self.report["completed_at"] = datetime.now(timezone.utc).isoformat()

    def public_evidence(self):
        keys = ("schema_version", "layer", "profile", "revision", "image_digest", "fixture_sha256", "measurement_sha256", "keycloak_version", "kubernetes_version",
                "publishable", "complete", "started_at", "completed_at", "counts", "workers", "steady_seconds_requested", "samples", "checks", "faults", "resources",
                "limitations", "steady", "soak", "provider_traffic", "client_ids_sha256", "failure_type", "cleanup_complete")
        return {key: self.report[key] for key in keys if key in self.report}

    def cleanup(self):
        if self.scraper:
            self.scraper.close()
        if self.burst and self.burst.poll() is None:
            self.burst.terminate()
            try:
                self.burst.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.burst.kill()
                self.burst.wait(timeout=10)
        for name in ("burst_stream", "burst_log"):
            if hasattr(self, name):
                getattr(self, name).close()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=DEFAULTS, default="smoke")
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--converge-timeout", type=int, default=900)
    for name in ("realms", "applications", "roles", "organizations", "grants"):
        parser.add_argument("--" + name, type=int)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path)
    args = parser.parse_args()
    args.deep_migration = False
    parameters(args)
    if not 120 <= args.converge_timeout <= 3600:
        parser.error("Convergence budget must be 120..3600 seconds")
    checkout(args.revision)
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="hankoshell-scale-private-") as directory:
        fixture, error = Scale(args, Path(directory)), None
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        try:
            fixture.qualify()
            checkout(args.revision)
        except BaseException as caught:
            error = caught
            fixture.report.update(complete=False, failure_type=type(caught).__name__)
            if isinstance(caught, Exception):
                system.diagnostics.capture(fixture, caught)
        finally:
            try:
                fixture.cleanup()
                fixture.report["cleanup_complete"] = True
            except Exception:
                fixture.report.update(complete=False, cleanup_complete=False)
                error = error or RuntimeError("Disposable scale cleanup failed")
            (args.output / "report.json").write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
        if error:
            raise error


if __name__ == "__main__":
    main()

"""Continuous read-only in-cluster measurements; interruption never resumes a claimed 24h run."""

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tools.qualification.reporting import scale_evidence as measure
RESOURCES = {"HankoRealm": "hankorealms", "HankoApplication": "hankoapplications", "HankoRole": "hankoroles",
             "HankoOrganization": "hankoorganizations", "HankoResourceServer": "hankoresourceservers"}
SERVICE_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def atomic(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def validate(args):
    if (not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", args.namespace)
            or not args.namespace.startswith("hanko-qualification-")):
        raise ValueError("Soak observation requires a dedicated qualification namespace")
    if not re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", args.image) or not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        raise ValueError("Exact immutable candidate identity is required")
    if not 86400 <= args.seconds <= 604800 or not 5 <= args.interval <= 15:
        raise ValueError("Continuous soak needs 24h–7d and a bounded sampling interval")
    if (set(args.counts) != set(RESOURCES) or any(type(value) is not int or not 1 <= value <= 2000 for value in args.counts.values())
            or set(args.workers) != measure.WORKER_KINDS or any(type(value) is not int or not 1 <= value <= 8 for value in args.workers.values())):
        raise ValueError("Invalid declared load or concurrency profile")
    if not 60 <= args.warmup <= 7200:
        raise ValueError("Warmup budget must be explicit and bounded")
    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", args.release):
        raise ValueError("Invalid qualification release selector")
    if not re.fullmatch(r"[a-z0-9.-]+\.svc", args.metrics_hostname):
        raise ValueError("Metrics TLS hostname must name an in-cluster service")


class PodConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, context):
        self.address = str(ipaddress.ip_address(address))
        super().__init__(hostname, port=8080, timeout=5, context=context)

    def connect(self):
        connection = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


class Observer:
    def __init__(self, args):
        validate(args)
        self.args = args
        self.context = ssl.create_default_context(cafile=str(SERVICE_ACCOUNT / "ca.crt"))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ledger = measure.Ledger()
        self.requests = 0
        self.identities = None
        self.observed_seconds = 0
        self.report = {"schema_version": 1, "layer": "continuous-soak-observation", "profile": "soak",
            "complete": False, "revision": args.revision, "image": args.image, "counts": args.counts,
            "workers_by_kind": args.workers, "required_seconds": args.seconds, "samples": 0,
            "max_sample_gap_seconds": 0, "started_at": datetime.now(timezone.utc).isoformat(),
            "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "measurement_sha256": hashlib.sha256(Path(measure.__file__).read_bytes()).hexdigest(),
            "limitations": ["read-only observation of an administrator-provisioned isolated fixture",
                            "does not replace burst, transaction failover, native preservation or public predecessor tests",
                            "no Secret data, native tenant data or raw metrics retained"]}

    def read(self, component, operation):
        """Retry only idempotent reads; the unchanged 45s sample bound still applies."""
        for attempt in range(3):
            try:
                return operation()
            except (OSError, HTTPError, URLError) as error:
                cause = error.reason if isinstance(error, URLError) else error
                code = error.code if isinstance(error, HTTPError) else None
                number = getattr(cause, "errno", None)
                transient = (code in {429, 500, 502, 503, 504} if code else
                    isinstance(cause, (TimeoutError, ConnectionError)) or
                    number in {errno.ECONNRESET, errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT, socket.EAI_AGAIN})
                diagnostic = {"component": component, "exception": type(cause).__name__,
                    "attempt": attempt + 1, "at": datetime.now(timezone.utc).isoformat()}
                if code is not None:
                    diagnostic["http_status"] = code
                if type(number) is int:
                    diagnostic["errno"] = number
                errors = self.report.setdefault("transport_errors", {})
                errors[component] = errors.get(component, 0) + 1
                self.report["last_transport_error"] = diagnostic
                if not transient or attempt == 2:
                    self.report["transport_failure"] = diagnostic
                    self.persist()
                    raise
                self.report["transport_retries"] = self.report.get("transport_retries", 0) + 1
                self.persist()
                time.sleep(0.25 * (2 ** attempt))

    def api(self, path):
        def perform():
            return self.api_read(path)
        return json.loads(self.read("kubernetes", perform))

    def api_read(self, path):
        # Projected service-account credentials rotate independently of this process.
        token = (SERVICE_ACCOUNT / "token").read_text().strip()
        request = Request("https://kubernetes.default.svc" + path, headers={"Authorization": "Bearer " + token})
        self.requests += 1
        with urlopen(request, context=self.context, timeout=5) as response:
            raw = response.read(16 * 1024**2 + 1)
        if len(raw) > 16 * 1024**2:
            raise ValueError("Qualification API response exceeded its budget")
        return raw

    def items(self, group, resource, selector):
        prefix = "/api/v1" if not group else "/apis/" + group
        path = f"{prefix}/namespaces/{self.args.namespace}/{resource}"
        result, continuation, seen = [], "", set()
        while True:
            page = self.api(path + "?" + urlencode({"labelSelector": selector, "limit": 200, "continue": continuation}))
            for item in page["items"]:
                uid = item["metadata"]["uid"]
                if uid in seen:
                    raise ValueError("Duplicate object in qualification API inventory")
                seen.add(uid)
                result.append(item)
            if len(result) > 2000:
                raise ValueError("Qualification inventory exceeded its bound")
            continuation = page.get("metadata", {}).get("continue", "")
            if not continuation:
                return result

    def ready(self):
        identities, converged = [], True
        for kind, resource in RESOURCES.items():
            objects = self.items("hanko.sh/v1alpha1", resource, "hanko-fixture=scale")
            if len(objects) != self.args.counts[kind]:
                converged = False
            for obj in objects:
                metadata, status = obj["metadata"], obj.get("status", {})
                identities.append(kind + ":" + metadata["uid"])
                converged &= (not metadata.get("deletionTimestamp") and status.get("phase") == "Ready"
                              and status.get("observedGeneration") == metadata["generation"]
                              and any(c.get("type") == "Synced" and c.get("status") == "True" for c in status.get("conditions", [])))
                if kind in {"HankoApplication", "HankoRole", "HankoResourceServer"}:
                    converged &= bool(status.get("appliedPlanHash") and status.get("observationComplete") is True
                                      and status.get("appliedPlanHash") == status.get("observationPlanHash"))
        identity = hashlib.sha256("\n".join(sorted(identities)).encode()).hexdigest()
        if self.identities is not None and identity != self.identities:
            raise ValueError("Measured objects were created, removed or recreated during steady state")
        return bool(converged), identity

    def sample(self):
        pods = self.items("", "pods", "app.kubernetes.io/instance=" + self.args.release)
        pods = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp")]
        if len(pods) != 2 or any(not any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", [])) for pod in pods):
            raise ValueError("Continuous qualification requires two Ready replicas")
        context = ssl.create_default_context(cafile=str(self.args.tls / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.args.tls / "tls.crt", self.args.tls / "tls.key")
        frames, names = {}, {}
        for pod in pods:
            if any(container["image"] != self.args.image for container in pod["spec"]["containers"]):
                raise ValueError("Measured Pod image differs from the reviewed candidate")
            if pod["spec"].get("hostNetwork") or len(pod["spec"]["containers"]) != 1:
                raise ValueError("Qualification requires isolated operator Pods")
            uid = pod["metadata"]["uid"]
            def scrape():
                connection = PodConnection(self.args.metrics_hostname, pod["status"]["podIP"], context)
                try:
                    connection.request("GET", "/metrics", headers={"Accept": "text/plain; version=0.0.4"})
                    response = connection.getresponse()
                    if response.status != 200:
                        raise HTTPError("metrics", response.status, "Metrics endpoint unavailable", None, None)
                    return response.read(2 * 1024**2 + 1).decode()
                finally:
                    connection.close()
            frames[uid] = measure.metrics(self.read("metrics", scrape))
            names[uid] = pod["metadata"]["name"]
        leader = [uid for uid, frame in frames.items() if frame["leader"]]
        lease = self.api(f"/apis/coordination.k8s.io/v1/namespaces/{self.args.namespace}/leases/hanko-operator.hanko.sh")
        holder = lease.get("spec", {}).get("holderIdentity", "").rsplit("_", 1)[0]
        if len(leader) != 1 or names[leader[0]] != holder:
            raise ValueError("Observed reconciliation leader differs from the lease holder")
        return frames

    def persist(self):
        self.report.update(samples=self.ledger.frames, observed_seconds=round(self.observed_seconds, 3), observer_api_requests=self.requests)
        atomic(self.args.output / "progress.json", self.report)

    def qualify(self):
        deadline = time.monotonic() + self.args.warmup
        while True:
            ready, identity = self.ready()
            if ready:
                self.identities = identity
                break
            if time.monotonic() >= deadline:
                raise ValueError("Declared qualification cohort did not converge within warmup")
            self.persist()
            time.sleep(self.args.interval)
        self.ledger.observe(self.sample(), self.args.workers)
        before = self.ledger.checkpoint()
        started = previous = time.monotonic()
        previous_wall = time.time()
        self.report["cohort_identity_sha256"] = identity
        self.report["steady_started_at"] = datetime.now(timezone.utc).isoformat()
        while self.observed_seconds < self.args.seconds:
            time.sleep(min(self.args.interval, self.args.seconds - self.observed_seconds))
            if not self.ready()[0]:
                raise ValueError("A measured object lost current-generation readiness")
            frame = self.ledger.observe(self.sample(), self.args.workers)
            self.ledger.require_continuity(before)
            now, wall = time.monotonic(), time.time()
            gap = max(measure.sampling_gap(previous, now), measure.sampling_gap(previous_wall, wall))
            if abs((now - previous) - (wall - previous_wall)) > 5:
                raise ValueError("Clock discontinuity invalidated continuous measurement")
            self.report["max_sample_gap_seconds"] = round(max(gap, self.report["max_sample_gap_seconds"]), 3)
            previous, previous_wall = now, wall
            self.observed_seconds = now - started
            with (self.args.output / "samples.jsonl").open("a") as stream:
                stream.write(json.dumps(frame, sort_keys=True) + "\n")
            self.persist()
        self.report.update(complete=True, steady=self.ledger.window(before, self.observed_seconds, self.args.counts),
                           completed_at=datetime.now(timezone.utc).isoformat())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("namespace", "release", "image", "revision", "metrics-hostname"):
        parser.add_argument("--" + name, required=True)
    for name in ("counts", "workers"):
        parser.add_argument("--" + name, type=json.loads, required=True)
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--warmup", type=int, default=3600)
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--tls", type=Path, default=Path("/run/metrics-identity"))
    parser.add_argument("--output", type=Path, default=Path("/evidence"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "report.json").exists() or (args.output / "samples.jsonl").exists():
        raise SystemExit("Refusing to resume or overwrite a previous measurement campaign")
    observer = Observer(args)
    try:
        observer.qualify()
    except BaseException as error:
        observer.report.update(complete=False, failure_type=type(error).__name__)
        raise SystemExit("Continuous qualification interrupted; no 24-hour claim is available") from None
    finally:
        observer.persist()
        atomic(args.output / "report.json", observer.report)


if __name__ == "__main__":
    main()

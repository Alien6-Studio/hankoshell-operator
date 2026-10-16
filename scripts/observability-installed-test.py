"""Qualify operational mTLS and a bounded two-replica failover on the scanned OCI.

This disposable kind smoke test does not qualify partitions, production HA,
Prometheus Operator/Grafana or a 24-hour soak. All private data stays temporary.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_system():
    spec = importlib.util.spec_from_file_location("operational_system", ROOT / "scripts/system-test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def qualify(system):
    fixture = load_system()
    checks = []
    directory = system.private / "metrics"
    directory.mkdir(mode=0o700)

    def openssl(*args):
        fixture.run([system.args.openssl, *args])

    ca, key = directory / "ca.crt", directory / "ca.key"
    openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", key, "-out", ca, "-days", "1", "-subj", "/CN=metrics-fixture",
            "-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign")
    identity = "spiffe://monitoring.example/prometheus/platform"

    def issue(name, san, usage):
        cert, private, csr, extensions = [directory / (name + suffix) for suffix in (".crt", ".key", ".csr", ".ext")]
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", private, "-out", csr, "-subj", "/CN=" + name)
        extensions.write_text("subjectAltName=" + san + "\nextendedKeyUsage=" + usage + "\nkeyUsage=critical,digitalSignature\n")
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", key, "-CAcreateserial", "-out", cert,
                "-days", "1", "-extfile", extensions)
        return cert, private

    server, server_key = issue("server", "DNS:system-operator-metrics.auth.svc,DNS:localhost", "serverAuth")
    approved = issue("approved", "URI:" + identity, "clientAuth")
    wrong = issue("wrong", "URI:spiffe://monitoring.example/unapproved", "clientAuth")
    openssl("verify", "-CAfile", ca, "-verify_hostname", "system-operator-metrics.auth.svc", server)
    system.apply(system.secret("metrics-server", {"tls.crt": server.read_text(), "tls.key": server_key.read_text()}),
                 system.secret("metrics-client-ca", {"ca.crt": ca.read_text()}))
    original = yaml.safe_load((system.private / "values.yaml").read_text())
    values = copy.deepcopy(original)
    values.update({"replicaCount": 2, "metrics": {"enabled": True,
        "tls": {"serverSecret": "metrics-server", "clientCASecret": "metrics-client-ca", "allowedClientURIs": [identity]},
        "networkPolicy": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}},
                          "podSelector": {"matchLabels": {"app.kubernetes.io/name": "prometheus"}}}}})
    enabled = directory / "values.yaml"
    enabled.write_text(yaml.safe_dump(values))

    def upgrade(path):
        fixture.run([system.args.helm, "upgrade", "system", ROOT / "charts/hankoshell-operator", "--namespace", "auth",
                     "--kubeconfig", system.config, "--values", path, "--wait", "--timeout", "180s"])
        # Helm's availability wait can still leave Ready replicas from the old
        # ReplicaSet. They have metrics disabled and can vanish during a scrape.
        system.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
    upgrade(enabled)
    checks.append("real Helm upgrade enables mandatory mTLS on two Restricted replicas")
    system.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                  "metadata": {"name": "ops-fixture", "namespace": "auth"},
                  "spec": {"realmRef": "managed", "clientID": "native-ops-metrics-label-sentinel", "type": "m2m"}})
    fixture.wait("operational native client", lambda: system.ready("hankoapplication", "ops-fixture"))
    native = system.client("managed", "native-ops-metrics-label-sentinel")["id"]
    # Exercise the runbook's deliberately selected public jsonpath fields.
    for kind, name, path in (
        ("deployment", "system-operator", "{.spec.template.spec.containers[0].image}"),
        ("hankoapplication", "ops-fixture", '{.status.phase}{" "}{.status.observedGeneration}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{end}'),
        ("lease", "hanko-operator.hanko.sh", "{.spec.holderIdentity}"),
    ):
        if not system.kubectl("get", kind, name, "-n", "auth", "-o", "jsonpath=" + path):
            raise ValueError("Runbook public-field command returned no evidence")
    checks.append("runbook public image/status/reason/lease jsonpath commands")
    secret = system.get("secret", "hanko-app-native-ops-metrics-label-sentinel")["data"]["client_secret"]
    system.sensitive.append(base64.b64decode(secret).decode())

    def pods():
        return [pod for pod in json.loads(system.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"]
                if not pod["metadata"].get("deletionTimestamp") and any(c["type"] == "Ready" and c["status"] == "True" for c in pod.get("status", {}).get("conditions", []))]
    fixture.wait("two serving replicas", lambda: len(pods()) == 2)
    observations = []
    for pod in pods():
        name = pod["metadata"]["name"]
        with tempfile.TemporaryFile() as log:
            forward = subprocess.Popen([str(system.args.kubectl), "--kubeconfig", str(system.config), "port-forward", "-n", "auth",
                "pod/" + name, ":8080", ":8081", "--address", "127.0.0.1"], stdout=log, stderr=subprocess.STDOUT)
            def ports():
                log.seek(0)
                return dict((int(remote), int(local)) for local, remote in re.findall(rb"Forwarding from 127.0.0.1:(\d+) -> (\d+)", log.read()))
            try:
                fixture.wait("metrics/health forward", lambda: len(ports()) == 2, 30)
                bound = ports()
                metrics_url = "https://localhost:" + str(bound[8080]) + "/metrics"
                def context(client=None):
                    result = ssl.create_default_context(cafile=str(ca))
                    result.minimum_version = ssl.TLSVersion.TLSv1_3
                    if client:
                        result.load_cert_chain(str(client[0]), str(client[1]))
                    return result
                with urlopen(metrics_url, context=context(approved), timeout=5) as response:
                    metrics = response.read(2_097_153).decode()
                if len(metrics.encode()) > 2_097_152 or any(value in metrics for value in system.sensitive) or "native-ops-metrics-label-sentinel" in metrics:
                    raise ValueError("Metrics are unbounded or include private data (withheld)")
                # Establish the verified authorized listener first. Linux TLS
                # 1.3 can surface a missing-client-certificate alert as EOF in
                # urllib; require the explicit peer alert rather than treating
                # a reset/timeout/EOF as evidence of authentication refusal.
                for client in (None, wrong):
                    require_tls_authentication_refusal(system.args.openssl, metrics_url, ca, client)
                with urlopen(metrics_url, context=context(approved), timeout=5) as response:
                    if response.status != 200:
                        raise ValueError("Authorized metrics listener did not survive refusal probes")
                active = bool(re.search(r"^hanko_operator_leader 1(?:\.0)?$", metrics, re.M))
                if active:
                    fixture.wait("complete leader inventory", lambda: scrape_complete(metrics_url, context(approved)), 60)
                    if 'hanko_operator_reconcile_total{kind="HankoApplication"' not in metrics or "hanko_operator_provider_requests_total" not in metrics:
                        raise ValueError("Registered controller/provider instrumentation is absent")
                def status(path):
                    try:
                        with urlopen("http://127.0.0.1:" + str(bound[8081]) + path, timeout=10) as response:
                            return response.status
                    except HTTPError as error:
                        return error.code
                if status("/healthz") != 200 or status("/readyz/serving") != 200 or status("/readyz?exclude=leader") != 200:
                    raise ValueError("A healthy standby is not serving-ready")
                if (status("/readyz") == 200) != active:
                    raise ValueError("Reconciliation readiness differs from leadership")
                observations.append({"pod": name, "leader": active})
            finally:
                forward.terminate()
                try:
                    forward.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    forward.kill()
                    forward.wait(timeout=10)
    if sum(item["leader"] for item in observations) != 1:
        raise ValueError("Exactly one running replica must hold leadership")
    checks += ["authorized certificate scrapes; anonymous and unapproved URI denied on every replica",
               "actual metrics contain no credential or native client-ID sentinel",
               "registered reconcile/provider outcomes and complete bounded leader inventory",
               "liveness/serving remain healthy on standby; full readiness requires leadership"]
    leader = next(item["pod"] for item in observations if item["leader"])
    old_holder = system.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"]
    if not old_holder.startswith(leader + "_"):
        raise ValueError("Metric leader does not match the Kubernetes lease")
    system.kubectl("delete", "pod", leader, "-n", "auth", "--wait=true", "--timeout=60s")
    fixture.wait("new lease holder", lambda: system.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity", old_holder) != old_holder, 120)
    fixture.wait("replica recovery", lambda: len(pods()) == 2)
    if system.client("managed", "native-ops-metrics-label-sentinel")["id"] != native or system.get("secret", "hanko-app-native-ops-metrics-label-sentinel")["data"]["client_secret"] != secret:
        raise ValueError("Leader removal duplicated a native client or changed its credential")
    checks.append("leader removal acquires a new lease without duplicate native client or credential rotation")
    evidence = system.kubectl("logs", "deployment/system-operator", "-n", "auth", "--all-pods=true") + system.kubectl("get", "events", "-n", "auth", "-o", "json")
    for crd in json.loads(system.kubectl("get", "crds", "-o", "json"))["items"]:
        if crd["spec"]["group"] == "hanko.sh":
            evidence += system.kubectl("get", crd["metadata"]["name"], "-n", "auth", "-o", "json")
    if any(value in evidence for value in system.sensitive) or re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", evidence):
        raise ValueError("Credential in logs/Events/CRDs (withheld)")
    checks.append("credential sentinel scan of logs, Events and all Hanko CRDs")
    system.kubectl("delete", "hankoapplication", "ops-fixture", "-n", "auth", "--wait=true", "--timeout=120s")
    upgrade(system.private / "values.yaml")
    deployment = system.get("deployment", "system-operator")
    if "--metrics-bind-address=0" not in deployment["spec"]["template"]["spec"]["containers"][0]["args"]:
        raise ValueError("Reviewed configuration rollback left metrics enabled")
    checks.append("real Helm configuration rollback disables metrics and returns to one replica")
    return checks


def scrape_complete(url, context):
    with urlopen(url, context=context, timeout=5) as response:
        return bool(re.search(rb"^hanko_operator_inventory_complete 1(?:\.0)?$", response.read(2_097_153), re.M))


def require_authentication_refusal(error):
    """A broken forward/listener is not evidence that authentication refused us."""
    if isinstance(error, HTTPError) and error.code in (401, 403):
        return
    cause = error.reason if isinstance(error, URLError) else error
    if isinstance(cause, ssl.SSLError):
        return
    raise ValueError("Metrics authentication check failed at transport, not authorization") from None


def require_tls_authentication_refusal(openssl, url, ca, client=None):
    address = urlsplit(url)
    if address.scheme != "https" or address.hostname != "localhost" or not address.port:
        raise ValueError("TLS fixture probe must target its local forward")
    command = [str(openssl), "s_client", "-connect", "localhost:" + str(address.port), "-servername", "localhost",
               "-CAfile", str(ca), "-verify_return_error", "-verify_hostname", "localhost", "-tls1_3", "-quiet"]
    if client:
        command += ["-cert", str(client[0]), "-key", str(client[1])]
    try:
        result = subprocess.run(command, input=b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                                capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("TLS authentication probe failed at transport") from None
    # Transcript/session data stays private. Only explicit remote certificate
    # alerts qualify; local trust failures and generic EOF/reset never do.
    error = result.stderr.decode(errors="replace").lower()
    if (result.returncode == 0 or "certificate verify failed" in error or "hostname mismatch" in error
            or not re.search(r"alert (?:certificate required|bad certificate|access denied|unknown ca)\b", error)):
        raise ValueError("TLS authentication probe did not observe an explicit peer certificate refusal")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    fixture = load_system()
    fixture.publication.publish.contract.security.verify(args.evidence, args.revision, fixture.VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hanko-observability-") as directory:
        system = fixture.System(args, Path(directory))
        try:
            system.create_cluster()
            system.keycloak()
            system.install()
            checks = qualify(system)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps({"result": "pass", "scope": "installed operational smoke; not production HA",
                "revision": args.revision, "image_digest": args.digest, "kubernetes": fixture.KUBERNETES_VERSION,
                "keycloak": fixture.KEYCLOAK_VERSION, "checks": checks,
                "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "system_harness_sha256": hashlib.sha256((ROOT / "scripts/system-test.py").read_bytes()).hexdigest()}, indent=2) + "\n")
        finally:
            system.cleanup()


if __name__ == "__main__":
    main()

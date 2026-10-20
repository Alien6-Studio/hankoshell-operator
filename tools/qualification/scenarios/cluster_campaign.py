"""Seed an isolated provider, exercise a real leader loss, then observe 24 hours.

Runs inside the qualification namespace with its own provider and scoped RBAC.
The PVC keeps incomplete results; a failed process never resumes an interval.
"""

import argparse
import hashlib
import json
from pathlib import Path
import ssl
import time
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from tools.qualification.scenarios import soak_observer as observer


class Campaign(observer.Observer):
    def __init__(self, args):
        super().__init__(args)
        self.config = json.loads(args.config.read_text())
        self.provider_context = ssl.create_default_context(cafile=str(args.provider / "ca.crt"))
        self.provider_token, self.provider_token_at = "", 0
        self.report.update(layer="isolated-cluster-scale-soak", phase="provider_setup", ha={})
        self.report["limitations"] += [
            "one Kubernetes/Keycloak cell; no public predecessor compatibility claim",
            "leader loss under application burst only; transaction checkpoint and clock-skew matrix remain separate",
        ]

    def request(self, method, path, value=None):
        if not path.startswith(("/api/v1/namespaces/" + self.args.namespace + "/",
                                "/apis/hanko.sh/v1alpha1/namespaces/" + self.args.namespace + "/",
                                "/apis/coordination.k8s.io/v1/namespaces/" + self.args.namespace + "/")):
            raise ValueError("Campaign request escaped its qualification namespace")
        token = (observer.SERVICE_ACCOUNT / "token").read_text().strip()
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        data = None if value is None else json.dumps(value).encode()
        request = Request("https://kubernetes.default.svc" + path, data=data, headers=headers, method=method)
        with urlopen(request, context=self.context, timeout=15) as response:
            raw = response.read(16 * 1024**2 + 1)
        if len(raw) > 16 * 1024**2:
            raise ValueError("Campaign response exceeded its bound")
        return json.loads(raw) if raw else None

    def provider(self, method, path, value=None):
        if time.monotonic() - self.provider_token_at > 30 or not self.provider_token:
            fields = {"client_id": "admin-cli", "grant_type": "password",
                      "username": "qualification-admin", "password": (self.args.provider / "password").read_text()}
            request = Request(self.config["provider"] + "/realms/master/protocol/openid-connect/token",
                              data=urlencode(fields).encode())
            with urlopen(request, context=self.provider_context, timeout=15) as response:
                self.provider_token = json.load(response)["access_token"]
            self.provider_token_at = time.monotonic()
        headers = {"Authorization": "Bearer " + self.provider_token, "Content-Type": "application/json"}
        request = Request(self.config["provider"] + path, method=method, headers=headers,
                          data=None if value is None else json.dumps(value).encode())
        with urlopen(request, context=self.provider_context, timeout=15) as response:
            raw = response.read(4 * 1024**2 + 1)
        if len(raw) > 4 * 1024**2:
            raise ValueError("Provider response exceeded its bound")
        return json.loads(raw) if raw else None

    def seed(self):
        def available():
            try:
                return self.provider("GET", "/admin/realms/master").get("realm") == "master"
            except (URLError, TimeoutError):
                return False
        self.wait_for(available, 600)
        objects = self.config["objects"]
        if not 1 <= len(objects) <= 5000 or any(
                obj["metadata"]["namespace"] != self.args.namespace or
                obj["metadata"].get("labels", {}).get("hanko-fixture") != "scale" or
                obj["kind"] not in observer.RESOURCES for obj in objects):
            raise ValueError("Invalid isolated qualification corpus")
        client = {"clientId": "system-operator", "secret": (self.args.provider / "operator-secret").read_text(),
                  "protocol": "openid-connect", "enabled": True, "publicClient": False,
                  "serviceAccountsEnabled": True, "standardFlowEnabled": False, "fullScopeAllowed": False}
        self.provider("POST", "/admin/realms/master/clients", client)
        clients = self.provider("GET", "/admin/realms/master/clients?clientId=system-operator")
        if len(clients) != 1:
            raise ValueError("Ambiguous isolated operator client")
        identity = clients[0]["id"]
        user = self.provider("GET", f"/admin/realms/master/clients/{identity}/service-account-user")["id"]
        for obj in objects:
            if obj["kind"] != "HankoRealm":
                continue
            realm = obj["metadata"]["name"]
            self.provider("POST", "/admin/realms", {"realm": realm, "enabled": True, "organizationsEnabled": True})
            proxies = self.provider("GET", "/admin/realms/master/clients?clientId=" + realm + "-realm")
            if len(proxies) != 1:
                raise ValueError("Ambiguous target realm authority")
            proxy = proxies[0]["id"]
            roles = [self.provider("GET", f"/admin/realms/master/clients/{proxy}/roles/{permission}") for permission in
                     ("view-realm", "manage-realm", "manage-clients", "manage-users", "manage-organizations",
                      "manage-authorization", "manage-events")]
            self.provider("POST", f"/admin/realms/master/users/{user}/role-mappings/clients/{proxy}", roles)
            self.provider("POST", f"/admin/realms/master/clients/{identity}/scope-mappings/clients/{proxy}", roles)

    def submit(self, kinds):
        for obj in self.config["objects"]:
            if obj["kind"] in kinds:
                self.request("POST", f"/apis/hanko.sh/v1alpha1/namespaces/{self.args.namespace}/" + observer.RESOURCES[obj["kind"]], obj)

    def converged(self, kinds):
        counts = {}
        ready = True
        for kind in kinds:
            values = self.items("hanko.sh/v1alpha1", observer.RESOURCES[kind], "hanko-fixture=scale")
            current = sum(current_ready(obj) for obj in values)
            counts[kind] = {"expected": self.args.counts[kind], "count": len(values), "current": current}
            ready &= len(values) == self.args.counts[kind] == current
        self.report["convergence"] = counts
        return ready

    def wait_for(self, predicate, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            self.persist()
            time.sleep(5)
        raise TimeoutError("Isolated qualification phase exceeded its recorded budget")

    def lose_leader(self):
        path = f"/apis/coordination.k8s.io/v1/namespaces/{self.args.namespace}/leases/hanko-operator.hanko.sh"
        before = self.request("GET", path)["spec"]["holderIdentity"]
        pod_name = before.rsplit("_", 1)[0]
        pod_path = f"/api/v1/namespaces/{self.args.namespace}/pods/" + pod_name
        pod = self.request("GET", pod_path)
        labels = pod["metadata"].get("labels", {})
        if labels.get("app.kubernetes.io/instance") != self.args.release:
            raise ValueError("Leader is outside the isolated candidate release")
        frames = self.sample()
        if not any(frame["leader"] and frame["active"].get("hankoapplication", 0) > 0 for frame in frames.values()):
            raise ValueError("Leader loss must occur during real application reconciliation")
        started = time.monotonic()
        self.request("DELETE", pod_path, {"apiVersion": "v1", "kind": "DeleteOptions",
                     "preconditions": {"uid": pod["metadata"]["uid"]}})
        def changed():
            holder = self.request("GET", path)["spec"].get("holderIdentity")
            if not holder or holder == before:
                return False
            try:
                return sum(frame["leader"] for frame in self.sample().values()) == 1
            except ValueError:
                return False
        self.wait_for(changed, 120)
        self.report["ha"]["application_burst_leader_loss"] = {"complete": True,
            "new_holder": True, "two_ready_replicas": True, "seconds": round(time.monotonic() - started, 3)}

    def native_clients(self):
        found = {}
        for obj in self.config["objects"]:
            if obj["kind"] != "HankoRealm":
                continue
            realm, first = obj["metadata"]["name"], 0
            while True:
                page = self.provider("GET", f"/admin/realms/{realm}/clients?first={first}&max=100")
                for client in page:
                    if client.get("clientId", "").startswith("scale-app-"):
                        name = client["clientId"]
                        if name in found or not client.get("id"):
                            raise ValueError("Duplicate or missing native application identity")
                        found[name] = client["id"]
                if len(page) < 100:
                    break
                first += len(page)
                if first > 3000:
                    raise ValueError("Unbounded native client inventory")
        if len(found) != self.args.counts["HankoApplication"]:
            raise ValueError("Native application count differs from the corpus")
        return hashlib.sha256(json.dumps(found, sort_keys=True).encode()).hexdigest()

    def qualify(self):
        self.seed()
        initial = {"HankoRealm", "HankoRole", "HankoOrganization"}
        self.report["phase"] = "initial_dependencies"
        self.submit(initial)
        self.wait_for(lambda: self.converged(initial), 900)
        self.report["phase"] = "applications_after_leader_loss"
        self.submit({"HankoApplication"})
        self.lose_leader()
        self.wait_for(lambda: self.converged({"HankoApplication"}), 900)
        self.report["native_client_identity_sha256"] = self.native_clients()
        self.report["phase"] = "authorization_graph"
        self.submit({"HankoResourceServer"})
        self.wait_for(lambda: self.converged(set(observer.RESOURCES)), 900)
        self.report["phase"] = "continuous_soak"
        self.persist()
        super().qualify()
        if self.native_clients() != self.report["native_client_identity_sha256"]:
            raise ValueError("Native application identity changed during endurance")
        self.report["phase"] = "complete"


def current_ready(obj):
    status, generation = obj.get("status", {}), obj["metadata"]["generation"]
    ready = (status.get("phase") == "Ready" and status.get("observedGeneration") == generation and
             any(c.get("type") == "Synced" and c.get("status") == "True" for c in status.get("conditions", [])))
    if obj["kind"] in {"HankoApplication", "HankoRole", "HankoResourceServer"}:
        ready &= (status.get("appliedGeneration") == generation and status.get("observationComplete") is True and
                  status.get("appliedPlanHash") == status.get("observationPlanHash") and bool(status.get("appliedPlanHash")))
    return bool(ready)


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
    parser.add_argument("--provider", type=Path, default=Path("/run/provider"))
    parser.add_argument("--config", type=Path, default=Path("/qualification/config.json"))
    parser.add_argument("--output", type=Path, default=Path("/evidence"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        raise SystemExit("A campaign requires a new empty evidence directory")
    campaign = Campaign(args)
    try:
        campaign.qualify()
    except BaseException as error:
        campaign.report.update(complete=False, failure_type=type(error).__name__)
        raise SystemExit("Qualification failed; incomplete evidence retained") from None
    finally:
        campaign.persist()
        observer.atomic(args.output / "report.json", campaign.report)


if __name__ == "__main__":
    main()

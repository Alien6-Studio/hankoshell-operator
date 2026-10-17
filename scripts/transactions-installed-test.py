"""Replace the actual leader at six accepted transaction checkpoints.

The disposable external proxies lose acknowledgements only after successful
upstream writes. Reports contain fixed assertions and counts, never credentials,
native representations, receipts or plan payloads. This is selected development
HA evidence, not split-brain, every-journal or production qualification.
"""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fleet = module("transactions_fleet", "fleet-installed-test.py")
scale = module("transactions_scale", "scale-installed-test.py")
installed, native, system, wait = fleet.installed, fleet.native, fleet.system, fleet.wait
ROTATION = "hanko.sh/sa-secret-rotation"
TENANT = {"hanko.sh/tenant": "tenant-a"}
CHECKPOINTS = ("native_rotation", "secret_output", "rotation_commit", "client_acquisition", "role_acquisition", "verified_plan")


def ready_current(value):
    generation = value["metadata"]["generation"]
    status = value.get("status", {})
    return status.get("phase") == "Ready" and status.get("observedGeneration") == generation and any(
        c.get("type") == "Synced" and c.get("status") == "True" for c in status.get("conditions", []))


def native_semantics(value):
    value = copy.deepcopy(value)
    for key in ("access", "secret"):
        value.pop(key, None)
    attributes = value.get("attributes", {})
    for key in ("hanko.sh/client-owner-kind", "hanko.sh/client-owner-uid", "hanko.sh/role-owner", "hanko.sh/adoption-receipt"):
        attributes.pop(key, None)
    if not attributes:
        value.pop("attributes", None)
    return value


def rotation_recovered(value, journal):
    current = json.loads(value["metadata"].get("annotations", {}).get(ROTATION, "{}"))
    # metav1.Time status uses whole RFC3339 seconds; the durable journal keeps
    # nanoseconds. Compare at status precision without allowing a later rotation.
    at = datetime.fromisoformat(journal["rotatedAt"].replace("Z", "+00:00"))
    return (ready_current(value) and current.get("step") == "Committed" and current.get("requestID") == journal["requestID"]
            and value.get("status", {}).get("lastRotated") == fleet.timestamp(at))


class Transactions(fleet.Fleet):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.name = self.name.replace("workload", "transactions")
        self.registry_name = self.name + "-registry"
        self.certificate_days = 1
        self.scraper = None
        self.install_values = {"replicaCount": 2, "reconciliation": {"maxConcurrent": 4},
            "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "2", "memory": "512Mi"}},
            "fleetPlanVerification": {"trustConfigMap": "fleet-trust"},
            "hub": {"enabled": True, "caSecret": "hub-ca", "selector": {"app": "hanko-hub"}}}
        self.report.update(layer="installed-transactions", complete=False,
            fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), checkpoints={},
            limitations=["single disposable kind node and dev-file provider", "six selected accepted-write checkpoints",
                "26.7.5 reader profile can read native credentials; provider-level credential-read separation not qualified",
                "not delegation apply, every journal, stale-lease split brain, replica clock skew or production HA"])

    def replace_leader(self):
        holder = self.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"]
        pod = holder.rsplit("_", 1)[0]
        self.stop_log_capture()
        # Wait for this exact process to disappear before releasing either
        # proxy. A Deployment restart or scaling to zero cannot qualify this.
        self.kubectl("delete", "pod", pod, "-n", "auth", "--wait=true", "--timeout=90s")
        self.control("api", None)
        self.control("keycloak", None)
        self.scraper.close()
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        scale.Scale.await_leader(self)
        current = self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity")
        if not current or current == holder:
            raise ValueError("Transaction recovery did not replace the lease holder")
        self.start_log_capture()

    def checkpoint(self, name, **counts):
        if name not in CHECKPOINTS or name in self.report["checkpoints"]:
            raise ValueError("Unexpected or repeated transaction checkpoint")
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("Checkpoint evidence requires nonnegative numeric counts")
        self.report["checkpoints"][name] = {"complete": True, "leader_replaced": True, **counts}
        self.record(name + "_recovers_after_actual_leader_replacement")

    def rotation(self, boundary):
        name = "rotate-" + boundary.replace("_", "-")
        self.apply(installed.object_value("HankoServiceAccount", name, {"realmRef": "managed", "clientID": name,
            "secretRotationPolicy": {"enabled": False}}, labels=TENANT))
        wait("initial rotation client", lambda: ready_current(self.get("hankoserviceaccount", name)), 180)
        before = self.get("hankoserviceaccount", name)
        secret = self.get("secret", "hanko-sa-" + name)
        old = self.secret_value(name)
        uuid = self.client("managed", name)["id"]
        path = "/admin/realms/managed/clients/" + uuid + "/client-secret"
        secret_path = "/api/v1/namespaces/auth/secrets/hanko-sa-" + name
        root_path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankoserviceaccounts/" + name
        self.control("api", None, reset=True)
        self.control("keycloak", None, reset=True)
        target, rule = ("keycloak", {"method": "POST", "path": path}) if boundary == "native_rotation" else (
            "api", {"method": "PATCH", "path": secret_path} if boundary == "secret_output" else
            {"method": "PATCH", "path": root_path, "annotation": ROTATION, "step": "Committed"})
        self.control(target, {**rule, "action": "lost-ack"})
        force = fleet.timestamp(datetime.now(timezone.utc) + timedelta(seconds=2))
        self.patch("hankoserviceaccount", name, {"spec": {"secretRotationPolicy": {
            "enabled": True, "intervalDays": 30, "forceRotateAt": force}}})
        fault = self.await_fault(target)
        if fault["upstream_status"] != 200:
            raise ValueError("Rotation checkpoint was not an accepted upstream write")
        stalled = self.get("hankoserviceaccount", name)
        journal = json.loads(stalled["metadata"].get("annotations", {}).get(ROTATION, "{}"))
        if journal.get("attempted") is not True or journal.get("step") != ("Committed" if boundary == "rotation_commit" else "Prepared"):
            raise ValueError("Rotation stalled at another journal boundary")
        if stalled.get("status", {}).get("lastRotated") != before["status"].get("lastRotated"):
            raise ValueError("Rotation status advanced past the held checkpoint")
        current = self.secret_value(name)
        if (current == old) != (boundary == "native_rotation") or self.native_secret(name) == old:
            raise ValueError("Rotation checkpoint did not preserve the expected credential boundary")
        self.replace_leader()
        wait("committed rotation recovery", lambda: rotation_recovered(self.get("hankoserviceaccount", name), journal), 180)
        state = self.control("keycloak", None)
        api_state = self.control("api", None)
        output = self.get("secret", "hanko-sa-" + name)
        if (state["counts"].get("POST " + path) != 1 or state["attempted_counts"].get("POST " + path) != 1
                or api_state["counts"].get("PATCH " + secret_path) != 1 or output["metadata"]["uid"] != secret["metadata"]["uid"]
                or self.secret_value(name) == old or self.secret_value(name) != self.native_secret(name)
                or self.client("managed", name)["id"] != uuid):
            raise ValueError("Rotation repeated a native operation, replaced output, or lost physical identity")
        self.checkpoint(boundary, accepted_rotations=1, attempted_rotations=1, accepted_secret_patches=1)

    def acquisition_reader(self):
        credential = self.adoption_identity("ha-reader", "managed", ["view-realm", "view-clients"])
        token = self.access_token({"client_id": "ha-reader", "client_secret": credential, "grant_type": "client_credentials"})
        self.reader_token = token
        self.sensitive.append(token)
        self.apply(self.secret("ha-reader", {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
            "HANKO_KC_CLIENT_ID": "ha-reader", "HANKO_KC_CLIENT_SECRET": credential}),
            installed.object_value("HankoKeycloakInstance", "ha-reader", {"mode": "external", "adminRef": {"name": "ha-reader"},
                "tlsCARef": "operator-ca"}, labels=TENANT))

    def inspect_reader_permissions(self, path, before, credential):
        self.api("PUT", path, before, token=self.reader_token, expected=(403,))
        # These are measured pinned-provider behaviours, not interchangeable
        # successful authorization outcomes. 26.7.5's view-clients profile can
        # read credentials; do not claim provider-level separation on that cell.
        expected = {"26.7.5": 200, "26.8.0": 403}[self.args.keycloak_version]
        response = self.api("GET", path + "/client-secret", token=self.reader_token, expected=(expected,))
        if expected == 200 and response.get("value") != credential:
            raise ValueError("Reader credential response did not prove the observed provider permission")
        self.report["reader_profile"] = {"credential_read_http_status": expected,
            "provider_credential_read_separation": expected == 403, "native_client_writes_refused": True}
        self.record("inventory_reader_native_client_writes_refused")

    def acquisition(self, kind):
        role = kind == "HankoRole"
        name = "ha-acquire-role" if role else "ha-acquire-client"
        base = "/admin/realms/managed"
        if role:
            self.api("POST", base + "/roles", {"name": name, "description": "Reviewed leaf", "attributes": {"locale": ["fr"]}})
            path = base + "/roles/" + name
            spec = {"realmRef": "managed", "name": name, "description": "Reviewed leaf", "mode": "Observe"}
        else:
            self.api("POST", base + "/clients", {"clientId": name, "name": name, "protocol": "openid-connect", "enabled": True,
                "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                "fullScopeAllowed": False, "frontchannelLogout": True, "redirectUris": [], "webOrigins": [], "attributes": {"locale": "en"},
                "defaultClientScopes": [], "optionalClientScopes": []})
            path = base + "/clients/" + self.client("managed", name)["id"]
            for scope in self.api("GET", path + "/default-client-scopes"):
                self.api("DELETE", path + "/default-client-scopes/" + scope["id"])
            credential = self.native_secret(name)
            spec = {"realmRef": "managed", "clientID": name, "mode": "Observe"}
        before = self.api("GET", path)
        if not role:
            self.inspect_reader_permissions(path, before, credential)
        self.control("keycloak", None, reset=True)
        self.apply(installed.object_value(kind, name, spec, labels=TENANT, annotations={"hanko.sh/adoption-source": "ha-reader"}))
        resource = "hankorole" if role else "hankoserviceaccount"
        wait("reviewable acquisition candidate", lambda: self.get(resource, name).get("status", {}).get("adoptionCandidate", {}).get("approvable") is True, 180)
        target = self.get(resource, name)
        candidate = target["status"]["adoptionCandidate"]["candidateHash"]
        self.control("keycloak", {"method": "PUT", "path": path, "action": "lost-ack"})
        self.patch(resource, name, {"metadata": {"annotations": {"hanko.sh/adoption-contract": "hanko.sh/adoption-contract/v1alpha1",
            "hanko.sh/adoption-candidate": candidate}}})
        fault = self.await_fault("keycloak")
        if fault["upstream_status"] != 204:
            raise ValueError("Acquisition checkpoint was not an accepted provider PUT")
        self.replace_leader()
        wait("receipt recovery after leader loss", lambda: self.get(resource, name).get("status", {}).get("adoptionReceipt", {}).get("state") == "Verified", 180)
        state = self.control("keycloak", None)
        after, acquired = self.api("GET", path), self.get(resource, name)
        raw = after.get("attributes", {}).get("hanko.sh/adoption-receipt")
        receipt = json.loads(raw[0] if role else raw)
        expected = {"contractVersion": "hanko.sh/adoption-contract/v1alpha1", "targetKind": kind,
                    "targetUID": target["metadata"]["uid"], "candidateHash": candidate}
        if (receipt != expected or native_semantics(after) != native_semantics(before) or acquired["metadata"].get("finalizers")
                or acquired.get("status", {}).get("secretRef") or state["counts"].get("PUT " + path) != 1
                or state["attempted_counts"].get("PUT " + path) != 1
                or state.get("traffic", {}).get("credential_read_requests", 0) != 0):
            raise ValueError("Acquisition replayed, changed semantics or acquired unapproved authority")
        secrets = json.loads(self.kubectl("get", "secrets", "-n", "auth", "-o", "json"))["items"]
        if any(ref.get("uid") == target["metadata"]["uid"] for secret in secrets for ref in secret["metadata"].get("ownerReferences", [])):
            raise ValueError("Observe acquisition projected credentials")
        if not role and self.native_secret(name) != credential:
            raise ValueError("Client acquisition rotated its existing credential")
        self.checkpoint("role_acquisition" if role else "client_acquisition", accepted_receipt_writes=1,
            attempted_receipt_writes=1, credential_read_requests=0)

    def verified_plan(self):
        candidate = self.plan("tenant-a", 2, "After HA checkpoint")
        candidate["content"]["apps"].append(installed.object_value("HankoApplication", "ha-checkpoint-app",
            {"realmRef": "managed", "clientID": "ha-checkpoint-app", "type": "spa"}, labels=TENANT))
        identity = self.identity(candidate)
        path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankotenants/tenant-a/status"
        self.control("keycloak", None, reset=True)
        self.control("api", {"method": "PATCH", "path": path, "action": "lost-ack",
            "json_path": ["status", "fleetPlan", "identity"], "equals": identity}, reset=True)
        self.hub("tenant-a", envelope=self.sign(candidate), status=200)
        self.tick("tenant-a")
        fault = self.await_fault("api")
        checkpoint = self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]
        if (fault["upstream_status"] != 200 or checkpoint["identity"] != identity or checkpoint.get("appliedIdentity") == identity
                or self.exists("hankoapplication", "ha-checkpoint-app")):
            raise ValueError("Plan verification checkpoint was not durable before child creation")
        self.replace_leader()
        self.publish("tenant-a", candidate)
        self.converged("tenant-a", "After HA checkpoint")
        wait("recovered HA plan child", lambda: ready_current(self.get("hankoapplication", "ha-checkpoint-app")), 180)
        state = self.control("keycloak", None)
        api_state = self.control("api", None)
        counts = {"candidate_native_clients": len(self.api("GET", "/admin/realms/managed/clients?clientId=ha-checkpoint-app")),
                  "accepted_native_creates": state["counts"].get("POST /admin/realms/managed/clients", 0),
                  "accepted_child_creates": api_state.get("traffic", {}).get("kubernetes_application_creates", 0)}
        self.report["plan_counts"] = counts
        if any(value != 1 for value in counts.values()):
            raise ValueError("Verified plan resumed with duplicate native or Kubernetes children")
        self.checkpoint("verified_plan", accepted_native_creates=1, accepted_child_creates=1)

    def qualify(self):
        self.create_cluster()
        self.mirror_scanned_image()
        self.keycloak()
        self.record("exact_keycloak_version", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.provider_url = "https://keycloak.auth.svc:8443"
        self.identities()
        self.signing_keys()
        self.start_hub()
        self.fault_proxies()
        self.scraper = scale.Metrics(self)
        self.install()
        self.configure_api_proxy()
        scale.Scale.await_leader(self)
        self.setup_tenants()
        for name in self.hub_token:
            self.publish(name, self.plan(name, 1))
            self.converged(name, "Fleet baseline")
        other = self.client("managed-b", "tenant-b-app")["id"]
        for boundary in CHECKPOINTS[:3]:
            self.rotation(boundary)
        self.acquisition_reader()
        for kind in ("HankoServiceAccount", "HankoRole"):
            self.acquisition(kind)
        self.verified_plan()
        self.record("other_tenant_physical_identity_preserved", self.client("managed-b", "tenant-b-app")["id"] == other)
        self.leak_scan()
        if set(self.report["checkpoints"]) != set(CHECKPOINTS):
            raise ValueError("Transaction checkpoint inventory is incomplete")
        self.report.update(complete=True, completed_at=datetime.now(timezone.utc).isoformat())

    def public_evidence(self):
        return {**super().public_evidence(), **{key: self.report[key] for key in ("checkpoints", "limitations", "cleanup_complete", "reader_profile", "plan_counts") if key in self.report}}

    def cleanup(self):
        if self.scraper:
            self.scraper.close()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    args = parser.parse_args()
    args.deep_migration, args.node_archive = False, None
    scale.checkout(args.revision)
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise ValueError("Transaction evidence output must be fresh")
    with tempfile.TemporaryDirectory(prefix="hankoshell-transactions-private-") as directory:
        fixture, error = Transactions(args, Path(directory)), None
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        try:
            fixture.qualify()
            scale.checkout(args.revision)
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
                error = error or RuntimeError("Disposable transaction cleanup failed")
            args.output.write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
        if error:
            raise error


if __name__ == "__main__":
    main()

"""Upgrade and roll back authentic public 0.x artifacts in a disposable kind cluster.

The captured predecessor objects and signed published chart are inputs, never
synthesized from the candidate. No public predecessor means no compatibility pass.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import tempfile

import yaml

from tools.qualification.scenarios import system_test as system
from tools.release import public_release_verify as authentic
from tools.qualification.lib.sensitive_write_probe import probe as sensitive_write_probe

ROOT = Path(__file__).resolve().parents[3]
run, wait = system.run, system.wait


def fingerprint(value):
    # Preserve list order: normalization must never hide a changed historical spec.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def predecessor(capture, reviewed, proof):
    if (proof.get("verified") is not True or proof.get("published") is not True
            or not re.fullmatch(r"0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", capture.get("source_release", ""))
            or reviewed.get("state") != "reviewed-public-predecessor" or reviewed.get("published") is not True
            or capture.get("state") != "captured-for-review" or capture.get("published") is not False
            or reviewed.get("captured_sha256") != hashlib.sha256(capture.raw).hexdigest()):
        raise ValueError("A reviewed authentic installed predecessor corpus is required")
    for field, proof_field in (("source_release", "version"), ("revision", "revision"), ("image", "image")):
        if capture.get(field) != reviewed.get(field) or capture.get(field) != proof.get(proof_field):
            raise ValueError("Corpus and authenticated release identities differ")
    if proof.get("fixture_sha256") != hashlib.sha256(capture.raw).hexdigest():
        raise ValueError("Actual installed artifact does not bind the captured objects")
    fixtures = capture.get("fixtures", [])
    if (not 1 <= len(fixtures) <= 64 or not set(capture.get("schemas", {})) == {obj.get("kind") for obj in fixtures}
            or not set(capture.get("schemas", {})) <= {"HankoApplication", "HankoRole", "HankoResourceServer"}):
        raise ValueError("Historical fixture inventory is incomplete or unsupported")
    seen = set()
    for obj in fixtures:
        metadata = obj.get("metadata", {})
        key = obj.get("kind"), metadata.get("name")
        if (key in seen or metadata.get("namespace") != "auth" or not str(metadata.get("name", "")).startswith("public-")
                or obj.get("apiVersion") not in ("hanko.sh/v1alpha1", "hanko.sh/v1beta1")
                or obj.get("status", {}).get("phase") != "Ready" or not isinstance(obj.get("spec"), dict)):
            raise ValueError("Historical fixture scope or applied state is invalid")
        seen.add(key)
    pending, ordered = list(fixtures), []
    while pending:
        progressed = False
        for obj in list(pending):
            spec = obj["spec"]
            dependencies = set(spec.get("composites", []) + spec.get("realmRoleScopes", [])) if obj["kind"] in ("HankoRole", "HankoApplication") else set()
            blocked = any(other is not obj and (other["kind"] == "HankoRole" and other["spec"].get("name") in dependencies
                or other["kind"] == "HankoApplication" and other["metadata"]["name"] == spec.get("applicationRef")) for other in pending)
            if not blocked:
                ordered.append(obj)
                pending.remove(obj)
                progressed = True
        if not progressed:
            raise ValueError("Historical fixture dependency cycle")
    return ordered


class Capture(dict):
    def __init__(self, path):
        self.raw = path.read_bytes()
        if path.is_symlink() or len(self.raw) > 512 * 1024:
            raise ValueError("Invalid captured predecessor")
        super().__init__(json.loads(self.raw))


class HistoricalSystem(system.System):
    def install(self):
        service = self.get("service", "kubernetes", "default")["spec"]["clusterIP"]
        endpoints = self.get("endpoints", "kubernetes", "default")["subsets"][0]["addresses"]
        values = {"fullnameOverride": "system-operator", "image": {"repository": self.registry + "/hankoshell-operator", "digest": self.args.digest},
                  "resources": {"limits": {"cpu": "1", "memory": "256Mi"}},
                  "keycloak": {"url": "https://keycloak.auth.svc:8443", "credentialsSecret": "operator-credentials", "caSecret": "operator-ca"},
                  "networkPolicy": {"kubernetesAPIServiceCIDRs": [service + "/32"],
                                    "kubernetesAPIEndpointCIDRs": [item["ip"] + "/32" for item in endpoints]}}
        if getattr(self, "workload_grants", None):
            values["workloadBinding"] = {"grants": self.workload_grants}
        values.update(getattr(self, "install_values", {}))
        values["sensitiveWrites"] = {kind: sorted(set(values.get("sensitiveWrites", {}).get(kind, [])) | names)
                                    for kind, names in self.sensitive_write_names.items()} | {"projections": values.get("sensitiveWrites", {}).get("projections", [])}
        file = self.private / "values.yaml"
        file.write_text(yaml.safe_dump(values))
        run([self.args.helm, "install", "system", self.chart_path, "--namespace", "auth",
             "--kubeconfig", self.config, "--values", file, "--wait", "--timeout", "180s"])
        self.sensitive_write_values = file
        pod = json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"][0]
        container = pod["spec"]["containers"][0]
        if container["image"] != self.registry + "/hankoshell-operator@" + self.args.digest:
            raise ValueError("Installed image is not the scanned graph")
        self.sensitive_write_checks = sensitive_write_probe(self)
        if hasattr(self, "record"):
            for label, passed in self.sensitive_write_checks.items():
                self.record("sensitive_writes_" + label, passed)
        if (pod["spec"]["securityContext"]["runAsNonRoot"] is not True or container["securityContext"]["readOnlyRootFilesystem"] is not True
                or (("--metrics-bind-address=0" in container["args"]) != (not values.get("metrics", {}).get("enabled", False)))):
            raise ValueError("Installed chart hardening/metrics contract differs")
        for namespace, expected in (("auth", "yes"), ("other", "no")):
            result = self.kubectl("auth", "can-i", "get", "secrets", "-n", namespace, "--as", "system:serviceaccount:auth:system-operator") if expected == "yes" else subprocess.run(
                [str(self.args.kubectl), "--kubeconfig", str(self.config), "auth", "can-i", "get", "secrets", "-n", namespace,
                 "--as", "system:serviceaccount:auth:system-operator"], capture_output=True, timeout=30).stdout.decode().strip()
            if result != expected:
                raise ValueError("Operator Kubernetes namespace boundary differs")

    def adoption_operator(self, namespace, realm, reader_roles, writer_roles, lifecycle_enabled=False, sensitive_secrets=()):
        writer, reader = namespace + "-writer", namespace + "-reader"
        writer_secret = self.adoption_identity(writer, realm, writer_roles)
        reader_secret = self.adoption_identity(reader, realm, reader_roles)
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}}},
            self.secret("operator-credentials", {"client-id": writer, "client-secret": writer_secret}, namespace),
            self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}, namespace),
            self.secret("inventory-credentials", {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
                "HANKO_KC_CLIENT_ID": reader, "HANKO_KC_CLIENT_SECRET": reader_secret}, namespace))
        values = yaml.safe_load((self.private / "values.yaml").read_text())
        values["fullnameOverride"] = namespace + "-operator"
        values["lifecycle"] = {"enabled": lifecycle_enabled, "adminGroups": []}
        values["sensitiveWrites"] = {"secrets": list(sensitive_secrets), "deployments": [], "projections": []}
        values["networkPolicy"]["keycloakNamespace"] = "auth"
        config = self.private / (namespace + "-values.yaml")
        config.write_text(yaml.safe_dump(values))
        run([self.args.helm, "install", namespace, self.chart_path, "--namespace", namespace,
             "--kubeconfig", self.config, "--values", config, "--wait", "--timeout", "180s"])
        self.scanned_operators.append((namespace, namespace + "-operator"))
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {
            "name": realm, "namespace": namespace, "labels": {"hanko.sh/imported-by": "external"}}, "spec": {}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": "source", "namespace": namespace},
             "spec": {"mode": "external", "adminRef": {"name": "inventory-credentials"}, "tlsCARef": "operator-ca"}})
        wait("installed external realm observation", lambda: self.ready("hankorealm", realm, namespace) and not self.get("hankorealm", realm, namespace)["metadata"].get("finalizers"))

    def retain_upgrade_adoption(self):
        """Leave an explicitly adopted client alive for actual later upgrade tests."""
        realm, namespace, client_id = "upgrade-adoption-target", "upgrade-adoption", "public-upgrade-adopted"
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True})
        self.adoption_operator(namespace, realm, ["view-realm", "view-clients"],
            ["view-realm", "manage-clients"], sensitive_secrets=("hanko-app-" + client_id,))
        credential = secrets.token_hex(32)
        self.sensitive.append(credential)
        base = "/admin/realms/" + realm
        self.api("POST", base + "/clients", {"clientId": client_id, "secret": credential,
            "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "frontchannelLogout": True, "defaultClientScopes": [], "optionalClientScopes": [], "attributes": {"locale": "en"}})
        before = self.client(realm, client_id)
        for scope in self.api("GET", base + "/clients/" + before["id"] + "/default-client-scopes"):
            self.api("DELETE", base + "/clients/" + before["id"] + "/default-client-scopes/" + scope["id"])
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
            "metadata": {"name": "retained", "namespace": namespace, "annotations": {"hanko.sh/adoption-source": "source"}},
            "spec": {"realmRef": realm, "clientID": client_id, "type": "m2m", "mode": "Observe"}})
        receipt = self.approve_aggregate("hankoapplication", "retained", namespace)
        self.aggregate_manage("hankoapplication", "retained", namespace)
        if self.client(realm, client_id)["id"] != before["id"]:
            raise ValueError("Retained adopted client was replaced")
        return receipt

    def refresh_sensitive_grants(self, values):
        """Replay the predecessor's own chart grants, never candidate RBAC."""
        self.sensitive_write_values.write_text(yaml.safe_dump(values))
        manifest = system.run([self.args.helm, "template", "system", self.chart_path, "--namespace", "auth",
            "--kube-version", self.args.kubernetes_version, "--values", self.sensitive_write_values])
        grants = [doc for doc in yaml.safe_load_all(manifest) if doc and
            (doc["kind"] in ("Role", "RoleBinding") and doc["metadata"]["name"] in ("system-operator", "system-operator-sensitive-projections") or
             doc["kind"] == "ValidatingAdmissionPolicy" and "-sensitive-" in doc["metadata"]["name"])]
        if not any(doc["kind"] == "Role" and doc["metadata"]["name"] == "system-operator" for doc in grants) or sum(doc["kind"] == "ValidatingAdmissionPolicy" for doc in grants) != 2:
            raise ValueError("Authentic predecessor chart cannot provide the declared sensitive-write boundary")
        self.kubectl("apply", "-f", "-", input=yaml.safe_dump_all(grants).encode())


def snapshot(fixture, objects, excluded_clients=()):
    """Secrets and native representations stay in memory; only comparisons leave it."""
    result = {"objects": {}, "secrets": {}, "native": {}}
    for kind, name, namespace in objects:
        obj = fixture.get(kind, name, namespace)
        result["objects"][f"{namespace}/{kind}/{name}"] = {
            "uid": obj["metadata"]["uid"], "spec": fingerprint(obj["spec"]),
            "finalizers": sorted(obj["metadata"].get("finalizers", [])),
            "receipt": obj.get("status", {}).get("adoptionReceipt"),
            "foreign": obj["metadata"].get("annotations", {}).get("qualification.hanko.sh/foreign"),
        }
    for namespace in ("auth", "upgrade-adoption"):
        for secret in json.loads(fixture.kubectl("get", "secrets", "-n", namespace, "-o", "json"))["items"]:
            # Helm release storage legitimately changes at each upgrade.
            if secret.get("type") == "helm.sh/release.v1":
                continue
            result["secrets"][namespace + "/" + secret["metadata"]["name"]] = {
                "uid": secret["metadata"]["uid"], "data": fingerprint(secret.get("data", {}))}
    for realm in ("managed", "upgrade-adoption-target"):
        base = "/admin/realms/" + realm
        native = {"realm": fixture.api("GET", base), "clients": [], "roles": []}
        for client in fixture.api("GET", base + "/clients?max=100"):
            if (realm, client["clientId"]) in excluded_clients:
                continue
            path = base + "/clients/" + client["id"]
            value = fixture.api("GET", path)
            entry = {"client": value}
            if not value.get("publicClient") and not value.get("bearerOnly") and value.get("protocol", "openid-connect") == "openid-connect":
                entry["credential"] = fixture.api("GET", path + "/client-secret")
            if value.get("authorizationServicesEnabled"):
                entry["authorization"] = fixture.api("GET", path + "/authz/resource-server/settings")
            native["clients"].append(entry)
        for role in fixture.api("GET", base + "/roles?max=100"):
            native["roles"].append({"role": role, "composites": fixture.api("GET", base + "/roles-by-id/" + role["id"] + "/composites")})
        result["native"][realm] = fingerprint(native)
    return result


def preserve(before, after):
    for surface in ("objects", "secrets", "native"):
        if before[surface] != after[surface]:
            raise ValueError("Public upgrade changed preserved " + surface + "; private fixture discarded")


def transition(fixture, chart, digest, deployments):
    for namespace, name, release, _ in deployments:
        fixture.kubectl("scale", "deployment/" + name, "-n", namespace, "--replicas=0")
        system.wait("previous manager stopped", lambda namespace=namespace, release=release: not json.loads(
            fixture.kubectl("get", "pods", "-n", namespace, "-l", "app.kubernetes.io/instance=" + release, "-o", "json"))["items"], seconds=120)
    crds = system.run([fixture.args.helm, "show", "crds", chart])
    if not list(yaml.safe_load_all(crds)):
        raise ValueError("Historical or candidate chart has no CRDs")
    fixture.kubectl("apply", "-f", "-", input=crds.encode())
    for namespace, name, release, values in deployments:
        values = copy.deepcopy(values)
        values["image"] = {"repository": fixture.registry + "/hankoshell-operator", "digest": digest, "tag": ""}
        values["replicaCount"] = 1
        config = fixture.private / (namespace + "-transition.yaml")
        config.write_text(yaml.safe_dump(values))
        system.run([fixture.args.helm, "upgrade", release, chart, "--namespace", namespace,
                    "--kubeconfig", fixture.config, "--values", config, "--wait", "--timeout", "180s"])
        fixture.kubectl("rollout", "status", "deployment/" + name, "-n", namespace, "--timeout=180s")
        pods = json.loads(fixture.kubectl("get", "pods", "-n", namespace, "-l", "app.kubernetes.io/instance=" + release, "-o", "json"))["items"]
        if not pods or any(container["image"] != fixture.registry + "/hankoshell-operator@" + digest for pod in pods for container in pod["spec"]["containers"]):
            raise ValueError("Transition did not install the selected immutable image")


def qualify(args, fixtures, capture):
    candidate_digest = args.digest
    old_digest = capture["image"].split("@", 1)[1]
    with tempfile.TemporaryDirectory(prefix="hanko-public-upgrade-private-") as directory:
        fixture = HistoricalSystem(args, Path(directory))
        try:
            fixture.create_cluster()
            system.run([args.oras, "cp", capture["image"], "--to-plain-http", fixture.registry + "/hankoshell-operator:predecessor"])
            if system.publication.publish.Registry(args.oras, args.helm, plain_http=True).resolve(fixture.registry + "/hankoshell-operator:predecessor") != old_digest:
                raise ValueError("Mirroring changed the authentic predecessor graph")
            fixture.keycloak()
            args.digest = old_digest
            chart = args.assets / ("hankoshell-operator-" + capture["source_release"] + ".tgz")
            fixture.chart_path = chart
            fixture.install()
            installed_schemas = {crd["spec"]["names"]["kind"]: crd["spec"] for crd in json.loads(fixture.kubectl("get", "crds", "-o", "json"))["items"]}
            if any(installed_schemas.get(kind) != value for kind, value in capture["schemas"].items()):
                raise ValueError("Installed predecessor schemas differ from the actual captured schemas")
            fixture.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm",
                "metadata": {"name": "managed", "namespace": "auth"}, "spec": {"displayName": "Public upgrade fixture"}})
            system.wait("historical managed realm", lambda: fixture.ready("hankorealm", "managed"))
            objects = [("hankorealm", "managed", "auth")]
            for frozen in fixtures:
                obj = {"apiVersion": frozen["apiVersion"], "kind": frozen["kind"], "metadata": {
                    "name": frozen["metadata"]["name"], "namespace": "auth",
                    "annotations": {"qualification.hanko.sh/foreign": "preserve"}}, "spec": frozen["spec"]}
                fixture.apply_approved(obj)
                kind, name = obj["kind"].lower(), obj["metadata"]["name"]
                system.wait("historical corpus applied and read back", lambda kind=kind, name=name: fixture.iam_reconciled(kind, name))
                objects.append((kind, name, "auth"))
            fixture.retain_upgrade_adoption()
            objects += [("hankoapplication", "retained", "upgrade-adoption"), ("hankorealm", "upgrade-adoption-target", "upgrade-adoption")]
            fixture.api("POST", "/admin/realms/managed/clients", {"clientId": "foreign-upgrade-client", "enabled": True, "publicClient": True,
                        "attributes": {"locale": "fr"}})
            fixture.api("POST", "/admin/realms/upgrade-adoption-target/clients", {"clientId": "foreign-adoption-client", "enabled": True, "publicClient": True,
                        "attributes": {"locale": "en"}})
            deployments = []
            for namespace, name in (("auth", "system-operator"), ("upgrade-adoption", "upgrade-adoption-operator")):
                deployment = fixture.get("deployment", name, namespace)
                release = deployment["metadata"]["annotations"]["meta.helm.sh/release-name"]
                values = json.loads(system.run([args.helm, "get", "values", release, "-n", namespace, "--kubeconfig", fixture.config, "-o", "json"]))
                deployments.append((namespace, name, release, values))
            before = snapshot(fixture, objects)
            transitions = []
            for label, selected_chart, digest in (("upgrade", ROOT / "charts/hankoshell-operator", candidate_digest), ("rollback", chart, old_digest)):
                transition(fixture, selected_chart, digest, deployments)
                for kind, name, namespace in objects:
                    system.wait(label + " current readiness", lambda kind=kind, name=name, namespace=namespace: fixture.ready(kind, name, namespace))
                for frozen in fixtures:
                    system.wait(label + " applied/read-back contract", lambda frozen=frozen: fixture.iam_reconciled(frozen["kind"].lower(), frozen["metadata"]["name"]))
                    # A second field manager applies the identical historical intent,
                    # without force, preserving the historical field ownership.
                    fixture.kubectl("apply", "--server-side", "--field-manager=public-upgrade-author", "-f", "-", input=yaml.safe_dump({
                        "apiVersion": frozen["apiVersion"], "kind": frozen["kind"], "metadata": {"name": frozen["metadata"]["name"], "namespace": "auth"},
                        "spec": frozen["spec"]}).encode())
                preserve(before, snapshot(fixture, objects))
                transitions.append(label)
            remaining = [obj for obj in objects if obj != ("hankoapplication", "retained", "upgrade-adoption")]
            excluded = (("upgrade-adoption-target", "public-upgrade-adopted"),)
            cleanup_before = snapshot(fixture, remaining, excluded)
            cleanup_before["secrets"].pop("upgrade-adoption/hanko-app-public-upgrade-adopted")
            selected_id = fixture.client("upgrade-adoption-target", "public-upgrade-adopted")["id"]
            fixture.kubectl("delete", "hankoapplication", "retained", "-n", "upgrade-adoption", "--wait=false")
            system.wait("adopted selected client cleanup after rollback", lambda: not fixture.exists("hankoapplication", "retained", "upgrade-adoption"), seconds=180)
            fixture.api("GET", "/admin/realms/upgrade-adoption-target/clients/" + selected_id, expected=(404,))
            system.wait("selected credential Secret garbage collection", lambda: not fixture.exists("secret", "hanko-app-public-upgrade-adopted", "upgrade-adoption"), seconds=120)
            preserve(cleanup_before, snapshot(fixture, remaining, excluded))
            return {"schema_version": 1, "complete": True, "layer": "public-predecessor-upgrade-rollback",
                "revision": args.revision, "image_digest": candidate_digest, "predecessor_revision": capture["revision"],
                "predecessor_version": capture["source_release"], "predecessor_image": capture["image"],
                "kubernetes": system.KUBERNETES_VERSION, "keycloak": system.KEYCLOAK_VERSION,
                "corpus_sha256": hashlib.sha256(capture.raw).hexdigest(), "fixtures": len(fixtures),
                "transitions": transitions, "selected_adopted_cleanup": True, "preserved": ["CR UIDs, specs and finalizers", "native UUIDs, configuration and credentials",
                    "adoption receipts and explicit Manage", "Secret UIDs and data", "foreign client and SSA annotation"],
                "limitations": ["synthetic isolated installation of authentic public artifacts; no production tenant data",
                    "covers the selected provider/Kubernetes cell; all supported cells are required separately",
                    "provider request budgets and HA partitions are qualified by separate installed suites"]}
        finally:
            args.digest = candidate_digest
            fixture.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("archive", "evidence", "kind", "kubectl", "helm", "oras", "openssl", "assets", "trust", "cosign", "attest", "capture", "reviewed-corpus", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    for field in ("digest", "revision", "kubernetes-version", "keycloak-version"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--capture-artifact-id", type=int, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite a previous public compatibility campaign")
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    pins = system.PINS
    if args.kubernetes_version not in pins["kubernetes"]["versions"] or args.keycloak_version not in pins["keycloak"]["versions"]:
        raise SystemExit("Only reviewed compatibility cells may be qualified")
    system.KUBERNETES_VERSION, system.KEYCLOAK_VERSION = args.kubernetes_version, args.keycloak_version
    system.NODE, system.KEYCLOAK = pins["kubernetes"]["node_images"][args.kubernetes_version], pins["keycloak"]["images"][args.keycloak_version]
    captured = Capture(args.capture)
    proof = authentic.verify(captured["source_release"], captured["revision"], captured["image"], args.assets,
                             json.loads(args.trust.read_text()), args.cosign, args.attest)
    proof.update(authentic.capture_identity(args.capture, args.capture_artifact_id, captured["revision"]),
                 fixture_sha256=hashlib.sha256(captured.raw).hexdigest())
    fixtures = predecessor(captured, json.loads(args.reviewed_corpus.read_text()), proof)
    report = qualify(args, fixtures, captured)
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

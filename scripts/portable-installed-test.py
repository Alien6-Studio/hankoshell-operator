"""Run the identical portable-v1 corpus through an installed, scanned operator.

Both real providers run in each Kubernetes/Keycloak matrix cell. Only provider
selection metadata and explicitly reported cluster/connection bindings differ.
Private bootstrap data never enters the bounded difference report.
"""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import tempfile
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


installed = module("portable_installed_base", "workload-installed-test.py")
auth = module("portable_authentik_fixture", "authentik-fixture.py")
system, native, run, wait = installed.system, installed.native, installed.run, installed.wait
SELECTOR = "hanko.sh/provider-connection"
CORPUS = ROOT / "internal/iamconformance/testdata/portable-v1/corpus.json"


def read_corpus():
    data = CORPUS.read_bytes()
    if len(data) > 262144:
        raise ValueError("Portable corpus exceeds its budget")
    corpus = json.loads(data)
    if corpus["schemaVersion"] != 1 or corpus["providers"] != ["keycloak", "authentik"] or len(corpus["fixtures"]) != 14:
        raise ValueError("Unreviewed portable corpus inventory")
    names = set()
    for fixture in corpus["fixtures"]:
        if fixture["name"] in names or set(fixture["expected"]) != set(corpus["providers"]):
            raise ValueError("Missing portable fixture classification")
        names.add(fixture["name"])
        for expected in fixture["expected"].values():
            supported = expected["classification"] == "lossless"
            if (expected["classification"] not in ("lossless", "unsupported") or not expected["evidence"]
                    or expected["phase"] != ("Ready" if supported else "Error")
                    or bool(expected["reason"]) == supported or bool(expected["statusReason"]) == supported
                    or (not supported and expected["planEvidence"])):
                raise ValueError("Unreviewed semantic loss or observation")
    return corpus


def observation_valid(value, expected, provider, identity=None):
    status, generation = value.get("status", {}), value["metadata"]["generation"]
    if status.get("phase") != expected["phase"] or status.get("observedGeneration") != generation:
        return False
    if expected["classification"] == "unsupported":
        return (not status.get("appliedPlanHash") and not status.get("observationComplete") and any(
            c.get("type") == "Synced" and c.get("status") == "False" and c.get("reason") == expected["statusReason"]
            and c.get("observedGeneration") == generation for c in status.get("conditions", [])))
    if not expected["planEvidence"]:
        return True
    hashes = ("intentHash", "evaluatedPlanHash", "appliedPlanHash", "observationPlanHash", "observedStateHash")
    return (status.get("backendKind") == provider and status.get("observationComplete") is True
            and status.get("driftState") == "InSync"
            and all(status.get(key) == generation for key in ("evaluatedGeneration", "appliedGeneration", "observationGeneration"))
            and all(re.fullmatch(r"sha256:[a-f0-9]{64}", status.get(key, "")) for key in hashes)
            and status["evaluatedPlanHash"] == status["appliedPlanHash"] == status["observationPlanHash"]
            and (not identity or identity == status["intentHash"]))


class Portable(installed.Installed):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.extra_certificate_names += ",DNS:authentik.auth.svc"
        self.corpus = read_corpus()
        self.report.update(layer="installed-portable", fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           corpus_sha256=hashlib.sha256(CORPUS.read_bytes()).hexdigest(), differences=[],
                           authentik_image=auth.SERVER, postgres_image=auth.POSTGRES, hub_enabled=False,
                           bindings=["provider-selection-label", "connection-credentials-and-ca", "workload-cluster-issuer-and-anchor"],
                           approved_losses=[])

    def public_evidence(self):
        result = super().public_evidence()
        for key in ("corpus_sha256", "differences", "authentik_image", "postgres_image", "hub_enabled", "bindings", "approved_losses"):
            result[key] = self.report[key]
        return result

    def authority(self, name, permissions):
        credential = secrets.token_urlsafe(40)
        self.sensitive.append(credential)
        self.api("POST", "/admin/realms/master/clients", {"clientId": name, "secret": credential,
            "enabled": True, "protocol": "openid-connect", "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
        client, proxy = self.client("master", name), self.client("master", "portable-realm")
        user = self.api("GET", f'/admin/realms/master/clients/{client["id"]}/service-account-user')
        roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{role}') for role in permissions]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{client["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        token = self.access_token({"client_id": name, "client_secret": credential, "grant_type": "client_credentials"})
        self.api("GET", "/admin/realms/master/clients", token=token, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "denied-portable"}, token=token, expected=(403,))
        return credential

    def prepare_keycloak(self):
        self.api("POST", "/admin/realms", {"realm": "portable", "enabled": True})
        self.api("POST", "/admin/realms/portable/roles", {"name": "portable-writer"})
        pod = json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app=keycloak", "-o", "json"))["items"][0]
        self.patch("pod", pod["metadata"]["name"], {"metadata": {"labels": {"hanko-fixture": "keycloak-upstream"}}})
        self.apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "keycloak-upstream", "namespace": "auth"}, "spec": {
            "selector": {"app": "keycloak", "hanko-fixture": "keycloak-upstream"}, "ports": [{"port": 8443, "targetPort": 8443}]}})
        self.keycloak_proxy = self.setup_proxy("fault-keycloak", "https://keycloak-upstream.auth.svc:8443", (self.private / "tls.crt").read_text(), 8443)
        credential = self.authority("portable-operator", ["manage-realm", "manage-clients", "manage-events", "manage-users", "manage-authorization"])
        self.apply(self.secret("operator-credentials", {"client-id": "portable-operator", "client-secret": credential}),
                   self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}))
        self.install_values = {"keycloak": {"url": "https://fault-keycloak.auth.svc:8443", "credentialsSecret": "operator-credentials", "caSecret": "operator-ca"}}
        for name, roles in (("source", ["view-realm", "view-identity-providers", "manage-identity-providers"]),
                            ("dependent-reader", ["view-clients"])):
            credential = self.authority("portable-" + name, roles)
            self.apply(self.secret(name + "-credentials", {"HANKO_KEYCLOAK_URL": "https://fault-keycloak.auth.svc:8443",
                "HANKO_KC_CLIENT_ID": "portable-" + name, "HANKO_KC_CLIENT_SECRET": credential}))
        self.record("keycloak_runtime_cannot_create_realms_or_access_master")

    def authentik(self):
        password, token, denied = (secrets.token_urlsafe(40) for _ in range(3))
        secret_key = secrets.token_urlsafe(48)
        self.sensitive += [password, token, denied, secret_key]
        self.auth_token = token
        variables = {"AUTHENTIK_SECRET_KEY": secret_key, "AUTHENTIK_POSTGRESQL__HOST": "authentik-db",
            "AUTHENTIK_POSTGRESQL__USER": "authentik", "AUTHENTIK_POSTGRESQL__PASSWORD": password,
            "AUTHENTIK_POSTGRESQL__NAME": "authentik", "AUTHENTIK_ERROR_REPORTING__ENABLED": "false",
            "AUTHENTIK_LOG_LEVEL": "warning", "HANKO_FIXTURE_TOKEN": token, "HANKO_FIXTURE_DENIED_TOKEN": denied}
        self.apply(self.secret("authentik-bootstrap", variables), self.secret("authentik-db", {
            "POSTGRES_USER": "authentik", "POSTGRES_DB": "authentik", "POSTGRES_PASSWORD": password,
            "PGDATA": "/var/lib/postgresql/data/pgdata"}))
        security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        for name, image, uid, env, port, mounts in (
                ("authentik-db", auth.POSTGRES, 70, "authentik-db", 5432, [("data", "/var/lib/postgresql/data"), ("run", "/var/run/postgresql"), ("tmp", "/tmp")]),
                ("authentik-upstream", auth.SERVER, 1000, "authentik-bootstrap", 9000, [("media", "/media"), ("tmp", "/tmp")])):
            container = {"name": name, "image": image, "securityContext": security,
                "envFrom": [{"secretRef": {"name": env}}], "ports": [{"containerPort": port}],
                "volumeMounts": [{"name": volume, "mountPath": path} for volume, path in mounts],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "1Gi"}}}
            if name == "authentik-upstream":
                container["args"] = ["server"]
                container["readinessProbe"] = {"httpGet": {"path": "/-/health/ready/", "port": port}, "periodSeconds": 2}
            else:
                container["readinessProbe"] = {"exec": {"command": ["pg_isready", "-U", "authentik"]}, "periodSeconds": 2}
            self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": "auth"}, "spec": {
                "replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": {
                    "metadata": {"labels": {"app": name}}, "spec": {"automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [container], "volumes": [{"name": volume, "emptyDir": {}} for volume, _ in mounts]}}}},
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": "auth"}, "spec": {
                    "selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]}})
            self.kubectl("rollout", "status", "deployment/" + name, "-n", "auth", "--timeout=300s")
        seeded = self.kubectl("exec", "-i", "-n", "auth", "deployment/authentik-upstream", "--", "ak", "shell",
                              input=(ROOT / "scripts/fixtures/authentik-seed.py").read_bytes())
        configs = [line.split("=", 1)[1] for line in seeded.splitlines() if line.startswith("HANKO_FIXTURE_CONFIG=")]
        if len(configs) != 1:
            raise ValueError("Private authentik bootstrap did not produce its typed connection")
        self.authentik_proxy = self.setup_proxy("authentik", "http://authentik-upstream.auth.svc:9000", (self.private / "tls.crt").read_text(), 9443)
        connection = json.loads(configs[0])
        connection.update(endpoint="https://authentik.auth.svc:9443", caSecret="operator-ca")
        self.apply(self.secret("provider-token", {"token": token}), {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "experimental", "namespace": "auth"}, "data": {"connection.json": json.dumps(connection)}})
        self.install_values["experimental"] = {"authentik": {"enabled": True, "connectionNames": ["experimental"],
            "egress": {"namespace": "auth", "selector": {"app": "authentik"}, "port": 9443}}}
        self.record("real_authentik_verified_tls_and_minimal_runtime_identity")

    def proxy_state(self, provider):
        endpoint = getattr(self, provider + "_proxy")
        with urlopen(endpoint + "/__fixture/control", context=self.http, timeout=10) as response:
            return json.load(response)

    def writes(self, provider):
        state = self.proxy_state(provider)
        prefix = "/api/v3/" if provider == "authentik" else "/admin/"
        # Count attempts as well as accepted writes: a rejected mutation is
        # still a broken no-mutation contract. Token issuance is not IAM mutation.
        return {key: count for key, count in state["attempted_counts"].items() if key.split(" ", 1)[1].startswith(prefix)}

    def selected_manifest(self, fixture, provider):
        value = copy.deepcopy(fixture["manifest"])
        value["metadata"]["namespace"] = "auth"
        if provider == "authentik":
            value["metadata"]["labels"] = {SELECTOR: "experimental"}
        if value["kind"] == "HankoWorkloadTrust" and provider == "keycloak":
            value["spec"]["kubernetes"].update(issuer=self.report["discovery"]["issuer"], clusterAnchor={
                "kubeSystemNamespaceUID": self.report["cluster_namespace_uid"], "apiServerCAHash": "sha256:" + self.report["cluster_ca_sha256"]})
        return value

    def await_observation(self, fixture, provider):
        kind, name = fixture["manifest"]["kind"], fixture["manifest"]["metadata"]["name"]
        wait(provider + " portable " + fixture["name"], lambda: observation_valid(self.get(kind, name), fixture["expected"][provider], provider,
             fixture.get("intentIdentity")), 180)
        return self.get(kind, name)

    def auth_api(self, path):
        with urlopen(Request(self.authentik_proxy + path, headers={"Authorization": "Bearer " + self.auth_token}), context=self.http, timeout=10) as response:
            data = response.read(2**20 + 1)
        if len(data) > 2**20:
            raise ValueError("Native fixture read-back exceeds its budget")
        return json.loads(data)

    def native_observation(self, fixture, provider, value):
        spec, kind = fixture["manifest"]["spec"], fixture["manifest"]["kind"]
        if provider == "authentik":
            providers = self.auth_api("/api/v3/providers/oauth2/?client_id=" + spec["clientID"])["results"]
            self.record("authentik_" + fixture["name"] + "_native_readback", len(providers) == 1 and providers[0]["client_id"] == spec["clientID"]
                and providers[0]["client_type"] == ("public" if spec["type"] == "spa" else "confidential")
                and sorted(entry["url"] for entry in providers[0]["redirect_uris"]) == sorted(spec["redirectURIs"]))
            self.record("authentik_" + fixture["name"] + "_explicit_capability_limits", all(value["status"].get("capabilities", {}).get(key) is False
                for key in ("saml", "samlACS", "samlAssertionSigning", "samlResponseSigning", "samlMetadata", "clientRoles", "protocolMappers"))
                and any(c.get("type") == "Operational" and c.get("status") == "False" and c.get("reason") == "CredentialBindingUnsupported"
                        for c in value["status"].get("conditions", [])))
            return
        base = "/admin/realms/portable"
        if kind == "HankoRealm":
            valid = self.api("GET", base)["displayName"] == spec["displayName"]
        elif kind == "HankoIAMProfile":
            valid = bool(value["status"].get("policyHash"))
        elif kind in ("HankoApplication", "HankoServiceAccount"):
            client = self.client("portable", spec["clientID"])
            valid = client["enabled"] is True
            if spec.get("protocol") == "saml":
                valid = valid and client["protocol"] == "saml" and client["attributes"].get("saml.assertion.signature") == "true"
            else:
                valid = valid and client["protocol"] == "openid-connect" and client["publicClient"] == (spec.get("type") == "spa")
                if spec.get("redirectURIs"):
                    valid = valid and sorted(client["redirectUris"]) == sorted(spec["redirectURIs"])
                if kind == "HankoServiceAccount":
                    valid = valid and client["serviceAccountsEnabled"] is True
                if not client["publicClient"]:
                    credential = self.api("GET", base + "/clients/" + client["id"] + "/client-secret")["value"]
                    self.sensitive.append(credential)
            if fixture["name"] == "native-extension":
                valid = valid and client["attributes"].get("pkce.code.challenge.method") == "S256"
        elif kind == "HankoRole":
            role = self.api("GET", base + "/roles/" + spec["name"])
            valid = role["name"] == spec["name"] and role.get("description", "") == spec.get("description", "")
            if spec.get("composites"):
                valid = valid and sorted(r["name"] for r in self.api("GET", base + "/roles/" + spec["name"] + "/composites")) == sorted(spec["composites"])
        elif kind == "HankoOrganization":
            group = self.api("GET", base + "/groups/" + value["status"]["groupID"])
            valid = bool(group["id"]) and spec["roles"] == [r["name"] for r in self.api("GET", base + "/groups/" + group["id"] + "/role-mappings/realm")]
        elif kind == "HankoResourceServer":
            client = self.client("portable", "portable-m2m")
            authz = base + "/clients/" + client["id"] + "/authz/resource-server"
            valid = (client["authorizationServicesEnabled"] is True
                and "read" in [item["name"] for item in self.api("GET", authz + "/scope")]
                and "document" in [item["name"] for item in self.api("GET", authz + "/resource")]
                and "read-document" in [item["name"] for item in self.api("GET", authz + "/permission")])
        elif kind == "HankoWorkloadTrust":
            trust = self.api("GET", base + "/identity-provider/instances/" + spec["keycloakAlias"])
            valid = (trust["providerId"] == "kubernetes" and trust["config"]["fedClientAssertionMaxExp"] == "600"
                and trust["config"]["hanko.sh/workload-trust-owner"] == value["metadata"]["uid"]
                and value["status"].get("observationComplete") is True)
        else:
            raise ValueError("Unassigned native portable observation")
        suffix = "_local_validation" if kind == "HankoIAMProfile" else "_native_readback"
        self.record("keycloak_" + fixture["name"] + suffix, valid)

    def exercise(self, fixture, provider):
        expected = fixture["expected"][provider]
        before = self.writes(provider)
        self.apply(self.selected_manifest(fixture, provider))
        value = self.await_observation(fixture, provider)
        if expected["classification"] == "unsupported":
            self.record(provider + "_" + fixture["name"] + "_no_mutation", before == self.writes(provider) and not value["metadata"].get("finalizers"))
            self.kubectl("delete", fixture["manifest"]["kind"], value["metadata"]["name"], "-n", "auth", "--wait=true", "--timeout=60s")
        else:
            self.native_observation(fixture, provider, value)
        self.report["differences"].append({"fixture": fixture["name"], "provider": provider, **expected,
            "observed": True, "native_readback": expected["classification"] == "lossless" and fixture["manifest"]["kind"] != "HankoIAMProfile"})

    def authentik_recovery(self):
        fixture = next(f for f in self.corpus["fixtures"] if f["name"] == "spa")
        before = self.writes("authentik")
        self.control("authentik", {"method": "GET", "path": "/api/v3/providers/oauth2/", "action": "deny"})
        self.patch("HankoApplication", "spa", {"metadata": {"annotations": {"hanko.sh/reconcile-request": secrets.token_hex(8)}}})
        self.await_fault("authentik")
        wait("provider outage clears applied proof", lambda: self.get("HankoApplication", "spa").get("status", {}).get("phase") == "Error"
             and not self.get("HankoApplication", "spa").get("status", {}).get("appliedPlanHash"), 90)
        self.restart()
        self.control("authentik", None)
        self.await_observation(fixture, "authentik")
        self.record("authentik_outage_restart_no_duplicate", before == self.writes("authentik"))
        self.patch("HankoApplication", "spa", {"spec": {"attributes": {"pkce.code.challenge.method": "S256"}}})
        wait("native attribute cannot silently disappear", lambda: self.get("HankoApplication", "spa").get("status", {}).get("phase") == "Error"
             and not self.get("HankoApplication", "spa").get("status", {}).get("appliedPlanHash"), 90)
        self.record("authentik_native_extension_refused_without_silent_drop", before == self.writes("authentik"))
        self.patch("HankoApplication", "spa", {"spec": {"attributes": None}})
        self.await_observation(fixture, "authentik")
        # The native UNIQUE constraint rejects duplicate client IDs. Prove its
        # rollback, then corrupt only a provider's owner marker via bootstrap.
        # Runtime authority must neither adopt nor repair that foreign marker.
        result = self.kubectl("exec", "-i", "-n", "auth", "deployment/authentik-upstream", "--", "ak", "shell", input=b'''
from django.db import IntegrityError, transaction
from authentik.providers.oauth2.models import OAuth2Provider
p = OAuth2Provider.objects.get(client_id="portable-spa")
values = {field.attname: getattr(p, field.attname) for field in p._meta.concrete_fields
          if not field.primary_key and not field.auto_created}
try:
    with transaction.atomic():
        duplicate = OAuth2Provider(**values)
        duplicate.name = "foreign-portable-duplicate"
        duplicate.save(force_insert=True)
except IntegrityError as error:
    if "client_id" not in getattr(getattr(error.__cause__, "diag", None), "constraint_name", ""):
        raise RuntimeError("unexpected native duplicate constraint") from None
    print("HANKO_NATIVE_DUPLICATE_REFUSED")
else:
    raise RuntimeError("native duplicate constraint unexpectedly absent")
p.name = "foreign-portable-marker"
p.save(update_fields=["name"])
''')
        self.record("authentik_native_duplicate_identity_refused", "HANKO_NATIVE_DUPLICATE_REFUSED" in result)
        self.patch("HankoApplication", "spa", {"metadata": {"annotations": {"hanko.sh/reconcile-request": secrets.token_hex(8)}}})
        wait("foreign native marker refused", lambda: any(c.get("reason") == "ExperimentalOwnershipConflict" for c in
             self.get("HankoApplication", "spa").get("status", {}).get("conditions", [])), 90)
        self.record("authentik_foreign_marker_no_mutation", before == self.writes("authentik")
            and not self.get("HankoApplication", "spa").get("status", {}).get("appliedPlanHash"))
        self.kubectl("exec", "-i", "-n", "auth", "deployment/authentik-upstream", "--", "ak", "shell", input=b'''
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.core.models import Application
p = OAuth2Provider.objects.get(client_id="portable-spa")
p.name = Application.objects.get(provider=p).meta_description
p.save(update_fields=["name"])
''')
        self.patch("HankoApplication", "spa", {"metadata": {"annotations": {"hanko.sh/reconcile-request": secrets.token_hex(8)}}})
        self.await_observation(fixture, "authentik")
        # Removing selection cannot reuse the authentik journal as native authority.
        keycloak_before = self.writes("keycloak")
        self.patch("HankoApplication", "spa", {"metadata": {"labels": {SELECTOR: None}}})
        wait("authentik to Keycloak switch refused", lambda: self.get("HankoApplication", "spa").get("status", {}).get("phase") == "Error", 90)
        self.record("authentik_marker_not_reused_by_keycloak", keycloak_before == self.writes("keycloak"))
        self.patch("HankoApplication", "spa", {"metadata": {"labels": {SELECTOR: "experimental"}}})
        self.await_observation(fixture, "authentik")
        self.kubectl("delete", "HankoApplication", "spa", "web", "-n", "auth", "--wait=true", "--timeout=180s")
        self.record("authentik_owned_cleanup_confirmed", self.auth_api("/api/v3/providers/oauth2/?client_id=portable-spa")["count"] == 0
            and self.auth_api("/api/v3/providers/oauth2/?client_id=portable-web")["count"] == 0)

    def qualify_portable(self):
        self.create_cluster()
        self.mirror_scanned_image()
        self.keycloak()
        self.record("real_keycloak_exact_version", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.prepare_keycloak()
        self.authentik()
        self.install()
        self.start_log_capture()
        self.record("scanned_operator_installed_with_baseline_hardening")
        # Unsupported objects are independent attempts, removed before the next
        # fixture. In particular an unsupported identity domain grants no realm policy.
        for fixture in self.corpus["fixtures"]:
            self.exercise(fixture, "authentik")
        self.authentik_recovery()
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": self.name + "-public-discovery"}, "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:service-account-issuer-discovery"},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:unauthenticated"}]})
        for name in ("source", "dependent-reader"):
            self.apply(installed.object_value("HankoKeycloakInstance", name, {"mode": "external", "adminRef": {"name": name + "-credentials"}, "tlsCARef": "operator-ca"}))
        # Refusal first isolates mutation accounting from background realm maintenance.
        fixtures = sorted(self.corpus["fixtures"], key=lambda f: f["expected"]["keycloak"]["classification"] != "unsupported")
        for fixture in fixtures:
            self.exercise(fixture, "keycloak")
        before = self.writes("authentik")
        self.patch("HankoApplication", "spa", {"metadata": {"labels": {SELECTOR: "experimental"}}})
        wait("Keycloak to authentik switch refused", lambda: self.get("HankoApplication", "spa").get("status", {}).get("phase") == "Error", 90)
        self.record("keycloak_marker_not_reused_by_authentik", before == self.writes("authentik"))
        self.patch("HankoApplication", "spa", {"metadata": {"labels": {SELECTOR: None}}})
        self.await_observation(next(f for f in fixtures if f["name"] == "spa"), "keycloak")
        self.leak_scan()
        self.record("complete_reviewed_difference_inventory", len(self.report["differences"]) == 28
            and len({(r["fixture"], r["provider"]) for r in self.report["differences"]}) == 28)
        self.report.update(complete=True, completed_at=datetime.now(timezone.utc).isoformat())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path)
    args = parser.parse_args()
    args.deep_migration = False
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hanko-portable-installed-private-") as temp:
        fixture = Portable(args, Path(temp))
        try:
            fixture.qualify_portable()
        except Exception as error:
            system.diagnostics.capture(fixture, error)
            raise
        finally:
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
            finally:
                fixture.cleanup()


if __name__ == "__main__":
    main()

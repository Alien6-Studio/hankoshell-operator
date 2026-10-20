"""Qualify installed workload identity using the exact scanned OCI graph.

Six runtime cells are mandatory. Deep migration/fault scenarios additionally run
on the reviewed deep-migration Kubernetes version with each supported Keycloak version. No production test hook
or controller-side workload assertion is involved. Evidence is an allowlist of
public decisions, hashes, counts and versions, including on failure.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.request import Request, urlopen

import yaml

from evidence_privacy import contains_jwt

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_workload", ROOT / "scripts/workload-identity-probe.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
system, run, wait = native.system, native.run, native.system.wait
JOURNAL = "hanko.sh/workload-auth-transition"


def object_value(kind, name, spec=None, namespace="auth", **metadata):
    result = {"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
              "metadata": {"name": name, "namespace": namespace, **metadata}}
    if spec is not None:
        result["spec"] = spec
    return result


def snapshot_capture_valid(snapshot, capture, expected_name):
    """Require stored content and scope, not only a successful controller phase."""
    status, metadata = snapshot.get("status", {}), snapshot["metadata"]
    raw = capture.get("data", {}).get("snapshot.json", "")
    if (status.get("phase") != "Done" or capture.get("immutable") is not True
            or capture.get("metadata", {}).get("uid") != status.get("configMapUID")
            or not status.get("configMapUID") or set(capture.get("data", {})) != {"snapshot.json"}
            or hashlib.sha256(raw.encode()).hexdigest() != status.get("configHash")):
        return False
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return False
        for kind in ("realms", "applications", "serviceAccounts", "issuers"):
            items = payload.get(kind)
            if not isinstance(items, list) or sum(item.get("metadata", {}).get("name") == expected_name for item in items) != 1:
                return False
            for item in items:
                current = item.get("metadata", {})
                labels, expected = current.get("labels", {}), metadata.get("labels", {})
                if (current.get("namespace") != metadata["namespace"]
                        or ("hanko.sh/tenant" in labels) != ("hanko.sh/tenant" in expected)
                        or labels.get("hanko.sh/tenant") != expected.get("hanko.sh/tenant")):
                    return False
    except (ValueError, TypeError, AttributeError):
        return False
    return True


class Installed(native.Fixture):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.registry_name = self.name + "-registry"
        self.extra_certificate_names = ",DNS:fault-keycloak.auth.svc,DNS:keycloak-upstream.auth.svc"
        # This fixture explicitly exercises administrator-approved snapshots.
        self.install_values = {"lifecycle": {"enabled": True}}
        self.workload_grants = [{"namespace": "workload", "serviceAccounts": ["worker"], "configMaps": ["identity"]}]
        if args.deep_migration:
            self.workload_grants[0]["serviceAccounts"] += ["migration-worker", "creation-worker", "flow-worker"]
        self.report.update({"schema_version": 1, "layer": "installed-workload", "revision": args.revision,
                            "image_digest": args.digest, "deep_migration": args.deep_migration,
                            "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            "recovery": [], "migrations": {}, "checks": {}})
        self.proxy_forwards = []
        self.rotation_process = None
        self.operator_log_process = None
        self.operator_log_thread = None
        self.operator_log_failed = False
        self.operator_log_bytes = 0
        self.preserved_themes = {}
        self.workload_anchors = {}
        self.federated_secrets = {}

    def kubectl(self, *args, **kwargs):
        # Match the installed System helpers' text contract, while retaining
        # the native fixture's redacted command-failure boundary.
        return super().kubectl(*args, **kwargs).strip()

    def record(self, name, valid=True):
        self.report["checks"][name] = bool(valid)
        if not valid:
            raise ValueError("Installed qualification failed: " + name)
        print("Installed workload: " + name + " passed", flush=True)

    def patch(self, kind, name, value, namespace="auth", subresource=None):
        args = ["patch", kind, name, "-n", namespace, "--type=merge", "-p", json.dumps(value)]
        if subresource:
            args += ["--subresource", subresource]
        self.kubectl(*args)

    def hsa_ready(self, name):
        value = self.get("hankoserviceaccount", name)
        generation = value["metadata"]["generation"]
        required = {"WorkloadBindingReady", "FederatedModeApplied", "Synced"}
        good = {c["type"] for c in value.get("status", {}).get("conditions", [])
                if c.get("status") == "True" and c.get("observedGeneration") == generation}
        return self.ready("hankoserviceaccount", name) and required <= good

    def journal(self, name):
        value = self.get("hankoserviceaccount", name)["metadata"].get("annotations", {}).get(JOURNAL)
        return json.loads(value) if value else {}

    def stage(self, name, step):
        wait("installed journal " + step, lambda: self.journal(name).get("step") == step, 180)

    def start_log_capture(self):
        self.stop_log_capture()
        process = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "logs", "-f", "deployment/system-operator", "-n", "auth"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.operator_log_process = process
        def scan():
            for line in process.stdout:
                text = line.decode(errors="replace")
                self.operator_log_bytes += len(line)
                if any(value and (value in text or base64.b64encode(value.encode()).decode() in text) for value in self.sensitive) or contains_jwt(text):
                    self.operator_log_failed = True
        self.operator_log_thread = threading.Thread(target=scan, daemon=True)
        self.operator_log_thread.start()

    def stop_log_capture(self):
        if self.operator_log_process:
            self.operator_log_process.terminate()
            try:
                self.operator_log_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.operator_log_process.kill()
                self.operator_log_process.wait(timeout=10)
            self.operator_log_thread.join(timeout=10)
            self.operator_log_process.stdout.close()
            self.operator_log_process = None

    def restart(self, status_loss=None, fault=None):
        # Stop first so no previous process can repair the removed status.
        self.stop_log_capture()
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "--timeout=90s")
        if status_loss:
            self.patch("hankoserviceaccount", status_loss, {"status": None}, subresource="status")
        if hasattr(self, "api_proxy"):
            self.control("api", None)
            self.control("keycloak", None)
            if fault:
                self.control(fault[0], fault[1], reset=True)
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=1")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.start_log_capture()

    def identities(self):
        self.api("POST", "/admin/realms", {"realm": "unrelated", "enabled": True})
        self.api("POST", "/admin/realms/managed/users", {"username": "denial-target", "enabled": True})
        target = self.api("GET", "/admin/realms/managed/users?username=denial-target")[0]["id"]
        self.credentials = {}
        profiles = {"system-operator": ["manage-clients", "view-realm", "manage-authorization"],
                    "workload-observer": ["view-identity-providers", "view-realm"],
                    "workload-writer": ["manage-identity-providers", "view-realm"],
                    "workload-dependent-reader": ["view-clients"],
                    "workload-client-writer": ["manage-clients", "view-realm"]}
        profiles["system-operator"] += getattr(self, "additional_operator_roles", [])
        for name, roles in profiles.items():
            credential = self.adoption_identity(name, "managed", roles)
            self.credentials[name] = credential
            if name != "system-operator":
                self.apply(self.secret(name, {"HANKO_KEYCLOAK_URL": self.provider_url,
                    "HANKO_KC_CLIENT_ID": name, "HANKO_KC_CLIENT_SECRET": credential}))
            token = self.access_token({"client_id": name, "client_secret": credential, "grant_type": "client_credentials"})
            if name == "system-operator":
                self.api("GET", "/admin/serverinfo", token=token)
                self.record("scoped_chart_identity_serverinfo_read")
            denied = [("POST", "/admin/realms/managed/users", {"username": "forbidden"}),
                      ("GET", "/admin/realms/master/clients", None),
                      ("GET", "/admin/realms/unrelated/clients", None),
                      ("POST", f"/admin/realms/managed/users/{target}/impersonation", {})]
            if name == "workload-client-writer":
                denied += [("POST", "/admin/realms/managed/identity-provider/instances", {"alias": "forbidden", "providerId": "kubernetes"}),
                           ("GET", "/admin/realms/managed/identity-provider/instances", None)]
            for method, path, data in denied:
                self.api(method, path, data, token=token, expected=(403,))
        self.apply(self.secret("operator-credentials", {"client-id": "system-operator", "client-secret": self.credentials["system-operator"]}),
                   self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}))
        self.report["keycloak_profiles"] = profiles
        self.record("constrained_keycloak_denials")

    def trust(self):
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": self.name + "-public-discovery"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:service-account-issuer-discovery"},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:unauthenticated"}]})
        for name in ("workload-observer", "workload-writer", "workload-dependent-reader", "workload-client-writer"):
            self.apply(object_value("HankoKeycloakInstance", name, {"mode": "external", "adminRef": {"name": name}, "tlsCARef": "operator-ca"}))
        self.apply(object_value("HankoImport", "workload-source", {"sourceRef": "workload-client-writer", "realms": ["managed"],
                   "dryRun": True, "includeClients": False, "includeServiceAccounts": False, "includeIdentityProviders": False}),
                   object_value("HankoRealm", "managed", {}, labels={"hanko.sh/imported-by": "workload-source"}))
        wait("installed realm observation", lambda: self.ready("hankorealm", "managed"), 180)
        self.apply(object_value("HankoWorkloadTrust", "shared-workload", {"mode": "Manage", "realmRef": "managed",
            "sourceRef": "workload-observer", "writerRef": "workload-writer", "dependentReaderRef": "workload-dependent-reader",
            "keycloakAlias": "installed-cluster", "provider": "Kubernetes", "kubernetes": {
                "issuer": self.report["discovery"]["issuer"], "clusterAnchor": {
                    "kubeSystemNamespaceUID": self.report["cluster_namespace_uid"], "apiServerCAHash": "sha256:" + self.report["cluster_ca_sha256"]},
                "assertionMaxAgeSeconds": 600}}))
        wait("installed trust Ready", lambda: self.ready("hankoworkloadtrust", "shared-workload"), 180)
        self.record("controller_trust_ready")

    def binding(self, client=None):
        anchor = self.workload_anchors.get(client, {"account": "worker", "uid": self.worker_uid})
        return {"trustRef": "shared-workload", "sourceRef": "workload-client-writer", "workload": {
            "namespace": "workload", "serviceAccountRef": anchor["account"], "expectedUID": anchor["uid"]}, "expirationSeconds": 600}

    def create_hsa(self, name, kubernetes=True):
        # Independent fixture-administrator authorization also permits the
        # later explicitly reviewed Secret fallback; it does not activate it.
        self.approve_sensitive_writes([object_value("HankoServiceAccount", name, {"clientID": name})])
        value = {"realmRef": "managed", "clientID": name,
                 "tokenClaims": [{"name": "resource-audience", "claim": "aud", "value": "installed-api"}]}
        if kubernetes:
            value["authentication"] = {"mode": "Kubernetes", "kubernetes": self.binding(name)}
        self.apply(object_value("HankoServiceAccount", name, value))
        wait("installed HSA " + name, lambda: self.hsa_ready(name) if kubernetes else self.ready("hankoserviceaccount", name), 180)
        return self.client("managed", name)

    def workload_pod(self, name="probe", account="worker"):
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "workload", "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v" + self.args.kubernetes_version.rsplit(".", 1)[0]}}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account, "namespace": "workload"}, "automountServiceAccountToken": False},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "keycloak-ca", "namespace": "workload"},
             "data": {"ca.crt": (self.private / "tls.crt").read_text()}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "probe-code", "namespace": "workload"},
             "data": {"probe.py": (ROOT / "scripts/workload-pod-probe.py").read_text()}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "workload"}, "spec": {
                "serviceAccountName": account, "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "probe", "image": native.POD_IMAGE, "command": ["python", "-c", "import time; time.sleep(10800)"],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "assertion", "mountPath": "/var/run/hanko", "readOnly": True},
                                     {"name": "ca", "mountPath": "/ca", "readOnly": True}, {"name": "code", "mountPath": "/probe", "readOnly": True}]}],
                "volumes": [{"name": "assertion", "projected": {"sources": [{"serviceAccountToken": {
                    "audience": native.REALM_ISSUER, "expirationSeconds": 600, "path": "assertion.jwt"}}]}},
                    {"name": "ca", "configMap": {"name": "keycloak-ca"}}, {"name": "code", "configMap": {"name": "probe-code"}}]}})
        self.kubectl("wait", "--for=condition=Ready", "pod/" + name, "-n", "workload", "--timeout=180s")
        uid = self.get("serviceaccount", account, "workload")["metadata"]["uid"]
        if account == "worker":
            self.worker_uid = uid
        return {"account": account, "uid": uid, "pod": name}

    def projected(self, name="probe", namespace="workload", path="assertion.jwt"):
        token = self.kubectl("exec", "-n", namespace, name, "--", "cat", "/var/run/hanko/" + path).strip()
        self.sensitive.append(token)
        return token

    def metadata(self, name):
        account = self.get("hankoserviceaccount", name)
        prefix = "hanko.sh/workload-runtime-"
        consent = {prefix + "owner-kind": "HankoServiceAccount", prefix + "owner-namespace": "auth", prefix + "owner-name": name,
                   prefix + "owner-uid": account["metadata"]["uid"], prefix + "service-account": "worker", prefix + "service-account-uid": self.worker_uid}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "identity", "namespace": "workload",
            "labels": {"hanko.sh/runtime-target": "workload-metadata"}, "annotations": consent}, "data": {"unrelated": "preserved"}})
        self.target_uid = self.get("configmap", "identity", "workload")["metadata"]["uid"]
        self.patch("hankoserviceaccount", name, {"spec": {"runtimeMetadata": {"configMapRef": "identity", "expectedUID": self.target_uid}}})
        wait("installed metadata delivery", lambda: self.hsa_ready(name) and self.get("hankoserviceaccount", name).get("status", {}).get("runtimeMetadata", {}).get("configMapUID") == self.target_uid, 180)
        self.validate_metadata(name)

    def validate_metadata(self, name):
        account = self.get("hankoserviceaccount", name)
        cm = self.get("configmap", "identity", "workload")
        document = json.loads(cm["data"]["workload-identity.json"])
        valid = (document["schemaVersion"] == "hanko.sh/workload-runtime/v1alpha1" and document["authenticationActivation"] == "Federated"
            and document["clientID"] == name and document["assertionAudience"] == native.REALM_ISSUER
            and document["tokenEndpoint"] == native.REALM_ISSUER + "/protocol/openid-connect/token"
            and document["expirationSeconds"] == 600 and document["workload"]["expectedUID"] == self.worker_uid
            and document["bindingRevision"] == account["status"]["workloadBinding"]["bindingRevision"]
            and cm["data"]["unrelated"] == "preserved")
        native.safe_report(document, self.sensitive)
        self.record("current_runtime_metadata", valid)

    def resources(self, principal):
        self.apply_approved(object_value("HankoApplication", "installed-api", {"realmRef": "managed", "clientID": "installed-api", "type": "m2m"}))
        wait("installed resource application", lambda: self.ready("hankoapplication", "installed-api"), 180)
        self.apply(object_value("HankoResourceServer", "installed-server", {"realmRef": "managed", "applicationRef": "installed-api", "audience": "installed-api",
            "scopes": [{"name": "read"}], "resources": [{"name": name, "scopes": ["read"]} for name in ("allowed", "denied")],
            "permissions": [{"name": "worker-read", "resources": ["allowed"], "scopes": ["read"], "principals": [{"kind": "service_account", "ref": principal}]}]}))
        self.resource_ready()

    def resource_ready(self, timeout=180):
        wait("installed resource applied/read-back", lambda: self.iam_reconciled("hankoresourceserver", "installed-server"), timeout)
        status = self.get("hankoresourceserver", "installed-server")["status"]
        self.record("resource_service_account_capability", status["capabilities"]["serviceAccountPrincipals"] is True)
        client = self.client("managed", "installed-api")
        resources = self.api("GET", f'/admin/realms/managed/clients/{client["id"]}/authz/resource-server/resource')
        self.resource_ids = {item["name"]: item["_id"] for item in resources if item["name"] in ("allowed", "denied")}
        self.record("resource_ready_readback", set(self.resource_ids) == {"allowed", "denied"})

    def probe_settings(self, client, rotation=False):
        anchor = self.workload_anchors.get(client, {"account": "worker", "uid": self.worker_uid, "pod": "probe"})
        return {"issuer": native.REALM_ISSUER, "endpoint": native.REALM_ISSUER + "/protocol/openid-connect/token", "client": client,
                "namespace": "workload", "account": anchor["account"], "uid": anchor["uid"], "audience": "installed-api", "resources": self.resource_ids, "rotation": rotation}

    def pod_probe(self, client):
        pod = self.workload_anchors.get(client, {"pod": "probe"})["pod"]
        process = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "exec", "-i", "-n", "workload", pod,
            "--", "python", "/probe/probe.py"], input=json.dumps(self.probe_settings(client)).encode(), capture_output=True, timeout=60)
        results = json.loads(process.stdout[:16385])
        if process.returncode:
            decision = results.get("decision", "transport_or_input_failure")
            if not re.fullmatch(r"[a-z_]{1,64}", decision):
                decision = "withheld"
            status = results.get("http_status")
            raise ValueError("In-Pod " + decision + " (HTTP " + str(status if isinstance(status, int) else "unavailable") + ")")
        self.record("pod_client_assertion_allow_deny_" + client, all(results.get(key) is True for key in (
            "client_assertion", "access_token", "public_claims_valid", "projection_600_seconds", "resource_allowed", "resource_denied")))

    def start_rotation(self, client):
        self.rotation_process = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "exec", "-i", "-n", "workload",
            self.workload_anchors.get(client, {"pod": "probe"})["pod"], "--", "python", "/probe/probe.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.rotation_process.stdin.write(json.dumps(self.probe_settings(client, True)).encode())
        self.rotation_process.stdin.close()

    def finish_rotation(self):
        wait("real in-Pod expiry/rotation", lambda: self.rotation_process.poll() is not None, 700)
        if self.rotation_process.returncode:
            raise ValueError("In-Pod rotation/expiry probe failed (diagnostics withheld)")
        results = json.loads(self.rotation_process.stdout.read(16385))
        self.rotation_process.stdout.close()
        self.rotation_process.stderr.close()
        native.safe_report(results, self.sensitive)
        self.record("kubelet_rotation_real_expiry", all(results.get(key) is True for key in ("rotation", "old_assertion_expired_refused", "rotated_assertion_accepted")))
        self.report["rotation"] = {key: results[key] for key in ("first_iat", "first_exp", "checked_at", "elapsed_seconds")}

    def expect_auth(self, name, result, accepted=False, refused_errors=("invalid_client",)):
        self.record(name, result["http_status"] == 200 if accepted else result["http_status"] in (400, 401) and result.get("oauth_error") in refused_errors)

    def secret_value(self, client):
        value = base64.b64decode(self.get("secret", "hanko-sa-" + client)["data"]["client_secret"]).decode()
        self.sensitive.append(value)
        return value

    def native_secret(self, client):
        native_client = self.client("managed", client)
        value = self.api("GET", f'/admin/realms/managed/clients/{native_client["id"]}/client-secret')["value"]
        self.sensitive.append(value)
        if native_client["clientAuthenticatorType"] == "federated-jwt":
            self.federated_secrets[client] = value
        return value

    def secret_auth(self, client, value):
        return self.exchange({"grant_type": "client_credentials", "client_id": client, "client_secret": value})

    def negatives(self, client):
        token = self.projected()
        self.expect_auth("retained_secret_refused", self.secret_auth(client, self.native_secret(client)))
        for name, audiences in (("wrong_audience", ["https://wrong.invalid"]), ("api_only_audience", None),
                                ("multiple_audiences", [native.REALM_ISSUER, "https://wrong.invalid"])):
            minted = self.token_request(audiences=audiences)
            self.expect_auth(name, self.assertion(minted, client))
        for namespace, account, label in (("other", "worker", "wrong_namespace"), ("workload", "other", "wrong_sa"), ("workload", "default", "default_sa")):
            self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account, "namespace": namespace}, "automountServiceAccountToken": False})
            self.expect_auth(label, self.assertion(self.token_request(account, namespace, [native.REALM_ISSUER]), client))
        self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "other", "namespace": "workload"}, "automountServiceAccountToken": False})
        other_uid = self.get("serviceaccount", "other", "workload")["metadata"]["uid"]
        binding = self.binding()
        binding["workload"].update({"serviceAccountRef": "other", "expectedUID": other_uid})
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "negative-client", "namespace": "workload"},
                    "rules": [{"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["other"], "verbs": ["get"]}]},
                   {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "negative-client", "namespace": "workload"},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "negative-client"},
                    "subjects": [{"kind": "ServiceAccount", "name": "system-operator", "namespace": "auth"}]},
                   object_value("HankoServiceAccount", "other-client", {"realmRef": "managed", "clientID": "other-client",
                       "authentication": {"mode": "Kubernetes", "kubernetes": binding}}))
        wait("wrong-client positive control", lambda: self.hsa_ready("other-client"), 180)
        self.native_secret("other-client")  # Administrator-only leakage sentinel.
        self.expect_auth("wrong_client", self.assertion(token, "other-client"))
        self.expect_auth("other_client_positive_control", self.assertion(self.token_request("other", audiences=[native.REALM_ISSUER]), "other-client"), True)
        self.api("POST", "/admin/realms", {"realm": "realm-b", "enabled": True})
        self.api("POST", "/admin/realms/realm-b/identity-provider/instances", {"alias": "installed-cluster", "providerId": "kubernetes", "enabled": True,
            "config": {"issuer": self.report["discovery"]["issuer"], "fedClientAssertionMaxExp": "600"}})
        self.api("POST", "/admin/realms/realm-b/clients", {"clientId": client, "protocol": "openid-connect", "enabled": True,
            "publicClient": False, "serviceAccountsEnabled": True, "clientAuthenticatorType": "federated-jwt",
            "attributes": {"jwt.credential.issuer": "installed-cluster", "jwt.credential.sub": native.binding_subject("workload", "worker")}})
        self.expect_auth("cross_realm", self.assertion(token, client, "realm-b"))
        self.expect_auth("cross_realm_positive_control", self.assertion(self.token_request(audiences=["https://keycloak.auth.svc:8443/realms/realm-b"]), client, "realm-b"), True)
        parts = token.split(".")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        parts[2] = base64.urlsafe_b64encode(bytes([signature[0] ^ 1]) + signature[1:]).decode().rstrip("=")
        self.expect_auth("tampered_assertion", self.assertion(".".join(parts), client))
        self.foreign_cluster()
        self.expect_auth("wrong_cluster_issuer", self.assertion(self.token_request(audiences=[native.REALM_ISSUER], foreign=True), client))
        self.expect_auth("valid_after_negatives", self.assertion(self.projected(), client), True)

    def kubernetes_permissions(self):
        denied = [("create", "serviceaccounts/token"), ("create", "tokenreviews"), ("list", "serviceaccounts"), ("watch", "serviceaccounts"),
                  ("create", "configmaps"), ("delete", "configmaps")]
        denied += [(verb, resource) for verb in ("create", "update", "patch") for resource in ("pods", "deployments")]
        for verb, resource in denied:
            result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "auth", "can-i", verb, resource, "-n", "workload",
                "--as=system:serviceaccount:auth:system-operator"], capture_output=True, timeout=30, check=False)
            self.record("rbac_denies_" + verb + "_" + resource.replace("/", "_"), result.returncode == 1 and result.stdout.strip() == b"no")
        for verb, resource in (("get", "serviceaccounts/worker"), ("get", "configmaps/identity"), ("patch", "configmaps/identity")):
            self.record("rbac_named_" + verb + "_" + resource.split("/")[0], self.kubectl("auth", "can-i", verb, resource, "-n", "workload",
                "--as=system:serviceaccount:auth:system-operator").strip() == "yes")

    def two_client(self, old, old_secret, current):
        self.expect_auth("two_client_old_still_works", self.secret_auth(old, old_secret), True)
        self.pod_probe(current)
        value = self.get("hankoresourceserver", "installed-server")
        principal = value["spec"]["permissions"][0]["principals"]
        self.record("two_client_permissions_explicit", principal == [{"kind": "service_account", "ref": current}])
        # A consumer-owned pointer represents cutover; it contains no credential.
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "consumer", "namespace": "workload"}, "data": {"clientID": current}})
        self.record("two_client_consumer_cutover_review", self.get("configmap", "consumer", "workload")["data"]["clientID"] == current)
        self.kubectl("delete", "hankoserviceaccount", old, "-n", "auth", "--wait=true", "--timeout=180s")
        wait("retired canonical Secret garbage collection", lambda: not self.exists("secret", "hanko-sa-" + old), 120)
        self.record("two_client_retired_old", not self.api("GET", "/admin/realms/managed/clients?clientId=" + old))
        self.pod_probe(current)
        self.report["migrations"]["two_client"] = True

    def approve(self, name, action):
        value = self.get("hankoserviceaccount", name)["metadata"]["annotations"][JOURNAL]
        args = [self.review_tool, "--action", action]
        if action == "cleanup":
            args += ["--secret-uid", self.get("secret", "hanko-sa-" + name)["metadata"]["uid"]]
        annotation = json.loads(run(args, input=value.encode()))
        self.patch("hankoserviceaccount", name, {"metadata": {"annotations": annotation}})

    def transition(self, name, desired, request):
        authentication = {"mode": desired, "kubernetes" if desired == "Kubernetes" else "fallbackBinding": self.binding(name),
            "transition": {"strategy": "CoordinatedCutover", "requestID": request, "preparedWorkloadRevision": "installed-pod-v1"}}
        annotations = self.get("hankoserviceaccount", name)["metadata"].get("annotations", {})
        for key in ("approval", "review", "cleanup"):
            annotations["hanko.sh/workload-auth-" + key] = ""
        # One JSON Patch replaces authentication atomically, satisfying fallback CEL.
        self.kubectl("patch", "hankoserviceaccount", name, "-n", "auth", "--type=json", "-p", json.dumps([
            {"op": "add", "path": "/spec/authentication", "value": authentication},
            {"op": "add", "path": "/metadata/annotations", "value": annotations}]))
        self.stage(name, "Prepared")

    def stable_native(self, name, uuid, secret, method):
        current = self.client("managed", name)
        self.record("preserved_uuid_credential_" + name, current["id"] == uuid and current["clientAuthenticatorType"] == method
                    and current["enabled"] is True and self.native_secret(name) == secret
                    and (name not in self.preserved_themes or current.get("attributes", {}).get("login_theme") == self.preserved_themes[name]))

    def recovery_record(self, name, fault, step, before, after, counts=None):
        public_counts = {}
        for route, count in (counts or {}).items():
            if "/protocol/openid-connect/token" in route:
                continue  # Token issuance is not a provider configuration write.
            method = route.split(" ", 1)[0]
            public_counts[method] = public_counts.get(method, 0) + count
        self.report["recovery"].append({"case": name, "fault": fault, "journal_state": step, "native_before": before,
            "native_after": after, "duplicate_writes": False, "rotation": False, "result": True, "accepted_write_counts": public_counts})

    def checkpoint_restart(self, name, step, uuid, secret, method, status_loss=False):
        self.control("keycloak", None, reset=True)
        self.restart(status_loss=name if status_loss else None)
        self.stage(name, step)
        if step == "Committed":
            wait("committed current-generation readiness", lambda: self.hsa_ready(name), 180)
        self.stable_native(name, uuid, secret, method)
        counts = self.control("keycloak", None)["counts"]
        path = "/admin/realms/managed/clients/" + uuid
        self.record("restart_no_native_write_" + step, not any(count for key, count in counts.items()
            if key.split(" ", 1)[1] in (path, path + "/client-secret", "/admin/realms/managed/clients")))
        mode = "Kubernetes" if method == "federated-jwt" else "Secret"
        self.recovery_record(name, "status removed externally after stop; manager restart (not ACK loss)" if status_loss else "manager restart",
                             step, mode, mode, counts)

    def migration_roundtrip(self):
        name = "same-client"
        self.workload_anchors[name] = self.workload_pod("migration-probe", "migration-worker")
        self.create_hsa(name, False)
        uuid, secret = self.client("managed", name)["id"], self.secret_value(name)
        # Use the existing closed preservation schema. A nondefault display name
        # is deliberately outside QualifiedLeaf and blocks authentication plans.
        self.preserved_themes[name] = "keycloak.v2"
        self.api("PUT", "/admin/realms/managed/clients/" + uuid, {"attributes": {"login_theme": self.preserved_themes[name]}})
        self.expect_auth("same_client_secret_before", self.secret_auth(name, secret), True)
        # Explicit permission, independent from the two-client migration grant.
        server = self.get("hankoresourceserver", "installed-server")
        # One client policy explicitly permits either workload. Two overlapping
        # scope permissions would both participate in native UNANIMOUS evaluation.
        permissions = server["spec"]["permissions"]
        permissions[0]["principals"].append({"kind": "service_account", "ref": name})
        self.patch("hankoresourceserver", "installed-server", {"spec": {"permissions": permissions}})
        self.resource_ready()
        self.transition(name, "Kubernetes", "same-client-federated")
        self.checkpoint_restart(name, "Prepared", uuid, secret, "client-secret")
        path = "/admin/realms/managed/clients/" + uuid
        self.control("keycloak", {"method": "PUT", "path": path, "action": "lost-ack"}, reset=True)
        self.approve(name, "approval")
        fault = self.await_fault("keycloak")
        self.record("provider_accepted_response_lost", fault["upstream_status"] == 204 and fault["counts"].get("PUT " + path) == 1)
        self.restart()
        self.stage(name, "ModeApplied")
        self.stable_native(name, uuid, secret, "federated-jwt")
        state = self.control("keycloak", None)
        counts = state["counts"]
        self.record("provider_lost_ack_no_duplicate_toggle", counts.get("PUT " + path) == 1 and state["attempted_counts"].get("PUT " + path) == 1)
        self.recovery_record(name, "provider write accepted; downstream response dropped; manager restart", "Prepared", "Secret", "Kubernetes", counts)
        self.checkpoint_restart(name, "ModeApplied", uuid, secret, "federated-jwt")
        self.pod_probe(name)
        self.expect_auth("same_client_secret_inactive", self.secret_auth(name, secret))
        self.record("same_client_cleanup_waits_review", self.secret_value(name) == secret)
        self.approve(name, "review")
        self.stage(name, "AuthReviewed")
        self.checkpoint_restart(name, "AuthReviewed", uuid, secret, "federated-jwt")
        secret_path = "/api/v1/namespaces/auth/secrets/hanko-sa-" + name
        self.control("api", {"method": "PATCH", "path": secret_path, "action": "deny"}, reset=True)
        self.approve(name, "cleanup")
        self.await_fault("api")
        self.record("cleanup_patch_denied_preserves_inactive_secret", self.secret_value(name) == secret)
        self.stable_native(name, uuid, secret, "federated-jwt")
        self.restart(fault=("api", {"method": "PATCH", "path": secret_path, "action": "lost-ack"}))
        fault = self.await_fault("api")
        self.record("output_cleanup_ack_loss", fault["upstream_status"] == 200 and "client_secret" not in self.get("secret", "hanko-sa-" + name).get("data", {}))
        self.restart()
        wait("lost cleanup acknowledgement recovery", lambda: self.hsa_ready(name), 180)
        state = self.control("api", None)
        counts = state["counts"]
        self.record("cleanup_ack_loss_no_duplicate_write", counts.get("PATCH " + secret_path) == 1 and state["attempted_counts"].get("PATCH " + secret_path) == 1)
        self.recovery_record(name, "Secret field patch accepted; downstream response dropped; manager restart", "AuthReviewed", "Kubernetes", "Kubernetes", counts)
        self.checkpoint_restart(name, "Committed", uuid, secret, "federated-jwt", True)
        self.report["migrations"]["coordinated_cutover"] = True
        # Fallback stages the SAME inactive native secret before approval.
        self.control("api", {"method": "PATCH", "path": secret_path, "action": "lost-ack"}, reset=True)
        self.transition(name, "Secret", "same-client-fallback")
        fault = self.await_fault("api")
        self.record("fallback_output_accepted_ack_lost", fault["upstream_status"] == 200 and self.secret_value(name) == secret)
        self.restart()
        self.stage(name, "Prepared")
        state = self.control("api", None)
        counts = state["counts"]
        self.record("fallback_stage_no_duplicate_write", counts.get("PATCH " + secret_path) == 1 and state["attempted_counts"].get("PATCH " + secret_path) == 1)
        self.recovery_record(name, "fallback Secret patch accepted; downstream response dropped; manager restart", "Prepared", "Kubernetes", "Kubernetes", counts)
        wait("fallback staged canonical read-back", lambda: self.get("secret", "hanko-sa-" + name).get("data", {}).get("client_secret") is not None, 180)
        self.record("fallback_same_secret_staged_before_switch", self.secret_value(name) == secret and self.client("managed", name)["clientAuthenticatorType"] == "federated-jwt")
        self.approve(name, "approval")
        wait("reviewed Secret fallback", lambda: self.ready("hankoserviceaccount", name), 180)
        self.stable_native(name, uuid, secret, "client-secret")
        self.expect_auth("fallback_secret_accepted", self.secret_auth(name, secret), True)
        self.expect_auth("fallback_assertion_refused", self.assertion(self.projected(name="migration-probe"), name),
                         refused_errors=("invalid_client", "unauthorized_client"))
        self.report["migrations"]["secret_fallback"] = True
        self.transition(name, "Kubernetes", "same-client-return")
        self.approve(name, "approval")
        self.stage(name, "ModeApplied")
        self.pod_probe(name)
        self.approve(name, "review")
        self.stage(name, "AuthReviewed")
        hsa_path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankoserviceaccounts/" + name
        self.control("api", {"method": "PATCH", "path": hsa_path, "step": "OutputsCleaned", "action": "gate"})
        self.approve(name, "cleanup")
        self.await_fault("api")
        self.stage(name, "OutputsCleaned")
        self.control("keycloak", None, reset=True)
        self.restart()
        wait("OutputsCleaned restart commits", lambda: self.hsa_ready(name), 180)
        self.stable_native(name, uuid, secret, "federated-jwt")
        counts = self.control("keycloak", None)["counts"]
        self.record("restart_no_native_write_OutputsCleaned", counts.get("PUT " + path, 0) == 0
            and counts.get("POST " + path + "/client-secret", 0) == 0 and counts.get("POST /admin/realms/managed/clients", 0) == 0)
        self.pod_probe(name)
        self.recovery_record(name, "accepted OutputsCleaned checkpoint; external API gate; manager restart", "OutputsCleaned", "Kubernetes", "Kubernetes", counts)
        self.report["migrations"].update({"return_to_kubernetes": True, "uuid_preservation": True, "credential_continuity": True})

    def binding_failures(self, name):
        uuid, secret = self.client("managed", name)["id"], self.native_secret(name)
        path = "/api/v1/namespaces/workload/configmaps/identity"
        for action, status in (("deny", None), ("resource-version-conflict", 409), ("lost-ack", 200)):
            self.control("api", {"method": "PATCH", "path": path, "action": action}, reset=True)
            self.patch("configmap", "identity", {"data": {"workload-identity.json": "{}"}}, "workload")
            fault = self.await_fault("api")
            self.record("configmap_fault_" + action, fault["upstream_status"] == status)
            self.stable_native(name, uuid, secret, "federated-jwt")
            self.restart()
            wait("ConfigMap transport recovery", lambda: self.hsa_ready(name) and self.get("configmap", "identity", "workload")["data"].get("workload-identity.json") != "{}", 180)
            state = self.control("api", None)
            counts = state["counts"]
            phases = state["metadata_activations"].get("PATCH " + path, {})
            # Invalidated binding evidence may require a passive document before
            # active read-back. Those two distinct publications are not a replay
            # of the same output write, and neither changes native authentication.
            self.record("configmap_no_duplicate_activation_write_" + action, phases.get("Federated") == 1
                and phases.get("ManagedSeparately", 0) <= 1 and counts.get("PATCH " + path) == sum(phases.values()))
            self.validate_metadata(name)
            self.recovery_record(name, "runtime ConfigMap " + action + "; manager restart", "Committed", "Kubernetes", "Kubernetes", counts)
        before = self.get("configmap", "identity", "workload")
        consent = before["metadata"]["annotations"]
        key = "hanko.sh/workload-runtime-owner-uid"
        self.patch("configmap", "identity", {"metadata": {"annotations": {key: None}}}, "workload")
        wait("removed runtime consent blocks delivery", lambda: not self.hsa_ready(name), 180)
        self.stable_native(name, uuid, secret, "federated-jwt")
        self.record("consent_loss_preserves_last_known_output", self.get("configmap", "identity", "workload")["data"] == before["data"])
        self.patch("configmap", "identity", {"metadata": {"annotations": {key: consent[key]}}}, "workload")
        wait("restored consent convergence", lambda: self.hsa_ready(name), 180)
        # Immutable target with tampered public data cannot be repaired. Its UID
        # replacement also remains unauthorized until the owner pins the new UID.
        self.patch("configmap", "identity", {"data": {"workload-identity.json": "{}"}, "immutable": True}, "workload")
        wait("immutable target fails closed", lambda: not self.hsa_ready(name), 180)
        self.stable_native(name, uuid, secret, "federated-jwt")
        self.kubectl("delete", "configmap", "identity", "-n", "workload", "--wait=true")
        replacement = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "identity", "namespace": "workload",
            "labels": before["metadata"]["labels"], "annotations": consent}, "data": {"unrelated": "preserved"}}
        self.apply(replacement)
        replacement_uid = self.get("configmap", "identity", "workload")["metadata"]["uid"]
        self.record("runtime_target_uid_replaced", replacement_uid != self.target_uid)
        self.restart()
        wait("replacement UID is not approved", lambda: not self.hsa_ready(name), 180)
        self.record("no_implicit_target_acquisition", "workload-identity.json" not in self.get("configmap", "identity", "workload").get("data", {}))
        self.stable_native(name, uuid, secret, "federated-jwt")
        self.patch("hankoserviceaccount", name, {"spec": {"runtimeMetadata": {"expectedUID": replacement_uid}}})
        wait("replacement edit retains cleanup conflict", lambda: any(c.get("reason") == "CleanupConflict" for c in self.get("hankoserviceaccount", name).get("status", {}).get("conditions", [])), 180)
        self.record("replacement_uid_edit_does_not_erase_old_cleanup_authority", "workload-identity.json" not in self.get("configmap", "identity", "workload").get("data", {}))
        # Retire the absent old target through the controller's normal cleanup
        # path, then obtain fresh consent for a new object. Never delete or forge
        # its durable journal to bypass a replacement conflict.
        self.kubectl("delete", "configmap", "identity", "-n", "workload", "--wait=true")
        self.patch("hankoserviceaccount", name, {"spec": {"runtimeMetadata": None}})
        wait("absent runtime target journal retires safely", lambda: "hanko.sh/workload-runtime-journal" not in self.get("hankoserviceaccount", name)["metadata"].get("annotations", {}) and self.hsa_ready(name), 180)
        self.apply(replacement)
        replacement_uid = self.get("configmap", "identity", "workload")["metadata"]["uid"]
        self.patch("hankoserviceaccount", name, {"spec": {"runtimeMetadata": {"configMapRef": "identity", "expectedUID": replacement_uid}}})
        wait("explicit replacement target approval", lambda: self.hsa_ready(name), 180)
        self.target_uid = replacement_uid
        self.validate_metadata(name)
        self.record("runtime_failures_no_auth_switch_rotation")

    def wait_binding_invalidated(self, name):
        def invalidated():
            account = self.get("hankoserviceaccount", name)
            status = account.get("status", {})
            rejected = {condition["type"] for condition in status.get("conditions", [])
                        if condition.get("status") == "False"
                        and condition.get("observedGeneration") == account["metadata"]["generation"]}
            return (not status.get("workloadBinding") and not status.get("runtimeMetadata")
                    and {"WorkloadBindingReady", "FederatedModeApplied", "Synced"} <= rejected)
        # A reconcile already in flight can first mark its authentication
        # transaction stale while retaining binding evidence from its snapshot.
        # Wait for the next fresh read to invalidate that evidence completely.
        wait("outage invalidates fresh binding evidence", invalidated, 180)

    def prerequisites(self, name, old, old_secret):
        before = self.client("managed", name)
        secret = self.native_secret(name)
        output = self.get("configmap", "identity", "workload")["data"]
        # A controlled upstream Service outage leaves administrator access on
        # its original Pod port-forward available for independent inspection.
        self.patch("service", "keycloak-upstream", {"spec": {"selector": {"app": "provider-outage"}}})
        self.wait_binding_invalidated(name)
        self.record("provider_outage_fail_closed", not self.get("hankoserviceaccount", name).get("status", {}).get("workloadBinding")
            and self.get("configmap", "identity", "workload")["data"] == output)
        self.expect_auth("pre_retirement_failure_keeps_secret_a", self.secret_auth(old, old_secret), True)
        self.patch("service", "keycloak-upstream", {"spec": {"selector": {"app": "keycloak"}}})
        wait("provider outage recovers", lambda: self.hsa_ready(name), 180)
        self.stable_native(name, before["id"], secret, "federated-jwt")
        self.record("provider_outage_preserves_output")
        # A shared age generation change is independently reviewed; no HSA may
        # update it or silently clamp its declared projection age.
        self.patch("hankoworkloadtrust", "shared-workload", {"spec": {"kubernetes": {"assertionMaxAgeSeconds": 900}}})
        wait("shared age awaits explicit inventory review", lambda: any(c.get("reason") == "SharedAgeReviewRequired"
            for c in self.get("hankoworkloadtrust", "shared-workload").get("status", {}).get("conditions", [])), 180)
        wait("incompatible stale binding refuses progression", lambda: not self.hsa_ready(name), 180)
        provider = self.api("GET", "/admin/realms/managed/identity-provider/instances/installed-cluster")
        self.record("no_silent_shared_age_update_or_clamp", provider["config"]["fedClientAssertionMaxExp"] == "600"
            and self.get("hankoworkloadtrust", "shared-workload")["spec"]["kubernetes"]["assertionMaxAgeSeconds"] == 900
            and self.get("hankoserviceaccount", name)["spec"]["authentication"]["kubernetes"]["expirationSeconds"] == 600)
        self.patch("hankoworkloadtrust", "shared-workload", {"spec": {"kubernetes": {"assertionMaxAgeSeconds": 600}}})
        wait("restored shared trust", lambda: self.ready("hankoworkloadtrust", "shared-workload"), 180)
        # Reaffirm the same workload UID with an explicit owner spec generation;
        # the old generation's sealed authentication journal is stale after a
        # shared trust generation change, even if its values are restored.
        self.patch("hankoserviceaccount", name, {"spec": {"attributes": {"login_theme": "keycloak"}}})
        wait("owner reaffirmed binding after trust restoration", lambda: self.hsa_ready(name), 180)
        executions = self.api("GET", "/admin/realms/managed/authentication/flows/clients/executions")
        execution = next(item for item in executions if item.get("providerId") == "federated-jwt")
        self.workload_anchors["blocked-flow"] = self.workload_pod("flow-probe", "flow-worker")
        disabled = {**execution, "requirement": "DISABLED"}
        self.api("PUT", "/admin/realms/managed/authentication/flows/clients/executions", disabled)
        self.apply(object_value("HankoServiceAccount", "blocked-flow", {"realmRef": "managed", "clientID": "blocked-flow",
            "authentication": {"mode": "Kubernetes", "kubernetes": self.binding("blocked-flow")}}))
        wait("effective flow blocks activation", lambda: self.get("hankoserviceaccount", "blocked-flow").get("status", {}).get("phase") == "Error", 180)
        self.record("controller_does_not_repair_flow", next(item for item in self.api("GET", "/admin/realms/managed/authentication/flows/clients/executions")
            if item.get("providerId") == "federated-jwt")["requirement"] == "DISABLED"
            and not self.api("GET", "/admin/realms/managed/clients?clientId=blocked-flow"))
        self.api("PUT", "/admin/realms/managed/authentication/flows/clients/executions", execution)
        wait("administrator-restored flow converges", lambda: self.hsa_ready(name) and self.hsa_ready("blocked-flow"), 180)
        self.native_secret("blocked-flow")
        self.pod_probe(name)
        self.record("effective_flow_prerequisite_recovery")

    def foreign_objects(self):
        self.api("POST", "/admin/realms/managed/clients", {"clientId": "foreign-client", "enabled": True, "publicClient": True, "name": "Independent"})
        self.api("POST", "/admin/realms/managed/identity-provider/instances", {"alias": "foreign-idp", "providerId": "oidc", "enabled": False,
            "config": {"clientId": "independent"}})
        self.foreign_client = self.client("managed", "foreign-client")
        self.foreign_idp = self.api("GET", "/admin/realms/managed/identity-provider/instances/foreign-idp")

    def provider_create_ack_loss(self):
        name, path = "create-ack-client", "/admin/realms/managed/clients"
        self.workload_anchors[name] = self.workload_pod("creation-probe", "creation-worker")
        self.control("keycloak", {"method": "POST", "path": path, "action": "lost-ack"}, reset=True)
        self.apply(object_value("HankoServiceAccount", name, {"realmRef": "managed", "clientID": name,
            "authentication": {"mode": "Kubernetes", "kubernetes": self.binding(name)}}))
        fault = self.await_fault("keycloak")
        journal = self.journal(name)
        uuid = self.client("managed", name)["id"]
        self.record("provider_create_accepted_ack_lost", fault["upstream_status"] == 201 and journal["step"] == "Prepared"
                    and journal["attempted"] is True and journal["clientUUID"] == uuid)
        secret = self.native_secret(name)
        self.restart()
        wait("reserved provider CREATE recovery", lambda: self.hsa_ready(name), 180)
        state = self.control("keycloak", None)
        counts = state["counts"]
        self.record("no_duplicate_create_or_rotation", counts.get("POST " + path) == 1 and state["attempted_counts"].get("POST " + path) == 1
                    and counts.get("POST " + path + "/" + uuid + "/client-secret", 0) == 0)
        self.stable_native(name, uuid, secret, "federated-jwt")
        self.expect_auth("created_client_real_projected_assertion", self.assertion(self.projected(name="creation-probe"), name), True)
        self.recovery_record(name, "provider CREATE accepted; downstream response dropped; reserved-UUID restart recovery", "Prepared", "Absent", "Kubernetes", counts)

    def cleanup_recovery(self):
        name = "same-client"
        uuid = self.client("managed", name)["id"]
        secret = self.native_secret(name)
        native_path = "/admin/realms/managed/clients/" + uuid
        server = self.get("hankoresourceserver", "installed-server")
        permissions = server["spec"]["permissions"]
        for permission in permissions:
            permission["principals"] = [p for p in permission["principals"] if p["ref"] != name]
        self.patch("hankoresourceserver", "installed-server", {"spec": {"permissions": permissions}})
        self.resource_ready()
        # Status acknowledgement loss is an actual successful API PATCH whose
        # downstream response is dropped; it differs from status removal.
        path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankoserviceaccounts/" + name
        self.control("keycloak", None, reset=True)
        self.control("api", {"method": "PATCH", "path": path + "/status", "action": "lost-ack"}, reset=True)
        self.patch("hankoserviceaccount", name, {"status": None}, subresource="status")
        self.stop_log_capture()
        self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.start_log_capture()
        self.await_fault("api")
        self.restart()
        wait("accepted status patch recovery", lambda: self.hsa_ready(name), 180)
        self.stable_native(name, uuid, secret, "federated-jwt")
        counts = self.control("keycloak", None)["counts"]
        self.record("status_patch_ack_loss_recovered", counts.get("PUT " + native_path, 0) == 0
            and counts.get("POST " + native_path + "/client-secret", 0) == 0 and counts.get("POST /admin/realms/managed/clients", 0) == 0)
        self.recovery_record(name, "status PATCH accepted; downstream response dropped; restart", "Committed", "Kubernetes", "Kubernetes", counts)
        # Block finalizer response after upstream accepted the finalizer UPDATE.
        self.control("keycloak", None, reset=True)
        self.control("api", {"method": "PUT", "path": path, "action": "lost-ack"}, reset=True)
        self.kubectl("delete", "hankoserviceaccount", name, "-n", "auth", "--wait=false")
        fault = self.await_fault("api")
        self.record("finalizer_update_ack_lost", fault["upstream_status"] == 200)
        self.restart()
        wait("finalizer recovery removes child", lambda: not self.exists("hankoserviceaccount", name), 180)
        state = self.control("keycloak", None)
        counts = state["counts"]
        api_state = self.control("api", None)
        self.record("deleted_client_not_recreated", not self.api("GET", "/admin/realms/managed/clients?clientId=" + name)
            and counts.get("DELETE " + native_path) == 1 and state["attempted_counts"].get("DELETE " + native_path) == 1
            and counts.get("POST /admin/realms/managed/clients", 0) == 0 and counts.get("POST " + native_path + "/client-secret", 0) == 0
            and api_state["counts"].get("PUT " + path) == 1
            # Rejected resourceVersion attempts before acceptance are ordinary
            # retries. No further PUT may occur after the accepted lost ACK.
            and api_state["attempted_counts"].get("PUT " + path) == fault["attempted_counts"].get("PUT " + path))
        self.record("foreign_preservation", self.client("managed", "foreign-client") == self.foreign_client
            and self.api("GET", "/admin/realms/managed/identity-provider/instances/foreign-idp") == self.foreign_idp)
        self.recovery_record(name, "finalizer UPDATE accepted; downstream response dropped; restart", "Committed", "Kubernetes", "Absent", counts)

    def setup_proxy(self, name, upstream, ca, port, tls_secret="keycloak-tls"):
        settings = {"port": port, "upstream": upstream, "ca": "/fixture/ca.crt"}
        labels = {"app": "keycloak", "hanko-fixture": name} if name == "fault-keycloak" else {"app": name}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "auth"}, "data": {
            "proxy.py": (ROOT / "scripts/workload-fault-proxy.py").read_text(), "settings.json": json.dumps(settings), "ca.crt": ca}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "auth", "labels": labels}, "spec": {
                "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "proxy", "image": native.POD_IMAGE, "command": ["python", "/fixture/proxy.py"],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}, {"name": "tls", "mountPath": "/tls", "readOnly": True}]}],
                "volumes": [{"name": "fixture", "configMap": {"name": name}}, {"name": "tls", "secret": {"secretName": tls_secret, "defaultMode": 288}}]}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": "auth"},
             "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]}})
        self.kubectl("wait", "--for=condition=Ready", "pod/" + name, "-n", "auth", "--timeout=180s")
        log = self.private / (name + "-forward.log")
        stream = log.open("wb")
        process = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "port-forward", "-n", "auth", "pod/" + name,
            ":" + str(port), "--address", "127.0.0.1"], stdout=stream, stderr=subprocess.STDOUT)
        self.proxy_forwards.append((process, stream))
        wait("fault proxy forwarding", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()), 30)
        return "https://localhost:" + re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]

    def fault_proxies(self):
        provider = json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app=keycloak", "-o", "json"))["items"][0]
        self.patch("pod", provider["metadata"]["name"], {"metadata": {"labels": {"hanko-fixture": "keycloak-upstream"}}})
        self.apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "keycloak-upstream", "namespace": "auth"},
            "spec": {"selector": {"app": "keycloak", "hanko-fixture": "keycloak-upstream"}, "ports": [{"port": 8443, "targetPort": 8443}]}})
        self.keycloak_proxy = self.setup_proxy("fault-keycloak", "https://keycloak-upstream.auth.svc:8443", (self.private / "tls.crt").read_text(), 8443)
        self.patch("service", "keycloak", {"spec": {"selector": {"app": "keycloak", "hanko-fixture": "fault-keycloak"}}})
        ca = self.get("configmap", "kube-root-ca.crt")["data"]["ca.crt"]
        # The proxy endpoint uses a disposable cluster-CA-signed certificate so
        # the actual API CA DER anchor remains unchanged. Keys are private temp
        # inputs/fixture TLS Secrets, excluded from evidence and diagnostics.
        ca_path, key_path = self.private / "api-ca.crt", self.private / "api-ca.key"
        ca_path.write_text(ca)
        key_path.write_text(run(["docker", "exec", self.name + "-control-plane", "cat", "/etc/kubernetes/pki/ca.key"]))
        key_path.chmod(0o600)
        key, csr, cert = (self.private / name for name in ("proxy-api.key", "proxy-api.csr", "proxy-api.crt"))
        run([self.args.openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
            "-subj", "/CN=fault-api.auth.svc", "-addext", "subjectAltName=DNS:fault-api.auth.svc,DNS:localhost"])
        run([self.args.openssl, "x509", "-req", "-in", csr, "-CA", ca_path, "-CAkey", key_path, "-CAcreateserial", "-out", cert,
            "-days", str(getattr(self, "certificate_days", 1)), "-sha256", "-copy_extensions", "copy"])
        self.apply(self.secret("fixture-api-tls", {"tls.crt": cert.read_text(), "tls.key": key.read_text()}))
        self.api_proxy = self.setup_proxy("fault-api", "https://kubernetes.default.svc", ca, 8444, "fixture-api-tls")
        self.api_proxy_context = ssl.create_default_context(cafile=str(ca_path))

    def configure_api_proxy(self):
        # Test-only transport configuration supplied externally after Helm install.
        # No new API, chart field or production environment feature is introduced.
        self.stop_log_capture()
        self.apply({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "fixture-api-proxy", "namespace": "auth"},
            "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "system"}}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "fault-api"}}}], "ports": [{"protocol": "TCP", "port": 8444}]}]}})
        config = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "fixture", "cluster": {
            "server": "https://fault-api.auth.svc:8444", "certificate-authority": "/fixture-api/ca.crt"}}],
            "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "operator"}}], "current-context": "fixture",
            "users": [{"name": "operator", "user": {"tokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token"}}]}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-api", "namespace": "auth"},
            "data": {"kubeconfig": yaml.safe_dump(config), "ca.crt": self.get("configmap", "kube-root-ca.crt")["data"]["ca.crt"]}})
        deployment = self.get("deployment", "system-operator")
        pod = deployment["spec"]["template"]["spec"]
        pod["volumes"].append({"name": "fixture-api", "configMap": {"name": "fixture-api"}})
        pod["containers"][0]["env"].append({"name": "KUBECONFIG", "value": "/fixture-api/kubeconfig"})
        pod["containers"][0]["volumeMounts"].append({"name": "fixture-api", "mountPath": "/fixture-api", "readOnly": True})
        self.patch("deployment", "system-operator", {"spec": {"template": {"spec": pod}}})
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.start_log_capture()

    def control(self, target, rule, reset=False, *, track_document=None):
        url = getattr(self, target + "_proxy") + "/__fixture/control"
        context = self.api_proxy_context if target == "api" else self.http
        value = {"rule": rule, "reset_counts": reset}
        if track_document is not None:
            value["track_document"] = track_document
        with urlopen(Request(url, data=json.dumps(value).encode()), context=context, timeout=10) as response:
            return json.load(response)

    def observe_control(self, target):
        """Observe a fault without releasing it or changing its counters."""
        url = getattr(self, target + "_proxy") + "/__fixture/control"
        context = self.api_proxy_context if target == "api" else self.http
        with urlopen(url, context=context, timeout=10) as response:
            return json.load(response)

    def await_fault(self, target):
        url = getattr(self, target + "_proxy") + "/__fixture/control"
        context = self.api_proxy_context if target == "api" else self.http
        def triggered():
            with urlopen(url, context=context, timeout=10) as response:
                return json.load(response)["triggered"]
        wait("external deterministic fault", triggered, 180)
        with urlopen(url, context=context, timeout=10) as response:
            state = json.load(response)
        # Bounded diagnostic: no request/response body, token or native path.
        print("External fault: " + target + " " + state["rule"]["action"]
              + " upstream_status=" + str(state["upstream_status"]), flush=True)
        return state

    def containment(self, client):
        self.pod_probe(client)
        before = self.client("managed", client)
        self.api("PUT", "/admin/realms/managed/clients/" + before["id"], {"name": "Preserved display"})
        before = self.client("managed", client)
        metadata = self.get("configmap", "identity", "workload")["data"]
        old_uid = self.worker_uid
        # Freeze reconciliation to measure Keycloak's native name-based limit
        # independently before allowing Hanko asynchronous containment.
        self.stop_log_capture()
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "--timeout=90s")
        old = self.projected()
        self.kubectl("delete", "serviceaccount", "worker", "-n", "workload", "--wait=true")
        self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "worker", "namespace": "workload"}, "automountServiceAccountToken": False})
        new_uid = self.get("serviceaccount", "worker", "workload")["metadata"]["uid"]
        self.record("recreated_service_account_distinct_uid", new_uid != old_uid)
        new = self.token_request(audiences=[native.REALM_ISSUER])
        self.expect_auth("native_old_uid_name_acceptance", self.assertion(old, client), True)
        self.expect_auth("native_new_uid_name_acceptance", self.assertion(new, client), True)
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=1")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.start_log_capture()
        def contained():
            current = self.get("hankoserviceaccount", client)
            generation = current["metadata"]["generation"]
            invalidated = {c["type"] for c in current.get("status", {}).get("conditions", [])
                if c.get("status") == "False" and c.get("observedGeneration") == generation}
            return (not current.get("status", {}).get("workloadBinding") and not current.get("status", {}).get("runtimeMetadata")
                and {"WorkloadBindingReady", "FederatedModeApplied"} <= invalidated and self.client("managed", client)["enabled"] is False)
        wait("UID-bound owned-client containment", contained, 180)
        before["enabled"] = False
        self.record("containment_preserves_independent_fields", before == self.client("managed", client) and metadata == self.get("configmap", "identity", "workload")["data"])
        self.expect_auth("contained_client_refuses_new_assertion", self.assertion(new, client))
        # Even changing expectedUID without a new reviewed transaction is insufficient.
        self.patch("hankoserviceaccount", client, {"spec": {"authentication": {"kubernetes": {"workload": {"expectedUID": new_uid}}}, "runtimeMetadata": None}})
        self.restart()
        wait("new UID without review remains blocked", lambda: self.get("hankoserviceaccount", client).get("status", {}).get("observedGeneration") == self.get("hankoserviceaccount", client)["metadata"]["generation"], 180)
        self.record("no_automatic_reactivation", self.client("managed", client)["enabled"] is False and not self.ready("hankoserviceaccount", client))
        self.report["uid_hashes"] = {"before": hashlib.sha256(old_uid.encode()).hexdigest(), "after": hashlib.sha256(new_uid.encode()).hexdigest()}

    def leak_scan(self):
        self.stop_log_capture()
        self.record("operator_logs_including_retired_pods_no_credentials", not self.operator_log_failed and self.operator_log_bytes > 0)
        for namespace in ("auth", "workload", "other"):
            text = self.kubectl("get", "events,configmaps", "-n", namespace, "-o", "json")
            pods = json.loads(self.kubectl("get", "pods", "-n", namespace, "-o", "json"))["items"]
            text += json.dumps(pods)
            for pod in pods:
                text += self.kubectl("logs", pod["metadata"]["name"], "-n", namespace)
            for crd in json.loads(self.kubectl("get", "crds", "-o", "json"))["items"]:
                if crd["spec"]["group"] == "hanko.sh":
                    text += self.kubectl("get", crd["metadata"]["name"], "-n", namespace, "-o", "json")
            sensitive = self.sensitive + [base64.b64encode(value.encode()).decode() for value in self.sensitive if value]
            native.safe_report({"surface": text}, sensitive)
        # Never dump Secrets. Decode only in memory, reject any workload Secret.
        self.record("no_workload_secret", not json.loads(self.kubectl("get", "secrets", "-n", "workload", "-o", "json"))["items"])
        objects = json.loads(self.kubectl("get", "secrets,configmaps", "-A", "-o", "json"))["items"]
        for item in objects:
            values = [base64.b64decode(value).decode(errors="replace") for value in item.get("data", {}).values()] if item["kind"] == "Secret" else list(item.get("data", {}).values())
            values += [base64.b64decode(value).decode(errors="replace") for value in item.get("binaryData", {}).values()]
            values += [json.dumps(item.get("metadata", {})), json.dumps(item.get("stringData", {}))]
            if any(contains_jwt(value) for value in values):
                raise ValueError("JWT stored in Kubernetes fixture object (withheld)")
            if any(credential in value or base64.b64encode(credential.encode()).decode() in value
                   for credential in self.federated_secrets.values() for value in values):
                raise ValueError("Kubernetes-mode native credential stored in fixture object (withheld)")
        for pod in json.loads(self.kubectl("get", "pods", "-n", "workload", "-o", "json"))["items"]:
            self.record("no_workload_credential_mount", all("secret" not in volume for volume in pod["spec"]["volumes"])
                and all(not container.get("env") and not container.get("envFrom") for container in pod["spec"]["containers"]))
        native.safe_report(self.public_evidence(), self.sensitive)
        self.record("no_jwt_credential_leakage")
        self.report["hub_payloads_inspected"] = 0  # Hub is disabled; no payload exists in this fixture.

    def public_evidence(self):
        keys = ("schema_version", "layer", "keycloak_version", "kubernetes_version", "publishable", "complete", "started_at", "completed_at",
                "fixture_sha256", "node_image", "node_build", "keycloak_image", "revision", "image_digest", "checks", "deep_migration", "recovery",
                "migrations", "keycloak_profiles", "rotation", "uid_hashes", "hub_payloads_inspected", "failure_status")
        return {key: self.report[key] for key in keys if key in self.report}

    def failure_evidence(self):
        # Reuse the bounded, redacted snapshot already collected before teardown.
        # Do not start another series of API waits while the cluster is failing.
        directory = self.args.output.with_suffix(".diagnostics")
        records = {}
        for kind, names in (("hankorealms", ("managed",)), ("hankoworkloadtrusts", ("shared-workload",)),
                            ("hankoserviceaccounts", ("secret-a", "federated-b", "same-client", "blocked-flow")),
                            ("hankoresourceservers", ("installed-server",))):
            try:
                path = directory / (kind + ".hanko.sh.yaml")
                if path.stat().st_size > system.diagnostics.FILE_LIMIT:
                    raise ValueError("Diagnostic file exceeds budget")
                items = yaml.safe_load(path.read_text()).get("items", [])
            except Exception:
                items = []
            for name in names:
                value = next((item for item in items if item.get("metadata", {}).get("name") == name
                              and item["metadata"].get("namespace") == "auth"), None)
                if value is None:
                    records[name] = {"unavailable": True}
                    continue
                status = value.get("status", {})
                records[name] = {"generation": value["metadata"].get("generation", 0), "observed_generation": status.get("observedGeneration", 0),
                    "phase": status.get("phase", "Pending"), "conditions": [{"type": item.get("type"), "status": item.get("status"),
                        "reason": item.get("reason") if re.fullmatch(r"[A-Za-z0-9]{1,64}", item.get("reason", "")) else "Withheld"}
                        for item in status.get("conditions", [])]}
        native.safe_report(records, self.sensitive)
        self.report["failure_status"] = records

    def qualify_installed(self):
        self.create_cluster()
        self.record("exact_kubernetes_version")
        self.mirror_scanned_image()
        self.keycloak()
        info = self.api("GET", "/admin/serverinfo")
        self.record("exact_keycloak_version", info["systemInfo"]["version"] == self.args.keycloak_version)
        self.provider_url = "https://keycloak.auth.svc:8443"
        if self.args.deep_migration:
            self.fault_proxies()
        self.identities()
        self.install()
        self.start_log_capture()
        self.record("exact_scanned_image_installed")
        if self.args.deep_migration:
            self.configure_api_proxy()
            self.foreign_objects()
        self.trust()
        self.workload_anchors["federated-b"] = self.workload_pod()
        self.create_hsa("secret-a", False)
        old_secret = self.secret_value("secret-a")
        self.expect_auth("secret_a_before_migration", self.secret_auth("secret-a", old_secret), True)
        self.create_hsa("federated-b")
        self.record("separate_native_client_uuids", self.client("managed", "secret-a")["id"] != self.client("managed", "federated-b")["id"])
        self.metadata("federated-b")
        self.resources("federated-b")
        self.pod_probe("federated-b")
        self.negatives("federated-b")
        self.kubernetes_permissions()
        if self.args.deep_migration:
            self.prerequisites("federated-b", "secret-a", old_secret)
            self.binding_failures("federated-b")
            self.provider_create_ack_loss()
        self.two_client("secret-a", old_secret, "federated-b")
        if self.args.deep_migration:
            self.review_tool = self.private / "workload-auth-review"
            run(["go", "build", "-o", self.review_tool, "./scripts/workload-auth-review"], timeout=180)
            self.migration_roundtrip()
            self.cleanup_recovery()
        self.start_rotation("federated-b")
        self.finish_rotation()
        self.containment("federated-b")
        self.snapshot_isolation()
        self.leak_scan()
        self.report["complete"] = True
        self.report["completed_at"] = datetime.now(timezone.utc).isoformat()

    def snapshot_isolation(self):
        for scope in ("unlabelled", "empty", "tenant-a", "tenant-b"):
            name = "snapshot-" + scope
            labels = {} if scope == "unlabelled" else {"hanko.sh/tenant": "" if scope == "empty" else scope}
            realm = object_value("HankoRealm", name, {}, labels={**labels, "hanko.sh/imported-by": "fixture-observe"})
            self.apply(realm,
                object_value("HankoApplication", name, {"realmRef": name, "clientID": name, "type": "spa", "mode": "Observe"}, labels=labels),
                object_value("HankoServiceAccount", name, {"realmRef": name, "clientID": name, "mode": "Observe"}, labels=labels),
                object_value("HankoIssuer", name, {"realmRef": name, "host": name + ".example.test"}, labels=labels),
                object_value("HankoKeycloakInstance", name, {"mode": "external", "adminRef": {"name": "workload-observer"}, "tlsCARef": "operator-ca"}, labels=labels))
        for scope in ("unlabelled", "empty", "tenant-a", "tenant-b"):
            name = "snapshot-" + scope
            labels = {} if scope == "unlabelled" else {"hanko.sh/tenant": "" if scope == "empty" else scope}
            lost_ack = scope == "tenant-a" and self.args.deep_migration
            if lost_ack:
                path = "/api/v1/namespaces/auth/configmaps"
                self.control("api", {"method": "POST", "path": path, "action": "lost-ack"}, reset=True)
            self.apply(object_value("HankoSnapshot", name, {"instanceRef": name}, labels=labels))
            self.approve_lifecycle("hankosnapshot", name, "auth", operator_name="system-operator")
            self.record("snapshot_independent_approval_" + scope)
            captured = None
            if lost_ack:
                fault = self.await_fault("api")
                self.record("snapshot_capture_ack_loss_accepted", fault["upstream_status"] == 201)
                captured = self.get("configmap", "snap-" + name + "-config")
                self.restart()
            wait("installed scoped snapshot " + scope, lambda name=name: self.get("hankosnapshot", name).get("status", {}).get("phase") == "Done", 180)
            snapshot = self.get("hankosnapshot", name)
            capture = self.get("configmap", snapshot["status"]["configMapRef"])
            self.record("snapshot_scope_" + scope, snapshot_capture_valid(snapshot, capture, name))
            if lost_ack:
                state = self.control("api", None)
                self.record("snapshot_capture_restart_no_recreate", capture["metadata"]["uid"] == captured["metadata"]["uid"]
                    and capture["data"] == captured["data"] and state["counts"].get("POST " + path) == 1
                    and state["attempted_counts"].get("POST " + path) == 1)
        if self.args.deep_migration:
            self.legacy_snapshot_recovery()

    def legacy_snapshot_recovery(self):
        # Pause the real manager after its authority checkpoint and before the
        # capture write. Seed a historical immutable capture through the fixture
        # administrator, then let a fresh manager inspect it without alteration.
        name, path = "legacy-cross-tenant", "/api/v1/namespaces/auth/configmaps"
        self.control("api", {"method": "POST", "path": path, "action": "deny"}, reset=True)
        self.apply(object_value("HankoSnapshot", name, {"instanceRef": "snapshot-tenant-a"}, labels={"hanko.sh/tenant": "tenant-a"}))
        self.approve_lifecycle("hankosnapshot", name, "auth", operator_name="system-operator")
        self.record("snapshot_legacy_independent_approval")
        self.await_fault("api")
        snapshot = self.get("hankosnapshot", name)
        self.record("snapshot_legacy_authority_persisted", bool(snapshot.get("status", {}).get("intentHash")))
        self.stop_log_capture()
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "--timeout=90s")
        raw = json.dumps({kind: [self.get(resource, "snapshot-tenant-b")] for kind, resource in (
            ("realms", "hankorealm"), ("applications", "hankoapplication"),
            ("serviceAccounts", "hankoserviceaccount"), ("issuers", "hankoissuer"))})
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": "snap-" + name + "-config", "namespace": "auth", "labels": {"hanko.sh/tenant": "tenant-a"},
            "annotations": {"hanko.sh/snapshot-intent": snapshot["status"]["intentHash"], "hanko.sh/snapshot-hash": hashlib.sha256(raw.encode()).hexdigest()},
            "ownerReferences": [{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoSnapshot", "name": name, "uid": snapshot["metadata"]["uid"], "controller": True}]},
            "immutable": True, "data": {"snapshot.json": raw}})
        capture = self.get("configmap", "snap-" + name + "-config")
        self.restart()
        wait("legacy cross-tenant snapshot refusal", lambda: self.get("hankosnapshot", name).get("status", {}).get("phase") == "Failed", 180)
        status = self.get("hankosnapshot", name)["status"]
        stored = self.get("configmap", capture["metadata"]["name"])
        self.record("snapshot_legacy_cross_tenant_refused", not status.get("configMapUID")
            and any(c.get("type") == "SnapshotReady" and c.get("status") == "False" and c.get("reason") == "ConfigMapContractMismatch"
                    for c in status.get("conditions", [])))
        self.record("snapshot_legacy_capture_preserved_no_backup", stored["metadata"]["uid"] == capture["metadata"]["uid"]
            and stored["data"] == capture["data"] and not self.exists("job", "snap-" + name + "-pgdump")
            and self.control("api", None)["counts"].get("POST " + path, 0) == 0)

    def cleanup(self):
        self.stop_log_capture()
        if self.rotation_process and self.rotation_process.poll() is None:
            self.rotation_process.terminate()
            try:
                self.rotation_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.rotation_process.kill()
                self.rotation_process.wait(timeout=10)
        for process, stream in self.proxy_forwards:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            stream.close()
        try:
            super().cleanup()
        finally:
            # Unique fixture names only; never prune developer images/containers.
            if self.registry_created:
                subprocess.run(["docker", "rm", "--force", self.registry_name], capture_output=True, timeout=60, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path)
    parser.add_argument("--deep-migration", action="store_true")
    args = parser.parse_args()
    if args.deep_migration and args.kubernetes_version != system.PINS["kubernetes"]["deep_migration"]:
        parser.error("Deep migration requires Kubernetes " + system.PINS["kubernetes"]["deep_migration"])
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hankoshell-installed-workload-private-") as temp:
        fixture = Installed(args, Path(temp))
        try:
            fixture.qualify_installed()
        except Exception as error:
            system.diagnostics.capture(fixture, error)
            if fixture.config.exists():
                try:
                    fixture.failure_evidence()
                except Exception:
                    fixture.report["failure_status"] = {"unavailable": True}
            raise
        finally:
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
            finally:
                fixture.cleanup()


if __name__ == "__main__":
    main()

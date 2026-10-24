"""Install the scanned operator chart in kind and reconcile real HTTPS Keycloak.

Only disposable, uniquely named local containers/clusters are modified. The
normal operator uses the chart service account and target-realm Keycloak roles.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

from tools.qualification.lib.evidence_privacy import contains_jwt, redact_jwts
from tools.qualification.lib.sensitive_writes import declared_targets
from tools.qualification.lib.sensitive_write_probe import probe as sensitive_write_probe

ROOT = Path(__file__).resolve().parents[3]

spec = importlib.util.spec_from_file_location("release_system", ROOT / "tools/qualification/scenarios/release_system_test.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)
diagnostics = publication.publish.contract.module("qualification_diagnostics", "tools/qualification/lib/qualification_diagnostics.py")
run = publication.publish.run
lifecycle = publication.publish.contract.module("lifecycle_approval", "tools/operations/lifecycle_approval.py")
PINS = publication.publish.contract.pins.DATA
VERSION = PINS["release"]["version"]
KUBERNETES_VERSION = PINS["kubernetes"]["default"]
KEYCLOAK_VERSION = PINS["keycloak"]["default"]
NODE = PINS["kubernetes"]["node_images"][KUBERNETES_VERSION]
KEYCLOAK = PINS["keycloak"]["images"][KEYCLOAK_VERSION]
KIND_VERSION = PINS["tools"]["kind"]["version"]


def wait(label, check, seconds=120):
    started = time.monotonic()
    deadline = started + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise diagnostics.DeadlineExceeded(label, seconds, time.monotonic() - started)


class System:
    def __init__(self, args, private):
        self.args, self.private = args, private
        self.name = "hankoshell-system-" + secrets.token_hex(6)
        self.registry_name = self.name + "-registry"
        self.registry_created = False
        self.config = private / "kubeconfig"
        self.forward = None
        self.password, self.credential = secrets.token_hex(32), secrets.token_hex(32)
        self.sensitive = [self.password, self.credential]
        self.http, self.token, self.endpoint = None, "", ""
        self.token_at = 0
        self.scanned_operators = [("auth", "system-operator"), ("org-auth", "organization-operator")]
        self.sensitive_write_names = {"secrets": set(), "deployments": set()}
        self.sensitive_write_lock = threading.Lock()
        self.sensitive_write_values = None

    def kubectl(self, *args, **kwargs):
        return run([self.args.kubectl, "--kubeconfig", self.config, *args], **kwargs)

    def apply(self, *objects):
        self.kubectl("apply", "-f", "-", input=yaml.safe_dump_all(objects).encode())

    def apply_approved(self, *objects):
        self.approve_sensitive_writes(objects)
        self.apply(*objects)

    def approve_sensitive_writes(self, objects):
        """The fixture administrator prepares exact grants before declaring CRs.

        This uses the isolated cluster administrator kubeconfig, not the
        operator token. Adversarial calls use that token directly and never
        receive this independent approval.
        """
        targets = declared_targets(objects)
        if not any(targets.values()):
            return
        with self.sensitive_write_lock:
            changed = any(targets[kind] - self.sensitive_write_names[kind] for kind in targets)
            for kind in targets:
                self.sensitive_write_names[kind].update(targets[kind])
            if not changed or self.sensitive_write_values is None:
                return
            values = yaml.safe_load(self.sensitive_write_values.read_text())
            values["sensitiveWrites"] = {kind: sorted(set(values.get("sensitiveWrites", {}).get(kind, [])) | names)
                                        for kind, names in self.sensitive_write_names.items()} | {"projections": values.get("sensitiveWrites", {}).get("projections", [])}
            self.refresh_sensitive_grants(values)

    def refresh_sensitive_grants(self, values):
        self.sensitive_write_values.write_text(yaml.safe_dump(values))
        manifest = run([self.args.helm, "template", "system", ROOT / "charts/hankoshell-operator", "--namespace", "auth",
            "--kube-version", getattr(self.args, "kubernetes_version", KUBERNETES_VERSION), "--values", self.sensitive_write_values])
        grants = [doc for doc in yaml.safe_load_all(manifest) if doc and
            (doc["kind"] in ("Role", "RoleBinding") and doc["metadata"]["name"] in ("system-operator", "system-operator-sensitive-projections") or
             doc["kind"] == "ValidatingAdmissionPolicy" and "-sensitive-" in doc["metadata"]["name"])]
        if not any(doc["kind"] == "Role" and doc["metadata"]["name"] == "system-operator" for doc in grants) or sum(doc["kind"] == "ValidatingAdmissionPolicy" for doc in grants) != 2:
            raise ValueError("Administrator sensitive-write grant rendering is incomplete")
        self.kubectl("apply", "-f", "-", input=yaml.safe_dump_all(grants).encode())

    def approve_projection_write(self, namespace, name):
        with self.sensitive_write_lock:
            values = yaml.safe_load(self.sensitive_write_values.read_text())
            projections = values.setdefault("sensitiveWrites", {}).setdefault("projections", [])
            grant = next((entry for entry in projections if entry["namespace"] == namespace), None)
            if grant is None:
                grant = {"namespace": namespace, "secrets": [], "create": False}
                projections.append(grant)
            grant["secrets"] = sorted(set(grant["secrets"]) | {name})
            self.refresh_sensitive_grants(values)

    def get(self, kind, name, namespace="auth"):
        return json.loads(self.kubectl("get", kind, name, "-n", namespace, "-o", "json"))

    def ready(self, kind, name, namespace="auth"):
        value = self.get(kind, name, namespace)
        return value.get("status", {}).get("phase") == "Ready" and value["status"].get("observedGeneration") == value["metadata"]["generation"]

    def role_reconciled(self, name):
        return self.iam_reconciled("hankorole", name)

    def iam_reconciled(self, kind, name):
        value = self.get(kind, name)
        status, generation = value.get("status", {}), value["metadata"]["generation"]
        hashes = ("intentHash", "evaluatedPlanHash", "appliedPlanHash", "observedStateHash", "observationPlanHash")
        return status.get("phase") == "Ready" and all(
            status.get(field) == generation for field in ("observedGeneration", "evaluatedGeneration", "appliedGeneration", "observationGeneration")) and (
            status.get("contractVersion") == "hanko.sh/iam-contract/v1alpha1" and status.get("backendKind") == "keycloak"
            and status.get("observationComplete") is True and status.get("driftState") == "InSync"
            and all(re.fullmatch(r"sha256:[a-f0-9]{64}", status.get(field, "")) for field in hashes)
            and status["appliedPlanHash"] == status["evaluatedPlanHash"] == status["observationPlanHash"]
            and any(condition.get("type") == "Synced" and condition.get("status") == "True"
                    and condition.get("observedGeneration") == generation and condition.get("reason") == "Reconciled" for condition in status.get("conditions", [])))

    def api(self, method, path, data=None, token=None, expected=(200, 201, 204)):
        if token is None and self.token and time.monotonic() - self.token_at > 30:
            self.token = self.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password})
            self.token_at = time.monotonic()
        headers = {"Content-Type": "application/json"}
        if token or self.token:
            headers["Authorization"] = "Bearer " + (token or self.token)
        payload = None if data is None else json.dumps(data).encode()
        try:
            with urlopen(Request(self.endpoint + path, data=payload, headers=headers, method=method), context=self.http, timeout=10) as response:
                status, body = response.status, response.read(1_048_577)
        except HTTPError as error:
            status, body = error.code, error.read(8193)
        if status not in expected or len(body) > 1_048_576:
            raise RuntimeError(f"Fixture Admin API {method} returned unexpected HTTP {status}")
        return json.loads(body) if body else None

    def access_token(self, fields):
        with urlopen(Request(self.endpoint + "/realms/master/protocol/openid-connect/token", data=urlencode(fields).encode()), context=self.http, timeout=10) as response:
            data = response.read(65_537)
        if len(data) > 65_536:
            raise ValueError("Fixture token response too large")
        token = json.loads(data)["access_token"]
        self.sensitive.append(token)
        return token

    def client(self, realm, name):
        clients = self.api("GET", f"/admin/realms/{realm}/clients?" + urlencode({"clientId": name}))
        if len(clients) != 1:
            raise ValueError("Expected exactly one provider client")
        return self.api("GET", f'/admin/realms/{realm}/clients/{clients[0]["id"]}')

    def authorization_cleaned(self, client_id):
        # This fixture has no unowned authorization objects. Complete cleanup
        # disables Authorization Services; Keycloak then returns 404 for the
        # resource server rather than an empty scopes collection, and may omit
        # the disabled boolean from the client representation.
        client = self.client("managed", "system-contract-api")
        if client["id"] != client_id:
            raise ValueError("Authorization finalizer replaced the backing client")
        if client.get("authorizationServicesEnabled", False) is not False:
            raise ValueError("Authorization finalizer left Authorization Services enabled")
        if "hanko.sh/resource-server-ownership" in client.get("attributes", {}):
            raise ValueError("Authorization finalizer left the ownership journal behind")
        self.api("GET", f'/admin/realms/managed/clients/{client_id}/authz/resource-server', expected=(404,))

    def create_cluster(self):
        if not run([self.args.kind, "version"]).startswith("kind " + KIND_VERSION + " "):
            raise ValueError("Use the pinned kind 0.33.0 fixture")
        run([self.args.kind, "create", "cluster", "--name", self.name, "--image", NODE,
             "--kubeconfig", self.config, "--wait", "120s"])
        self.mirror_scanned_image()
        version = json.loads(self.kubectl("version", "-o", "json"))["serverVersion"]["gitVersion"]
        if version != "v" + KUBERNETES_VERSION:
            raise ValueError("Unexpected system Kubernetes version")

    def mirror_scanned_image(self):
        """Mirror the verified multiarch graph without rebuilding the operator."""
        run(["docker", "run", "--detach", "--name", self.registry_name, "--publish", "127.0.0.1::5000",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", publication.REGISTRY_IMAGE])
        self.registry_created = True
        node = self.name + "-control-plane"
        run(["docker", "network", "connect", "kind", self.registry_name])
        # Docker can reassign an ephemeral published port when attaching a
        # second network. Resolve it after all network mutations, then use the
        # exact IPv4 loopback endpoint for host writes and containerd aliases.
        address = run(["docker", "port", self.registry_name, "5000/tcp"])
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", address):
            raise ValueError("Registry must be loopback-only")
        self.registry = address
        directory = "/etc/containerd/certs.d/" + self.registry
        run(["docker", "exec", node, "mkdir", "-p", directory])
        hosts = f'[host."http://{self.registry_name}:5000"]\n  capabilities = ["pull", "resolve"]\n'
        run(["docker", "exec", "-i", node, "cp", "/dev/stdin", directory + "/hosts.toml"], input=hosts.encode())
        copy = subprocess.run([str(self.args.oras), "cp", "--from-oci-layout", str(self.args.archive) + "@" + self.args.digest,
                               "--to-plain-http", self.registry + "/hankoshell-operator:scanned"], capture_output=True, timeout=600)
        if copy.returncode:
            diagnostic = copy.stderr.decode(errors="replace")[-2048:]
            for value in self.sensitive:
                diagnostic = diagnostic.replace(value, "[REDACTED]")
            diagnostic = redact_jwts(diagnostic)
            raise RuntimeError("Local OCI mirror copy failed: " + diagnostic)
        if publication.publish.Registry(self.args.oras, self.args.helm, plain_http=True).resolve(self.registry + "/hankoshell-operator:scanned") != self.args.digest:
            raise ValueError("System-test mirror changed the scanned OCI graph")

    def secret(self, name, values, namespace="auth"):
        return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": namespace},
                "data": {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}}

    def keycloak(self):
        # Build the disposable server's optimized mode from the pinned official
        # image, then run it with the same read-only pod baseline as production.
        build = self.private / "keycloak-build"
        build.mkdir()
        dockerfile = build / "Dockerfile"
        dockerfile.write_text(f"FROM {KEYCLOAK}\nRUN /opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true\n")
        self.keycloak_image = self.name + "-keycloak:fixture"
        run(["docker", "build", "--network=none", "--tag", self.keycloak_image, "--file", dockerfile, build])
        run([self.args.kind, "load", "docker-image", self.keycloak_image, "--name", self.name])
        cert, key = self.private / "tls.crt", self.private / "tls.key"
        run([self.args.openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=keycloak.auth.svc",
             "-addext", "subjectAltName=DNS:keycloak.auth.svc,DNS:localhost",
             "-addext", "basicConstraints=critical,CA:true"])
        self.http = ssl.create_default_context(cafile=str(cert))
        self.http.minimum_version = ssl.TLSVersion.TLSv1_3
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "auth", "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}}},
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other"}},
            self.secret("keycloak-bootstrap", {"username": "fixture-admin", "password": self.password}),
            self.secret("keycloak-tls", {"tls.crt": cert.read_text(), "tls.key": key.read_text()}))
        security = {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"}}
        self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "keycloak", "namespace": "auth"}, "spec": {
            "replicas": 1, "selector": {"matchLabels": {"app": "keycloak"}}, "template": {
                "metadata": {"labels": {"app": "keycloak"}}, "spec": {
                    "securityContext": security, "automountServiceAccountToken": False,
                    "containers": [{"name": "keycloak", "image": self.keycloak_image, "imagePullPolicy": "IfNotPresent", "args": ["start", "--optimized",
                        "--http-enabled=false", "--http-management-scheme=http", "--hostname=https://keycloak.auth.svc:8443", "--https-protocols=TLSv1.3",
                        "--https-certificate-file=/tls/tls.crt", "--https-certificate-key-file=/tls/tls.key"],
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                        "env": [{"name": name, "valueFrom": {"secretKeyRef": {"name": "keycloak-bootstrap", "key": key}}}
                                for name, key in [("KC_BOOTSTRAP_ADMIN_USERNAME", "username"), ("KC_BOOTSTRAP_ADMIN_PASSWORD", "password")]],
                        "ports": [{"name": "https", "containerPort": 8443}],
                        "readinessProbe": {"httpGet": {"path": "/health/ready", "port": 9000}, "initialDelaySeconds": 10, "periodSeconds": 2},
                        "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True}, {"name": "tmp", "mountPath": "/tmp"},
                                         {"name": "data", "mountPath": "/opt/keycloak/data"}],
                        "resources": {"requests": {"cpu": "100m", "memory": "512Mi"}, "limits": {"memory": "2Gi"}}}],
                    "volumes": [{"name": "tls", "secret": {"secretName": "keycloak-tls", "defaultMode": 288}},
                                {"name": "tmp", "emptyDir": {}}, {"name": "data", "emptyDir": {}}]}}}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "keycloak", "namespace": "auth"},
             "spec": {"selector": {"app": "keycloak"}, "ports": [{"port": 8443, "targetPort": 8443}]}})
        self.kubectl("rollout", "status", "deployment/keycloak", "-n", "auth", "--timeout=180s")
        # kubectl chooses a loopback ephemeral port itself, avoiding a reservation race.
        log = self.private / "port-forward.log"
        self.forward_log = log.open("wb")
        self.forward = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "port-forward", "-n", "auth",
                                         "service/keycloak", ":8443", "--address", "127.0.0.1"], stdout=self.forward_log, stderr=subprocess.STDOUT)
        wait("Keycloak port-forward", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()) is not None, 30)
        port = re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]
        self.endpoint = "https://localhost:" + port
        self.token = self.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password})
        self.token_at = time.monotonic()
        self.api("POST", "/admin/realms", {"realm": "managed", "enabled": True})
        self.api("POST", "/admin/realms/master/clients", {"clientId": "system-operator", "secret": self.credential,
            "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
        client, proxy = self.client("master", "system-operator"), self.client("master", "managed-realm")
        user = self.api("GET", f'/admin/realms/master/clients/{client["id"]}/service-account-user')
        roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{name}')
                 for name in ("manage-realm", "manage-clients", "manage-events")]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{client["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        constrained = self.access_token({"client_id": "system-operator", "client_secret": self.credential, "grant_type": "client_credentials"})
        for path in ("/admin/realms/master/clients", "/admin/realms/managed/users", "/admin/realms/managed/identity-provider/instances"):
            self.api("GET", path, token=constrained, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "denied"}, token=constrained, expected=(403,))
        self.apply(self.secret("operator-credentials", {"client-id": "system-operator", "client-secret": self.credential}),
                   self.secret("operator-ca", {"ca.crt": cert.read_text()}))

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
        run([self.args.helm, "install", "system", ROOT / "charts/hankoshell-operator", "--namespace", "auth",
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

    def standalone_organizations(self):
        # Isolate the existing optional group/organization profile. The common
        # operator's user/IdP denial checks and credentials remain unchanged.
        realm, namespace = "organization-target", "org-auth"
        credential = secrets.token_hex(32)
        self.sensitive.append(credential)
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True})
        self.api("POST", f"/admin/realms/{realm}/roles", {"name": "reader"})
        self.api("POST", f"/admin/realms/{realm}/clients", {"clientId": "organization-app", "enabled": True, "publicClient": True})
        app = self.client(realm, "organization-app")
        self.api("POST", f'/admin/realms/{realm}/clients/{app["id"]}/roles', {"name": "access"})
        self.api("POST", "/admin/realms/master/clients", {
            "clientId": "organization-operator", "secret": credential, "protocol": "openid-connect",
            "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
        identity, proxy = self.client("master", "organization-operator"), self.client("master", realm + "-realm")
        user = self.api("GET", f'/admin/realms/master/clients/{identity["id"]}/service-account-user')
        roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{name}')
                 for name in ("manage-realm", "manage-clients", "manage-events", "manage-users")]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{identity["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        constrained = self.access_token({"client_id": "organization-operator", "client_secret": credential, "grant_type": "client_credentials"})
        for path in ("/admin/realms/master/clients", "/admin/realms/managed/clients",
                     f"/admin/realms/{realm}/identity-provider/instances"):
            self.api("GET", path, token=constrained, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "organization-denied"}, token=constrained, expected=(403,))
        self.apply_approved({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}}},
            self.secret("operator-credentials", {"client-id": "organization-operator", "client-secret": credential}, namespace),
            self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}, namespace))
        values = yaml.safe_load((self.private / "values.yaml").read_text())
        values["fullnameOverride"] = "organization-operator"
        values["sensitiveWrites"] = {"secrets": ["hanko-app-system-organization-api"], "deployments": [], "projections": []}
        values["networkPolicy"]["keycloakNamespace"] = "auth"
        # Do not override organizationProjection: qualify the chart default.
        config = self.private / "organization-values.yaml"
        config.write_text(yaml.safe_dump(values))
        run([self.args.helm, "install", "organizations", ROOT / "charts/hankoshell-operator", "--namespace", namespace,
             "--kubeconfig", self.config, "--values", config, "--wait", "--timeout", "180s"])
        pod = json.loads(self.kubectl("get", "pods", "-n", namespace, "-l", "app.kubernetes.io/instance=organizations", "-o", "json"))["items"][0]
        container = pod["spec"]["containers"][0]
        env = {entry["name"]: entry for entry in container["env"]}
        if (container["image"] != self.registry + "/hankoshell-operator@" + self.args.digest
                or env["HANKO_ORGANIZATION_PROJECTION_ENABLED"].get("value") != "false"
                or "HANKO_API_URL" in env or "HANKO_API_TOKEN" in env):
            raise ValueError("Installed standalone projection/image contract differs")

        def organization_ready(name):
            value = self.get("hankoorganization", name, namespace)
            status, generation = value.get("status", {}), value["metadata"]["generation"]
            conditions = {condition["type"]: condition for condition in status.get("conditions", [])}
            return (status.get("phase") == "Ready" and status.get("observedGeneration") == generation
                    and status.get("groupID") and not status.get("positionID")
                    and all(conditions.get(kind, {}).get("status") == outcome
                            and conditions[kind].get("reason") == reason
                            and conditions[kind].get("observedGeneration") == generation
                            for kind, outcome, reason in (("Synced", "True", "Reconciled"), ("Projection", "Unknown", "Disabled"))))

        for name, parent in (("root", ""), ("child", "root")):
            desired = {"realmRef": realm, "name": name, "roles": ["reader"],
                       "clientRoles": [{"client": "organization-app", "roles": ["access"]}]}
            if parent:
                desired["parentRef"] = parent
            else:
                desired.update({"slug": "system-organization", "domains": ["company.invalid"]})
            self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOrganization",
                        "metadata": {"name": name, "namespace": namespace}, "spec": desired})
        for name in ("root", "child"):
            wait("installed standalone organization " + name, lambda name=name: organization_ready(name))
        objects = [self.get("hankoorganization", name, namespace) for name in ("root", "child")]
        for value, path in zip(objects, ("/root", "/root/child")):
            group_id = value["status"]["groupID"]
            group = self.api("GET", f"/admin/realms/{realm}/groups/{group_id}")
            if group["path"] != path or group.get("attributes", {}).get("hanko.sh/organization-uid") != [value["metadata"]["uid"]]:
                raise ValueError("Installed provider hierarchy/UID ownership differs")
            realm_roles = self.api("GET", f"/admin/realms/{realm}/groups/{group_id}/role-mappings/realm")
            client_roles = self.api("GET", f'/admin/realms/{realm}/groups/{group_id}/role-mappings/clients/{app["id"]}')
            if {role["name"] for role in realm_roles} != {"reader"} or {role["name"] for role in client_roles} != {"access"}:
                raise ValueError("Installed organization role bindings differ")
        native_id = objects[0]["status"]["orgID"]
        native = self.api("GET", f"/admin/realms/{realm}/organizations/{native_id}")
        if (native["alias"] != "system-organization" or native.get("attributes", {}).get("hanko.sh/organization-uid") != [objects[0]["metadata"]["uid"]]
                or {domain["name"] for domain in native.get("domains", [])} != {"company.invalid"}):
            raise ValueError("Installed root Organization alias/domains/UID differs")
        # Exercise organizational grants with the already-installed exact image.
        # This process also provisions organizations, so it retains the separate
        # existing organization-writer profile. The two-version suite qualifies
        # authorization separately with manage-clients + view-users only.
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm",
                    "metadata": {"name": realm, "namespace": namespace}, "spec": {"roles": [{"name": "reader"}]}},
                   {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                    "metadata": {"name": "organization-api", "namespace": namespace},
                    "spec": {"realmRef": realm, "clientID": "system-organization-api", "type": "m2m"}})
        wait("organization grant backing application", lambda: self.ready("hankoapplication", "organization-api", namespace))
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoResourceServer",
                    "metadata": {"name": "organization-server", "namespace": namespace},
                    "spec": {"realmRef": realm, "applicationRef": "organization-api", "audience": "urn:organization-system",
                             "scopes": [{"name": "read"}], "resources": [{"name": "invoice", "scopes": ["read"]}],
                             "permissions": [{"name": "invoice-read", "scopes": ["read"], "resources": ["invoice"],
                                              "principals": [{"kind": "organization", "ref": "root", "includeDescendants": True}, {"kind": "realm_role", "ref": "reader"}]}]}})
        def grant_current():
            value = self.get("hankoresourceserver", "organization-server", namespace)
            status = value.get("status", {})
            return (status.get("phase") == "Ready" and status.get("appliedGeneration") == value["metadata"]["generation"]
                    and status.get("appliedPlanHash") == status.get("evaluatedPlanHash")
                    and status.get("observationComplete") is True and status.get("driftState") == "InSync"
                    and status.get("capabilities", {}).get("organizationPrincipals") is True
                    and status.get("capabilities", {}).get("organizationDescendants") is True
                    and status.get("authorizationExplanation", {}).get("complete") is True)
        wait("installed organizational current applied evidence", grant_current)
        resource_client = self.client(realm, "system-organization-api")
        policies = self.api("GET", f'/admin/realms/{realm}/clients/{resource_client["id"]}/authz/resource-server/policy/group')
        expected_groups = {value["status"]["groupID"] for value in objects}
        if (len(policies) != 1 or {entry["id"] for entry in policies[0].get("groups", [])} != expected_groups
                or len(policies[0].get("groups", [])) != len(expected_groups)
                or any(entry.get("extendChildren") is not False for entry in policies[0]["groups"])
                or policies[0].get("groupsClaim")):
            raise ValueError("Installed organizational policy group contract differs")
        explanation = self.get("hankoresourceserver", "organization-server", namespace)["status"]["authorizationExplanation"]
        status = self.get("hankoresourceserver", "organization-server", namespace)["status"]
        paths = explanation["paths"]
        if (explanation["source"] != "Applied" or explanation["sourcePlanHash"] != status["appliedPlanHash"]
                or explanation["sourceGeneration"] != status["appliedGeneration"] or explanation["truncated"]
                or not any(p["sourceKind"] == "organization" and p.get("organizationRef") == "root" and p["relationship"] == "direct" for p in paths)
                or not any(p["sourceKind"] == "organization" and p.get("organizationRef") == "child" and p["relationship"] == "descendant" and p["ancestry"] == ["root", "child"] for p in paths)
                or not any(p["sourceKind"] == "realm_role" and p["relationship"] == "generic" and not p.get("organizationRef") for p in paths)
                or not any(p["sourceKind"] == "realm_role" and p.get("organizationRef") == "root" and p["relationship"] == "mapped_role" for p in paths)):
            raise ValueError("Installed structural provenance differs")
        encoded = json.dumps(explanation)
        if any(word in encoded for word in ("username", "email", "password", "access_token", "client_secret")):
            raise ValueError("Installed explanation exported subject or credential data")
        server_uid = self.get("hankoresourceserver", "organization-server", namespace)["metadata"]["uid"]
        journal = json.loads(resource_client.get("attributes", {}).get("hanko.sh/resource-server-ownership", "{}"))
        if (journal.get("ownerUID") != server_uid or len(journal.get("objects", {}).get("policies", [])) != 2):
            raise ValueError("Installed organization grant journal differs")
        self.kubectl("delete", "hankoresourceserver", "organization-server", "-n", namespace, "--wait=true", "--timeout=120s")
        remaining_client = self.client(realm, "system-organization-api")
        if (remaining_client.get("authorizationServicesEnabled", False)
                or "hanko.sh/resource-server-ownership" in remaining_client.get("attributes", {})):
            raise ValueError("Installed owned organization grant graph/journal survived cleanup")
        self.api("GET", f'/admin/realms/{realm}/clients/{resource_client["id"]}/authz/resource-server/policy/group', expected=(404,))
        for value in objects:
            self.api("GET", f'/admin/realms/{realm}/groups/{value["status"]["groupID"]}')
        self.kubectl("delete", "hankoapplication", "organization-api", "-n", namespace, "--wait=true", "--timeout=120s")
        for value in reversed(objects):
            self.kubectl("delete", "hankoorganization", value["metadata"]["name"], "-n", namespace, "--wait=true", "--timeout=120s")
            self.api("GET", f'/admin/realms/{realm}/groups/{value["status"]["groupID"]}', expected=(404,))
        self.api("GET", f"/admin/realms/{realm}/organizations/{native_id}", expected=(404,))

    def reject_wrong_ca(self):
        wrong_cert, wrong_key = self.private / "wrong-ca.crt", self.private / "wrong-ca.key"
        run([self.args.openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-keyout", wrong_key, "-out", wrong_cert, "-days", "1", "-subj", "/CN=untrusted-system-fixture"])
        # Stop the old process before changing startup trust; an already-running
        # healthy replica must not hide a broken CA or perform the denied write.
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        wait("operator stop", lambda: not json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"])
        self.apply(self.secret("operator-ca", {"ca.crt": wrong_cert.read_text()}))
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=1")
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": {"name": "tls-denied", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": "tls-denied", "type": "spa"}})
        # A bounded interval observes a running process, failed TLS readiness and
        # no provider writes before trust is restored.
        wait("operator pod creation", lambda: bool(json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"]))
        time.sleep(10)
        if self.get("deployment", "system-operator").get("status", {}).get("availableReplicas", 0) != 0:
            raise ValueError("Operator became ready with an untrusted Keycloak CA")
        if self.api("GET", "/admin/realms/managed/clients?clientId=tls-denied"):
            raise ValueError("Operator wrote through an untrusted HTTPS endpoint")
        self.apply(self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}))
        self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
        wait("reconciliation after CA repair", lambda: self.ready("hankoapplication", "tls-denied"))
        self.client("managed", "tls-denied")
        self.kubectl("delete", "hankoapplication", "tls-denied", "-n", "auth", "--wait=true", "--timeout=120s")

    def runtime_binding(self, name, credentials=False):
        resource = self.get("hankoapplication", name)
        namespace = "runtime-qualified"
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
                   {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"namespace": namespace, "name": name}, "automountServiceAccountToken": False})
        sa_uid = self.get("serviceaccount", name, namespace)["metadata"]["uid"]
        annotations = {"hanko.sh/runtime-application-namespace": "auth", "hanko.sh/runtime-application-name": name,
                       "hanko.sh/runtime-application-uid": resource["metadata"]["uid"], "hanko.sh/runtime-binding-name": "workload",
                       "hanko.sh/runtime-service-account": name, "hanko.sh/runtime-service-account-uid": sa_uid}
        def meta(kind):
            return {"namespace": namespace, "name": name, "labels": {"hanko.sh/runtime-target": kind}, "annotations": annotations}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("metadata"), "data": {"owner": "preserved"}})
        rules = [{"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": [name], "verbs": ["get"]},
                 {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [name], "verbs": ["get", "patch"]}]
        binding = {"name": "workload", "workload": {"namespace": namespace, "serviceAccountRef": name}, "publicMetadata": {"configMapRef": name}}
        if credentials:
            target = self.secret(name, {"owner": "preserved"}, namespace)
            target["metadata"] = meta("credentials")
            self.apply(target)
            self.approve_projection_write(namespace, name)
            binding["credentials"] = {"secretRef": name}
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"namespace": namespace, "name": name}, "rules": rules},
                   {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"namespace": namespace, "name": name},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                    "subjects": [{"kind": "ServiceAccount", "namespace": "auth", "name": "system-operator"}]})
        self.kubectl("patch", "hankoapplication", name, "-n", "auth", "--type=merge", "-p", json.dumps({"spec": {"runtimeBindings": [binding]}}))
        wait("installed runtime binding " + name, lambda: self.runtime_ready(name))
        doc = json.loads(self.get("configmap", name, namespace)["data"]["identity.json"])
        if doc.get("schemaVersion") != "hanko.sh/application-runtime/v1alpha1" or doc.get("clientID") != resource["spec"]["clientID"] or doc.get("serviceAccountUID") != sa_uid:
            raise ValueError("Installed runtime identity differs")
        if credentials:
            self.runtime_token(name, doc)
            previous = self.get("secret", name, namespace)["data"]["client_secret"]
            # The request is newer than the initial credential checkpoint. The
            # normal periodic reconciliation applies it after this deadline.
            force_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2))
            self.kubectl("patch", "hankoapplication", name, "-n", "auth", "--type=merge", "-p", json.dumps({"spec": {"secretRotationPolicy": {"enabled": True, "forceRotateAt": force_at}}}))
            wait("installed runtime rotation", lambda: self.runtime_ready(name) and
                 self.get("secret", name, namespace)["data"]["client_secret"] != previous and
                 json.loads(self.get("configmap", name, namespace)["data"]["identity.json"])["bindingRevision"] != doc["bindingRevision"])
            self.runtime_token(name, json.loads(self.get("configmap", name, namespace)["data"]["identity.json"]))
            self.kubectl("patch", "hankoapplication", name, "-n", "auth", "--type=merge", "-p", '{"spec":{"runtimeBindings":[]}}')
            wait("installed runtime removal", lambda: self.ready("hankoapplication", name) and self.runtime_clean(name, True))
        else:
            saml = doc.get("saml", {})
            if doc.get("oidc") or doc.get("credentials") or saml.get("nameIDFormat") != "persistent" or not all(saml.get(k) for k in ("issuer", "sso", "metadata")):
                raise ValueError("Installed SAML runtime subset differs")
        return doc

    def runtime_ready(self, name):
        if not self.iam_reconciled("hankoapplication", name):
            return False
        app = self.get("hankoapplication", name)
        status = app.get("status", {}).get("runtimeBindings", [])
        if len(status) != 1 or not any(c.get("type") == "Ready" and c.get("status") == "True" for c in status[0].get("conditions", [])):
            return False
        revision = status[0]["bindingRevision"]
        cm = self.get("configmap", name, "runtime-qualified")
        if cm["metadata"].get("annotations", {}).get("hanko.sh/runtime-binding-revision") != revision:
            return False
        if app["spec"]["runtimeBindings"][0].get("credentials"):
            return self.get("secret", name, "runtime-qualified")["metadata"].get("annotations", {}).get("hanko.sh/runtime-binding-revision") == revision
        return True

    def runtime_clean(self, name, credentials=False):
        cm = self.get("configmap", name, "runtime-qualified")
        if cm.get("data", {}).get("identity.json") or cm.get("data", {}).get("owner") != "preserved" or cm["metadata"].get("annotations", {}).get("hanko.sh/runtime-binding-revision"):
            return False
        if credentials:
            secret = self.get("secret", name, "runtime-qualified")
            return not secret.get("data", {}).get("client_secret") and base64.b64decode(secret["data"]["owner"]).decode() == "preserved" and not secret["metadata"].get("annotations", {}).get("hanko.sh/runtime-binding-revision")
        return True

    def runtime_token(self, name, doc):
        credential = base64.b64decode(self.get("secret", name, "runtime-qualified")["data"]["client_secret"]).decode()
        self.sensitive.append(credential)
        fields = {"grant_type": "client_credentials", "client_id": doc["clientID"], "client_secret": credential}
        # HTTPS response acceptance and issuer/audience are asserted here. Full
        # JWT/JWKS signature verification lives in both real-Keycloak flow suites.
        # The fixture's canonical hostname keeps issuer stable across the
        # internal service and verified-localhost port-forward socket.
        with urlopen(Request(self.endpoint + "/realms/managed/protocol/openid-connect/token", data=urlencode(fields).encode()), context=self.http, timeout=10) as response:
            data = response.read(65_537)
        if len(data) > 65_536:
            raise ValueError("Runtime token response too large")
        token = json.loads(data)["access_token"]
        self.sensitive.append(token)
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        audiences = claims.get("aud", [])
        if isinstance(audiences, str):
            audiences = [audiences]
        if claims.get("iss") != doc["oidc"]["issuer"] or doc["clientID"] not in audiences:
            raise ValueError("Projected-credential token issuer/audience differs")

    def application_protocols(self):
        # Browser protocol handshakes live in the two-version Keycloak suite;
        # this fixture qualifies the scanned manager's installed lifecycle.
        wait("legacy OIDC application evidence", lambda: self.iam_reconciled("hankoapplication", "app"))
        oidc = self.get("hankoapplication", "app")["status"]
        if oidc.get("protocol") != "oidc" or not oidc.get("oidcEndpoints") or oidc.get("samlEndpoints"):
            raise ValueError("Installed legacy OIDC status differs")
        entity, acs = "https://system-sp.example/entity", "https://system-sp.example/acs"
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                    "metadata": {"name": "saml", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": entity, "protocol": "saml",
                             "saml": {"assertionConsumerServices": [acs]}, "roles": [{"name": "use"}]}},
                   {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                    "metadata": {"name": "saml-observe", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": entity, "protocol": "saml", "mode": "Observe",
                             "saml": {"assertionConsumerServices": [acs]}}})
        wait("installed SAML contract", lambda: self.iam_reconciled("hankoapplication", "saml"))
        wait("installed SAML Observe", lambda: self.ready("hankoapplication", "saml-observe"))
        resource = self.get("hankoapplication", "saml")
        status = resource["status"]
        if status.get("protocol") != "saml" or status.get("oidcEndpoints") or status.get("clientSecret") or not status.get("samlEndpoints"):
            raise ValueError("Installed SAML metadata/credential boundary differs")
        if not any(c.get("type") == "Operational" and c.get("status") == "True" for c in status.get("conditions", [])):
            raise ValueError("Installed private-CA SAML metadata validation failed")
        provider = self.client("managed", entity)
        attributes = provider.get("attributes", {})
        if provider.get("protocol") != "saml" or provider.get("redirectUris") != [acs] or attributes.get("hanko.sh/application-owner") != resource["metadata"]["uid"] or attributes.get("saml.assertion.signature") != "true" or attributes.get("saml.server.signature") != "true":
            raise ValueError("Installed SAML ownership/configuration differs")
        for secret in json.loads(self.kubectl("get", "secrets", "-n", "auth", "-o", "json"))["items"]:
            if any(ref.get("uid") == resource["metadata"]["uid"] for ref in secret.get("metadata", {}).get("ownerReferences", [])):
                raise ValueError("SAML acquired an OIDC Secret")
        self.runtime_binding("saml")
        observer = self.get("hankoapplication", "saml-observe")
        if observer["metadata"].get("finalizers") or observer["status"].get("clientSecret") or observer["status"].get("appliedPlanHash"):
            raise ValueError("Installed Observe acquired write/secret authority")
        self.kubectl("delete", "hankoapplication", "saml-observe", "-n", "auth", "--wait=true", "--timeout=30s")
        self.kubectl("delete", "hankoapplication", "saml", "-n", "auth", "--wait=true", "--timeout=120s")
        if not self.runtime_clean("saml"):
            raise ValueError("Application finalizer left runtime metadata")
        if self.api("GET", "/admin/realms/managed/clients?" + urlencode({"clientId": entity})):
            raise ValueError("SAML finalizer left owned client behind")

    def ownership_adoption(self):
        """Qualify import, acquisition, explicit Manage, repair and cleanup."""
        self.approve_sensitive_writes([{"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": {"namespace": "auth"}, "spec": {"clientID": "system-adopt-m2m"}}])
        reader_secret = secrets.token_hex(32)
        credential = secrets.token_hex(32)
        self.sensitive.extend((reader_secret, credential))
        base = "/admin/realms/managed"
        self.api("POST", "/admin/realms/master/clients", {
            "clientId": "system-inventory", "secret": reader_secret, "enabled": True,
            "protocol": "openid-connect", "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
        reader, proxy = self.client("master", "system-inventory"), self.client("master", "managed-realm")
        user = self.api("GET", f'/admin/realms/master/clients/{reader["id"]}/service-account-user')
        roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{name}')
                 for name in ("view-realm", "view-clients")]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{reader["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", base + "/clients", {
            "clientId": "system-adopt-m2m", "name": "system-adopt-m2m", "secret": credential,
            "protocol": "openid-connect", "enabled": True, "publicClient": False,
            "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False, "frontchannelLogout": True, "redirectUris": [], "webOrigins": [], "attributes": {"locale": "en"},
            "defaultClientScopes": [], "optionalClientScopes": []})
        before = self.client("managed", "system-adopt-m2m")
        path = base + "/clients/" + before["id"]
        for scope in self.api("GET", path + "/default-client-scopes"):
            self.api("DELETE", path + "/default-client-scopes/" + scope["id"])
        before = self.client("managed", "system-adopt-m2m")
        self.api("POST", base + "/roles", {"name": "system-adopt-role", "description": "Reviewed leaf", "attributes": {"locale": ["fr"]}})
        self.api("POST", base + "/roles", {"name": "system-foreign-composite"})
        foreign_composite = self.api("GET", base + "/roles/system-foreign-composite")
        self.api("POST", base + "/roles/system-adopt-role/composites", [foreign_composite])
        role_composites_before = self.api("GET", base + "/roles/system-adopt-role/composites")
        role_before = self.api("GET", base + "/roles/system-adopt-role")
        readonly = self.access_token({"client_id": "system-inventory", "client_secret": reader_secret, "grant_type": "client_credentials"})
        self.api("PUT", path, before, token=readonly, expected=(403,))
        self.api("GET", path + "/client-secret", token=readonly, expected=(403,))
        self.apply(self.secret("inventory-credentials", {
            "HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443", "HANKO_KC_CLIENT_ID": "system-inventory",
            "HANKO_KC_CLIENT_SECRET": reader_secret}),
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance",
             "metadata": {"name": "inventory-source", "namespace": "auth"},
             "spec": {"mode": "external", "adminRef": {"name": "inventory-credentials"}, "tlsCARef": "operator-ca"}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoImport",
             "metadata": {"name": "leaf-inventory", "namespace": "auth"},
             "spec": {"sourceRef": "inventory-source", "realms": ["managed"], "includeIdentityProviders": False}})
        # Import publishes discovery candidates while creating targets. Finish
        # that publisher before reviewing a fresh target-controller observation.
        wait("completed leaf inventory", lambda: self.get("hankoimport", "leaf-inventory").get("status", {}).get("phase") == "Done")
        self.kubectl("label", "hankorealm", "managed", "-n", "auth", "hanko.sh/imported-by=leaf-inventory", "--overwrite")
        wait("external realm Observe boundary", lambda: not self.get("hankorealm", "managed")["metadata"].get("finalizers") and any(
            c.get("reason") == "Observed" for c in self.get("hankorealm", "managed").get("status", {}).get("conditions", [])))
        realm_before = self.api("GET", base)

        def imported(kind, field, value):
            items = json.loads(self.kubectl("get", kind, "-n", "auth", "-o", "json"))["items"]
            matches = [item for item in items if item["spec"].get(field) == value
                       and item["metadata"].get("labels", {}).get("hanko.sh/imported-by") == "leaf-inventory"]
            return matches[0] if len(matches) == 1 else None

        pairs = (("hankoserviceaccount", "clientID", "system-adopt-m2m", before),
                 ("hankorole", "name", "system-adopt-role", role_before))
        for kind, field, value, original in pairs:
            wait("imported lossless leaf candidate", lambda: imported(kind, field, value) is not None and
                 imported(kind, field, value).get("status", {}).get("adoptionCandidate", {}).get("approvable") is True)
            target = imported(kind, field, value)
            name, uid = target["metadata"]["name"], target["metadata"]["uid"]
            previous_observation = target.get("status", {}).get("lastReconciled")
            self.kubectl("annotate", kind, name, "-n", "auth", "hanko.sh/reconcile-request=" + str(time.time_ns()))
            wait("fresh installed leaf observation", lambda: self.get(kind, name).get("status", {}).get("lastReconciled") not in (None, previous_observation)
                 and self.get(kind, name).get("status", {}).get("adoptionCandidate", {}).get("approvable") is True)
            target = self.get(kind, name)
            candidate = target["status"]["adoptionCandidate"]
            if target["spec"].get("mode") != "Observe" or target["metadata"].get("finalizers"):
                raise ValueError("Import acquired semantic or destructive authority")
            self.kubectl("annotate", kind, name, "-n", "auth",
                         "hanko.sh/adoption-source=inventory-source",
                         "hanko.sh/adoption-contract=hanko.sh/adoption-contract/v1alpha1",
                         "hanko.sh/adoption-candidate=" + candidate["candidateHash"])
            try:
                wait("installed ownership receipt", lambda: self.get(kind, name).get("status", {}).get("adoptionReceipt", {}).get("state") == "Verified")
            except RuntimeError:
                status = self.get(kind, name).get("status", {})
                observed = status.get("adoptionCandidate", {})
                print(json.dumps({"kind": kind, "name": name, "approvedHash": candidate["candidateHash"],
                                  "currentHash": observed.get("candidateHash"), "complete": observed.get("complete"),
                                  "approvable": observed.get("approvable"), "receiptState": status.get("adoptionReceipt", {}).get("state"),
                                  "conditions": [{"type": c.get("type"), "reason": c.get("reason")} for c in status.get("conditions", [])][:32],
                                  "findings": [f.get("code") for f in observed.get("findings", [])][:32]}), flush=True)
                raise
            adopted = self.get(kind, name)
            current = self.client("managed", value) if kind == "hankoserviceaccount" else self.api("GET", base + "/roles/" + value)
            attrs = current.get("attributes", {})
            receipt_value = attrs.pop("hanko.sh/adoption-receipt", None)
            if kind == "hankorole":
                if attrs.pop("hanko.sh/role-owner", None) != [uid] or not isinstance(receipt_value, list) or len(receipt_value) != 1:
                    raise ValueError("Installed role ownership envelope differs")
                receipt_value = receipt_value[0]
            elif attrs.pop("hanko.sh/client-owner-kind", None) != "HankoServiceAccount" or attrs.pop("hanko.sh/client-owner-uid", None) != uid:
                raise ValueError("Installed M2M ownership envelope differs")
            if json.loads(receipt_value) != {"contractVersion": "hanko.sh/adoption-contract/v1alpha1",
                                           "targetKind": adopted["kind"], "targetUID": uid, "candidateHash": candidate["candidateHash"]}:
                raise ValueError("Installed receipt does not bind the reviewed candidate")
            for document in (current, original):
                document.pop("access", None)
                document.pop("secret", None)
                if not document.get("attributes"):
                    document.pop("attributes", None)
            if current != original or adopted["metadata"].get("finalizers") or adopted["status"].get("secretRef"):
                raise ValueError("Ownership acquisition changed leaf semantics or acquired a Secret/finalizer")
            for secret in json.loads(self.kubectl("get", "secrets", "-n", "auth", "-o", "json"))["items"]:
                if any(ref.get("uid") == uid for ref in secret.get("metadata", {}).get("ownerReferences", [])):
                    raise ValueError("Observe ownership acquisition projected credentials")
            if kind == "hankoserviceaccount":
                if self.api("GET", path + "/client-secret")["value"] != credential:
                    raise ValueError("Installed acquisition rotated the provider credential")
            self.kubectl("patch", kind, name, "-n", "auth", "--type=merge", "-p", '{"spec":{"mode":"Manage"}}')
            # The import latch retains Observe even when spec says Manage.
            time.sleep(2)
            if self.get(kind, name)["metadata"].get("finalizers"):
                raise ValueError("Imported latch allowed destructive authority")
            self.kubectl("label", kind, name, "-n", "auth", "hanko.sh/imported-by-")
            self.kubectl("annotate", kind, name, "-n", "auth", "hanko.sh/adoption-source-", "hanko.sh/adoption-contract-", "hanko.sh/adoption-candidate-")
            wait("explicit adopted Manage", lambda: self.get(kind, name)["metadata"].get("finalizers") and self.ready(kind, name))
            current = self.client("managed", value) if kind == "hankoserviceaccount" else self.api("GET", base + "/roles/" + value)
            if current["id"] != original["id"] or current.get("attributes", {}).get("locale") != ("en" if kind == "hankoserviceaccount" else ["fr"]):
                raise ValueError("Adopted Manage lost native metadata or replaced UUID")
            # Lose status, then restart the real manager. The provider receipt
            # must remain the only ownership checkpoint.
            self.kubectl("patch", kind, name, "-n", "auth", "--subresource=status", "--type=merge", "-p", '{"status":null}')
            if kind == "hankorole":
                current["description"] = "Drift"
                self.api("PUT", base + "/roles/" + value, current)
            else:
                self.kubectl("patch", kind, name, "-n", "auth", "--type=merge", "-p", '{"spec":{"attributes":{"locale":"fr"}}}')
            self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
            self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
            if kind == "hankoserviceaccount":
                wait("adopted service native-field repair", lambda: self.client("managed", value).get("attributes", {}).get("locale") == "fr" and self.ready(kind, name))
                reference = self.get(kind, name)["status"]["secretRef"]["secretRef"]
                if base64.b64decode(self.get("secret", reference["name"])["data"][reference["key"]]).decode() != credential:
                    raise ValueError("Post-Manage recovery changed the service credential")
                self.kubectl("delete", kind, name, "-n", "auth", "--wait=true", "--timeout=120s")
                if self.api("GET", base + "/clients?" + urlencode({"clientId": value})):
                    raise ValueError("Safe adopted client cleanup left its owned node")
            else:
                wait("adopted role drift repair", lambda: self.api("GET", base + "/roles/" + value).get("description") == "Reviewed leaf" and self.role_reconciled(name))
                if (self.api("GET", base + "/roles/" + value + "/composites") != role_composites_before or
                        self.api("GET", base + "/roles/system-foreign-composite") != foreign_composite):
                    raise ValueError("Adopted role lost its foreign composite")
                self.kubectl("delete", kind, name, "-n", "auth", "--wait=false")
                wait("adopted role unproven cleanup refusal", lambda: self.cleanup_conflict(kind, name))
                self.api("GET", base + "/roles/" + value)
                # Explicit Observe withdraws provider deletion consent.
                self.kubectl("patch", kind, name, "-n", "auth", "--type=merge", "-p", '{"spec":{"mode":"Observe"}}')
                wait("Observe releases adopted role finalizer", lambda: not self.exists(kind, name))
                if self.api("GET", base + "/roles/" + value)["id"] != original["id"]:
                    raise ValueError("Observe removed or replaced the adopted role")
        if self.api("GET", base) != realm_before or self.get("hankorealm", "managed")["metadata"].get("finalizers"):
            raise ValueError("Child Manage acquired or changed the external realm")
        self.kubectl("label", "hankorealm", "managed", "-n", "auth", "hanko.sh/imported-by-")
        self.kubectl("delete", "hankoimport", "leaf-inventory", "-n", "auth", "--wait=true", "--timeout=30s")

    def exists(self, kind, name, namespace="auth"):
        result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "get", kind, name,
                                 "-n", namespace, "--ignore-not-found", "-o", "name"], capture_output=True, timeout=30, check=True)
        return bool(result.stdout.strip())

    def cleanup_conflict(self, kind, name, namespace="auth"):
        value = self.get(kind, name, namespace)
        return bool(value["metadata"].get("deletionTimestamp") and value["metadata"].get("finalizers") and any(
            c.get("reason") == "CleanupConflict" for c in value.get("status", {}).get("conditions", [])))

    def adoption_identity(self, name, realm, permissions):
        credential = secrets.token_hex(32)
        self.sensitive.append(credential)
        self.api("POST", "/admin/realms/master/clients", {"clientId": name, "secret": credential,
            "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
        identity, proxy = self.client("master", name), self.client("master", realm + "-realm")
        user = self.api("GET", f'/admin/realms/master/clients/{identity["id"]}/service-account-user')
        roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{permission}') for permission in permissions]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{identity["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        constrained = self.access_token({"client_id": name, "client_secret": credential, "grant_type": "client_credentials"})
        self.api("DELETE", "/admin/realms/" + realm, token=constrained, expected=(403,))
        self.api("PUT", "/admin/realms/" + realm, {"sslRequired": "none"}, token=constrained, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "denied-adoption"}, token=constrained, expected=(403,))
        return credential

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
        run([self.args.helm, "install", namespace, ROOT / "charts/hankoshell-operator", "--namespace", namespace,
             "--kubeconfig", self.config, "--values", config, "--wait", "--timeout", "180s"])
        self.scanned_operators.append((namespace, namespace + "-operator"))
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {
            "name": realm, "namespace": namespace, "labels": {"hanko.sh/imported-by": "external"}}, "spec": {}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": "source", "namespace": namespace},
             "spec": {"mode": "external", "adminRef": {"name": "inventory-credentials"}, "tlsCARef": "operator-ca"}})
        wait("installed external realm observation", lambda: self.ready("hankorealm", realm, namespace) and not self.get("hankorealm", realm, namespace)["metadata"].get("finalizers"))

    def approve_aggregate(self, kind, name, namespace):
        wait("complete installed aggregate candidate " + kind, lambda: self.get(kind, name, namespace).get("status", {}).get("adoptionCandidate", {}).get("approvable") is True)
        target = self.get(kind, name, namespace)
        candidate = target["status"]["adoptionCandidate"]
        if target["metadata"].get("finalizers") or target["spec"].get("mode") != "Observe":
            raise ValueError("Candidate gained lifecycle before explicit Manage")
        self.kubectl("annotate", kind, name, "-n", namespace, "hanko.sh/adoption-source=source",
                     "hanko.sh/adoption-contract=hanko.sh/adoption-contract/v1alpha1",
                     "hanko.sh/adoption-candidate=" + candidate["candidateHash"])
        wait("installed aggregate checkpoint read-back " + kind, lambda: self.get(kind, name, namespace).get("status", {}).get("adoptionReceipt", {}).get("state") == "Verified")
        acquired = self.get(kind, name, namespace)
        if acquired["metadata"].get("finalizers") or acquired["spec"].get("mode") != "Observe":
            raise ValueError("Aggregate checkpoint implicitly granted Manage")
        return {"contractVersion": "hanko.sh/adoption-contract/v1alpha1", "targetKind": acquired["kind"],
                "targetUID": acquired["metadata"]["uid"], "candidateHash": candidate["candidateHash"]}

    def approve_lifecycle(self, kind, name, namespace, operator_name=None):
        def request():
            return any(c.get("type") == "Authorized" and c.get("reason") == "ApprovalRequired"
                       for c in self.get(kind, name, namespace).get("status", {}).get("conditions", []))
        wait("installed lifecycle waits for independent approval", request)
        target = self.get(kind, name, namespace)
        if target.get("status", {}).get("steps") or target.get("status", {}).get("configMapUID"):
            raise ValueError("Unapproved lifecycle request created an execution checkpoint")
        patch = lifecycle.prepare(target)
        author = "lifecycle-fixture-author"
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                    "metadata": {"namespace": namespace, "name": author}, "rules": [{"apiGroups": ["hanko.sh"],
                    "resources": ["hankooperations", "hankosnapshots"], "verbs": ["get", "create", "patch"]}]},
                   {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                    "metadata": {"namespace": namespace, "name": author},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": author},
                    "subjects": [{"kind": "User", "name": author, "apiGroup": "rbac.authorization.k8s.io"}]})
        for identity in (author, f"system:serviceaccount:{namespace}:{operator_name or namespace + '-operator'}"):
            result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "--as=" + identity,
                "patch", kind, name, "-n", namespace, "--type=merge", "-p", json.dumps(patch), "--dry-run=server"],
                capture_output=True, text=True, timeout=30, check=False)
            if result.returncode == 0 or "Lifecycle approval requires independent administrator authority" not in result.stderr:
                raise ValueError("Installed lifecycle self-approval was not independently refused")
        forged = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoSnapshot",
                  "metadata": {"name": "forged-" + name, "namespace": namespace,
                               "annotations": {"hanko.sh/operation-intent": "forged"}},
                  "spec": {"instanceRef": target["spec"]["instanceRef"]}}
        result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "--as=" + author,
            "create", "--dry-run=server", "-f", "-"], input=json.dumps(forged), capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0 or "Lifecycle child provenance requires operator or administrator authority" not in result.stderr:
            raise ValueError("Installed ordinary author forged lifecycle child provenance")
        self.kubectl("--as=lifecycle-fixture-administrator", "--as-group=system:masters",
                     "patch", kind, name, "-n", namespace, "--type=merge", "-p", json.dumps(patch))

    def lifecycle_alias(self):
        """Exercise real Clone/configuration recovery with a read-only provider identity."""
        realm, namespace = "lifecycle-target", "lifecycle-auth"
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True})
        self.api("POST", f"/admin/realms/{realm}/clients", {"clientId": "lifecycle-spa", "protocol": "openid-connect",
            "enabled": True, "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "fullScopeAllowed": False, "redirectUris": ["https://lifecycle.example.test/callback"]})
        roles = ["view-realm", "view-clients", "view-identity-providers"]
        self.adoption_operator(namespace, realm, [*roles, "view-users"], roles, lifecycle_enabled=True)
        source = self.get("hankokeycloakinstance", "source", namespace)
        provider_before, client_before = self.api("GET", "/admin/realms/" + realm), self.client(realm, "lifecycle-spa")
        reader = self.get("secret", "inventory-credentials", namespace)["data"]
        inventory_token = self.access_token({"client_id": namespace + "-reader",
            "client_secret": base64.b64decode(reader["HANKO_KC_CLIENT_SECRET"]).decode(), "grant_type": "client_credentials"})
        self.api("GET", f"/admin/realms/{realm}/groups", token=inventory_token)
        self.api("PUT", f'/admin/realms/{realm}/clients/{client_before["id"]}', {"enabled": False}, token=inventory_token, expected=(403,))
        deployment = namespace + "-operator"
        role = self.get("role", deployment, namespace)
        blocked, protected = [], False
        for rule in role["rules"]:
            if "" in rule.get("apiGroups", []) and "configmaps" in rule.get("resources", []) and "create" in rule.get("verbs", []):
                protected = True
                others = [resource for resource in rule["resources"] if resource != "configmaps"]
                if others:
                    blocked.append({**rule, "resources": others})
                blocked.append({**rule, "resources": ["configmaps"], "verbs": [verb for verb in rule["verbs"] if verb != "create"]})
            else:
                blocked.append(rule)
        if not protected:
            raise ValueError("Lifecycle fixture cannot establish its ConfigMap create denial")
        self.kubectl("patch", "role", deployment, "-n", namespace, "--type=merge", "-p", json.dumps({"rules": blocked}))
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOperation", "metadata": {"name": "clone", "namespace": namespace},
                    "spec": {"type": "Clone", "instanceRef": "source", "clone": {"targetName": "alias"}}})

        self.approve_lifecycle("hankooperation", "clone", namespace)

        def blocked_snapshot():
            operation = self.get("hankooperation", "clone", namespace)
            step = next((s for s in operation.get("status", {}).get("steps", []) if s["name"] == "Snapshot"), {})
            if not step.get("childUID"):
                return False
            snapshot = self.get("hankosnapshot", "op-clone-snap", namespace)
            return (snapshot["metadata"]["uid"] == step["childUID"] and snapshot.get("status", {}).get("intentHash")
                    and not snapshot["status"].get("configMapUID") and snapshot["status"].get("phase") == "Running")

        wait("installed lifecycle durable checkpoint under real RBAC denial", blocked_snapshot)
        snapshot_before = self.get("hankosnapshot", "op-clone-snap", namespace)
        if self.exists("configmap", "snap-op-clone-snap-config", namespace):
            raise ValueError("Lifecycle fixture did not deny capture creation")
        self.kubectl("scale", "deployment/" + deployment, "-n", namespace, "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", namespace, "-l", "app.kubernetes.io/instance=" + namespace, "--timeout=90s")
        self.kubectl("patch", "role", deployment, "-n", namespace, "--type=merge", "-p", json.dumps({"rules": role["rules"]}))
        self.kubectl("scale", "deployment/" + deployment, "-n", namespace, "--replicas=1")
        self.kubectl("rollout", "status", "deployment/" + deployment, "-n", namespace, "--timeout=180s")
        def clone_complete():
            phase = self.get("hankooperation", "clone", namespace).get("status", {}).get("phase")
            if phase == "Failed":
                raise ValueError("Installed Clone failed before complete provider verification")
            return phase == "Done"

        wait("installed configuration alias Clone completion", clone_complete, 240)
        operation = self.get("hankooperation", "clone", namespace)
        snapshot = self.get("hankosnapshot", "op-clone-snap", namespace)
        target, imported = self.get("hankokeycloakinstance", "alias", namespace), self.get("hankoimport", "op-clone-import", namespace)
        steps = {step["name"]: step for step in operation["status"]["steps"]}
        if (set(steps) != {"Snapshot", "CreateTarget", "ImportConfig", "Validate"}
                or any(step["status"] != "Done" for step in steps.values())
                or operation["status"].get("instanceUID") != source["metadata"]["uid"]
                or operation["status"].get("startedGeneration") != operation["metadata"]["generation"]
                or not any(c.get("type") == "Completed" and c.get("status") == "True"
                           and c.get("observedGeneration") == operation["metadata"]["generation"] for c in operation["status"].get("conditions", []))
                or snapshot["metadata"]["uid"] != snapshot_before["metadata"]["uid"]
                or steps["Snapshot"].get("childUID") != snapshot["metadata"]["uid"]
                or steps["CreateTarget"].get("childUID") != target["metadata"]["uid"]
                or steps["ImportConfig"].get("childUID") != imported["metadata"]["uid"]):
            raise ValueError("Installed Clone did not preserve exact durable child identities")
        capture = self.get("configmap", snapshot["status"]["configMapRef"], namespace)
        if (capture["metadata"]["uid"] != snapshot["status"].get("configMapUID") or capture.get("immutable") is not True
                or hashlib.sha256(capture["data"]["snapshot.json"].encode()).hexdigest() != snapshot["status"].get("configHash")
                or [item["metadata"]["name"] for item in json.loads(capture["data"]["snapshot.json"]).get("realms", [])] != [realm]):
            raise ValueError("Installed Clone did not validate its immutable configuration capture")
        if (target["spec"]["mode"] != "external" or target.get("status", {}).get("phase") != "Ready" or target["spec"]["adminRef"] != source["spec"]["adminRef"]
                or target["spec"]["tlsCARef"] != source["spec"]["tlsCARef"] or target["spec"].get("hardenMasterRealm", False)
                or not any(c.get("type") == "AdminAPIReachable" and c.get("status") == "True"
                           and c.get("observedGeneration") == target["metadata"]["generation"] for c in target.get("status", {}).get("conditions", []))
                or imported["status"].get("phase") != "Done" or not imported["status"].get("coverage", {}).get("complete")
                or imported["status"]["coverage"].get("truncated", False)):
            raise ValueError("Installed Clone did not retain verified TLS and complete provider observation")
        for resource in ("hankosnapshots", "hankoimports"):
            if len(json.loads(self.kubectl("get", resource, "-n", namespace, "-o", "json"))["items"]) != 1:
                raise ValueError("Installed Clone restart duplicated a child")
        # Existing aliases remain foreign even when their connection spec matches.
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": "foreign", "namespace": namespace}, "spec": source["spec"]})
        foreign = self.get("hankokeycloakinstance", "foreign", namespace)
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOperation", "metadata": {"name": "foreign", "namespace": namespace},
                    "spec": {"type": "Clone", "instanceRef": "source", "snapshotBefore": False, "clone": {"targetName": "foreign"}}})
        self.approve_lifecycle("hankooperation", "foreign", namespace)
        wait("installed Clone refuses foreign target", lambda: self.get("hankooperation", "foreign", namespace).get("status", {}).get("phase") == "Failed")
        current = self.get("hankokeycloakinstance", "foreign", namespace)
        if (current["metadata"]["uid"] != foreign["metadata"]["uid"] or current["spec"] != foreign["spec"]
                or current["metadata"].get("ownerReferences") or self.exists("hankoimport", "op-foreign-import", namespace)):
            raise ValueError("Installed Clone took ownership of a foreign alias")
        credential = self.adoption_identity("lifecycle-incomplete-reader", realm, ["view-realm", "view-clients", "view-users"])
        token = self.access_token({"client_id": "lifecycle-incomplete-reader", "client_secret": credential, "grant_type": "client_credentials"})
        self.api("GET", f"/admin/realms/{realm}/identity-provider/instances", token=token, expected=(403,))
        self.apply(self.secret("incomplete-inventory", {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
            "HANKO_KC_CLIENT_ID": "lifecycle-incomplete-reader", "HANKO_KC_CLIENT_SECRET": credential}, namespace),
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": "incomplete-source", "namespace": namespace},
             "spec": {"mode": "external", "adminRef": {"name": "incomplete-inventory"}, "tlsCARef": "operator-ca"}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOperation", "metadata": {"name": "incomplete", "namespace": namespace},
             "spec": {"type": "Clone", "instanceRef": "incomplete-source", "snapshotBefore": False, "clone": {"targetName": "incomplete-alias"}}})
        self.approve_lifecycle("hankooperation", "incomplete", namespace)
        wait("installed Clone propagates a real denied inventory read", lambda: self.get("hankooperation", "incomplete", namespace).get("status", {}).get("phase") == "Failed", 180)
        failed = self.get("hankooperation", "incomplete", namespace)["status"]
        child = self.get("hankoimport", "op-incomplete-import", namespace)
        if (child.get("status", {}).get("phase") != "Failed" or child["status"].get("coverage", {}).get("complete", False)
                or not any(step["name"] == "ImportConfig" and step["status"] == "Failed" for step in failed["steps"])
                or not any(c.get("type") == "Completed" and c.get("status") == "False" for c in failed.get("conditions", []))):
            raise ValueError("Installed Clone reported success after incomplete provider discovery")
        if self.api("GET", "/admin/realms/" + realm) != provider_before or self.client(realm, "lifecycle-spa") != client_before:
            raise ValueError("Configuration alias Clone changed the provider")

    def aggregate_manage(self, kind, name, namespace):
        self.kubectl("annotate", kind, name, "-n", namespace, "hanko.sh/adoption-source-", "hanko.sh/adoption-contract-", "hanko.sh/adoption-candidate-")
        self.kubectl("patch", kind, name, "-n", namespace, "--type=merge", "-p", '{"spec":{"mode":"Manage"}}')
        wait("explicit installed aggregate Manage " + kind, lambda: self.ready(kind, name, namespace) and self.get(kind, name, namespace)["metadata"].get("finalizers"))

    def workload_trust(self):
        realm = "workload-trust-target"
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True})
        # Public issuer/JWKS metadata is an explicit fixture administrator
        # prerequisite. The controller adds no anonymous-discovery grants.
        self.apply({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": self.name + "-public-discovery"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:service-account-issuer-discovery"},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:unauthenticated"}]})
        discovery = json.loads(self.kubectl("get", "--raw", "/.well-known/openid-configuration"))
        anchor_uid = self.get("namespace", "kube-system")["metadata"]["uid"]
        ca = self.get("configmap", "kube-root-ca.crt")["data"]["ca.crt"]
        anchor_ca = "sha256:" + hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca)).hexdigest()
        profiles = {"workload-observer": ["view-identity-providers", "view-realm"],
                    "workload-writer": ["manage-identity-providers", "view-realm"],
                    "workload-dependent-reader": ["view-clients"]}
        for name, roles in profiles.items():
            secret = self.adoption_identity(name, realm, roles)
            self.apply(self.secret(name, {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
                "HANKO_KC_CLIENT_ID": name, "HANKO_KC_CLIENT_SECRET": secret}),
                {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": name, "namespace": "auth"},
                 "spec": {"mode": "external", "adminRef": {"name": name}, "tlsCARef": "operator-ca"}})
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoImport", "metadata": {"name": "workload-source", "namespace": "auth"},
            "spec": {"sourceRef": "workload-observer", "realms": [realm], "dryRun": True,
                     "includeClients": False, "includeServiceAccounts": False, "includeIdentityProviders": False}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {"name": realm, "namespace": "auth",
                "labels": {"hanko.sh/imported-by": "workload-source"}}, "spec": {}})
        trust = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoWorkloadTrust", "metadata": {"name": "shared-workload", "namespace": "auth"},
            "spec": {"mode": "Manage", "realmRef": realm, "sourceRef": "workload-observer", "writerRef": "workload-writer",
                     "dependentReaderRef": "workload-dependent-reader", "keycloakAlias": "installed-cluster", "provider": "Kubernetes",
                     "kubernetes": {"issuer": discovery["issuer"], "clusterAnchor": {"kubeSystemNamespaceUID": anchor_uid, "apiServerCAHash": anchor_ca},
                                    "assertionMaxAgeSeconds": 600}}}
        self.apply(trust)
        wait("installed current-cluster shared trust", lambda: self.ready("hankoworkloadtrust", "shared-workload"))
        value = self.get("hankoworkloadtrust", "shared-workload")
        path = "/admin/realms/" + realm + "/identity-provider/instances/installed-cluster"
        native = self.api("GET", path)
        journal = json.loads(native["config"]["hanko.sh/workload-trust-journal"])
        if native["internalId"] != value["status"]["providerID"] or journal["providerID"] != native["internalId"] or journal["owner"] != value["metadata"]["uid"]:
            raise ValueError("Installed trust lacks exact UID/native UUID journal ownership")
        self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
        # Clear diagnostic status after the old process has stopped: only the
        # new controller can reconstruct Ready from current native ownership.
        self.kubectl("patch", "hankoworkloadtrust", "shared-workload", "-n", "auth", "--subresource=status",
                     "--type=merge", "-p", '{"status":null}')
        wait("installed trust reconstructs after restart", lambda: self.ready("hankoworkloadtrust", "shared-workload"))
        if self.api("GET", path)["internalId"] != native["internalId"]:
            raise ValueError("Installed trust restart replaced native UUID")
        self.workload_binding(realm)
        self.kubectl("patch", "hankoworkloadtrust", "shared-workload", "-n", "auth", "--type=merge", "-p", '{"spec":{"kubernetes":{"assertionMaxAgeSeconds":900}}}')
        def review_ready():
            value = self.get("hankoworkloadtrust", "shared-workload")
            return value.get("status", {}).get("observedGeneration") == value["metadata"]["generation"] and any(
                c.get("reason") == "SharedAgeReviewRequired" for c in value.get("status", {}).get("conditions", []))
        wait("installed exact shared-age dependency review", review_ready)
        status = self.get("hankoworkloadtrust", "shared-workload")["status"]
        review = {"contract": "hanko.sh/iam-contract/v1alpha1", "planHash": status["evaluatedPlanHash"],
                  "dependenciesHash": status["dependentInventoryHash"], "reviewHash": status["sharedAgeReviewHash"]}
        self.kubectl("annotate", "hankoworkloadtrust", "shared-workload", "-n", "auth", "hanko.sh/workload-trust-age-review=" + json.dumps(review, separators=(",", ":")))
        wait("installed reviewed shared-age update", lambda: self.ready("hankoworkloadtrust", "shared-workload"))
        if self.api("GET", path)["config"]["fedClientAssertionMaxExp"] != "900":
            raise ValueError("Installed shared-age native read-back differs")
        self.kubectl("delete", "hankoworkloadtrust", "shared-workload", "-n", "auth", "--wait=true", "--timeout=120s")
        self.api("GET", path, expected=(404,))
        if self.get("hankorealm", realm)["metadata"].get("finalizers"):
            raise ValueError("Trust controller acquired external realm lifecycle")
        self.api("GET", "/admin/realms/" + realm)

    def workload_binding(self, realm):
        namespace = "workload-binding"
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "worker", "namespace": namespace}})
        uid = self.get("serviceaccount", "worker", namespace)["metadata"]["uid"]
        credential = self.adoption_identity("workload-client-writer", realm, ["manage-clients", "view-realm"])
        self.apply(self.secret("workload-client-writer", {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
            "HANKO_KC_CLIENT_ID": "workload-client-writer", "HANKO_KC_CLIENT_SECRET": credential}),
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"name": "workload-client-writer", "namespace": "auth"},
             "spec": {"mode": "external", "adminRef": {"name": "workload-client-writer"}, "tlsCARef": "operator-ca"}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "workload-binding", "namespace": namespace},
             "rules": [{"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["worker"], "verbs": ["get"]},
                       {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["identity"], "verbs": ["get", "patch"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "workload-binding", "namespace": namespace},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "workload-binding"},
             "subjects": [{"kind": "ServiceAccount", "name": "system-operator", "namespace": "auth"}]})
        account = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": {"name": "bound-worker", "namespace": "auth"},
            "spec": {"realmRef": realm, "clientID": "bound-worker", "authentication": {"mode": "Kubernetes", "kubernetes": {
                "trustRef": "shared-workload", "sourceRef": "workload-client-writer", "workload": {"namespace": namespace, "serviceAccountRef": "worker", "expectedUID": uid}, "expirationSeconds": 600}}}}
        self.apply(account)
        def bound():
            current = self.get("hankoserviceaccount", "bound-worker")
            return current.get("status", {}).get("observedGeneration") == current["metadata"]["generation"] and any(
                c.get("type") == "WorkloadBindingReady" and c.get("status") == "True" for c in current.get("status", {}).get("conditions", []))
        # BindingReady precedes the durable native activation commit. Editing
        # spec during that transaction correctly invalidates its exact plan.
        wait("installed current native federated activation",
             lambda: bound() and self.ready("hankoserviceaccount", "bound-worker"))
        account = self.get("hankoserviceaccount", "bound-worker")
        prefix = "hanko.sh/workload-runtime-"
        consent = {prefix + "owner-kind": "HankoServiceAccount", prefix + "owner-namespace": "auth", prefix + "owner-name": account["metadata"]["name"],
                   prefix + "owner-uid": account["metadata"]["uid"], prefix + "service-account": "worker", prefix + "service-account-uid": uid}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "identity", "namespace": namespace,
            "labels": {"hanko.sh/runtime-target": "workload-metadata"}, "annotations": consent}, "data": {"unrelated": "preserved"}})
        target_uid = self.get("configmap", "identity", namespace)["metadata"]["uid"]
        self.kubectl("patch", "hankoserviceaccount", "bound-worker", "-n", "auth", "--type=merge", "-p",
            json.dumps({"spec": {"runtimeMetadata": {"configMapRef": "identity", "expectedUID": target_uid}}}))
        def delivered():
            current = self.get("hankoserviceaccount", "bound-worker")
            return bound() and self.ready("hankoserviceaccount", "bound-worker") and current.get("status", {}).get("runtimeMetadata", {}).get("configMapUID") == target_uid
        wait("installed named public runtime metadata", delivered)
        account = self.get("hankoserviceaccount", "bound-worker")
        metadata = self.get("configmap", "identity", namespace)
        document = json.loads(metadata["data"]["workload-identity.json"])
        if account["status"].get("secretRef") or document["authenticationActivation"] != "Federated" or document["workload"]["expectedUID"] != uid or document["bindingRevision"] != account["status"]["workloadBinding"]["bindingRevision"]:
            raise ValueError("Installed activation lost exact public UID/revision evidence")
        before = self.client(realm, "bound-worker")
        if before["clientAuthenticatorType"] != "federated-jwt" or before["attributes"].get("hanko.sh/client-owner-uid") != account["metadata"]["uid"]:
            raise ValueError("Installed controller did not create the owned native federated client")
        self.api("PUT", "/admin/realms/" + realm + "/clients/" + before["id"], {"name": "Preserved display"})
        before = self.client(realm, "bound-worker")
        metadata = self.get("configmap", "identity", namespace)
        self.kubectl("delete", "serviceaccount", "worker", "-n", namespace, "--wait=true")
        self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "worker", "namespace": namespace}})
        if self.get("serviceaccount", "worker", namespace)["metadata"]["uid"] == uid:
            raise ValueError("Workload recreation did not change immutable UID")
        def contained():
            current = self.get("hankoserviceaccount", "bound-worker")
            return not current.get("status", {}).get("workloadBinding") and not current.get("status", {}).get("runtimeMetadata") and self.client(realm, "bound-worker")["enabled"] is False
        wait("installed UID replacement containment", contained)
        after = self.client(realm, "bound-worker")
        before["enabled"] = False
        if before != after or self.get("configmap", "identity", namespace)["data"] != metadata["data"]:
            raise ValueError("UID containment changed independent native fields or delivered stale metadata")
        for verb, resource in (("list", "serviceaccounts"), ("create", "serviceaccounts/token"), ("create", "configmaps"), ("delete", "configmaps")):
            result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "auth", "can-i", verb, resource,
                "-n", namespace, "--as=system:serviceaccount:auth:system-operator"], capture_output=True, timeout=30, check=False)
            if result.returncode != 1 or result.stdout.decode().strip() != "no":
                raise ValueError("Installed binding grant exceeds named get/patch boundary")
        # Fixture administration retires the deliberately invalidated native
        # child only after containment/preservation has been measured. The
        # controller remains blocked on the old workload UID/output consent;
        # this is not a claim of automatic cleanup after UID replacement.
        self.api("DELETE", "/admin/realms/" + realm + "/clients/" + after["id"])

    def organization_adoption(self):
        realm, namespace, name = "adopt-org-target", "adopt-org", "reviewed-root"
        base = "/admin/realms/" + realm
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True, "organizationsEnabled": True})
        self.adoption_operator(namespace, realm,
            ["view-realm", "view-users", "view-organizations", "view-identity-providers", "view-clients"],
            ["view-realm", "manage-users", "manage-organizations", "view-identity-providers", "view-clients"])
        self.api("POST", base + "/groups", {"name": name, "attributes": {"trunx_slug": [name], "locale": ["fr"]}})
        group = self.api("GET", base + "/group-by-path/" + name)
        group_path = base + "/groups/" + group["id"]
        self.api("POST", group_path + "/children", {"name": "foreign-child"})
        foreign = self.api("GET", group_path + "/children")
        self.api("POST", base + "/organizations", {"name": name, "alias": name, "enabled": True,
            "attributes": {"locale": ["en"]}, "domains": [{"name": "reviewed.example.test", "verified": True}]})
        native = [item for item in self.api("GET", base + "/organizations?max=100") if item["alias"] == name][0]
        native_path = base + "/organizations/" + native["id"]
        native = self.api("GET", native_path)
        realm_before = self.api("GET", base)
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOrganization",
            "metadata": {"name": name, "namespace": namespace, "annotations": {"hanko.sh/adoption-source": "source"}},
            "spec": {"mode": "Observe", "realmRef": realm, "name": name, "slug": name, "domains": ["reviewed.example.test"]}})
        receipt = self.approve_aggregate("hankoorganization", name, namespace)
        for path in (group_path, native_path):
            if json.loads(self.api("GET", path)["attributes"]["hanko.sh/adoption-receipt"][0]) != receipt:
                raise ValueError("Installed group/native checkpoints do not share the reviewed receipt")
        self.aggregate_manage("hankoorganization", name, namespace)
        changed = self.api("GET", native_path)
        changed["enabled"] = False
        self.api("PUT", native_path, changed)
        self.kubectl("patch", "hankoorganization", name, "-n", namespace, "--subresource=status", "--type=merge", "-p", '{"status":null}')
        self.kubectl("rollout", "restart", "deployment/" + namespace + "-operator", "-n", namespace)
        self.kubectl("rollout", "status", "deployment/" + namespace + "-operator", "-n", namespace, "--timeout=120s")
        wait("installed adopted native Organization repair", lambda: self.api("GET", native_path).get("enabled") is True and self.ready("hankoorganization", name, namespace))
        if (self.api("GET", group_path)["attributes"].get("locale") != ["fr"] or
                self.api("GET", group_path + "/children") != foreign or self.api("GET", native_path)["domains"] != native["domains"] or
                self.api("GET", native_path)["attributes"].get("locale") != ["en"]):
            raise ValueError("Installed aggregate Manage lost foreign/native state")
        self.kubectl("delete", "hankoorganization", name, "-n", namespace, "--wait=false")
        wait("foreign child holds installed aggregate cleanup", lambda: self.cleanup_conflict("hankoorganization", name, namespace))
        if self.api("GET", group_path + "/children") != foreign:
            raise ValueError("Unsafe Organization cleanup mutated foreign children")
        self.api("DELETE", base + "/groups/" + foreign[0]["id"])
        wait("safe installed aggregate cleanup", lambda: not self.exists("hankoorganization", name, namespace))
        self.api("GET", group_path, expected=(404,))
        self.api("GET", native_path, expected=(404,))
        if self.api("GET", base) != realm_before or self.get("hankorealm", realm, namespace)["metadata"].get("finalizers"):
            raise ValueError("Organization child lifecycle changed the external realm")

    def resourceserver_adoption(self):
        realm, namespace = "adopt-authz-target", "adopt-authz"
        base = "/admin/realms/" + realm
        self.api("POST", "/admin/realms", {"realm": realm, "enabled": True})
        self.adoption_operator(namespace, realm, ["view-realm", "view-clients", "view-authorization"],
            ["view-realm", "manage-clients", "manage-authorization"], sensitive_secrets=("hanko-app-reviewed-api",))
        credential = secrets.token_hex(32)
        self.sensitive.append(credential)
        self.api("POST", base + "/clients", {"clientId": "reviewed-api", "name": "reviewed-api", "secret": credential,
            "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "authorizationServicesEnabled": True, "frontchannelLogout": True, "defaultClientScopes": [], "optionalClientScopes": [], "attributes": {"locale": "en"}})
        backing = self.client(realm, "reviewed-api")
        client_path = base + "/clients/" + backing["id"]
        for scope in self.api("GET", client_path + "/default-client-scopes"):
            self.api("DELETE", client_path + "/default-client-scopes/" + scope["id"])
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
            "metadata": {"name": "api", "namespace": namespace, "annotations": {"hanko.sh/adoption-source": "source"}},
            "spec": {"realmRef": realm, "clientID": "reviewed-api", "type": "m2m", "mode": "Observe"}})
        app_receipt = self.approve_aggregate("hankoapplication", "api", namespace)
        self.aggregate_manage("hankoapplication", "api", namespace)
        authz = client_path + "/authz/resource-server"

        def object_id(collection, name, key="id"):
            matches = [item for item in self.api("GET", authz + "/" + collection + "?max=100") if item["name"] == name]
            if len(matches) != 1:
                raise ValueError("Selected graph identity is ambiguous")
            return matches[0][key]

        self.api("POST", base + "/roles", {"name": "reviewed-readers"})
        principal = self.api("GET", base + "/roles/reviewed-readers")
        self.api("POST", authz + "/scope", {"name": "read", "displayName": "Read"})
        scope_id = object_id("scope", "read")
        self.api("POST", authz + "/resource", {"name": "invoice", "uris": ["/invoice"], "scopes": [{"id": scope_id, "name": "read"}]})
        resource_id = object_id("resource", "invoice", "_id")
        policy_name = "hanko:server:readers:realm_roles"
        self.api("POST", authz + "/policy/role", {"name": policy_name, "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "roles": [{"id": principal["id"], "required": False}]})
        policy_id = object_id("policy", policy_name)
        self.api("POST", authz + "/permission/scope", {"name": "readers", "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "scopes": [scope_id], "resources": [resource_id], "policies": [policy_id]})
        permission_id = object_id("permission", "readers")
        self.api("POST", authz + "/resource", {"name": "foreign-invoice", "uris": ["/foreign"]})
        foreign_id = object_id("resource", "foreign-invoice", "_id")
        foreign = self.api("GET", authz + "/resource/" + foreign_id)
        realm_before = self.api("GET", base)
        selected = {"scopes": [{"name": "read", "id": scope_id}], "resources": [{"name": "invoice", "id": resource_id}],
            "policies": [{"name": "readers#realm_roles", "id": policy_id}], "permissions": [{"name": "readers", "id": permission_id}], "resourceServerID": backing["id"]}
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRole", "metadata": {"name": "readers", "namespace": namespace},
                    "spec": {"mode": "Observe", "realmRef": realm, "name": "reviewed-readers"}},
            {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoResourceServer", "metadata": {
                "name": "server", "namespace": namespace, "annotations": {"hanko.sh/adoption-source": "source"}},
             "spec": {"mode": "Observe", "realmRef": realm, "applicationRef": "api", "audience": "urn:reviewed",
                "scopes": [{"name": "read", "description": "Read"}], "resources": [{"name": "invoice", "uris": ["/invoice"], "scopes": ["read"]}],
                "permissions": [{"name": "readers", "scopes": ["read"], "resources": ["invoice"], "principals": [{"kind": "realm_role", "ref": "readers"}]}]}})
        receipt = self.approve_aggregate("hankoresourceserver", "server", namespace)
        actual = self.client(realm, "reviewed-api")
        journal = json.loads(actual["attributes"]["hanko.sh/resource-server-ownership"])
        if (journal.get("version") != 2 or journal.get("objects") != selected or journal.get("adoptionReceipt") != receipt or
                journal.get("ownerUID") != receipt["targetUID"] or journal.get("realmID") != realm_before["id"] or
                journal.get("applicationUID") != app_receipt["targetUID"]):
            raise ValueError("Installed V2 selected journal identities/receipt differ")
        if json.loads(actual["attributes"]["hanko.sh/adoption-receipt"]) != app_receipt:
            raise ValueError("Installed V2 journal overwrote Application receipt")
        self.kubectl("patch", "hankoresourceserver", "server", "-n", namespace, "--subresource=status", "--type=merge", "-p", '{"status":null}')
        self.aggregate_manage("hankoresourceserver", "server", namespace)
        # Drift a selected field; foreign resource and all selected UUIDs remain.
        self.api("PUT", authz + "/scope/" + scope_id, {"id": scope_id, "name": "read", "displayName": "Drift"})
        self.kubectl("rollout", "restart", "deployment/" + namespace + "-operator", "-n", namespace)
        self.kubectl("rollout", "status", "deployment/" + namespace + "-operator", "-n", namespace, "--timeout=120s")
        wait("installed selected graph drift repair", lambda: self.api("GET", authz + "/scope/" + scope_id).get("displayName") == "Read" and self.ready("hankoresourceserver", "server", namespace))
        if self.api("GET", authz + "/resource/" + foreign_id) != foreign:
            raise ValueError("Installed Manage mutated a foreign graph node")
        self.api("POST", authz + "/resource", {"name": "late-shared", "scopes": [{"id": scope_id, "name": "read"}]})
        shared_id = object_id("resource", "late-shared", "_id")
        self.kubectl("delete", "hankoresourceserver", "server", "-n", namespace, "--wait=false")
        wait("installed foreign incoming dependency cleanup refusal", lambda: self.cleanup_conflict("hankoresourceserver", "server", namespace))
        self.api("GET", authz + "/scope/" + scope_id)
        self.api("DELETE", authz + "/resource/" + shared_id)
        wait("safe selected graph cleanup", lambda: not self.exists("hankoresourceserver", "server", namespace))
        for kind, identity in (("scope", scope_id), ("resource", resource_id), ("policy/role", policy_id), ("permission/scope", permission_id)):
            self.api("GET", authz + "/" + kind + "/" + identity, expected=(404,))
        remaining = self.client(realm, "reviewed-api")
        if (not remaining.get("authorizationServicesEnabled") or "hanko.sh/resource-server-ownership" in remaining["attributes"] or
                json.loads(remaining["attributes"]["hanko.sh/adoption-receipt"]) != app_receipt or self.api("GET", authz + "/resource/" + foreign_id) != foreign):
            raise ValueError("Selected cleanup erased foreign graph or sibling ownership")
        self.kubectl("delete", "hankoapplication", "api", "-n", namespace, "--wait=false")
        wait("foreign authorization graph holds parent deletion", lambda: self.cleanup_conflict("hankoapplication", "api", namespace))
        self.kubectl("patch", "hankoapplication", "api", "-n", namespace, "--type=merge", "-p", '{"spec":{"mode":"Observe"}}')
        wait("explicit Observe releases parent lifecycle", lambda: not self.exists("hankoapplication", "api", namespace))
        if self.client(realm, "reviewed-api")["id"] != backing["id"] or self.api("GET", base) != realm_before:
            raise ValueError("Child cleanup replaced the client or changed the external realm")

    def public_contract_corpus(self):
        path = ROOT / "internal/iamconformance/testdata/public-initial/corpus.json"
        corpus = json.loads(path.read_text())
        aliases = {"portal": "public-application-oidc", "api": "public-application-m2m", "reader": "public-role-composite"}
        for name in ("writer", "viewer"):
            self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRole", "metadata": {"name": "public-" + name, "namespace": "auth"},
                        "spec": {"realmRef": "managed", "name": "public-" + name}})
            wait("public auxiliary owned role", lambda: self.role_reconciled("public-" + name))
        # Parent roles precede scoped clients; the resource server follows its
        # backing client. Logical fixture references are rebound explicitly.
        ordered = sorted(corpus["fixtures"], key=lambda f: {"HankoRole": 0, "HankoApplication": 1, "HankoResourceServer": 2}[f["kind"]])
        objects = []
        clients = []
        for fixture in ordered:
            spec = copy.deepcopy(fixture["spec"])
            spec["realmRef"] = "managed"
            if fixture["kind"] == "HankoRole":
                spec["name"] = "public-" + spec["name"]
                spec["composites"] = ["public-" + name for name in spec.get("composites", [])]
            elif fixture["kind"] == "HankoApplication":
                if spec.get("protocol") == "saml":
                    spec["clientID"] = "https://public-contract.example.test/entity"
                else:
                    spec["clientID"] = "public-" + spec["clientID"]
                spec["realmRoleScopes"] = ["public-" + role for role in spec["realmRoleScopes"]] if "realmRoleScopes" in spec else None
                if spec["realmRoleScopes"] is None:
                    del spec["realmRoleScopes"]
                clients.append(spec["clientID"])
            else:
                spec["applicationRef"] = aliases[spec["applicationRef"]]
                for permission in spec["permissions"]:
                    for principal in permission["principals"]:
                        principal["ref"] = aliases[principal["ref"]]
            name = "public-" + fixture["name"]
            self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": fixture["kind"],
                        "metadata": {"name": name, "namespace": "auth"}, "spec": spec})
            wait("installed public corpus evaluated/applied/observed", lambda: self.iam_reconciled(fixture["kind"].lower(), name))
            objects.append((fixture["kind"].lower(), name))
            if fixture["kind"] == "HankoApplication" and spec.get("protocol", "oidc") == "oidc":
                secret = self.get("secret", "hanko-app-" + spec["clientID"])["data"]["client_secret"]
                self.sensitive.append(base64.b64decode(secret).decode())
        before = {client: self.client("managed", client)["id"] for client in clients}
        owners = {(kind, name): self.get(kind, name)["metadata"]["uid"] for kind, name in objects}
        role_id = self.api("GET", "/admin/realms/managed/roles/public-reader")["id"]
        journal_before = json.loads(self.client("managed", "public-api")["attributes"]["hanko.sh/resource-server-ownership"])
        self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
        for kind, name in objects:
            wait("public corpus readiness after restart", lambda: self.iam_reconciled(kind, name))
            if self.get(kind, name)["metadata"]["uid"] != owners[(kind, name)]:
                raise ValueError("Public corpus object was recreated")
        if any(self.client("managed", name)["id"] != identity for name, identity in before.items()):
            raise ValueError("Public corpus client was duplicated or replaced")
        role = self.api("GET", "/admin/realms/managed/roles/public-reader")
        if role["id"] != role_id or role.get("attributes", {}).get("hanko.sh/role-owner") != [owners[("hankorole", "public-role-composite")]]:
            raise ValueError("Public role UID ownership changed")
        journal = json.loads(self.client("managed", "public-api")["attributes"]["hanko.sh/resource-server-ownership"])
        if journal != journal_before or journal["ownerUID"] != owners[("hankoresourceserver", "public-resource-server")]:
            raise ValueError("Public authorization UID ownership changed")
        for fixture in ordered:
            if fixture["kind"] == "HankoApplication":
                client_id = "https://public-contract.example.test/entity" if fixture["spec"].get("protocol") == "saml" else "public-" + fixture["spec"]["clientID"]
                owner = owners[("hankoapplication", "public-" + fixture["name"])]
                if self.client("managed", client_id).get("attributes", {}).get("hanko.sh/application-owner") != owner:
                    raise ValueError("Public application UID ownership changed")
        self.public_corpus_evidence = {"fixture_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "fixtures": len(objects),
            "restart_preserves_native_identity": True, "cross_release": corpus["limitation"]}
        print("System: public contract corpus and restart passed; cross-release: " + corpus["limitation"], flush=True)

    def reconcile(self):
        self.reject_wrong_ca()
        self.api("POST", "/admin/realms/managed/clients", {"clientId": "unmanaged", "enabled": True, "publicClient": True})
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {"name": "managed", "namespace": "auth"},
                    "spec": {"displayName": "System qualification", "roles": [{"name": "reader"}]}},
                   {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": {"name": "app", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": "system-app", "type": "web", "redirectURIs": ["https://app.example/callback"],
                             "roles": [{"name": "access"}]}},
                   {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": {"name": "observe", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": "unmanaged", "type": "spa", "mode": "Observe"}})
        wait("realm reconciliation", lambda: self.ready("hankorealm", "managed"))
        wait("application reconciliation", lambda: self.ready("hankoapplication", "app"))
        wait("observation", lambda: self.ready("hankoapplication", "observe"))
        self.application_protocols()
        self.ownership_adoption()
        app_uid = self.get("hankoapplication", "app")["metadata"]["uid"]
        wait("namespaced current-API event recording", lambda: any(
            event.get("reason") == "ClientCreated" and event.get("regarding", {}).get("uid") == app_uid
            for event in json.loads(self.kubectl("get", "events.events.k8s.io", "-n", "auth", "-o", "json"))["items"]))
        # Exercise the domain compiler/adapter through the installed manager.
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRole",
                    "metadata": {"name": "contract-role", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "name": "system-contract-role", "description": "contract desired"}})
        wait("IAM contract role reconciliation", lambda: self.role_reconciled("contract-role"))
        role = self.api("GET", "/admin/realms/managed/roles/system-contract-role")
        owner = self.get("hankorole", "contract-role")["metadata"]["uid"]
        if role.get("description") != "contract desired" or role.get("attributes", {}).get("hanko.sh/role-owner") != [owner]:
            raise ValueError("Installed IAM role contract or ownership differs")
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                    "metadata": {"name": "contract-api", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": "system-contract-api", "type": "m2m",
                             "tokenClaims": [{"name": "audience", "claim": "aud", "value": "system-contract-api"}]}})
        wait("IAM backing application", lambda: self.ready("hankoapplication", "contract-api"))
        self.runtime_binding("contract-api", credentials=True)
        self.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoResourceServer",
                    "metadata": {"name": "contract-server", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "applicationRef": "contract-api", "audience": "urn:system-contract",
                             "scopes": [{"name": "read", "description": "Read documents"}],
                             "resources": [{"name": "document", "uris": ["/document"], "scopes": ["read"]}],
                             "permissions": [{"name": "readers", "scopes": ["read"], "resources": ["document"],
                                              "principals": [{"kind": "realm_role", "ref": "contract-role"}]}]}})
        wait("IAM authorization applied/read-back evidence", lambda: self.iam_reconciled("hankoresourceserver", "contract-server"))
        api = self.client("managed", "system-contract-api")
        server_uid = self.get("hankoresourceserver", "contract-server")["metadata"]["uid"]
        journal = json.loads(api.get("attributes", {}).get("hanko.sh/resource-server-ownership", "{}"))
        if journal.get("ownerUID") != server_uid:
            raise ValueError("Installed authorization ownership journal differs")
        self.kubectl("delete", "hankoresourceserver", "contract-server", "-n", "auth", "--wait=true", "--timeout=120s")
        self.authorization_cleaned(api["id"])
        self.kubectl("delete", "hankoapplication", "contract-api", "-n", "auth", "--wait=true", "--timeout=120s")
        self.kubectl("delete", "hankorole", "contract-role", "-n", "auth", "--wait=true", "--timeout=120s")
        if self.api("GET", "/admin/realms/managed/roles?search=system-contract-role"):
            raise ValueError("IAM contract role finalizer left the owned role behind")
        app = self.client("managed", "system-app")
        if app["redirectUris"] != ["https://app.example/callback"] or len(self.api("GET", f'/admin/realms/managed/clients/{app["id"]}/roles?search=access')) != 1:
            raise ValueError("Provider application/roles differ")
        secret = self.get("secret", "hanko-app-system-app")["data"]["client_secret"]
        self.sensitive.append(base64.b64decode(secret).decode())
        realm = self.api("GET", "/admin/realms/managed")
        if realm["displayName"] != "System qualification":
            raise ValueError("Provider realm differs")
        # Drift plus a real manager restart tests informer/cache recovery and
        # credential persistence, without calling Reconcile directly.
        app["redirectUris"] = ["https://drift.example/callback"]
        self.api("PUT", f'/admin/realms/managed/clients/{app["id"]}', app)
        self.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
        wait("drift repair after restart", lambda: self.client("managed", "system-app")["redirectUris"] == ["https://app.example/callback"])
        if self.client("managed", "system-app")["id"] != app["id"] or self.get("secret", "hanko-app-system-app")["data"]["client_secret"] != secret:
            raise ValueError("Restart duplicated the client or rotated its credential")
        self.kubectl("delete", "hankoapplication", "app", "-n", "auth", "--wait=true", "--timeout=120s")
        if self.api("GET", "/admin/realms/managed/clients?clientId=system-app"):
            raise ValueError("Finalizer left the managed client behind")
        self.kubectl("delete", "hankoapplication", "observe", "-n", "auth", "--wait=true", "--timeout=30s")
        self.client("managed", "unmanaged")
        self.standalone_organizations()
        self.organization_adoption()
        self.workload_trust()
        self.resourceserver_adoption()
        self.lifecycle_alias()
        self.public_contract_corpus()
        observability_spec = importlib.util.spec_from_file_location("installed_observability", ROOT / "tools/qualification/scenarios/observability_installed_test.py")
        observability = importlib.util.module_from_spec(observability_spec)
        observability_spec.loader.exec_module(observability)
        self.observability_checks = observability.qualify(self)
        # Verify logs, events and every stored CRD, never exposing Secret values.
        data = ""
        for namespace, deployment in self.scanned_operators:
            data += self.kubectl("logs", "deployment/" + deployment, "-n", namespace) + self.kubectl("get", "events", "-n", namespace, "-o", "json")
            for crd in json.loads(self.kubectl("get", "crds", "-o", "json"))["items"]:
                if crd["spec"]["group"] == "hanko.sh":
                    data += self.kubectl("get", crd["metadata"]["name"], "-n", namespace, "-o", "json")
        if any(value in data for value in self.sensitive) or contains_jwt(data):
            raise ValueError("Credential detected in system logs/events/CRDs (withheld)")

    def cleanup(self):
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=10)
            self.forward_log.close()
        run([self.args.kind, "delete", "cluster", "--name", self.name])
        # No prune: never touch developer-owned clusters or containers.
        if self.registry_created:
            run(["docker", "rm", "--force", self.registry_name])
        if hasattr(self, "keycloak_image"):
            run(["docker", "image", "rm", self.keycloak_image])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    publication.publish.contract.security.verify(args.evidence, args.revision, VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hankoshell-system-private-") as temp:
        system = System(args, Path(temp))
        try:
            system.create_cluster()
            print(f"System: Kubernetes {KUBERNETES_VERSION} running", flush=True)
            system.keycloak()
            print(f"System: HTTPS Keycloak {KEYCLOAK_VERSION} and constrained identity running", flush=True)
            system.install()
            print("System: scanned operator installed through Helm", flush=True)
            system.reconcile()
            args.output.write_text(json.dumps({"version": VERSION, "revision": args.revision, "image_digest": args.digest,
                "kubernetes": KUBERNETES_VERSION, "keycloak": KEYCLOAK_VERSION, "result": "pass", "public_contract": system.public_corpus_evidence, "operational_checks": system.observability_checks, "sensitive_write_checks": system.sensitive_write_checks,
                "checks": ["Helm installation and real pod startup under Restricted admission", "namespace RBAC and current-API event recording",
                           "verified private-CA HTTPS, wrong-CA readiness/write denial and trust repair", "scoped Keycloak identity and denied authority", "realm/client/roles/Secret reconciliation",
                           "IAM role and authorization evaluated/applied/read-back evidence, UID ownership and finalizer cleanup",
                           "legacy OIDC and SAML installed contracts, metadata, UID ownership, Observe/no SAML Secret and deletion",
                           "imported M2M and role reviewed leaf acquisition, exact candidate/receipt/UUID, no acquisition credential access, import latch, explicit Manage, native locale/composite preservation and restart/status-loss recovery",
                           "receipt-backed safe M2M cleanup; role cleanup holds unqualified foreign-reference boundary and explicit Observe preserves the provider",
                           "standalone root/child organization and owned direct-only organizational descendant grant, current applied/read-back evidence, grant cleanup preserving organizations; native alias/domains, role bindings, Synced=True and Projection=Unknown/Disabled, no API URL/token/PositionID and child-first finalizer cleanup",
                           "Organization group/native owner-only checkpoints, same receipt, explicit Manage, native drift repair, foreign child cleanup refusal and safe selected cleanup in an external realm",
                           "Application acquisition followed by ResourceServer selective V2 journal, sibling receipt preservation, exact selected IDs, status-loss/restart recovery, drift repair, late shared dependency cleanup refusal and foreign graph survival",
                           "drift recovery after manager restart without duplicate client or credential rotation", "managed finalizer and Observe preservation", "runtime M2M projected-credential token and rotation", "SAML metadata binding and target-preserving cleanup",
                           "independent typed shared trust in external Observe realm; actual current kube-system UID/public API CA DER anchor and verified issuer/JWKS, three dedicated credentials, native UUID/journal, manager restart, explicit shared-age inventory review and zero-dependent provider-only cleanup",
                           "workload binding and native federated activation: actual cross-namespace named SA/CM get/patch, explicit approved UID and target UID consent, current owned native client and active public-only metadata, recreated-SA containment preserves complete native state except enabled=false; no TokenRequest/list/create/delete grant",
                           "configuration-only Clone alias: explicit lifecycle opt-in and UID/intent approval, ordinary author/operator self-approval and forged-child denial, read-only provider identities, actual ConfigMap-create RBAC denial, durable snapshot checkpoint, manager restart, same child UIDs, immutable capture, complete import and current verified-TLS target observation; foreign target refused and actual denied inventory propagated as failure without provider mutation",
                           "no credentials in logs/events/CRDs"],
                "organization_permissions": {"scope": "organization-target only", "roles": ["manage-realm", "manage-clients", "manage-events", "manage-users"],
                                             "denied": ["master administration", "managed realm administration", "realm creation", "identity providers"]},
                "adoption_permissions": {"scope": "managed target realm", "reader": ["view-realm", "view-clients"],
                                         "writer": ["manage-realm", "manage-clients", "manage-events"],
                                         "reader_denied": ["client PUT", "client-secret GET"]},
                "aggregate_adoption_permissions": {
                    "organizations": {"scope": "adopt-org-target only", "reader": ["view-realm", "view-users", "view-organizations", "view-identity-providers", "view-clients"],
                        "writer": ["view-realm", "manage-users", "manage-organizations", "view-identity-providers", "view-clients"]},
                    "authorization": {"scope": "adopt-authz-target only", "reader": ["view-realm", "view-clients", "view-authorization"],
                        "writer": ["view-realm", "manage-clients", "manage-authorization"]},
                    "denied": ["target realm deletion", "realm security PUT", "global realm creation"]},
                "limitations": ["realm-role definitions require manage-realm with target-realm security/deletion authority; no realm-admin or global administrator",
                                "adopted realm-role cleanup remains held without qualified absence of foreign references",
                                "single disposable kind node and Keycloak dev-file database",
                                "kindnet does not enforce NetworkPolicy; CNI, CSI/cloud, enterprise fleet and DB recovery unqualified"]}, indent=2) + "\n")
            print("System qualification passed", flush=True)
        except Exception as error:
            diagnostics.capture(system, error)
            raise
        finally:
            system.cleanup()


if __name__ == "__main__":
    main()

"""Install the scanned operator chart in kind and reconcile real HTTPS Keycloak.

Only disposable, uniquely named local containers/clusters are modified. The
normal operator uses the chart service account and target-realm Keycloak roles.
"""

import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_system", ROOT / "scripts/release-system-test.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)
run = publication.publish.run
NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
KEYCLOAK = "quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc"
KIND_VERSION = "v0.33.0"


def wait(label, check, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise RuntimeError(label + " deadline exceeded")


class System:
    def __init__(self, args, private):
        self.args, self.private = args, private
        self.name = "hankoshell-system-" + secrets.token_hex(6)
        self.registry_name = self.name + "-registry"
        self.config = private / "kubeconfig"
        self.forward = None
        self.password, self.credential = secrets.token_hex(32), secrets.token_hex(32)
        self.sensitive = [self.password, self.credential]
        self.http, self.token, self.endpoint = None, "", ""
        self.token_at = 0

    def kubectl(self, *args, **kwargs):
        return run([self.args.kubectl, "--kubeconfig", self.config, *args], **kwargs)

    def apply(self, *objects):
        self.kubectl("apply", "-f", "-", input=yaml.safe_dump_all(objects).encode())

    def get(self, kind, name, namespace="auth"):
        return json.loads(self.kubectl("get", kind, name, "-n", namespace, "-o", "json"))

    def ready(self, kind, name):
        value = self.get(kind, name)
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
        run(["docker", "run", "--detach", "--name", self.registry_name, "--publish", "127.0.0.1::5000",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", publication.REGISTRY_IMAGE])
        run([self.args.kind, "create", "cluster", "--name", self.name, "--image", NODE,
             "--kubeconfig", self.config, "--wait", "120s"])
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
            diagnostic = re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED JWT]", diagnostic)
            raise RuntimeError("Local OCI mirror copy failed: " + diagnostic)
        if publication.publish.Registry(self.args.oras, self.args.helm, plain_http=True).resolve(self.registry + "/hankoshell-operator:scanned") != self.args.digest:
            raise ValueError("System-test mirror changed the scanned OCI graph")
        version = json.loads(self.kubectl("version", "-o", "json"))["serverVersion"]["gitVersion"]
        if version != "v1.37.0":
            raise ValueError("Unexpected system Kubernetes version")

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
        file = self.private / "values.yaml"
        file.write_text(yaml.safe_dump(values))
        run([self.args.helm, "install", "system", ROOT / "charts/hankoshell-operator", "--namespace", "auth",
             "--kubeconfig", self.config, "--values", file, "--wait", "--timeout", "180s"])
        pod = json.loads(self.kubectl("get", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "-o", "json"))["items"][0]
        container = pod["spec"]["containers"][0]
        if container["image"] != self.registry + "/hankoshell-operator@" + self.args.digest:
            raise ValueError("Installed image is not the scanned graph")
        if (pod["spec"]["securityContext"]["runAsNonRoot"] is not True or container["securityContext"]["readOnlyRootFilesystem"] is not True
                or "--metrics-bind-address=0" not in container["args"]):
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
                 for name in ("manage-realm", "manage-clients", "manage-users")]
        self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
        self.api("POST", f'/admin/realms/master/clients/{identity["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
        constrained = self.access_token({"client_id": "organization-operator", "client_secret": credential, "grant_type": "client_credentials"})
        for path in ("/admin/realms/master/clients", "/admin/realms/managed/clients",
                     f"/admin/realms/{realm}/identity-provider/instances"):
            self.api("GET", path, token=constrained, expected=(403,))
        self.api("POST", "/admin/realms", {"realm": "organization-denied"}, token=constrained, expected=(403,))
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.37"}}},
            self.secret("operator-credentials", {"client-id": "organization-operator", "client-secret": credential}, namespace),
            self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}, namespace))
        values = yaml.safe_load((self.private / "values.yaml").read_text())
        values["fullnameOverride"] = "organization-operator"
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
            self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoOrganization",
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
            rules.append({"apiGroups": [""], "resources": ["secrets"], "resourceNames": [name], "verbs": ["get", "patch"]})
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
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
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

    def reconcile(self):
        self.reject_wrong_ca()
        self.api("POST", "/admin/realms/managed/clients", {"clientId": "unmanaged", "enabled": True, "publicClient": True})
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {"name": "managed", "namespace": "auth"},
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
        app_uid = self.get("hankoapplication", "app")["metadata"]["uid"]
        wait("namespaced current-API event recording", lambda: any(
            event.get("reason") == "ClientCreated" and event.get("regarding", {}).get("uid") == app_uid
            for event in json.loads(self.kubectl("get", "events.events.k8s.io", "-n", "auth", "-o", "json"))["items"]))
        # Exercise the domain compiler/adapter through the installed manager.
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRole",
                    "metadata": {"name": "contract-role", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "name": "system-contract-role", "description": "contract desired"}})
        wait("IAM contract role reconciliation", lambda: self.role_reconciled("contract-role"))
        role = self.api("GET", "/admin/realms/managed/roles/system-contract-role")
        owner = self.get("hankorole", "contract-role")["metadata"]["uid"]
        if role.get("description") != "contract desired" or role.get("attributes", {}).get("hanko.sh/role-owner") != [owner]:
            raise ValueError("Installed IAM role contract or ownership differs")
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication",
                    "metadata": {"name": "contract-api", "namespace": "auth"},
                    "spec": {"realmRef": "managed", "clientID": "system-contract-api", "type": "m2m",
                             "tokenClaims": [{"name": "audience", "claim": "aud", "value": "system-contract-api"}]}})
        wait("IAM backing application", lambda: self.ready("hankoapplication", "contract-api"))
        self.runtime_binding("contract-api", credentials=True)
        self.apply({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoResourceServer",
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
        # Verify logs, events and every stored CRD, never exposing Secret values.
        data = ""
        for namespace, deployment in (("auth", "system-operator"), ("org-auth", "organization-operator")):
            data += self.kubectl("logs", "deployment/" + deployment, "-n", namespace) + self.kubectl("get", "events", "-n", namespace, "-o", "json")
            for crd in json.loads(self.kubectl("get", "crds", "-o", "json"))["items"]:
                if crd["spec"]["group"] == "hanko.sh":
                    data += self.kubectl("get", crd["metadata"]["name"], "-n", namespace, "-o", "json")
        if any(value in data for value in self.sensitive) or re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", data):
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
    publication.publish.contract.security.verify(args.evidence, args.revision, "0.3.0", args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hankoshell-system-private-") as temp:
        system = System(args, Path(temp))
        try:
            system.create_cluster()
            print("System: Kubernetes 1.37.0 running", flush=True)
            system.keycloak()
            print("System: HTTPS Keycloak 26.8.0 and constrained identity running", flush=True)
            system.install()
            print("System: scanned operator installed through Helm", flush=True)
            system.reconcile()
            args.output.write_text(json.dumps({"version": "0.3.0", "revision": args.revision, "image_digest": args.digest,
                "kubernetes": "1.37.0", "keycloak": "26.8.0", "result": "pass",
                "checks": ["Helm installation and real pod startup under Restricted admission", "namespace RBAC and current-API event recording",
                           "verified private-CA HTTPS, wrong-CA readiness/write denial and trust repair", "scoped Keycloak identity and denied authority", "realm/client/roles/Secret reconciliation",
                           "IAM role and authorization evaluated/applied/read-back evidence, UID ownership and finalizer cleanup",
                           "legacy OIDC and SAML installed contracts, metadata, UID ownership, Observe/no SAML Secret and deletion",
                           "standalone root/child organization, native alias/domains, role bindings, Synced=True and Projection=Unknown/Disabled, no API URL/token/PositionID and child-first finalizer cleanup",
                           "drift recovery after manager restart without duplicate client or credential rotation", "managed finalizer and Observe preservation", "runtime M2M projected-credential token and rotation", "SAML metadata binding and target-preserving cleanup",
                           "no credentials in logs/events/CRDs"],
                "organization_permissions": {"scope": "organization-target only", "roles": ["manage-realm", "manage-clients", "manage-users"],
                                             "denied": ["master administration", "managed realm administration", "realm creation", "identity providers"]},
                "limitations": ["single disposable kind node and Keycloak dev-file database",
                                "kindnet does not enforce NetworkPolicy; CNI, CSI/cloud, enterprise fleet and DB recovery unqualified"]}, indent=2) + "\n")
            print("System qualification passed", flush=True)
        except Exception:
            if system.config.exists():
                for command in (("get", "pods", "-n", "auth"), ("logs", "deployment/keycloak", "-n", "auth", "--tail=50"),
                                ("logs", "deployment/system-operator", "-n", "auth", "--tail=50")):
                    try:
                        diagnostic = system.kubectl(*command)
                        for value in system.sensitive:
                            diagnostic = diagnostic.replace(value, "[REDACTED]")
                        diagnostic = re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED JWT]", diagnostic)
                        print(diagnostic, flush=True)
                    except RuntimeError:
                        pass
            raise
        finally:
            system.cleanup()


if __name__ == "__main__":
    main()

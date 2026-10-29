"""Qualify native Kubernetes client assertions in disposable local fixtures.

This is test infrastructure, never an operator token broker or production writer.
JWTs remain in process memory or kubelet-managed projected volumes; reports contain
only explicitly selected public claims and decisions. No existing cluster is used.
"""

import argparse
import base64
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
import os
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

from tools.qualification.lib.evidence_privacy import contains_jwt
from tools.qualification.fixtures import python_image

ROOT = Path(__file__).resolve().parents[3]

spec = importlib.util.spec_from_file_location("system_fixture", ROOT / "tools/qualification/scenarios/system_test.py")
system = importlib.util.module_from_spec(spec)
spec.loader.exec_module(system)

KEYCLOAK_IMAGES = system.PINS["keycloak"]["images"]
NODE_IMAGES = system.PINS["kubernetes"]["node_images"]
BUILT_NODE = system.PINS["kubernetes"]["built_node"]
POD_IMAGE = python_image.LOCAL_IMAGE
NODE_BASE = BUILT_NODE["base_image"]
NODE_ARCHIVES = BUILT_NODE["sha256"]
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
REALM_ISSUER = "https://keycloak.auth.svc:8443/realms/managed"
CONTROLLER_REALM = "controller-managed"
CONTROLLER_ISSUER = "https://keycloak.auth.svc:8443/realms/" + CONTROLLER_REALM


def run(args, input=None, timeout=240, include_stderr=False):
    try:
        result = subprocess.run([str(a) for a in args], input=input, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise system.diagnostics.DeadlineExceeded("Disposable workload fixture command", timeout, timeout) from None
    if result.returncode:
        # Never render arguments, stdout, stderr, or stdin: a failed token read or
        # TokenReview could otherwise disclose a credential through diagnostics.
        raise RuntimeError("Disposable workload fixture command failed: " + Path(str(args[0])).name)
    return (result.stdout + (result.stderr if include_stderr else b"")).decode()


def claims(token):
    encoded = token.split(".")[1]
    value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    return {k: value[k] for k in ("iss", "sub", "aud", "iat", "nbf", "exp", "kubernetes.io") if k in value}


def binding_subject(namespace, name):
    label = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    if (name == "default" or len(namespace) > 63 or len(name) > 253
            or not re.fullmatch(label, namespace) or not re.fullmatch(label + r"(?:\." + label + r")*", name)):
        raise ValueError("A dedicated, explicit ServiceAccount is required")
    return "system:serviceaccount:" + namespace + ":" + name


def safe_report(report, sensitive):
    encoded = json.dumps(report, indent=2) + "\n"
    if any(secret and secret in encoded for secret in sensitive) or contains_jwt(encoded):
        raise ValueError("Credential found in report (withheld)")
    return encoded


def public_report(report):
    # Uploaded evidence is deliberately narrower than local fixture evidence.
    # Never publish full provider/client/flow/permission representations.
    keys = ("keycloak_version", "kubernetes_version", "publishable", "complete", "started_at", "completed_at",
            "fixture_sha256", "node_image", "keycloak_image", "controller_authentication",
            "no_jwt_in_logs_events_secrets_configmaps", "projected_rotation", "secret_recovered_without_rotation")
    result = {key: report[key] for key in keys if key in report}
    result["checks"] = {name: {"http_status": value["http_status"]} for name, value in report.get("checks", {}).items()}
    result["check_count"] = len(result["checks"])
    return result


class Fixture(system.System):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.name = "hankoshell-workload-" + secrets.token_hex(6)
        self.config = private / "kubeconfig"
        self.report = {"keycloak_version": args.keycloak_version,
                       "kubernetes_version": args.kubernetes_version,
                       "publishable": False, "complete": False, "checks": {},
                       "started_at": datetime.now(timezone.utc).isoformat(),
                       "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        self.foreign_name = self.name + "-foreign"
        self.foreign_config = private / "foreign-kubeconfig"
        self.owned_clusters = set()

    def reserve_cluster(self, name):
        if name in run([self.args.kind, "get", "clusters"]).splitlines():
            raise ValueError("Disposable fixture name already exists; refusing to touch it")
        self.owned_clusters.add(name)

    def kubectl(self, *args, **kwargs):
        return run([self.args.kubectl, "--kubeconfig", self.config, *args], **kwargs)

    def create_cluster(self):
        if not run([self.args.kind, "version"]).startswith("kind " + system.KIND_VERSION + " "):
            raise ValueError("Use the pinned kind fixture")
        if self.args.kubernetes_version == BUILT_NODE["version"]:
            self.build_node()
        else:
            self.node_image = NODE_IMAGES[self.args.kubernetes_version]
        node = self.node_image
        self.reserve_cluster(self.name)
        run([self.args.kind, "create", "cluster", "--name", self.name,
             "--image", node, "--kubeconfig", self.config, "--wait", "120s"])
        self.report["python_fixture"] = python_image.load(self.args.kind, self.name)
        actual = json.loads(self.kubectl("version", "-o", "json"))["serverVersion"]["gitVersion"]
        if actual != "v" + self.args.kubernetes_version:
            raise ValueError("The real Kubernetes server version differs from the requested qualification")
        self.report["node_image"] = node
        self.report["discovery"] = json.loads(self.kubectl("get", "--raw", "/.well-known/openid-configuration"))
        self.report["cluster_namespace_uid"] = self.get("namespace", "kube-system")["metadata"]["uid"]
        configuration = json.loads(self.kubectl("config", "view", "--raw", "-o", "json"))
        ca = base64.b64decode(configuration["clusters"][0]["cluster"]["certificate-authority-data"])
        self.report["cluster_ca_sha256"] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode())).hexdigest()
        server = self.get("pod", "kube-apiserver-" + self.name + "-control-plane", "kube-system")
        self.report["apiserver_token_flags"] = [arg for arg in server["spec"]["containers"][0]["command"]
            if arg.startswith(("--service-account-max-token-expiration=", "--service-account-extend-token-expiration="))]

    def build_node(self):
        # No published kind node exists for 1.36.2. Build the exact official
        # server archive, never substitute another patch version.
        architecture = run(["docker", "info", "--format", "{{.Architecture}}"]).strip()
        architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(architecture, architecture)
        if architecture not in NODE_ARCHIVES:
            raise ValueError("Unqualified Docker architecture")
        archive = self.args.node_archive or self.private / "kubernetes-server.tar.gz"
        if self.args.node_archive is None:
            url = f"https://dl.k8s.io/release/v{BUILT_NODE['version']}/kubernetes-server-linux-{architecture}.tar.gz"
            total = 0
            with urlopen(url, timeout=120) as response, archive.open("wb") as destination:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 1024**3:
                        raise ValueError("Kubernetes archive exceeds fixture budget")
                    destination.write(chunk)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != NODE_ARCHIVES[architecture]:
            raise ValueError("Kubernetes server archive checksum mismatch")
        self.built_node_image = self.name + "-node:v" + BUILT_NODE["version"]
        print(f"Building checksum-verified Kubernetes v{BUILT_NODE['version']} node", flush=True)
        run([self.args.kind, "build", "node-image", "--type", "file", "--base-image", NODE_BASE,
             "--image", self.built_node_image, archive], timeout=600)
        self.node_image = self.built_node_image
        self.report["node_build"] = {"server_archive_sha256": digest, "base_image": NODE_BASE, "architecture": architecture}

    def keycloak_build(self, build, image):
        dockerfile = build / "Dockerfile"
        dockerfile.write_text(f"FROM {image}\nRUN /opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true\n")
        return dockerfile

    def keycloak_start_arguments(self):
        return []

    def keycloak(self):
        build = self.private / "keycloak-build"
        build.mkdir()
        image = KEYCLOAK_IMAGES[self.args.keycloak_version]
        dockerfile = self.keycloak_build(build, image)
        self.keycloak_image = self.name + "-keycloak:fixture"
        run(["docker", "build", "--network=none", "--tag", self.keycloak_image, "--file", dockerfile, build])
        run([self.args.kind, "load", "docker-image", self.keycloak_image, "--name", self.name])
        cert, key = self.private / "tls.crt", self.private / "tls.key"
        run([self.args.openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-keyout", key, "-out", cert, "-days", str(getattr(self, "certificate_days", 1)), "-subj", "/CN=keycloak.auth.svc",
             "-addext", "subjectAltName=DNS:keycloak.auth.svc,DNS:localhost" + getattr(self, "extra_certificate_names", ""),
             "-addext", "basicConstraints=critical,CA:true"])
        self.http = ssl.create_default_context(cafile=str(cert))
        self.http.minimum_version = ssl.TLSVersion.TLSv1_3
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "auth", "labels": {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v" + self.args.kubernetes_version.rsplit(".", 1)[0]}}},
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "workload"}},
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other"}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "keycloak-discovery", "namespace": "auth"}},
            self.secret("keycloak-bootstrap", {"username": "fixture-admin", "password": self.password}),
            self.secret("keycloak-tls", {"tls.crt": cert.read_text(), "tls.key": key.read_text()}))
        security = {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"}}
        self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "keycloak", "namespace": "auth"}, "spec": {
            "replicas": 1, "selector": {"matchLabels": {"app": "keycloak"}}, "template": {
                "metadata": {"labels": {"app": "keycloak"}}, "spec": {
                    "securityContext": security, "serviceAccountName": "keycloak-discovery",
                    "automountServiceAccountToken": True,
                    "containers": [{"name": "keycloak", "image": self.keycloak_image, "imagePullPolicy": "IfNotPresent", "args": ["start", "--optimized",
                        "--http-enabled=false", "--http-management-scheme=http", "--hostname=https://keycloak.auth.svc:8443", "--https-protocols=TLSv1.3",
                        "--https-certificate-file=/tls/tls.crt", "--https-certificate-key-file=/tls/tls.key", *self.keycloak_start_arguments()],
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
        log = self.private / "port-forward.log"
        self.forward_log = log.open("wb")
        self.forward = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "port-forward", "-n", "auth",
                                         "service/keycloak", ":8443", "--address", "127.0.0.1"], stdout=self.forward_log, stderr=subprocess.STDOUT)
        system.wait("Keycloak port-forward", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()) is not None, 30)
        self.endpoint = "https://localhost:" + re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]
        self.token = self.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password})
        self.token_at = time.monotonic()
        self.api("POST", "/admin/realms", {"realm": "managed", "enabled": True})
        self.report["keycloak_image"] = image

    def pod(self, name, account, namespace="workload"):
        self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account, "namespace": namespace}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "keycloak-ca", "namespace": namespace},
             "data": {"ca.crt": (self.private / "tls.crt").read_text()}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace}, "spec": {
                "serviceAccountName": account, "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "probe", "image": POD_IMAGE, "imagePullPolicy": "Never", "command": ["python", "-c", "import time; time.sleep(1800)"],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "tokens", "mountPath": "/tokens", "readOnly": True},
                                     {"name": "ca", "mountPath": "/ca", "readOnly": True}]}],
                "volumes": [{"name": "tokens", "projected": {"sources": [
                    {"serviceAccountToken": {"audience": REALM_ISSUER, "expirationSeconds": 600, "path": "assertion"}},
                    {"serviceAccountToken": {"audience": CONTROLLER_ISSUER, "expirationSeconds": 600, "path": "controller-assertion"}},
                    {"serviceAccountToken": {"audience": "https://wrong.invalid", "expirationSeconds": 600, "path": "wrong-audience"}}]}},
                    {"name": "ca", "configMap": {"name": "keycloak-ca"}}]}})
        self.kubectl("wait", "--for=condition=Ready", "pod/" + name, "-n", namespace, "--timeout=180s")

    def projected(self, name="probe", namespace="workload", path="assertion"):
        token = self.kubectl("exec", "-n", namespace, name, "--", "cat", "/tokens/" + path).strip()
        self.sensitive.append(token)
        return token

    def assertion(self, token, client="workload-a", realm="managed"):
        fields = {"grant_type": "client_credentials", "client_id": client,
                  "client_assertion_type": ASSERTION_TYPE, "client_assertion": token}
        return self.exchange(fields, realm)

    def token_request(self, account="worker", namespace="workload", audiences=None, seconds=600, foreign=False):
        request = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": seconds}}
        if audiences is not None:
            request["spec"]["audiences"] = audiences
        config = self.foreign_config if foreign else self.config
        result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(config), "create", "--raw",
            f"/api/v1/namespaces/{namespace}/serviceaccounts/{account}/token", "-f", "-"],
            input=json.dumps(request).encode(), capture_output=True, timeout=30)
        if result.returncode:
            return None
        token = json.loads(result.stdout)["status"]["token"]
        self.sensitive.append(token)
        return token

    def review(self, token):
        result = json.loads(self.kubectl("create", "--raw", "/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-",
            input=json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                "spec": {"token": token, "audiences": [REALM_ISSUER]}}).encode()))["status"]
        return {"authenticated": result.get("authenticated", False), "uid": result.get("user", {}).get("uid")}

    def pod_exchange(self):
        # The HTTP request runs inside the Pod and reads the actual projected
        # volume. Only a filtered decision returns to the test driver.
        script = '''import json,ssl,urllib.request,urllib.parse,urllib.error,base64
token=open('/tokens/assertion').read().strip()
fields={'grant_type':'client_credentials','client_id':'workload-a','client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':token}
ctx=ssl.create_default_context(cafile='/ca/ca.crt');ctx.minimum_version=ssl.TLSVersion.TLSv1_3
try:
 r=urllib.request.urlopen(urllib.request.Request('https://keycloak.auth.svc:8443/realms/managed/protocol/openid-connect/token',data=urllib.parse.urlencode(fields).encode()),context=ctx,timeout=15)
 d=json.load(r);a=d['access_token'].split('.')[1];c=json.loads(base64.urlsafe_b64decode(a+'='*(-len(a)%4)))
 print(json.dumps({'http_status':r.status,'issuer':c['iss'],'authorized_party':c['azp'],'expires_in':d['expires_in']}))
except urllib.error.HTTPError as e:
 print(json.dumps({'http_status':e.code,'oauth_error':json.load(e).get('error')}))
'''
        return json.loads(self.kubectl("exec", "-i", "-n", "workload", "probe", "--", "python", "-", input=script.encode()))

    def foreign_cluster(self):
        node = self.node_image
        issuer = "https://" + self.foreign_name + "-control-plane:6443"
        # kind deliberately retains kubeadm v1beta3 for Kubernetes < 1.36.
        legacy = self.args.kubernetes_version == "1.35.0"
        version = "v1beta3" if legacy else "v1beta4"
        extra = {"service-account-issuer": issuer} if legacy else [{"name": "service-account-issuer", "value": issuer}]
        configuration = {"apiVersion": "kind.x-k8s.io/v1alpha4", "kind": "Cluster", "nodes": [{"role": "control-plane",
            "kubeadmConfigPatches": [yaml.safe_dump({"apiVersion": "kubeadm.k8s.io/" + version, "kind": "ClusterConfiguration",
                "apiServer": {"certSANs": [self.foreign_name + "-control-plane"],
                    "extraArgs": extra}})]}]}
        path = self.private / "foreign-kind.yaml"
        path.write_text(yaml.safe_dump(configuration))
        self.reserve_cluster(self.foreign_name)
        run([self.args.kind, "create", "cluster", "--name", self.foreign_name, "--image", node,
             "--config", path, "--kubeconfig", self.foreign_config, "--wait", "120s"])
        run([self.args.kubectl, "--kubeconfig", self.foreign_config, "create", "namespace", "workload"])
        run([self.args.kubectl, "--kubeconfig", self.foreign_config, "create", "serviceaccount", "worker", "-n", "workload"])
        actual = json.loads(run([self.args.kubectl, "--kubeconfig", self.foreign_config, "get", "--raw", "/.well-known/openid-configuration"]))
        self.report["foreign_discovery"] = actual
        if actual["issuer"] != issuer:
            raise ValueError("Foreign cluster issuer was not applied")
        # This fixture explicitly publishes discovery/JWKS, not workload tokens.
        # External Keycloak has no mounted Kubernetes credential.
        public = [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                   "metadata": {"name": "fixture-public-jwks"}, "rules": [{"nonResourceURLs": ["/.well-known/openid-configuration", "/openid/v1/jwks"], "verbs": ["get"]}]},
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                   "metadata": {"name": "fixture-public-jwks"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "fixture-public-jwks"},
                   "subjects": [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:unauthenticated"}]}]
        run([self.args.kubectl, "--kubeconfig", self.foreign_config, "apply", "-f", "-"], input=yaml.safe_dump_all(public).encode())

    def client_update(self, changes, name="workload-a"):
        client = self.client("managed", name)
        client.update(changes)
        self.api("PUT", "/admin/realms/managed/clients/" + client["id"], client)

    def permissions(self):
        self.api("POST", "/admin/realms", {"realm": "unrelated", "enabled": True})
        self.api("POST", "/admin/realms/managed/users", {"username": "impersonation-target", "enabled": True})
        target = self.api("GET", "/admin/realms/managed/users?username=impersonation-target")[0]["id"]
        proxy = self.client("master", "managed-realm")
        records = {}
        for profile, role_names in (("trust-writer", ["manage-identity-providers"]),
                                    ("trust-reader", ["view-identity-providers"]),
                                    ("client-writer", ["manage-clients"]),
                                    ("federated-writer", ["manage-clients", "view-realm"]),
                                    ("flow-reader", ["view-realm"])):
            secret = secrets.token_hex(32)
            self.sensitive.append(secret)
            self.api("POST", "/admin/realms/master/clients", {"clientId": profile, "secret": secret,
                "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
                "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
            client = self.client("master", profile)
            user = self.api("GET", f'/admin/realms/master/clients/{client["id"]}/service-account-user')
            roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{role}') for role in role_names]
            self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
            self.api("POST", f'/admin/realms/master/clients/{client["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
            token = self.access_token({"client_id": profile, "client_secret": secret, "grant_type": "client_credentials"})
            denied = [("POST", "/admin/realms/managed/users", {"username": "forbidden"}),
                ("DELETE", "/admin/realms/managed", None),
                ("PUT", "/admin/realms/managed", {"sslRequired": "none"}),
                ("POST", "/admin/realms", {"realm": "forbidden"}),
                ("PUT", "/admin/realms/master", {"enabled": False}),
                ("PUT", "/admin/realms/unrelated", {"enabled": False}),
                ("POST", f"/admin/realms/managed/users/{target}/impersonation", {})]
            for method, path, data in denied:
                self.api(method, path, data, token=token, expected=(403,))
            record = {"roles": role_names, "denials": [method + " " + path for method, path, _ in denied]}
            if profile == "trust-writer":
                base = "/admin/realms/managed/identity-provider/instances"
                payload = {"alias": "permission-proof", "providerId": "kubernetes", "enabled": True,
                           "config": {"issuer": self.report["foreign_discovery"]["issuer"]}}
                self.api("POST", base, payload, token=token)
                observed = self.api("GET", base + "/permission-proof", token=token)
                observed["displayName"] = "updated-by-trust-writer"
                self.api("PUT", base + "/permission-proof", observed, token=token)
                self.api("DELETE", base + "/permission-proof", token=token)
                self.api("GET", base + "/permission-proof", token=token, expected=(404,))
                record["provider_crud"] = True
                # This role is realm-wide: an unrelated broker is writable too.
                unrelated = {"alias": "unrelated-broker", "providerId": "oidc", "config": {"clientId": "public-test"}}
                self.api("POST", base, unrelated, token=token)
                self.api("DELETE", base + "/unrelated-broker", token=token)
                record["unrelated_idp_write"] = "allowed (realm-wide native role)"
                self.api("GET", "/admin/realms/managed/authentication/flows", token=token, expected=(403,))
            elif profile == "trust-reader":
                base = "/admin/realms/managed/identity-provider/instances"
                self.api("GET", base, token=token)
                observed = self.api("GET", base + "/workload-kube", token=token)
                self.api("POST", base, {"alias": "forbidden-trust", "providerId": "kubernetes"}, token=token, expected=(403,))
                self.api("PUT", base + "/workload-kube", observed, token=token, expected=(403,))
                self.api("DELETE", base + "/workload-kube", token=token, expected=(403,))
                record["provider_read_only"] = True
            elif profile in ("client-writer", "federated-writer"):
                self.api("POST", "/admin/realms/managed/clients", {"clientId": "permission-" + profile,
                    "serviceAccountsEnabled": True, "clientAuthenticatorType": "federated-jwt",
                    "attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": "permission-subject"}}, token=token)
                observed = self.client("managed", "permission-" + profile)
                self.api("GET", "/admin/realms/managed/clients/" + observed["id"], token=token)
                native_secret = self.api("GET", "/admin/realms/managed/clients/" + observed["id"] + "/client-secret", token=token).get("value")
                if not native_secret:
                    raise ValueError("Scoped client writer cannot read the native recovery credential")
                self.sensitive.append(native_secret)
                record["native_secret_recovery_read"] = True
                self.api("PUT", "/admin/realms/managed/clients/" + observed["id"], observed, token=token)
                self.api("DELETE", "/admin/realms/managed/clients/" + observed["id"], token=token)
                record["client_crud"] = True
                self.api("GET", "/admin/realms/managed/identity-provider/instances", token=token, expected=(403,))
                if profile == "federated-writer":
                    record["flow_reads"] = self.api("GET", "/admin/realms/managed/authentication/flows/clients/executions", token=token)
                else:
                    self.api("GET", "/admin/realms/managed/authentication/flows", token=token, expected=(403,))
            else:
                record["flow_reads"] = self.api("GET", "/admin/realms/managed/authentication/flows/clients/executions", token=token)
                self.api("POST", "/admin/realms/managed/authentication/flows/clients/copy", {"newName": "forbidden-flow"}, token=token, expected=(403,))
            records[profile] = record
        self.report["permissions"] = records

    def exchange(self, fields, realm="managed"):
        try:
            with urlopen(Request(self.endpoint + "/realms/" + realm + "/protocol/openid-connect/token",
                                 data=urlencode(fields).encode()), context=self.http, timeout=10) as response:
                status, body = response.status, response.read(65_537)
        except HTTPError as error:
            status, body = error.code, error.read(8193)
        data = json.loads(body)
        if "access_token" in data:
            access = data["access_token"]
            self.sensitive.append(access)
            c = claims(access)
            # Access tokens have additional machine-client claims; select safely.
            raw = json.loads(base64.urlsafe_b64decode(access.split(".")[1] + "=" * (-len(access.split(".")[1]) % 4)))
            if realm == CONTROLLER_REALM and fields.get("client_id") in ("controller-worker", "controller-secret"):
                if raw.get("workload_qualification") != "controller-managed":
                    raise ValueError("Controller-managed typed token claim missing from active authentication")
            return {"http_status": status, "issuer": c["iss"], "subject": c["sub"], "authorized_party": raw.get("azp"),
                    "expires_in": data["expires_in"]}
        return {"http_status": status, "oauth_error": data.get("error")}

    def prepare_native(self):
        provider = {"alias": "workload-kube", "providerId": "kubernetes", "enabled": True,
                    "config": {"issuer": self.report["discovery"]["issuer"],
                               "hanko.sh/workload-trust-owner": self.get("namespace", "auth")["metadata"]["uid"]}}
        self.api("POST", "/admin/realms/managed/identity-provider/instances", provider)
        self.report["provider_created"] = self.api("GET", "/admin/realms/managed/identity-provider/instances/workload-kube")
        self.api("POST", "/admin/realms/managed/clients", {"clientId": "workload-a", "protocol": "openid-connect",
            "enabled": True, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "fullScopeAllowed": False, "clientAuthenticatorType": "federated-jwt",
            "attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": binding_subject("workload", "worker")}})
        client = self.client("managed", "workload-a")
        self.report["client_created"] = {k: client[k] for k in ("id", "clientId", "clientAuthenticatorType", "serviceAccountsEnabled", "attributes")}
        self.api("POST", "/admin/realms/managed/clients", {"clientId": "workload-b", "protocol": "openid-connect",
            "enabled": True, "publicClient": False, "serviceAccountsEnabled": True, "clientAuthenticatorType": "federated-jwt",
            "attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": binding_subject("workload", "other")}})

    def check(self, name, value, expected_status, client="workload-a", issuer=REALM_ISSUER):
        self.report["checks"][name] = value
        print(name + ": HTTP " + str(value["http_status"]), flush=True)
        statuses = expected_status if isinstance(expected_status, tuple) else (expected_status,)
        if value["http_status"] not in statuses:
            raise ValueError("Native qualification unexpected result: " + name)
        if value["http_status"] == 200 and (value.get("authorized_party") != client or value.get("issuer") != issuer):
            raise ValueError("Native token is not bound to the expected machine client and realm")

    def controller_action(self, action):
        # The production reconciler receives no projected assertion. Its only
        # credential input is the four separately constrained admin identities.
        self.controller_input["Action"] = action
        path = self.private / "controller-input.json"
        path.write_text(json.dumps(self.controller_input))
        path.chmod(0o600)
        env = dict(os.environ, HANKO_NATIVE_CONTROLLER_INPUT=str(path))
        result = subprocess.run([str(self.controller_binary), "-test.run=^TestNativeWorkloadAuthenticationController$",
                                 "-test.timeout=120s"], env=env, capture_output=True, timeout=150)
        if result.returncode:
            # This tagged harness logs only bounded reasons, but diagnostics
            # still stay in the private, disposable fixture directory.
            (self.private / "controller-failure.log").write_bytes(result.stdout + result.stderr)
            failure = self.args.output.with_suffix(".controller-private.log")
            failure.write_bytes(result.stdout + result.stderr)
            failure.chmod(0o600)
            raise RuntimeError("Native production controller action failed: " + action)

    def controller_authentication(self):
        self.api("POST", "/admin/realms", {"realm": CONTROLLER_REALM, "enabled": True})
        profiles = {"controller-observer": ["view-identity-providers", "view-realm"],
                    "controller-trust-writer": ["manage-identity-providers", "view-realm"],
                    "controller-dependent-reader": ["view-clients"],
                    "controller-client-writer": ["manage-clients", "view-realm"]}
        credentials = {name: self.adoption_identity(name, CONTROLLER_REALM, roles) for name, roles in profiles.items()}
        self.pod("controller-legacy", "controller-legacy")
        self.controller_input = {"Endpoint": self.endpoint, "CA": (self.private / "tls.crt").read_text(),
            "Kubeconfig": str(self.config), "Realm": CONTROLLER_REALM, "Issuer": self.report["discovery"]["issuer"],
            "KeysHash": "sha256:" + hashlib.sha256(self.kubectl("get", "--raw", "/openid/v1/jwks").encode()).hexdigest(),
            "ExpectedUID": self.get("serviceaccount", "worker", "workload")["metadata"]["uid"],
            "LegacyUID": self.get("serviceaccount", "controller-legacy", "workload")["metadata"]["uid"], "Credentials": credentials}
        self.controller_binary = self.private / "native-controller.test"
        run(["go", "test", "-c", "-tags=native_workload_qualification", "./internal/controller", "-o", self.controller_binary], timeout=240)
        self.controller_action("create")
        self.controller_check("controller_fresh_assertion", self.assertion(self.projected(path="controller-assertion"), "controller-worker", CONTROLLER_REALM), 200, "controller-worker")
        worker = self.client(CONTROLLER_REALM, "controller-worker")
        worker_secret = self.api("GET", f'/admin/realms/{CONTROLLER_REALM}/clients/{worker["id"]}/client-secret')["value"]
        self.sensitive.append(worker_secret)
        self.controller_check("controller_fresh_rejects_secret", self.exchange({"grant_type": "client_credentials", "client_id": "controller-worker", "client_secret": worker_secret}, CONTROLLER_REALM), (400, 401), "controller-worker")
        self.controller_action("secret")
        legacy = self.client(CONTROLLER_REALM, "controller-secret")
        credential = self.api("GET", f'/admin/realms/{CONTROLLER_REALM}/clients/{legacy["id"]}/client-secret')["value"]
        self.sensitive.append(credential)
        fields = {"grant_type": "client_credentials", "client_id": "controller-secret", "client_secret": credential}
        self.controller_check("controller_legacy_secret", self.exchange(fields, CONTROLLER_REALM), 200)
        self.controller_check("controller_legacy_rejects_assertion", self.assertion(self.projected("controller-legacy", path="controller-assertion"), "controller-secret", CONTROLLER_REALM), (400, 401))
        for request in ("prepare-federated", "prepare-fallback", "prepare-return"):
            self.controller_action(request)
            before_approval = self.client(CONTROLLER_REALM, "controller-secret")
            expected_before = "federated-jwt" if request == "prepare-fallback" else "client-secret"
            if before_approval["clientAuthenticatorType"] != expected_before:
                raise ValueError("Controller changed native authentication before exact approval")
            self.controller_action("approve")
            applied = self.client(CONTROLLER_REALM, "controller-secret")
            if applied["clientAuthenticatorType"] != ("client-secret" if request == "prepare-fallback" else "federated-jwt"):
                raise ValueError("Approved controller method was not applied")
            fallback = request == "prepare-fallback"
            self.controller_check("controller_" + request + "_assertion", self.assertion(self.projected("controller-legacy", path="controller-assertion"), "controller-secret", CONTROLLER_REALM), (400, 401) if fallback else 200)
            self.controller_check("controller_" + request + "_secret", self.exchange(fields, CONTROLLER_REALM), 200 if fallback else (400, 401))
            if not fallback:
                # AuthReviewed is authored by this external workload fixture
                # only after its actual projected assertion succeeded.
                self.controller_action("review")
            after = self.client(CONTROLLER_REALM, "controller-secret")
            retained = self.api("GET", f'/admin/realms/{CONTROLLER_REALM}/clients/{after["id"]}/client-secret')["value"]
            if after["id"] != legacy["id"] or retained != credential or after["defaultClientScopes"] != legacy["defaultClientScopes"] or after["optionalClientScopes"] != legacy["optionalClientScopes"] or after["attributes"].get("locale") != "fr":
                raise ValueError("Controller transition changed native identity, recovery credential or independent configuration")
        self.report["controller_authentication"] = {"fresh_creation": True, "same_client_round_trip": True,
            "retained_credential_without_rotation": True, "external_projected_review": True,
            "typed_claims_qualified": True,
            "controller_received_workload_jwt": False, "hanko_storage": "ephemeral-fixture", "workload_uid_reads": "real-api"}

    def controller_check(self, name, value, status, client="controller-secret"):
        self.check(name, value, status, client, CONTROLLER_ISSUER)

    def qualify(self):
        self.create_cluster()
        # Complete both cluster startups before issuing a 600-second assertion.
        self.foreign_cluster()
        self.keycloak()
        self.pod("probe", "worker")
        self.prepare_native()
        token = self.projected()
        self.report["projected_claims"] = claims(token)
        self.report["service_account_uid_a"] = self.get("serviceaccount", "worker", "workload")["metadata"]["uid"]
        self.check("projected_client_assertion", self.assertion(token), 200)
        self.check("pod_to_keycloak", self.pod_exchange(), 200)
        self.check("wrong_audience", self.assertion(self.projected(path="wrong-audience")), (400, 401))
        self.check("replay", self.assertion(token), 200)
        for namespace, account, name in (("other", "worker", "wrong_namespace"), ("workload", "other", "wrong_sa"), ("workload", "default", "default_sa")):
            self.apply({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account, "namespace": namespace}})
            self.check(name, self.assertion(self.token_request(account, namespace, [REALM_ISSUER])), (400, 401))
        self.check("default_api_audience", self.assertion(self.token_request()), (400, 401))
        self.check("wrong_client", self.assertion(token, client="workload-b"), (400, 401))
        multiple = self.token_request(audiences=[REALM_ISSUER, "https://kubernetes.default.svc.cluster.local"])
        self.check("multiple_audiences", self.assertion(multiple), (400, 401))
        self.api("POST", "/admin/realms", {"realm": "realm-b", "enabled": True})
        self.api("POST", "/admin/realms/realm-b/identity-provider/instances", {"alias": "workload-kube", "providerId": "kubernetes", "enabled": True,
            "config": {"issuer": self.report["discovery"]["issuer"]}})
        self.api("POST", "/admin/realms/realm-b/clients", {"clientId": "workload-a", "protocol": "openid-connect", "enabled": True,
            "publicClient": False, "serviceAccountsEnabled": True, "clientAuthenticatorType": "federated-jwt",
            "attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": binding_subject("workload", "worker")}})
        self.check("cross_realm", self.assertion(token, realm="realm-b"), (400, 401))
        parts = token.split(".")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        altered = bytes([signature[0] ^ 1]) + signature[1:]
        tampered = ".".join(parts[:2] + [base64.urlsafe_b64encode(altered).decode().rstrip("=")])
        self.check("tampered", self.assertion(tampered), (400, 401))
        foreign = self.token_request(audiences=[REALM_ISSUER], foreign=True)
        self.check("wrong_issuer", self.assertion(foreign), (400, 401))
        self.report["token_lifetime_limits"] = {}
        # The deliberately excessive request measures the fixture's server
        # ceiling; it is never a product recommendation or runtime fallback.
        for seconds in (599, 600, 900, 3600, 7200, 86400, 172800, 1_000_000_000):
            minted = self.token_request(audiences=[REALM_ISSUER], seconds=seconds)
            if minted is None:
                self.report["token_lifetime_limits"][str(seconds)] = {"token_request": "refused"}
                if seconds != 599:
                    raise ValueError("Required TokenRequest lifetime was refused")
            else:
                c = claims(minted)
                decision = self.assertion(minted)
                self.report["token_lifetime_limits"][str(seconds)] = {"requested": seconds, "issued": c["exp"] - c["iat"], **decision}
                self.check("lifetime_" + str(seconds), decision, 200)
        provider_path = "/admin/realms/managed/identity-provider/instances/workload-kube"
        provider = self.api("GET", provider_path)
        provider["config"]["fedClientAssertionMaxExp"] = "600"
        provider["config"]["allowedClockSkew"] = "0"
        self.api("PUT", provider_path, provider)
        self.report["provider_updated"] = self.api("GET", provider_path)
        if (self.report["provider_updated"]["internalId"] != self.report["provider_created"]["internalId"]
                or self.report["provider_updated"]["config"]["hanko.sh/workload-trust-owner"] != provider["config"]["hanko.sh/workload-trust-owner"]):
            raise ValueError("Provider update did not preserve native identity and fixture UID marker")
        provider["enabled"] = False
        self.api("PUT", provider_path, provider)
        self.check("provider_disabled", self.assertion(token), (400, 401))
        provider["enabled"] = True
        self.api("PUT", provider_path, provider)
        duplicate = {"alias": "duplicate-issuer", "providerId": "kubernetes", "config": {"issuer": provider["config"]["issuer"]}}
        self.api("POST", "/admin/realms/managed/identity-provider/instances", duplicate, expected=(400,))
        self.report["duplicate_issuer_create"] = {"http_status": 400}
        try:
            binding_subject("workload", "default")
        except ValueError:
            self.report["default_serviceaccount_contract"] = "refused"
        else:
            raise ValueError("Default ServiceAccount contract accepted")
        self.age_token = self.token_request(audiences=[REALM_ISSUER], seconds=900)
        self.age_token_claims = claims(self.age_token)
        self.check("fresh_long_token_under_age_limit", self.assertion(self.age_token), 200)
        self.check("provider_maximum_600_allowed", self.assertion(token), 200)
        self.client_update({"serviceAccountsEnabled": False})
        self.check("service_accounts_disabled", self.assertion(token), (400, 401))
        self.client_update({"serviceAccountsEnabled": True})
        self.client_update({"attributes": {"jwt.credential.issuer": "wrong-provider", "jwt.credential.sub": binding_subject("workload", "worker")}})
        self.check("wrong_provider_alias", self.assertion(token), (400, 401))
        self.client_update({"attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": binding_subject("workload", "worker")}})
        provider["config"]["issuer"] = self.report["foreign_discovery"]["issuer"]
        self.api("PUT", provider_path, provider)
        self.check("wrong_provider_issuer", self.assertion(token), (400, 401))
        provider["config"]["issuer"] = self.report["discovery"]["issuer"]
        self.api("PUT", provider_path, provider)
        self.secret_migration(token)
        self.flows(token)
        self.permissions()
        self.controller_authentication()
        self.external_keycloak(foreign)
        self.identity_lifecycle(token)
        live = self.token_request(audiences=[REALM_ISSUER])
        self.check("live_assertion_before_provider_delete", self.assertion(live), 200)
        self.api("DELETE", provider_path)
        self.api("GET", provider_path, expected=(404,))
        self.check("provider_absent", self.assertion(live), (400, 401))
        self.inspect_no_jwt_storage()
        self.report["complete"] = True
        self.report["completed_at"] = datetime.now(timezone.utc).isoformat()
        return self.report

    def external_keycloak(self, foreign_token):
        configuration = json.loads(run([self.args.kubectl, "--kubeconfig", self.foreign_config,
                                       "config", "view", "--raw", "-o", "json"]))
        ca = self.private / "external-kube-ca.crt"
        ca.write_bytes(base64.b64decode(configuration["clusters"][0]["cluster"]["certificate-authority-data"]))
        self.external_name = self.name + "-external-keycloak"
        # Bind individual files, never the private directory containing cluster
        # administrator kubeconfigs. The private parent is mode 0700 on the host.
        (self.private / "tls.key").chmod(0o644)
        run(["docker", "run", "--detach", "--name", self.external_name, "--network", "kind", "--publish", "127.0.0.1::8443",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--user", "1000:1000",
            "--tmpfs", "/tmp:rw,uid=1000,gid=1000", "--tmpfs", "/opt/keycloak/data:rw,uid=1000,gid=1000",
            "--mount", "type=bind,src=" + str(self.private / "tls.crt") + ",dst=/fixture/tls.crt,readonly",
            "--mount", "type=bind,src=" + str(self.private / "tls.key") + ",dst=/fixture/tls.key,readonly",
            "--mount", "type=bind,src=" + str(ca) + ",dst=/fixture/external-kube-ca.crt,readonly",
            "--env", "KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin", "--env", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + self.password,
            self.keycloak_image, "start", "--optimized", "--http-enabled=false", "--hostname=https://keycloak.auth.svc:8443",
            "--https-protocols=TLSv1.3", "--https-certificate-file=/fixture/tls.crt", "--https-certificate-key-file=/fixture/tls.key",
            "--truststore-paths=/fixture/external-kube-ca.crt"])
        address = run(["docker", "port", self.external_name, "8443/tcp"]).strip()
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", address):
            raise ValueError("External fixture must bind only loopback")
        saved = self.endpoint, self.token, self.token_at
        self.endpoint, self.token = "https://localhost:" + address.rsplit(":", 1)[1], ""
        def started():
            try:
                with urlopen(self.endpoint + "/realms/master/.well-known/openid-configuration", context=self.http, timeout=2) as response:
                    return response.status == 200
            except (OSError, HTTPError):
                return False
        try:
            system.wait("External HTTPS Keycloak", started, 120)
            self.token = self.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password})
            self.token_at = time.monotonic()
            self.api("POST", "/admin/realms", {"realm": "managed", "enabled": True})
            path = "/admin/realms/managed/identity-provider/instances/workload-kube"
            payload = {"alias": "workload-kube", "providerId": "kubernetes", "enabled": True,
                       "config": {"issuer": self.report["foreign_discovery"]["issuer"]}}
            self.api("POST", "/admin/realms/managed/identity-provider/instances", payload)
            self.report["external_provider_created"] = self.api("GET", path)
            self.api("POST", "/admin/realms/managed/clients", {"clientId": "workload-a", "protocol": "openid-connect",
                "enabled": True, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False, "fullScopeAllowed": False, "clientAuthenticatorType": "federated-jwt",
                "attributes": {"jwt.credential.issuer": "workload-kube", "jwt.credential.sub": binding_subject("workload", "worker")}})
            self.check("external_public_discovery", self.assertion(foreign_token), 200)
            payload["config"] = {"issuer": self.report["discovery"]["issuer"],
                                 "issuerDiscoveryUrl": self.report["foreign_discovery"]["issuer"]}
            self.api("PUT", path, payload)
            self.report["external_discovery_override"] = self.api("GET", path)
            self.check("external_discovery_override", self.assertion(foreign_token),
                       200 if self.args.keycloak_version == "26.8.1" else (400, 401))
            logs = run(["docker", "logs", self.external_name], include_stderr=True)
            safe_report({"fixture_logs": logs}, self.sensitive)
        finally:
            self.endpoint, self.token, self.token_at = saved
            run(["docker", "rm", "--force", self.external_name])
            del self.external_name

    def inspect_no_jwt_storage(self):
        logs = self.kubectl("logs", "deployment/keycloak", "-n", "auth")
        events = self.kubectl("get", "events", "-A", "-o", "json")
        safe_report({"logs": logs, "events": events}, self.sensitive)
        objects = json.loads(self.kubectl("get", "secrets,configmaps", "-A", "-o", "json"))
        for item in objects["items"]:
            if item["kind"] == "Secret":
                values = [base64.b64decode(value).decode(errors="replace") for value in item.get("data", {}).values()]
            else:
                values = list(item.get("data", {}).values())
                values.extend(base64.b64decode(value).decode(errors="replace") for value in item.get("binaryData", {}).values())
            if any(contains_jwt(value) for value in values):
                raise ValueError("JWT found in fixture Kubernetes object (withheld)")
        self.report["no_jwt_in_logs_events_secrets_configmaps"] = True

    def secret_migration(self, token):
        credential = secrets.token_hex(32)
        self.sensitive.append(credential)
        self.client_update({"clientAuthenticatorType": "client-secret", "secret": credential})
        fields = {"client_id": "workload-a", "client_secret": credential, "grant_type": "client_credentials"}
        self.check("secret_before_migration", self.exchange(fields), 200)
        self.check("assertion_in_secret_mode", self.assertion(token), (400, 401))
        self.client_update({"clientAuthenticatorType": "federated-jwt"})
        self.check("client_secret_attempt", self.exchange(fields), (400, 401))
        self.check("assertion_after_migration", self.assertion(token), 200)
        recovered = self.api("GET", "/admin/realms/managed/clients/" + self.client("managed", "workload-a")["id"] + "/client-secret").get("value")
        if recovered != credential:
            raise ValueError("Native fallback did not preserve the same recovery secret")
        self.sensitive.append(recovered)
        fields["client_secret"] = recovered
        self.report["secret_recovered_without_rotation"] = True
        self.client_update({"clientAuthenticatorType": "client-secret"})
        self.check("explicit_secret_fallback", self.exchange(fields), 200)
        self.check("fallback_rejects_assertion", self.assertion(token), (400, 401))
        self.client_update({"clientAuthenticatorType": "federated-jwt"})
        self.check("return_to_kubernetes", self.assertion(token), 200)
        self.check("return_rejects_secret", self.exchange(fields), (400, 401))
        self.report["inactive_native_secret_retained"] = bool(self.api("GET", "/admin/realms/managed/clients/" + self.client("managed", "workload-a")["id"] + "/client-secret").get("value"))

    def flows(self, token):
        realm = self.api("GET", "/admin/realms/managed")
        alias = realm["clientAuthenticationFlow"]
        executions = self.api("GET", "/admin/realms/managed/authentication/flows/" + alias + "/executions")
        fed = [e for e in executions if e.get("providerId") == "federated-jwt"]
        if len(fed) != 1 or fed[0]["requirement"] != "ALTERNATIVE":
            raise ValueError("Fresh realm does not have the expected native client execution")
        self.report["fresh_realm_client_flow"] = {"alias": alias, "executions": executions}
        builtin = [f for f in self.api("GET", "/admin/realms/managed/authentication/flows") if f["alias"] == alias][0]
        self.api("DELETE", "/admin/realms/managed/authentication/flows/" + builtin["id"], expected=(400,))
        self.report["builtin_client_flow_delete"] = {"http_status": 400}
        disabled = dict(fed[0], requirement="DISABLED")
        self.api("PUT", "/admin/realms/managed/authentication/flows/" + alias + "/executions", disabled, expected=(204,))
        self.check("builtin_execution_disabled", self.assertion(token), (400, 401))
        self.api("PUT", "/admin/realms/managed/authentication/flows/" + alias + "/executions", fed[0], expected=(204,))
        self.check("builtin_execution_restored", self.assertion(token), 200)
        self.report["builtin_execution_requirement_write"] = {"http_status": 204, "allowed_for_fixture_administrator": True}
        self.api("POST", "/admin/realms/managed/authentication/flows/" + alias + "/copy", {"newName": "legacy-clients"})
        copy = self.api("GET", "/admin/realms/managed/authentication/flows/legacy-clients/executions")
        missing = [e for e in copy if e.get("providerId") == "federated-jwt"][0]
        self.api("DELETE", "/admin/realms/managed/authentication/executions/" + missing["id"])
        self.api("PUT", "/admin/realms/managed", {"clientAuthenticationFlow": "legacy-clients"})
        self.check("legacy_flow_missing_execution", self.assertion(token), (400, 401))
        self.api("PUT", "/admin/realms/managed", {"clientAuthenticationFlow": alias})
        self.check("fresh_flow_restored", self.assertion(token), 200)

    def identity_lifecycle(self, token):
        self.pod("rotation", "rotation")
        rotation = self.projected("rotation")
        rotation_claims = claims(rotation)
        self.report["review_before_deletion"] = self.review(token)
        self.kubectl("delete", "pod", "probe", "-n", "workload", "--wait=true")
        self.kubectl("delete", "serviceaccount", "worker", "-n", "workload")
        self.report["review_after_sa_deletion"] = self.review(token)
        if self.report["review_after_sa_deletion"]["authenticated"]:
            raise ValueError("TokenReview accepted a deleted ServiceAccount")
        self.check("deleted_sa_offline_assertion", self.assertion(token), 200)
        self.pod("probe-b", "worker")
        uid_b = self.get("serviceaccount", "worker", "workload")["metadata"]["uid"]
        token_b = self.projected("probe-b")
        self.report["service_account_uid_b"] = uid_b
        self.report["recreated_claims"] = claims(token_b)
        if uid_b == self.report["service_account_uid_a"]:
            raise ValueError("ServiceAccount was not recreated")
        self.check("recreated_sa_native_acceptance", self.assertion(token_b), 200)
        self.controller_action("contain")
        if self.client(CONTROLLER_REALM, "controller-worker")["enabled"]:
            raise ValueError("Production controller did not contain the actual recreated workload UID")
        self.report["controller_authentication"]["real_uid_replacement_contained"] = True
        self.check("old_sa_after_recreation", self.assertion(token), 200)
        # Hold assertions only in memory and leave a real live Pod running so
        # kubelet rotation is measured, rather than forging dates or signatures.
        deadline = rotation_claims["exp"] + 15
        rotation_started = time.monotonic()
        rotation_seconds = max(0, deadline - time.time())
        while time.time() < deadline:
            current = self.projected("rotation")
            if current != rotation:
                c = claims(current)
                self.report["projected_rotation"] = {"first_iat": rotation_claims["iat"], "next_iat": c["iat"],
                    "lifetime": c["exp"] - c["iat"], "same_sa_uid": c["kubernetes.io"]["serviceaccount"]["uid"] == rotation_claims["kubernetes.io"]["serviceaccount"]["uid"]}
                break
            time.sleep(5)
        if "projected_rotation" not in self.report:
            raise system.diagnostics.DeadlineExceeded("Kubelet projected token rotation", rotation_seconds, time.monotonic() - rotation_started)
        while time.time() <= self.report["projected_claims"]["exp"] + 2:
            time.sleep(1)
        self.check("expired", self.assertion(token), (400, 401))
        while time.time() <= self.age_token_claims["iat"] + 602:
            time.sleep(1)
        if time.time() >= self.age_token_claims["exp"]:
            raise ValueError("Age-limit evidence would be confounded by expiration")
        self.check("age_limit_before_expiration", self.assertion(self.age_token), (400, 401))

    def cleanup(self):
        if hasattr(self, "external_name"):
            run(["docker", "rm", "--force", self.external_name])
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=10)
            self.forward_log.close()
        for name in sorted(self.owned_clusters):
            run([self.args.kind, "delete", "cluster", "--name", name])
        if hasattr(self, "keycloak_image"):
            run(["docker", "image", "rm", self.keycloak_image])
        if hasattr(self, "built_node_image"):
            run(["docker", "image", "rm", self.built_node_image])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-version", choices=KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path, help="Optional cached official server archive; checksum is still mandatory")
    parser.add_argument("--kind", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hankoshell-workload-private-") as temp:
        fixture = Fixture(args, Path(temp))
        try:
            report = fixture.qualify()
        except Exception as error:
            system.diagnostics.capture(fixture, error)
            raise
        finally:
            report = fixture.report
            try:
                encoded = safe_report(public_report(report), fixture.sensitive)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(encoded)
            finally:
                fixture.cleanup()


if __name__ == "__main__":
    main()

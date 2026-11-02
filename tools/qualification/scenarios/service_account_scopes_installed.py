"""Exercise declared M2M scopes through the installed controller and a TLS API.

Only uniquely named disposable fixtures are changed. Credentials and bearer
tokens remain in memory; the report contains public decisions and binary hashes.
"""
from contextlib import contextmanager
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
READ, WRITE = "registry:oci:artifacts:read", "registry:oci:artifacts:publish"
ISSUER = "https://keycloak.auth.svc:8443/realms/managed"
AUDIENCE = "scope-artifact-api"
BASE = "gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88"


def exchange(fixture, secret, requested=None):
    fields = {"grant_type": "client_credentials", "client_id": "scope-reader", "client_secret": secret}
    if requested is not None:
        fields["scope"] = requested
    request = Request(fixture.endpoint + "/realms/managed/protocol/openid-connect/token", data=urlencode(fields).encode())
    try:
        with urlopen(request, context=fixture.http, timeout=10) as response:
            result = json.loads(response.read(32769))
        token = result.get("access_token")
        if not isinstance(token, str) or not 1 <= len(token) <= 16384:
            raise ValueError("Installed scope token response refused")
        fixture.sensitive.append(token)
        return 200, token
    except HTTPError as error:
        return error.code, None


def access(fixture, endpoint, token, path):
    request = Request(endpoint + path, headers={"Authorization": "Bearer " + token})
    try:
        response = urlopen(request, context=fixture.http, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        status = response.code
        body = json.loads(response.read(1025))
    if body != {"allowed": status == 200}:
        raise ValueError("Installed scope resource returned an invalid decision")
    return status


@contextmanager
def resource(fixture, run, wait):
    build = fixture.private / "scope-resource-build"
    build.mkdir()
    architecture = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64"}[platform.machine()]
    environment = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=architecture)
    subprocess.run(["go", "build", "-trimpath", "-o", str(build / "resource"), "./tools/qualification/fixtures/delegation-resource-server"],
                   cwd=ROOT, env=environment, timeout=180, check=True)
    (build / "Dockerfile").write_text(f'FROM {BASE}\nCOPY --chmod=0555 resource /resource\nUSER 1000\nENTRYPOINT ["/resource"]\n')
    image, forward, built = fixture.name + "-scope-resource:fixture", None, False
    try:
        run(["docker", "build", "--network=none", "--tag", image, build])
        built = True
        run([fixture.args.kind, "load", "docker-image", image, "--name", fixture.name])
        settings = {"issuer": ISSUER, "audience": AUDIENCE, "resources": {"/read": READ, "/publish": WRITE}, "oauth_scopes": True}
        fixture.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "scope-resource", "namespace": "auth"},
                       "data": {"settings.json": json.dumps(settings), "ca.crt": (fixture.private / "tls.crt").read_text()}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "scope-resource", "namespace": "auth"}, "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "resource", "image": image, "imagePullPolicy": "Never",
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "readinessProbe": {"tcpSocket": {"port": 8445}},
                    "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}},
                    "volumeMounts": [{"name": "settings", "mountPath": "/fixture", "readOnly": True}, {"name": "settings", "mountPath": "/ca", "readOnly": True},
                                     {"name": "tls", "mountPath": "/tls", "readOnly": True}]}],
                "volumes": [{"name": "settings", "configMap": {"name": "scope-resource"}}, {"name": "tls", "secret": {"secretName": "keycloak-tls", "defaultMode": 288}}]}})
        fixture.kubectl("wait", "--for=condition=Ready", "pod/scope-resource", "-n", "auth", "--timeout=180s")
        log = fixture.private / "scope-resource-forward.log"
        with log.open("wb") as output:
            forward = subprocess.Popen([str(fixture.args.kubectl), "--kubeconfig", str(fixture.config), "port-forward", "-n", "auth",
                                        "pod/scope-resource", ":8445", "--address", "127.0.0.1"], stdout=output, stderr=subprocess.STDOUT)
            wait("scope API loopback forward", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()) is not None, 30)
            port = re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]
            yield "https://localhost:" + port, hashlib.sha256((build / "resource").read_bytes()).hexdigest()
    finally:
        if forward:
            forward.terminate()
            try:
                forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forward.kill()
                forward.wait(timeout=10)
        if built:
            run(["docker", "image", "rm", image])


def qualify(fixture, run, wait):
    checks = []

    def record(name, valid=True):
        if not valid:
            raise ValueError("Installed OAuth scope invariant failed: " + name)
        checks.append(name)
        print("Installed OAuth scopes: " + name + " passed", flush=True)

    for name in (READ, WRITE):
        existing = [s for s in fixture.api("GET", "/admin/realms/managed/client-scopes") if s.get("name") == name]
        if not existing:
            fixture.api("POST", "/admin/realms/managed/client-scopes", {"name": name, "protocol": "openid-connect",
                        "attributes": {"include.in.token.scope": "true"}})
        elif len(existing) != 1 or existing[0].get("protocol") != "openid-connect" or existing[0].get("attributes", {}).get("include.in.token.scope") != "true":
            raise ValueError("Unexpected disposable shared scope definition")
    wanted = ["basic", "service_account", READ]
    account = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": {"name": "scope-unresolved", "namespace": "auth"},
               "spec": {"realmRef": "managed", "clientID": "scope-unresolved", "scopes": ["missing-fixture-scope"],
                        "tokenClaims": [{"name": "artifact-audience", "claim": "aud", "value": AUDIENCE,
                                         "addToAccessToken": True, "addToIDToken": False, "addToUserInfo": False, "addToIntrospection": True}]}}
    fixture.apply_approved(account)
    wait("unresolved installed scope refusal", lambda: any(c.get("reason") == "OAuthScopesUnresolved" and c.get("status") == "False"
         for c in fixture.get("hankoserviceaccount", "scope-unresolved").get("status", {}).get("conditions", [])))
    secrets = json.loads(fixture.kubectl("get", "secrets", "-n", "auth", "--field-selector=metadata.name=hanko-sa-scope-unresolved", "-o", "json"))
    record("unresolved_scope_does_not_create_client_or_publish_secret", not secrets["items"] and not fixture.api("GET", "/admin/realms/managed/clients?clientId=scope-unresolved"))
    fixture.kubectl("delete", "hankoserviceaccount", "scope-unresolved", "-n", "auth", "--wait=true", "--timeout=120s")
    account["metadata"]["name"] = account["spec"]["clientID"] = "scope-reader"
    account["spec"]["scopes"] = wanted
    fixture.apply_approved(account)

    def update(scopes):
        fixture.kubectl("patch", "hankoserviceaccount", "scope-reader", "-n", "auth", "--type=merge", "-p", json.dumps({"spec": {"scopes": scopes}}))
        wait("current installed scope declaration", lambda: fixture.ready("hankoserviceaccount", "scope-reader"))

    update(wanted)
    client = fixture.client("managed", "scope-reader")
    native_base = "/admin/realms/managed/clients/" + client["id"]
    native_defaults = lambda: fixture.api("GET", native_base + "/default-client-scopes")
    native_optional = lambda: fixture.api("GET", native_base + "/optional-client-scopes")
    output = fixture.get("secret", "hanko-sa-scope-reader")
    credential = base64.b64decode(output["data"]["client_secret"]).decode()
    fixture.sensitive.append(credential)
    secret_uid, client_uid = output["metadata"]["uid"], client["id"]
    record("controller_confirms_exact_defaults_before_secret_delivery", sorted(x["name"] for x in native_defaults()) == sorted(wanted) and native_optional() == [])
    with resource(fixture, run, wait) as (endpoint, digest):
        status, token = exchange(fixture, credential)
        record("native_client_credentials_token", status == 200)
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        record("native_machine_identity_and_declared_scope", claims.get("iss") == ISSUER and claims.get("azp") == "scope-reader" and bool(claims.get("jti")) and READ in claims.get("scope", "").split())
        record("signed_token_allowed_read", access(fixture, endpoint, token, "/read") == 200)
        record("undeclared_api_right_refused", access(fixture, endpoint, token, "/publish") == 403)
        record("undeclared_scope_cannot_be_requested", exchange(fixture, credential, WRITE)[0] == 400)
        parts = token.split(".")
        parts[-1] = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
        record("forged_signature_refused", access(fixture, endpoint, ".".join(parts), "/read") == 401)
        update(None)
        record("omitted_scopes_preserve_existing_grants", sorted(x["name"] for x in native_defaults()) == sorted(wanted))
        update(wanted[:2])
        record("removed_scope_cannot_be_requested", exchange(fixture, credential, READ)[0] == 400)
        status, fresh = exchange(fixture, credential)
        record("new_token_loses_removed_api_access", status == 200 and access(fixture, endpoint, fresh, "/read") == 403)
        record("previously_issued_token_retains_rights_until_expiry", access(fixture, endpoint, token, "/read") == 200)
        update([])
        record("explicit_empty_list_survives_controller_updates_and_revokes_all_attachments", fixture.get("hankoserviceaccount", "scope-reader")["spec"].get("scopes") == [] and native_defaults() == [] and native_optional() == [])
        update(wanted)
        checkpoint = fixture.get("hankoserviceaccount", "scope-reader")["status"].get("lastReconciled")
        fixture.kubectl("rollout", "restart", "deployment/system-operator", "-n", "auth")
        fixture.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=120s")
        wait("fresh scope reconciliation after restart", lambda: fixture.ready("hankoserviceaccount", "scope-reader") and
             fixture.get("hankoserviceaccount", "scope-reader")["status"].get("lastReconciled") not in (None, checkpoint))
        record("restart_preserves_client_and_credential", fixture.client("managed", "scope-reader")["id"] == client_uid and fixture.get("secret", "hanko-sa-scope-reader")["metadata"]["uid"] == secret_uid and fixture.get("secret", "hanko-sa-scope-reader")["data"]["client_secret"] == output["data"]["client_secret"])
        record("restored_declaration_allows_fresh_token", access(fixture, endpoint, exchange(fixture, credential)[1], "/read") == 200)
    fixture.kubectl("delete", "hankoserviceaccount", "scope-reader", "-n", "auth", "--wait=true", "--timeout=120s")
    shared = fixture.api("GET", "/admin/realms/managed/client-scopes")
    record("owned_client_cleanup_preserves_shared_scope_definitions", not fixture.api("GET", "/admin/realms/managed/clients?clientId=scope-reader") and {READ, WRITE} <= {x["name"] for x in shared})
    return {"result": "pass", "resource_verifier_sha256": digest, "checks": checks}

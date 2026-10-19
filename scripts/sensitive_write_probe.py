"""Exercise installed admission with a real, token-only operator identity.

Only the disposable fixture administrator prepares exact grants. Requests below
have no client certificate, ambient proxy, redirect or administrator fallback.
Reports contain fixed booleans; tokens and Kubernetes bodies never leave memory.
"""
import base64
import copy
import json
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import yaml


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TokenAPI:
    def __init__(self, cluster, token):
        if not cluster["server"].startswith("https://"):
            raise ValueError("Operator probe requires verified HTTPS")
        self.server = cluster["server"].rstrip("/")
        self.token = token
        tls = ssl.create_default_context(cadata=base64.b64decode(cluster["certificate-authority-data"]).decode())
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls), NoRedirect())

    def __call__(self, method, path, body=None, dry=False):
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json"}
        req = Request(self.server + path + ("?dryRun=All" if dry else ""),
            data=json.dumps(body, allow_nan=False).encode() if body is not None else None, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise ValueError("Operator probe API response exceeded its budget")
            return response.code, json.loads(raw) if raw else {}


def probe(fixture):
    checks = {}
    identity = "system-operator"

    def record(name, value):
        checks[name] = value is True
        if not checks[name]:
            raise ValueError("Installed sensitive-write admission failed: " + name)

    request = subprocess.run([str(fixture.args.kubectl), "--kubeconfig", str(fixture.config), "create", "token",
        identity, "--duration=600s", "--namespace", "auth"], capture_output=True, text=True, timeout=30)
    if request.returncode or not request.stdout.strip():
        raise ValueError("Operator probe TokenRequest failed")
    token = request.stdout.strip()
    fixture.sensitive.append(token)
    config = yaml.safe_load(fixture.config.read_text())
    context = next(item["context"] for item in config["contexts"] if item["name"] == config["current-context"])
    cluster = next(item["cluster"] for item in config["clusters"] if item["name"] == context["cluster"])
    api = TokenAPI(cluster, token)

    code, who = api("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
    record("real_operator_token_identity", code == 201 and who.get("status", {}).get("userInfo", {}).get("username") == f"system:serviceaccount:auth:{identity}")
    fixture.approve_sensitive_writes([
        {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": {"namespace": "auth"}, "spec": {"clientID": "security-probe"}},
        {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoKeycloakInstance", "metadata": {"namespace": "auth", "name": "security-reviewed-provider"}, "spec": {"mode": "managed"}},
    ])
    root = "/api/v1/namespaces/auth/secrets"
    target, foreign = "hanko-app-security-probe", "security-unapproved-output"
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": target, "namespace": "auth"}, "type": "Opaque", "data": {"public-fixture": "cHJvYmU="}}
    # Both the broad CREATE authorization and the independently denied unknown
    # name must be observed; an RBAC refusal is not admission qualification.
    def ready():
        code, review = api("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", {
            "apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": {"resourceAttributes": {"namespace": "auth", "verb": "create", "resource": "secrets"}}})
        if code != 201 or review.get("status", {}).get("allowed") is not True:
            return False
        positive, _ = api("POST", root, secret, dry=True)
        unknown = copy.deepcopy(secret); unknown["metadata"]["name"] = foreign
        negative, _ = api("POST", root, unknown, dry=True)
        return positive == 201 and negative == 403
    deadline = time.monotonic() + 10
    while not ready():
        if time.monotonic() >= deadline:
            raise ValueError("Installed sensitive-write policy did not become effective")
        time.sleep(0.1)
    record("create_is_admission_scoped", True)
    forged = copy.deepcopy(secret); forged["metadata"]["name"] = foreign
    forged["metadata"].update(labels={"app.kubernetes.io/managed-by": "Helm"}, ownerReferences=[{
        "apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "name": "forged", "uid": "forged-owner"}])
    record("forged_ownership_cannot_expand_targets", api("POST", root, forged, dry=True)[0] == 403)
    forged = copy.deepcopy(secret); forged["type"] = "kubernetes.io/service-account-token"
    forged["metadata"]["annotations"] = {"kubernetes.io/service-account.name": "system-operator"}
    record("service_account_token_minting_refused", api("POST", root, forged, dry=True)[0] == 403)
    projection_prepared = False
    try:
        code, _ = api("POST", root, secret)
        record("reviewed_opaque_output_created", code == 201)
        record("reviewed_output_patch_allowed", api("PATCH", root + "/" + target, {"data": {"public-fixture": "dXBkYXRlZA=="}})[0] == 200)
        fixture.apply(fixture.secret(foreign, {"public-fixture": "preserved"}))
        record("foreign_secret_patch_refused", api("PATCH", root + "/" + foreign, {"data": {"public-fixture": "dGFtcGVyZWQ="}})[0] == 403)
        record("foreign_secret_unchanged", fixture.get("secret", foreign)["data"]["public-fixture"] == "cHJlc2VydmVk")
        record("output_delete_refused", api("DELETE", root + "/" + target)[0] == 403)
        role = fixture.get("role", "system-operator")
        rules = role["rules"] + [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        record("own_role_cannot_change_rules", api("PATCH", "/apis/rbac.authorization.k8s.io/v1/namespaces/auth/roles/system-operator", {"rules": rules}, dry=True)[0] == 403)
        binding = fixture.get("rolebinding", "system-operator")
        subjects = binding["subjects"] + [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "another-authenticated-user"}]
        record("rolebinding_delegation_refused", api("PATCH", "/apis/rbac.authorization.k8s.io/v1/namespaces/auth/rolebindings/system-operator", {"subjects": subjects}, dry=True)[0] == 403)
        record("metadata_adoption_preserved", api("PATCH", "/apis/rbac.authorization.k8s.io/v1/namespaces/auth/rolebindings/system-operator", {
            "metadata": {"ownerReferences": [{"apiVersion": "v1", "kind": "Namespace", "name": "auth", "uid": fixture.get("namespace", "auth")["metadata"]["uid"]}]}}, dry=True)[0] == 200)
        deployment = fixture.get("deployment", "system-operator")
        forged = {"spec": {"template": {"spec": {"serviceAccountName": "default"}}}}
        record("deployment_service_account_change_refused", api("PATCH", "/apis/apps/v1/namespaces/auth/deployments/system-operator", forged, dry=True)[0] == 403)
        provider = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "security-reviewed-provider", "namespace": "auth"},
            "spec": {"replicas": 0, "selector": {"matchLabels": {"app": "security-probe"}}, "template": {"metadata": {"labels": {"app": "security-probe"}},
                "spec": {"automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "provider", "image": deployment["spec"]["template"]["spec"]["containers"][0]["image"],
                        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}}}}
        record("reviewed_provider_creation_allowed", api("POST", "/apis/apps/v1/namespaces/auth/deployments", provider, dry=True)[0] == 201)
        provider["metadata"]["name"] = "security-unapproved-provider"
        record("foreign_provider_creation_refused", api("POST", "/apis/apps/v1/namespaces/auth/deployments", provider, dry=True)[0] == 403)
        provider["metadata"]["name"] = "security-reviewed-provider"
        provider["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
        record("provider_api_token_mount_refused", api("POST", "/apis/apps/v1/namespaces/auth/deployments", provider, dry=True)[0] == 403)
        provider["spec"]["template"]["spec"]["automountServiceAccountToken"] = False
        template = copy.deepcopy(provider["spec"]["template"])
        template["spec"]["restartPolicy"] = "Never"
        job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "security-probe", "namespace": "auth"}, "spec": {"template": template}}
        jobs = "/apis/batch/v1/namespaces/auth/jobs"
        record("token_free_job_allowed", api("POST", jobs, job, dry=True)[0] == 201)
        for attack in ("automount", "service-account", "projection"):
            changed = copy.deepcopy(job)
            pod = changed["spec"]["template"]["spec"]
            if attack == "automount": pod["automountServiceAccountToken"] = True
            elif attack == "service-account": pod["serviceAccountName"] = "system-operator"
            else: pod["volumes"] = [{"name": "token", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
            record("job_" + attack + "_refused", api("POST", jobs, changed, dry=True)[0] == 403)
        # The independent administrator creates a pre-existing output and adds
        # its exact grant after initial Helm installation. Leave the RBAC objects
        # until the later real Helm upgrade, which must adopt their release
        # metadata successfully; delete only public fixture Secret data below.
        namespace, approved, unrelated = "security-projection", "reviewed-output", "foreign-output"
        fixture.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
            fixture.secret(approved, {"public-fixture": "preserved"}, namespace),
            fixture.secret(unrelated, {"public-fixture": "preserved"}, namespace))
        projection_prepared = True
        fixture.approve_projection_write(namespace, approved)
        projected = "/api/v1/namespaces/" + namespace + "/secrets"
        patch = {"data": {"public-fixture": "dXBkYXRlZA=="}}
        deadline = time.monotonic() + 10
        while api("PATCH", projected + "/" + approved, patch)[0] != 200:
            if time.monotonic() >= deadline:
                raise ValueError("Installed projection grant did not become effective")
            time.sleep(0.1)
        record("existing_projection_patch_allowed", True)
        record("projection_foreign_name_refused", api("PATCH", projected + "/" + unrelated, patch)[0] == 403)
        code, review = api("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", {
            "apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": {"resourceAttributes": {"namespace": namespace, "verb": "create", "resource": "secrets"}}})
        record("projection_creation_not_granted", code == 201 and review.get("status", {}).get("allowed") is False)
        projected_secret = copy.deepcopy(secret)
        projected_secret["metadata"].update(namespace=namespace, name=approved)
        record("projection_create_refused", api("POST", projected, projected_secret, dry=True)[0] == 403)
    finally:
        fixture.kubectl("delete", "secret", target, foreign, "--namespace", "auth", "--ignore-not-found=true", "--wait=true")
        if projection_prepared:
            fixture.kubectl("delete", "secret", "reviewed-output", "foreign-output", "--namespace", "security-projection", "--ignore-not-found=true", "--wait=true")
    return checks

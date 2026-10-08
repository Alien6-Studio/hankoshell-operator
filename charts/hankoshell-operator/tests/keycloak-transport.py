#!/usr/bin/env python3
"""Verify the same administrative endpoint contract in Helm and Go."""
import copy
import json
import pathlib
import subprocess
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
CHART = ROOT / "charts/hankoshell-operator"
BASE = ["helm", "template", "transport-test", str(CHART), "--namespace", "auth",
        "--kube-version", "1.37.0", "--set-string", "image.tag=fixture"]


def render(values, valid):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as config:
        yaml.safe_dump(values, config)
        config.flush()
        result = subprocess.run(BASE + ["-f", config.name], text=True, capture_output=True)
    assert (result.returncode == 0) == valid, (values, result.stderr)
    if valid:
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    return []


enterprise = {
    "profile": "enterprise", "image": {"digest": "sha256:" + "0" * 64},
    "hub": {"enabled": True, "tenantID": "fixture", "endpoint": "https://hub.mesh.example:9443"},
    "continuum": {"enabled": True, "hubAddress": "10.250.0.1", "hubHostname": "hub.mesh.example"},
}
endpoints = json.loads((ROOT / "internal/keycloak/testdata/endpoints.json").read_text())
for endpoint in endpoints:
    for profile in ("standard", "enterprise"):
        for allow in (False, True):
            values = copy.deepcopy(enterprise) if profile == "enterprise" else {}
            values["keycloak"] = {"url": endpoint["url"], "allowInsecureHTTP": allow}
            valid = endpoint["valid"] and (endpoint["url"].startswith("https://") or
                                          (profile == "standard" and allow))
            render(values, valid)

for ca_secret in ("", "iam-private-ca"):
    docs = render({"keycloak": {"url": "https://iam.example.com/auth", "caSecret": ca_secret}}, True)
    pod = next(doc for doc in docs if doc["kind"] == "Deployment")["spec"]["template"]["spec"]
    env = {entry["name"]: entry for entry in pod["containers"][0]["env"]}
    assert env["HANKO_KEYCLOAK_URL"]["value"] == "https://iam.example.com/auth"
    assert env["HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP"]["value"] == "false"
    assert ("HANKO_KEYCLOAK_CA_FILE" in env) == bool(ca_secret)
    assert any(v["name"] == "keycloak-ca" for v in pod["volumes"]) == bool(ca_secret)
    assert all("SKIP_VERIFY" not in name for name in env)

http = {"keycloak": {"url": "http://iam.auth.svc:8080", "allowInsecureHTTP": True}}
docs = render(http, True)
env = next(doc for doc in docs if doc["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]
assert next(e for e in env if e["name"] == "HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP")["value"] == "true"
http["keycloak"]["caSecret"] = "iam-ca"
render(http, False)
render({"keycloak": {"enabled": False, "url": ""}}, True)
for invalid in ("true", "false", 1, None):
    render({"keycloak": {"allowInsecureHTTP": invalid}}, False)
for name in ("HANKO_KEYCLOAK_URL", "HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP"):
    render({"env": {name: "override"}}, False)
print("Keycloak transport: default HTTPS, public/private CA, explicit HTTP, enterprise and endpoint guards passed")

#!/usr/bin/env python3
"""Qualify explicit projection mode, credentials and exact optional API egress."""
import copy
from pathlib import Path
import subprocess
import tempfile

import yaml

CHART = Path(__file__).resolve().parents[1]


def render(values=None, valid=True):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as config:
        yaml.safe_dump(values or {}, config)
        config.flush()
        result = subprocess.run(["helm", "template", "projection-test", str(CHART), "--namespace", "auth",
                                 "--kube-version", "1.37.0", "--set-string", "image.tag=fixture", "-f", config.name],
                                capture_output=True, text=True)
    assert (result.returncode == 0) == valid, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc] if valid else []


def environment(docs):
    pod = next(doc for doc in docs if doc["kind"] == "Deployment")["spec"]["template"]["spec"]
    return {entry["name"]: entry for entry in pod["containers"][0]["env"]}


def egress(docs):
    return next(doc for doc in docs if doc["kind"] == "NetworkPolicy")["spec"]["egress"]


default = render()
env = environment(default)
assert env["HANKO_ORGANIZATION_PROJECTION_ENABLED"]["value"] == "false"
assert "HANKO_API_URL" not in env and "HANKO_API_TOKEN" not in env
assert not any(peer.get("podSelector", {}).get("matchLabels", {}).get("app") == "hanko-api"
               for rule in egress(default) for peer in rule["to"])

projection = {"enabled": True, "apiURL": "http://hanko-api.auth.svc:8080", "apiPorts": [8080],
              "apiSelector": {"app": "hanko-api", "component": "positions"}, "tokenSecret": "projection-token", "tokenKey": "credential"}
docs = render({"organizationProjection": projection})
env = environment(docs)
assert env["HANKO_ORGANIZATION_PROJECTION_ENABLED"]["value"] == "true"
assert env["HANKO_API_URL"]["value"] == projection["apiURL"]
assert env["HANKO_API_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": "projection-token", "key": "credential"}
assert len(egress(docs)) == len(egress(default)) + 1
assert {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "auth"}},
                "podSelector": {"matchLabels": projection["apiSelector"]}}],
        "ports": [{"port": 8080, "protocol": "TCP"}]} in egress(docs)

for key, bad in (("apiURL", ""), ("tokenSecret", ""), ("tokenKey", ""), ("apiPorts", []),
                 ("apiPorts", [0]), ("apiPorts", [65536]), ("apiSelector", None),
                 ("apiSelector", {"app": True}), ("apiSelector", {"app": "*"}), ("enabled", "true")):
    invalid = copy.deepcopy(projection)
    invalid[key] = bad
    render({"organizationProjection": invalid}, valid=False)
for name in ("HANKO_ORGANIZATION_PROJECTION_ENABLED", "HANKO_API_URL", "HANKO_API_TOKEN"):
    render({"env": {name: "override"}}, valid=False)

enterprise = {"profile": "enterprise", "image": {"digest": "sha256:" + "0" * 64},
              "hub": {"enabled": True, "tenantID": "fixture", "endpoint": "https://hub.mesh.example:9443"},
              "continuum": {"enabled": True, "hubAddress": "10.250.0.1", "hubHostname": "hub.mesh.example"},
              "organizationProjection": copy.deepcopy(projection)}
render(enterprise, valid=False)
enterprise["organizationProjection"].update({"apiURL": "https://hanko-api.auth.svc:8443", "apiPorts": [8443]})
assert environment(render(enterprise))["HANKO_ORGANIZATION_PROJECTION_ENABLED"]["value"] == "true"
print("Organization projection: explicit disabled/enabled mode, isolated Secret reference, narrow egress and enterprise HTTPS passed")

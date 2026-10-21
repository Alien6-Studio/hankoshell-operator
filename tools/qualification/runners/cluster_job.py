"""Render a persistent, namespaced qualification Job from a reviewed load corpus.

No deployment, credential access, cluster-wide RBAC or CRD update is performed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

import yaml

from tools.qualification.scenarios import soak_observer

ROOT = Path(__file__).resolve().parents[3]
FILES = (
    "tools/qualification/scenarios/cluster_campaign.py",
    "tools/qualification/scenarios/soak_observer.py",
    "tools/qualification/reporting/scale_evidence.py",
)


def manifests(state, config):
    namespace, release = state["namespace"], state["release"]
    hostname = release + "-hanko-operator-metrics." + namespace + ".svc"
    soak_observer.validate(SimpleNamespace(namespace=namespace, release=release, image=state["operator_image"],
        revision=state["revision"], metrics_hostname=hostname, counts=state["counts"], workers=state["workers"],
        seconds=86400, warmup=3600, interval=10))
    if not re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", state["runner"]):
        raise ValueError("Qualification requires an immutable Python runtime")
    if not isinstance(config.get("objects"), list) or not config["objects"] or any(
            obj.get("metadata", {}).get("namespace") != namespace for obj in config["objects"]):
        raise ValueError("The load corpus must be limited to the qualification namespace")
    if config.get("provider") != "https://keycloak." + namespace + ".svc:8443":
        raise ValueError("The provider must be the dedicated same-namespace fixture")
    name = "qualification-campaign"
    def resource(kind, **fields):
        return {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace}, **fields}
    sources = {path.replace("/", "__"): (ROOT / path).read_text() for path in FILES}
    sources["config.json"] = json.dumps(config, sort_keys=True)
    digest = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()
    items = [{"key": path.replace("/", "__"), "path": path} for path in FILES]
    items.append({"key": "config.json", "path": "config.json"})
    role = resource("Role", rules=[
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "delete"]},
        {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"],
         "resourceNames": ["hanko-operator.hanko.sh"], "verbs": ["get"]},
        {"apiGroups": ["hanko.sh"], "resources": list(soak_observer.RESOURCES.values()),
         "verbs": ["create", "get", "list"]},
    ])
    role["apiVersion"] = "rbac.authorization.k8s.io/v1"
    binding = resource("RoleBinding", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
        subjects=[{"kind": "ServiceAccount", "name": name, "namespace": namespace}])
    binding["apiVersion"] = "rbac.authorization.k8s.io/v1"
    args = ["--namespace", namespace, "--release", release, "--image", state["operator_image"],
            "--revision", state["revision"], "--metrics-hostname", hostname,
            "--counts", json.dumps(state["counts"], sort_keys=True), "--workers", json.dumps(state["workers"], sort_keys=True),
            "--output", "/evidence/campaign"]
    mounts = [{"name": "source", "mountPath": "/qualification", "readOnly": True},
              {"name": "evidence", "mountPath": "/evidence"},
              {"name": "metrics", "mountPath": "/run/metrics-identity", "readOnly": True},
              {"name": "provider", "mountPath": "/run/provider", "readOnly": True},
              {"name": "api", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}]
    job = resource("Job", spec={"backoffLimit": 0, "activeDeadlineSeconds": 86400 + 600 + 3 * 900 + 3600,
        "template": {"metadata": {"labels": {"hanko.sh/qualification-observer": "true"},
                                  "annotations": {"hanko.sh/campaign-sha256": digest}},
            "spec": {"serviceAccountName": name, "automountServiceAccountToken": False, "restartPolicy": "Never",
                "nodeSelector": {"kubernetes.io/os": "linux"},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "campaign", "image": state["runner"],
                    "command": ["python3", "-m", "tools.qualification.scenarios.cluster_campaign"], "args": args,
                    "workingDir": "/qualification", "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                    "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
                    "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]}}, "volumeMounts": mounts}],
                "volumes": [{"name": "source", "configMap": {"name": name, "items": items}},
                    {"name": "evidence", "persistentVolumeClaim": {"claimName": name}},
                    {"name": "metrics", "secret": {"secretName": "metrics-observer", "defaultMode": 0o440}},
                    {"name": "provider", "secret": {"secretName": "provider-bootstrap", "defaultMode": 0o440}},
                    {"name": "api", "projected": {"defaultMode": 0o440, "sources": [
                        {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
                        {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]}}]}}})
    job["apiVersion"] = "batch/v1"
    return [resource("ServiceAccount", automountServiceAccountToken=False), role, binding,
        resource("ConfigMap", immutable=True, data=sources),
        resource("PersistentVolumeClaim", spec={"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}), job]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    from tools.qualification.checks import release_contract
    state = json.loads(args.state.read_text())
    release_contract.security.verify(args.evidence, state["revision"], release_contract.VERSION,
                                    state["operator_image"].rsplit("@", 1)[-1], args.archive)
    documents = manifests(state, json.loads(args.config.read_text()))
    with args.output.open("x") as stream:
        stream.write(yaml.safe_dump_all(documents, sort_keys=False))


if __name__ == "__main__":
    main()

"""Qualify exact workload-owner grants without token or workload authority."""
from pathlib import Path
import subprocess
import tempfile

import yaml

CHART = Path(__file__).resolve().parents[1]


def render(grants, invalid=False):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as values:
        yaml.safe_dump({"workloadBinding": {"grants": grants}}, values)
        values.flush()
        result = subprocess.run(["helm", "template", "binding", str(CHART), "--namespace", "auth",
                                 "--set-string", "image.tag=fixture", "-f", values.name],
                                text=True, capture_output=True, check=False)
    if invalid:
        assert result.returncode != 0, "invalid workload grant was rendered"
        return []
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def binding_roles(docs):
    return [doc for doc in docs if doc["kind"] == "Role" and doc["metadata"]["name"].endswith("-workload-binding")]


assert not binding_roles(render([])), "default installation added workload grants"
grant = {"namespace": "workloads", "serviceAccounts": ["worker"], "configMaps": ["identity"]}
docs = render([grant])
roles = binding_roles(docs)
assert len(roles) == 1 and roles[0]["metadata"]["namespace"] == "workloads"
assert roles[0]["rules"] == [
    {"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["worker"], "verbs": ["get"]},
    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["identity"], "verbs": ["get", "patch"]},
], "binding authority exceeds named get/patch"
bindings = [doc for doc in docs if doc["kind"] == "RoleBinding" and doc["metadata"]["name"].endswith("-workload-binding")]
assert len(bindings) == 1 and bindings[0]["subjects"] == [{"kind": "ServiceAccount", "name": "binding-hanko-operator", "namespace": "auth"}]
assert not [doc for doc in docs if doc["kind"] in ("ServiceAccount", "ConfigMap") and doc["metadata"].get("namespace") == "workloads"], "runtime targets were created"
for invalid in ([grant, grant], [{**grant, "namespace": "*"}], [{**grant, "serviceAccounts": ["*"]}],
                [{**grant, "serviceAccounts": ["default"]}], [{**grant, "serviceAccounts": []}],
                [{**grant, "configMaps": ["*"]}], [{**grant, "namespace": "x" * 64}]):
    render(invalid, invalid=True)
print("Workload binding grants: default absent, exact named get/patch, no runtime targets, invalid grants rejected")

"""Keep IAM workers bounded and prevent environment bypasses of reviewed values."""
import json
from pathlib import Path
import subprocess
import tempfile

import yaml

CHART = Path(__file__).resolve().parents[1]
PINS = json.loads((CHART.parents[1] / "versions.json").read_text())


def render(values, valid):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as file:
        yaml.safe_dump(values, file)
        file.flush()
        result = subprocess.run(["helm", "template", "workers", CHART, "--kube-version", PINS["kubernetes"]["default"],
                                 "--set-string", "image.tag=qualification", "--values", file.name], capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == valid, result.stderr
    if valid:
        deployment = next(d for d in yaml.safe_load_all(result.stdout) if d and d["kind"] == "Deployment")
        return deployment["spec"]["template"]["spec"]["containers"][0]
    assert "concurren" in result.stderr.lower(), result.stderr


for workers in (1, 4, 8):
    manager = render({"reconciliation": {"maxConcurrent": workers}}, True)
    assert next(v["value"] for v in manager["env"] if v["name"] == "HANKO_IAM_MAX_CONCURRENT_RECONCILES") == str(workers)
for workers in (0, 9, -1, True, "4", "", 1.5):
    render({"reconciliation": {"maxConcurrent": workers}}, False)
render({"env": {"HANKO_IAM_MAX_CONCURRENT_RECONCILES": "8"}}, False)
for kind in ("Application", "Role", "Organization", "ResourceServer"):
    key = "HANKO_IAM_" + kind.upper() + "_MAX_CONCURRENT_RECONCILES"
    manager = render({"reconciliation": {"maxConcurrent": 4, "maxConcurrentByKind": {kind: 8}}}, True)
    env = {v["name"]: v.get("value") for v in manager["env"]}
    assert env[key] == "8" and env["HANKO_IAM_MAX_CONCURRENT_RECONCILES"] == "4"
    assert sum(k.startswith("HANKO_IAM_") for k in env) == 2
    render({"env": {key: "8"}}, False)
    for workers in (0, 9, True, "4", None, 1.5):
        render({"reconciliation": {"maxConcurrentByKind": {kind: workers}}}, False)
for overrides in ([], "", {"Tenant": 4}, {"application": 4}):
    render({"reconciliation": {"maxConcurrentByKind": overrides}}, False)
print("IAM workers: reviewed 1..8 values and override refusal passed")

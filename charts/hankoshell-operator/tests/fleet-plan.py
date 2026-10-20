"""Keep signed fleet verification an explicit locally configured transition."""

import json
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "charts/hankoshell-operator"
VERSION = json.loads((ROOT / "versions.json").read_text())["kubernetes"]["default"]
BASE = ["helm", "template", "fleet-fixture", str(CHART), "--namespace", "auth",
        "--kube-version", VERSION, "--set-string", "image.tag=fixture"]


def render(values):
    args = BASE.copy()
    for value in values:
        args += ["--set", value]
    return subprocess.run(args, capture_output=True, text=True, check=False)


for values, enabled in [([], False), (["hub.enabled=true", "fleetPlanVerification.trustConfigMap=hanko-fleet-plan-trust"], True)]:
    result = render(values)
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    env = {e["name"]: e for e in deployment["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert ("HANKO_FLEET_TRUST_CONFIGMAP" in env) == enabled
    if enabled:
        assert env["HANKO_FLEET_TRUST_CONFIGMAP"]["value"] == "hanko-fleet-plan-trust"
    assert not any(d["kind"].startswith("ValidatingAdmissionPolicy") and not any(marker in d["metadata"]["name"] for marker in ("-lifecycle-", "-sensitive-", "-rbac-", "-execution-jobs-")) for d in docs)
    assert not any(d["kind"] == "ConfigMap" and d["metadata"]["name"] == "hanko-fleet-plan-trust" for d in docs)

for values in [["fleetPlanVerification.trustConfigMap=hanko-fleet-plan-trust"],
               ["hub.enabled=true", "fleetPlanVerification.trustConfigMap=Invalid"],
               ["hub.enabled=true", "fleetPlanVerification.trustConfigMap=true"],
               ["env.HANKO_FLEET_TRUST_CONFIGMAP=unprotected"]]:
    assert render(values).returncode != 0, values

print("Fleet plans: explicit opt-in, local trust reference and independent admission ownership passed")

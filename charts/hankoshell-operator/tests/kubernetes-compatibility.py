#!/usr/bin/env python3
"""Reject unsupported versions/options and preserve the baseline across versions."""
import pathlib
import re
import subprocess
import tempfile

import yaml

CHART = pathlib.Path(__file__).resolve().parents[1]

# SDK and runtime upgrades are reviewed as a family, independently of the
# operator/chart SemVer. This mapping follows controller-runtime's support table.
go_mod = (CHART.parents[1] / "go.mod").read_text()
sdk_versions = [re.search(rf"\b{re.escape(module)} (v[\d.]+)", go_mod).group(1)
                for module in ("k8s.io/api", "k8s.io/apimachinery", "k8s.io/client-go",
                               "k8s.io/apiextensions-apiserver")]
assert len(set(sdk_versions)) == 1 and sdk_versions[0].startswith("v0.37."), sdk_versions
assert re.search(r"sigs.k8s.io/controller-runtime v0\.25\.\d+\b", go_mod), "review the runtime/SDK compatibility mapping"


def render(version, values=None, error=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as config:
        yaml.safe_dump(values or {}, config)
        config.flush()
        result = subprocess.run(
            ["helm", "template", "compatibility", str(CHART), "--namespace", "auth",
             "--kube-version", version, "--set-string", "image.tag=fixture", "-f", config.name],
            text=True, capture_output=True, check=False,
        )
    if error:
        assert result.returncode != 0 and error in result.stderr, result.stderr
        return None
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    return next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]


def baseline(pod):
    assert pod["os"]["name"] == pod["nodeSelector"]["kubernetes.io/os"] == "linux"
    assert pod["securityContext"]["runAsNonRoot"]
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    security = pod["containers"][0]["securityContext"]
    assert security["capabilities"]["drop"] == ["ALL"]
    assert not security["allowPrivilegeEscalation"] and security["readOnlyRootFilesystem"]
    assert not any(pod.get(k, False) for k in ("hostNetwork", "hostPID", "hostIPC"))


for minor in (35, 36, 37):
    # Include managed-provider build metadata and vendor prerelease suffixes.
    for version in (f"1.{minor}.0", f"1.{minor}.1+vendor.1", f"1.{minor}.1-gke.100"):
        pod = render(version)
        baseline(pod)
        assert "hostUsers" not in pod and "appArmorProfile" not in pod["securityContext"]
    pod = render(f"1.{minor}.1", {"hardening": {"appArmor": True}})
    baseline(pod)
    assert pod["securityContext"]["appArmorProfile"] == {"type": "RuntimeDefault"}
    if minor >= 36:
        pod = render(f"1.{minor}.1", {"hardening": {"userNamespaces": True, "appArmor": True}})
        baseline(pod)
        assert pod["hostUsers"] is False

render("1.35.1", {"hardening": {"userNamespaces": True}}, "requires stable user namespace")
for option in ("appArmor", "userNamespaces"):
    render("1.37.0", {"hardening": {option: "false"}}, "must be a boolean")
render("1.37.0", {"hardening": {"apparmor": True}}, "unknown hardening option")
for version in ("1.30.0", "1.34.12", "1.35.0-alpha.1", "1.38.0-alpha.1", "1.38.0", "2.0.0"):
    render(version, error="incompatible")
print("Kubernetes version bounds and optional hardening checks passed")

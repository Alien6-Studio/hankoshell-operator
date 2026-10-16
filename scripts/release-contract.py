"""Check the development contract and package one already scanned OCI delivery."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


metadata = module("release_metadata", "release-metadata.py")
security = module("oci_security", "oci-security.py")
pins = module("versions", "versions.py")
support = module("api_support", "api-support.py")
public = module("public_contract", "public-contract.py")
stable = module("stable_contract", "stable-contract.py")
operations = module("operations_contract", "operations-contract.py")
window = module("support_window", "support-window.py")
compatibility = module("compatibility_gate", "compatibility-gate.py")
go_api = module("go_api_contract", "go-api-contract.py")
versioning = metadata.versioning
VERSION = versioning.VERSION


def notes(version=VERSION):
    changelog = (ROOT / "CHANGELOG.md").read_text()
    start, end = "<!-- release-notes:start -->", "<!-- release-notes:end -->"
    if changelog.count(start) != 1 or changelog.count(end) != 1:
        raise ValueError("Expected one curated release-note block")
    body = changelog.split(start)[1].split(end)[0].strip()
    if f"hankoShell Operator {version}" not in body or "### Release overview" not in body:
        raise ValueError("Curated release notes must identify the reviewed version")
    return body + "\n"


def check(version=VERSION):
    chart = yaml.safe_load((ROOT / "charts/hankoshell-operator/Chart.yaml").read_text())
    if version != VERSION or chart["version"] != version or chart["appVersion"] != version:
        raise ValueError("Source, chart and requested qualification versions must match " + VERSION)
    if chart["annotations"]["artifacthub.io/prerelease"] != ("true" if "-" in version else "false"):
        raise ValueError("Artifact Hub prerelease status must match source maturity")
    if "artifacthub.io/signKey" in chart["annotations"]:
        raise ValueError("The Attest receipt key is not a Helm chart signing key")
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    pins.check(ROOT)
    support.check(ROOT)
    public.check(ROOT)
    stable.check(ROOT)
    operations.check(ROOT)
    window.check(ROOT)
    compatibility.check(ROOT)
    go_api.check(ROOT)
    for job in ("kubernetes", "keycloak"):
        if ci[job]["strategy"]["matrix"]["version"] != pins.DATA[job]["versions"]:
            raise ValueError("Qualification matrix differs from versions.json")
    for path in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "charts/hankoshell-operator/README.md"):
        text = (ROOT / path).read_text()
        if "initial development" not in text or "v1alpha1" not in text:
            raise ValueError(f"Missing maturity/API contract in {path}")
    return notes(version)


def prepare(version, image, revision, archive, evidence, chart_output, dist, helm,
            repository_id, public_key):
    check(version)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected the full source revision")
    if not re.fullmatch(re.escape(metadata.IMAGE) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("Expected the scanned image's immutable identity")
    security.verify(evidence, revision, version, image.split("@")[1], archive)
    if subprocess.check_output([str(helm), "version", "--template", "{{.Version}}"], text=True, timeout=30) != "v" + pins.DATA["tools"]["helm"]["version"]:
        raise ValueError("Release packaging requires the reviewed Helm " + pins.DATA["tools"]["helm"]["version"])
    if dist.exists() or chart_output.exists():
        raise ValueError("Delivery output must be fresh")
    metadata.prepare(version, image, chart_output, dist, repository_id, public_key, revision)
    for name in ("oci-security.json", "trivy-amd64.json", "trivy-arm64.json"):
        shutil.copyfile(evidence / name, dist / name)
    shutil.copyfile(security.POLICY, dist / security.POLICY.name)
    for name in ("THIRD_PARTY_NOTICES", "THIRD_PARTY_NOTICES.cosign"):
        shutil.copyfile(ROOT / name, dist / name)
    shutil.copyfile(ROOT / "security/dependency-policy.json", dist / "dependency-policy.json")
    subprocess.run([str(helm), "lint", str(chart_output), "--kube-version", pins.DATA["kubernetes"]["default"]], check=True, timeout=60)
    subprocess.run([str(helm), "package", str(chart_output), "-d", str(dist)], check=True, timeout=60)
    (dist / "image-digest.txt").write_text(image + "\n")
    (dist / "source-revision.txt").write_text(revision + "\n")
    (dist / "release-notes.md").write_text(notes(version))
    (dist / "checksums.txt").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
        for path in sorted(dist.iterdir())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("check")
    validate.add_argument("--version", default=VERSION)
    package = sub.add_parser("prepare")
    for name in ("version", "image", "revision"):
        package.add_argument("--" + name, required=True)
    for name in ("archive", "evidence", "chart-output", "dist", "helm"):
        package.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.command == "check":
        check(args.version)
    else:
        repository_id, public_key = metadata.configuration()
        prepare(args.version, args.image, args.revision, args.archive, args.evidence,
                args.chart_output, args.dist, args.helm, repository_id, public_key)


if __name__ == "__main__":
    main()

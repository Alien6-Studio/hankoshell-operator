"""Check the reviewed 0.4.0 contract and package one already scanned OCI delivery."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0"


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


metadata = module("release_metadata", "release-metadata.py")
security = module("oci_security", "oci-security.py")


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
        raise ValueError("Source, chart and requested release versions must remain 0.4.0")
    if chart["annotations"]["artifacthub.io/prerelease"] != "false":
        raise ValueError("0.4.0 is a normal initial-development SemVer release")
    if "artifacthub.io/signKey" in chart["annotations"]:
        raise ValueError("The Attest receipt key is not a Helm chart signing key")
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    expected = {"kubernetes": ["1.35.0", "1.36.2", "1.37.0"],
                "keycloak": ["26.8.0", "26.7.5"]}
    for job, versions in expected.items():
        if ci[job]["strategy"]["matrix"]["version"] != versions:
            raise ValueError("Update the release contract when changing qualification fixtures")
    crds = list((ROOT / "charts/hankoshell-operator/crds").glob("*.yaml"))
    if len(crds) != 16 or any([version["name"] for version in yaml.safe_load(path.read_text())["spec"]["versions"]]
                             != ["v1alpha1"] for path in crds):
        raise ValueError("The reviewed release exposes 16 experimental v1alpha1 APIs")
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
    if subprocess.check_output([str(helm), "version", "--template", "{{.Version}}"], text=True, timeout=30) != "v3.17.0":
        raise ValueError("Release packaging requires the reviewed Helm 3.17.0")
    if dist.exists() or chart_output.exists():
        raise ValueError("Delivery output must be fresh")
    metadata.prepare(version, image, chart_output, dist, repository_id, public_key)
    for name in ("oci-security.json", "trivy-amd64.json", "trivy-arm64.json"):
        shutil.copyfile(evidence / name, dist / name)
    shutil.copyfile(security.POLICY, dist / security.POLICY.name)
    subprocess.run([str(helm), "lint", str(chart_output), "--kube-version", "1.37.0"], check=True, timeout=60)
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

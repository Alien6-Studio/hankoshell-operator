"""Check the development contract and package one already scanned OCI delivery."""

import argparse
import hashlib
from importlib import import_module
from pathlib import Path
import re
import shutil
import subprocess

import yaml

from tools import versions as pins
from tools.release import release_metadata as metadata, oci_security as security, release_eligibility as eligibility
from tools.qualification.checks import (
    stable_contract as stable, operations_contract as operations,
    compatibility_gate as compatibility, go_api_contract as go_api,
    compatibility_evidence as production_evidence,
)

ROOT = Path(__file__).resolve().parents[3]
versioning = metadata.versioning
VERSION = versioning.VERSION


def module(_name, filename):
    # Keep the entry point used by retained, hash-bound installed harnesses.
    return import_module(filename.removesuffix(".py").replace("/", "."))


def notes(version=VERSION):
    changelog = (ROOT / "CHANGELOG.md").read_text()
    start, end = "<!-- release-notes:start -->", "<!-- release-notes:end -->"
    if changelog.count(start) != 1 or changelog.count(end) != 1:
        raise ValueError("Expected one curated release-note block")
    body = changelog.split(start)[1].split(end)[0].strip()
    if f"hankoShell Operator {version}" not in body or "### Release overview" not in body:
        raise ValueError("Curated release notes must identify the reviewed version")
    return body + "\n"


def check_qualification_permissions(release, ci):
    allowed = release["jobs"]["quality"].get("permissions", release.get("permissions", {}))
    levels = {"none": 0, "read": 1, "write": 2}
    for name, job in ci["jobs"].items():
        requested = job.get("permissions", ci.get("permissions", {}))
        if not isinstance(allowed, dict) or not isinstance(requested, dict):
            raise ValueError("Release qualification requires explicit scoped permission maps")
        for scope, level in requested.items():
            if levels.get(allowed.get(scope, "none"), -1) < levels[level]:
                raise ValueError(f"Release qualification must allow {scope}: {level} for CI job {name}, including skipped jobs")


def check_qualification_profiles(ci):
    jobs = ci["jobs"]
    if set(jobs["checks"]["needs"]) != eligibility.QUALIFICATION_JOBS:
        raise ValueError("Required gate and qualification profiles disagree")
    for name in eligibility.SOURCE_JOBS:
        if jobs[name].get("if") != "github.event_name != 'push' && inputs.release != true":
            raise ValueError("Source-only checks must run on PRs, never repeat on main or release")
    for name in ("source", "keycloak-extension", "oci"):
        if jobs[name].get("if") != "github.event_name != 'push'":
            raise ValueError("Delivery qualification must not repeat on main")
    for mode, required in (("full", eligibility.QUALIFICATION_JOBS - {"installed-scale-qualification"}),
                           ("integration", {"preflight"}),
                           ("release", eligibility.DELIVERY_JOBS | {"preflight"})):
        results = {name: {"result": "success" if name in required else "skipped"}
                   for name in eligibility.QUALIFICATION_JOBS}
        eligibility.check_jobs(results, mode)
        for name in required:
            for bad in ("skipped", "failure", "cancelled"):
                try:
                    eligibility.check_jobs(dict(results, **{name: {"result": bad}}), mode)
                except ValueError:
                    pass
                else:
                    raise ValueError("Required qualification failure was accepted: " + name)


def check(version=VERSION):
    chart = yaml.safe_load((ROOT / "charts/hankoshell-operator/Chart.yaml").read_text())
    if version != VERSION or chart["version"] != version or chart["appVersion"] != version:
        raise ValueError("Source, chart and requested qualification versions must match " + VERSION)
    if chart["annotations"]["artifacthub.io/prerelease"] != ("true" if "-" in version else "false"):
        raise ValueError("Artifact Hub prerelease status must match source maturity")
    if "artifacthub.io/signKey" in chart["annotations"]:
        raise ValueError("The Attest receipt key is not a Helm chart signing key")
    ci_workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    release_workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    check_qualification_permissions(release_workflow, ci_workflow)
    check_qualification_profiles(ci_workflow)
    ci = ci_workflow["jobs"]
    pins.check(ROOT)
    stable.check(ROOT)
    operations.check(ROOT)
    compatibility.check(ROOT)
    go_api.check(ROOT)
    production_evidence.check(ROOT)
    for job, family in (("kubernetes", "kubernetes"), ("keycloak", "keycloak")):
        if ci[job]["strategy"]["matrix"]["version"] != pins.DATA[family]["versions"]:
            raise ValueError("Qualification matrix differs from versions.json")
    for path in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
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

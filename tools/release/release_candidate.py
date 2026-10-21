"""Package a scanned qualification candidate without production trust or publication."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

import yaml

from tools.qualification.checks import release_contract as contract

ROOT = Path(__file__).resolve().parents[2]


def prepare(archive, evidence, digest, revision, output, helm):
    version = contract.VERSION
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*", version):
        raise ValueError("Candidate delivery requires a reviewed rc version")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected the full source revision")
    contract.check(version)
    contract.security.verify(evidence, revision, version, digest, archive)
    expected_helm = "v" + contract.pins.DATA["tools"]["helm"]["version"]
    if subprocess.check_output([str(helm), "version", "--template", "{{.Version}}"], text=True, timeout=30) != expected_helm:
        raise ValueError("Candidate packaging requires the reviewed Helm version")
    if output.exists():
        raise ValueError("Candidate output must be fresh")
    output.mkdir(parents=True)
    chart = output / "chart/hankoshell-operator"
    shutil.copytree(ROOT / "charts/hankoshell-operator", chart)
    image = contract.metadata.IMAGE + "@" + digest
    values_path = chart / "values.yaml"
    values = yaml.safe_load(values_path.read_text())
    values["image"].update(repository=contract.metadata.IMAGE, digest=digest, tag="")
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    chart_path = chart / "Chart.yaml"
    metadata = yaml.safe_load(chart_path.read_text())
    metadata["icon"] = f"{contract.metadata.REPOSITORY.replace('github.com', 'raw.githubusercontent.com')}/{revision}/charts/hankoshell-operator/icon.svg"
    metadata["annotations"]["artifacthub.io/images"] = yaml.safe_dump([
        {"name": "hankoshell-operator", "image": image, "platforms": ["linux/amd64", "linux/arm64"]}
    ], sort_keys=False)
    chart_path.write_text(yaml.safe_dump(metadata, sort_keys=False))
    dist = output / "dist"
    dist.mkdir()
    subprocess.run([str(helm), "lint", str(chart), "--kube-version", contract.pins.DATA["kubernetes"]["default"]], check=True, timeout=60)
    subprocess.run([str(helm), "package", str(chart), "-d", str(dist)], check=True, timeout=60)
    shutil.copyfile(archive, dist / "image.tar")
    for name in ("oci-security.json", "trivy-amd64.json", "trivy-arm64.json"):
        shutil.copyfile(evidence / name, dist / name)
    for source in (contract.security.POLICY, ROOT / "LICENSE", ROOT / "NOTICE", ROOT / "THIRD_PARTY_NOTICES", ROOT / "THIRD_PARTY_NOTICES.cosign"):
        shutil.copyfile(source, dist / source.name)
    (dist / "release-notes.md").write_text(contract.notes())
    (dist / "candidate.json").write_text(json.dumps({
        "schemaVersion": 1, "version": version, "target": contract.versioning.TARGET_VERSION,
        "state": "ready-for-qualification", "productionQualified": False,
        "published": False, "image": image, "revision": revision,
        "imageArchive": "image.tar", "chart": f"hankoshell-operator-{version}.tgz",
        "apiMaturity": "experimental", "independentReleaseApproval": False,
        "stableBlockingIssues": [21, 87, 88, 89, 93, 95, 96, 101, 104, 105, 106, 107, 110],
        "verification": "OCI checks bind this archive, version, revision and digest. Checksums establish integrity, not independent publisher trust. No production Attest key, timestamp authority or catalog identity is included.",
    }, indent=2) + "\n")
    (dist / "checksums.txt").write_text("".join(
        contract.security.sha256(path) + "  " + path.name + "\n" for path in sorted(dist.iterdir())
    ))
    print(f"Candidate {version} packaged at {dist}; no tag, registry write or GitHub Release created.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "helm"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    prepare(args.archive, args.evidence, args.digest, args.revision, args.output, args.helm)


if __name__ == "__main__":
    main()

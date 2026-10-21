"""Prepare Artifact Hub metadata and the public Attest signer before delivery verification."""

import argparse
import base64
import os
from pathlib import Path
import re
import shutil
from urllib.parse import quote
from uuid import UUID

import yaml

from tools.release import release_version as versioning

ROOT = Path(__file__).resolve().parents[2]

REPOSITORY = "https://github.com/Alien6-Studio/hankoshell-operator"
IMAGE = "ghcr.io/alien6-studio/hankoshell-operator"
PUBLIC_KEY_FILE = "hankoshell-operator-attest-public-key.pem"


def configuration():
    repository_id = os.environ.get("HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID", "")
    try:
        parsed = UUID(repository_id)
    except (ValueError, AttributeError) as error:
        raise ValueError("Set the repository UUID assigned by Artifact Hub") from error
    if str(parsed) != repository_id or parsed.int == 0:
        raise ValueError("Expected the canonical repository UUID assigned by Artifact Hub")
    public_key = os.environ.get("HANKOSHELL_ATTEST_PUBLIC_KEY", "")
    if not re.fullmatch(r"[0-9a-f]{64}", public_key):
        raise ValueError("Expected the trusted Ed25519 Attest public key as lowercase hex")
    return repository_id, public_key


def prepare(version, image, chart_output, dist, repository_id, public_key, revision=None):
    if "-" in version:
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Development metadata requires the actual source revision")
        icon_ref = revision
        tag = None
    else:
        versioning.require_production(version)
        tag = quote(versioning.public_tag(version), safe="")
        icon_ref = tag
    if not re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("Expected the exact published operator image digest")
    source = ROOT / "charts/hankoshell-operator"
    chart = yaml.safe_load((source / "Chart.yaml").read_text())
    if chart["version"] != version or chart["appVersion"] != version:
        raise ValueError("Chart and application versions must match the reviewed release tag")
    annotations = chart["annotations"]
    if not yaml.safe_load(annotations.get("artifacthub.io/changes", "")):
        raise ValueError("Describe this chart version in artifacthub.io/changes")
    chart["icon"] = f"https://raw.githubusercontent.com/Alien6-Studio/hankoshell-operator/{icon_ref}/charts/hankoshell-operator/icon.svg"
    annotations["artifacthub.io/prerelease"] = "true" if "-" in version else "false"
    annotations["artifacthub.io/images"] = yaml.safe_dump([{
        "name": "hankoshell-operator", "image": image,
        "platforms": ["linux/amd64", "linux/arm64"],
    }], sort_keys=False)
    annotations.pop("artifacthub.io/signKey", None)
    links = yaml.safe_load(annotations.get("artifacthub.io/links", "[]"))
    links = [link for link in links if link["name"] != "Attest delivery verification key"]
    if tag is not None:
        links.insert(0, {"name": "Attest delivery verification key",
                         "url": f"{REPOSITORY}/releases/download/{tag}/{PUBLIC_KEY_FILE}"})
    annotations["artifacthub.io/links"] = yaml.safe_dump(links, sort_keys=False)
    shutil.copytree(source, chart_output)
    (chart_output / "Chart.yaml").write_text(yaml.safe_dump(chart, sort_keys=False))
    values_path = chart_output / "values.yaml"
    values = yaml.safe_load(values_path.read_text())
    values["image"]["repository"], values["image"]["digest"] = image.split("@")
    values["image"]["tag"] = ""
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    dist.mkdir(parents=True, exist_ok=True)
    # This ID comes from Artifact Hub, never from a generated placeholder UUID.
    (dist / "artifacthub-repo.yml").write_text(yaml.safe_dump({"repositoryID": repository_id}))
    der = bytes.fromhex("302a300506032b6570032100" + public_key)
    (dist / PUBLIC_KEY_FILE).write_text(
        "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--image")
    parser.add_argument("--revision")
    parser.add_argument("--chart-output", type=Path)
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    repository_id, public_key = configuration()
    if args.check_config:
        return
    if any(value is None for name, value in vars(args).items() if name != "check_config"):
        parser.error("All metadata arguments are required")
    prepare(args.version, args.image, args.chart_output, args.dist, repository_id, public_key, args.revision)


if __name__ == "__main__":
    main()

"""Publish a documentation-only chart revision using an existing signed operator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
from urllib.parse import quote

import yaml

from tools import versions
from tools.release import attest_release as attest
from tools.release import public_release_verify as public
from tools.release import release_eligibility as eligibility
from tools.release import release_metadata as metadata
from tools.release import release_publish as delivery
from tools.release import oci_security

ROOT = Path(__file__).resolve().parents[2]
REPO = delivery.REPOSITORY
BUNDLE = "hankoshell-chart-attest.tar.gz"
WORKFLOW = "chart-package.yml"


def configuration():
    config = dict(versions.DATA["chart_revision"])
    config["chart_version"] = versions.chart_version()
    if (config["operator_version"] != versions.DATA["release"]["version"]
            or not all(metadata.versioning.is_stable(config[k]) for k in ("operator_version", "chart_version"))
            or config["operator_version"] == config["chart_version"]
            or not re.fullmatch(r"[0-9a-f]{40}", config["operator_revision"])
            or not re.fullmatch(r"[0-9a-f]{64}", config["base_chart_sha256"])
            or not re.fullmatch(re.escape(metadata.IMAGE) + r"@sha256:[0-9a-f]{64}", config["image"])):
        raise ValueError("Invalid independent chart/operator pins")
    return config


def identity():
    config = configuration()
    revision = os.environ["GITHUB_SHA"]
    tag = "chart-v" + config["chart_version"]
    if os.environ["TAG"] != tag or os.environ["GITHUB_REPOSITORY"] != REPO:
        raise ValueError("Unexpected chart release identity")
    metadata.versioning.require_production(config["operator_version"])
    eligibility.verify_tag(REPO, tag, revision, os.environ["REF"], public.github,
                           lambda *args: public.run(["git", *args]).decode(),
                           os.environ.get("EXPECTED_TAG_OBJECT"), tag_prefix="chart-")
    eligibility.verify_qualification(REPO, revision, public.github,
                                    lambda *args: public.run(["git", *args]).decode(),
                                    lambda path: public.github(path, binary=True))
    return config, revision, tag


def public_trust():
    policy = metadata.publisher()["attest"]
    config = {"KEY_ID": policy["key_id"], "PUBLIC_KEY": policy["public_key"],
              "TSA_CERTIFICATE": os.environ["HANKOSHELL_ATTEST_TSA_CERTIFICATE"]}
    attest.validate_publisher_trust(config)
    return config


def chart_contents(path):
    with tarfile.open(path) as archive:
        entries = [m for m in archive.getmembers() if not m.isdir()]
        if (len(entries) > 256 or len({m.name for m in entries}) != len(entries)
                or sum(m.size for m in entries) > 32 * 1024**2
                or any(not m.isfile() or Path(m.name).is_absolute() or ".." in Path(m.name).parts for m in entries)):
            raise ValueError("Unsafe chart archive")
        return {m.name: archive.extractfile(m).read() for m in entries}


def documentation_only(base, revised):
    """Every template, CRD and default value must retain its exact bytes."""
    if set(base) != set(revised):
        raise ValueError("Chart revision changed its file inventory")
    permitted = {"hankoshell-operator/Chart.yaml", "hankoshell-operator/README.md"}
    changed = {name for name in base if base[name] != revised[name]}
    if not changed <= permitted or "hankoshell-operator/README.md" not in changed:
        raise ValueError("Only catalogue metadata and README changes are permitted")
    old = yaml.safe_load(base["hankoshell-operator/Chart.yaml"])
    new = yaml.safe_load(revised["hankoshell-operator/Chart.yaml"])
    expected = dict(old)
    expected.update(version=new["version"], description=new["description"], annotations=dict(old["annotations"]))
    expected["annotations"]["artifacthub.io/changes"] = new["annotations"]["artifacthub.io/changes"]
    if expected != new or new["appVersion"] != old["appVersion"]:
        raise ValueError("Chart revision changed operator identity or installation metadata")
    return sorted(changed)


def normalized_render(helm, chart):
    raw = delivery.run([helm, "template", "hankoshell-operator", chart, "--namespace", "hankoshell-system",
                        "--kube-version", versions.DATA["kubernetes"]["default"], "--include-crds"])
    objects = [o for o in yaml.safe_load_all(raw) if o]

    def visit(value, path=()):
        if isinstance(value, dict):
            if path[-2:] == ("metadata", "labels"):
                value.pop("helm.sh/chart", None)
            for key, child in value.items():
                visit(child, path + (key,))
        elif isinstance(value, list):
            for child in value:
                visit(child, path)
    for value in objects:
        visit(value)
    objects.sort(key=lambda o: (o["kind"], o.get("metadata", {}).get("namespace", ""), o["metadata"]["name"]))
    return hashlib.sha256(json.dumps(objects, sort_keys=True).encode()).hexdigest()


def notes(config):
    text = (ROOT / "CHART_CHANGELOG.md").read_text()
    marker = "## " + config["chart_version"] + "\n"
    if text.count(marker) != 1:
        raise ValueError("Missing reviewed chart release notes")
    body = text.split(marker, 1)[1].split("\n## ", 1)[0].strip() + "\n"
    if "hankoShell Helm chart " + config["chart_version"] not in body:
        raise ValueError("Chart notes must identify the chart version")
    return body


def binding(root, config, revision):
    return {"schema": 1, "kind": "helm-chart-revision", "source_revision": revision,
            **config, "files": delivery.hashes(root)}


def verify_checkpoint(root, config, revision):
    record = json.loads((root / "checkpoint.json").read_text())
    if record != binding(root, config, revision):
        raise ValueError("Chart checkpoint identity or bytes changed")
    return record


def restore(registry, reference, root, config, revision):
    digest = registry.resolve(reference)
    if digest is None:
        return False
    with tempfile.TemporaryDirectory() as directory:
        downloaded = Path(directory)
        registry.pull(reference.rsplit(":", 1)[0] + "@" + digest, downloaded)
        if {p.name for p in downloaded.iterdir()} != {"chart-delivery.tar"}:
            raise ValueError("Unexpected chart checkpoint layers")
        delivery.extract(downloaded / "chart-delivery.tar", root)
    verify_checkpoint(root, config, revision)
    return True


def base_delivery(args, config):
    base = args.root.parent / "operator-base"
    registry = delivery.Registry(args.oras, args.helm)
    record = delivery.restore(registry, metadata.IMAGE + ":delivery-candidate-" + config["operator_version"],
                              base, config["operator_version"], config["operator_revision"])
    if record is None or record["image"] != config["image"]:
        raise ValueError("The public operator checkpoint is unavailable or differs")
    assets = args.root.parent / "operator-public-assets"
    assets.mkdir()
    for directory in (base / "dist", base / "release-evidence"):
        for path in directory.iterdir():
            shutil.copyfile(path, assets / path.name)
    verified = public.verify(config["operator_version"], config["operator_revision"], config["image"],
                             assets, public_trust(), args.cosign, args.attest)
    if verified["chart_sha256"] != config["base_chart_sha256"]:
        raise ValueError("Public base chart differs from its reviewed checksum")
    fresh = args.root.parent / "fresh-scan"
    oci_security.scan(SimpleNamespace(archive=base / "image.tar", scanner=args.trivy, output=fresh,
                     digest=config["image"].split("@")[1], revision=config["operator_revision"], version=config["operator_version"]))
    return metadata.chart_file(assets, config["operator_version"]), fresh


def prepare(args):
    config, revision, _ = identity()
    base, fresh = base_delivery(args, config)
    registry = delivery.Registry(args.oras, args.helm)
    reference = delivery.CHART + ":chart-delivery-candidate-" + config["chart_version"]
    if restore(registry, reference, args.root, config, revision):
        print("restored=true")
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write("restored=true\n")
        return
    args.root.mkdir()
    chart, dist = args.root.parent / "chart/hankoshell-operator", args.root / "dist"
    repository_id, public_key = metadata.configuration()
    metadata.prepare(config["operator_version"], config["image"], chart, dist, repository_id, public_key,
                     config["operator_revision"])
    delivery.run([args.helm, "lint", chart, "--kube-version", versions.DATA["kubernetes"]["default"]])
    delivery.run([args.helm, "package", chart, "--destination", dist])
    packaged = metadata.chart_file(dist, config["operator_version"])
    changed = documentation_only(chart_contents(base), chart_contents(packaged))
    before, after = normalized_render(args.helm, base), normalized_render(args.helm, packaged)
    if before != after:
        raise ValueError("Chart revision changed rendered installation resources")
    (dist / "render-equivalence.json").write_text(json.dumps({"result": "pass", "changed_files": changed,
        "normalized_render_sha256": after, "normalization": "metadata.labels helm.sh/chart only"}, indent=2) + "\n")
    (dist / "chart-revision.json").write_text(json.dumps({**config, "source_revision": revision}, indent=2) + "\n")
    (dist / "source-revision.txt").write_text(revision + "\n")
    (dist / "operator-source-revision.txt").write_text(config["operator_revision"] + "\n")
    (dist / "image-digest.txt").write_text(config["image"] + "\n")
    (dist / "release-notes.md").write_text(notes(config))
    for path in fresh.iterdir():
        shutil.copyfile(path, dist / path.name)
    (dist / "checksums.txt").write_text("".join(delivery.contract.security.sha256(p) + "  " + p.name + "\n" for p in sorted(dist.iterdir())))
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("restored=false\n")


def verify_payloads(root, config, revision):
    dist = root / "dist"
    chart = metadata.chart_file(dist, config["operator_version"])
    if metadata.chart_metadata(chart)["version"] != config["chart_version"]:
        raise ValueError("Unexpected chart version")
    if json.loads((dist / "chart-revision.json").read_text()) != {**config, "source_revision": revision}:
        raise ValueError("Chart source/operator binding differs")
    if ((dist / "source-revision.txt").read_text().strip() != revision
            or (dist / "image-digest.txt").read_text().strip() != config["image"]
            or (dist / "operator-source-revision.txt").read_text().strip() != config["operator_revision"]
            or (dist / "release-notes.md").read_text() != notes(config)):
        raise ValueError("Chart release identity differs")
    files = {p.name: p for p in dist.iterdir()}
    expected_files = {chart.name, "chart-revision.json", "render-equivalence.json", "source-revision.txt",
                      "operator-source-revision.txt", "image-digest.txt", "release-notes.md",
                      "artifacthub-repo.yml", metadata.PUBLIC_KEY_FILE, "oci-security.json", "trivy-amd64.json",
                      "trivy-arm64.json", "checksums.txt", "checksums.sigstore.json"}
    if set(files) != expected_files or any(p.is_symlink() or not p.is_file() for p in files.values()):
        raise ValueError("Unexpected chart delivery files")
    checksums = {}
    for line in (dist / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("Ambiguous chart checksums")
        checksums[match[2]] = match[1]
    if set(checksums) != set(files) - {"checksums.txt", "checksums.sigstore.json"} or any(
            files[n].is_symlink() or not files[n].is_file() or metadata.chart_metadata(chart)["appVersion"] != config["operator_version"]
            or delivery.contract.security.sha256(files[n]) != digest for n, digest in checksums.items()):
        raise ValueError("Chart checksums or operator version changed")
    return files


def verify_signatures(args, config, revision, tag):
    files = verify_payloads(args.root, config, revision)
    certificate = f"https://github.com/{REPO}/.github/workflows/{WORKFLOW}@refs/tags/{tag}"
    delivery.run([args.cosign, "verify-blob", "--bundle", files["checksums.sigstore.json"],
                  "--certificate-identity", certificate, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", files["checksums.txt"]])
    trust = public_trust()
    attest.validate_public_identity(trust, args.attest)
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        with tarfile.open(args.root / "release-evidence" / BUNDLE) as archive:
            members = archive.getmembers()
            if (len(members) > 64 or sum(m.size for m in members) > 64 * 1024**2
                    or any(not (m.isfile() or m.isdir()) or Path(m.name).is_absolute() or ".." in Path(m.name).parts for m in members)):
                raise ValueError("Unsafe chart receipt")
            archive.extractall(workspace, filter="data")
        manifest = json.loads((workspace / "delivery/manifest.json").read_text())
        expected = {"artifact_kind": "helm-chart-revision", "operator_version": config["operator_version"],
                    "operator_revision": config["operator_revision"], "source_revision": revision,
                    "version": config["chart_version"], "image": config["image"], "repository": REPO}
        if any(manifest.get(k) != v for k, v in expected.items()) or set(manifest["artifacts"]) != set(files):
            raise ValueError("Chart receipt identity differs")
        if (workspace / "attest.yaml").read_bytes() != (ROOT / "attest.yaml").read_bytes():
            raise ValueError("Unexpected chart receipt pipeline")
        for name, digest in manifest["artifacts"].items():
            if delivery.contract.security.sha256(files[name]) != digest or (workspace / "delivery" / name).read_bytes() != files[name].read_bytes():
                raise ValueError("Chart receipt payload differs")
        store = workspace / ".attest/trust"
        (store / "tsa").mkdir(parents=True)
        (store / (trust["KEY_ID"] + ".pub")).write_text(attest.public_key_pem(trust["PUBLIC_KEY"]))
        (store / "trust.toml").write_text(f'version = 1\n\n[[key]]\nid = "{trust["KEY_ID"]}"\nname = "chart release"\nstatus = "trusted"\n')
        (store / "tsa/issuer.crt").write_text(trust["TSA_CERTIFICATE"])
        receipt = workspace / "receipt.yaml"
        verdict = json.loads(delivery.run([args.attest, "verify", receipt, "--recompute", "--workspace", workspace,
            "--trust-store", store, "--offline", "--require", attest.REQUIRED, "--format", "json"]))
        attest.validate_verdict(verdict, trust["PUBLIC_KEY"], receipt)


def save(args):
    config, revision, tag = identity()
    verify_signatures(args, config, revision, tag)
    record = binding(args.root, config, revision)
    (args.root / "checkpoint.json").write_text(json.dumps(record, sort_keys=True) + "\n")
    registry = delivery.Registry(args.oras, args.helm)
    reference = delivery.CHART + ":chart-delivery-candidate-" + config["chart_version"]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        if registry.resolve(reference) is not None:
            restored = path / "existing"
            restore(registry, reference, restored, config, revision)
            if json.loads((restored / "checkpoint.json").read_text()) != record:
                raise ValueError("Existing chart delivery differs")
            return
        archive = path / "chart-delivery.tar"
        with tarfile.open(archive, "w") as package:
            for file in sorted(args.root.rglob("*")):
                if file.is_file():
                    package.add(file, arcname=file.relative_to(args.root), recursive=False)
        registry.push_file(reference, archive, "application/vnd.hanko.chart-delivery.layer.v1.tar")
        restore(registry, reference, path / "confirmed", config, revision)


def publish(args):
    config, revision, tag = identity()
    verify_checkpoint(args.root, config, revision)
    verify_signatures(args, config, revision, tag)
    base = args.root.parent / "operator-base"
    oci_security.verify(args.root.parent / "fresh-scan", config["operator_revision"], config["operator_version"],
                        config["image"].split("@")[1], base / "image.tar")
    registry = delivery.Registry(args.oras, args.helm)
    chart = metadata.chart_file(args.root / "dist", config["operator_version"])
    exists = delivery.matching_file(registry, delivery.CHART + ":" + config["chart_version"], chart)
    if registry.resolve(metadata.IMAGE + ":" + config["operator_version"]) != config["image"].split("@")[1]:
        raise ValueError("Public operator tag differs from the qualified image")
    if not exists:
        registry.push_chart(chart, delivery.CHART)
        if not delivery.matching_file(registry, delivery.CHART + ":" + config["chart_version"], chart):
            raise ValueError("Chart publication was not acknowledged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("eligibility", "prepare", "sign", "save", "publish", "verify"))
    parser.add_argument("--root", type=Path)
    for tool in ("helm", "oras", "cosign", "attest", "trivy"):
        parser.add_argument("--" + tool, type=Path)
    args = parser.parse_args()
    if args.mode == "eligibility":
        config, revision, tag = identity()
        print(json.dumps({"chart_version": config["chart_version"], "operator_version": config["operator_version"], "revision": revision, "tag": tag}))
    elif args.mode == "prepare":
        prepare(args)
    elif args.mode == "sign":
        config, revision, _ = identity()
        files = verify_payloads(args.root, config, revision)
        signing = SimpleNamespace(attest=args.attest, openssl=Path("/usr/bin/openssl"), version=config["chart_version"],
            revision=revision, image=config["image"], workspace=args.root.parent / "chart-attest", output=args.root / "release-evidence",
            run_url=f'https://github.com/{REPO}/actions/runs/{os.environ["GITHUB_RUN_ID"]}')
        attest.sign_files(signing, attest.configuration(), files, bundle_name=BUNDLE,
                          extra={"artifact_kind": "helm-chart-revision", "operator_version": config["operator_version"], "operator_revision": config["operator_revision"]})
    elif args.mode == "save":
        save(args)
    elif args.mode == "publish":
        publish(args)
    else:
        config, revision, tag = identity()
        verify_checkpoint(args.root, config, revision)
        verify_signatures(args, config, revision, tag)


if __name__ == "__main__":
    main()

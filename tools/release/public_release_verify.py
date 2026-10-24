"""Authenticate historical public release assets without borrowing current-version fixture trust."""

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import zipfile

import yaml

from tools.release import release_eligibility as eligibility, attest_release as attestation, release_version as versioning

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Alien6-Studio/hankoshell-operator"


def run(command, **kwargs):
    result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise ValueError("Historical public artifact verification failed")
    return result.stdout


def github(path, binary=False):
    raw = run(["gh", "api", path])
    if len(raw) > (4 * 1024**2 if binary else 1024**2):
        raise ValueError("Historical verification response exceeds its budget")
    return raw if binary else json.loads(raw)


def capture_identity(capture_path, artifact_id, revision, fetch=github):
    if type(artifact_id) is not int or artifact_id < 1:
        raise ValueError("An actual installed-corpus Actions artifact is required")
    base = f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}"
    artifact = fetch(base)
    if (not isinstance(artifact, dict) or artifact.get("id") != artifact_id or artifact.get("expired") is not False
            or artifact.get("workflow_run", {}).get("head_sha") != revision
            or type(artifact.get("size_in_bytes")) is not int or not 1 <= artifact["size_in_bytes"] <= 4 * 1024**2
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", ""))):
        raise ValueError("Captured corpus artifact is not bound to the published source")
    raw = fetch(base + "/zip", binary=True)
    if hashlib.sha256(raw).hexdigest() != artifact["digest"].split(":")[1]:
        raise ValueError("Installed-corpus artifact transport integrity failed")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        corpus = [item for item in members if item.filename.endswith(".corpus.json")]
        if (len(corpus) != 1 or len(members) > 8 or sum(item.file_size for item in members) > 2 * 1024**2
                or len({item.filename for item in members}) != len(members)):
            raise ValueError("Unexpected installed corpus artifact")
        if archive.read(corpus[0]) != capture_path.read_bytes():
            raise ValueError("Captured corpus differs from the actual installed Actions artifact")
    return {"artifact_id": artifact_id, "artifact_digest": artifact["digest"]}


def verify(version, revision, image, assets, trust, cosign, attest, *, fetch=github, git=None):
    if (not versioning.is_stable(version)
            or not re.fullmatch(r"ghcr\.io/alien6-studio/hankoshell-operator@sha256:[0-9a-f]{64}", image)):
        raise ValueError("Historical qualification requires a real stable public release")
    tag = "v" + version
    release = fetch(f"repos/{REPOSITORY}/releases/tags/{tag}")
    if (not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False
            or release.get("tag_name") != tag or not release.get("published_at")):
        raise ValueError("A draft, prerelease or invented release is not a supported public predecessor")
    git = git or (lambda *args: run(["git", *args], cwd=ROOT).decode())
    identity = eligibility.verify_tag(REPOSITORY, tag, revision, "refs/tags/" + tag, fetch, git)
    chart_name = f"hankoshell-operator-{version}.tgz"
    files = {path.name: path for path in assets.iterdir()}
    if any(path.is_symlink() or not path.is_file() for path in files.values()):
        raise ValueError("Historical assets must be regular files")
    bundle_name = "hankoshell-operator-attest.tar.gz"
    required = {chart_name, "checksums.txt", "checksums.sigstore.json", "image-digest.txt", "source-revision.txt", bundle_name}
    if not required <= files.keys() or sum(path.stat().st_size for path in files.values()) > 96 * 1024**2:
        raise ValueError("Historical delivery is incomplete or oversized")
    published = {asset.get("name"): asset for asset in release.get("assets", [])}
    for name, path in files.items():
        asset = published.get(name, {})
        if (asset.get("size") != path.stat().st_size
                or asset.get("digest") != "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()):
            raise ValueError("Historical file does not match its actual GitHub Release asset")
    expected_identity = f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
    run([cosign, "verify-blob", "--certificate-identity", expected_identity,
         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
         "--bundle", files["checksums.sigstore.json"], files["checksums.txt"]])
    run([cosign, "verify", "--certificate-identity", expected_identity,
         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", image])
    hashes = {}
    for line in files["checksums.txt"].read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in hashes or match[2] not in files:
            raise ValueError("Historical checksum manifest is ambiguous")
        hashes[match[2]] = match[1]
    if not {chart_name, "image-digest.txt", "source-revision.txt"} <= hashes.keys() or any(
            hashlib.sha256(files[name].read_bytes()).hexdigest() != value for name, value in hashes.items()):
        raise ValueError("Historical signed checksums do not match")
    if files["source-revision.txt"].read_text().strip() != revision or files["image-digest.txt"].read_text().strip() != image:
        raise ValueError("Historical artifact identity differs from the selected predecessor")
    with tarfile.open(files[chart_name]) as chart:
        members = chart.getmembers()
        names = [member.name for member in members]
        if len(names) > 256 or sum(member.size for member in members) > 32 * 1024**2 or len(names) != len(set(names)) or any(not (member.isdir() or member.isfile()) or
                PurePosixPath(member.name).is_absolute() or ".." in PurePosixPath(member.name).parts
                for member in chart.getmembers()):
            raise ValueError("Historical chart contains unsafe entries")
        metadata = yaml.safe_load(chart.extractfile("hankoshell-operator/Chart.yaml"))
        values = yaml.safe_load(chart.extractfile("hankoshell-operator/values.yaml"))
        if (metadata.get("version") != version or metadata.get("appVersion") != version
                or values["image"].get("tag") or values["image"]["repository"] + "@" + values["image"]["digest"] != image):
            raise ValueError("Historical chart does not pin the authentic predecessor")
    public = {key: trust[key] for key in ("KEY_ID", "PUBLIC_KEY", "TSA_CERTIFICATE")}
    attestation.validate_public_identity(public, attest)
    with tempfile.TemporaryDirectory(prefix="historical-release-trust-") as directory:
        workspace = Path(directory)
        with tarfile.open(files[bundle_name]) as package:
            members = package.getmembers()
            names = [member.name for member in members]
            if (len(names) != len(set(names)) or len(names) > 64 or sum(member.size for member in members) > 64 * 1024**2
                    or any(not (member.isdir() or member.isfile()) or PurePosixPath(member.name).is_absolute()
                           or ".." in PurePosixPath(member.name).parts for member in members)):
                raise ValueError("Historical receipt contains unsafe or unbounded entries")
            package.extractall(workspace, filter="data")
        if yaml.safe_load((workspace / "attest.yaml").read_text()) != yaml.safe_load((ROOT / "attest.yaml").read_text()):
            raise ValueError("Historical receipt attempts to select another verification pipeline")
        manifest = json.loads((workspace / "delivery/manifest.json").read_text())
        if (manifest.get("repository") != REPOSITORY or manifest.get("version") != version
                or manifest.get("image") != image or manifest.get("source_revision") != revision):
            raise ValueError("Historical receipt does not bind the published identities")
        payloads = manifest.get("artifacts", {})
        if set(payloads) != set(hashes) | {"checksums.txt", "checksums.sigstore.json"}:
            raise ValueError("Historical receipt and signed checksum coverage differ")
        for name, value in payloads.items():
            if name not in files or hashlib.sha256(files[name].read_bytes()).hexdigest() != value or (workspace / "delivery" / name).read_bytes() != files[name].read_bytes():
                raise ValueError("Historical receipt payload was substituted")
        store = workspace / ".attest/trust"
        (store / "tsa").mkdir(parents=True)
        (store / f"{public['KEY_ID']}.pub").write_text(attestation.public_key_pem(public["PUBLIC_KEY"]))
        (store / "trust.toml").write_text(f'version = 1\n\n[[key]]\nid = "{public["KEY_ID"]}"\nname = "reviewed historical release"\nstatus = "trusted"\n')
        (store / "tsa/issuer.crt").write_text(public["TSA_CERTIFICATE"])
        receipt = workspace / "receipt.yaml"
        verdict = json.loads(run([attest, "verify", receipt, "--recompute", "--workspace", workspace,
                                 "--trust-store", store, "--offline", "--require", attestation.REQUIRED, "--format", "json"]))
        attestation.validate_verdict(verdict, public["PUBLIC_KEY"], receipt)
    return {"version": version, "revision": revision, "image": image, "published": True, "verified": True,
            "tag_object": identity["tag_object"], "cosign_identity": expected_identity,
            "attest_key_id": public["KEY_ID"], "chart_sha256": hashlib.sha256(files[chart_name].read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("version", "revision", "image"):
        parser.add_argument("--" + name, required=True)
    for name in ("assets", "trust", "cosign", "attest", "capture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--capture-artifact-id", type=int, required=True)
    args = parser.parse_args()
    result = verify(args.version, args.revision, args.image, args.assets, json.loads(args.trust.read_text()), args.cosign, args.attest)
    result.update(capture_identity(args.capture, args.capture_artifact_id, args.revision),
                  fixture_sha256=hashlib.sha256(args.capture.read_bytes()).hexdigest())
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

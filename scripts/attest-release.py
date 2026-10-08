"""Sign and strictly verify the operator delivery before release publication."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tarfile
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oci_security", ROOT / "scripts/oci-security.py")
oci_security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oci_security)
spec = importlib.util.spec_from_file_location("release_contract", ROOT / "scripts/release-contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

CHECKS = {"schema", "consistency", "signature", "timestamp", "recompute"}
PUBLIC_KEY_FILE = "hankoshell-operator-attest-public-key.pem"


def public_key_pem(public_key):
    der = bytes.fromhex("302a300506032b6570032100" + public_key)
    return "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n"


def configuration():
    prefix = "HANKOSHELL_ATTEST_"
    config = {name: os.environ.get(prefix + name, "") for name in (
        "KEY_ID", "PUBLIC_KEY", "TSA_URL", "TSA_CERTIFICATE"
    )}
    config["SIGNING_KEY"] = os.environ.pop(prefix + "SIGNING_KEY", "")
    if not all(config.values()):
        raise ValueError("The operator's Attest signer and TSA configuration is required")
    if not re.fullmatch(r"[0-9a-f]{32}", config["KEY_ID"]):
        raise ValueError("Invalid Attest key ID")
    if not re.fullmatch(r"[0-9a-f]{64}", config["PUBLIC_KEY"]):
        raise ValueError("Invalid Attest public key")
    url = urlsplit(config["TSA_URL"])
    if (url.scheme not in ("http", "https") or not url.hostname
            or url.username or url.password or url.query or url.fragment):
        raise ValueError("Expected an explicit RFC 3161 endpoint without credentials")
    if len(config["SIGNING_KEY"]) > 16384 or not config["SIGNING_KEY"].startswith("-----BEGIN PRIVATE KEY-----"):
        raise ValueError("Expected a PKCS#8 signing key")
    if len(config["TSA_CERTIFICATE"]) > 32768:
        raise ValueError("TSA certificate is too large")
    ssl.PEM_cert_to_DER_cert(config["TSA_CERTIFICATE"])
    return config


def validate_verdict(report, signer, receipt):
    if not isinstance(report, dict) or set(report) != {"receipt", "verdict", "checks", "signed_by", "warnings"}:
        raise ValueError("Invalid native Attest verdict")
    checks = report["checks"]
    if (report["receipt"] != str(receipt) or report["verdict"] != "pass"
            or report["signed_by"] != signer or report["warnings"] != []
            or not isinstance(checks, list) or len(checks) != len(CHECKS)):
        raise ValueError("Attest requires the expected receipt and signer without warnings")
    if any(not isinstance(check, dict) or set(check) != {"name", "status", "detail"}
           or not isinstance(check["name"], str) or check["status"] != "pass" or not isinstance(check["detail"], str)
           for check in checks) or {check["name"] for check in checks} != CHECKS:
        raise ValueError("All five native Attest checks must pass")


def delivery_files(dist, version, revision, image):
    expected = {f"hankoshell-operator-{version}.tgz", "image-digest.txt",
                "source-revision.txt", "checksums.txt", "checksums.sigstore.json",
                "artifacthub-repo.yml", PUBLIC_KEY_FILE, "oci-security.json",
                "trivy-amd64.json", "trivy-arm64.json", "oci-vulnerability-policy.json", "release-notes.md"}
    files = {path.name: path for path in dist.iterdir()}
    if set(files) != expected or any(path.is_symlink() or not path.is_file() for path in files.values()):
        raise ValueError("Expected only the exact operator release artifacts")
    if files["image-digest.txt"].read_text().strip() != image or files["source-revision.txt"].read_text().strip() != revision:
        raise ValueError("Delivery image/source identity mismatch")
    if files["release-notes.md"].read_text() != contract.notes(version):
        raise ValueError("Delivery must include the reviewed curated release notes")
    covered = expected - {"checksums.txt", "checksums.sigstore.json"}
    recorded = {}
    for line in files["checksums.txt"].read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-zA-Z0-9_.-]+)", line)
        if not match or match[2] in recorded or match[2] not in covered:
            raise ValueError("Invalid or duplicate artifact checksum")
        recorded[match[2]] = match[1]
    if set(recorded) != covered or any(hashlib.sha256(files[name].read_bytes()).hexdigest() != digest for name, digest in recorded.items()):
        raise ValueError("Delivery artifact checksum mismatch")
    if files["oci-vulnerability-policy.json"].read_bytes() != oci_security.POLICY.read_bytes():
        raise ValueError("Delivered OCI vulnerability policy mismatch")
    oci_security.verify(dist, revision, version, image.split("@")[1])
    with tarfile.open(files[f"hankoshell-operator-{version}.tgz"]) as chart:
        values = yaml.safe_load(chart.extractfile("hankoshell-operator/values.yaml"))
        metadata = yaml.safe_load(chart.extractfile("hankoshell-operator/Chart.yaml"))
    if (values["image"]["repository"] + "@" + values["image"]["digest"] != image or values["image"].get("tag")
            or metadata["version"] != version or metadata["appVersion"] != version):
        raise ValueError("Packaged chart must select the scanned image digest and release version")
    return files


def sign_delivery(args, config):
    if subprocess.check_output([str(args.attest), "--version"], text=True).strip() != "attest 0.1.0":
        raise ValueError("Expected Attest 0.1.0")
    files = delivery_files(args.dist, args.version, args.revision, args.image)
    if files[PUBLIC_KEY_FILE].read_text() != public_key_pem(config["PUBLIC_KEY"]):
        raise ValueError("Published Attest key must match the independently trusted delivery signer")
    workspace = args.workspace.resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copyfile(ROOT / "attest.yaml", workspace / "attest.yaml")
    delivery = workspace / "delivery"
    delivery.mkdir()
    hashes = {}
    for name, path in files.items():
        target = delivery / name
        shutil.copyfile(path, target)
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    (delivery / "manifest.json").write_text(json.dumps({
        "scope": "verified-release-delivery; build not supervised by Attest",
        "repository": "Alien6-Studio/hankoshell-operator",
        "source_revision": args.revision,
        "version": args.version,
        "image": args.image,
        "workflow_run": args.run_url,
        "artifacts": hashes,
    }, indent=2, sort_keys=True) + "\n")
    trust = workspace / ".attest/trust"
    (trust / "tsa").mkdir(parents=True)
    (trust / f'{config["KEY_ID"]}.pub').write_text(public_key_pem(config["PUBLIC_KEY"]))
    (trust / "trust.toml").write_text(
        'version = 1\n\n[[key]]\n' + f'id = "{config["KEY_ID"]}"\nname = "hankoShell Operator release"\nstatus = "trusted"\n')
    (trust / "tsa/issuer.crt").write_text(config["TSA_CERTIFICATE"])
    keys = workspace / ".attest/keys"
    keys.mkdir(mode=0o700)
    key = keys / f'{config["KEY_ID"]}.key'
    try:
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(config.pop("SIGNING_KEY"))
        subprocess.run([str(args.attest), "run", "--pipeline", "attest.yaml", "--sign",
                        "--timestamp", "--key", config["KEY_ID"], "--tsa", config["TSA_URL"]],
                       cwd=workspace, check=True, timeout=180)
    finally:
        key.unlink(missing_ok=True)
    receipts = list((workspace / ".attest/receipts").glob("*.yaml"))
    if len(receipts) != 1:
        raise ValueError("Expected one fresh delivery receipt")
    receipt = workspace / "receipt.yaml"
    shutil.copyfile(receipts[0], receipt)
    result = subprocess.run([str(args.attest), "verify", str(receipt), "--recompute",
                             "--workspace", str(workspace), "--trust-store", str(trust),
                             "--offline", "--format", "json"],
                            capture_output=True, text=True, check=True, timeout=120)
    report = json.loads(result.stdout)
    validate_verdict(report, config["PUBLIC_KEY"], receipt)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "attest-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    with tarfile.open(args.output / "hankoshell-operator-attest.tar.gz", "w:gz") as archive:
        for name in ("attest.yaml", "receipt.yaml", "delivery"):
            archive.add(workspace / name, arcname=name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--attest", type=Path)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--version")
    parser.add_argument("--image")
    parser.add_argument("--run-url")
    args = parser.parse_args()
    config = configuration()
    if args.check_config:
        return
    if any(value is None for name, value in vars(args).items() if name != "check_config"):
        parser.error("All delivery arguments are required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("Expected the full source revision")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.version):
        parser.error("Expected a release version")
    if not re.fullmatch(r"ghcr\.io/alien6-studio/hankoshell-operator@sha256:[0-9a-f]{64}", args.image):
        parser.error("Expected the exact operator image digest")
    if not re.fullmatch(r"https://github\.com/Alien6-Studio/hankoshell-operator/actions/runs/[1-9][0-9]*", args.run_url):
        parser.error("Expected the operator workflow run URL")
    args.attest = args.attest.resolve()
    sign_delivery(args, config)


if __name__ == "__main__":
    main()

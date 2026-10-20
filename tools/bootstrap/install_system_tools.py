"""Acquire the reviewed kind and kubectl fixtures with committed SHA-256 pins."""

import argparse
import hashlib
import platform
from pathlib import Path
import subprocess
from urllib.request import urlopen

import json

PINS = json.loads((Path(__file__).resolve().parents[2] / "versions.json").read_text())["tools"]
KIND = PINS["kind"]["version"]
KUBECTL = PINS["kubectl"]["version"]
KIND_HASHES = PINS["kind"]["sha256"]
KUBECTL_HASHES = PINS["kubectl"]["sha256"]


def acquire(url, digest, path):
    with urlopen(url, timeout=120) as response:
        data = response.read(128 * 1024**2 + 1)
    if len(data) > 128 * 1024**2 or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("System fixture download checksum mismatch")
    path.write_bytes(data)
    path.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    target = platform.system().lower() + "-" + {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), "unsupported")
    if target not in KIND_HASHES or target not in KUBECTL_HASHES:
        raise ValueError("Unqualified system-test host")
    args.output.mkdir(parents=True, exist_ok=True)
    acquire(f"https://github.com/kubernetes-sigs/kind/releases/download/{KIND}/kind-{target}", KIND_HASHES[target], args.output / "kind")
    system, arch = target.split("-")
    acquire(f"https://dl.k8s.io/release/{KUBECTL}/bin/{system}/{arch}/kubectl", KUBECTL_HASHES[target], args.output / "kubectl")
    if not subprocess.check_output([args.output / "kind", "version"], text=True).startswith("kind " + KIND + " "):
        raise ValueError("Unexpected kind version")
    version = json.loads(subprocess.check_output([args.output / "kubectl", "version", "--client", "-o", "json"], text=True))
    if version["clientVersion"]["gitVersion"] != KUBECTL:
        raise ValueError("Unexpected kubectl version")


if __name__ == "__main__":
    main()

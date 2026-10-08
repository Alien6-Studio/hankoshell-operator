"""Acquire the reviewed kind and kubectl fixtures with committed SHA-256 pins."""

import argparse
import hashlib
import platform
from pathlib import Path
import subprocess
from urllib.request import urlopen

KIND = "v0.33.0"
KUBECTL = "v1.37.0"
KIND_HASHES = {
    "linux-amd64": "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d",
    "darwin-arm64": "0c8c7dbe5e23594a198b786c4bc13dacc101fa6196b0cb0b23a1ca44e61f4b4f",
}
KUBECTL_HASHES = {
    "linux-amd64": "6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f",
    "darwin-arm64": "583beedaebe422e71d3f1a96acef8b1fef86ea2f09a45ad01aa6c9ce287c1380",
}


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
    import json
    version = json.loads(subprocess.check_output([args.output / "kubectl", "version", "--client", "-o", "json"], text=True))
    if version["clientVersion"]["gitVersion"] != KUBECTL:
        raise ValueError("Unexpected kubectl version")


if __name__ == "__main__":
    main()

"""Install reviewed binaries into one directory, verifying checksums and versions."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen

from tools import versions

LIMIT = 128 * 1024**2
BINARY_LIMIT = 512 * 1024**2
TOOLS = ("helm", "kind", "kubectl", "trivy", "gitleaks", "pre_commit", "attest")


def asset(name, target):
    pin = versions.get("tools", name)
    version = pin["version"]
    checksum = pin["sha256"] if name == "pre_commit" else pin["sha256"][target]
    system, arch = target.split("-")
    member = None
    executable = name
    if name == "helm":
        url = f"https://get.helm.sh/helm-v{version}-{target}.tar.gz"
        member = target + "/helm"
        command = ["version", "--template", "{{.Version}}"]
        expected = "v" + version
    elif name == "kind":
        url = f"https://github.com/kubernetes-sigs/kind/releases/download/{version}/kind-{target}"
        command, expected = ["version"], "kind " + version
    elif name == "kubectl":
        url = f"https://dl.k8s.io/release/{version}/bin/{system}/{arch}/kubectl"
        command, expected = ["version", "--client", "-o", "json"], version
    elif name == "trivy":
        flavor = {"linux-amd64": "Linux-64bit", "darwin-arm64": "macOS-ARM64"}[target]
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{flavor}.tar.gz"
        member = name
        command, expected = ["--version", "--format", "json"], version
    elif name == "attest":
        flavor = {"linux-amd64": "linux-x86_64", "darwin-arm64": "macos-aarch64"}[target]
        url = f"https://github.com/Alien6-Studio/continuum-attest/releases/download/v{version}/attest-v{version}-{flavor}.tar.gz"
        member = name
        command, expected = ["--version"], "attest " + version
    elif name == "gitleaks":
        flavor = {"linux-amd64": "linux_x64", "darwin-arm64": "darwin_arm64"}[target]
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{flavor}.tar.gz"
        member = name
        command, expected = ["version"], version
    else:
        url = f"https://github.com/pre-commit/pre-commit/releases/download/v{version}/pre-commit-{version}.pyz"
        executable = "pre-commit.pyz"
        command, expected = ["--version"], "pre-commit " + version
    return url, checksum, member, executable, command, expected


def payload(url, checksum, cache):
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ValueError("Malformed tool checksum")
    if cache.is_file() and cache.stat().st_size <= LIMIT:
        data = cache.read_bytes()
        if hashlib.sha256(data).hexdigest() == checksum:
            return data
    with urlopen(url, timeout=90) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("Tool checksum mismatch or size limit exceeded")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data


def install(name, destination, spec):
    url, checksum, member, executable, command, expected = spec
    data = payload(url, checksum, destination / ".downloads" / checksum)
    if member:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            matches = [entry for entry in archive.getmembers() if entry.name == member]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= BINARY_LIMIT:
                raise ValueError("Expected one bounded regular tool binary")
            data = archive.extractfile(matches[0]).read(BINARY_LIMIT + 1)
    # Verify before replacing an existing executable. Never extract archive paths.
    with tempfile.TemporaryDirectory(dir=destination) as staging:
        binary = Path(staging) / executable
        binary.write_bytes(data)
        binary.chmod(0o755)
        prefix = [sys.executable, str(binary)] if name == "pre_commit" else [str(binary)]
        actual = subprocess.check_output(prefix + command, text=True, timeout=30).strip()
        if name == "kubectl":
            actual = json.loads(actual)["clientVersion"]["gitVersion"]
        elif name == "trivy":
            actual = json.loads(actual)["Version"]
        elif name == "kind":
            actual = " ".join(actual.split()[:2])
        if actual != expected:
            raise ValueError("Unexpected installed version: " + name)
        binary.replace(destination / executable)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", nargs="+", choices=TOOLS)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), "unsupported")
    target = platform.system().lower() + "-" + arch
    # Resolve all supported assets before making requests or changing tools.
    assets = [(name, asset(name, target)) for name in dict.fromkeys(args.tools)]
    destination = args.directory.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name, spec in assets:
        install(name, destination, spec)


if __name__ == "__main__":
    main()

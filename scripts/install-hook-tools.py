"""Install checksum-pinned pre-commit and Gitleaks in the repository tool cache."""

import argparse
import hashlib
import io
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
from urllib.request import urlopen

import versions

LIMIT = 128 * 1024 * 1024


def payload(url, checksum, cache):
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ValueError("Malformed hook tool checksum")
    if cache.is_file() and cache.stat().st_size <= LIMIT:
        data = cache.read_bytes()
        if hashlib.sha256(data).hexdigest() == checksum:
            return data
    with urlopen(url, timeout=30) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("Hook tool checksum mismatch or size limit exceeded")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data


def install(destination, target):
    pre_commit = versions.get("tools", "pre_commit")
    gitleaks = versions.get("tools", "gitleaks")
    # Resolve supported assets before making any request or writing a tool.
    checksum = gitleaks["sha256"][target]
    archive_platform = {"linux-amd64": "linux_x64", "darwin-arm64": "darwin_arm64"}[target]
    destination.mkdir(parents=True, exist_ok=True)
    pre_commit_path = destination / "pre-commit.pyz"
    payload(f"https://github.com/pre-commit/pre-commit/releases/download/v{pre_commit['version']}/"
            f"pre-commit-{pre_commit['version']}.pyz", pre_commit["sha256"], pre_commit_path)
    archive = payload(f"https://github.com/gitleaks/gitleaks/releases/download/v{gitleaks['version']}/"
                      f"gitleaks_{gitleaks['version']}_{archive_platform}.tar.gz", checksum,
                      destination / ("gitleaks-" + target + ".tar.gz"))
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
        matches = [member for member in stream.getmembers() if member.name == "gitleaks"]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= LIMIT:
            raise ValueError("Expected one bounded regular Gitleaks binary")
        binary = stream.extractfile(matches[0]).read(LIMIT + 1)
    gitleaks_path = destination / "gitleaks"
    gitleaks_path.write_bytes(binary)
    gitleaks_path.chmod(0o755)
    for command, expected in (([sys.executable, str(pre_commit_path), "--version"], "pre-commit " + pre_commit["version"]),
                              ([str(gitleaks_path), "version"], gitleaks["version"])):
        if subprocess.check_output(command, text=True, timeout=30).strip() != expected:
            raise ValueError("Unexpected installed hook tool version")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), "unsupported")
    install(args.output.resolve(), platform.system().lower() + "-" + arch)


if __name__ == "__main__":
    main()

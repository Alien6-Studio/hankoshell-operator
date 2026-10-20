"""Acquire the reviewed Trivy release by archive SHA256 and verify its version."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "0.75.0"
ARCHIVES = {
    ("Linux", "x86_64"): ("Linux-64bit", "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"),
    ("Darwin", "arm64"): ("macOS-ARM64", "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568"),
}


def unpack(archive, expected, destination):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError("Trivy archive checksum mismatch")
    with tarfile.open(archive, "r:gz") as package:
        members = [member for member in package.getmembers() if member.name == "trivy"]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("Expected one regular Trivy executable")
        with package.extractfile(members[0]) as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)
    destination.chmod(0o755)


def check_version(executable):
    report = json.loads(subprocess.check_output([str(executable), "--version", "--format", "json"], text=True, timeout=30))
    if report.get("Version") != VERSION:
        raise ValueError("Expected Trivy " + VERSION)


def install(destination):
    flavor, checksum = ARCHIVES[(platform.system(), platform.machine())]
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_{flavor}.tar.gz"
    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory)
        archive = staging / "trivy.tar.gz"
        with urllib.request.urlopen(url, timeout=90) as response, archive.open("wb") as target:
            shutil.copyfileobj(response, target)
        executable = staging / "trivy"
        unpack(archive, checksum, executable)
        check_version(executable)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(executable, destination)
        destination.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    install(parser.parse_args().destination.resolve())

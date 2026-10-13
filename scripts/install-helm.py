"""Install only the reviewed Helm binary after verifying its archive checksum."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import tarfile
from urllib.request import urlopen

PINS = json.loads((Path(__file__).resolve().parents[1] / "versions.json").read_text())["tools"]["helm"]
LIMIT = 128 * 1024**2


def install(destination, target, pins=PINS):
    # Refuse unsupported hosts before making a network request.
    checksum = pins["sha256"][target]
    url = f"https://get.helm.sh/helm-v{pins['version']}-{target}.tar.gz"
    with urlopen(url, timeout=120) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("Helm archive checksum mismatch or size limit exceeded")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember(target + "/helm")
        if not member.isfile() or not 0 < member.size <= LIMIT:
            raise ValueError("Expected a bounded regular Helm binary")
        binary = archive.extractfile(member).read(LIMIT + 1)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(binary)
    destination.chmod(0o755)
    actual = subprocess.check_output([str(destination), "version", "--template", "{{.Version}}"], text=True, timeout=30)
    if actual != "v" + pins["version"]:
        raise ValueError("Unexpected Helm version")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), "unsupported")
    install(args.output, platform.system().lower() + "-" + arch)


if __name__ == "__main__":
    main()

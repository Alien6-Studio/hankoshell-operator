"""Resolve the reviewed standalone extension; never build a moving remote branch."""

import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import versions

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Alien6-Studio/keycloak-bounded-delegation"


def pin():
    value = json.loads((ROOT / "extensions/keycloak-bounded-delegation.json").read_text())
    if (not isinstance(value, dict) or set(value) != {"repository", "revision", "contract"} or value["repository"] != REPOSITORY
            or value["contract"] != "bounded-delegation/software-v1"
            or not isinstance(value["revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["revision"])):
        raise ValueError("Extension source requires the reviewed repository, profile and immutable commit")
    return value


def directory(value=None):
    value = pin() if value is None else value
    return ROOT / ".tools/keycloak-bounded-delegation" / value["revision"]


def artifact(version):
    if version not in versions.get("keycloak", "versions"):
        raise ValueError("Unreviewed Keycloak SDK")
    return directory() / "target" / version / ("bounded-delegation-keycloak-" + version + ".jar")


def verify_artifact(version, jar):
    expected = artifact(version)
    if jar.resolve() != expected.resolve() or not jar.is_file() or not 0 < jar.stat().st_size <= 5 * 1024 * 1024:
        raise ValueError("Build the exact version-matched standalone extension JAR before qualification")
    manifest = expected.parent / "build.json"
    if not manifest.is_file() or manifest.stat().st_size > 1024 * 1024:
        raise ValueError("Missing bounded extension build identity")
    built = json.loads(manifest.read_text())
    if (built.get("extension") != pin() or built.get("keycloak") != version
            or built.get("jar_sha256") != hashlib.sha256(jar.read_bytes()).hexdigest()):
        raise ValueError("Extension artifact differs from its reviewed source/SDK build identity")


def verify(path, value):
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=path, text=True, timeout=10).strip()

    if (path.is_symlink() or git("rev-parse", "HEAD") != value["revision"]
            or git("remote", "get-url", "origin") != "https://github.com/" + value["repository"] + ".git"
            or git("status", "--porcelain", "--untracked-files=all")):
        raise ValueError("Cached extension source is modified or differs from its reviewed pin")


def checkout():
    value = pin()
    path = directory(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Matrix builds share only a clean immutable checkout; SDK targets are separate.
    with (path.parent / "checkout.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists() or path.is_symlink():
            verify(path, value)
            return path
        with tempfile.TemporaryDirectory(prefix="fetch-", dir=path.parent) as temporary:
            candidate = Path(temporary) / "source"
            candidate.mkdir()
            for args in (("init", "--quiet"),
                         ("remote", "add", "origin", "https://github.com/" + value["repository"] + ".git"),
                         ("fetch", "--quiet", "--depth=1", "origin", value["revision"]),
                         ("checkout", "--quiet", "--detach", "FETCH_HEAD")):
                subprocess.run(["git", "--no-replace-objects", *args], cwd=candidate, timeout=120, check=True)
            verify(candidate, value)
            candidate.rename(path)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keycloak_version")
    print(artifact(parser.parse_args().keycloak_version))

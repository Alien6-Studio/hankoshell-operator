"""Preload the immutable Python fixture once; pods need no registry requests."""

import json
from pathlib import Path
import subprocess
import tempfile

DIGEST = "sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"
LOCAL_IMAGE = "hankoshell-python-fixture:sha256-" + DIGEST.split(":")[1]
SOURCES = tuple(repository + "@" + DIGEST for repository in (
    "mirror.gcr.io/library/python:3.12-alpine",
    "docker.io/library/python:3.12-alpine",
    "public.ecr.aws/docker/library/python:3.12-alpine",
))


def command(args):
    return subprocess.run([str(arg) for arg in args], capture_output=True, timeout=180)


def load(kind, cluster, execute=command):
    for source in SOURCES:
        try:
            pulled = execute(["docker", "pull", source])
        except subprocess.TimeoutExpired:
            continue
        if pulled.returncode:
            continue
        inspected = execute(["docker", "image", "inspect", source])
        if inspected.returncode:
            raise RuntimeError("Cannot inspect the downloaded Python fixture")
        images = json.loads(inspected.stdout)
        if (len(images) != 1 or not any(ref.endswith("@" + DIGEST) for ref in images[0].get("RepoDigests", []))
                or images[0].get("Os") != "linux" or images[0].get("Architecture") not in {"amd64", "arm64"}):
            raise ValueError("Python fixture does not match its pinned digest and platform")
        # Export only this node's platform: Docker's containerd store can retain
        # an index whose other platform blobs were never downloaded (kind#3795).
        with tempfile.TemporaryDirectory(prefix="hankoshell-python-image-") as temporary:
            archive = Path(temporary) / "python.tar"
            for args in (["docker", "tag", source, LOCAL_IMAGE],
                         ["docker", "image", "save", "--platform", "linux/" + images[0]["Architecture"],
                          "--output", archive, LOCAL_IMAGE],
                         [kind, "load", "image-archive", archive, "--name", cluster]):
                if execute(args).returncode:
                    raise RuntimeError("Cannot preload the verified Python fixture")
        return {"source": source, "digest": DIGEST, "image": LOCAL_IMAGE,
                "image_id": images[0]["Id"], "architecture": images[0]["Architecture"]}
    raise RuntimeError("All pinned Python fixture sources are unavailable")

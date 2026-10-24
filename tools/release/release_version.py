"""Parse normal public tags and reject production delivery until source is ready."""

import argparse
import re
import json
from pathlib import Path


_RELEASE = json.loads((Path(__file__).resolve().parents[2] / "versions.json").read_text())["release"]
VERSION = _RELEASE["version"]
RELEASE_STATUS = _RELEASE["status"]


NUMBER = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION_PATTERN = (
    rf"{NUMBER}\.{NUMBER}\.{NUMBER}"
    rf"(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SEMVER = re.compile(VERSION_PATTERN)
PUBLIC_TAG = re.compile(r"v(?P<version>" + VERSION_PATTERN + r")")


def from_tag(tag):
    match = PUBLIC_TAG.fullmatch(tag) if isinstance(tag, str) and len(tag) <= 256 else None
    if match is None:
        raise ValueError("Expected a public v<SemVer> tag")
    return match["version"]


def public_tag(version):
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ValueError("Expected a valid product SemVer version")
    tag = "v" + version
    from_tag(tag)
    return tag


def is_stable(version):
    return (isinstance(version, str) and SEMVER.fullmatch(version) is not None
            and "-" not in version and "+" not in version)


def require_production(version):
    # Readiness is a reviewed source decision, never an environment/CLI override.
    if (RELEASE_STATUS != "ready" or version != VERSION or "-" in version or "+" in version):
        raise ValueError("Production publication blocked: " + VERSION + " remains in development")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    args = parser.parse_args()
    try:
        print(from_tag(args.tag))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

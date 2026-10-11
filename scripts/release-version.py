"""Parse public release tags without accepting historical source checkpoints."""

import argparse
import re


NUMBER = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION_PATTERN = (
    rf"{NUMBER}\.{NUMBER}\.{NUMBER}"
    rf"(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SEMVER = re.compile(VERSION_PATTERN)
PUBLIC_TAG = re.compile(r"release/v(?P<version>" + VERSION_PATTERN + r")")


def from_tag(tag):
    match = PUBLIC_TAG.fullmatch(tag) if isinstance(tag, str) and len(tag) <= 256 else None
    if match is None:
        raise ValueError("Expected a public release/v<SemVer> tag")
    return match["version"]


def public_tag(version):
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ValueError("Expected a valid product SemVer version")
    tag = "release/v" + version
    from_tag(tag)
    return tag


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

"""Fail-closed GitHub identity and ancestry checks before release work."""

import json
import os
import re
import subprocess
from urllib.parse import quote


NUMBER = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(
    rf"v{NUMBER}\.{NUMBER}\.{NUMBER}"
    rf"(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(repository, tag, revision, ref, api, git, expected_tag_object=None):
    """Bind a protected release ref to the exact source qualified by CI.

    Callbacks allow adversarial tests without credentials or publication.
    GitHub must verify both the source signature and the annotated tag signature.
    Local Git checks bind the checkout and protected-main ancestry. Sigstore and
    Attest authenticate delivered artifacts separately. Re-read the ref to detect
    movement during eligibility.
    """
    require(isinstance(repository, str) and
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository identity")
    require(isinstance(tag, str) and len(tag) <= 256 and SEMVER.fullmatch(tag), "Invalid SemVer release tag")
    require(isinstance(revision, str) and SHA.fullmatch(revision), "Invalid release commit identity")
    require(ref == "refs/tags/" + tag, "Run the workflow from the reviewed tag itself")
    base = "repos/" + repository

    def document(path):
        value = api(path)
        require(isinstance(value, dict), "Malformed release identity API response")
        return value

    def verified(value, description):
        verification = value.get("verification")
        require(isinstance(verification, dict) and verification.get("verified") is True,
                description + " must be signed and GitHub Verified")

    require(document(base).get("private") is False, "Publication requires a public repository")
    require(document(base + "/private-vulnerability-reporting").get("enabled") is True,
            "Private vulnerability reporting must be enabled")
    commit = document(base + "/git/commits/" + revision)
    require(commit.get("sha") == revision, "GitHub returned a different release commit")
    verified(commit, "Release commit")
    path = base + "/git/ref/tags/" + quote(tag, safe="")
    tag_ref = document(path)
    require(tag_ref.get("ref") == ref, "GitHub returned a conflicting tag ref")
    obj = tag_ref.get("object", {})
    require(isinstance(obj, dict) and obj.get("type") == "tag" and
            isinstance(obj.get("sha"), str) and SHA.fullmatch(obj["sha"]),
            "Release ref must identify an annotated tag")
    if expected_tag_object is not None:
        require(obj["sha"] == expected_tag_object, "Release tag changed after eligibility")
    annotated = document(base + "/git/tags/" + obj["sha"])
    require(annotated.get("sha") == obj["sha"] and annotated.get("tag") == tag,
            "GitHub returned a conflicting tag object")
    verified(annotated, "Release tag")
    target = annotated.get("object", {})
    require(isinstance(target, dict) and target.get("type") == "commit" and target.get("sha") == revision,
            "Release tag must target the exact release commit")
    require(git("rev-parse", ref).strip() == obj["sha"],
            "Local tag object conflicts with the GitHub tag")
    require(git("rev-parse", ref + "^{commit}").strip() == revision,
            "Local tag conflicts with the GitHub tag")
    git("merge-base", "--is-ancestor", revision, "origin/main")
    current = document(path)
    require(current.get("ref") == ref and current.get("object", {}) == obj,
            "Release tag moved during verification")
    return {"revision": revision, "tag": tag, "tag_object": obj["sha"]}


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Release identity API or protected-main ancestry check failed")
    if len(result.stdout.encode("utf-8")) > 1 << 20:
        raise ValueError("Release identity response exceeds the size limit")
    return result.stdout


def main():
    try:
        result = verify(
            os.environ["GITHUB_REPOSITORY"], os.environ["TAG"],
            os.environ["GITHUB_SHA"], os.environ["REF"],
            lambda path: json.loads(command("gh", "api", path)),
            lambda *args: command("git", *args),
            os.environ.get("EXPECTED_TAG_OBJECT"),
        )
    except (KeyError, ValueError, TypeError) as error:
        raise SystemExit("Release eligibility rejected: " + str(error)) from None
    print("Verified release identity: " + json.dumps(result, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("tag_object=" + result["tag_object"] + "\n")


if __name__ == "__main__":
    main()

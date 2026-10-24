"""Fail-closed GitHub identity and ancestry checks before release work."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import quote
import zipfile

from tools.release import release_version as versioning

ROOT = Path(__file__).resolve().parents[2]


SHA = re.compile(r"[0-9a-f]{40}")
SOURCE_JOBS = {"kubernetes", "keycloak", "keycloak-ordinary", "keycloak-static", "workload",
               "security-fuzz", "security-mutations"}
DELIVERY_JOBS = {"source", "keycloak-extension", "oci", "rehearsal", "system", "installed-workload",
                 "installed-delegation", "installed-portable", "installed-fleet", "installed-transactions"}
QUALIFICATION_JOBS = SOURCE_JOBS | DELIVERY_JOBS | {"preflight", "installed-scale-qualification"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_jobs(results, mode, scale=False):
    """A skipped job is acceptable only in its explicitly declared profile."""
    require(mode in {"full", "integration", "release"}, "Unknown qualification profile")
    require(set(results) == QUALIFICATION_JOBS, "Qualification job inventory changed")
    required = {"preflight"}
    if mode == "full":
        required |= SOURCE_JOBS | DELIVERY_JOBS
    elif mode == "release":
        required |= DELIVERY_JOBS
    if scale:
        require(mode == "full", "Scale qualification requires the full profile")
        required.add("installed-scale-qualification")
    for name, result in results.items():
        expected = "success" if name in required else "skipped"
        require(result.get("result") == expected, f"{name}: expected {expected}")


def record_source(environment, event, git):
    check_jobs(json.loads(environment["CI_NEEDS"]), environment["PIPELINE_MODE"],
               environment["QUALIFY_SCALE"] == "true")
    require(environment["PIPELINE_MODE"] == "full", "Only a full qualification can certify source")
    revision = environment["GITHUB_SHA"]
    require(git("rev-parse", "HEAD").strip() == revision, "Qualified checkout differs from the event")
    return {"schema": 1, "repository": environment["GITHUB_REPOSITORY"],
            "revision": revision, "tree": git("rev-parse", "HEAD^{tree}").strip(),
            "event": environment["GITHUB_EVENT_NAME"], "ref": environment["GITHUB_REF"],
            "head_sha": event.get("pull_request", {}).get("head", {}).get("sha", revision),
            "pull_request": event.get("number") if environment["GITHUB_EVENT_NAME"] == "pull_request" else None,
            "run_id": int(environment["GITHUB_RUN_ID"]), "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"])}


def source_proof(repository, run, expected, api, download):
    base = f"repos/{repository}/actions/runs/{run['id']}"
    require(type(run["run_attempt"]) is int and 1 <= run["run_attempt"] <= 100, "Invalid CI attempt")
    for attempt in range(run["run_attempt"], 0, -1):
        name = f"qualified-source-{run['id']}-{attempt}"
        artifacts = api(base + f"/artifacts?name={name}&per_page=2")
        if artifacts.get("total_count") == 0:
            continue
        require(artifacts.get("total_count") == 1 and len(artifacts["artifacts"]) == 1,
                "Ambiguous qualification proof")
        artifact = artifacts["artifacts"][0]
        require(artifact.get("name") == name, "Unexpected qualification artifact")
        break
    else:
        return None
    if artifact.get("expired") is True:
        return None
    require(artifact.get("expired") is False and 0 < artifact.get("size_in_bytes", 0) <= 16384,
            "Qualification proof exceeds its size budget")
    require(artifact.get("workflow_run", {}).get("id") == run["id"] and
            artifact["workflow_run"].get("head_sha") == run["head_sha"], "Proof belongs to another run")
    raw = download(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == artifact.get("digest"),
            "Qualification artifact transport digest differs")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 1 and entries[0].filename == "qualified-source.json"
                and entries[0].file_size <= 8192, "Unexpected qualification proof archive")
        proof = json.loads(archive.read(entries[0]))
    require(proof.get("schema") == 1 and proof.get("repository") == repository and
            proof.get("run_id") == run["id"] and proof.get("run_attempt") == attempt and
            proof.get("event") == run["event"] and proof.get("head_sha") == run["head_sha"],
            "Qualification proof identity differs")
    require(proof.get("tree") == expected["tree"] and SHA.fullmatch(proof.get("revision", "")),
            "Qualified source differs from the integrated tree")
    tested = api(f"repos/{repository}/git/commits/{proof['revision']}")
    require(tested.get("sha") == proof["revision"] and tested.get("tree", {}).get("sha") == expected["tree"],
            "Actual tested Git tree differs from the integrated source")
    if run["event"] == "pull_request":
        number = expected["pull_request"]
        require(proof.get("pull_request") == number and proof.get("ref") == f"refs/pull/{number}/merge",
                "Qualification belongs to another pull request")
        require(proof["revision"] == run["head_sha"] or
                run["head_sha"] in {p["sha"] for p in tested.get("parents", [])},
                "Tested merge does not contain the reviewed PR head")
    else:
        require(proof["revision"] == expected["revision"] and proof.get("pull_request") is None,
                "Manual or scheduled qualification must test the exact integrated commit")
    return {"run_id": run["id"], "artifact_id": artifact["id"], "tree": expected["tree"],
            "qualified_revision": proof["revision"], "revision": expected["revision"]}


def verify_qualification(repository, revision, api, git, download):
    """Reuse complete CI evidence, never an image built before a squash merge."""
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) and SHA.fullmatch(revision),
            "Invalid qualification repository or revision")
    require(git("rev-parse", "HEAD").strip() == revision, "Integration checkout differs from the event")
    git("merge-base", "--is-ancestor", revision, "origin/main")
    tree = git("rev-parse", "HEAD^{tree}").strip()
    base = f"repos/{repository}"
    integrated = api(base + "/git/commits/" + revision)
    require(integrated.get("sha") == revision and integrated.get("tree", {}).get("sha") == tree and
            integrated.get("verification", {}).get("verified") is True, "Integrated source must be GitHub Verified")
    workflow = api(base + "/actions/workflows/ci.yml")
    require(workflow.get("path") == ".github/workflows/ci.yml", "Unexpected qualification workflow")
    pulls = api(base + "/commits/" + revision + "/pulls?per_page=100")
    require(isinstance(pulls, list) and len(pulls) < 100, "Pull request inventory truncated")
    merged = [p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") == revision
              and p.get("base", {}).get("ref") == "main" and
              p["base"].get("repo", {}).get("full_name") == repository]
    require(len(merged) <= 1, "Ambiguous integrated pull request")
    candidates = [(p["head"]["sha"], p["number"], {"pull_request"}) for p in merged]
    # A deliberate full rerun on the exact revision can renew expired evidence.
    candidates.append((revision, None, {"workflow_dispatch", "schedule"}))
    for head, number, events in candidates:
        runs = api(base + f"/actions/workflows/ci.yml/runs?head_sha={head}&status=success&per_page=20")
        for run in runs.get("workflow_runs", []):
            if not (run.get("head_sha") == head and run.get("event") in events and
                    run.get("status") == "completed" and run.get("conclusion") == "success" and
                    run.get("workflow_id") == workflow["id"] and run.get("path") == workflow["path"] and
                    run.get("repository", {}).get("full_name") == repository):
                continue
            proof = source_proof(repository, run, {"revision": revision, "tree": tree, "pull_request": number},
                                 api, download)
            if proof:
                return proof
    raise ValueError("No complete CI proof for this source; run full CI on the exact revision")


def verify(repository, tag, revision, ref, api, git, expected_tag_object=None):
    versioning.require_production(versioning.from_tag(tag))
    return verify_tag(repository, tag, revision, ref, api, git, expected_tag_object)


def verify_tag(repository, tag, revision, ref, api, git, expected_tag_object=None):
    """Bind a protected release ref to the exact source qualified by CI.

    Callbacks allow adversarial tests without credentials or publication.
    GitHub must verify both the source signature and the annotated tag signature.
    Local Git checks bind the checkout and protected-main ancestry. Sigstore and
    Attest authenticate delivered artifacts separately. Re-read the ref to detect
    movement during eligibility.
    """
    require(isinstance(repository, str) and
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository identity")
    versioning.from_tag(tag)
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


def command_bytes(*args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=90)
    if result.returncode:
        raise ValueError("Release identity API or protected-main ancestry check failed")
    if len(result.stdout) > 1 << 20:
        raise ValueError("Release identity response exceeds the size limit")
    return result.stdout


def command(*args):
    return command_bytes(*args).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--qualified-source", action="store_true")
    mode.add_argument("--check-jobs", action="store_true")
    mode.add_argument("--record-source", type=Path)
    args = parser.parse_args()
    try:
        if args.check_jobs:
            check_jobs(json.loads(os.environ["CI_NEEDS"]), os.environ["PIPELINE_MODE"],
                       os.environ["QUALIFY_SCALE"] == "true")
            print("Qualification profile passed: " + os.environ["PIPELINE_MODE"])
            return
        if args.record_source:
            proof = record_source(os.environ, json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
                                  lambda *args: command("git", *args))
            args.record_source.write_text(json.dumps(proof, sort_keys=True) + "\n")
            return
        if args.qualified_source:
            for attempt in range(3):
                try:
                    result = verify_qualification(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                        lambda path: json.loads(command("gh", "api", path)), lambda *args: command("git", *args),
                        lambda path: command_bytes("gh", "api", path))
                    break
                except ValueError as error:
                    # Allow brief GitHub metadata propagation after merge, never
                    # rerun tests or retry a conflicting source/artifact proof.
                    if attempt == 2 or not str(error).startswith("No complete CI proof"):
                        raise
                    time.sleep(2)
            print("Verified complete source qualification: " + json.dumps(result, sort_keys=True))
            return
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

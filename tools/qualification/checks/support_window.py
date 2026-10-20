"""Review qualification windows without silently promoting unqualified upstream releases.

Discovery and proposals are read-only. A draft PR is created only by an explicit
manual workflow input; it contains a review packet, never unreviewed fixture pins.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[3]

REPOSITORIES = {"kubernetes": "kubernetes/kubernetes", "keycloak": "keycloak/keycloak"}
POLICY = "docs/compatibility-policy.json"
MAX_CATALOG_BYTES = 2 * 1024 * 1024


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}", value):
        raise ValueError("Expected an exact released numeric version")
    return tuple(map(int, value.split(".")))


def policy(root=ROOT):
    data = json.loads((root / POLICY).read_text())
    if data["schema_version"] != 1 or data["state"] != "prepublication-proposal":
        raise ValueError("Public compatibility ratification requires a separate reviewed change")
    if data["review"] != {"state": "pending", "issue": 87, "started_at": None, "accepted_at": None}:
        raise ValueError("Do not fabricate community review or publication")
    q = data["qualification"]
    if (q["kubernetes_minors"] != 3 or q["keycloak_minors"] != 2 or q["patch_review_days"] != 14
            or q["patch_grace_days"] != 30 or q["upstream_eol_extends_support"] is not False
            or q["production_requires_upstream_support_review"] is not True):
        raise ValueError("Qualification window rules need an explicit policy review")
    if data["notice_rules"] != {"minimum_minor_releases": 2, "minimum_days": 90}:
        raise ValueError("Deprecation notice policy differs from the documented proposal")
    return data


def check(root=ROOT):
    rules = policy(root)
    pins = json.loads((root / "versions.json").read_text())
    for family in REPOSITORIES:
        values = [version(item) for item in pins[family]["versions"]]
        minors = sorted(set(item[:2] for item in values))
        expected = rules["qualification"][family + "_minors"]
        if (len(values) != expected or len(minors) != expected or len({v[0] for v in minors}) != 1
                or any(b[1] != a[1] + 1 for a, b in zip(minors, minors[1:]))
                or version(pins[family]["default"]) != max(values)):
            raise ValueError("Window must contain one exact patch for each consecutive minor: " + family)
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    if not ci[True].get("schedule") or "tools.qualification.reporting.schedule_report" not in yaml.safe_dump(ci["jobs"]["schedule-report"]):
        raise ValueError("Weekly qualification must retain its tracking issue")
    for job in ("kubernetes", "storage-migration", "keycloak", "workload", "installed-workload", "installed-portable", "installed-fleet", "installed-transactions"):
        matrix = ci["jobs"][job]["strategy"]["matrix"]
        families = ("kubernetes", "keycloak") if "kubernetes" in matrix else ("kubernetes" if job == "storage-migration" else job,)
        for family in families:
            key = family if "kubernetes" in matrix else "version"
            if set(matrix[key]) != set(pins[family]["versions"]):
                raise ValueError("Weekly matrix lost qualification coverage: " + job)
        if ci["jobs"][job]["strategy"].get("fail-fast") is not False:
            raise ValueError("Window qualification must exercise every matrix cell")
    for name in ("README.md", "SECURITY.md", "charts/hankoshell-operator/README.md", "CHANGELOG.md"):
        text = (root / name).read_text()
        if "compatibility-policy.md" not in text or "support-window.md" not in text:
            raise ValueError("Missing linked compatibility/support policy: " + name)
    return pins


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def gh(path, payload=None):
    args = ["gh", "api", path]
    if payload is not None:
        args += ["--method", "POST", "--input", "-"]
    result = subprocess.run(args, input=None if payload is None else canonical(payload), capture_output=True, timeout=60)
    if result.returncode or len(result.stdout) > MAX_CATALOG_BYTES:
        raise ValueError("GitHub request failed or exceeded its reviewed budget")
    return json.loads(result.stdout)


def discover():
    catalog = {}
    for family, repository in REPOSITORIES.items():
        # Drop release bodies/assets inside gh before retaining the bounded catalog.
        result = subprocess.run(["gh", "api", f"repos/{repository}/releases?per_page=100",
            "--jq", "[.[] | {tag_name,draft,prerelease,published_at}]"], capture_output=True, timeout=60)
        if result.returncode or len(result.stdout) > MAX_CATALOG_BYTES:
            raise ValueError("Official upstream release discovery failed")
        catalog[family] = json.loads(result.stdout)
    return catalog


def propose(catalog, pins, revision, today=None):
    today = today or datetime.now(timezone.utc)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Proposal needs its exact base revision")
    if set(catalog) != set(REPOSITORIES):
        raise ValueError("Both official upstream catalogs are required")
    changes, candidates = [], []
    for family, repository in REPOSITORIES.items():
        entries = catalog[family]
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Catalog is not a bounded release list")
        released = set()
        for item in entries:
            if item.get("draft") is not False or item.get("prerelease") is not False:
                continue
            tag = item.get("tag_name", "")
            if not re.fullmatch(r"v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}", tag):
                continue
            try:
                timestamp = datetime.fromisoformat(item["published_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError, KeyError):
                raise ValueError("Released version lacks a valid publication timestamp") from None
            if timestamp.tzinfo is None or timestamp > today:
                continue
            released.add(version(tag.removeprefix("v")))
        current = [version(value) for value in pins[family]["versions"]]
        for old in current:
            newer = [value for value in released if value[:2] == old[:2] and value > old]
            if newer:
                value = ".".join(map(str, max(newer)))
                changes.append({"family": family, "from": ".".join(map(str, old)), "to": value,
                                "upstream": "https://github.com/" + repository + "/releases"})
        newer_minors = sorted({value[:2] for value in released if value[:2] > max(current)[:2]})
        for minor in newer_minors:
            candidates.append({"family": family, "minor": ".".join(map(str, minor)), "requires_retirement_review": True})
    return {"schema_version": 1, "state": "review-required", "base_revision": revision,
            "pins_sha256": hashlib.sha256(canonical(pins)).hexdigest(), "observed_at": today.isoformat(),
            "changes": changes, "new_minor_candidates": candidates, "automatically_qualified": False,
            "required_review": ["upstream support/EOL", "security patch urgency", "immutable image and envtest/node checksums",
                                "python3 -m tools.versions sync and generated window docs", "deprecation/removal notice",
                                "full installed/security/rollback CI and retained provider evidence"]}


def create_draft(repository, packet):
    # This function is never called by discovery/schedule/default CLI execution.
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("HANKO_CREATE_SUPPORT_PR") != "true":
        raise ValueError("Draft PR creation requires the explicit manual workflow input")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected one GitHub repository")
    if not packet["changes"] and not packet["new_minor_candidates"]:
        return {"result": "no-updates"}
    default = gh(f"repos/{repository}")["default_branch"]
    base = gh(f"repos/{repository}/git/ref/heads/{quote(default, safe='')}")["object"]["sha"]
    if base != packet["base_revision"]:
        raise ValueError("Create support proposals only from the current default-branch revision")
    identity = hashlib.sha256(canonical({k: packet[k] for k in ("base_revision", "changes", "new_minor_candidates")})).hexdigest()[:16]
    branch = "automation/support-window-" + identity
    existing = gh(f"repos/{repository}/pulls?state=all&head={quote(repository.split('/')[0]+':'+branch, safe='')}")
    if existing:
        return {"result": "existing", "url": existing[0]["html_url"]}
    gh(f"repos/{repository}/git/refs", {"ref": "refs/heads/" + branch, "sha": base})
    mutation = """mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid signature{isValid}}}}"""
    commit = gh("graphql", {"query": mutation, "variables": {"input": {
        "branch": {"repositoryNameWithOwner": repository, "branchName": branch}, "expectedHeadOid": base,
        "message": {"headline": "chore(support): propose reviewed qualification updates",
                    "body": "Review packet only; no runtime or qualification pin is changed.\n\nSigned-off-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"},
        "fileChanges": {"additions": [{"path": "docs/support-proposals/" + identity + ".json",
                                       "contents": base64.b64encode(json.dumps(packet, indent=2).encode()+b"\n").decode()}]}}}})
    value = commit.get("data", {}).get("createCommitOnBranch", {}).get("commit", {})
    if not value.get("signature", {}).get("isValid"):
        raise ValueError("GitHub must verify the generated proposal commit before creating a PR")
    request = gh(f"repos/{repository}/pulls", {"head": branch, "base": default, "draft": True,
        "title": "Review Kubernetes/Keycloak qualification window updates",
        "body": "Generated review packet from official upstream release catalogs. No pin is promoted automatically. Supply reviewed immutable fixtures, edit versions.json, run tools.versions sync, update qualification evidence and migration notices, then pass every existing gate. No release or merge is authorized."})
    return {"result": "created", "url": request["html_url"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "propose"))
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--create-pull-request", action="store_true")
    parser.add_argument("--repository")
    args = parser.parse_args()
    pins = check()
    if args.command == "check":
        if args.create_pull_request:
            parser.error("check cannot create a pull request")
        return
    if not args.output or not args.revision:
        parser.error("propose requires --output and --revision")
    if args.catalog:
        if args.catalog.stat().st_size > MAX_CATALOG_BYTES:
            raise ValueError("Catalog exceeds its byte budget")
        catalog = json.loads(args.catalog.read_text())
    else:
        catalog = discover()
    packet = propose(catalog, pins, args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(packet, indent=2) + "\n")
    if args.create_pull_request:
        print(json.dumps(create_draft(args.repository or "", packet)))


if __name__ == "__main__":
    main()

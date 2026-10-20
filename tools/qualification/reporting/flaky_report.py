"""Read recent main CI artifacts; distinguish mixed outcomes on the exact same SHA.

Only bounded outcome JSON is consumed from the JUnit artifact bundles. Nothing is
extracted or executed, and this command never posts messages or changes test gates.
Missing historical reports are explicit gaps, not evidence of stable tests.
"""

import argparse
from collections import defaultdict
import html
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

from tools import versions

MAX_ARCHIVE = 32 * 1024 * 1024


def github(endpoint, binary=False):
    # GET-only. Never render gh stderr, which may contain remote payloads.
    result = subprocess.run(["gh", "api", "--hostname", "github.com", endpoint],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45, check=False)
    if result.returncode or len(result.stdout) > MAX_ARCHIVE:
        raise ValueError("GitHub report read failed or exceeded its budget")
    return result.stdout if binary else json.loads(result.stdout)


def artifact_suites():
    suites = {"unit": "unit", "authentik-2026.8.4": "authentik/2026.8.4"}
    for version in versions.get("kubernetes", "versions"):
        suites["kubernetes-" + version] = "kubernetes/" + version
    for version in versions.get("keycloak", "versions"):
        for shard in ("core", "adoption", "protocols", "ordinary"):
            suites[f"keycloak-{version}-{shard}"] = f"keycloak/{version}/{shard}"
    return suites


def read_artifact(data, suite, revision):
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Artifact exceeds archive budget")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [m for m in archive.infolist() if m.filename.endswith("/results.json") or m.filename == "results.json"]
        if len(members) != 1 or members[0].file_size > 16 * 1024 * 1024:
            raise ValueError("Missing, ambiguous or oversized outcome report")
        report = json.loads(archive.read(members[0]))
    if (type(report.get("schema")) is not int or report.get("schema") != 1 or report.get("suite") != suite or report.get("revision") != revision
            or report.get("worktree_dirty") is not False):
        raise ValueError("Outcome report is not bound to its run SHA and suite")
    tests = report.get("tests")
    if not isinstance(tests, list) or not tests or len(tests) > 50000 or type(report.get("returncode")) is not int:
        raise ValueError("Invalid test outcome report")
    seen = set()
    for test in tests:
        if not isinstance(test, dict):
            raise ValueError("Invalid test outcome")
        package, name, outcome = (test.get(field) for field in ("package", "name", "outcome"))
        if (not isinstance(package, str) or not package.startswith("github.com/Alien6-Studio/hankoshell-operator/")
                or len(package) > 512 or not isinstance(name, str) or not name or len(name) > 4096
                or outcome not in ("passed", "failed", "skipped") or (package, name) in seen):
            raise ValueError("Invalid or duplicate test identity/outcome")
        if report["returncode"] == 0 and outcome == "failed":
            raise ValueError("Successful report contains failed tests")
        seen.add((package, name))
    return report


def collect(repo, count, fetch=github):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not 1 <= count <= 100:
        raise ValueError("Invalid repository or run count")
    prefix = "repos/" + repo + "/actions/"
    result = fetch(prefix + f"workflows/ci.yml/runs?branch=main&status=completed&per_page={count}")
    runs = result["workflow_runs"]
    if len(runs) > count:
        raise ValueError("Run inventory exceeded the requested bound")
    records, gaps, seen_runs = [], [], set()
    for run in runs:
        run_id, attempt, revision = run["id"], run["run_attempt"], run["head_sha"]
        if (type(run_id) is not int or run_id <= 0 or run_id in seen_runs or type(attempt) is not int or attempt <= 0
                or run["head_branch"] != "main" or run["status"] != "completed" or not re.fullmatch(r"[0-9a-f]{40}", revision)):
            raise ValueError("Unexpected or duplicate main run identity")
        seen_runs.add(run_id)
        inventory = fetch(prefix + f"runs/{run_id}/artifacts?per_page=100")
        if inventory["total_count"] != len(inventory["artifacts"]) or inventory["total_count"] > 100:
            raise ValueError("Artifact inventory was truncated")
        by_name = defaultdict(list)
        for artifact in inventory["artifacts"]:
            by_name[artifact["name"]].append(artifact)
        for suffix, suite in artifact_suites().items():
            current_accounted = False
            pattern = re.compile(re.escape(f"go-tests-{suffix}-{run_id}-") + r"([1-9][0-9]*)$")
            for name, matches in by_name.items():
                match = pattern.fullmatch(name)
                if not match:
                    continue
                artifact_attempt = int(match[1])
                if len(matches) != 1 or artifact_attempt > attempt:
                    raise ValueError("Ambiguous artifact for this run attempt")
                artifact = matches[0]
                if artifact["expired"]:
                    gaps.append({"run": run_id, "attempt": artifact_attempt, "suite": suite, "reason": "expired"})
                    current_accounted = current_accounted or artifact_attempt == attempt
                    continue
                if type(artifact["id"]) is not int or artifact["id"] <= 0 or artifact["size_in_bytes"] > MAX_ARCHIVE:
                    raise ValueError("Invalid or oversized artifact")
                report = read_artifact(fetch(prefix + f"artifacts/{artifact['id']}/zip", binary=True), suite, revision)
                records.append({"run": run_id, "attempt": artifact_attempt, "report": report})
                current_accounted = current_accounted or artifact_attempt == attempt
            if not current_accounted:
                gaps.append({"run": run_id, "attempt": attempt, "suite": suite, "reason": "missing or expired"})
    return records, gaps, len(runs)


def aggregate(records):
    observations = defaultdict(lambda: {"passed": set(), "failed": set()})
    for record in records:
        report = record["report"]
        for test in report["tests"]:
            if test["outcome"] == "skipped":
                continue
            key = (report["revision"], report["suite"], test["package"], test["name"])
            observations[key][test["outcome"]].add(f"{record['run']}/attempts/{record['attempt']}")
    mixed = []
    for (revision, suite, package, name), values in sorted(observations.items()):
        if values["passed"] and values["failed"]:
            mixed.append({"revision": revision, "suite": suite, "package": package, "name": name,
                          "passed_runs": sorted(values["passed"]), "failed_runs": sorted(values["failed"])})
    return mixed


def summarize(repo, records, gaps, runs, requested):
    mixed = aggregate(records)
    lines = ["### Recent main Go test outcomes", "",
             f"Completed runs examined: {runs}/{requested}; suite reports: {len(records)}; missing reports: {len(gaps)}.", "",
             "Mixed outcomes are compared only at the exact same commit and suite/version. "
             "Missing reports, skipped tests and changed commits do not establish stability.", ""]
    if not mixed:
        lines.append("No mixed pass/fail outcome found in the available comparable reports.")
    for item in mixed[:100]:
        identity = html.escape(item["suite"] + " / " + item["package"] + " / " + item["name"]).replace("\n", " ").replace("\r", " ")
        runs_text = ", ".join(f"[failed attempt {run}](https://github.com/{repo}/actions/runs/{run})" for run in item["failed_runs"])
        lines.append(f"- <code>{identity}</code> at `{item['revision'][:12]}`: {runs_text}")
    if len(mixed) > 100:
        lines.append(f"Additional mixed outcomes in the JSON artifact: {len(mixed) - 100}.")
    report = {"schema": 1, "requested_runs": requested, "examined_runs": runs, "reports": len(records),
              "gaps": gaps, "mixed_outcomes": mixed}
    return report, "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "Alien6-Studio/hankoshell-operator"))
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        records, gaps, count = collect(args.repo, args.runs)
        report, summary = summarize(args.repo, records, gaps, count, args.runs)
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "flaky.json").write_text(json.dumps(report, indent=2) + "\n")
        (args.output / "summary.md").write_text(summary)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(summary)
        print(summary)
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError):
        print("Cannot verify recent test reports; no stability claim is available.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

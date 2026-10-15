"""List tests that both passed and failed across recent qualification runs.

Bounded JUnit outcome reports from completed runs of the reviewed workflow are
aggregated; a test is flaky when the same identity carries both outcomes inside
the window. The GitHub token stays in the environment and never reaches a
command line. The optional tracking issue carries test identities, run URLs and
counts only. No failed test is retried or quarantined.
"""

import argparse
import html
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

spec = importlib.util.spec_from_file_location("schedule_report", Path(__file__).with_name("schedule-report.py"))
schedule_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(schedule_report)

TITLE = "Flaky qualification tests on main"
LABEL = "ci"
MAX_RUNS = 50
MAX_ARTIFACTS = 64
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_LISTED_TESTS = 50


def github_archive(endpoint):
    # Artifact archives are binary; the response stays bounded below.
    result = subprocess.run(["gh", "api", "--hostname", "github.com", endpoint],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300, check=False)
    if result.returncode or len(result.stdout) > MAX_ARCHIVE:
        raise ValueError("Artifact download failed or exceeded its budget")
    return result.stdout


def recent_runs(repo, branch, count, fetch):
    page = fetch(f"repos/{repo}/actions/workflows/ci.yml/runs?branch={branch}"
                 f"&status=completed&exclude_pull_requests=true&per_page={count}")
    runs = page.get("workflow_runs") if isinstance(page, dict) else None
    if not isinstance(runs, list) or len(runs) > count:
        raise ValueError("Run inventory is invalid")
    selected = []
    for run in runs:
        if (not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] <= 0
                or not isinstance(run.get("head_sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", run["head_sha"])):
            raise ValueError("Run identity is invalid")
        selected.append((run["id"], run["head_sha"]))
    return selected


def outcome_reports(repo, run_id, revision, fetch, archive=None):
    """Yield validated per-test outcomes from one run's Go test artifacts."""
    archive = archive or github_archive
    page = fetch(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page={MAX_ARTIFACTS}")
    artifacts = page.get("artifacts") if isinstance(page, dict) else None
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise ValueError("Artifact inventory is invalid")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or type(artifact.get("id")) is not int:
            raise ValueError("Artifact identity is invalid")
        if not str(artifact.get("name", "")).startswith("go-tests-") or artifact.get("expired"):
            continue
        with zipfile.ZipFile(io.BytesIO(archive(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip"))) as bundle:
            for info in bundle.infolist():
                if Path(info.filename).name != "results.json":
                    continue
                if info.file_size > MAX_REPORT:
                    raise ValueError("Outcome report exceeds its budget")
                report = json.loads(bundle.read(info).decode("utf-8"))
                if (report.get("schema") != 1 or not isinstance(report.get("suite"), str)
                        or report.get("revision") != revision or not isinstance(report.get("tests"), list)
                        or len(report["tests"]) > 50000):
                    raise ValueError("Outcome report is not bound to its run")
                for test in report["tests"]:
                    if (not isinstance(test, dict) or test.get("outcome") not in ("passed", "failed", "skipped")
                            or not isinstance(test.get("package"), str) or len(test["package"]) > 512
                            or not isinstance(test.get("name"), str) or not test["name"] or len(test["name"]) > 4096):
                        raise ValueError("Invalid test outcome")
                    yield report["suite"], test["package"], test["name"], test["outcome"], run_id


def flaky_tests(repo, branch, count, fetch):
    """Identities that both passed and failed inside the inspected window."""
    outcomes = {}
    runs = recent_runs(repo, branch, count, fetch)
    for run_id, revision in runs:
        for suite, package, name, outcome, seen_run in outcome_reports(repo, run_id, revision, fetch):
            record = outcomes.setdefault((suite, package, name), {"passed": set(), "failed": set()})
            if outcome in record:
                record[outcome].add(seen_run)
    flaky = {identity: record for identity, record in sorted(outcomes.items())
             if record["passed"] and record["failed"]}
    return flaky, len(runs)


def render(repo, flaky, inspected):
    lines = [f"Flaky-test window: the last {inspected} completed qualification runs.", ""]
    if not flaky:
        lines.append("No test both passed and failed inside the window.")
        return "\n".join(lines) + "\n"
    lines.append("Tests that both passed and failed on the same commit range:")
    for (suite, package, name), record in list(flaky.items())[:MAX_LISTED_TESTS]:
        identity = html.escape(f"{suite} / {package} / {name}").replace("\n", " ").replace("\r", " ")
        failed = sorted(record["failed"])[-1]
        lines.append(f"- <code>{identity}</code>: failed {len(record['failed'])}x, passed {len(record['passed'])}x; "
                     f"last failed run https://github.com/{repo}/actions/runs/{failed}")
    if len(flaky) > MAX_LISTED_TESTS:
        lines.append(f"Additional flaky tests not listed: {len(flaky) - MAX_LISTED_TESTS}.")
    return "\n".join(lines) + "\n"


def reconcile(repo, text, flaky, fetch):
    existing = schedule_report.tracking_issue(repo, fetch, title=TITLE)
    if not flaky:
        if existing is None:
            return "clean"
        fetch(f"repos/{repo}/issues/{existing}/comments", method="POST",
              payload={"body": "The window no longer contains flaky tests; closing.\n\n" + text})
        fetch(f"repos/{repo}/issues/{existing}", method="PATCH", payload={"state": "closed"})
        return "closed"
    if existing is None:
        fetch(f"repos/{repo}/issues", method="POST",
              payload={"title": TITLE, "body": text, "labels": [LABEL]})
        return "opened"
    fetch(f"repos/{repo}/issues/{existing}/comments", method="POST", payload={"body": text})
    return "updated"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--post", action="store_true",
                        help="maintain the tracking issue instead of only reporting")
    args = parser.parse_args()
    try:
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository)
                or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", args.branch) or not 1 <= args.runs <= MAX_RUNS):
            raise ValueError("Invalid repository, branch or window")
        flaky, inspected = flaky_tests(args.repository, args.branch, args.runs, schedule_report.github)
        text = render(args.repository, flaky, inspected)
        print(text, end="")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write("### Flaky tests\n\n" + text)
        if args.post:
            print("Flaky tracking issue outcome: "
                  + reconcile(args.repository, text, flaky, schedule_report.github))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            zipfile.BadZipFile, json.JSONDecodeError):
        print("Cannot aggregate the flaky-test window.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Open, update or close the tracking issue for the scheduled qualification run.

Only bounded job results from this run and its local outcome reports are read.
The GitHub token stays in the environment and never reaches a command line.
Issue content carries job names, the run URL, the commit and failing test names
only. A green scheduled run closes the issue; no test gate changes.
"""

import argparse
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys

TITLE = "Scheduled qualification failed on main"
LABEL = "ci"
MAX_RESPONSE = 4 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_LISTED_TESTS = 50
RESULTS = ("success", "failure", "cancelled", "skipped")


def github(endpoint, payload=None, method=None):
    # The gh client reads GH_TOKEN from the environment; stderr may carry
    # remote payloads and is never rendered.
    command = ["gh", "api", "--hostname", "github.com", endpoint]
    if method:
        command += ["--method", method]
    stdin = None
    if payload is not None:
        command += ["--input", "-"]
        stdin = json.dumps(payload)
    result = subprocess.run(command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=45, check=False)
    if result.returncode or len(result.stdout) > MAX_RESPONSE:
        raise ValueError("GitHub issue access failed or exceeded its budget")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def job_results(raw):
    needs = json.loads(raw)
    if not isinstance(needs, dict) or not needs or len(needs) > 32 or "checks" not in needs:
        raise ValueError("Invalid qualification results")
    results = {}
    for name, value in needs.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z-]{0,63}", name)
                or not isinstance(value, dict) or value.get("result") not in RESULTS):
            raise ValueError("Invalid qualification results")
        results[name] = value["result"]
    return results


def failed_tests(reports, revision):
    failures = set()
    for path in sorted(reports.glob("**/results.json")) if reports.is_dir() else []:
        if path.stat().st_size > MAX_REPORT:
            raise ValueError("Outcome report exceeds its budget")
        report = json.loads(path.read_text())
        if (report.get("schema") != 1 or not isinstance(report.get("suite"), str)
                or report.get("revision") != revision or not isinstance(report.get("tests"), list)
                or len(report["tests"]) > 50000):
            raise ValueError("Outcome report is not bound to this run and revision")
        for test in report["tests"]:
            if not isinstance(test, dict) or test.get("outcome") not in ("passed", "failed", "skipped"):
                raise ValueError("Invalid test outcome")
            if test["outcome"] != "failed":
                continue
            package, name = test.get("package"), test.get("name")
            if (not isinstance(package, str) or len(package) > 512
                    or not isinstance(name, str) or not name or len(name) > 4096):
                raise ValueError("Invalid test identity")
            failures.add(report["suite"] + " / " + package + " / " + name)
    return sorted(failures)


def tracking_issue(repo, fetch):
    issues = fetch(f"repos/{repo}/issues?state=open&labels={LABEL}&per_page=100")
    # A full page cannot prove the matching issue was seen.
    if not isinstance(issues, list) or len(issues) >= 100:
        raise ValueError("Issue inventory was truncated or invalid")
    numbers = sorted(issue["number"] for issue in issues
                     if isinstance(issue, dict) and issue.get("title") == TITLE
                     and "pull_request" not in issue
                     and type(issue.get("number")) is int and issue["number"] > 0)
    return numbers[0] if numbers else None


def body(repo, run_id, revision, results, failures):
    lines = [f"Scheduled qualification run: https://github.com/{repo}/actions/runs/{run_id}",
             f"Commit: {revision}", "", "Job results:"]
    for name in sorted(results):
        lines.append(f"- `{name}`: {results[name]}")
    if failures:
        lines += ["", "Failing tests:"]
        for failure in failures[:MAX_LISTED_TESTS]:
            identity = html.escape(failure).replace("\n", " ").replace("\r", " ")
            lines.append(f"- <code>{identity}</code>")
        if len(failures) > MAX_LISTED_TESTS:
            lines.append(f"Additional failing tests not listed: {len(failures) - MAX_LISTED_TESTS}.")
    return "\n".join(lines) + "\n"


def reconcile(repo, run_id, revision, results, failures, fetch=github):
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or not re.fullmatch(r"[1-9][0-9]{0,18}", run_id) or not re.fullmatch(r"[0-9a-f]{40}", revision)):
        raise ValueError("Invalid repository, run or revision identity")
    existing = tracking_issue(repo, fetch)
    text = body(repo, run_id, revision, results, failures)
    if results["checks"] == "success":
        if existing is None:
            return "green"
        fetch(f"repos/{repo}/issues/{existing}/comments", method="POST",
              payload={"body": "The scheduled qualification is green again; closing.\n\n" + text})
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
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    try:
        results = job_results(os.environ["QUALIFICATION_RESULTS"])
        failures = failed_tests(args.reports, args.revision)
        outcome = reconcile(args.repository, args.run_id, args.revision, results, failures)
        print("Scheduled qualification tracking issue outcome: " + outcome)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Cannot maintain the scheduled qualification tracking issue.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

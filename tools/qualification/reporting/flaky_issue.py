"""Open, update or close the tracking issue for flaky Go tests on main.

Only the bounded JSON report written by tools.qualification.reporting.flaky_report in this run is read.
The GitHub token stays in the environment and never reaches a command line.
An empty mixed-outcome inventory closes the issue; evidence gaps stay visible
in the issue text and never count as stability. No test gate changes.
"""

import argparse
import html
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


spec = importlib.util.spec_from_file_location("schedule_report", ROOT / 'tools/qualification/reporting/schedule_report.py')
schedule_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(schedule_report)

TITLE = "Flaky Go tests on main"
MAX_REPORT = 16 * 1024 * 1024
MAX_LISTED = 50


def load_report(directory):
    path = directory / "flaky.json"
    if path.stat().st_size > MAX_REPORT:
        raise ValueError("Flaky report exceeds its budget")
    report = json.loads(path.read_text())
    if (not isinstance(report, dict) or report.get("schema") != 1
            or type(report.get("requested_runs")) is not int or type(report.get("examined_runs")) is not int
            or not isinstance(report.get("gaps"), list) or not isinstance(report.get("mixed_outcomes"), list)
            or len(report["mixed_outcomes"]) > 50000):
        raise ValueError("Invalid flaky report")
    for item in report["mixed_outcomes"]:
        if not isinstance(item, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("revision"))):
            raise ValueError("Invalid mixed outcome")
        suite, package, name = (item.get(field) for field in ("suite", "package", "name"))
        failed = item.get("failed_runs")
        if (not isinstance(suite, str) or not suite or len(suite) > 128
                or not isinstance(package, str) or not package or len(package) > 512
                or not isinstance(name, str) or not name or len(name) > 4096
                or not isinstance(failed, list) or not failed or len(failed) > 1000
                or not all(isinstance(run, str) and re.fullmatch(r"[1-9][0-9]{0,18}/attempts/[1-9][0-9]{0,8}", run)
                           for run in failed)):
            raise ValueError("Invalid mixed outcome")
    return report


def body(repo, run_id, report):
    mixed = report["mixed_outcomes"]
    lines = [f"Weekly history run: https://github.com/{repo}/actions/runs/{run_id}",
             f"Completed runs examined: {report['examined_runs']}/{report['requested_runs']}; "
             f"missing suite reports: {len(report['gaps'])}.", "",
             "Mixed outcomes are compared only at the exact same commit and suite/version. "
             "Missing reports do not establish stability.", ""]
    if not mixed:
        lines.append("No test both passed and failed inside the available comparable reports.")
    for item in mixed[:MAX_LISTED]:
        identity = html.escape(item["suite"] + " / " + item["package"] + " / " + item["name"])
        identity = identity.replace("\n", " ").replace("\r", " ")
        runs = ", ".join(f"https://github.com/{repo}/actions/runs/{run}" for run in item["failed_runs"][:5])
        lines.append(f"- <code>{identity}</code> at `{item['revision'][:12]}`: failed in {runs}")
    if len(mixed) > MAX_LISTED:
        lines.append(f"Additional mixed outcomes not listed: {len(mixed) - MAX_LISTED}.")
    return "\n".join(lines) + "\n"


def reconcile(repo, run_id, report, fetch=schedule_report.github):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[1-9][0-9]{0,18}", run_id):
        raise ValueError("Invalid repository or run identity")
    existing = schedule_report.tracking_issue(repo, fetch, title=TITLE)
    text = body(repo, run_id, report)
    if not report["mixed_outcomes"]:
        if existing is None:
            return "clean"
        fetch(f"repos/{repo}/issues/{existing}/comments", method="POST",
              payload={"body": "The latest weekly window shows no mixed outcome; closing.\n\n" + text})
        fetch(f"repos/{repo}/issues/{existing}", method="PATCH", payload={"state": "closed"})
        return "closed"
    if existing is None:
        fetch(f"repos/{repo}/issues", method="POST",
              payload={"title": TITLE, "body": text, "labels": [schedule_report.LABEL]})
        return "opened"
    fetch(f"repos/{repo}/issues/{existing}/comments", method="POST", payload={"body": text})
    return "updated"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = load_report(args.report)
        outcome = reconcile(args.repository, args.run_id, report)
        print("Flaky-test tracking issue outcome: " + outcome)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Cannot maintain the flaky-test tracking issue.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Record consecutive single attempts of the two #110 tests; stop on first failure.

Each attempt creates its normal disposable HTTPS Keycloak fixture and keeps its
own JUnit/report. This is qualification, never a failed-test retry or a CI gate
replacement. The aggregate binds every outcome to one clean revision.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from tools.qualification.runners import go_tests as runner

ROOT = Path(__file__).resolve().parents[3]


def identity():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=runner.ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=runner.ROOT, text=True).strip())
    if dirty or not runner.re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Stability qualification requires a clean exact revision")
    return revision


def qualify(root, count, gotestsum, output):
    if root not in runner.STABILITY_ROOTS or not 20 <= count <= 100:
        raise ValueError("A reviewed test and between 20 and 100 consecutive attempts are required")
    version = os.environ.get("KEYCLOAK_VERSION")
    if version != "26.7.5":
        raise ValueError("#110 stability evidence requires Keycloak 26.7.5")
    revision = identity()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "revision": revision, "worktree_dirty": False, "keycloak": version,
              "root": root, "requested_attempts": count, "complete": False, "attempts": []}
    destination = output / "stability.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    for index in range(1, count + 1):
        if identity() != revision:
            raise ValueError("Revision changed during stability qualification")
        attempt = output / f"attempt-{index:02d}"
        code = runner.run("keycloak", gotestsum, attempt, root=root)
        outcome = json.loads((attempt / "results.json").read_text())
        valid = (code == 0 and outcome["returncode"] == 0 and outcome["revision"] == revision
                 and outcome["worktree_dirty"] is False and outcome["counts"]["failed"] == 0
                 and outcome["counts"]["skipped"] == 0 and outcome["suite_errors"] == 0
                 and any(t["name"] == root and t["outcome"] == "passed" for t in outcome["tests"]))
        report["attempts"].append({"attempt": index, "passed": valid, "report": f"attempt-{index:02d}/results.json",
                                   "junit": f"attempt-{index:02d}/junit.xml", "counts": outcome["counts"]})
        report["complete"] = valid and index == count and identity() == revision
        destination.write_text(json.dumps(report, indent=2) + "\n")
        if not valid:
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, choices=runner.STABILITY_ROOTS)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--gotestsum", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        return qualify(args.root, args.count, args.gotestsum, args.output.resolve())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Stability qualification incomplete; no consecutive-success claim is available.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

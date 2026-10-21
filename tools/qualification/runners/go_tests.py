"""Run the existing Go gates once, preserving JUnit and bounded outcome summaries.

Keycloak shards partition the complete compiled test inventory, including the
ordinary tests previously run with that tag. New tagged-only roots must be assigned
explicitly; ordinary roots have their own required tagged job for both versions.
No failed test is retried or quarantined.
"""

import argparse
import html
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from tools import versions
from tools.qualification.lib import keycloak_extension_source as extension

ROOT = Path(__file__).resolve().parents[3]

ROOT_NAME = re.compile(r"(?:Test|Example|Fuzz)[A-Za-z0-9_]+")
SHARDS = ("core", "adoption", "protocols")
STABILITY_ROOTS = ("TestRealKeycloakAdoptionCharacterization", "TestRealKeycloakApplicationProtocolsAndFlows")
EXTENSION_ROOTS = ("TestRealKeycloakBoundedDelegationExtension",)


def test_inventory(tagged, extension=False):
    command = ["go", "test", "-list", "."]
    if tagged:
        command += ["-tags=keycloak_integration,keycloak_extension_integration" if extension else "-tags=keycloak_integration"]
    output = subprocess.check_output(command + ["./internal/controller"], cwd=ROOT, text=True, timeout=180)
    names = [line for line in output.splitlines() if ROOT_NAME.fullmatch(line)]
    if not names or len(names) != len(set(names)):
        raise ValueError("Missing or duplicate compiled Go test roots")
    return set(names)


def partition(tagged, ordinary, manifest):
    if set(manifest) != set(SHARDS) or not ordinary or not ordinary <= tagged:
        raise ValueError("Invalid shard groups or compiled test inventories")
    assigned = []
    for names in manifest.values():
        if not isinstance(names, list) or not names or any(not isinstance(n, str) or not ROOT_NAME.fullmatch(n) for n in names):
            raise ValueError("Invalid shard test names")
        assigned += names
    if len(assigned) != len(set(assigned)):
        raise ValueError("A tagged test is assigned to multiple shards")
    if set(assigned) != tagged - ordinary:
        missing = sorted(tagged - ordinary - set(assigned))
        obsolete = sorted(set(assigned) - (tagged - ordinary))
        raise ValueError(f"Keycloak shard inventory drift: unassigned={missing}, obsolete={obsolete}")
    result = {name: set(manifest[name]) for name in SHARDS}
    result["ordinary"] = ordinary
    return result


def keycloak_selection(shard):
    groups = partition(test_inventory(True), test_inventory(False),
                       json.loads((ROOT / "tools/qualification/config/keycloak-shards.json").read_text()))
    selected = set.union(*groups.values()) if shard == "all" else groups[shard]
    return sorted(selected)


def extension_selection():
    if test_inventory(True, True) - test_inventory(True) != set(EXTENSION_ROOTS):
        raise ValueError("Keycloak extension test inventory drift")
    return list(EXTENSION_ROOTS)


def parse_junit(path):
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("JUnit exceeds the report budget")
    data = path.read_bytes().decode("utf-8")
    if "\x00" in data or "<!DOCTYPE" in data.upper() or "<!ENTITY" in data.upper():
        raise ValueError("JUnit declarations are not supported")
    root = ET.fromstring(data)
    if root.tag != "testsuites" or not list(root):
        raise ValueError("Missing JUnit test suites")
    root_errors = int(root.get("errors", "0"))
    cases, seen, suite_errors = [], set(), 0
    for suite in root:
        if suite.tag != "testsuite":
            raise ValueError("Invalid JUnit suite")
        suite_errors += int(suite.get("errors", "0"))
        for case in suite.findall("testcase"):
            name, package = case.get("name", ""), case.get("classname", "")
            # gotestsum represents a package build failure as TestMain with
            # an empty classname; the containing suite supplies its identity.
            if not package and name == "TestMain" and case.find("failure") is not None:
                package = suite.get("name", "")
            identity = (package, name)
            if not name or not package or identity in seen or len(name) > 4096 or len(package) > 512:
                raise ValueError("Missing, duplicate or oversized JUnit test identity")
            seen.add(identity)
            elapsed = float(case.get("time", "0"))
            if not math.isfinite(elapsed) or elapsed < 0:
                raise ValueError("Invalid JUnit duration")
            outcome = "passed"
            if case.find("failure") is not None or case.find("error") is not None:
                outcome = "failed"
            elif case.find("skipped") is not None:
                outcome = "skipped"
            cases.append({"package": package, "name": name, "outcome": outcome, "seconds": elapsed})
            if len(cases) > 50000:
                raise ValueError("JUnit exceeds the test count budget")
    if root_errors < 0 or suite_errors < 0:
        raise ValueError("Invalid JUnit error count")
    suite_errors = max(suite_errors, root_errors)
    if not cases and not suite_errors:
        raise ValueError("JUnit contains no test outcomes")
    return cases, suite_errors


def checkout_identity():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid checkout revision")
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, timeout=10).strip())
    return revision, dirty


def write_summary(output, label, returncode, selected=None, source=None, require_all_pass=False):
    cases, suite_errors = parse_junit(output / "junit.xml")
    if selected is not None and returncode == 0:
        roots = {c["name"].split("/", 1)[0] for c in cases}
        if roots != set(selected):
            raise ValueError("Successful shard did not report every selected test root")
    failures = [c for c in cases if c["outcome"] == "failed"]
    if returncode == 0 and (failures or suite_errors):
        raise ValueError("Go exit status contradicts JUnit failures")
    counts = {value: sum(c["outcome"] == value for c in cases) for value in ("passed", "failed", "skipped")}
    if require_all_pass and returncode == 0 and counts["skipped"]:
        returncode = 1
    current_revision, current_dirty = checkout_identity()
    revision, initially_dirty = source or (current_revision, current_dirty)
    changed = current_revision != revision or not initially_dirty and current_dirty
    dirty = initially_dirty or current_dirty or changed
    returncode = returncode or int(changed)
    report = {"schema": 1, "suite": label, "revision": revision, "returncode": returncode,
              "worktree_dirty": dirty, "source_changed": changed, "suite_errors": suite_errors, "counts": counts, "tests": cases}
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [f"### Go tests: {html.escape(label)}", "",
             f"Exit code: {returncode}. Passed: {counts['passed']}; failed: {counts['failed']}; "
             f"skipped: {counts['skipped']}; package errors: {suite_errors}.", ""]
    lines += [f"Revision: `{revision}`; checkout: {'modified' if dirty else 'clean'}.", ""]
    if changed:
        lines += ["Checkout changed during execution; this is not qualification of the ending revision.", ""]
    for case in failures[:100]:
        identity = html.escape(case["package"] + " / " + case["name"]).replace("\n", " ").replace("\r", " ")
        lines.append(f"- <code>{identity}</code>")
    if len(failures) > 100:
        lines.append(f"- {len(failures) - 100} additional failures in the JUnit artifact.")
    summary = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(summary)
    return changed


def run(suite, gotestsum, output, shard="all", root=None):
    if root is not None and (suite != "keycloak" or root not in STABILITY_ROOTS or shard != "all"):
        raise ValueError("Only reviewed Keycloak stability roots can be selected individually")
    output.mkdir(parents=True, exist_ok=True)
    # Never publish stale success from an earlier local invocation.
    for name in ("junit.xml", "results.json", "summary.md", "coverage.out", "coverage-functions.txt", "coverage-summary.md", "coverage.json"):
        (output / name).unlink(missing_ok=True)
    actual = subprocess.check_output([gotestsum, "--version"], text=True, timeout=10).strip()
    if actual != "gotestsum version " + versions.get("tools", "gotestsum"):
        raise ValueError("gotestsum does not match its reviewed version pin")
    source = checkout_identity()
    selected = None
    args = ["-race", "-count=1"]
    if suite in ("unit", "kubernetes"):
        args += ["-covermode=atomic", "-coverprofile=" + str((output / "coverage.out").resolve())]
    label = suite
    if suite == "unit":
        args += ["./..."]
    elif suite == "kubernetes":
        version = os.environ["KUBERNETES_VERSION"]
        if version not in versions.get("kubernetes", "versions") or not os.environ.get("KUBEBUILDER_ASSETS"):
            raise ValueError("Kubernetes tests require reviewed envtest assets and version")
        label += "/" + version
        args += ["-tags=integration", "-timeout=5m", "./api/v1alpha1"]
    else:
        version = os.environ.get("KEYCLOAK_VERSION", versions.get("keycloak", "default"))
        if version not in versions.get("keycloak", "versions"):
            raise ValueError("Unsupported Keycloak version")
        if suite == "keycloak-extension":
            jar = Path(os.environ.get("KEYCLOAK_EXTENSION_JAR", ""))
            extension.verify_artifact(version, jar)
            selected = extension_selection()
            label += "/" + version
        else:
            label += "/" + version + "/" + ("stability/" + root if root else shard)
            selected = keycloak_selection(shard)
        if root:
            if root not in selected:
                raise ValueError("Stability root is absent from the complete shard inventory")
            selected = [root]
        expression = "^(" + "|".join(selected) + ")$"
        deadline = "8m" if suite == "keycloak-extension" else "3m" if root else "25m" if shard == "all" else "10m"
        tags = "keycloak_integration,keycloak_extension_integration" if suite == "keycloak-extension" else "keycloak_integration"
        args += ["-tags=" + tags, "-timeout=" + deadline, "-run", expression, "./internal/controller"]
    result = subprocess.run([gotestsum, "--format=standard-verbose", "--junitfile", str(output / "junit.xml"), "--", *args], cwd=ROOT, check=False)
    try:
        changed = write_summary(output, label, result.returncode, selected, source, suite == "keycloak-extension")
        if suite == "keycloak-extension" and result.returncode == 0:
            cases, errors = parse_junit(output / "junit.xml")
            if errors or any(c["outcome"] != "passed" for c in cases):
                raise ValueError("Extension qualification requires every selected test to pass without skips")
    except (OSError, ValueError, ET.ParseError) as error:
        print("Go test report failed: " + str(error), file=sys.stderr)
        return result.returncode or 1
    return result.returncode or int(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("unit", "kubernetes", "keycloak", "keycloak-extension"))
    parser.add_argument("--gotestsum", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard", choices=(*SHARDS, "ordinary", "all"), default="all")
    args = parser.parse_args()
    if args.suite != "keycloak" and args.shard != "all":
        parser.error("shards apply only to Keycloak")
    try:
        return run(args.suite, args.gotestsum, args.output.resolve(), args.shard)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("Go test runner failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

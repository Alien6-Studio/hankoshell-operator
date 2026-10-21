#!/usr/bin/env python3
"""Enforce reviewed statement coverage floors without averaging package percentages."""

import argparse
from collections import defaultdict
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


MODULE = "github.com/Alien6-Studio/hankoshell-operator/"
MAX_REPORT = 32 * 1024 * 1024
BLOCK = re.compile(r"([^: ]+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)")
FUNCTION = re.compile(r"([^:\s]+):(\d+):\s+(\w+)\s+(\d+\.\d+)%")
TOTAL = re.compile(r"total:\s+\(statements\)\s+(\d+\.\d+)%")


def bounded_text(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_REPORT + 1)
    if len(data) > MAX_REPORT:
        raise ValueError("Coverage input exceeds its size budget")
    return data.decode("utf-8")


def source_path(name):
    if not name.startswith(MODULE):
        raise ValueError("Coverage contains a foreign module")
    path = name[len(MODULE):]
    if not re.fullmatch(r"[A-Za-z0-9_./-]+\.go", path) or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("Invalid coverage source path")
    return path


def parse_profile(text):
    lines = text.splitlines()
    if not lines or lines[0] != "mode: atomic":
        raise ValueError("Coverage must use atomic mode with the race detector")
    packages = defaultdict(lambda: {"covered": 0, "statements": 0})
    blocks, files = set(), set()
    for number, line in enumerate(lines[1:], 2):
        match = BLOCK.fullmatch(line)
        if not match:
            raise ValueError(f"Malformed coverage block at line {number}")
        path = source_path(match[1])
        start_line, start_column, end_line, end_column, statements, count = map(int, match.groups()[1:])
        if (min(start_line, start_column, end_line, end_column) < 1
                or (end_line, end_column) < (start_line, start_column)):
            raise ValueError(f"Invalid coverage range at line {number}")
        identity = (path, start_line, start_column, end_line, end_column)
        if identity in blocks:
            raise ValueError(f"Duplicate coverage block at line {number}")
        blocks.add(identity)
        files.add(path)
        package = str(Path(path).parent)
        packages[package]["statements"] += statements
        packages[package]["covered"] += statements if count else 0
    if not blocks or not sum(item["statements"] for item in packages.values()):
        raise ValueError("Coverage profile contains no executable statements")
    return dict(packages), files


def percentage(value):
    if not value["statements"]:
        return Decimal(0)
    return Decimal(100) * value["covered"] / value["statements"]


def parse_functions(text, files, packages):
    functions = defaultdict(list)
    seen, total = set(), None
    for line in text.splitlines():
        match = TOTAL.fullmatch(line)
        if match:
            if total is not None:
                raise ValueError("Duplicate function coverage total")
            total = Decimal(match[1])
            continue
        match = FUNCTION.fullmatch(line)
        if not match:
            raise ValueError("Malformed go tool cover function output")
        path = source_path(match[1])
        identity = (path, int(match[2]), match[3])
        value = Decimal(match[4])
        if path not in files or identity in seen or identity[1] < 1 or not 0 <= value <= 100:
            raise ValueError("Invalid, duplicate or foreign coverage function")
        seen.add(identity)
        functions[path + ":" + match[3]].append(value)
    overall = {key: sum(item[key] for item in packages.values()) for key in ("covered", "statements")}
    # go tool cover renders one decimal; package/global enforcement uses exact counts.
    if total is None or not functions or abs(total - percentage(overall)) > Decimal("0.051"):
        raise ValueError("Function coverage total contradicts the profile")
    return dict(functions), overall


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate coverage policy key: " + key)
        result[key] = value
    return result


def validate_policy(policy):
    if (not isinstance(policy, dict) or set(policy) != {"schema", "global", "packages", "functions"}
            or type(policy["schema"]) is not int or policy["schema"] != 1):
        raise ValueError("Invalid coverage policy schema")
    if not isinstance(policy["packages"], dict) or not policy["packages"] or not isinstance(policy["functions"], dict) or not policy["functions"]:
        raise ValueError("Coverage policy must name packages and security functions")
    for value in [policy["global"], *policy["packages"].values(), *policy["functions"].values()]:
        if type(value) not in (int, float) or not Decimal(str(value)).is_finite() or not 0 <= value <= 100:
            raise ValueError("Coverage floor must be a finite percentage from 0 to 100")
    for package in policy["packages"]:
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", package):
            raise ValueError("Invalid coverage package identity")
    for name in policy["functions"]:
        parts = name.rsplit(":", 1)
        if len(parts) != 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parts[1]):
            raise ValueError("Invalid security function identity")
        path = source_path(MODULE + parts[0])
        if str(Path(path).parent) not in policy["packages"]:
            raise ValueError("Security function has no package floor: " + name)
    return policy


def evaluate(packages, functions, overall, policy):
    validate_policy(policy)
    failures = []
    for package in sorted(set(policy["packages"]) - set(packages)):
        failures.append(f"Missing package coverage: {package}")
    for package in sorted(set(packages) - set(policy["packages"])):
        failures.append(f"Package needs a reviewed coverage floor: {package}")
    metrics = [("global", percentage(overall), policy["global"])]
    metrics += [(package, percentage(packages[package]), floor) for package, floor in sorted(policy["packages"].items()) if package in packages]
    for name, floor in sorted(policy["functions"].items()):
        matches = functions.get(name, [])
        if len(matches) != 1:
            failures.append(f"Missing or ambiguous security function: {name}")
        else:
            metrics.append((name, matches[0], floor))
    for name, actual, floor in metrics:
        if actual < Decimal(str(floor)):
            failures.append(f"{name}: {actual:.2f}% is below {floor}%")
    return failures


def summarize(packages, functions, overall, policy, failures):
    lines = ["### Go statement coverage", "", f"Global: {percentage(overall):.2f}%; floor: {policy['global']}%.", "",
             "| Package | Covered / statements | Coverage | Floor |", "| --- | ---: | ---: | ---: |"]
    for package, counts in sorted(packages.items()):
        lines.append(f"| `{package}` | {counts['covered']} / {counts['statements']} | {percentage(counts):.2f}% | {policy['packages'].get(package, 'missing')}% |")
    lines += ["", "| Security function | Coverage | Floor |", "| --- | ---: | ---: |"]
    for name, floor in sorted(policy["functions"].items()):
        values = functions.get(name, [])
        actual = f"{values[0]:.1f}%" if len(values) == 1 else "missing/ambiguous"
        lines.append(f"| `{name}` | {actual} | {floor}% |")
    lines += ["", "Coverage measures executed statements, not assertion quality or security correctness."]
    lines += ["", *["- " + failure for failure in failures]] if failures else ["", "All reviewed coverage floors passed."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=ROOT / "tools/qualification/config/coverage-floors.json")
    args = parser.parse_args()
    try:
        policy = validate_policy(json.loads(bounded_text(args.policy), object_pairs_hook=unique_object))
        packages, files = parse_profile(bounded_text(args.profile))
        result = subprocess.run(["go", "tool", "cover", "-func=" + str(args.profile.resolve())], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120, check=True)
        if len(result.stdout) > MAX_REPORT:
            raise ValueError("Function coverage exceeds its size budget")
        text = result.stdout.decode("utf-8")
        functions, overall = parse_functions(text, files, packages)
        failures = evaluate(packages, functions, overall, policy)
        summary = summarize(packages, functions, overall, policy, failures)
        output = args.profile.parent
        (output / "coverage-functions.txt").write_text(text)
        (output / "coverage-summary.md").write_text(summary)
        report = {"schema": 1, "global": overall, "packages": packages,
                  "functions": {name: [float(value) for value in values] for name, values in functions.items()}, "failures": failures}
        (output / "coverage.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(summary)
        print(summary)
        return int(bool(failures))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Coverage check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

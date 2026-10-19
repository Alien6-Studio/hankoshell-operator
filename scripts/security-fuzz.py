"""Run every reviewed Go fuzz target with bounded workers, time and evidence.

The mandatory CI campaign is a finite regression gate, not proof of the absence
of crashes or an allocation profiler. GOMEMLIMIT is a soft runtime memory target.
Go saves minimized failures in testdata/fuzz; both these and interesting cached
inputs are preserved as artifacts. Reproduce with make security-fuzz.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/fuzz-targets.json"
MODULE = "github.com/Alien6-Studio/hankoshell-operator/"
OUTPUT_LIMIT = 2 * 1024**2


def source_identity():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, timeout=10)
    digest = hashlib.sha256()
    for name in sorted(set(names.split(b"\0")) - {b""}):
        path = ROOT / os.fsdecode(name)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Source inventory contains a symlink or missing file")
        digest.update(name + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, timeout=10).strip())
    return {"revision": revision, "dirty": dirty, "sha256": digest.hexdigest()}


def target_inventory():
    manifest = json.loads(MANIFEST.read_text())
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("Missing fuzz inventory")
    for package, names in manifest.items():
        if not re.fullmatch(r"(?:internal/[a-z]+|api/v1beta1)", package) or not isinstance(names, list) or not names:
            raise ValueError("Invalid fuzz package")
        if len(names) != len(set(names)) or any(not re.fullmatch(r"Fuzz[A-Za-z0-9]+", n) for n in names):
            raise ValueError("Invalid fuzz target")
        output = subprocess.check_output(["go", "test", "-list", "^Fuzz", "./" + package], cwd=ROOT, text=True, timeout=180)
        compiled = [line for line in output.splitlines() if re.fullmatch(r"Fuzz[A-Za-z0-9]+", line)]
        if sorted(compiled) != sorted(names):
            raise ValueError("Compiled fuzz inventory drift: " + package)
    # New packages cannot silently escape the reviewed CI campaign.
    source_packages = {str(p.parent.relative_to(ROOT)) for folder in ("internal", "api") for p in (ROOT / folder).rglob("*_test.go")
                       if re.search(r"^func Fuzz[A-Za-z0-9]+\(", p.read_text(), re.MULTILINE)}
    if source_packages != set(manifest):
        raise ValueError("Unreviewed fuzz package")
    return [(package, name) for package, names in manifest.items() for name in names]


def command(package, name, seconds):
    return ["go", "test", "-json", "-run=^$", "-fuzz=^" + name + "$", "-fuzztime=" + str(seconds) + "s",
            "-timeout=" + str(seconds + 45) + "s", "-parallel=2", "./" + package]


def run_target(args, output, seconds):
    env = {**os.environ, "GOMAXPROCS": "2", "GOMEMLIMIT": "256MiB"}
    with output.open("wb") as stdout, output.with_suffix(".stderr").open("wb") as stderr:
        process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + seconds + 60
        try:
            while True:
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
                    raise ValueError("Fuzz output exceeded budget")
                if time.monotonic() >= deadline:
                    raise ValueError("Fuzz process exceeded deadline")
                try:
                    process.wait(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    pass
            if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
                raise ValueError("Fuzz output exceeded budget")
            return process.returncode
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def prepare_package(package, name, output):
    # Instrumentation can compile the Kubernetes dependency graph on a cold CI
    # runner. Give that build a separate finite budget, preserving campaign limits.
    with tempfile.TemporaryDirectory(prefix="hanko-fuzz-build-") as directory:
        binary = Path(directory) / "fuzz.test"
        args = ["go", "test", "-c", "-fuzz=^" + name + "$", "-o", str(binary), "./" + package]
        code = run_target(args, output / (package.replace("/", "-") + "-build.log"), 240)
        if code or not binary.is_file() or not binary.stat().st_size:
            raise ValueError("Fuzz instrumentation build failed: " + package)


def outcome(code, data, package, name):
    rows = [json.loads(line) for line in data.splitlines() if line.strip()]
    tests = [r for r in rows if r.get("Test") == name and r.get("Package") == MODULE + package]
    text = "".join(r.get("Output", "") for r in tests)
    counts = [int(n) for n in re.findall(r"execs: (\d+)", text)]
    seeds = [(int(a), int(b)) for a, b in re.findall(r"gathering baseline coverage: (\d+)/(\d+) completed", text)]
    complete = code == 0 and any(r.get("Action") == "pass" for r in tests)
    complete = complete and bool(counts) and max(counts) > 0 and any(a == b and b > 0 for a, b in seeds)
    complete = complete and not any(r.get("Action") in ("fail", "skip") for r in rows)
    return {"passed": bool(complete), "executions": max(counts, default=0),
            "baseline_inputs": max((b for a, b in seeds if a == b), default=0)}


def preserve_corpus(output, targets):
    cache = Path(subprocess.check_output(["go", "env", "GOCACHE"], cwd=ROOT, text=True, timeout=10).strip())
    for package, name in targets:
        for label, source in (("interesting", cache / "fuzz" / (MODULE + package) / name),
                              ("failures", ROOT / package / "testdata/fuzz" / name)):
            if source.is_dir():
                shutil.copytree(source, output / "corpus" / label / package / name, dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--output", type=Path, default=ROOT / ".tools/security-fuzz")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error("--seconds must be between 1 and 300 per target")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": 1, "complete": False, "phase": "inventory", "seconds_per_target": args.seconds,
              "workers": 2, "memory_target": "256MiB (soft)", "targets": []}
    targets = []
    started = time.monotonic()
    try:
        source = source_identity()
        report["source"] = source
        targets = target_inventory()
        report["expected_targets"] = len(targets)
        prepared = set()
        report["builds"] = []
        for package, name in targets:
            if package not in prepared:
                report["phase"] = "instrumentation"
                began = time.monotonic()
                prepare_package(package, name, output)
                report["builds"].append({"package": package, "seconds": round(time.monotonic() - began, 3)})
                prepared.add(package)
            report["phase"] = "fuzz"
            began = time.monotonic()
            log = output / (name + ".jsonl")
            code = run_target(command(package, name, args.seconds), log, args.seconds)
            result = outcome(code, log.read_text(), package, name)
            result.update(package=package, name=name, seconds=round(time.monotonic() - began, 3), returncode=code)
            report["targets"].append(result)
            print(name + ": " + ("PASS" if result["passed"] else "FAIL"), flush=True)
        report["source_changed"] = source_identity() != source
        report["complete"] = not report["source_changed"] and all(r["passed"] for r in report["targets"])
        report["phase"] = "complete"
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        try:
            preserve_corpus(output, targets)
        except (OSError, subprocess.SubprocessError) as error:
            report["complete"] = False
            report["corpus_error"] = type(error).__name__
        report["seconds"] = round(time.monotonic() - started, 3)
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

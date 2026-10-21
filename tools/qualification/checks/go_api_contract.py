"""Check compiler-resolved fixture APIs against a reviewed development snapshot.

The development snapshot is not a published compatibility baseline. Future public
baselines must retain their own go_api snapshot beside their stable CRD schemas.
"""
import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import subprocess

from tools.qualification.checks import compatibility_gate as gate

ROOT = Path(__file__).resolve().parents[3]

CONFIG = "tools/qualification/config/contracts/go-api-contract.json"


def capture(root, packages):
    if (not isinstance(packages, list) or not packages or len(set(packages)) != len(packages)
            or any(not isinstance(p, str) or not p.startswith("./") or ".." in p or "\n" in p or "\r" in p for p in packages)):
        raise ValueError("Go API selection must contain unique exact local packages")
    inventory = subprocess.run(["go", "list", "-deps", "-export", "-json", *packages], cwd=root,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180, check=False)
    if inventory.returncode or len(inventory.stdout) > 32 * 1024 * 1024:
        raise ValueError("Go export inventory failed or exceeded its budget")
    process = subprocess.run(["go", "run", "./tools/qualification/fixtures/api-surface", *packages], cwd=root, input=inventory.stdout,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180, check=False)
    if process.returncode or len(process.stdout) > 8 * 1024 * 1024:
        raise ValueError("Compiler-resolved Go API capture failed or exceeded its budget")
    result = json.loads(process.stdout)
    module = "github.com/Alien6-Studio/hankoshell-operator/"
    if set(result) != {module + p[2:] for p in packages} or any(not values for values in result.values()):
        raise ValueError("Go API capture omitted or expanded the reviewed selection")
    return result


def changes(before, after):
    result = []
    for package, objects in sorted(before.items()):
        for name, signature in sorted(objects.items()):
            current = after.get(package, {}).get(name)
            if current != signature:
                result.append({"schema": "GoAPI/" + package, "path": name,
                               "rule": "go-api-removed" if current is None else "go-api-changed",
                               "old_hash": gate.digest(signature), "new_hash": gate.digest(current)})
    return result


def check(root=ROOT, current=None):
    config = json.loads((root / CONFIG).read_text())
    if config["schema"] != 1 or config["state"] != "development-fixture-contract":
        raise ValueError("Go fixture contract cannot grant public API maturity")
    path = gate.local_file(root, config["baseline"]["path"])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != config["baseline"]["sha256"]:
        raise ValueError("Reviewed Go API development snapshot was altered")
    baseline = json.loads(raw)
    if baseline["published"] is not False:
        raise ValueError("Development Go API snapshot is not public release evidence")
    current = capture(root, config["packages"]) if current is None else current
    failures = changes(baseline["go_api"], current)
    policy = json.loads((root / gate.POLICY).read_text())
    if policy["baseline"]:
        public_raw = gate.local_file(root, policy["baseline"]["path"]).read_bytes()
        if hashlib.sha256(public_raw).hexdigest() != policy["baseline"]["sha256"]:
            raise ValueError("Published Go API baseline was altered")
        public = json.loads(public_raw)
        if (public.get("published") is not True or not public.get("go_api")
                or public.get("version") not in {release["version"] for release in policy.get("public_releases", [])}):
            raise ValueError("Published compatibility baseline must include its authentic Go API surface")
        for failure in changes(public["go_api"], current):
            change = {key: value for key, value in failure.items() if key != "schema"}
            if not gate.approved(change, failure["schema"], policy, root, date.today()):
                failures.append(failure)
    if failures:
        raise ValueError("Go API compatibility refused: " + json.dumps(failures, sort_keys=True))
    return {"state": config["state"], "packages": len(current), "exports": sum(map(len, current.values()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "snapshot"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "check":
        print(json.dumps(check(), sort_keys=True))
    else:
        if not args.output:
            parser.error("snapshot requires --output; reviewed baselines are never replaced implicitly")
        config = json.loads((ROOT / CONFIG).read_text())
        data = {"schema": 1, "published": False, "state": "candidate-only", "go_api": capture(ROOT, config["packages"])}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

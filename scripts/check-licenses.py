"""Enforce the Go dependency license/source policy and render the shipped third-party notices."""
import argparse
import csv
from datetime import date, timedelta
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location("versions", Path(__file__).with_name("versions.py"))
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "security/dependency-policy.json"
NOTICES = {"operator": "THIRD_PARTY_NOTICES", "cosign": "THIRD_PARTY_NOTICES.cosign"}
COSIGN_TARGET = "github.com/sigstore/cosign/v3/cmd/cosign"
LICENSE_NAME = re.compile(r"(?i)(license|licence|copying|notice)([-.].*)?")
EXCLUDED_DIRS = {".git", "node_modules", "testdata", "vendor"}
MODULE_SUM = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
EXCEPTION_FIELDS = {"module", "version", "sum", "license", "justification", "expires"}
SHIPPED_PLATFORMS = (("linux", "amd64"), ("linux", "arm64"))


def read_policy(path=POLICY, today=None):
    policy = json.loads(path.read_text())
    sources = policy.get("module_sources")
    if (set(policy) != {"schema_version", "allowed_licenses", "denied_licenses", "module_sources", "exceptions"}
            or policy["schema_version"] != 1 or not isinstance(policy["exceptions"], list)
            or not isinstance(sources, dict) or set(sources) != {"goproxy", "gosumdb", "allow_replace"}
            or sources["goproxy"] != "https://proxy.golang.org" or sources["gosumdb"] != "sum.golang.org"
            or sources["allow_replace"] is not False):
        raise ValueError("Invalid dependency policy")
    for group in ("allowed_licenses", "denied_licenses"):
        values = policy[group]
        if (not isinstance(values, list) or not values or values != sorted(set(values))
                or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", v) for v in values)):
            raise ValueError("License lists must be sorted unique SPDX identifiers")
    if set(policy["allowed_licenses"]) & set(policy["denied_licenses"]):
        raise ValueError("A license cannot be both allowed and denied")
    today = today or date.today()
    seen = set()
    for exception in policy["exceptions"]:
        if (not isinstance(exception, dict) or set(exception) != EXCEPTION_FIELDS
                or any(not isinstance(v, str) or not v.strip() for v in exception.values())):
            raise ValueError("Invalid license exception fields")
        if (not MODULE_SUM.fullmatch(exception["sum"]) or not exception["version"].startswith("v")
                or exception["license"] not in policy["allowed_licenses"]
                or len(exception["justification"].strip()) < 20):
            raise ValueError("Exception needs a module hash, an allowed license and a justification")
        expiry = date.fromisoformat(exception["expires"])
        if expiry.isoformat() != exception["expires"] or not today < expiry <= today + timedelta(days=365):
            raise ValueError("Exception must be unexpired and reviewed within a year")
        key = (exception["module"], exception["version"])
        if key in seen:
            raise ValueError("Duplicate license exception")
        seen.add(key)
    return policy


def run(arguments, cwd, platform=None):
    """Go commands under the reviewed toolchain so classification stays reproducible."""
    environment = dict(os.environ, GOTOOLCHAIN="local")
    if platform:
        environment.update(GOOS=platform[0], GOARCH=platform[1], CGO_ENABLED="0",
                           GOAMD64="v1", GOARM64="v8.0")
    result = subprocess.run([str(a) for a in arguments], cwd=cwd, env=environment,
                            capture_output=True, text=True, timeout=1800)
    if result.returncode:
        raise ValueError(f"{arguments[0]} failed in {cwd}: {result.stderr.strip()[-2000:]}")
    return result.stdout


def source_rules(cwd, policy):
    """Modules may only come from the public proxy, verified by the public sum database."""
    sources = policy["module_sources"]
    environment = json.loads(run(["go", "env", "-json", "GOPROXY", "GOSUMDB", "GOFLAGS",
                                  "GOPRIVATE", "GONOSUMDB", "GOINSECURE"], cwd))
    proxies = environment["GOPROXY"].split(",")
    if proxies[0] != sources["goproxy"] or set(proxies[1:]) - {"direct"}:
        raise ValueError("GOPROXY must resolve through " + sources["goproxy"])
    if environment["GOSUMDB"] != sources["gosumdb"]:
        raise ValueError("GOSUMDB must stay " + sources["gosumdb"])
    for name in ("GOFLAGS", "GOPRIVATE", "GONOSUMDB", "GOINSECURE"):
        if environment[name]:
            raise ValueError(name + " overrides are incompatible with the dependency policy")
    if not sources["allow_replace"] and re.search(r"(?m)^\s*replace[\s(]", (cwd / "go.mod").read_text()):
        raise ValueError("replace directives bypass the module source policy: " + str(cwd / "go.mod"))
    run(["go", "mod", "verify"], cwd)


def dependencies(cwd, target, tests=False, platform=None):
    """Non-main modules the target depends on, bound to their sum-verified cache copies."""
    template = ("{{if .Module}}{{if not .Module.Main}}"
                "{{.Module.Path}}|{{.Module.Version}}|{{.Module.Sum}}|{{.Module.Dir}}{{end}}{{end}}")
    arguments = ["go", "list", "-deps"] + (["-test"] if tests else []) + ["-f", template, target]
    modules = {}
    for line in sorted(set(run(arguments, cwd, platform=platform).splitlines())):
        if not line:
            continue
        path, version, checksum, directory = line.split("|")
        if not MODULE_SUM.fullmatch(checksum) or not directory:
            raise ValueError("Module outside the verified cache: " + path)
        modules[path] = {"version": version, "sum": checksum, "dir": Path(directory)}
    if not modules:
        raise ValueError("No dependency modules resolved for " + target)
    return modules


def classified(binary, cwd, target, tests=False, platform=None):
    """Package license identities from the pinned classifier as (prefix, identifier) rows."""
    arguments = [binary, "report"] + (["--include_tests"] if tests else []) + [target]
    return [(row[0], row[2]) for row in csv.reader(io.StringIO(run(arguments, cwd, platform=platform))) if row]


def merge_modules(destination, current):
    for path, record in current.items():
        previous = destination.get(path)
        if previous and any(previous[key] != record[key] for key in ("version", "sum")):
            raise ValueError("Dependency identity differs across shipped platforms: " + path)
        destination[path] = record


def inventory(binary, cwd, target, main_module, tests=False):
    """Union both shipped build graphs, independent of the developer's host OS."""
    modules, licenses = {}, {}
    for platform in SHIPPED_PLATFORMS:
        current = dependencies(cwd, target, tests=tests, platform=platform)
        identities = attribute(classified(binary, cwd, target, tests=tests, platform=platform), current, main_module)
        merge_modules(modules, current)
        for path, names in identities.items():
            licenses.setdefault(path, set()).update(names)
    return modules, licenses


def attribute(rows, modules, main_module):
    """Fold per-package identities onto their module; reject rows outside the graph."""
    licenses = {}
    for prefix, name in rows:
        if prefix == main_module or prefix.startswith(main_module + "/"):
            continue
        owner = max((path for path in modules if prefix == path or prefix.startswith(path + "/")),
                    key=len, default=None)
        if owner is None:
            raise ValueError("License entry outside the dependency graph: " + prefix)
        licenses.setdefault(owner, set()).add(name)
    return licenses


def enforce(modules, licenses, policy, used):
    """Every module needs allowed identities or one unexpired hash-bound exception."""
    problems = []
    for path in sorted(modules):
        identified = licenses.get(path, {"Unknown"})
        denied = identified & set(policy["denied_licenses"])
        unresolved = {name for name in identified if name not in policy["allowed_licenses"]}
        if not denied and not unresolved:
            continue
        record = modules[path]
        exception = next((entry for entry in policy["exceptions"]
                          if entry["module"] == path and entry["version"] == record["version"]
                          and entry["sum"] == record["sum"]), None)
        if exception and not denied:
            used.add((path, record["version"]))
            licenses[path] = (identified - {"Unknown"}) | {exception["license"]}
            continue
        state = "denied " + ", ".join(sorted(denied)) if denied else ", ".join(sorted(identified))
        problems.append(f"{path}@{record['version']}: {state}")
    if problems:
        raise ValueError("Modules outside the dependency license policy:\n" + "\n".join(problems))


def license_files(directory):
    """Shippable license/notice files, deterministic and bounded, test fixtures excluded."""
    found = []
    for base, folders, names in os.walk(directory):
        folders[:] = sorted(folder for folder in folders if folder not in EXCLUDED_DIRS)
        for name in sorted(names):
            path = Path(base) / name
            if LICENSE_NAME.fullmatch(name) and path.is_file() and not path.is_symlink() \
                    and 0 < path.stat().st_size <= 1024 * 1024:
                found.append(path.relative_to(directory))
    return sorted(found, key=str)


def render(title, modules, licenses):
    """One deduplicated notices document; identical texts are shipped once and referenced."""
    texts, order, inventory = {}, [], []
    for path in sorted(modules):
        record = modules[path]
        references = []
        for relative in license_files(record["dir"]):
            content = (record["dir"] / relative).read_bytes().decode("utf-8", "backslashreplace")
            digest = hashlib.sha256(content.encode()).hexdigest()
            if digest not in texts:
                order.append(digest)
                texts[digest] = (f"text-{len(order):03d}", content)
            references.append(f"{texts[digest][0]} ({relative})")
        identities = ", ".join(sorted(licenses.get(path, set()))) or "Unknown"
        location = "; ".join(references) if references else "license text at the module repository"
        inventory.append(f"{path} {record['version']} — {identities} — {location}")
    lines = [f"Third-party notices for the {title}.", "",
             "Generated by scripts/check-licenses.py (make licenses); do not edit.",
             "Each module lists its SPDX identifiers and the shipped license texts below.", ""]
    lines += inventory
    for digest in order:
        label, content = texts[digest]
        lines += ["", "=" * 72, label, "=" * 72, content.rstrip("\n")]
    return "\n".join(lines) + "\n"


def cosign_workspace(directory):
    """Rebuild the synthetic module the image build uses, from the reviewed cosign pins."""
    cosign = pins.DATA["tools"]["cosign"]
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("go.mod", "go.sum"):
        (directory / name).unlink(missing_ok=True)
    run(["go", "mod", "init", "hankoshell.local/cosign-build"], directory)
    run(["go", "get", f"{COSIGN_TARGET.rsplit('/cmd/', 1)[0]}/cmd/cosign@{cosign['version']}"], directory)
    # Resolve all overrides together, as Docker does. Sequential updates can
    # silently upgrade an earlier pin and hide an incompatible image build.
    run(["go", "get", *[f"{module}@{version}" for module, version in cosign["dependencies"].items()]], directory)
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-licenses", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=ROOT / ".tools/cosign-licenses")
    args = parser.parse_args()
    policy = read_policy()
    used = set()

    source_rules(ROOT, policy)
    reachable, identities = inventory(args.go_licenses, ROOT, "./...", run(["go", "list", "-m"], ROOT).strip(), tests=True)
    enforce(reachable, identities, policy, used)
    shipped = {}
    for platform in SHIPPED_PLATFORMS:
        merge_modules(shipped, dependencies(ROOT, "./cmd/operator", platform=platform))

    workspace = cosign_workspace(args.workspace)
    source_rules(workspace, policy)
    cosign_modules, cosign_identities = inventory(args.go_licenses, workspace, COSIGN_TARGET, "hankoshell.local/cosign-build")
    enforce(cosign_modules, cosign_identities, policy, used)

    stale = [f"{e['module']}@{e['version']}" for e in policy["exceptions"]
             if (e["module"], e["version"]) not in used]
    if stale:
        raise ValueError("Unused license exceptions must be removed: " + ", ".join(stale))

    (ROOT / NOTICES["operator"]).write_text(render("hankoshell-operator binary", shipped, identities))
    (ROOT / NOTICES["cosign"]).write_text(render("embedded cosign binary", cosign_modules, cosign_identities))
    print(f"License policy satisfied: {len(reachable)} operator modules, "
          f"{len(cosign_modules)} cosign modules, {len(used)} exceptions applied")


if __name__ == "__main__":
    main()

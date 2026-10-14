"""Read reviewed pins; run `python3 scripts/versions.py sync` after editing versions.json.

Docker base images and Go modules stay visible to Dependabot. Their reviewed
toolchain must agree with the manifest. Generated literals are checked in
preflight; executable consumers read the manifest directly. A disabled tool
has a null pin and cannot be installed through this API.
"""

import argparse
import ast
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "versions.json").read_text())


def get(*keys, data=None):
    value = DATA if data is None else data
    for key in keys:
        value = value[key]
    if value is None:
        raise ValueError("Tool is not enabled/pinned: " + ".".join(keys))
    return value


def crd_inventory(root=ROOT, data=None):
    """Derive the count and compare actual kinds, not just two equal counts."""
    import yaml

    data = DATA if data is None else data
    api = data["api"]
    kinds = set()
    for path in sorted((root / api["crds"]).glob("*.yaml")):
        crd = yaml.safe_load(path.read_text())
        spec = crd["spec"]
        kind = spec["names"]["kind"]
        if (crd["kind"] != "CustomResourceDefinition" or spec["group"] != "hanko.sh"
                or [v["name"] for v in spec["versions"]] != [api["version"]]
                or not spec["versions"][0]["served"] or not spec["versions"][0]["storage"]
                or kind in kinds):
            raise ValueError("Invalid or duplicate served API: " + str(path))
        kinds.add(kind)
    declarations = "\n".join(p.read_text() for p in (root / api["types"]).glob("*_types.go"))
    source_kinds = set(re.findall(r"(?m)^type (\w+) struct \{\s*metav1\.TypeMeta\b", declarations))
    source_kinds = {kind for kind in source_kinds if not kind.endswith("List")}
    registration = (root / api["types"] / "groupversion_info.go").read_text()
    registered = set(re.findall(r"&(\w+)\{\}", registration))
    registered = {kind for kind in registered if not kind.endswith("List")}
    if not kinds or kinds != source_kinds or kinds != registered:
        raise ValueError(f"CRD/source/scheme kinds differ: manifests={sorted(kinds)}, "
                         f"types={sorted(source_kinds)}, scheme={sorted(registered)}")
    return {"version": api["version"], "crd_count": len(kinds), "kinds": sorted(kinds)}


def generated(root=ROOT, data=None):
    """Render only owned literals; never rewrite actions, base images or gates."""
    data = DATA if data is None else data
    output = {}

    def replace(filename, pattern, value, count=1):
        original = output.get(filename, (root / filename).read_text())
        changed, matches = re.subn(pattern, lambda m: m[1] + value, original, flags=re.M)
        if matches != count:
            raise ValueError(f"Expected {count} version binding(s) in {filename}, found {matches}: {pattern}")
        output[filename] = changed

    release = data["release"]["version"]
    replace("go.mod", r"^(toolchain go)\S+$", data["go"]["toolchain"])
    replace(".pre-commit-config.yaml", r"^(minimum_pre_commit_version: )'.+'$",
            "'" + data["tools"]["pre_commit"]["version"] + "'")
    replace("Dockerfile", r"^(ARG VERSION=)\S+$", release)
    replace("internal/version/version.go", r'^(var Agent = ).+$', json.dumps(release))
    chart = "charts/hankoshell-operator/Chart.yaml"
    for field in ("version", "appVersion"):
        replace(chart, rf"^({field}: ).+$", json.dumps(release))
    replace(chart, r"^(kubeVersion: ).+$", json.dumps(data["kubernetes"]["chart_range"]))
    replace(chart, r'^(  artifacthub.io/prerelease: ).+$', json.dumps(str("-" in release).lower()))
    replace(chart, r"^(      image: ghcr.io/alien6-studio/hankoshell-operator:).+$", release)

    ci = ".github/workflows/ci.yml"
    # Explicit generated markers survive YAML parsing and make ownership visible.
    matrices = {"kubernetes": data["kubernetes"]["versions"],
                "keycloak": data["keycloak"]["versions"],
                "workload-keycloak": sorted(data["keycloak"]["versions"])}
    for name, values in matrices.items():
        count = 2 if name == "workload-keycloak" else (3 if name == "kubernetes" else 1)
        replace(ci, rf"^(        (?:version|keycloak|kubernetes): ).+(?= # versions:{name}$)",
                json.dumps(values), count)
    for family in ("kubernetes", "keycloak"):
        replace(ci, rf"^(        if: matrix.version == )'[^']+'(?=(?: && matrix.shard == 'core')? # versions:{family}-lint$)",
                "'" + data[family]["default"] + "'")

    cosign = data["tools"]["cosign"]
    # One generated shell fragment is sourced by both native and image builds.
    dependencies = " ".join(module + "@" + version for module, version in cosign["dependencies"].items())
    for pin in (cosign["version"], *cosign["dependencies"].values()):
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", pin):
            raise ValueError("Expected a pinned cosign module version")
    for module in cosign["dependencies"]:
        if not re.fullmatch(r"[a-zA-Z0-9./_-]+", module):
            raise ValueError("Invalid cosign dependency module")
    output["scripts/cosign-pins.sh"] = (
        "# Generated from versions.json by scripts/versions.py sync; do not edit.\n"
        f"COSIGN_VERSION='{cosign['version']}'\n"
        f"COSIGN_DEPENDENCIES='{dependencies}'\n")
    return output


def check(root=ROOT, data=None):
    data = DATA if data is None else data
    validate(data)
    for filename, expected in generated(root, data).items():
        path = root / filename
        if not path.exists() or path.read_text() != expected:
            raise ValueError(f"Version drift in {filename}; run python3 scripts/versions.py sync")
    # Dependabot owns FROM lines; do not hide them behind ARG or overwrite a digest.
    images = re.findall(r"^FROM .*\bgolang:([^@ ]+)@sha256:([0-9a-f]{64})", (root / "Dockerfile").read_text(), re.M)
    if len(images) != 2 or len(set(images)) != 1 or not images[0][0].startswith(data["go"]["toolchain"] + "-"):
        raise ValueError("Dependabot-managed Go base images must match the reviewed toolchain and each other")
    check_consumers(root)
    return crd_inventory(root, data)


def validate(data):
    for family in ("kubernetes", "keycloak"):
        values = data[family]["versions"]
        if (not values or len(values) != len(set(values)) or data[family]["default"] not in values
                or any(not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) for value in values)):
            raise ValueError("Invalid qualification versions for " + family)
    kubernetes = data["kubernetes"]
    if (kubernetes["deep_migration"] not in kubernetes["versions"]
            or set(kubernetes["node_images"]) | {kubernetes["built_node"]["version"]} != set(kubernetes["versions"])
            or set(kubernetes["envtest_sha512"]) != set(kubernetes["versions"])
            or set(data["keycloak"]["images"]) != set(data["keycloak"]["versions"])):
        raise ValueError("Every qualification version needs its reviewed fixture pins")
    for prefix, images in (("kindest/node:v", kubernetes["node_images"]),
                           ("quay.io/keycloak/keycloak:", data["keycloak"]["images"])):
        for version, image in images.items():
            if not re.fullmatch(re.escape(prefix + version) + r"@sha256:[0-9a-f]{64}", image):
                raise ValueError("Fixture image version or checksum differs: " + version)
    hashes = [(values, 128) for values in kubernetes["envtest_sha512"].values()]
    hashes += [(data["tools"][tool]["sha256"], 64) for tool in ("helm", "kind", "kubectl", "gitleaks")]
    hashes += [({"pyz": data["tools"]["pre_commit"]["sha256"]}, 64)]
    hashes += [(kubernetes["built_node"]["sha256"], 64)]
    for values, length in hashes:
        if not values or any(not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", digest) for digest in values.values()):
            raise ValueError("Missing or malformed reviewed fixture checksum")


def check_consumers(root):
    """Reject reintroduced literal overrides at workflow/build entry points."""
    import yaml

    for path in (root / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                options = step.get("with", {})
                if step.get("uses", "").startswith("actions/setup-go@"):
                    if options.get("go-version-file") != "go.mod" or "go-version" in options:
                        raise ValueError("setup-go must consume go.mod in " + str(path))
                if "build-args" in options and options["build-args"] != "VERSION=${{ steps.versions.outputs.version }}":
                    raise ValueError("OCI build version must come from versions.json")
                run = step.get("run", "")
                if re.search(r"get\.helm\.sh/|oras/cmd/oras@v|--version\s+['\"]?\d", run):
                    raise ValueError("Duplicated tool/release pin in " + str(path))
    for filename in ("Dockerfile", "scripts/install-cosign.sh"):
        contents = (root / filename).read_text()
        if "cosign-pins.sh" not in contents or re.search(r"\bgo get[^\n]*@v\d", contents):
            raise ValueError("Cosign builders must share the generated module pins")
    makefile = (root / "Makefile").read_text()
    for variable in ("VERSION", "RELEASE_VERSION", "CONTROLLER_GEN_VERSION", "GOLANGCI_LINT_VERSION",
                     "GO_ARCH_LINT_VERSION", "GOVULNCHECK_VERSION", "GOTESTSUM_VERSION", "KUBERNETES_VERSION", "KEYCLOAK_VERSION"):
        if not re.search(r"^" + variable + r" [?:]= \$\(shell python3 scripts/versions.py get [a-z_ ]+\)$", makefile, re.M):
            raise ValueError("Makefile must read the reviewed pin: " + variable)
    # Qualification-specific protocol expectations remain explicit tests. Active
    # build/install pins cannot be replaced by literal constants in a consumer.
    consumers = {
        "scripts/release-version.py": ("VERSION", "TARGET_VERSION", "RELEASE_STATUS"),
        "scripts/install-system-tools.py": ("KIND", "KUBECTL", "KIND_HASHES", "KUBECTL_HASHES"),
        "scripts/system-test.py": ("VERSION", "KUBERNETES_VERSION", "KEYCLOAK_VERSION", "NODE", "KEYCLOAK", "KIND_VERSION"),
        "scripts/workload-identity-probe.py": ("KEYCLOAK_IMAGES", "NODE_IMAGES", "BUILT_NODE", "NODE_BASE", "NODE_ARCHIVES"),
    }
    for filename, names in consumers.items():
        for statement in ast.parse((root / filename).read_text()).body:
            if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in statement.targets):
                try:
                    ast.literal_eval(statement.value)
                except (ValueError, TypeError):
                    continue
                raise ValueError("Duplicated version/fixture literal in " + filename)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("get", "sync", "check", "inventory"))
    parser.add_argument("keys", nargs="*")
    args = parser.parse_args()
    if args.command == "get":
        value = get(*args.keys)
        print(value if isinstance(value, str) else json.dumps(value, separators=(",", ":")))
    elif args.command == "sync":
        validate(DATA)
        for filename, content in generated().items():
            (ROOT / filename).write_text(content)
    else:
        print(json.dumps(check() if args.command == "check" else crd_inventory(), sort_keys=True))


if __name__ == "__main__":
    main()

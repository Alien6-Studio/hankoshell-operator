"""Validate the selected initial public contract without declaring a release.

Selection is reviewed data. This tool never promotes a field automatically when
the API grows; every spec/status group must have an explicit decision.
"""

import argparse
import difflib
import importlib.util
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[3]

START, END = "<!-- public-selection:start -->", "<!-- public-selection:end -->"
CLASSES = {"public", "alpha", "experimental"}
PUBLIC_DOMAINS = {"HankoApplication", "HankoRole", "HankoResourceServer"}
spec = importlib.util.spec_from_file_location("selection_inventory", ROOT / "tools/qualification/checks/api_support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def selection(root=ROOT):
    inventory = support.inventory(root)
    data = json.loads((root / "tools/qualification/config/contracts/public-contract-selection.json").read_text())
    if (data.get("schemaVersion") != 1 or data.get("targetRelease") != "0.1.0"
            or data.get("state") != "selected-for-qualification" or data.get("published") is not False):
        raise ValueError("Public selection must identify the unpublished qualification candidate")
    resources = data.get("resources", [])
    by_kind = {r["kind"]: r for r in resources}
    if len(by_kind) != len(resources) or set(by_kind) != {r["kind"] for r in inventory["resources"]}:
        raise ValueError("Public review must classify all 17 resources exactly once")
    for resource in inventory["resources"]:
        row = by_kind[resource["kind"]]
        if row.get("classification") not in CLASSES or not row.get("rationale"):
            raise ValueError("Resource selection needs a classification and rationale")
        if row["classification"] == "public" and row["kind"] not in PUBLIC_DOMAINS:
            raise ValueError("Public promotion needs a reviewed executable domain and corpus")
        for group in ("spec", "status"):
            fields = row.get(group, {})
            if set(fields) != set(resource[group + "Fields"]) or any(v not in CLASSES for v in fields.values()):
                raise ValueError(f"Unreviewed public field group: {row['kind']}.{group}")
        native = set(row.get("publicNativeSpecFields", []))
        if native != {f for f in resource["nativeSpecFields"] if row["spec"][f] == "public"}:
            raise ValueError("Public native fields need an explicit Keycloak extension boundary")
        evidence = row.get("evidence", [])
        if not evidence or any(not (root / p).is_file() or not (root / p).resolve().is_relative_to(root.resolve()) for p in evidence):
            raise ValueError("Public selection needs existing, local evidence")
        if row["classification"] != "public" and any(v == "public" for v in (*row["spec"].values(), *row["status"].values())):
            raise ValueError("Deferred resources cannot silently contain public groups")
    if {r["kind"] for r in resources if r["classification"] == "public"} != PUBLIC_DOMAINS:
        raise ValueError("Selected public compiler domains differ from the reviewed corpus")
    exceptions = data.get("nestedExclusions", [])
    if not exceptions or any(e.get("classification") not in {"alpha", "experimental"} or not e.get("rationale") for e in exceptions):
        raise ValueError("Nested authority extensions need explicit deferred decisions")
    crds = [yaml.safe_load(p.read_text()) for p in (root / "charts/hankoshell-operator/crds").glob("*.yaml")]
    by_schema = {c["spec"]["names"]["kind"]: c["spec"]["versions"][0]["schema"]["openAPIV3Schema"] for c in crds}
    for item in exceptions:
        row = by_kind.get(item.get("kind"))
        path = item.get("path", "").split(".")
        if row is None or len(path) < 3 or path[0] not in ("spec", "status") or path[1].removesuffix("[]") not in row[path[0]]:
            raise ValueError("Nested exclusion must identify an existing reviewed field group")
        node = by_schema[row["kind"]]
        for part in path:
            node = node.get("properties", {}).get(part.removesuffix("[]"))
            if node is None or (part.endswith("[]") and node.get("type") != "array"):
                raise ValueError("Nested exclusion refers to an absent schema path")
            if part.endswith("[]"):
                node = node["items"]
        if "when" in item and item["when"] not in node.get("enum", []):
            raise ValueError("Conditional exclusion must name an admitted enum value")
    return data


def summary(data):
    return (f"Initial 0.1.0 selection: {sum(r['classification'] == 'public' for r in data['resources'])} public resource candidates; "
            "qualification and first publication remain pending. Current development APIs remain experimental.")


def render(data):
    rows = [summary(data), "", "| Resource | Selected scope | Public spec groups |", "| --- | --- | --- |"]
    for row in data["resources"]:
        fields = ", ".join("`" + f + "`" for f, c in row["spec"].items() if c == "public") or "—"
        rows.append(f"| `{row['kind']}` | {row['classification']} | {fields} |")
    rows += ["", "Native SAML and CORS entry policy remain Keycloak extensions. Delegation, organization principals,",
             "connected integrations and every other deferred field retain their named limitations in",
             "the complete selection; no planned capability is removed."]
    return "\n".join(rows)


def check(root=ROOT):
    data = selection(root)
    corpus(root, data)
    expected = render(data)
    for name in ("charts/hankoshell-operator/README.md", "docs/public-contract-selection.md"):
        text = (root / name).read_text()
        if text.count(START) != 1 or text.count(END) != 1 or text.split(START)[1].split(END)[0].strip() != expected:
            raise ValueError("Public selection documentation drift: " + name)
    return data


def corpus(root, data):
    base = root / "internal/iamconformance/testdata/public-0.1.0"
    value = json.loads((base / "corpus.json").read_text())
    if (value.get("schemaVersion") != 1 or value.get("release") != "0.1.0-candidate"
            or value.get("predecessor") != "" or value.get("limitation") != "NoPublishedPredecessor"):
        raise ValueError("The first unpublished candidate cannot invent predecessor qualification")
    fixtures = value.get("fixtures", [])
    if not fixtures or len({f["name"] for f in fixtures}) != len(fixtures):
        raise ValueError("Public corpus needs unique named fixtures")
    crds = [yaml.safe_load(p.read_text()) for p in (root / "charts/hankoshell-operator/crds").glob("*.yaml")]
    schemas = {c["spec"]["names"]["kind"]: c["spec"]["versions"][0]["schema"]["openAPIV3Schema"] for c in crds}
    for row in data["resources"]:
        if row["classification"] != "public":
            continue
        selected = [f for f in fixtures if f["kind"] == row["kind"]]
        if not selected:
            raise ValueError("Missing public resource corpus: " + row["kind"])
        for group in ("spec", "status"):
            covered = set().union(*(set(f["defaultedSpec" if group == "spec" else "status"]) for f in selected))
            required = {field for field, cls in row[group].items() if cls == "public"}
            if not required <= covered:
                raise ValueError(f"Missing public corpus field groups: {row['kind']}.{group}: {sorted(required-covered)}")
        stored = json.loads((base / "schemas" / (row["kind"] + ".json")).read_text())
        current = schemas[row["kind"]]
        if stored != current:
            diff = list(difflib.unified_diff(json.dumps(stored, indent=2, sort_keys=True).splitlines(),
                        json.dumps(current, indent=2, sort_keys=True).splitlines(), fromfile="frozen schema", tofile="current schema"))
            raise ValueError("Reviewed schema/default/topology drift for " + row["kind"] + "\n" + "\n".join(diff[:80]))
    if {f["kind"] for f in fixtures} != PUBLIC_DOMAINS:
        raise ValueError("Fixture domain differs from selected public scope")
    for fixture in fixtures:
        identity = fixture.get("identity", {})
        if (set(identity) != {"contract", "backend", "intent", "plan"} or identity["contract"] != "hanko.sh/iam-contract/v1alpha1"
                or identity["backend"] != "keycloak" or any(not re.fullmatch(r"sha256:[a-f0-9]{64}", identity[k]) for k in ("intent", "plan"))):
            raise ValueError("Public fixture lacks independently frozen compiler identity")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "render"), default="check", nargs="?")
    args = parser.parse_args()
    if args.command == "render":
        print(render(selection()))
    else:
        check()
        print("Public resource/field selection agrees with the complete API inventory")


if __name__ == "__main__":
    main()

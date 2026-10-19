"""Check the reviewed development API inventory and documentation classification.

Field additions require an explicit inventory review. This is not a stable API
baseline, a provider conformance result, or permission to publish a release.
"""

import json
from pathlib import Path

import yaml
import api_conversion_contract as conversion

ROOT = Path(__file__).resolve().parents[1]
START, END = "<!-- api-support:start -->", "<!-- api-support:end -->"
SURFACES = {"standalone IAM", "instance and operations", "connected", "deprecated"}
FEATURES = {"Delegation and agent identity", "Second IAM provider", "Hub and Continuum",
            "Mesh traffic enforcement", "Portable backup and restore", "Managed lifecycle", "Cloud, CNI and CSI"}


def inventory(root=ROOT):
    data = json.loads((root / "docs/api-support.json").read_text())
    expected = {"schemaVersion": 1, "stage": "development", "apiVersion": "hanko.sh/v1alpha1",
                "storedVersion": "v1alpha1", "conversion": "None", "compatibility": "experimental",
                "publicSelectionIssue": 81}
    if any(data.get(key) != value for key, value in expected.items()):
        raise ValueError("API inventory must retain the reviewed development classification")
    resources = data.get("resources", [])
    kinds = [r["kind"] for r in resources]
    if len(set(kinds)) != len(kinds):
        raise ValueError("Duplicate API support resource")
    schemas = {}
    candidate = conversion.load(root, optional=True)
    expected_candidates = {"v1beta1": sorted(candidate["resources"])} if candidate else {}
    if data.get("candidateVersions", {}) != expected_candidates:
        raise ValueError("Candidate API support requires the exact conversion decision")
    for path in (root / "charts/hankoshell-operator/crds").glob("*.yaml"):
        crd = yaml.safe_load(path.read_text())
        kind = crd["spec"]["names"]["kind"]
        versions = crd["spec"]["versions"]
        reviewed = candidate and kind in candidate["resources"]
        if reviewed:
            conversion.validate_crd(crd, candidate)
        if (crd["spec"]["group"] != "hanko.sh" or len(versions) != (2 if reviewed else 1)
                or versions[0]["name"] != data["storedVersion"] or not versions[0]["storage"]
                or not versions[0]["served"] or crd["spec"].get("conversion", {}).get("strategy", "None") != data["conversion"]):
            raise ValueError("Stored API version or conversion changed without an inventory review")
        if kind in schemas:
            raise ValueError("Duplicate CRD kind")
        schemas[kind] = versions[0]["schema"]["openAPIV3Schema"]["properties"]
    if not schemas or set(kinds) != set(schemas):
        raise ValueError("API support inventory must cover every installed CRD")
    for resource in resources:
        kind = resource["kind"]
        if resource["surface"] not in SURFACES:
            raise ValueError("Unknown API surface classification")
        for group in ("spec", "status"):
            fields = resource[group + "Fields"]
            if fields != sorted(set(fields)) or set(fields) != set(schemas[kind][group]["properties"]):
                raise ValueError(f"Unreviewed {kind}.{group} field-group drift")
        native = resource["nativeSpecFields"]
        if len(set(native)) != len(native) or not set(native) <= set(resource["specFields"]):
            raise ValueError(f"Unknown native extension boundary for {kind}")
    features = data.get("features", [])
    if len(features) != len(FEATURES) or {f["name"] for f in features} != FEATURES:
        raise ValueError("Deferred capability inventory is incomplete")
    for item in resources + features:
        path = (root / item["evidence"]).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError("API classification needs an existing repository evidence reference")
    if any(f["compatibility"] not in ("alpha", "experimental") or not f["limitation"] for f in features):
        raise ValueError("Deferred capabilities need explicit alpha/experimental limits")
    return data


def summary(data):
    text = (f"All {len(data['resources'])} `{data['apiVersion']}` resources are experimental; "
            "no public API compatibility commitment has been selected.")
    if data.get("candidateVersions"):
        text += " Candidate `v1beta1` additionally serves Application, Role and ResourceServer with identical schemas; storage remains `v1alpha1`."
    return text


def render(data):
    lines = [summary(data), "", "| Resource | Surface | Compatibility |", "| --- | --- | --- |"]
    for resource in data["resources"]:
        lines.append(f"| `{resource['kind']}` | {resource['surface']} | experimental |")
    lines += ["", "| Additional surface | Compatibility |", "| --- | --- |"]
    for feature in data["features"]:
        lines.append(f"| {feature['name']} | {feature['compatibility']} |")
    return "\n".join(lines)


def check(root=ROOT):
    data = inventory(root)
    expected = render(data)
    for name in ("README.md", "charts/hankoshell-operator/README.md", "docs/api-support.md"):
        text = (root / name).read_text()
        if text.count(START) != 1 or text.count(END) != 1 or text.index(START) >= text.index(END):
            raise ValueError(f"Missing unique API support classification in {name}")
        if text.split(START)[1].split(END)[0].strip() != expected:
            raise ValueError(f"API support classification differs from reviewed inventory in {name}")
    notes = (root / "CHANGELOG.md").read_text().split("<!-- release-notes:start -->")[-1].split("<!-- release-notes:end -->")[0]
    if summary(data) not in notes or "Experimental surfaces:" not in notes:
        raise ValueError("Curated release notes must retain the API classification and experimental surfaces")
    return data


if __name__ == "__main__":
    check()
    print("API support inventory and documentation agree")

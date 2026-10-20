"""Closed structural conversion decision for the experimental IAM beta API."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

CONTRACT = "tools/qualification/config/contracts/api-conversion.json"
KINDS = {"HankoApplication", "HankoRole", "HankoResourceServer"}
VERSIONS = ["v1alpha1", "v1beta1"]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def load(root=ROOT, *, optional=False):
    path = root / CONTRACT
    if optional and not path.exists():
        return None
    data = json.loads(path.read_text())
    if (set(data) != {"schema_version", "group", "hub_version", "default_storage", "strategy", "maturity", "published", "resources"}
            or data["schema_version"] != 1 or data["group"] != "hanko.sh" or data["hub_version"] != "v1alpha1"
            or data["default_storage"] != "v1alpha1" or data["strategy"] != "None"
            or data["maturity"] != "experimental" or data["published"] is not False
            or set(data["resources"]) != KINDS):
        raise ValueError("Unreviewed structural conversion decision")
    for kind, entry in data["resources"].items():
        if (set(entry) != {"plural", "versions", "schema_sha256"} or entry["plural"] != kind.lower() + "s"
                or entry["versions"] != VERSIONS or not isinstance(entry["schema_sha256"], str) or len(entry["schema_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in entry["schema_sha256"])):
            raise ValueError("Unreviewed conversion resource or schema identity")
    return data


def validate_crd(crd, contract, *, live=False):
    spec = crd["spec"]
    kind = spec["names"]["kind"]
    entry = contract["resources"].get(kind)
    if entry is None:
        raise ValueError("Resource has no structural conversion decision")
    versions = spec["versions"]
    if (spec["group"] != contract["group"] or spec["scope"] != "Namespaced"
            or spec["names"]["plural"] != entry["plural"]
            or spec.get("conversion", {}).get("strategy", "None") != "None"
            or [v["name"] for v in versions] != entry["versions"]
            or any(v.get("served") is not True or v.get("deprecated", False) for v in versions)
            or len([v for v in versions if v.get("storage") is True]) != 1):
        raise ValueError("Served/storage/conversion contract differs from reviewed decision")
    if not live and next(v["name"] for v in versions if v["storage"]) != contract["default_storage"]:
        raise ValueError("Changing the default storage version requires a migration decision")
    for version in versions:
        if digest(version["schema"]["openAPIV3Schema"]) != entry["schema_sha256"]:
            raise ValueError(kind + ": conversion would lose or change a schema field/default/validation")
    for key in ("subresources", "selectableFields", "additionalPrinterColumns"):
        if versions[0].get(key) != versions[1].get(key):
            raise ValueError(kind + ": version-specific subresource or field-selector semantics")
    return entry

"""Compare reviewed stable CRD schemas without inventing a published predecessor."""
import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re

import yaml
import api_conversion_contract as conversion

ROOT = Path(__file__).resolve().parents[1]
POLICY = "docs/compatibility-policy.json"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def changes(before, after, path=""):
    result = []

    def changed(rule, old, new, field=path):
        result.append({"path": field or "$", "rule": rule, "old_hash": digest(old), "new_hash": digest(new)})

    for key in ("type", "format", "default", "x-kubernetes-list-type", "x-kubernetes-list-map-keys",
                "x-kubernetes-map-type", "x-kubernetes-preserve-unknown-fields", "nullable",
                "uniqueItems", "x-kubernetes-embedded-resource", "x-kubernetes-int-or-string"):
        if before.get(key) != after.get(key) or (key in before) != (key in after):
            changed(key, {"present": key in before, "value": before.get(key)}, {"present": key in after, "value": after.get(key)})
    for key in ("pattern", "x-kubernetes-validations", "oneOf", "anyOf", "allOf", "not", "multipleOf"):
        if before.get(key) != after.get(key):
            changed(key, before.get(key), after.get(key))
    for key, tighter in (("minimum", lambda old, new: new > old), ("exclusiveMinimum", lambda old, new: new > old),
                         ("minLength", lambda old, new: new > old), ("minItems", lambda old, new: new > old),
                         ("minProperties", lambda old, new: new > old), ("maximum", lambda old, new: new < old),
                         ("exclusiveMaximum", lambda old, new: new < old), ("maxLength", lambda old, new: new < old),
                         ("maxItems", lambda old, new: new < old), ("maxProperties", lambda old, new: new < old)):
        if key in after and (key not in before or tighter(before[key], after[key])):
            changed(key, before.get(key), after[key])
    old_enum, new_enum = before.get("enum"), after.get("enum")
    if new_enum is not None and (old_enum is None or any(item not in new_enum for item in old_enum)):
        changed("enum-narrowed", old_enum, new_enum)
    for field in sorted(set(after.get("required", [])) - set(before.get("required", []))):
        changed("required-added", False, True, path + "." + field if path else field)
    old_properties, new_properties = before.get("properties", {}), after.get("properties", {})
    for field in sorted(set(new_properties) - set(old_properties)):
        if "default" in new_properties[field]:
            child = path + "." + field if path else field
            changed("field-added-with-default", None, new_properties[field], child)
    for field in sorted(old_properties):
        child = path + "." + field if path else field
        if field not in new_properties:
            changed("field-removed", old_properties[field], None, child)
        else:
            result.extend(changes(old_properties[field], new_properties[field], child))
    if "items" in before:
        if "items" not in after:
            changed("items-removed", before["items"], None)
        else:
            result.extend(changes(before["items"], after["items"], path + "[]"))
    old_map, new_map = before.get("additionalProperties"), after.get("additionalProperties")
    if isinstance(old_map, dict) and isinstance(new_map, dict):
        result.extend(changes(old_map, new_map, path + "{}"))
    elif old_map != new_map:
        changed("additionalProperties", old_map, new_map)
    # New optional fields with a default also change previously absent stored values.
    for field in sorted(set(new_properties) - set(old_properties)):
        if "default" in new_properties[field]:
            changed("added-field-default", None, new_properties[field]["default"], path + "." + field if path else field)
    return result


def schemas(root=ROOT):
    entries = {}
    for path in sorted((root / "charts/hankoshell-operator/crds").glob("*.yaml")):
        item = yaml.safe_load(path.read_text())
        spec = item["spec"]
        for version in spec["versions"]:
            if version["served"]:
                key = spec["names"]["kind"] + "/" + version["name"]
                if key in entries:
                    raise ValueError("Duplicate served schema " + key)
                entries[key] = version["schema"]["openAPIV3Schema"]
    return entries


def local_file(root, name):
    if not isinstance(name, str):
        raise ValueError("Expected one repository evidence path")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Missing or external compatibility evidence")
    return path


def approved(change, key, policy, root, today):
    releases = policy["public_releases"]
    by_version = {entry["version"]: entry for entry in releases}
    for entry in policy["exceptions"]:
        if any(entry.get(field) != value for field, value in {"schema": key, **change}.items()):
            continue
        announcement = by_version.get(entry.get("announced_in"))
        if announcement is None:
            continue
        announced = date.fromisoformat(announcement["published_on"])
        subsequent = {(int(r["version"].split(".")[0]), int(r["version"].split(".")[1]))
                      for r in releases if date.fromisoformat(r["published_on"]) > announced and date.fromisoformat(r["published_on"]) <= today
                      and tuple(map(int, r["version"].split(".")[:2])) > tuple(map(int, entry["announced_in"].split(".")[:2]))}
        if len(subsequent) < policy["notice_rules"]["minimum_minor_releases"] or (today - announced).days < policy["notice_rules"]["minimum_days"]:
            continue
        if not re.fullmatch(r"https://github\.com/Alien6-Studio/hankoshell-operator/pull/[1-9][0-9]*", entry.get("review", "")):
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]{2,63}", entry.get("notice_id", "")):
            continue
        try:
            migration = local_file(root, entry.get("migration_note"))
        except ValueError:
            continue
        if migration.suffix != ".md" or not migration.read_text().strip():
            continue
        if not any(notice.get("id") == entry.get("notice_id") and notice.get("announced_in") == entry.get("announced_in")
                   and notice.get("schema") == key and notice.get("path") == change["path"] for notice in policy["notices"]):
            continue
        if entry.get("notice_id", "") not in (root / "CHANGELOG.md").read_text():
            continue
        return True
    return False


def compare(baseline, current, policy, root=ROOT, today=None):
    today = today or date.today()
    failures = []
    for key, old in sorted(baseline.items()):
        if key not in current:
            candidates = [{"path": "$", "rule": "served-version-removed", "old_hash": digest(old), "new_hash": digest(None)}]
        else:
            candidates = changes(old, current[key])
        for change in candidates:
            if not approved(change, key, policy, root, today):
                failures.append({"schema": key, **change})
    return failures


def check(root=ROOT):
    policy = json.loads((root / POLICY).read_text())
    current = schemas(root)
    version_contract = check_versions(root, policy)
    if not policy["baseline"]:
        if policy["public_releases"] or policy["notices"] or policy["exceptions"]:
            raise ValueError("Public compatibility claims require authentic retained release baselines")
        candidate = conversion.load(root, optional=True)
        reviewed = {kind + "/v1beta1" for kind in (candidate or {}).get("resources", {})}
        if any(re.fullmatch(r"v[1-9][0-9]*(?:beta[1-9][0-9]*)?", key.split("/")[1]) and key not in reviewed for key in current):
            raise ValueError("New stable API requires a reviewed conversion/baseline decision")
        return {"state": "NoPublishedPredecessor", "experimental_schemas": len(current), "stable_comparisons": 0}
    baseline_file = local_file(root, policy["baseline"]["path"])
    raw = baseline_file.read_bytes()
    if hashlib.sha256(raw).hexdigest() != policy["baseline"]["sha256"]:
        raise ValueError("Published compatibility baseline was altered")
    baseline = json.loads(raw)
    if baseline.get("published") is not True or baseline.get("version") not in {r["version"] for r in policy["public_releases"]}:
        raise ValueError("A candidate snapshot is not a published compatibility baseline")
    def storage_contract(inventory):
        return {kind: {"strategy": entry["strategy"], "versions": [{k: v[k] for k in ("name", "served", "storage")} for v in entry["versions"]]}
                for kind, entry in inventory.items()}
    if not baseline.get("version_contract") or storage_contract(baseline["version_contract"]) != storage_contract(version_contract):
        raise ValueError("Served/storage/conversion/deprecation contract changed; a reviewed migration is required")
    failures = compare(baseline["stable_schemas"], current, policy, root)
    if failures:
        raise ValueError("Stable schema compatibility refused: " + json.dumps(failures, sort_keys=True))
    return {"state": "compared", "stable_comparisons": len(baseline["stable_schemas"])}


def check_versions(root, policy):
    """Refuse unimplemented multi-version conversion and unannounced deprecation."""
    result = {}
    candidate = conversion.load(root, optional=True)
    for path in sorted((root / "charts/hankoshell-operator/crds").glob("*.yaml")):
        crd = yaml.safe_load(path.read_text())
        spec = crd["spec"]
        versions = spec["versions"]
        served = [v for v in versions if v["served"]]
        storage = [v for v in versions if v["storage"]]
        strategy = spec.get("conversion", {}).get("strategy", "None")
        reviewed = candidate and spec["names"]["kind"] in candidate["resources"]
        if reviewed:
            conversion.validate_crd(crd, candidate)
        if len(storage) != 1 or not storage[0]["served"] or not reviewed and len(served) != 1 or strategy != "None":
            raise ValueError(spec["names"]["kind"] + ": conversion/storage change requires #91 round-trip and #92 migration qualification")
        records = []
        for version in versions:
            deprecated = version.get("deprecated", False)
            warning = version.get("deprecationWarning")
            if warning is not None and not deprecated:
                raise ValueError("Deprecation warning without deprecated version: " + spec["names"]["kind"])
            key = spec["names"]["kind"] + "/" + version["name"]
            if deprecated:
                notices = [n for n in policy["notices"] if n.get("schema") == key and n.get("path") == "$version"]
                announced = False
                for notice in notices:
                    identifier = notice.get("id", "")
                    if (not re.fullmatch(r"[A-Z][A-Z0-9_-]{2,63}", identifier) or not warning or identifier not in warning
                            or identifier not in (root / "CHANGELOG.md").read_text()
                            or not re.fullmatch(r"https://github\.com/Alien6-Studio/hankoshell-operator/pull/[1-9][0-9]*", notice.get("review", ""))
                            or not any(r["version"] == notice.get("announced_in") and date.fromisoformat(r["published_on"]) <= date.today() for r in policy["public_releases"])):
                        continue
                    try:
                        migration = local_file(root, notice.get("migration_note"))
                    except ValueError:
                        continue
                    announced = migration.suffix == ".md" and bool(migration.read_text().strip())
                    if announced:
                        break
                if not announced:
                    raise ValueError("Unannounced or undocumented version deprecation: " + key)
            records.append({k: version.get(k) for k in ("name", "served", "storage", "deprecated", "deprecationWarning")})
        result[spec["names"]["kind"]] = {"strategy": strategy, "versions": records}
    if not result:
        raise ValueError("Missing CRD conversion inventory")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "snapshot"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "check":
        print(json.dumps(check(), sort_keys=True))
    else:
        if not args.output:
            parser.error("snapshot requires --output")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        policy = json.loads((ROOT / POLICY).read_text())
        args.output.write_text(json.dumps({"published": False, "state": "candidate-only", "schemas": schemas(), "version_contract": check_versions(ROOT, policy)}, indent=2) + "\n")


if __name__ == "__main__":
    main()

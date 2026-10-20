"""Apply reviewed admission bounds for imported fields and status evidence.

Paths and limits are explicit. Missing/changed types or conflicting constraints
fail generation; this never widens validation or changes a served version.
Only inserted schema keywords are rendered, preserving controller-gen output.
"""

import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[3]

LIMITS = {"minLength", "maxLength", "maxItems", "maxProperties", "pattern"}


def member(node, key):
    if not isinstance(node, yaml.MappingNode):
        raise ValueError("Expected a schema mapping")
    for name, value in node.value:
        if name.value == key:
            return value
    raise ValueError("Missing reviewed schema member: " + key)


def resolve(schema, path):
    if not re.fullmatch(r"(?:spec|status)(?:\.[A-Za-z][A-Za-z0-9]*|\[\]|\{\})+", path):
        raise ValueError("Invalid input-bound path")
    group, suffix = path.split(".", 1)
    node = member(member(schema, "properties"), group)
    for part in re.findall(r"\.[A-Za-z][A-Za-z0-9]*|\[\]|\{\}", "." + suffix):
        node = member(node, "items" if part == "[]" else "additionalProperties") if part in ("[]", "{}") else member(member(node, "properties"), part[1:])
    return node


def constrain(node, limits):
    current = yaml.safe_load(yaml.serialize(node))
    kind = current.get("type")
    integer_or_string = current.get("x-kubernetes-int-or-string") is True
    if not limits or set(limits) - LIMITS:
        raise ValueError("Unreviewed validation keyword")
    added = {}
    for key, value in limits.items():
        expected = "array" if key == "maxItems" else "object" if key == "maxProperties" else "string"
        if kind != expected and not (expected == "string" and integer_or_string):
            raise ValueError("Input-bound schema type changed")
        if key == "pattern":
            if not isinstance(value, str) or not value.startswith("^") or not value.endswith("$"):
                raise ValueError("Input-bound pattern must be anchored")
        elif type(value) is not int or not 0 < value <= 16384:
            raise ValueError("Invalid input bound")
        if key in current and current[key] != value:
            raise ValueError("Input bound conflicts with generated validation")
        if key not in current:
            added[key] = value
    return added


def apply(root=ROOT):
    entries, seen = {}, set()
    for group in ("input", "status"):
        policy = json.loads((root / ("api/schema-" + group + "-bounds.json")).read_text())
        if set(policy) != {"schemaVersion", "purpose", "bounds"} or policy["schemaVersion"] != 1:
            raise ValueError("Unknown input-bound policy")
        for entry in policy["bounds"]:
            prefix = "spec." if group == "input" else "status."
            if (set(entry) != {"kind", "path", "limits"} or not entry["path"].startswith(prefix)
                    or (entry["kind"], entry["path"]) in seen):
                raise ValueError("Duplicate or invalid input-bound entry")
            seen.add((entry["kind"], entry["path"]))
            entries.setdefault(entry["kind"], []).append(entry)
    changes, found, count = {}, set(), 0
    for path in sorted((root / "charts/hankoshell-operator/crds").glob("*.yaml")):
        text = path.read_text()
        document = yaml.compose(text)
        spec = member(document, "spec")
        kind = member(member(spec, "names"), "kind").value
        if kind not in entries:
            continue
        found.add(kind)
        insertions = {}
        for version in member(spec, "versions").value:
            schema = member(member(version, "schema"), "openAPIV3Schema")
            for entry in entries[kind]:
                node = resolve(schema, entry["path"])
                added = constrain(node, entry["limits"])
                if added:
                    offset = node.start_mark.index - node.start_mark.column
                    if offset in insertions:
                        raise ValueError("Overlapping schema insertions")
                    indent = " " * node.start_mark.column
                    insertions[offset] = "".join(indent + key + ": " + json.dumps(value) + "\n" for key, value in sorted(added.items()))
                count += 1
        for offset, inserted in sorted(insertions.items(), reverse=True):
            text = text[:offset] + inserted + text[offset:]
        changes[path] = text
    if found != set(entries):
        raise ValueError("Input-bound policy names an absent CRD")
    # Validate every input first, then write. A stale policy cannot partially
    # update an otherwise freshly generated CRD set.
    for path, text in changes.items():
        if path.read_text() != text:
            path.write_text(text)
    return count


if __name__ == "__main__":
    print(json.dumps({"reviewed_input_bounds": apply()}))

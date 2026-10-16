import copy
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("compatibility_gate", Path(__file__).with_name("compatibility-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SCHEMA = {"type": "object", "properties": {"spec": {"type": "object", "properties": {
    "name": {"type": "string", "default": "before", "pattern": ".*"},
    "mode": {"type": "string", "enum": ["Observe", "Manage"]},
    "items": {"type": "array", "x-kubernetes-list-type": "map", "x-kubernetes-list-map-keys": ["name"], "items": {"type": "object"}},
}}}}


class CompatibilityGateTests(unittest.TestCase):
    def test_current_alpha_does_not_fabricate_stable_history(self):
        self.assertEqual(gate.check(), {"state": "NoPublishedPredecessor", "experimental_schemas": 17, "stable_comparisons": 0})

    def test_breaking_changes_name_the_precise_field(self):
        for change in ("rename", "required", "default", "enum", "pattern", "listType", "listKey", "type", "maxLength", "validation"):
            with self.subTest(change=change):
                new = copy.deepcopy(SCHEMA)
                spec = new["properties"]["spec"]
                fields = spec["properties"]
                if change == "rename": fields["replacement"] = fields.pop("name")
                elif change == "required": spec["required"] = ["name"]
                elif change == "default": fields["name"]["default"] = "after"
                elif change == "enum": fields["mode"]["enum"] = ["Observe"]
                elif change == "pattern": fields["name"]["pattern"] = "^[a-z]+$"
                elif change == "listType": fields["items"]["x-kubernetes-list-type"] = "atomic"
                elif change == "listKey": fields["items"]["x-kubernetes-list-map-keys"] = ["id"]
                elif change == "type": fields["name"]["type"] = "integer"
                elif change == "maxLength": fields["name"]["maxLength"] = 8
                else: fields["name"]["x-kubernetes-validations"] = [{"rule": "self != 'x'"}]
                failures = gate.compare({"HankoExample/v1": SCHEMA}, {"HankoExample/v1": new}, {"public_releases": [], "exceptions": []})
                self.assertTrue(failures)
                self.assertTrue(all(item["path"].startswith("spec.") for item in failures))

    def test_optional_additions_enum_expansion_and_bound_relaxation_are_safe(self):
        new = copy.deepcopy(SCHEMA)
        new["properties"]["spec"]["properties"]["optional"] = {"type": "string"}
        new["properties"]["spec"]["properties"]["mode"]["enum"].append("NewMode")
        self.assertEqual(gate.changes(SCHEMA, new), [])
        self.assertEqual(gate.changes({"type": "string", "maxLength": 8}, {"type": "string", "maxLength": 16}), [])
        self.assertTrue(gate.changes({"type": "string"}, {"type": "string", "default": None}))

    def test_exception_requires_real_notice_both_waits_hash_binding_and_migration(self):
        new = copy.deepcopy(SCHEMA)
        new["properties"]["spec"]["properties"]["mode"]["enum"] = ["Observe"]
        change = gate.changes(SCHEMA, new)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "migration.md").write_text("Reviewed migration and rollback limits")
            (root / "CHANGELOG.md").write_text("Deprecation DEP-1")
            policy = {"notice_rules": {"minimum_minor_releases": 2, "minimum_days": 90},
                      "public_releases": [{"version": "0.1.0", "published_on": "2026-01-01"}, {"version": "0.2.0", "published_on": "2026-02-01"}, {"version": "0.3.0", "published_on": "2026-03-01"}],
                      "notices": [{"id": "DEP-1", "announced_in": "0.1.0", "schema": "HankoExample/v1", "path": change["path"]}],
                      "exceptions": [{"schema": "HankoExample/v1", **change, "notice_id": "DEP-1", "announced_in": "0.1.0", "migration_note": "migration.md", "review": "https://github.com/Alien6-Studio/hankoshell-operator/pull/123"}]}
            self.assertFalse(gate.compare({"HankoExample/v1": SCHEMA}, {"HankoExample/v1": new}, policy, root, date(2026, 4, 5)))
            for mutation in ("days", "releases", "patch-not-minor", "hash", "review", "notice", "changelog"):
                with self.subTest(mutation=mutation):
                    current = copy.deepcopy(policy)
                    today = date(2026, 4, 5)
                    if mutation == "days": today = date(2026, 3, 5)
                    elif mutation == "releases": current["public_releases"].pop()
                    elif mutation == "patch-not-minor": current["public_releases"][2]["version"] = "0.1.1"
                    elif mutation == "hash": current["exceptions"][0]["new_hash"] = "0"*64
                    elif mutation == "review": current["exceptions"][0]["review"] = "self-approved"
                    elif mutation == "notice": current["notices"] = []
                    else: (root / "CHANGELOG.md").write_text("No notice")
                    self.assertTrue(gate.compare({"HankoExample/v1": SCHEMA}, {"HankoExample/v1": new}, current, root, today))

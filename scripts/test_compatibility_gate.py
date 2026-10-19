import copy
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import yaml

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
        self.assertEqual(gate.check(), {"state": "NoPublishedPredecessor", "experimental_schemas": 20, "stable_comparisons": 0})

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
        new["properties"]["spec"]["properties"]["optional"]["default"] = "changes-reader-behaviour"
        self.assertEqual(gate.changes(SCHEMA, new)[0]["rule"], "field-added-with-default")

    def test_conversion_storage_and_deprecation_metadata_cannot_silently_drift(self):
        policy = {"notices": [], "public_releases": []}
        original = {"spec": {"names": {"kind": "HankoExample"}, "versions": [{"name": "v1alpha1", "served": True, "storage": True}], "conversion": {"strategy": "None"}}}
        for mutation in ("none", "webhook", "second-version", "unserved-storage", "no-storage", "deprecated", "orphan-warning"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                folder = root / "charts/hankoshell-operator/crds"
                folder.mkdir(parents=True)
                value = copy.deepcopy(original)
                version = value["spec"]["versions"][0]
                if mutation == "webhook": value["spec"]["conversion"]["strategy"] = "Webhook"
                elif mutation == "second-version": value["spec"]["versions"].append({"name": "v1", "served": True, "storage": False})
                elif mutation == "unserved-storage": version["served"] = False
                elif mutation == "no-storage": version["storage"] = False
                elif mutation == "deprecated": version["deprecated"] = True
                elif mutation == "orphan-warning": version["deprecationWarning"] = "Unannounced"
                (folder / "example.yaml").write_text(yaml.safe_dump(value))
                if mutation == "none": self.assertEqual(len(gate.check_versions(root, policy)), 1)
                else:
                    with self.assertRaises(ValueError): gate.check_versions(root, policy)

    def test_version_notice_needs_real_announcement_review_and_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "charts/hankoshell-operator/crds"
            folder.mkdir(parents=True)
            (folder / "example.yaml").write_text(yaml.safe_dump({"spec": {"names": {"kind": "HankoExample"}, "versions": [
                {"name": "v1alpha1", "served": True, "storage": True, "deprecated": True, "deprecationWarning": "DEP-1: reviewed replacement"}]}}))
            (root / "CHANGELOG.md").write_text("Announce DEP-1")
            (root / "migration.md").write_text("Reviewed replacement, upgrade and rollback")
            policy = {"public_releases": [{"version": "0.1.0", "published_on": "2026-01-01"}], "notices": [
                {"id": "DEP-1", "schema": "HankoExample/v1alpha1", "path": "$version", "announced_in": "0.1.0",
                 "review": "https://github.com/Alien6-Studio/hankoshell-operator/pull/123", "migration_note": "migration.md"}]}
            self.assertEqual(len(gate.check_versions(root, policy)), 1)
            for field, value in (("id", ""), ("announced_in", "9.9.9"), ("review", "self-approved"), ("migration_note", "missing.md")):
                current = copy.deepcopy(policy)
                current["notices"][0][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError): gate.check_versions(root, current)

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
            for mutation in ("days", "releases", "patch-not-minor", "hash", "review", "notice", "empty-notice", "changelog"):
                with self.subTest(mutation=mutation):
                    current = copy.deepcopy(policy)
                    today = date(2026, 4, 5)
                    if mutation == "days": today = date(2026, 3, 5)
                    elif mutation == "releases": current["public_releases"].pop()
                    elif mutation == "patch-not-minor": current["public_releases"][2]["version"] = "0.1.1"
                    elif mutation == "hash": current["exceptions"][0]["new_hash"] = "0"*64
                    elif mutation == "review": current["exceptions"][0]["review"] = "self-approved"
                    elif mutation == "notice": current["notices"] = []
                    elif mutation == "empty-notice":
                        current["notices"][0]["id"] = ""
                        current["exceptions"][0]["notice_id"] = ""
                    else: (root / "CHANGELOG.md").write_text("No notice")
                    self.assertTrue(gate.compare({"HankoExample/v1": SCHEMA}, {"HankoExample/v1": new}, current, root, today))

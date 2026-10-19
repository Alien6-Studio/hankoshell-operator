import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("security_surface", Path(__file__).with_name("security-surface.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def roles(rule):
    return [{"kind": "Role", "metadata": {"name": "operator", "namespace": "auth"}, "rules": [rule]},
            {"kind": "RoleBinding", "metadata": {"name": "operator", "namespace": "auth"},
             "roleRef": {"kind": "Role", "name": "operator", "apiGroup": "rbac.authorization.k8s.io"},
             "subjects": [{"kind": "ServiceAccount", "name": "operator", "namespace": "auth"}]}]


class SecuritySurfaceTests(unittest.TestCase):
    def test_unbounded_new_inputs_cannot_be_added_to_the_inventory(self):
        schema = {"Thing/v1": {"nodes": gate.schema_nodes({"type": "object", "properties": {
            "values": {"type": "array", "maxItems": 2, "items": {"type": "string"}}}}, "spec")}}
        with self.assertRaisesRegex(ValueError, r"spec.values\[\]"):
            gate.check_input_bounds(schema)
        schema["Thing/v1"]["nodes"]["spec.values[]"] = gate.schema_nodes({"type": "string", "maxLength": 10}, "spec.values[]")["spec.values[]"]
        schema["Thing/v1"]["nodes"].update(gate.schema_nodes({"type": "string"}, "status.legacy"))
        with self.assertRaisesRegex(ValueError, "status.legacy"):
            gate.check_input_bounds(schema)
        schema["Thing/v1"]["nodes"]["status.legacy"] = gate.schema_nodes({"type": "string", "maxLength": 64}, "status.legacy")["status.legacy"]
        gate.check_input_bounds(schema)

    def test_nested_maps_lists_and_enum_bounds_are_inventoried(self):
        schema = {"type": "object", "properties": {
            "list": {"type": "array", "maxItems": 2, "items": {"type": "string", "maxLength": 10}},
            "map": {"type": "object", "additionalProperties": {"type": "string"}},
            "mode": {"type": "string", "enum": ["Observe", "Manage"]}}}
        nodes = gate.schema_nodes(schema, "spec")
        self.assertEqual(set(nodes), {"spec.list", "spec.list[]", "spec.map", "spec.map{}", "spec.mode"})
        self.assertEqual({k for k, v in nodes.items() if v["missing_explicit_bound"]}, {"spec.map", "spec.map{}"})

    def test_lowered_removed_and_changed_bounds_name_the_field(self):
        before = {"schemas": {"Thing/v1": {"schema_sha256": "a", "nodes": gate.schema_nodes(
            {"type": "string", "maxLength": 253, "pattern": "^[a-z]+$"}, "spec.realmRef")}}, "rbac": {}}
        for limits in ({}, {"maxLength": 254}, {"maxLength": 253, "pattern": "^.*$"}):
            changed = copy.deepcopy(before)
            changed["schemas"]["Thing/v1"]["nodes"]["spec.realmRef"]["limits"] = limits
            self.assertIn("Thing/v1:spec.realmRef", gate.drift(before, changed))
        self.assertEqual(gate.drift(before, copy.deepcopy(before)), [])

    def test_inventory_cannot_claim_a_completed_audit(self):
        before = {"schemaVersion": 1, "stage": "development-inventory-not-security-acceptance", "schemas": {}, "rbac": {}}
        after = {**before, "stage": "accepted"}
        self.assertEqual(gate.drift(before, after), ["inventory metadata"])

    def test_binding_or_non_leaf_validation_drift_is_not_hidden(self):
        before = {"schemas": {"Thing/v1": {"schema_sha256": "a", "nodes": {}}}, "rbac": {"standard": {"bindings": []}}}
        changed = copy.deepcopy(before)
        changed["schemas"]["Thing/v1"]["schema_sha256"] = "b"
        changed["rbac"]["standard"]["bindings"] = [{"subjects": ["foreign-account"]}]
        self.assertEqual(gate.drift(before, changed), ["Thing/v1:schema", "RBAC:standard"])

    def test_lease_privileges_cannot_expand_or_lose_the_name(self):
        rule = {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"],
                "resourceNames": ["hanko-operator.hanko.sh"], "verbs": ["get", "update"]}
        self.assertEqual(len(gate.rbac(roles(rule))["rules"]), 1)
        for change in ({"resourceNames": []}, {"verbs": ["get", "list", "update"]},
                       {"verbs": ["get", "patch", "update"]}, {"resourceNames": ["foreign-lock"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.rbac(roles({**rule, **change}))
        self.assertEqual(len(gate.rbac(roles({"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["create"]}))["rules"]), 1)

    def test_runtime_identity_wildcards_and_named_create_fail(self):
        for change in ({"verbs": ["*"]}, {"resources": ["*"]}, {"apiGroups": ["*"]},
                       {"resources": ["serviceaccounts/token"]}, {"resources": ["tokenreviews"]},
                       {"verbs": ["impersonate"]}, {"verbs": ["bind"]}, {"verbs": ["escalate"]},
                       {"resourceNames": ["apparently-scoped"], "verbs": ["create"]}):
            rule = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.rbac(roles(rule))

    def test_custom_resource_grants_cannot_restore_the_bulk_writer(self):
        for resource, verb in (("hankoissuers", "patch"), ("hankomeshservices", "create"),
                               ("hankoroles", "delete"), ("hankooperations", "create"),
                               ("hankoimports", "update"), ("hankoworkloadtrusts", "create"),
                               ("hankorealms", "deletecollection"), ("hankoissuers/finalizers", "update")):
            with self.subTest(resource=resource, verb=verb), self.assertRaises(ValueError):
                gate.rbac(roles({"apiGroups": ["hanko.sh"], "resources": [resource], "verbs": [verb]}))
        for resource, verb in (("hankoissuers/status", "patch"), ("hankoroles", "create"),
                               ("hankorealms", "delete"), ("hankotenants", "delete"),
                               ("hankokeycloakinstances", "create")):
            self.assertEqual(len(gate.rbac(roles({"apiGroups": ["hanko.sh"], "resources": [resource], "verbs": [verb]}))["rules"]), 1)

    def test_unreviewed_nonresource_paths_and_empty_roles_fail(self):
        for urls in (["/*"], ["/private"]):
            with self.assertRaises(ValueError):
                gate.rbac(roles({"nonResourceURLs": urls, "verbs": ["get"]}))
        with self.assertRaises(ValueError):
            gate.rbac([])

    def test_all_current_fields_have_an_explicit_review_record(self):
        baseline = json.loads(gate.BASELINE.read_text())
        self.assertEqual(baseline["schemas"], gate.schemas())
        self.assertEqual(set(baseline["rbac"]), set(gate.PROFILES))
        self.assertEqual(gate.summary(baseline)["served_schemas"], 20)
        for profile in baseline["rbac"].values():
            for row in profile["rules"]:
                self.assertTrue(row["justification"])
        self.assertIn("python3 scripts/security-surface.py check", (gate.ROOT / "Makefile").read_text())


if __name__ == "__main__":
    unittest.main()

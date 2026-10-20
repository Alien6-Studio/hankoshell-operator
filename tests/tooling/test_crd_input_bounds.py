import importlib.util
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("crd_input_bounds", ROOT / 'tools/qualification/checks/crd_input_bounds.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class InputBoundsTests(unittest.TestCase):
    def test_imported_integer_or_string_keeps_its_union_and_pattern(self):
        value = {"anyOf": [{"type": "integer"}, {"type": "string"}], "pattern": "native-quantity", "x-kubernetes-int-or-string": True}
        node = yaml.compose(yaml.safe_dump(value))
        self.assertEqual(gate.constrain(node, {"maxLength": 64}), {"maxLength": 64})
        self.assertEqual(yaml.safe_load(yaml.serialize(node)), value)

    def test_conflicting_or_wrong_type_constraints_are_not_overwritten(self):
        for current, change in (({"type": "string", "maxLength": 8}, {"maxLength": 9}),
                                ({"type": "integer"}, {"maxLength": 8}),
                                ({"type": "string"}, {"pattern": ".*"}),
                                ({"type": "string"}, {"default": "unsafe"})):
            with self.subTest(current=current, change=change), self.assertRaises(ValueError):
                gate.constrain(yaml.compose(yaml.safe_dump(current)), change)

    def test_application_is_idempotent_and_a_stale_policy_cannot_partially_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("api/schema-input-bounds.json", "api/schema-status-bounds.json", *[str(p.relative_to(gate.ROOT)) for p in (gate.ROOT / "charts/hankoshell-operator/crds").glob("*.yaml")]):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((gate.ROOT / name).read_bytes())
            before = {p: p.read_bytes() for p in (root / "charts/hankoshell-operator/crds").glob("*.yaml")}
            self.assertGreater(gate.apply(root), 20)
            self.assertEqual({p: p.read_bytes() for p in before}, before)
            import json
            path = root / "api/schema-input-bounds.json"
            policy = json.loads(path.read_text())
            # Simulate fresh generator output without the first imported
            # constraint, followed by a stale path in a later CRD.
            first = root / "charts/hankoshell-operator/crds/hanko.sh_hankoapplications.yaml"
            crd = yaml.safe_load(first.read_text())
            for version in crd["spec"]["versions"]:
                version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["attributes"]["additionalProperties"].pop("maxLength")
            first.write_text(yaml.safe_dump(crd))
            before[first] = first.read_bytes()
            policy["bounds"][-1]["path"] = "spec.removed"
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                gate.apply(root)
            self.assertEqual({p: p.read_bytes() for p in before}, before)


if __name__ == "__main__":
    unittest.main()

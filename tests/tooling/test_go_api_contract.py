import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("go_api_contract", ROOT / 'tools/qualification/checks/go_api_contract.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class GoAPIContractTests(unittest.TestCase):
    def fixture(self, root):
        (root / "docs/contracts").mkdir(parents=True)
        current = {"example.test/api": {"Value": "type struct{Name string}", "*Value.Read": "func() error", "Format": "const untyped int = 1"}}
        raw = json.dumps({"published": False, "go_api": current}).encode()
        (root / "docs/contracts/api.json").write_bytes(raw)
        config = {"schema": 1, "state": "development-fixture-contract", "packages": ["./api"],
                  "baseline": {"path": "docs/contracts/api.json", "sha256": hashlib.sha256(raw).hexdigest()}}
        (root / api.CONFIG).write_text(json.dumps(config))
        (root / api.gate.POLICY).write_text(json.dumps({"baseline": None}))
        return current, config

    def test_optional_exports_are_additive_but_removal_and_changes_name_the_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, _ = self.fixture(root)
            self.assertEqual(api.check(root, current)["exports"], 3)
            additional = copy.deepcopy(current)
            additional["example.test/api"]["New"] = "func()"
            self.assertEqual(api.check(root, additional)["exports"], 4)
            for name in current["example.test/api"]:
                for mode in ("removed", "changed"):
                    with self.subTest(name=name, mode=mode):
                        changed = copy.deepcopy(current)
                        if mode == "removed": changed["example.test/api"].pop(name)
                        else: changed["example.test/api"][name] += " changed"
                        with self.assertRaisesRegex(ValueError, name.replace("*", r"\*")):
                            api.check(root, changed)

    def test_altered_candidate_and_fabricated_public_baseline_fail(self):
        for mutation in ("hash", "published", "missing-public-api"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                current, config = self.fixture(root)
                if mutation == "hash":
                    (root / config["baseline"]["path"]).write_text("{}")
                elif mutation == "published":
                    raw = json.dumps({"published": True, "go_api": current}).encode()
                    (root / config["baseline"]["path"]).write_bytes(raw)
                    config["baseline"]["sha256"] = hashlib.sha256(raw).hexdigest()
                    (root / api.CONFIG).write_text(json.dumps(config))
                else:
                    raw = json.dumps({"published": True, "stable_schemas": {}}).encode()
                    (root / "docs/public.json").write_bytes(raw)
                    (root / api.gate.POLICY).write_text(json.dumps({"baseline": {"path": "docs/public.json", "sha256": hashlib.sha256(raw).hexdigest()}}))
                with self.assertRaises(ValueError):
                    api.check(root, current)

    def test_exact_package_selection_precedes_compiler_execution(self):
        for packages in ([], ["./..."], ["../foreign"], ["./api", "./api"], ["./api\n"]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                api.capture(Path.cwd(), packages)

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location("public_contract", Path(__file__).with_name("public-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class PublicContractTests(unittest.TestCase):
    def fixture(self, root):
        data = contract.selection()
        inventory = contract.support.inventory()
        files = {"docs/public-contract-selection.json", "docs/public-contract-selection.md", "docs/api-support.json",
                 "README.md", "charts/hankoshell-operator/README.md", "docs/api-migration-policy.md"}
        files.update(p["evidence"] for p in inventory["resources"] + inventory["features"])
        files.update(p for r in data["resources"] for p in r["evidence"])
        files.update(str(p.relative_to(contract.ROOT)) for p in (contract.ROOT / "charts/hankoshell-operator/crds").glob("*.yaml"))
        files.update(str(p.relative_to(contract.ROOT)) for p in (contract.ROOT / "internal/iamconformance/testdata/public-0.1.0").rglob("*.json"))
        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(contract.ROOT / name, target)
        return data

    def test_complete_selection_and_real_corpus_match(self):
        data = contract.check()
        self.assertEqual(len(data["resources"]), 17)
        self.assertEqual(sum(len(r["spec"]) + len(r["status"]) for r in data["resources"]), 352)

    def test_unreviewed_promotion_and_field_exclusions_fail(self):
        for change in ("promote", "missing-field", "native", "nested-path", "fake-publication"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = self.fixture(root)
                if change == "promote":
                    next(r for r in data["resources"] if r["kind"] == "HankoTenant")["classification"] = "public"
                elif change == "missing-field":
                    data["resources"][0]["spec"].pop("clientID")
                elif change == "native":
                    data["resources"][0]["publicNativeSpecFields"] = []
                elif change == "nested-path":
                    data["nestedExclusions"][0]["path"] = "spec.permissions[].invented"
                elif change == "fake-publication":
                    data["published"] = True
                (root / "docs/public-contract-selection.json").write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    contract.check(root)

    def test_schema_default_enum_and_topology_drift_name_the_resource(self):
        for change in ("remove", "default", "enum", "topology", "pattern"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = self.fixture(root)
                path = root / "charts/hankoshell-operator/crds/hanko.sh_hankoapplications.yaml"
                crd = yaml.safe_load(path.read_text())
                schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
                if change == "remove":
                    del schema["redirectURIs"]
                elif change == "default":
                    schema["protocol"]["default"] = "saml"
                elif change == "enum":
                    schema["protocol"]["enum"] = ["oidc"]
                elif change == "topology":
                    schema["redirectURIs"]["x-kubernetes-list-type"] = "atomic"
                elif change == "pattern":
                    schema["clientID"]["pattern"] = "^new-restriction$"
                path.write_text(yaml.safe_dump(crd))
                with self.assertRaisesRegex(ValueError, "HankoApplication"):
                    contract.corpus(root, data)

    def test_no_predecessor_or_missing_field_coverage_can_be_reported_as_qualified(self):
        for change in ("invented-predecessor", "missing-status", "missing-domain", "empty-plan"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = self.fixture(root)
                path = root / "internal/iamconformance/testdata/public-0.1.0/corpus.json"
                corpus = json.loads(path.read_text())
                if change == "invented-predecessor":
                    corpus["predecessor"] = "0.0.0"
                elif change == "missing-status":
                    for fixture in corpus["fixtures"]:
                        fixture["status"].pop("contractVersion", None)
                elif change == "missing-domain":
                    corpus["fixtures"] = [f for f in corpus["fixtures"] if f["kind"] != "HankoRole"]
                elif change == "empty-plan":
                    corpus["fixtures"][0]["identity"]["plan"] = ""
                path.write_text(json.dumps(corpus))
                with self.assertRaises(ValueError):
                    contract.corpus(root, data)


if __name__ == "__main__":
    unittest.main()

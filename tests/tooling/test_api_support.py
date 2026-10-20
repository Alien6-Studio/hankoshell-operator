import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("api_support", ROOT / 'tools/qualification/checks/api_support.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class APISupportTests(unittest.TestCase):
    def fixture(self, root):
        data = support.inventory()
        files = {"docs/api-conversion.json", "docs/api-support.json", "docs/api-support.md", "README.md",
                 "charts/hankoshell-operator/README.md", "CHANGELOG.md"}
        files.update(item["evidence"] for item in data["resources"] + data["features"])
        files.update(str(p.relative_to(support.ROOT)) for p in (support.ROOT / "charts/hankoshell-operator/crds").glob("*.yaml"))
        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(support.ROOT / name, target)
        return data

    def test_reviewed_inventory_matches_all_resources_and_field_groups(self):
        data = support.check()
        self.assertEqual(len(data["resources"]), 17)
        self.assertEqual({r["surface"] for r in data["resources"]}, support.SURFACES)

    def test_unreviewed_inventory_or_schema_changes_fail_the_gate(self):
        for mutation in ("missing-resource", "missing-spec-group", "new-status-group", "native-boundary",
                         "future-public-promise", "removed-capability", "missing-evidence"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = self.fixture(root)
                if mutation == "missing-resource":
                    data["resources"].pop()
                elif mutation == "missing-spec-group":
                    data["resources"][0]["specFields"].pop()
                elif mutation == "new-status-group":
                    path = root / "charts/hankoshell-operator/crds/hanko.sh_hankorealms.yaml"
                    crd = yaml.safe_load(path.read_text())
                    crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"]["unreviewed"] = {"type": "string"}
                    path.write_text(yaml.safe_dump(crd))
                elif mutation == "native-boundary":
                    data["resources"][0]["nativeSpecFields"].append("not-a-field")
                elif mutation == "future-public-promise":
                    data["compatibility"] = "public"
                elif mutation == "removed-capability":
                    data["features"] = [f for f in data["features"] if f["name"] != "Second IAM provider"]
                elif mutation == "missing-evidence":
                    data["resources"][0]["evidence"] = "docs/missing-contract.md"
                (root / "docs/api-support.json").write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    support.check(root)

    def test_documentation_drift_and_missing_experimental_notes_fail_the_gate(self):
        for name in ("README.md", "charts/hankoshell-operator/README.md", "docs/api-support.md", "CHANGELOG.md"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / name
                text = path.read_text()
                if name == "CHANGELOG.md":
                    text = text.replace("Experimental surfaces:", "Features:")
                else:
                    text = text.replace(support.START, support.START + "\nUnreviewed compatibility promise", 1)
                path.write_text(text)
                with self.assertRaises(ValueError):
                    support.check(root)

    def test_release_packaging_invokes_the_support_gate(self):
        spec = importlib.util.spec_from_file_location("support_release_contract", support.ROOT / "tools/qualification/checks/release_contract.py")
        release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release)
        with patch.object(release.support, "check", side_effect=ValueError("classification drift")):
            with self.assertRaisesRegex(ValueError, "classification drift"):
                release.check()


if __name__ == "__main__":
    unittest.main()

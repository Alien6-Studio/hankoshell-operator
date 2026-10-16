import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("stable", Path(__file__).with_name("stable-contract.py"))
stable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stable)


class StableContractTests(unittest.TestCase):
    def fixture(self, root):
        shutil.copytree(stable.ROOT / "docs", root / "docs")
        files = ["README.md", "charts/hankoshell-operator/README.md", "versions.json", "SECURITY.md",
                 "scripts/system-test.py", "internal/iamconformance/testdata/portable-v1/corpus.json"]
        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(stable.ROOT / name, target)

    def test_every_resource_and_semantic_has_an_honest_record(self):
        records, review = stable.check()
        self.assertEqual(len(records["resources"]), 17)
        self.assertEqual(len(review["semantics"]), 14)
        self.assertEqual(len(review["installedEvidence"]), 6)
        self.assertEqual([s["fixture"] for s in review["semantics"] if s["decision"] == "portable-candidate"], ["spa", "web"])

    def test_graduation_cannot_hide_missing_fields_evidence_or_blockers(self):
        for mutation in ("resource", "spec", "status", "native", "stable", "criteria", "blockers", "evidence", "production"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / "docs/stable-graduation.json"
                data = json.loads(path.read_text())
                record = data["resources"][0]
                if mutation == "resource":
                    data["resources"].pop()
                elif mutation in ("spec", "status"):
                    record[mutation + "Groups"].pop(next(iter(record[mutation + "Groups"])))
                elif mutation == "native":
                    record["specGroups"]["attributes"]["providerNative"] = False
                elif mutation == "stable":
                    record["disposition"] = "graduating"
                elif mutation == "criteria":
                    record["criteria"].pop()
                elif mutation == "blockers":
                    record["blockers"] = []
                elif mutation == "evidence":
                    record["evidence"] = ["../foreign.json"]
                elif mutation == "production":
                    record["productionEvidence"] = ["synthetic-fixture"]
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    stable.check(root)

    def test_unsupported_lossy_stale_or_partial_evidence_cannot_become_portable(self):
        for mutation in ("unsupported", "outcome", "golden", "corpus", "cell", "partial", "source", "report", "loss", "support"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / "docs/stable-provider-review.json"
                data = json.loads(path.read_text())
                if mutation == "unsupported":
                    data["semantics"][0]["decision"] = "portable-candidate"
                elif mutation == "outcome":
                    data["semantics"][0]["providers"]["authentik"] = "lossless"
                elif mutation == "golden":
                    data["semantics"][2]["intentIdentity"] = "sha256:" + "f" * 64
                elif mutation == "corpus":
                    corpus = root / data["corpus"]
                    corpus.write_text(corpus.read_text() + "\n")
                elif mutation == "cell":
                    data["installedEvidence"].pop()
                elif mutation in ("partial", "source", "report"):
                    report = root / data["installedEvidence"][0]
                    value = json.loads(report.read_text())
                    if mutation == "partial":
                        value["complete"] = False
                    elif mutation == "source":
                        value["revision"] = "0" * 40
                    else:
                        value["differences"].pop()
                    report.write_text(json.dumps(value))
                elif mutation == "loss":
                    data["approvedLosses"] = ["silently accepted"]
                elif mutation == "support":
                    data["secondProviderStatus"] = "production"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    stable.check(root)

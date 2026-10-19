import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("operations_contract", Path(__file__).with_name("operations-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class OperationalContractTests(unittest.TestCase):
    def fixture(self, root):
        for name in ("internal", "cmd", "api", "docs", "scripts"):
            shutil.copytree(contract.ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
        chart = root / "charts/hankoshell-operator"
        chart.mkdir(parents=True)
        shutil.copyfile(contract.ROOT / "charts/hankoshell-operator/README.md", chart / "README.md")
        shutil.copyfile(contract.ROOT / "README.md", root / "README.md")

    def test_reviewed_operational_inventory(self):
        self.assertEqual(len(contract.check()["metrics"]), 11)

    def test_release_contract_rejects_output_or_runbook_divergence(self):
        active_report = json.loads((contract.ROOT / "docs/operational-contract.json").read_text())["installedEvidence"][0]["report"]
        mutations = [
            (active_report, '"result": "pass"', '"result": "fail"'),
            ("internal/observability/metrics.go", "hanko_operator_reconcile_total", "hanko_operator_unreviewed_total"),
            ("internal/observability/metrics.go", '[]string{"kind", "outcome"}', '[]string{"object", "outcome"}'),
            ("internal/observability/events.go", '"ClientCreated"', '"UnreviewedReason"'),
            ("scripts/fleet-installed-test.py", '"BundleTenantConflict"', '"BundleUnreviewedConflict"'),
            ("cmd/operator/main.go", "observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName))", "mgr.GetEventRecorder(operatorRecorderName)"),
            ("internal/controller/hankoapplication_controller.go", 'observeReconciler("HankoApplication", scheduleIAMReconciler(r))', "scheduleIAMReconciler(r)"),
            ("README.md", "operations-runbooks.md", "missing-runbooks.md"),
            ("docs/operations-runbooks.md", "AuditRecorderUnavailable", "UnreviewedState"),
            ("scripts/evidence_privacy.py", 'value.find("eyJ")', 'value.find("other-marker")'),
        ]
        for name, before, after in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / name
                original = path.read_text()
                self.assertIn(before, original)
                path.write_text(original.replace(before, after))
                with self.assertRaises(ValueError):
                    contract.check(root)

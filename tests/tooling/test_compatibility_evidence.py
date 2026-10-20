import copy
from datetime import date
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("compatibility_evidence", ROOT / 'tools/qualification/checks/compatibility_evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class CompatibilityEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        (root / "docs").mkdir()
        # Synthetic public releases exist only in this unit-test directory.
        (root / "docs/compatibility-policy.json").write_text(json.dumps({"public_releases": [
            {"version": "0.1.0", "published_on": "2025-01-01"}, {"version": "0.2.0", "published_on": "2025-02-01"},
            {"version": "0.3.0", "published_on": "2025-03-01"}]}))
        (root / "docs/api-support.json").write_text(json.dumps({"resources": [{"kind": "HankoApplication"}]}))
        report = {"id": "EVID-0001", "installation": "installation-0123456789abcdef", "reported_on": "2025-02-02",
                  "source_issue": evidence.GITHUB + "/issues/123", "review": evidence.GITHUB + "/pull/124", "mode": "standalone",
                  "from_version": "0.1.0", "to_version": "0.2.0", "kubernetes": "1.35.0", "keycloak": "26.7.5",
                  "resources": ["HankoApplication"], "scenarios": ["upgrade", "rollback"], "outcome": "limited",
                  "incidents": [{"id": "INC-0001", "issue": evidence.GITHUB + "/issues/125", "status": "open", "resolution": None}],
                  "migration": "planned", "fixtures": [], "privacy_review": {k: True for k in evidence.REVIEW_CHECKS}}
        self.save(root, [report])
        return report

    def save(self, root, reports):
        (root / evidence.REGISTRY).write_text(json.dumps({"schema_version": 1, "reports": reports}))

    def test_current_registry_does_not_fabricate_public_history(self):
        self.assertEqual(evidence.check(), {"public_releases": 0, "production_reports": 0, "state": "NoProductionReports"})

    def test_summaries_retain_paths_incidents_and_absence_of_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self.fixture(root)
            self.assertEqual(evidence.check(root, write=True)["production_reports"], 1)
            self.assertEqual(evidence.check(root)["production_reports"], 1)
            summary = (root / evidence.SUMMARIES / "v0.2.0.md").read_text()
            for expected in ("0.1.0 → 0.2.0", "INC-0001", "open", "limited", "migration: planned", report["review"]):
                self.assertIn(expected, summary)
            self.assertIn("No reviewed production report", (root / evidence.SUMMARIES / "v0.3.0.md").read_text())
            report["incidents"][0].update(status="resolved", resolution=evidence.GITHUB + "/pull/126")
            self.save(root, [report])
            with self.assertRaisesRegex(ValueError, "summary differs"):
                evidence.check(root)
            evidence.check(root, write=True)
            self.assertIn("resolved", (root / evidence.SUMMARIES / "v0.2.0.md").read_text())

    def test_unknown_private_unpublished_or_ambiguous_records_are_refused(self):
        mutations = {
            "raw_dump": lambda r: r.update(logs="private tenant data"),
            "development": lambda r: r.update(to_version="1.0.0-dev"),
            "unknown_release": lambda r: r.update(to_version="0.9.0"),
            "not_yet_published": lambda r: r.update(reported_on="2025-01-15"),
            "future": lambda r: r.update(reported_on="2999-01-01"),
            "identity": lambda r: r.update(installation="a-person@example.test"),
            "url": lambda r: r.update(source_issue="https://foreign.example/issues/123"),
            "review": lambda r: r.update(review=evidence.GITHUB + "/issues/124"),
            "privacy": lambda r: r["privacy_review"].update(no_credentials=False),
            "privacy_unknown": lambda r: r["privacy_review"].update(automated=True),
            "version": lambda r: r.update(keycloak="26.7"),
            "kind": lambda r: r.update(resources=["Unknown"]),
            "repeated_kind": lambda r: r.update(resources=["HankoApplication"] * 2),
            "scenario": lambda r: r.update(scenarios=["upgrade", "imagined"]),
            "same_version": lambda r: r.update(from_version="0.2.0"),
            "missing_upgrade": lambda r: r.update(scenarios=["installation"]),
            "untracked_failure": lambda r: r.update(incidents=[]),
            "false_resolution": lambda r: r["incidents"][0].update(resolution=evidence.GITHUB + "/pull/126"),
            "missing_resolution": lambda r: r["incidents"][0].update(status="resolved"),
            "fake_migration": lambda r: r.update(migration="reproduced"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = self.fixture(root)
            for name, mutate in mutations.items():
                with self.subTest(mutation=name):
                    report = copy.deepcopy(original)
                    mutate(report)
                    self.save(root, [report])
                    with self.assertRaises(ValueError):
                        evidence.load(root, date(2026, 10, 16))
            for field in ("id", "source_issue"):
                duplicate = copy.deepcopy(original)
                duplicate["id" if field == "source_issue" else "source_issue"] = "EVID-0002" if field == "source_issue" else evidence.GITHUB + "/issues/127"
                self.save(root, [original, duplicate])
                with self.subTest(duplicate=field), self.assertRaises(ValueError):
                    evidence.load(root)

    def test_fixture_binding_rejects_changed_unlinked_or_foreign_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self.fixture(root)
            path = root / "fixture.json"
            corpus = {"source_release": "0.1.0", "compatibility_reports": [report["id"]]}
            path.write_text(json.dumps(corpus))
            report.update(migration="reproduced", scenarios=["upgrade", "migration"], fixtures=[{"path": "fixture.json", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}])
            self.save(root, [report])
            evidence.check(root, write=True)
            for mutation in ("digest", "link", "release", "escape", "symlink"):
                current = copy.deepcopy(report)
                path.write_text(json.dumps(corpus))
                if mutation == "digest":
                    current["fixtures"][0]["sha256"] = "0" * 64
                elif mutation in ("link", "release"):
                    changed = dict(corpus)
                    changed["compatibility_reports" if mutation == "link" else "source_release"] = [] if mutation == "link" else "0.3.0"
                    path.write_text(json.dumps(changed))
                    current["fixtures"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                elif mutation == "escape":
                    current["fixtures"][0]["path"] = "../foreign.json"
                else:
                    (root / "linked.json").symlink_to(path)
                    current["fixtures"][0]["path"] = "linked.json"
                self.save(root, [current])
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    evidence.load(root)

    def test_render_refuses_symlink_and_check_refuses_stale_extra_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            evidence.check(root, write=True)
            extra = root / evidence.SUMMARIES / "v99.0.0.md"
            extra.write_text("Invented history")
            with self.assertRaises(ValueError):
                evidence.check(root)
            extra.unlink()
            page = root / evidence.SUMMARIES / "README.md"
            page.unlink()
            protected = root / "protected.md"
            protected.write_text("unchanged")
            page.symlink_to(protected)
            with self.assertRaises(ValueError):
                evidence.check(root, write=True)
            self.assertEqual(protected.read_text(), "unchanged")

    def test_issue_form_requires_versions_scope_and_sanitization(self):
        form = yaml.safe_load((evidence.ROOT / ".github/ISSUE_TEMPLATE/compatibility_evidence.yml").read_text())
        fields = {field["id"]: field for field in form["body"] if "id" in field}
        for name in ("installation", "from_version", "to_version", "kubernetes", "keycloak", "observed_on", "mode", "resources", "scenarios", "outcome", "observations"):
            self.assertIs(fields[name]["validations"]["required"], True)
        kinds = {r["kind"] for r in json.loads((evidence.ROOT / "docs/api-support.json").read_text())["resources"]}
        self.assertEqual(set(fields["resources"]["attributes"]["options"]), kinds)
        self.assertEqual(set(fields["scenarios"]["attributes"]["options"]), evidence.SCENARIOS)
        checklist = fields["privacy"]["attributes"]["options"]
        self.assertEqual(len(checklist), len(evidence.REVIEW_CHECKS))
        self.assertTrue(all(item["required"] is True for item in checklist))
        make = (evidence.ROOT / "Makefile").read_text()
        self.assertIn("\tpython3 -m tools.qualification.checks.compatibility_evidence check\n", make)


if __name__ == "__main__":
    unittest.main()

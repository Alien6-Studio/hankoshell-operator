import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("adr_references", ROOT / 'tools/quality/check_adr_references.py')
adr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adr)


class ADRReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = []

    def write(self, name, text):
        path = Path(name)
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_text(text, encoding="utf-8")
        self.paths.append(path)
        return path

    def record(self, number="009", slug="operator"):
        return self.write(adr.DECISIONS / f"ADR-{number}-{slug}.md",
                          f"# ADR-{number}: Operator\n\nStatus: Accepted\n"
                          "\n## Context\n\nContext.\n\n## Decision\n\nDecision.\n"
                          "\n## Consequences\n\nConsequence.\n\n## Enforcement\n\nCode and tests.\n")

    def check(self):
        return adr.check(self.root, self.paths)

    def test_references_in_go_yaml_and_markdown_resolve(self):
        self.record()
        for name in ("internal/client.go", ".go-arch-lint.yml", "chart/values.yaml", "docs/design.md"):
            self.write(name, "// ADR-009\n")
        self.assertEqual(self.check(), 1)

    def test_dangling_reference_reports_file_and_line_for_every_supported_extension(self):
        self.record()
        self.write("existing.go", "// ADR-009\n")
        for name in ("new.go", "new.yml", "new.yaml", "new.md"):
            self.write(name, "first line\nADR-999\n")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, f"{name}:2: ADR-999"):
                self.check()
            self.paths.pop()

    def test_shorthand_checks_every_decision(self):
        self.record()
        self.write("internal/client.go", "// ADR-009/010\n")
        with self.assertRaisesRegex(ValueError, "ADR-010 has no decision record"):
            self.check()
        self.record("010", "hub")
        self.assertEqual(self.check(), 2)

    def test_self_references_and_index_do_not_hide_orphans(self):
        self.record()
        self.write(adr.DECISIONS / "README.md", "[ADR-009](ADR-009-operator.md)\n")
        self.write(adr.DECISIONS / "TEMPLATE.md", "Example: ADR-009\n")
        with self.assertRaisesRegex(ValueError, "ADR-009 is not referenced"):
            self.check()

    def test_other_decision_can_reference_a_record(self):
        first = self.record()
        self.record("010", "hub")
        with (self.root / first).open("a") as output:
            output.write("See ADR-010.\n")
        self.write("client.go", "// ADR-009\n")
        self.assertEqual(self.check(), 2)

    def test_duplicate_number_is_rejected(self):
        self.record()
        self.record(slug="other")
        self.write("client.go", "// ADR-009\n")
        with self.assertRaisesRegex(ValueError, "duplicate ADR-009"):
            self.check()

    def test_deleted_record_cannot_resolve_from_an_index_link(self):
        self.write(adr.DECISIONS / "README.md", "[ADR-009](ADR-009-operator.md)\n")
        with self.assertRaisesRegex(ValueError, "ADR-009 has no decision record"):
            self.check()

    def test_invalid_filename_number_status_and_sections_fail(self):
        for number in ("9", "0009", "000"):
            self.record(number)
            with self.subTest(number=number), self.assertRaisesRegex(ValueError, "expected ADR-NNN"):
                self.check()
            self.paths.clear()
        record = self.record()
        self.write("client.go", "// ADR-009\n")
        (self.root / record).write_text("# ADR-010: Wrong\nStatus: Proposed\n")
        with self.assertRaises(ValueError) as result:
            self.check()
        for expected in ("title must start", "Status: Accepted", "missing Context", "missing Enforcement"):
            self.assertIn(expected, str(result.exception))

    def test_git_inventory_handles_hidden_new_deleted_and_ignored_files(self):
        self.write(".go-arch-lint.yml", "ADR-009")
        self.write("new directory/design.md", "ADR-009")
        self.write("ignored.go", "ADR-999")
        self.write("image.png", "ADR-999")
        output = b".go-arch-lint.yml\0new directory/design.md\0deleted.go\0image.png\0"
        with patch.object(adr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output)) as run:
            self.assertEqual(adr.repository_files(self.root),
                             [Path(".go-arch-lint.yml"), Path("new directory/design.md")])
        self.assertEqual(run.call_args.args[0],
                         ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_cli_fails_closed_on_invalid_reference_or_inventory_failure(self):
        for error in (ValueError("ADR-999 has no decision record"), OSError("unreadable source"),
                      subprocess.CalledProcessError(1, "git")):
            with self.subTest(error=error), patch.object(adr, "check", side_effect=error), \
                    patch("sys.stderr") as stderr:
                self.assertEqual(adr.main(), 1)
                self.assertTrue(stderr.write.called)

    def test_repository_records_have_resolving_code_and_test_links(self):
        self.assertGreater(adr.check(), 0)
        for path in sorted((adr.ROOT / adr.DECISIONS).glob("ADR-*.md")):
            content = path.read_text()
            links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", content)
            files = []
            for link in links:
                self.assertNotIn("://", link)  # Evidence stays reviewable in this checkout.
                target = (path.parent / link.split("#", 1)[0]).resolve()
                self.assertTrue(target.is_relative_to(adr.ROOT), link)
                self.assertTrue(target.is_file(), f"{path.name}: {link}")
                files.append(target)
            self.assertTrue(any(file.suffix == ".go" and not file.name.endswith("_test.go") for file in files), path)
            self.assertTrue(any(file.name.endswith("_test.go") for file in files), path)

    def test_ci_runs_checker_as_a_required_source_step_and_preflight_tests(self):
        jobs = yaml.safe_load((adr.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        step = next(step for step in jobs["source"]["steps"]
                    if step.get("run") == "python3 -m tools.quality.check_adr_references")
        self.assertNotIn("if", step)
        self.assertFalse(step.get("continue-on-error", False))
        self.assertIn("source", jobs["checks"]["needs"])
        self.assertIn("make preflight", [step.get("run") for step in jobs["preflight"]["steps"]])
        self.assertIn("python3 -m unittest discover -s tests/tooling -t . -p 'test_*.py'", (adr.ROOT / "Makefile").read_text())


if __name__ == "__main__":
    unittest.main()

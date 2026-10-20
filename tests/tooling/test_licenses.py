"""Tests for the dependency license policy checker and the notices pipeline wiring."""
import copy
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

spec = importlib.util.spec_from_file_location("check_licenses", ROOT / 'tools/quality/check_licenses.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

TODAY = date(2026, 10, 1)
SUM = "h1:" + "A" * 42 + "0="
POLICY = {
    "schema_version": 1,
    "allowed_licenses": ["Apache-2.0", "MIT"],
    "denied_licenses": ["GPL-3.0"],
    "module_sources": {"goproxy": "https://proxy.golang.org", "gosumdb": "sum.golang.org",
                       "allow_replace": False},
    "exceptions": [{"module": "example.com/quirky", "version": "v1.2.3", "sum": SUM,
                    "license": "Apache-2.0",
                    "justification": "Classifier cannot map the repository root license",
                    "expires": "2027-03-01"}],
}


def policy_with(**overrides):
    policy = copy.deepcopy(POLICY)
    policy.update(overrides)
    return policy


def read(policy, today=TODAY):
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "policy.json"
        path.write_text(json.dumps(policy))
        return checker.read_policy(path, today=today)


class PolicyTest(unittest.TestCase):
    def test_repository_policy_is_valid(self):
        policy = checker.read_policy(today=date(2026, 10, 15))
        self.assertTrue(policy["exceptions"])

    def test_accepts_the_reference_policy(self):
        self.assertEqual(read(POLICY)["allowed_licenses"], ["Apache-2.0", "MIT"])

    def test_rejects_structural_drift(self):
        for broken in (
            policy_with(schema_version=2),
            policy_with(extra=True),
            policy_with(module_sources={"goproxy": "https://proxy.golang.org",
                                        "gosumdb": "sum.golang.org", "allow_replace": True}),
            policy_with(module_sources={"goproxy": "https://evil.example",
                                        "gosumdb": "sum.golang.org", "allow_replace": False}),
            policy_with(allowed_licenses=[]),
            policy_with(allowed_licenses=["MIT", "Apache-2.0"]),
            policy_with(allowed_licenses=["MIT", "MIT"]),
            policy_with(denied_licenses=["GPL 3.0"]),
            policy_with(denied_licenses=["GPL-3.0", "MIT"]),
        ):
            with self.assertRaises(ValueError):
                read(broken)

    def test_rejects_malformed_exceptions(self):
        base = POLICY["exceptions"][0]
        for broken in (
            {**base, "sum": "deadbeef"},
            {**base, "version": "1.2.3"},
            {**base, "license": "GPL-3.0"},
            {**base, "justification": "too short"},
            {**base, "expires": "2027-3-1"},
            {k: v for k, v in base.items() if k != "expires"},
            {**base, "extra": "field"},
        ):
            with self.assertRaises(ValueError):
                read(policy_with(exceptions=[broken]))

    def test_rejects_expired_distant_or_duplicate_exceptions(self):
        base = POLICY["exceptions"][0]
        with self.assertRaises(ValueError):
            read(policy_with(exceptions=[{**base, "expires": "2026-10-01"}]))
        with self.assertRaises(ValueError):
            read(policy_with(exceptions=[{**base, "expires": "2027-10-02"}]))
        with self.assertRaises(ValueError):
            read(policy_with(exceptions=[base, {**base, "justification": base["justification"] + "!"}]))


class EnforcementTest(unittest.TestCase):
    def modules(self):
        return {"example.com/fine": {"version": "v1.0.0", "sum": SUM, "dir": Path("/none")},
                "example.com/quirky": {"version": "v1.2.3", "sum": SUM, "dir": Path("/none")}}

    def test_attribute_folds_packages_onto_modules(self):
        rows = [("example.com/fine", "MIT"), ("example.com/fine/sub/pkg", "Apache-2.0"),
                ("example.com/app/internal", "Unknown")]
        licenses = checker.attribute(rows, self.modules(), "example.com/app")
        self.assertEqual(licenses, {"example.com/fine": {"MIT", "Apache-2.0"}})
        with self.assertRaises(ValueError):
            checker.attribute([("example.com/stranger", "MIT")], self.modules(), "example.com/app")

    def test_enforce_accepts_allowed_and_exception_modules(self):
        used = set()
        licenses = {"example.com/fine": {"MIT"}}
        checker.enforce(self.modules(), licenses, POLICY, used)
        self.assertEqual(used, {("example.com/quirky", "v1.2.3")})
        self.assertEqual(licenses["example.com/quirky"], {"Apache-2.0"})

    def test_enforce_rejects_denied_unknown_and_hash_mismatch(self):
        with self.assertRaises(ValueError) as denied:
            checker.enforce(self.modules(), {"example.com/fine": {"GPL-3.0"},
                                             "example.com/quirky": {"Apache-2.0"}}, POLICY, set())
        self.assertIn("denied GPL-3.0", str(denied.exception))
        with self.assertRaises(ValueError):
            checker.enforce(self.modules(), {"example.com/quirky": {"Apache-2.0"}}, POLICY, set())
        drifted = self.modules()
        drifted["example.com/quirky"]["sum"] = "h1:" + "B" * 42 + "0="
        with self.assertRaises(ValueError):
            checker.enforce(drifted, {"example.com/fine": {"MIT"}}, POLICY, set())

    def test_exception_never_launders_a_denied_license(self):
        with self.assertRaises(ValueError):
            checker.enforce(self.modules(), {"example.com/fine": {"MIT"},
                                             "example.com/quirky": {"GPL-3.0"}}, POLICY, set())

    def test_inventory_unions_both_shipped_platforms_and_license_identities(self):
        first, second = self.modules(), {"example.com/fine": self.modules()["example.com/fine"]}
        second["example.com/arm-only"] = {"version": "v1.0.0", "sum": SUM, "dir": Path("/arm")}
        rows = [[("example.com/fine", "MIT"), ("example.com/quirky", "Apache-2.0")],
                [("example.com/fine", "Apache-2.0"), ("example.com/arm-only", "MIT")]]
        with patch.object(checker, "dependencies", side_effect=[first, second]) as dependencies, \
                patch.object(checker, "classified", side_effect=rows) as classified:
            modules, licenses = checker.inventory("classifier", Path("/module"), "./...", "example.com/app", tests=True)
        self.assertEqual(set(modules), {"example.com/fine", "example.com/quirky", "example.com/arm-only"})
        self.assertEqual(licenses["example.com/fine"], {"MIT", "Apache-2.0"})
        self.assertEqual([call.kwargs["platform"] for call in dependencies.call_args_list], [("linux", "amd64"), ("linux", "arm64")])
        self.assertTrue(all(call.kwargs["tests"] for call in dependencies.call_args_list))
        self.assertEqual([call.kwargs["platform"] for call in classified.call_args_list], [("linux", "amd64"), ("linux", "arm64")])

    def test_platform_union_refuses_version_or_sum_drift(self):
        original = self.modules()
        for key, replacement in (("version", "v9.0.0"), ("sum", "h1:" + "B" * 42 + "0=")):
            current = copy.deepcopy(original)
            current["example.com/fine"][key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "identity differs"):
                checker.merge_modules(copy.deepcopy(original), current)

    def test_classifier_and_go_graph_use_the_shipped_target_even_on_a_foreign_host(self):
        with patch.dict(checker.os.environ, {"GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "1"}), \
                patch.object(checker.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            checker.run(["classifier", "report", "./cmd/operator"], Path("/module"), platform=("linux", "amd64"))
        environment = run.call_args.kwargs["env"]
        self.assertEqual({key: environment[key] for key in ("GOOS", "GOARCH", "CGO_ENABLED", "GOTOOLCHAIN")},
                         {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"})


class RenderTest(unittest.TestCase):
    def test_license_files_are_discovered_case_insensitively(self):
        with tempfile.TemporaryDirectory() as scratch:
            module = Path(scratch)
            (module / "License.txt").write_text("text")
            (module / "NOTICE").write_text("notice")
            (module / "README.md").write_text("readme")
            (module / "testdata").mkdir()
            (module / "testdata/LICENSE").write_text("fixture")
            (module / "sub").mkdir()
            (module / "sub/COPYING").write_text("text")
            found = [str(p) for p in checker.license_files(module)]
            self.assertEqual(found, ["License.txt", "NOTICE", "sub/COPYING"])

    def test_render_is_deterministic_and_deduplicates_texts(self):
        with tempfile.TemporaryDirectory() as scratch:
            first, second, bare = (Path(scratch) / n for n in ("a", "b", "c"))
            for module in (first, second, bare):
                module.mkdir()
            (first / "LICENSE").write_text("same words\n")
            (second / "LICENSE").write_text("same words\n")
            modules = {"example.com/a": {"version": "v1.0.0", "sum": SUM, "dir": first},
                       "example.com/b": {"version": "v2.0.0", "sum": SUM, "dir": second},
                       "example.com/quirky": {"version": "v1.2.3", "sum": SUM, "dir": bare}}
            licenses = {"example.com/a": {"MIT"}, "example.com/b": {"MIT"},
                        "example.com/quirky": {"Apache-2.0"}}
            document = checker.render("test binary", modules, licenses)
            self.assertEqual(document, checker.render("test binary", modules, licenses))
            self.assertEqual(document.count("same words"), 1)
            self.assertEqual(document.count("text-001"), 3)
            self.assertIn("license text at the module repository", document)
            self.assertTrue(document.endswith("\n") and not document.endswith("\n\n"))


class WiringTest(unittest.TestCase):
    def test_ci_source_job_runs_the_license_gate(self):
        self.assertIn("make licenses", (ROOT / ".github/workflows/ci.yml").read_text())

    def test_makefile_pins_the_classifier_and_checks_drift(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("go_licenses", makefile)
        self.assertIn("github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)", makefile)
        self.assertIn("git diff --exit-code -- THIRD_PARTY_NOTICES THIRD_PARTY_NOTICES.cosign", makefile)

    def test_versions_json_pins_go_licenses(self):
        tools = json.loads((ROOT / "versions.json").read_text())["tools"]
        self.assertEqual(tools["go_licenses"], "v2.0.1")

    def test_image_ships_the_notices(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("THIRD_PARTY_NOTICES THIRD_PARTY_NOTICES.cosign "
                      "/usr/share/licenses/hankoshell-operator/", dockerfile)

    def test_notices_are_committed_and_generated(self):
        for name in ("THIRD_PARTY_NOTICES", "THIRD_PARTY_NOTICES.cosign"):
            text = (ROOT / name).read_text()
            self.assertIn("Generated by tools/quality/check_licenses.py", text)

    def test_large_file_hook_excludes_only_the_notices(self):
        config = (ROOT / ".pre-commit-config.yaml").read_text()
        self.assertIn("exclude: ^THIRD_PARTY_NOTICES", config)


if __name__ == "__main__":
    unittest.main()

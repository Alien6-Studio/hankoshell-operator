import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("security_mutations", Path(__file__).with_name("security-mutations.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def item():
    return gate.mutation("fixture", "source.go", "protection", "disabled", "internal/fixture", "TestProtection")


def events(result="pass", test="TestProtection", extra=None):
    package = item()["package"]
    rows = [{"Action": "run", "Package": package, "Test": test}]
    if extra:
        rows.append({"Action": "output", "Package": package, "Test": test, "Output": extra})
    rows += [{"Action": result, "Package": package, "Test": test}, {"Action": result, "Package": package}]
    return "\n".join(json.dumps(row) for row in rows) + "\n"


class MutationRunnerTests(unittest.TestCase):
    def test_cold_compilation_is_separate_and_never_a_mutation_or_baseline_verdict(self):
        def runner(command, root, seconds):
            self.assertEqual(command[:6], ["go", "test", "-json", "-race", "-run", "^$"])
            self.assertEqual(seconds, 300)
            return 0, json.dumps({"Action": "pass", "Package": item()["package"]}) + "\n"
        prepared = gate.prepare_compilation(Path("."), [item(), item()], runner)
        self.assertEqual(prepared["packages"], 1)
        self.assertEqual(prepared["tests_executed"], 0)
        for code, output in ((1, ""), (0, ""), (0, events()), (0, "not JSON"),
                             (0, json.dumps({"Action": "skip", "Package": item()["package"]})),
                             (0, json.dumps({"Action": "pass", "Package": "wrong"}))):
            with self.subTest(output=output), self.assertRaises(gate.GateError):
                gate.prepare_compilation(Path("."), [item()], lambda *_: (code, output))

    def test_all_reviewed_anchors_are_unique_and_commands_select_real_tests(self):
        required = {"hub-control-json-ambiguity", "image-policy-json-ambiguity", "oidc-discovery-json-ambiguity", "authorization-journal-json-ambiguity", "metrics-uri-authorization", "metrics-client-authentication", "provider-error-redaction", "lifecycle-independent-approval", "lifecycle-mutation-recheck", "lifecycle-parent-revocation", "lifecycle-database-tenant", "fleet-command-log-sanitization", "fleet-all-route-redirect", "fleet-independent-decommission", "fleet-hub-destination", "fleet-provider-mutation-guard", "fleet-cache-uid", "fleet-rollback-content", "fleet-sticky-expiry", "fleet-expiry", "fleet-native-permission", "fleet-atomic-refusal", "fleet-local-pause", "fleet-provider-version-scope", "fleet-provider-client-binding", "fleet-signature", "fleet-target", "fleet-sequence", "fleet-sticky-signature-mode", "hub-hmac", "image-sha256", "image-keyless-identity", "tls-peer-verification", "tls-minimum",
                    "keycloak-redirect", "realm-live-inventory", "realm-complete-dependencies", "realm-complete-pages", "realm-deletion-authority-recheck", "unowned-realm-deletion", "unowned-client-role-deletion",
                    "bundle-tenant-namespace", "bundle-live-tenant-ownership", "bundle-forced-ownership",
                    "bundle-write-version-precondition", "secret-cache-exclusion",
                    "snapshot-tenant-inventory", "snapshot-stored-tenant-scope", "operation-child-tenant-presence",
                    "operation-managed-provider-binding", "managed-probe-rollout-fence",
                    "managed-infrastructure-owner", "managed-infrastructure-live-owner",
                    "managed-infrastructure-write-version", "managed-pdb-delete-identity",
                    "managed-instance-live-intent", "managed-instance-deletion",
                    "hub-enrollment-redirect", "hub-error-body-redaction", "legacy-bundle-stream-count",
                    "legacy-bundle-json-ambiguity", "legacy-bundle-before-api", "application-canonical-owner",
                    "application-canonical-write-version", "application-projection-write-version",
                    "application-projection-cleanup-version", "application-canonical-readback-uid",
                    "application-projection-live-plan", "runtime-cleanup-canonical-journal", "runtime-cleanup-record-bound", "bounded-actor-explicit-recovery-identity"}
        required.update({"application-cors-validation", "application-cors-explicit-empty", "settled-authorization-retire-scopes", "settled-authorization-retire-resources",
                         "settled-authorization-retire-policies", "settled-authorization-retire-permissions"})
        self.assertEqual({entry["name"] for entry in gate.MUTATIONS}, required)
        self.assertEqual(len(gate.MUTATIONS), len(required))
        for entry in gate.MUTATIONS:
            with self.subTest(mutation=entry["name"]):
                self.assertEqual((gate.ROOT / entry["file"]).read_text().count(entry["before"]), 1)
                package = gate.ROOT / entry["command"][-1]
                tests = "\n".join(p.read_text() for p in package.glob("*_test.go"))
                self.assertIn("func " + entry["test"] + "(t *testing.T)", tests)
                self.assertEqual(entry["command"][:7], ["go", "test", "-json", "-race", "-count=1", "-timeout=45s", "-run"])

    def test_anchor_missing_already_applied_or_ambiguous_never_changes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source.go"
            for content, reason in (("other", "anchor occurs 0"), ("disabled", "already applied"),
                                    ("protection protection", "anchor occurs 2")):
                path.write_text(content)
                with self.assertRaisesRegex(gate.GateError, reason):
                    gate.apply_mutation(root, item())
                self.assertEqual(path.read_text(), content)

    def test_only_a_completed_matching_test_failure_counts(self):
        self.assertEqual(gate.outcome(0, events(), item()), "pass")
        self.assertEqual(gate.outcome(1, events("fail"), item()), "fail")
        invalid = [(0, events("skip")), (1, events()), (1, "compiler failed"), (1, "{}"),
                   (1, events("fail", "TestOther")), (-9, events("fail")),
                   (1, events("fail", extra="panic: fixture")), (1, events("fail", extra="[build failed]")),
                   (1, events("fail", extra="WARNING: DATA RACE")), (1, events("fail") + events("fail")),
                   (1, "[]"), (1, events("fail").rsplit("\n", 2)[0])]
        for code, output in invalid:
            with self.subTest(code=code, output=output), self.assertRaises(gate.GateError):
                gate.outcome(code, output, item())

    def test_detection_survival_baseline_failure_and_timeout_are_distinct(self):
        for behavior, expected in (("detected", "detected"), ("survived", "survived"),
                                   ("baseline-failed", "error"), ("timeout", "error")):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                (source / "source.go").write_text("protection")
                seen = []

                def copy(original, destination):
                    shutil.copy2(original / "source.go", destination / "source.go")

                def runner(_command, root, _seconds):
                    self.assertNotEqual(root, source)
                    content = (root / "source.go").read_text()
                    seen.append((root, content))
                    if behavior == "timeout":
                        raise gate.GateError("test command timed out")
                    fail = behavior == "baseline-failed" or behavior == "detected" and content == "disabled"
                    return (1, events("fail")) if fail else (0, events())

                with patch.object(gate, "snapshot", side_effect=copy):
                    result = gate.qualify(source, [item()], runner)
                self.assertEqual(result["mutations"][0]["result"], expected)
                self.assertEqual(result["result"], "pass" if expected == "detected" else "fail")
                self.assertEqual((source / "source.go").read_text(), "protection")
                self.assertFalse(seen[0][0].exists())  # Temporary source and mutations are removed.
                self.assertEqual(len(seen), 2 if expected in ("detected", "survived") else 1)

    def test_each_mutation_starts_from_the_original_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "source.go").write_text("protection")
            first, second = item(), {**item(), "name": "second", "after": "also-disabled"}
            seen = []

            def runner(_command, root, _seconds):
                content = (root / "source.go").read_text()
                seen.append(content)
                return (0, events()) if content == "protection" else (1, events("fail"))

            with patch.object(gate, "snapshot", side_effect=lambda src, dst: shutil.copy2(src / "source.go", dst / "source.go")):
                result = gate.qualify(source, [first, second], runner)
            self.assertEqual(result["result"], "pass")
            self.assertEqual(seen, ["protection", "disabled", "also-disabled"])

    def test_real_command_timeout_and_output_overflow_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(gate.GateError, "timed out"):
                gate.run_command([sys.executable, "-c", "import time; time.sleep(30)"], root, 0.1)
            with patch.object(gate, "OUTPUT_LIMIT", 100), self.assertRaisesRegex(gate.GateError, "output budget"):
                gate.run_command([sys.executable, "-c", "print('x' * 200)"], root, 5)

    def test_stderr_downloads_do_not_corrupt_events_and_share_the_output_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for result, returncode in (("pass", 0), ("fail", 1)):
                script = "import sys; sys.stderr.write('go: downloading example.com/module v1.0.0\\n'); "
                script += "sys.stdout.write(" + repr(events(result)) + "); sys.exit(" + str(returncode) + ")"
                code, output = gate.run_command([sys.executable, "-c", script], root, 5)
                self.assertEqual(gate.outcome(code, output, item()), result)
            for script in ("import sys; sys.stderr.write('x' * 101)",
                           "import sys; sys.stdout.write('x' * 60); sys.stderr.write('x' * 60)"):
                with patch.object(gate, "OUTPUT_LIMIT", 100), self.assertRaisesRegex(gate.GateError, "output budget"):
                    gate.run_command([sys.executable, "-c", script], root, 5)
            code, output = gate.run_command([sys.executable, "-c", "import sys; sys.stderr.write('build failed'); sys.exit(1)"], root, 5)
            with self.assertRaises(gate.GateError):
                gate.outcome(code, output, item())

    def test_mutant_timeout_restores_source_before_the_next_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "source.go").write_text("protection")
            seen = []

            def runner(_command, root, _seconds):
                content = (root / "source.go").read_text()
                seen.append(content)
                if content == "disabled":
                    raise gate.GateError("test command timed out")
                return (0, events()) if content == "protection" else (1, events("fail"))

            with patch.object(gate, "snapshot", side_effect=lambda src, dst: shutil.copy2(src / "source.go", dst / "source.go")):
                report = gate.qualify(source, [item(), {**item(), "name": "second", "after": "also-disabled"}], runner)
            self.assertEqual([row["result"] for row in report["mutations"]], ["error", "detected"])
            self.assertEqual(report["result"], "fail")
            self.assertEqual(seen, ["protection", "disabled", "also-disabled"])
            self.assertEqual((source / "source.go").read_text(), "protection")

    def test_snapshot_copies_current_files_but_never_symlinks_or_git_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source, copy = Path(directory) / "source", Path(directory) / "copy"
            source.mkdir()
            copy.mkdir()
            (source / "source.go").write_text("uncommitted source")
            completed = subprocess.CompletedProcess([], 0, stdout=b"source.go\0deleted.go\0", stderr=b"")
            with patch.object(gate.subprocess, "run", return_value=completed):
                gate.snapshot(source, copy)
            self.assertEqual((copy / "source.go").read_text(), "uncommitted source")
            self.assertFalse((copy / "deleted.go").exists())
            (source / "link").symlink_to(source / "source.go")
            for entry in (b"../escape\0", b".git/config\0", b"link\0"):
                completed.stdout = entry
                with patch.object(gate.subprocess, "run", return_value=completed), self.assertRaises(gate.GateError):
                    gate.snapshot(source, copy)
            with self.assertRaises(gate.GateError):
                gate.snapshot(source, source / "nested")


if __name__ == "__main__":
    unittest.main()

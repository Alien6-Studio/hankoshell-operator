import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("rulesets", ROOT / 'tools/quality/check_rulesets.py')
rulesets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rulesets)


class RulesetTests(unittest.TestCase):
    def setUp(self):
        self.exports = rulesets.check_contract()

    def fixture(self, directory):
        root = Path(directory)
        shutil.copytree(rulesets.ROOT / ".github/rulesets", root / ".github/rulesets")
        (root / ".github/workflows").mkdir()
        shutil.copyfile(rulesets.ROOT / ".github/workflows/ci.yml", root / ".github/workflows/ci.yml")
        return root

    def documents(self):
        documents = {}
        inventory = []
        for index, config in enumerate(self.exports.values(), 1):
            meta = {"id": index, "name": config["name"], "source_type": "Repository", "source": rulesets.REPOSITORY,
                    "target": config["target"], "enforcement": config["enforcement"]}
            inventory.append(meta)
            documents["repos/" + rulesets.REPOSITORY + "/rulesets/" + str(index)] = {
                **copy.deepcopy(config), **meta, "created_at": "fixture", "updated_at": "fixture",
                "current_user_can_bypass": "never", "node_id": "fixture", "_links": {},
            }
        documents["repos/" + rulesets.REPOSITORY + "/rulesets?includes_parents=true&per_page=100"] = inventory
        return documents

    def verify_documents(self, documents, **options):
        paths = []

        def api(path):
            paths.append(path)
            return copy.deepcopy(documents[path])

        hidden = rulesets.check_live(self.exports, api=api, **options)
        self.assertEqual(len(paths), 3)
        self.assertIn("includes_parents=true", paths[0])
        return hidden

    def test_current_exports_and_complete_live_snapshot_match(self):
        self.assertEqual(self.verify_documents(self.documents()), [])

    def test_ordering_and_server_metadata_do_not_create_false_drift(self):
        documents = self.documents()
        for document in documents.values():
            if isinstance(document, list):
                document.reverse()
            else:
                document["rules"].reverse()
                document["current_user_can_bypass"] = "different-caller"
                document["updated_at"] = "different-time"
        self.assertEqual(self.verify_documents(documents), [])

    def test_each_material_live_protection_change_fails(self):
        cases = {
            "disabled": lambda d: d.update(enforcement="disabled"),
            "bypass": lambda d: d.update(bypass_actors=[{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}]),
            "exclude": lambda d: d["conditions"]["ref_name"]["exclude"].append("refs/heads/main"),
            "unsigned": lambda d: d.update(rules=[r for r in d["rules"] if r["type"] != "required_signatures"]),
            "review": lambda d: rulesets.rule_map(d)["pull_request"]["parameters"].update(required_approving_review_count=1),
            "wrong-check": lambda d: rulesets.rule_map(d)["required_status_checks"]["parameters"]["required_status_checks"][0].update(context="Unrelated checks"),
            "unbound-app": lambda d: rulesets.rule_map(d)["required_status_checks"]["parameters"]["required_status_checks"][0].update(integration_id=None),
            "unknown-config": lambda d: d.update(future_bypass=True),
            "unknown-rule": lambda d: d["rules"].append({"type": "future_rule"}),
            "duplicate-rule": lambda d: d["rules"].append(copy.deepcopy(d["rules"][0])),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                documents = self.documents()
                mutate(documents["repos/" + rulesets.REPOSITORY + "/rulesets/1"])
                with self.assertRaises(ValueError):
                    self.verify_documents(documents)

    def test_tag_scope_deletion_and_rewrite_cannot_drift(self):
        for change in (lambda d: d["conditions"]["ref_name"].update(include=["refs/tags/release-*"]),
                       lambda d: d.update(rules=[{"type": "deletion"}]),
                       lambda d: d.update(rules=[{"type": "non_fast_forward"}])):
            documents = self.documents()
            change(documents["repos/" + rulesets.REPOSITORY + "/rulesets/2"])
            with self.assertRaisesRegex(ValueError, "release-tags.json"):
                self.verify_documents(documents)

    def test_hidden_bypass_is_never_treated_as_an_empty_list(self):
        documents = self.documents()
        branch = documents["repos/" + rulesets.REPOSITORY + "/rulesets/1"]
        del branch["bypass_actors"]
        with self.assertRaisesRegex(ValueError, "bypass visibility"):
            self.verify_documents(documents)
        self.assertEqual(self.verify_documents(documents, allow_hidden_bypass=True), ["default-branch.json"])
        branch["enforcement"] = "disabled"
        with self.assertRaisesRegex(ValueError, "drift"):
            self.verify_documents(documents, allow_hidden_bypass=True)
        branch["enforcement"] = "active"
        del branch["rules"]
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.verify_documents(documents, allow_hidden_bypass=True)

    def test_cli_distinguishes_partial_visibility_from_full_audit(self):
        output = io.StringIO()
        with patch.object(rulesets.sys, "argv", ["tools/quality/check_rulesets.py", "--live", "--allow-hidden-bypass"]), \
                patch.object(rulesets, "check_live", return_value=["default-branch.json"]), \
                patch.object(rulesets.sys, "stdout", output):
            self.assertEqual(rulesets.main(), 0)
        self.assertIn("UNVERIFIED", output.getvalue())
        self.assertNotIn("and live GitHub configuration", output.getvalue())
        errors = io.StringIO()
        with patch.object(rulesets.sys, "argv", ["tools/quality/check_rulesets.py", "--live"]), \
                patch.object(rulesets, "check_live", side_effect=ValueError("bypass visibility unavailable")), \
                patch.object(rulesets.sys, "stderr", errors):
            self.assertEqual(rulesets.main(), 1)
        self.assertIn("bypass visibility unavailable", errors.getvalue())

    def test_missing_additional_inherited_and_ambiguous_inventory_fails(self):
        path = "repos/" + rulesets.REPOSITORY + "/rulesets?includes_parents=true&per_page=100"
        cases = [[], None, {}, [None, None]]
        entries = self.documents()[path]
        cases.extend([entries[:1], entries + entries, entries[:1] * 100,
                      [entries[0], entries[0]], [dict(entries[0], source_type="Organization"), entries[1]],
                      [dict(entries[0], source="other/repo"), entries[1]],
                      [dict(entries[0], id=True), entries[1]],
                      [dict(entries[0], name="other-name"), entries[1]]])
        for inventory in cases:
            with self.subTest(inventory=inventory):
                documents = self.documents()
                documents[path] = inventory
                with self.assertRaises(ValueError):
                    self.verify_documents(documents)

    def test_detail_identity_must_match_discovered_id_and_repository(self):
        for fields in ({"id": 3}, {"id": True}, {"name": "other"}, {"source": "other/repo"}, {"source_type": "Organization"}):
            documents = self.documents()
            documents["repos/" + rulesets.REPOSITORY + "/rulesets/1"].update(fields)
            with self.assertRaisesRegex(ValueError, "identity"):
                self.verify_documents(documents)

    def test_offline_contract_rejects_weakened_exports_and_gate_rename(self):
        changes = {
            "review-threads": lambda d: rulesets.rule_map(d)["pull_request"]["parameters"].update(required_review_thread_resolution=False),
            "boolean-review-count": lambda d: rulesets.rule_map(d)["pull_request"]["parameters"].update(required_approving_review_count=False),
            "merge-commit": lambda d: rulesets.rule_map(d)["pull_request"]["parameters"]["allowed_merge_methods"].append("merge"),
            "linear-history": lambda d: d.update(rules=[r for r in d["rules"] if r["type"] != "required_linear_history"]),
            "signatures": lambda d: d.update(rules=[r for r in d["rules"] if r["type"] != "required_signatures"]),
            "stale-base": lambda d: rulesets.rule_map(d)["required_status_checks"]["parameters"].update(strict_required_status_checks_policy=False),
            "scanning": lambda d: rulesets.rule_map(d)["code_scanning"]["parameters"]["code_scanning_tools"][0].update(security_alerts_threshold="none"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            path = root / ".github/rulesets/default-branch.json"
            original = path.read_text()
            for name, change in changes.items():
                with self.subTest(name=name):
                    data = json.loads(original)
                    change(data)
                    path.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        rulesets.check_contract(root)
            path.write_text(original)
            ci = root / ".github/workflows/ci.yml"
            ci.write_text(ci.read_text().replace("name: Source and chart checks", "name: New gate"))
            with self.assertRaisesRegex(ValueError, "Required status check"):
                rulesets.check_contract(root)

    def test_json_rejects_duplicates_bad_numbers_and_oversize(self):
        for payload in (b'{"rules":[],"rules":[]}', b'{"id":NaN}', b'{"id":Infinity}', b'{"id":1.0}', b'{'):
            with self.assertRaises(ValueError):
                rulesets.decode(payload)
        with patch.object(rulesets, "MAX_DOCUMENT_BYTES", 5), self.assertRaisesRegex(ValueError, "exceeds"):
            rulesets.decode(b'{"id":1}')

    def test_github_reader_is_get_only_bounded_and_does_not_echo_credentials(self):
        response = subprocess.CompletedProcess([], 0, stdout=b'[]', stderr=b'private credential')
        with patch.object(rulesets.subprocess, "run", return_value=response) as run:
            self.assertEqual(rulesets.github_document("repos/example/repo/rulesets"), [])
            command = run.call_args.args[0]
            self.assertEqual(command[:6], ["gh", "api", "--hostname", "github.com", "--method", "GET"])
            self.assertEqual(run.call_args.kwargs["timeout"], 30)
            self.assertNotIn("shell", run.call_args.kwargs)
        for result in (subprocess.CompletedProcess([], 1, stdout=b'private credential', stderr=b'private credential'),
                       subprocess.TimeoutExpired("private credential", 30), OSError("private credential")):
            with patch.object(rulesets.subprocess, "run", **({"side_effect": result} if isinstance(result, Exception) else {"return_value": result})):
                with self.assertRaises(ValueError) as failure:
                    rulesets.github_document("repos/example/repo/rulesets")
                self.assertNotIn("private credential", str(failure.exception))

    def test_invalid_repository_is_refused_before_network(self):
        for name in ("https://example/repo", "example/repo?token=x", "example/..", "--hostname/other", "a/b/c", "a/b\n"):
            with patch.object(rulesets, "github_document") as api, self.assertRaises(ValueError):
                rulesets.check_live(self.exports, name, api=api)
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

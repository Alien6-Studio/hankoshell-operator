import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("check_dco", Path(__file__).with_name("check-dco.py"))
dco = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dco)


class DCOGitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.base = self.commit("Unsigned base outside the PR range")
        self.api = Mock(side_effect=AssertionError("Ordinary commits must not need GitHub"))

    def git(self, *args, input=None):
        return dco.command(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                            "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                            "-c", "user.name=Fixture Maintainer", "-c", "user.email=maintainer@example.com",
                            *args], cwd=self.root, input=input)

    def commit(self, message, author="Fixture Author <author@example.com>"):
        self.git("commit", "--quiet", "--allow-empty", "--allow-empty-message", "--cleanup=verbatim",
                 "--author=" + author, "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def check(self, head):
        return dco.check(self.base, head, self.git, self.api)

    def test_matching_author_trailer_passes_without_api_or_base_signoff(self):
        head = self.commit("Change\n\nSigned-off-by: Fixture Author <author@example.com>")
        self.assertEqual(self.check(head), [head + ": author-matching Signed-off-by trailer"])
        self.api.assert_not_called()

    def test_missing_and_mismatched_signoffs_name_every_failing_commit(self):
        revisions = [self.commit(message) for message in (
            "No trailer",
            "Wrong name\n\nSigned-off-by: Fixture Maintainer <author@example.com>",
            "Wrong email\n\nSigned-off-by: Fixture Author <other@example.com>",
            "Malformed\n\nSigned-off-by: Fixture Author author@example.com",
        )]
        with self.assertRaises(ValueError) as raised:
            self.check(revisions[-1])
        for revision in revisions:
            self.assertIn(revision, str(raised.exception))
        self.assertNotIn(self.base, str(raised.exception))
        self.api.assert_not_called()

    def test_multiple_signoffs_accepts_the_author_among_other_signers(self):
        head = self.commit("Change\n\nSigned-off-by: Reviewer <reviewer@example.com>\n"
                           "Signed-off-by: Fixture Author <author@example.com>\n"
                           "Signed-off-by: Other Reviewer <other@example.com>")
        self.assertEqual(len(self.check(head)), 1)

    def test_trailer_key_and_email_case_are_insensitive(self):
        head = self.commit("Change\n\nsigned-OFF-by: Fixture Author <AUTHOR@EXAMPLE.COM>")
        self.assertEqual(len(self.check(head)), 1)

    def test_signoff_in_subject_or_body_is_not_a_final_trailer(self):
        for message in ("Signed-off-by: Fixture Author <author@example.com>",
                        "Change\n\nSigned-off-by: Fixture Author <author@example.com>\n\n"
                        "This is body prose after the apparent sign-off."):
            with self.subTest(message=message):
                head = self.commit(message)
                with self.assertRaisesRegex(ValueError, head):
                    self.check(head)

    def test_each_commit_is_checked_even_if_head_has_signoff(self):
        unsigned = self.commit("Unsigned contributor change")
        head = self.commit("Signed head\n\nSigned-off-by: Fixture Author <author@example.com>")
        with self.assertRaisesRegex(ValueError, unsigned):
            self.check(head)

    def test_merge_commits_are_checked(self):
        self.git("checkout", "--quiet", "-b", "topic", self.base)
        self.commit("Topic\n\nSigned-off-by: Fixture Author <author@example.com>")
        self.git("checkout", "--quiet", "main")
        self.commit("Main\n\nSigned-off-by: Fixture Author <author@example.com>")
        self.git("merge", "--quiet", "--no-ff", "topic", "-m", "Unsigned merge")
        head = self.git("rev-parse", "HEAD").strip()
        with self.assertRaisesRegex(ValueError, head):
            self.check(head)

    def test_current_base_need_not_be_an_ancestor_of_pr_head(self):
        head = self.commit("PR\n\nSigned-off-by: Fixture Author <author@example.com>")
        self.git("checkout", "--quiet", "-b", "advanced-main", self.base)
        base = self.commit("Unrelated main advance")
        self.assertEqual(len(dco.check(base, head, self.git, self.api)), 1)

    def test_empty_missing_noncommit_and_unrelated_ranges_fail(self):
        with self.assertRaisesRegex(ValueError, "must contain"):
            self.check(self.base)
        with self.assertRaises(ValueError):
            self.check("f" * 40)
        self.git("tag", "-a", "fixture", "-m", "Annotated fixture", self.base)
        with self.assertRaisesRegex(ValueError, "commit objects"):
            self.check(self.git("rev-parse", "fixture").strip())
        self.git("checkout", "--quiet", "--orphan", "unrelated")
        with self.assertRaises(ValueError):
            self.check(self.commit("Unrelated root"))

    def test_ref_strings_are_rejected_before_git(self):
        git = Mock()
        for value in ("HEAD", "--help", "f" * 39, "F" * 40, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "full commit SHAs"):
                dco.check(value, self.base, git, self.api)
        git.assert_not_called()

    def test_mailmap_does_not_rewrite_author_identity(self):
        (self.root / ".mailmap").write_text("Reviewer <reviewer@example.com> Fixture Author <author@example.com>\n")
        self.git("add", ".mailmap")
        head = self.commit("Spoof mapped author\n\nSigned-off-by: Reviewer <reviewer@example.com>")
        with self.assertRaisesRegex(ValueError, head):
            self.check(head)

    def test_replace_objects_cannot_hide_an_unsigned_commit(self):
        unsigned = self.commit("Unsigned original")
        signed = self.commit("Replacement\n\nSigned-off-by: Fixture Author <author@example.com>")
        self.git("replace", unsigned, signed)
        with self.assertRaisesRegex(ValueError, unsigned):
            self.check(unsigned)

    def test_cli_checks_full_range(self):
        head = self.commit("Change\n\nSigned-off-by: Fixture Author <author@example.com>")
        result = subprocess.run(["python3", str(Path(dco.__file__)), "--root", str(self.root),
                                 "--base", self.base, "--head", head,
                                 "--repository", "Alien6-Studio/hankoshell-operator"],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(head, result.stdout)


class DCOExceptionTests(unittest.TestCase):
    def setUp(self):
        self.commit = {"sha": "a" * 40, "author": {"name": "Fixture Author", "email": "author@example.com"},
                       "committer": {"name": dco.WEB_FLOW_NAME, "email": dco.WEB_FLOW_EMAIL}}

    def document(self, commit=None):
        commit = commit or self.commit
        return {"sha": commit["sha"], "author": {"login": "fixture", "type": "User"},
                "committer": {"login": "web-flow"}, "commit": {
                    "author": copy.deepcopy(commit["author"]), "committer": copy.deepcopy(commit["committer"]),
                    "verification": {"verified": True, "reason": "valid"}}}

    def test_verified_web_flow_is_an_explicit_exception(self):
        api = Mock(return_value=self.document())
        self.assertEqual(dco.verified_exception(self.commit, api), "GitHub Verified web-flow exception")
        api.assert_called_once_with(self.commit["sha"])

    def test_verified_dependabot_is_an_explicit_exception(self):
        self.commit["author"] = {"name": dco.DEPENDABOT_NAME, "email": dco.DEPENDABOT_EMAIL}
        self.commit["committer"] = {"name": "Fixture Maintainer", "email": "maintainer@example.com"}
        document = self.document()
        document["author"] = {"login": "dependabot[bot]", "type": "Bot"}
        self.assertEqual(dco.verified_exception(self.commit, lambda sha: document), "GitHub Verified Dependabot exception")

    def test_bot_lookalike_names_do_not_grant_exceptions(self):
        self.commit["author"] = {"name": dco.DEPENDABOT_NAME, "email": "attacker@example.com"}
        self.commit["committer"] = {"name": "GitHub", "email": "attacker@example.com"}
        api = Mock()
        self.assertIsNone(dco.verified_exception(self.commit, api))
        api.assert_not_called()

    def test_missing_malformed_conflicting_or_unverified_api_metadata_fails(self):
        mutations = (
            lambda doc: doc.update(sha="b" * 40),
            lambda doc: doc.update(commit=None),
            lambda doc: doc["commit"].update(author=None),
            lambda doc: doc["commit"]["author"].update(email="attacker@example.com"),
            lambda doc: doc["commit"]["committer"].update(name="Attacker"),
            lambda doc: doc["commit"].update(verification=None),
            lambda doc: doc["commit"]["verification"].update(verified=False),
            lambda doc: doc["commit"]["verification"].update(verified="true"),
            lambda doc: doc["commit"]["verification"].update(reason="unsigned"),
            lambda doc: doc.update(committer=None),
            lambda doc: doc["committer"].update(login="attacker"),
        )
        for mutate in mutations:
            document = self.document()
            mutate(document)
            with self.subTest(document=document), self.assertRaises(ValueError):
                dco.verified_exception(self.commit, lambda sha: document)
        for document in (None, [], "not a document"):
            with self.subTest(document=document), self.assertRaises(ValueError):
                dco.verified_exception(self.commit, lambda sha: document)

    def test_unverified_or_spoofed_dependabot_is_rejected(self):
        self.commit["author"] = {"name": dco.DEPENDABOT_NAME, "email": dco.DEPENDABOT_EMAIL}
        self.commit["committer"] = {"name": "Fixture Maintainer", "email": "maintainer@example.com"}
        for author in ({"login": "attacker", "type": "Bot"}, {"login": "dependabot[bot]", "type": "User"}, None):
            document = self.document()
            document["author"] = author
            with self.subTest(author=author), self.assertRaises(ValueError):
                dco.verified_exception(self.commit, lambda sha: document)
        document["author"] = {"login": "dependabot[bot]", "type": "Bot"}
        document["commit"]["verification"]["verified"] = False
        with self.assertRaisesRegex(ValueError, "Verified"):
            dco.verified_exception(self.commit, lambda sha: document)

    def test_api_failure_does_not_grant_an_exception(self):
        with self.assertRaisesRegex(ValueError, "unavailable"):
            dco.verified_exception(self.commit, Mock(side_effect=ValueError("API unavailable")))

    def test_commands_fail_closed_without_dumping_payloads(self):
        for outcome in (OSError("missing"), subprocess.TimeoutExpired("fixture", 30)):
            with patch.object(dco.subprocess, "run", side_effect=outcome), self.assertRaisesRegex(ValueError, "unavailable"):
                dco.command(["fixture"])
        for result in (subprocess.CompletedProcess([], 1, "", "private diagnostic"),
                       subprocess.CompletedProcess([], 0, "x" * ((1 << 20) + 1), "")):
            with patch.object(dco.subprocess, "run", return_value=result), self.assertRaises(ValueError) as raised:
                dco.command(["fixture"])
            self.assertNotIn("private diagnostic", str(raised.exception))

    def test_malformed_github_json_is_rejected(self):
        with patch.object(dco, "command", return_value="not JSON"), self.assertRaisesRegex(ValueError, "Malformed GitHub"):
            dco.github_commit("Alien6-Studio/hankoshell-operator", self.commit["sha"])


if __name__ == "__main__":
    unittest.main()

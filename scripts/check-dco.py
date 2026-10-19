"""Check author-matching DCO trailers on the exact pull-request commit range."""

import argparse
import json
from pathlib import Path
import re
import subprocess


SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
IDENTITY = re.compile(r"([^<>\r\n]+) <([^<>\s]+)>")
DEPENDABOT_NAME = "dependabot[bot]"
DEPENDABOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
WEB_FLOW_NAME = "GitHub"
WEB_FLOW_EMAIL = "noreply@github.com"


def command(args, *, cwd=None, input=None):
    try:
        result = subprocess.run(args, cwd=cwd, input=input, capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("DCO metadata command unavailable") from error
    if result.returncode:
        raise ValueError("DCO metadata command failed; ensure both commits are fetched")
    if len(result.stdout.encode("utf-8")) > 1 << 20:
        raise ValueError("DCO metadata exceeds the size limit")
    return result.stdout


def commits(base, head, git):
    for revision in (base, head):
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise ValueError("DCO base and head must be full commit SHAs")
        if git("rev-parse", "--verify", "--end-of-options", revision + "^{commit}").strip() != revision:
            raise ValueError("DCO range must identify commit objects")
    git("merge-base", base, head)
    revisions = git("rev-list", "--reverse", base + ".." + head).splitlines()
    if not revisions or any(not SHA.fullmatch(revision) for revision in revisions):
        raise ValueError("DCO range must contain pull-request commits")
    result = []
    for revision in revisions:
        raw = git("show", "--no-show-signature", "--no-patch",
                  "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B",
                  "--end-of-options", revision)
        fields = raw.split("\0", 5)
        if len(fields) != 6 or fields[0] != revision:
            raise ValueError("Malformed DCO commit metadata for " + revision)
        for name, email in ((fields[1], fields[2]), (fields[3], fields[4])):
            if not name.strip() or not IDENTITY.fullmatch(name + " <" + email + ">"):
                raise ValueError("Malformed DCO author/committer identity for " + revision)
        result.append({"sha": revision, "author": {"name": fields[1], "email": fields[2]},
                       "committer": {"name": fields[3], "email": fields[4]}, "message": fields[5]})
    return result


def has_signoff(commit, trailers):
    for line in trailers.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key.casefold() != "signed-off-by":
            continue
        identity = IDENTITY.fullmatch(value.strip())
        if identity and identity[1] == commit["author"]["name"] and \
                identity[2].casefold() == commit["author"]["email"].casefold():
            return True
    return False


def verified_exception(commit, api):
    bot = commit["author"] == {"name": DEPENDABOT_NAME, "email": DEPENDABOT_EMAIL}
    web = commit["committer"] == {"name": WEB_FLOW_NAME, "email": WEB_FLOW_EMAIL}
    if not (bot or web):
        return None
    document = api(commit["sha"])
    if not isinstance(document, dict) or document.get("sha") != commit["sha"]:
        raise ValueError("GitHub returned conflicting DCO commit metadata")
    metadata = document.get("commit")
    if not isinstance(metadata, dict):
        raise ValueError("GitHub returned malformed DCO commit metadata")
    for field in ("author", "committer"):
        identity = metadata.get(field)
        if not isinstance(identity, dict) or any(identity.get(key) != value
                                                for key, value in commit[field].items()):
            raise ValueError("GitHub DCO author/committer differs from the checked commit")
    verification = metadata.get("verification")
    if not isinstance(verification, dict) or verification.get("verified") is not True or \
            verification.get("reason") != "valid":
        raise ValueError("DCO exceptions require a GitHub Verified signature")
    author, committer = document.get("author"), document.get("committer")
    if bot and isinstance(author, dict) and author.get("login") == DEPENDABOT_NAME and author.get("type") == "Bot":
        return "GitHub Verified Dependabot exception"
    if web and isinstance(committer, dict) and committer.get("login") == "web-flow":
        return "GitHub Verified web-flow exception"
    raise ValueError("DCO exception lacks the authenticated GitHub bot/web-flow identity")


def check(base, head, git, api):
    outcomes, failures = [], []
    for commit in commits(base, head, git):
        try:
            trailers = git("interpret-trailers", "--parse", input=commit["message"])
            outcome = "author-matching Signed-off-by trailer" if has_signoff(commit, trailers) else verified_exception(commit, api)
            if outcome is None:
                raise ValueError("missing author-matching Signed-off-by trailer; use git commit -s")
            outcomes.append(commit["sha"] + ": " + outcome)
        except ValueError as error:
            failures.append(commit["sha"] + ": " + str(error))
    if failures:
        raise ValueError("\n".join(failures))
    return outcomes


def github_commit(repository, revision):
    # Retain only identity metadata, never patches or commit messages in diagnostics.
    query = "{sha, author: {login: .author.login, type: .author.type}, committer: {login: .committer.login}, commit: {author: .commit.author, committer: .commit.committer, verification: {verified: .commit.verification.verified, reason: .commit.verification.reason}}}"
    try:
        return json.loads(command(["gh", "api", "--hostname", "github.com",
                                   "repos/" + repository + "/commits/" + revision, "--jq", query]))
    except json.JSONDecodeError as error:
        raise ValueError("Malformed GitHub DCO verification response") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        if not REPOSITORY.fullmatch(args.repository):
            raise ValueError("Invalid DCO repository identity")
        outcomes = check(args.base, args.head,
                         lambda *params, input=None: command(["git", "--no-replace-objects", *params], cwd=args.root, input=input),
                         lambda revision: github_commit(args.repository, revision))
    except ValueError as error:
        raise SystemExit("DCO rejected:\n" + str(error)) from None
    print("DCO passed for " + str(len(outcomes)) + " commit(s):\n" + "\n".join(outcomes))


if __name__ == "__main__":
    main()

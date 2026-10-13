"""Check reviewed GitHub protections offline; --live compares them using GET only.

Exports contain importable configuration, including bypass actors. Server IDs,
timestamps and caller-specific metadata are not policy. Unknown configuration,
missing visibility and any policy drift fail the full audit. The explicit
--allow-hidden-bypass mode checks visible policy and reports hidden bypass lists;
nothing updates GitHub or rewrites the reviewed exports.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Alien6-Studio/hankoshell-operator"
EXPORTS = {"default-branch.json": "Protect default branch", "release-tags.json": "Release tags"}
CONFIG_FIELDS = {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"}
SERVER_FIELDS = {"id", "node_id", "source_type", "source", "created_at", "updated_at",
                 "current_user_can_bypass", "_links"}
MAX_DOCUMENT_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(data):
    require(len(data) <= MAX_DOCUMENT_BYTES, "Ruleset document exceeds 1 MiB")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key in ruleset document")
            result[key] = value
        return result

    def invalid_number(_value):
        raise ValueError("Ruleset document requires finite integer numbers")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_number, parse_float=invalid_number)


def canonical(value):
    """Policy arrays are sets; reordering never conceals additions/removals."""
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=encoded)
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def same(left, right):
    # JSON comparison distinguishes false/0 and true/1, unlike Python equality.
    return encoded(canonical(left)) == encoded(canonical(right))


def configuration(value, *, live=False, allow_hidden_bypass=False):
    require(isinstance(value, dict), "Ruleset must be an object")
    required = CONFIG_FIELDS - ({"bypass_actors"} if live and allow_hidden_bypass else set())
    require(required <= value.keys(), "Incomplete ruleset configuration (including bypass visibility)")
    require(not value.keys() - CONFIG_FIELDS - (SERVER_FIELDS if live else set()),
            "Unknown ruleset configuration field")
    require(isinstance(value["rules"], list), "Ruleset rules must be a list")
    types = []
    for rule in value["rules"]:
        require(isinstance(rule, dict) and isinstance(rule.get("type"), str), "Invalid ruleset rule")
        types.append(rule["type"])
    require(len(types) == len(set(types)), "Duplicate rule type")
    return {key: value[key] for key in CONFIG_FIELDS if key in value}


def rule_map(config):
    return {rule["type"]: rule for rule in config["rules"]}


def check_contract(root=ROOT):
    directory = root / ".github/rulesets"
    require({path.name for path in directory.glob("*.json")} == set(EXPORTS), "Unexpected ruleset export inventory")
    exports = {}
    for filename, name in EXPORTS.items():
        config = configuration(decode((directory / filename).read_bytes()))
        require(config["name"] == name, "Unexpected exported ruleset name")
        require(config["enforcement"] == "active" and config["bypass_actors"] == [],
                "Reviewed rulesets must be active with no bypass actors")
        exports[filename] = config

    branch = exports["default-branch.json"]
    require(branch["target"] == "branch" and same(branch["conditions"],
            {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}), "Default branch scope changed")
    rules = rule_map(branch)
    require(set(rules) == {"deletion", "non_fast_forward", "required_linear_history", "required_signatures",
                           "pull_request", "code_scanning", "required_status_checks"}, "Default branch protections changed")
    for name in ("deletion", "non_fast_forward", "required_linear_history", "required_signatures"):
        require(rules[name] == {"type": name}, "Unexpected branch protection parameters")
    require(same(rules["pull_request"], {"type": "pull_request", "parameters": {
        "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": True, "required_reviewers": [],
        "require_code_owner_review": False, "dismissal_restriction": {"enabled": False, "allowed_actors": []},
        "require_last_push_approval": False, "required_review_thread_resolution": True,
        "require_extra_approval_for_unattributed_changes": True, "allowed_merge_methods": ["squash"],
    }}), "Review/squash policy changed; SECURITY.md and exports require review")
    require(same(rules["code_scanning"], {"type": "code_scanning", "parameters": {"code_scanning_tools": [{
        "tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors",
    }]}}), "CodeQL protection changed")
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    gate = ci["jobs"]["checks"]["name"]
    require(isinstance(gate, str) and bool(gate), "Required CI aggregate has no stable name")
    require(same(rules["required_status_checks"], {"type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": True, "do_not_enforce_on_create": False,
        "required_status_checks": [{"context": gate, "integration_id": 15368}],
    }}), "Required status check differs from the CI aggregate or its GitHub Actions binding")

    tags = exports["release-tags.json"]
    require(tags["target"] == "tag" and same(tags["conditions"],
            {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}}), "Release tag scope changed")
    require(same(tags["rules"], [{"type": "deletion"}, {"type": "non_fast_forward"}]),
            "Release tag deletion/rewrite protections changed")
    return exports


def github_document(path):
    try:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
            "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10", path],
            capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("GitHub ruleset read unavailable or timed out") from error
    require(result.returncode == 0, "GitHub ruleset read failed; verify metadata read access")
    # Never print subprocess diagnostics, which could contain credential data.
    return decode(result.stdout)


def check_live(exports, repository=REPOSITORY, api=github_document, *, allow_hidden_bypass=False):
    require(isinstance(repository, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository),
            "Invalid repository identity")
    base = "repos/" + repository + "/rulesets"
    inventory = api(base + "?includes_parents=true&per_page=100")
    require(isinstance(inventory, list) and len(inventory) < 100, "Ruleset inventory malformed or incomplete")
    require(len(inventory) == len(exports), "Live ruleset inventory differs (including inherited rulesets)")
    names, ids = set(), set()
    live = {}
    for item in inventory:
        require(isinstance(item, dict), "Invalid ruleset inventory entry")
        identity, name = item.get("id"), item.get("name")
        require(type(identity) is int and identity > 0 and identity not in ids, "Invalid or duplicate ruleset ID")
        require(isinstance(name, str) and name in EXPORTS.values() and name not in names,
                "Unexpected or duplicate live ruleset name")
        require(item.get("source_type") == "Repository" and item.get("source") == repository,
                "Unexpected inherited ruleset authority")
        names.add(name)
        ids.add(identity)
        detail = api(base + "/" + str(identity))
        require(isinstance(detail, dict) and type(detail.get("id")) is int and detail["id"] == identity
                and detail.get("name") == name and detail.get("source_type") == "Repository"
                and detail.get("source") == repository, "Ruleset response identity differs from inventory")
        live[name] = configuration(detail, live=True, allow_hidden_bypass=allow_hidden_bypass)
    hidden = []
    for filename, expected in exports.items():
        actual = live[expected["name"]]
        compared = CONFIG_FIELDS
        if "bypass_actors" not in actual:
            hidden.append(filename)
            compared = CONFIG_FIELDS - {"bypass_actors"}
        changed = sorted(key for key in compared if not same(expected[key], actual[key]))
        require(not changed, "Ruleset drift in " + filename + ": " + ", ".join(changed))
    return hidden


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--allow-hidden-bypass", action="store_true",
                        help="compare visible fields and warn if GitHub hides bypass actors (never a full audit)")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", REPOSITORY))
    args = parser.parse_args()
    if args.allow_hidden_bypass and not args.live:
        parser.error("--allow-hidden-bypass requires --live")
    hidden = []
    try:
        exports = check_contract()
        if args.live:
            hidden = check_live(exports, args.repository, allow_hidden_bypass=args.allow_hidden_bypass)
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError) as error:
        print("Ruleset check failed: " + str(error), file=sys.stderr)
        return 1
    if hidden:
        print("::warning::Visible ruleset policy matches; bypass actors remain UNVERIFIED: " + ", ".join(hidden))
    else:
        print("Ruleset exports match the security contract" + (" and live GitHub configuration" if args.live else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

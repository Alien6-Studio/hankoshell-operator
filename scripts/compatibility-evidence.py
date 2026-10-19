"""Validate reviewed production reports and derive public-release summaries.

No network access, issue-body ingestion, telemetry or publication. Human privacy
review is mandatory; structural validation cannot prove that a report is true.
"""

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "docs/compatibility-evidence.json"
SUMMARIES = "docs/compatibility-evidence"
GITHUB = "https://github.com/Alien6-Studio/hankoshell-operator"
REVIEW_CHECKS = {"no_credentials", "no_personal_or_tenant_data", "no_raw_dumps", "anonymous_installation", "public_release_verified"}
SCENARIOS = {"installation", "upgrade", "rollback", "adoption", "rotation", "migration", "recovery"}
REPORT_KEYS = {"id", "installation", "reported_on", "source_issue", "review", "mode", "from_version", "to_version",
               "kubernetes", "keycloak", "resources", "scenarios", "outcome", "incidents", "migration", "fixtures", "privacy_review"}


def require(value, message):
    if not value:
        raise ValueError(message)


def exact_keys(value, expected):
    require(isinstance(value, dict) and set(value) == expected, "Evidence fields must match the reviewed allowlist")


def match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def reference(value, kind):
    require(match(re.escape(GITHUB) + "/" + kind + r"/[1-9][0-9]*", value), "Evidence requires a repository issue or review PR")


def unique(values, allowed):
    require(isinstance(values, list) and 0 < len(values) <= len(allowed) and all(isinstance(v, str) for v in values)
            and len(values) == len(set(values)) and set(values) <= allowed, "Evidence contains missing, repeated or unknown choices")


def local_file(root, name):
    require(isinstance(name, str) and match(r"[a-zA-Z0-9_./-]+\.json", name), "Fixture reference must name a repository JSON file")
    path = root / name
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()) and path.is_file(), "Fixture reference leaves the repository or is missing")
    require(path.stat().st_size <= 512 * 1024, "Evidence fixture exceeds its review budget")
    return path


def load(root=ROOT, today=None):
    today = today or date.today()
    registry = json.loads((root / REGISTRY).read_text())
    exact_keys(registry, {"schema_version", "reports"})
    require(type(registry["schema_version"]) is int and registry["schema_version"] == 1, "Unknown evidence registry version")
    reports = registry["reports"]
    require(isinstance(reports, list) and len(reports) <= 4096, "Evidence report budget exceeded")
    policy = json.loads((root / "docs/compatibility-policy.json").read_text())
    releases = {}
    for release in policy["public_releases"]:
        version = release["version"]
        require(match(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) and version not in releases,
                "Public evidence requires unique public release versions")
        published = date.fromisoformat(release["published_on"])
        require(published <= today, "A future publication is not production evidence")
        releases[version] = published
    kinds = {r["kind"] for r in json.loads((root / "docs/api-support.json").read_text())["resources"]}
    seen = set()
    sources = set()
    for report in reports:
        exact_keys(report, REPORT_KEYS)
        identifier = report["id"]
        require(match(r"EVID-[0-9]{4,8}", identifier) and identifier not in seen, "Evidence IDs must be unique")
        seen.add(identifier)
        require(match(r"installation-[0-9a-f]{16}", report["installation"]), "Use an anonymous random installation reference")
        reference(report["source_issue"], "issues")
        reference(report["review"], "pull")
        require(report["source_issue"] not in sources, "One source report cannot count as independent duplicate evidence")
        sources.add(report["source_issue"])
        reported = date.fromisoformat(report["reported_on"])
        require(reported <= today, "Future observations cannot be accepted")
        versions = (report["from_version"], report["to_version"])
        require(all(isinstance(v, str) and v in releases and releases[v] <= reported for v in versions),
                "Development, invented or not-yet-published releases are not production evidence")
        require(report["mode"] in ("standalone", "connected"), "Unknown installation mode")
        for platform in ("kubernetes", "keycloak"):
            require(match(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", report[platform]), "Exact provider and Kubernetes versions are mandatory")
        unique(report["resources"], kinds)
        unique(report["scenarios"], SCENARIOS)
        require(report["outcome"] in ("pass", "failed", "limited"), "Unknown observed outcome")
        if versions[0] != versions[1]:
            require(bool(set(report["scenarios"]) & {"upgrade", "rollback"}), "A version pair requires an observed upgrade or rollback scenario")
        else:
            require(not set(report["scenarios"]) & {"upgrade", "rollback"}, "Same-version configuration changes are not public release upgrades")
        exact_keys(report["privacy_review"], REVIEW_CHECKS)
        require(all(value is True for value in report["privacy_review"].values()), "Every human privacy review check is mandatory")
        incidents = report["incidents"]
        require(isinstance(incidents, list) and len(incidents) <= 32, "Incident budget exceeded")
        incident_ids = set()
        for incident in incidents:
            exact_keys(incident, {"id", "issue", "status", "resolution"})
            require(match(r"INC-[0-9]{4,8}", incident["id"]) and incident["id"] not in incident_ids, "Incident IDs must be unique per report")
            incident_ids.add(incident["id"])
            reference(incident["issue"], "issues")
            require(incident["status"] in ("open", "resolved"), "Unknown incident resolution state")
            if incident["status"] == "resolved":
                reference(incident["resolution"], "pull")
            else:
                require(incident["resolution"] is None, "Open incident cannot claim a resolution")
        require(report["outcome"] == "pass" or incidents, "Failures and limitations require a tracked incident")
        require(report["migration"] in ("not-required", "planned", "reproduced"), "Unknown migration observation")
        fixtures = report["fixtures"]
        require(isinstance(fixtures, list) and len(fixtures) <= 32, "Fixture budget exceeded")
        paths = set()
        for fixture in fixtures:
            exact_keys(fixture, {"path", "sha256"})
            path = local_file(root, fixture["path"])
            require(fixture["path"] not in paths, "Repeated fixture reference")
            paths.add(fixture["path"])
            require(match(r"[0-9a-f]{64}", fixture["sha256"]) and hashlib.sha256(path.read_bytes()).hexdigest() == fixture["sha256"], "Referenced fixture changed without review")
            captured = json.loads(path.read_text())
            require(isinstance(captured, dict) and identifier in captured.get("compatibility_reports", []) and captured.get("source_release") in versions,
                    "A historical fixture must cite its report and observed release")
        if report["migration"] == "reproduced":
            require("migration" in report["scenarios"] and fixtures, "Reproduced migration needs an explicit scenario and retained fixture")
    return releases, reports


def render(releases, reports):
    pages = {}
    lines = ["# Public compatibility evidence", "", "Generated from the reviewed [registry](../compatibility-evidence.json).",
             "Reports describe observed paths and limitations; they do not grant stable maturity or extend support.", ""]
    if not releases:
        lines += ["No published public release is recorded. No production reports or upgrade paths are claimed.", ""]
    else:
        lines += ["| Public release | Reports | Open incidents |", "| --- | ---: | ---: |"]
    for version in sorted(releases, key=lambda value: tuple(map(int, value.split(".")))):
        selected = sorted((r for r in reports if version in (r["from_version"], r["to_version"])), key=lambda r: r["id"])
        open_count = sum(i["status"] == "open" for r in selected for i in r["incidents"])
        lines.append(f"| [{version}](v{version}.md) | {len(selected)} | {open_count} |")
        page = [f"# Compatibility evidence for {version}", "", f"Recorded publication: {releases[version].isoformat()}.", "",
                "Observed reports only; missing scenarios remain unqualified. Anonymous references do not prove installation independence.", ""]
        if not selected:
            page += ["No reviewed production report received for this release.", ""]
        for report in selected:
            page += [f"## {report['id']}", "", f"[Source report]({report['source_issue']}); [privacy and evidence review]({report['review']}).", "",
                     f"- Installation: `{report['installation']}`; mode: {report['mode']}; observed: {report['reported_on']}.",
                     f"- Path: {report['from_version']} → {report['to_version']}; Kubernetes {report['kubernetes']}; Keycloak {report['keycloak']}.",
                     f"- Resources: {', '.join(sorted(report['resources']))}.",
                     f"- Scenarios: {', '.join(sorted(report['scenarios']))}; outcome: **{report['outcome']}**; migration: {report['migration']}."]
            for incident in report["incidents"]:
                resolution = f"; [resolution]({incident['resolution']})" if incident["resolution"] else ""
                page.append(f"- [{incident['id']}]({incident['issue']}): {incident['status']}{resolution}.")
            for fixture in report["fixtures"]:
                page.append(f"- [Retained fixture](../../{fixture['path']}); SHA-256 `{fixture['sha256']}`.")
            page.append("")
        pages[f"v{version}.md"] = "\n".join(page).rstrip() + "\n"
    pages["README.md"] = "\n".join(lines).rstrip() + "\n"
    return pages


def check(root=ROOT, *, write=False):
    releases, reports = load(root)
    pages = render(releases, reports)
    folder = root / SUMMARIES
    require(not folder.is_symlink(), "Evidence summary folder must stay in the repository")
    if write:
        folder.mkdir(parents=True, exist_ok=True)
        require(all(not (folder / name).is_symlink() for name in pages), "Refuse to overwrite a linked evidence summary")
        for name, content in pages.items():
            (folder / name).write_text(content)
    require(folder.is_dir() and {p.name for p in folder.iterdir()} == set(pages), "Missing or unreviewed per-release evidence summary")
    for name, content in pages.items():
        require(not (folder / name).is_symlink() and (folder / name).read_text() == content, "Evidence summary differs from reviewed reports; run render")
    return {"public_releases": len(releases), "production_reports": len(reports), "state": "ReviewedReports" if reports else "NoProductionReports"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "render"))
    args = parser.parse_args()
    print(json.dumps(check(write=args.command == "render"), sort_keys=True))

"""Review gates for prospective graduation; never manufacture stable maturity."""

import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

CRITERIA = {"conformance", "installed", "production", "ownership", "compatibility", "security", "operations", "blockers"}


def document(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("graduation evidence must be an existing repository file")
    return path


def check(root=ROOT):
    inventory = json.loads((root / "tools/qualification/config/contracts/api-support.json").read_text())
    data = json.loads((root / "tools/qualification/config/contracts/stable-graduation.json").read_text())
    if (data.get("schemaVersion") != 1 or data.get("stage") != "development" or data.get("ratified") is not False
            or set(data.get("criteria", {})) != CRITERIA):
        raise ValueError("graduation must retain measurable unratified development criteria")
    for criterion in data["criteria"].values():
        if not criterion.get("threshold"):
            raise ValueError("graduation criterion requires a measurable threshold")
        document(root, criterion["evidence"])
    records = data.get("resources", [])
    by_kind = {r["kind"]: r for r in records}
    if len(records) != len(by_kind) or set(by_kind) != {r["kind"] for r in inventory["resources"]}:
        raise ValueError("graduation records must cover each public resource exactly once")
    for resource in inventory["resources"]:
        record = by_kind[resource["kind"]]
        if record.get("disposition") not in ("staying-alpha", "experimental") or record.get("targetVersion") != "v1alpha1":
            raise ValueError("no resource can graduate before production, migration and ratification evidence")
        if len(record.get("criteria", [])) != len(CRITERIA) or set(record["criteria"]) != CRITERIA or not record.get("blockers"):
            raise ValueError("every non-graduating resource requires all criteria and explicit blockers")
        if set(record.get("specGroups", {})) != set(resource["specFields"]) or set(record.get("statusGroups", {})) != set(resource["statusFields"]):
            raise ValueError(f"unreviewed graduation field group for {resource['kind']}")
        for field, group in record["specGroups"].items():
            if group.get("maturity") not in ("alpha", "experimental") or group.get("providerNative") != (field in resource["nativeSpecFields"]):
                raise ValueError("graduation changed a field maturity or native extension boundary")
        if any(v not in ("alpha", "experimental") for v in record["statusGroups"].values()):
            raise ValueError("public evidence fields have not graduated")
        if record.get("productionEvidence") != []:
            raise ValueError("first production reports require explicit sanitized evidence review")
        if not record.get("evidence"):
            raise ValueError("graduation record needs evidence")
        for path in record["evidence"]:
            document(root, path)
    review = provider_review(root)
    for path in ("README.md", "docs/api-support.md"):
        text = (root / path).read_text()
        if "stable-graduation.md" not in text or "stable-provider-review.md" not in text:
            raise ValueError("entry-point documentation must link the graduation and provider decisions")
    return data, review


def provider_review(root):
    review = json.loads((root / "tools/qualification/config/contracts/stable-provider-review.json").read_text())
    if (review.get("schemaVersion") != 1 or review.get("stage") != "development"
            or review.get("secondProviderStatus") != "experimental" or review.get("approvedLosses") != []):
        raise ValueError("second-provider review cannot imply production support or accepted losses")
    path = document(root, review["corpus"])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != review.get("corpusSha256"):
        raise ValueError("portable semantics changed without an explicit stable review")
    corpus = json.loads(path.read_text())
    semantics = review.get("semantics", [])
    by_name = {s["fixture"]: s for s in semantics}
    if len(semantics) != len(by_name) or set(by_name) != {f["name"] for f in corpus["fixtures"]}:
        raise ValueError("provider review must cover each shared semantic exactly once")
    for fixture in corpus["fixtures"]:
        row = by_name[fixture["name"]]
        expected = {p: e["classification"] for p, e in fixture["expected"].items()}
        if (row.get("providers") != expected or row.get("capability") != fixture["capability"]
                or row.get("intentIdentity") != fixture.get("intentIdentity", "") or row.get("currentMaturity") != "experimental"):
            raise ValueError("provider review differs from frozen observed intent")
        if row.get("decision") not in ("portable-candidate", "native-extension-candidate", "experimental") or not row.get("scope"):
            raise ValueError("semantic requires an explicit bounded review decision")
        if row["decision"] == "portable-candidate" and (set(expected.values()) != {"lossless"} or not row["intentIdentity"]):
            raise ValueError("unsupported or lossy semantics cannot become portable candidates")
    pins = json.loads((root / "versions.json").read_text())
    cells = set(itertools.product(pins["kubernetes"]["versions"], pins["keycloak"]["versions"]))
    seen = set()
    if set(review.get("reportHashes", {})) != set(review.get("installedEvidence", [])):
        raise ValueError("every retained report must have its reviewed byte digest")
    for name in review.get("installedEvidence", []):
        report_path = document(root, name)
        if hashlib.sha256(report_path.read_bytes()).hexdigest() != review["reportHashes"][name]:
            raise ValueError("retained provider report changed without review")
        report = json.loads(report_path.read_text())
        cell = report.get("kubernetes_version"), report.get("keycloak_version")
        if cell in seen or cell not in cells or report.get("complete") is not True or report.get("publishable") is not False:
            raise ValueError("provider review needs complete unique nonpublishable supported cells")
        seen.add(cell)
        if (report.get("revision") != review.get("reviewedRevision") or report.get("corpus_sha256") != digest
                or report.get("image_digest") != review.get("reviewedImageDigest") or report.get("fixture_sha256") != review.get("fixtureSha256")
                or report.get("approved_losses") != [] or report.get("hub_enabled") is not False):
            raise ValueError("provider evidence source/corpus/authority binding differs")
        differences = report.get("differences", [])
        expected = {(f["name"], p): e["classification"] for f in corpus["fixtures"] for p, e in f["expected"].items()}
        if len(differences) != len(expected) or {(d["fixture"], d["provider"]): d["classification"] for d in differences} != expected or any(d.get("observed") is not True for d in differences):
            raise ValueError("provider evidence omits or changes an observed semantic")
    if seen != cells:
        raise ValueError("provider review needs the full supported installed window")
    return review


if __name__ == "__main__":
    check()
    print("All resource graduation records and provider semantic decisions agree with frozen evidence")

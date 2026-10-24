"""Capture synthetic installed objects; import them only with authentic public delivery evidence."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile

from tools.release import release_version as versioning

from tools.qualification.lib.evidence_privacy import contains_jwt

MAX_BYTES = 512 * 1024
KINDS = {"HankoApplication", "HankoRole", "HankoResourceServer"}
IDENTITY = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"ghcr\.io/alien6-studio/hankoshell-operator@sha256:[0-9a-f]{64}")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def capture(objects, schemas, version, revision, image, sensitive=()):
    if not IDENTITY.fullmatch(revision) or not IMAGE.fullmatch(image):
        raise ValueError("Capture needs exact installed source and image identities")
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?", version):
        raise ValueError("Invalid capture version")
    if not 1 <= len(objects) <= 64:
        raise ValueError("Synthetic capture object budget exceeded")
    fixtures, seen = [], set()
    for obj in objects:
        kind, metadata = obj.get("kind"), obj.get("metadata", {})
        key = kind, metadata.get("name")
        if (kind not in KINDS or key in seen or not str(metadata.get("name", "")).startswith("public-")
                or metadata.get("namespace") != "auth" or metadata.get("labels", {}).get("hanko-fixture") != "public-contract"
                or obj.get("apiVersion") != "hanko.sh/v1alpha1" or not metadata.get("uid")):
            raise ValueError("Capture is restricted to explicitly labelled synthetic public-contract objects")
        seen.add(key)
        status = obj.get("status", {})
        generation = metadata.get("generation")
        if (type(generation) is not int or generation < 1 or status.get("observedGeneration") != generation
                or status.get("phase") != "Ready" or not status.get("appliedPlanHash")
                or status.get("appliedPlanHash") != status.get("observationPlanHash")
                or status.get("observationComplete") is not True):
            raise ValueError("Capture requires current applied and complete read-back evidence")
        fixtures.append({"apiVersion": obj["apiVersion"], "kind": kind,
            "metadata": {field: copy.deepcopy(metadata[field]) for field in ("name", "namespace", "uid", "generation", "finalizers") if field in metadata},
            "spec": copy.deepcopy(obj["spec"]), "status": copy.deepcopy(status)})
    used_schemas = {kind: copy.deepcopy(schemas[kind]) for kind in sorted({obj["kind"] for obj in fixtures})}
    result = {"schema_version": 1, "state": "captured-for-review", "published": False,
              "source_release": version, "revision": revision, "image": image,
              "scope": "synthetic-installed-public-contract", "compatibility_reports": [],
              "schemas": used_schemas, "fixtures": sorted(fixtures, key=lambda obj: (obj["kind"], obj["metadata"]["name"]))}
    raw = json.dumps(result, sort_keys=True)
    if len(raw.encode()) > MAX_BYTES or contains_jwt(raw) or any(value and value in raw for value in sensitive):
        raise ValueError("Capture exceeds its budget or contains credential-shaped data")
    forbidden = {"password", "accesstoken", "refreshtoken", "privatekey", "clientsecret"}
    def inspect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                secret_reference = (key == "clientSecret" and isinstance(child, dict) and set(child) == {"secretRef"}
                    and isinstance(child["secretRef"], dict) and {"name", "key"} <= set(child["secretRef"]) <= {"name", "key", "optional"})
                if re.sub(r"[_-]", "", key).lower() in forbidden and not secret_reference:
                    raise ValueError("Credential fields are forbidden in public fixtures")
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
    inspect(fixtures)
    return result


def approve(capture_path, verification_path, reports, review):
    """A human reviews privacy; authenticated delivery alone cannot approve publication."""
    raw = capture_path.read_bytes()
    if capture_path.is_symlink() or len(raw) > MAX_BYTES:
        raise ValueError("Invalid captured corpus")
    captured, verified = json.loads(raw), json.loads(verification_path.read_text())
    if (captured.get("published") is not False or captured.get("state") != "captured-for-review"
            or captured.get("scope") != "synthetic-installed-public-contract"
            or not versioning.is_stable(captured.get("source_release", ""))):
        raise ValueError("Only authentic published stable versions can enter the historical corpus")
    expected = {"version": captured["source_release"], "revision": captured["revision"], "image": captured["image"]}
    if (any(verified.get(key) != value for key, value in expected.items()) or verified.get("verified") is not True
            or verified.get("published") is not True or verified.get("fixture_sha256") != hashlib.sha256(raw).hexdigest()):
        raise ValueError("Public delivery verification does not bind this captured corpus")
    if (not isinstance(reports, list) or not reports or len(set(reports)) != len(reports)
            or any(not re.fullmatch(r"EVID-[0-9]{4,8}", report) for report in reports)
            or not re.fullmatch(r"https://github\.com/Alien6-Studio/hankoshell-operator/pull/[1-9][0-9]*", review)):
        raise ValueError("Import requires real report references and a human privacy review PR")
    captured.update(published=True, state="reviewed-public-predecessor", compatibility_reports=reports,
                    review=review, captured_sha256=hashlib.sha256(raw).hexdigest(), verification=verified)
    return captured


def capture_installed(args):
    from tools.qualification.scenarios import system_test as system

    class CapturedSystem(system.System):
        def public_contract_corpus(self):
            super().public_contract_corpus()
            source = json.loads((system.ROOT / "internal/iamconformance/testdata/public-initial/corpus.json").read_text())
            selected = [(item["kind"], "public-" + item["name"]) for item in source["fixtures"]]
            selected += [("HankoRole", "public-writer"), ("HankoRole", "public-viewer")]
            objects = []
            for kind, name in selected:
                self.kubectl("label", kind.lower(), name, "-n", "auth", "hanko-fixture=public-contract", "--overwrite")
                objects.append(self.get(kind.lower(), name))
            schemas = {obj["spec"]["names"]["kind"]: obj["spec"] for obj in
                       json.loads(self.kubectl("get", "crds", "-o", "json"))["items"]}
            self.captured = capture(objects, schemas, system.VERSION, args.revision,
                                    system.publication.publish.IMAGE + "@" + args.digest, self.sensitive)

    if args.output.exists() or args.output.with_suffix(".corpus.json").exists():
        raise ValueError("Installed capture requires fresh output paths")
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hanko-public-corpus-private-") as directory:
        fixture = CapturedSystem(args, Path(directory))
        try:
            fixture.create_cluster()
            fixture.keycloak()
            fixture.install()
            fixture.reconcile()
            args.output.with_suffix(".corpus.json").write_text(json.dumps(fixture.captured, indent=2, sort_keys=True) + "\n")
            args.output.write_text(json.dumps({"version": system.VERSION, "revision": args.revision,
                "image_digest": args.digest, "kubernetes": system.KUBERNETES_VERSION, "keycloak": system.KEYCLOAK_VERSION,
                "result": "pass", "public_contract": fixture.public_corpus_evidence,
                "operational_checks": fixture.observability_checks, "sensitive_write_checks": fixture.sensitive_write_checks,
                "limitations": ["synthetic installed capture for review; not a public predecessor or stable compatibility promise"]},
                indent=2, sort_keys=True) + "\n")
        except Exception as error:
            system.diagnostics.capture(fixture, error)
            raise
        finally:
            fixture.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    installed = subparsers.add_parser("capture", help="Run the installed suite and retain its synthetic corpus")
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        installed.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        installed.add_argument("--" + name, required=True)
    approval = subparsers.add_parser("approve", help="Prepare an authenticated historical corpus for privacy review")
    approval.add_argument("--capture", type=Path, required=True)
    approval.add_argument("--verification", type=Path, required=True)
    approval.add_argument("--report", action="append", required=True)
    approval.add_argument("--privacy-review", required=True)
    approval.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "capture":
        capture_installed(args)
        return
    result = approve(args.capture, args.verification, args.report, args.privacy_review)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

"""Scan and verify the immutable final multi-architecture OCI delivery."""
import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCANNER_VERSION = "0.75.0"
PLATFORMS = ("linux/amd64", "linux/arm64")
POLICY = ROOT / "security/oci-vulnerability-policy.json"
REPORTS = {platform: "trivy-" + platform.split("/")[1] + ".json" for platform in PLATFORMS}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SUMMARY = "oci-security.json"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_policy(path=POLICY, today=None):
    policy = json.loads(path.read_text())
    if (set(policy) != {"schema_version", "fail_severities", "only_fixable", "exceptions"}
            or policy["schema_version"] != 1 or policy["fail_severities"] != ["HIGH", "CRITICAL"]
            or policy["only_fixable"] is not True or not isinstance(policy["exceptions"], list)):
        raise ValueError("Invalid OCI vulnerability policy")
    today = today or datetime.now(timezone.utc).date()
    seen = set()
    for exception in policy["exceptions"]:
        fields = {"cve", "package", "target", "installed_version", "justification", "expires"}
        if not isinstance(exception, dict) or set(exception) != fields or any(not isinstance(v, str) or not v.strip() for v in exception.values()):
            raise ValueError("Invalid vulnerability exception fields")
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", exception["cve"]) or len(exception["justification"].strip()) < 20:
            raise ValueError("Exception needs an exact CVE and justification")
        if any(c in exception[field] for field in ("package", "target", "installed_version") for c in "*?[]"):
            raise ValueError("Broad vulnerability exceptions are forbidden")
        expiry = date.fromisoformat(exception["expires"])
        if expiry.isoformat() != exception["expires"] or not today < expiry <= today + timedelta(days=90):
            raise ValueError("Exception must be unexpired and reviewed within 90 days")
        key = tuple(exception[field] for field in ("cve", "package", "target", "installed_version"))
        if key in seen:
            raise ValueError("Duplicate vulnerability exception")
        seen.add(key)
    return policy


def image_manifests(archive, digest):
    """Verify the OCI graph without executing binaries or extracting layers."""
    if not DIGEST.fullmatch(digest):
        raise ValueError("Expected the immutable OCI index digest")
    with tarfile.open(archive) as package:
        members = {}
        for member in package.getmembers():
            name = member.name.rstrip("/")
            if member.isdir():
                continue
            if (name in members or not member.isfile() or str(PurePosixPath(name)) != name
                    or not (name in {"index.json", "oci-layout"} or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name))):
                raise ValueError("Unsafe or duplicate OCI archive member")
            members[name] = member
        def data(name):
            member = members[name]
            if member.size > 32 * 1024 * 1024:
                raise ValueError("Oversize OCI metadata")
            with package.extractfile(member) as source:
                return json.load(source)
        if data("oci-layout") != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("Unsupported OCI layout")
        roots = data("index.json")["manifests"]
        if len(roots) != 1 or roots[0]["digest"] != digest:
            raise ValueError("OCI archive index differs from the BuildKit digest")
        checked = set()
        def blob(descriptor, metadata=False):
            value = descriptor["digest"]
            if not DIGEST.fullmatch(value):
                raise ValueError("Unsupported OCI blob digest")
            name = "blobs/sha256/" + value.split(":")[1]
            member = members[name]
            if member.size != descriptor["size"]:
                raise ValueError("OCI blob size mismatch")
            if value not in checked:
                with package.extractfile(member) as source:
                    if "sha256:" + hashlib.file_digest(source, "sha256").hexdigest() != value:
                        raise ValueError("OCI blob checksum mismatch")
                checked.add(value)
            return data(name) if metadata else None
        index = blob(roots[0], True)
        runtime, attestations = {}, []
        for descriptor in index["manifests"]:
            manifest = blob(descriptor, True)
            config = blob(manifest["config"], True)
            for layer in manifest["layers"]:
                blob(layer)
            platform = descriptor.get("platform", {})
            platform_name = platform.get("os", "") + "/" + platform.get("architecture", "")
            if platform_name in PLATFORMS:
                if platform_name in runtime or platform != {"os": "linux", "architecture": platform_name.split("/")[1]}:
                    raise ValueError("Duplicate or ambiguous runtime platform")
                if config.get("os") != "linux" or config.get("architecture") != platform_name.split("/")[1]:
                    raise ValueError("Runtime configuration architecture mismatch")
                runtime[platform_name] = {"digest": descriptor["digest"], "config_digest": manifest["config"]["digest"]}
            elif descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                target = descriptor["annotations"]["vnd.docker.reference.digest"]
                predicates = set()
                for layer in manifest["layers"]:
                    statement = blob(layer, True)
                    subjects = statement.get("subject", [])
                    # OCI exporter evidence may leave subjects empty; the index's
                    # attestation descriptor binds it to the runtime digest.
                    if subjects and not any("sha256:" + subject.get("digest", {}).get("sha256", "") == target for subject in subjects):
                        raise ValueError("BuildKit evidence subject mismatch")
                    predicates.add(statement["predicateType"])
                attestations.append((target, predicates))
            else:
                raise ValueError("Unexpected OCI platform or manifest")
        if set(runtime) != set(PLATFORMS):
            raise ValueError("Both AMD64 and ARM64 runtime images must be scanned")
        for record in runtime.values():
            evidence = [predicates for target, predicates in attestations if target == record["digest"]]
            if (len(evidence) != 1 or "https://spdx.dev/Document" not in evidence[0]
                    or not {"https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"}.intersection(evidence[0])):
                raise ValueError("Missing per-platform BuildKit SBOM or provenance")
        return runtime


def evaluate(report, config_digest, policy):
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image"
            or report.get("Metadata", {}).get("ImageID") != config_digest or not isinstance(report.get("Results"), list)):
        raise ValueError("Scanner report does not identify the expected runtime image")
    results = report["Results"]
    binaries = {result.get("Target", "").lstrip("/"): result for result in results if result.get("Type") == "gobinary"}
    for target in ("hankoshell-operator", "usr/local/bin/cosign"):
        if target not in binaries or not binaries[target].get("Packages"):
            raise ValueError("Scanner omitted a shipped Go binary: " + target)
        if not any(p.get("Name") == "stdlib" for p in binaries[target]["Packages"]):
            raise ValueError("Scanner omitted Go runtime metadata: " + target)
    if not any(p.get("Name") == "github.com/sigstore/cosign/v3" and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", p.get("Version") or "")
               for p in binaries["usr/local/bin/cosign"]["Packages"]):
        raise ValueError("Scanner omitted the embedded cosign main module version")
    if not any(result.get("Class") == "os-pkgs" and result.get("Packages") for result in results):
        raise ValueError("Scanner omitted OS package inventory")
    blocked, allowed, unfixed = [], [], []
    for result in results:
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = vulnerability["Severity"]
            if severity not in policy["fail_severities"]:
                continue
            finding = {"cve": vulnerability["VulnerabilityID"], "package": vulnerability["PkgName"],
                       "target": "os:" + result["Type"] if result.get("Class") == "os-pkgs" else result["Target"].lstrip("/"),
                       "installed_version": vulnerability["InstalledVersion"],
                       "severity": severity, "fixed_version": vulnerability.get("FixedVersion", "")}
            if not finding["fixed_version"]:
                unfixed.append(finding)
                continue
            exception = next((entry for entry in policy["exceptions"] if all(entry[key] == finding[key] for key in ("cve", "package", "target", "installed_version"))), None)
            if severity == "HIGH" and exception:
                allowed.append(finding)
            else:
                blocked.append(finding)
    return {"blocked": blocked, "exceptions_applied": allowed, "unfixed_high_critical": unfixed}


def scanner_env():
    return {key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")}


def scan(args):
    policy = read_policy()
    platforms = image_manifests(args.archive, args.digest)
    scanner = args.scanner.resolve()
    version = json.loads(subprocess.check_output([str(scanner), "--version", "--format", "json"], text=True, env=scanner_env(), timeout=30))
    if version.get("Version") != SCANNER_VERSION:
        raise ValueError("Unexpected image scanner version")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as directory:
        layout = Path(directory) / "layout"
        with tarfile.open(args.archive) as package:
            package.extractall(layout, filter="data")
        base = [str(scanner), "image", "--quiet", "--config", "", "--cache-dir", directory, "--disable-telemetry"]
        subprocess.run(base + ["--download-db-only"], check=True, env=scanner_env(), timeout=300)
        database = Path(directory) / "db"
        db_metadata = json.loads((database / "metadata.json").read_text())
        updated = datetime.fromisoformat(db_metadata["UpdatedAt"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if not now - timedelta(hours=48) <= updated <= now + timedelta(minutes=5):
            raise ValueError("Vulnerability database is stale or future-dated")
        summary = {"schema_version": 1, "scanner": {"name": "trivy", "version": SCANNER_VERSION, "binary_sha256": sha256(scanner)},
                   "index_digest": args.digest, "archive_sha256": sha256(args.archive), "revision": args.revision,
                   "version": args.version, "scanned_at": now.isoformat(), "policy_sha256": sha256(POLICY),
                   "database": {"sha256": sha256(database / "trivy.db"), "metadata": db_metadata}, "platforms": {}}
        for platform, record in platforms.items():
            output = args.output / REPORTS[platform]
            # Trivy's OCI loader can pick the first index entry even with
            # --platform. A single-manifest view fixes the exact child digest;
            # all original blobs and the delivery archive remain unchanged.
            view = Path(directory) / platform.split("/")[1]
            view.mkdir()
            (view / "oci-layout").write_text((layout / "oci-layout").read_text())
            (view / "blobs").symlink_to(layout / "blobs", target_is_directory=True)
            manifest_blob = layout / "blobs/sha256" / record["digest"].split(":")[1]
            (view / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": record["digest"],
                "size": manifest_blob.stat().st_size, "platform": {"os": "linux", "architecture": platform.split("/")[1]},
            }]}))
            subprocess.run(base + ["--skip-db-update", "--scanners", "vuln", "--pkg-types", "os,library",
                                   "--ignorefile", "", "--ignore-policy", "", "--ignore-unfixed=false", "--sbom-sources", "",
                                   "--list-all-pkgs", "--format", "json", "--output", str(output.resolve()),
                                   "--platform", platform, "--input", str(view)],
                           check=True, env=scanner_env(), timeout=600)
            verdict = evaluate(json.loads(output.read_text()), record["config_digest"], policy)
            summary["platforms"][platform] = dict(record, report_sha256=sha256(output), **verdict)
        summary["verdict"] = "fail" if any(p["blocked"] for p in summary["platforms"].values()) else "pass"
        (args.output / SUMMARY).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        if summary["verdict"] != "pass":
            raise ValueError("Fixable HIGH/CRITICAL vulnerabilities block the OCI delivery; inspect the JSON reports")


def verify(evidence, revision, version, digest, archive=None, *, fresh=True):
    policy = read_policy()
    summary = json.loads((evidence / SUMMARY).read_text())
    if (summary.get("schema_version") != 1 or summary.get("verdict") != "pass" or summary.get("revision") != revision
            or summary.get("version") != version or summary.get("index_digest") != digest or summary.get("policy_sha256") != sha256(POLICY)
            or summary.get("scanner", {}).get("name") != "trivy" or summary["scanner"].get("version") != SCANNER_VERSION
            or set(summary.get("platforms", {})) != set(PLATFORMS)):
        raise ValueError("OCI security evidence identity or policy mismatch")
    scanned = datetime.fromisoformat(summary["scanned_at"])
    now = datetime.now(timezone.utc)
    if scanned > now + timedelta(minutes=5) or (fresh and scanned < now - timedelta(hours=24)):
        raise ValueError("OCI scan must belong to a fresh delivery")
    records = image_manifests(archive, digest) if archive else None
    if archive and summary["archive_sha256"] != sha256(archive):
        raise ValueError("Verified OCI archive content changed")
    for platform, record in summary["platforms"].items():
        if records and any(record[key] != records[platform][key] for key in ("digest", "config_digest")):
            raise ValueError("Verified platform digest changed")
        report = evidence / REPORTS[platform]
        verdict = evaluate(json.loads(report.read_text()), record["config_digest"], policy)
        if record["report_sha256"] != sha256(report) or verdict["blocked"] or any(record[key] != verdict[key] for key in verdict):
            raise ValueError("OCI scanner report or verdict changed")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("scan", "verify"))
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--scanner", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not DIGEST.fullmatch(args.digest) or not re.fullmatch(r"[0-9a-f]{40}", args.revision) or args.version != "0.2.0":
        parser.error("Expected immutable digest, full revision and version 0.2.0")
    if args.mode == "scan":
        if args.archive is None or args.scanner is None:
            parser.error("Scanning requires the exact OCI archive and pinned scanner")
        scan(args)
    else:
        verify(args.output, args.revision, args.version, args.digest, args.archive)


if __name__ == "__main__":
    main()

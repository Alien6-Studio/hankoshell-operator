import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oci = load("oci_security", "oci-security.py")
installer = load("install_trivy", "install-trivy.py")


def report(config):
    results = [{"Target": "fixture (debian 13)", "Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "base-files", "Version": "13"}]}]
    for target in ("hankoshell-operator", "usr/local/bin/cosign"):
        packages = [{"Name": "stdlib", "Version": "v1.27.1"}]
        if target.endswith("cosign"):
            packages.append({"Name": "github.com/sigstore/cosign/v3", "Version": "v3.1.3"})
        results.append({"Target": target, "Class": "lang-pkgs", "Type": "gobinary", "Packages": packages, "Vulnerabilities": []})
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": config}, "Results": results}


def write_evidence(directory, revision, version, digest):
    summary = {"schema_version": 1, "verdict": "pass", "scanner": {"name": "trivy", "version": oci.SCANNER_VERSION, "binary_sha256": "b" * 64},
               "index_digest": digest, "archive_sha256": "a" * 64, "revision": revision, "version": version,
               "scanned_at": datetime.now(timezone.utc).isoformat(), "policy_sha256": oci.sha256(oci.POLICY),
               "database": {"sha256": "c" * 64, "metadata": {}}, "platforms": {}}
    for i, platform in enumerate(oci.PLATFORMS):
        config = "sha256:" + str(i + 1) * 64
        path = directory / oci.REPORTS[platform]
        path.write_text(json.dumps(report(config)))
        summary["platforms"][platform] = {"digest": "sha256:" + str(i + 3) * 64, "config_digest": config,
                                         "report_sha256": oci.sha256(path), **oci.evaluate(report(config), config, oci.read_policy())}
    (directory / oci.SUMMARY).write_text(json.dumps(summary))
    return summary


def archive_fixture(path, omit=None, revision=None):
    blobs, manifests = {}, []
    def blob(value):
        contents = value if isinstance(value, bytes) else json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(contents).hexdigest()
        blobs["blobs/sha256/" + digest.split(":")[1]] = contents
        return {"digest": digest, "size": len(contents), "mediaType": "application/vnd.oci.image.manifest.v1+json"}
    for platform in oci.PLATFORMS:
        if platform == omit:
            continue
        arch = platform.split("/")[1]
        config = blob({"architecture": arch, "os": "linux", "config": {"Labels": {"org.opencontainers.image.revision": revision}}})
        image = blob({"schemaVersion": 2, "config": config, "layers": [blob(b"synthetic runtime layer")]})
        image["platform"] = {"architecture": arch, "os": "linux"}
        manifests.append(image)
        layers = [blob({"subject": [], "predicateType": predicate}) for predicate in
                  ("https://spdx.dev/Document", "https://slsa.dev/provenance/v1")]
        attestation = blob({"schemaVersion": 2, "config": blob({}), "layers": layers})
        attestation.update({"platform": {"os": "unknown", "architecture": "unknown"},
                            "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": image["digest"]}})
        manifests.append(attestation)
    index = blob({"schemaVersion": 2, "manifests": manifests})
    blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [index]}).encode()
    blobs["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    with tarfile.open(path, "w") as archive:
        for name, data in blobs.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return index["digest"]


class ScannerAcquisitionTests(unittest.TestCase):
    def test_archive_integrity_and_regular_executable_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, executable = Path(directory) / "scanner.tgz", Path(directory) / "trivy"
            for kind in (tarfile.REGTYPE, tarfile.SYMTYPE):
                with tarfile.open(archive, "w:gz") as package:
                    member = tarfile.TarInfo("trivy")
                    member.type, member.size = kind, 4 if kind == tarfile.REGTYPE else 0
                    member.linkname = "/untrusted" if kind == tarfile.SYMTYPE else ""
                    package.addfile(member, io.BytesIO(b"tool") if member.size else None)
                digest = oci.sha256(archive)
                with self.assertRaises(ValueError):
                    installer.unpack(archive, "0" * 64, executable)
                if kind == tarfile.REGTYPE:
                    installer.unpack(archive, digest, executable)
                    self.assertEqual(executable.read_bytes(), b"tool")
                else:
                    with self.assertRaises(ValueError):
                        installer.unpack(archive, digest, executable)

    def test_version_and_acquisition_are_pinned(self):
        self.assertEqual(installer.VERSION, oci.SCANNER_VERSION)
        self.assertEqual(len(installer.ARCHIVES), 2)
        self.assertTrue(all(len(checksum) == 64 for _, checksum in installer.ARCHIVES.values()))
        with patch.object(installer.subprocess, "check_output", return_value='{"Version":"0.74.0"}'), self.assertRaises(ValueError):
            installer.check_version(Path("/scanner"))
        with patch.object(installer.subprocess, "check_output", return_value=json.dumps({"Version": installer.VERSION})):
            installer.check_version(Path("/scanner"))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(installer.platform, "system", return_value="Linux"), \
                patch.object(installer.platform, "machine", return_value="x86_64"), \
                patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(b"untrusted archive")) as download:
            destination = Path(directory) / "installed"
            with self.assertRaises(ValueError):
                installer.install(destination)
            self.assertFalse(destination.exists())
            self.assertEqual(download.call_args.args[0], "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz")


class VulnerabilityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = "sha256:" + "1" * 64
        self.report = report(self.config)
        self.finding = {"VulnerabilityID": "CVE-2026-12345", "PkgName": "example/library", "InstalledVersion": "v1.0.0",
                        "FixedVersion": "v1.0.1", "Severity": "HIGH"}
        self.report["Results"][-1]["Vulnerabilities"] = [self.finding]
        self.policy = oci.read_policy()

    def exception(self):
        return {"cve": self.finding["VulnerabilityID"], "package": self.finding["PkgName"], "target": "usr/local/bin/cosign",
                "installed_version": "v1.0.0", "justification": "Reviewed narrowly scoped temporary mitigation.",
                "expires": (datetime.now(timezone.utc).date() + timedelta(days=7)).isoformat()}

    def test_fixable_high_and_critical_block_but_unfixed_are_recorded(self):
        for severity in ("HIGH", "CRITICAL"):
            self.finding["Severity"] = severity
            verdict = oci.evaluate(self.report, self.config, self.policy)
            self.assertEqual(len(verdict["blocked"]), 1)
            self.finding["FixedVersion"] = ""
            verdict = oci.evaluate(self.report, self.config, self.policy)
            self.assertFalse(verdict["blocked"])
            self.assertEqual(len(verdict["unfixed_high_critical"]), 1)
            self.finding["FixedVersion"] = "v1.0.1"

    def test_only_exact_high_exception_is_allowed_and_critical_is_never_exempt(self):
        self.policy["exceptions"] = [self.exception()]
        self.assertEqual(len(oci.evaluate(self.report, self.config, self.policy)["exceptions_applied"]), 1)
        for field, value in (("target", "hankoshell-operator"), ("package", "another/library"), ("installed_version", "v0.9.0")):
            altered = copy.deepcopy(self.policy)
            altered["exceptions"][0][field] = value
            self.assertTrue(oci.evaluate(self.report, self.config, altered)["blocked"])
        self.finding["Severity"] = "CRITICAL"
        self.assertTrue(oci.evaluate(self.report, self.config, self.policy)["blocked"])

    def test_expired_broad_missing_and_duplicate_exceptions_fail_closed(self):
        for field, value in (("expires", "2020-01-01"), ("expires", "2099-01-01"), ("cve", "CVE-*"),
                             ("package", "*"), ("target", "*"), ("justification", ""), ("installed_version", "")):
            policy = copy.deepcopy(self.policy)
            entry = self.exception()
            entry[field] = value
            policy["exceptions"] = [entry]
            self.assert_invalid(policy)
        entry = self.exception()
        self.assert_invalid(dict(self.policy, exceptions=[entry, entry]))
        del entry["justification"]
        self.assert_invalid(dict(self.policy, exceptions=[entry]))
        self.assert_invalid(dict(self.policy, fail_severities=["CRITICAL"]))

    def assert_invalid(self, policy):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                oci.read_policy(path)

    def test_missing_binary_runtime_os_inventory_and_wrong_architecture_are_rejected(self):
        for index in range(3):
            changed = copy.deepcopy(self.report)
            del changed["Results"][index]
            with self.assertRaises(ValueError):
                oci.evaluate(changed, self.config, self.policy)
        with self.assertRaises(ValueError):
            oci.evaluate(self.report, "sha256:" + "2" * 64, self.policy)
        for package in ("stdlib", "github.com/sigstore/cosign/v3"):
            changed = copy.deepcopy(self.report)
            changed["Results"][-1]["Packages"] = [p for p in changed["Results"][-1]["Packages"] if p["Name"] != package]
            with self.subTest(missing=package), self.assertRaises(ValueError):
                oci.evaluate(changed, self.config, self.policy)
        changed = copy.deepcopy(self.report)
        changed["Results"][-1]["Packages"][-1]["Version"] = "(devel)"
        with self.assertRaises(ValueError):
            oci.evaluate(changed, self.config, self.policy)


class ImageEvidenceTests(unittest.TestCase):
    def test_digest_graph_requires_both_runtime_platforms_and_native_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            digest = archive_fixture(archive)
            self.assertEqual(set(oci.image_manifests(archive, digest)), set(oci.PLATFORMS))
            with self.assertRaises(ValueError):
                oci.image_manifests(archive, "sha256:" + "0" * 64)
            digest = archive_fixture(archive, omit="linux/arm64")
            with self.assertRaises(ValueError):
                oci.image_manifests(archive, digest)

    def test_scan_failure_and_exact_per_platform_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "image.tar"
            digest = archive_fixture(archive)
            scanner = root / "trivy"
            scanner.write_bytes(b"scanner fixture")
            args = SimpleNamespace(archive=archive, digest=digest, scanner=scanner, output=root / "evidence", revision="1" * 40, version="0.1.0")
            seen = []
            def scanner_run(command, **kwargs):
                cache = Path(command[command.index("--cache-dir") + 1])
                if "--download-db-only" in command:
                    database = cache / "db"
                    database.mkdir()
                    (database / "trivy.db").write_bytes(b"database fixture")
                    (database / "metadata.json").write_text(json.dumps({"UpdatedAt": datetime.now(timezone.utc).isoformat()}))
                    return
                view = Path(command[command.index("--input") + 1])
                descriptor = json.loads((view / "index.json").read_text())["manifests"]
                self.assertEqual(len(descriptor), 1)
                manifest = json.loads((view / "blobs/sha256" / descriptor[0]["digest"].split(":")[1]).read_text())
                platform = command[command.index("--platform") + 1]
                self.assertEqual(descriptor[0]["platform"]["architecture"], platform.split("/")[1])
                seen.append(manifest["config"]["digest"])
                result = report(manifest["config"]["digest"])
                Path(command[command.index("--output") + 1]).write_text(json.dumps(result))
            with patch.object(oci.subprocess, "check_output", return_value=json.dumps({"Version": oci.SCANNER_VERSION})), \
                    patch.object(oci.subprocess, "run", side_effect=scanner_run):
                oci.scan(args)
            self.assertEqual(len(set(seen)), 2)
            oci.verify(args.output, args.revision, args.version, digest, archive)
            args.output = root / "policy-failed"
            def vulnerable_scanner(command, **kwargs):
                scanner_run(command, **kwargs)
                if "--output" in command:
                    path = Path(command[command.index("--output") + 1])
                    result = json.loads(path.read_text())
                    result["Results"][-1]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2026-12345", "PkgName": "fixture",
                        "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"}]
                    path.write_text(json.dumps(result))
            with patch.object(oci.subprocess, "check_output", return_value=json.dumps({"Version": oci.SCANNER_VERSION})), \
                    patch.object(oci.subprocess, "run", side_effect=vulnerable_scanner), self.assertRaises(ValueError):
                oci.scan(args)
            self.assertEqual(json.loads((args.output / oci.SUMMARY).read_text())["verdict"], "fail")
            args.output = root / "failed"
            with patch.object(oci.subprocess, "check_output", return_value=json.dumps({"Version": oci.SCANNER_VERSION})), \
                    patch.object(oci.subprocess, "run", side_effect=subprocess.CalledProcessError(2, ["trivy"])), \
                    self.assertRaises(subprocess.CalledProcessError):
                oci.scan(args)
            self.assertFalse((args.output / oci.SUMMARY).exists())

    def test_changed_reports_identity_or_stale_evidence_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest, revision = "sha256:" + "a" * 64, "1" * 40
            summary = write_evidence(root, revision, "0.1.0", digest)
            oci.verify(root, revision, "0.1.0", digest)
            for field, value in (("index_digest", "sha256:" + "b" * 64), ("revision", "2" * 40),
                                 ("verdict", "fail"), ("scanned_at", "2020-01-01T00:00:00+00:00")):
                changed = dict(summary, **{field: value})
                (root / oci.SUMMARY).write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    oci.verify(root, revision, "0.1.0", digest)
            (root / oci.SUMMARY).write_text(json.dumps(summary))
            (root / "trivy-arm64.json").write_text("{}")
            with self.assertRaises(ValueError):
                oci.verify(root, revision, "0.1.0", digest)


class ReleaseWorkflowSecurityTests(unittest.TestCase):
    def test_scanned_digest_is_the_only_release_image_source_and_promotion_follows_attest(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        gate = yaml.safe_load((ROOT / ".github/workflows/oci-security.yml").read_text())
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        self.assertEqual(ci["jobs"]["oci"]["uses"], "./.github/workflows/oci-security.yml")
        self.assertIn("oci", ci["jobs"]["checks"]["needs"])
        self.assertEqual(release["jobs"]["quality"]["uses"], "./.github/workflows/ci.yml")
        self.assertEqual(release["jobs"]["publish"]["needs"], "quality")
        self.assertNotIn("if", release["jobs"]["publish"])
        self.assertEqual(ci[True]["workflow_call"]["outputs"]["oci_digest"]["value"], "${{ jobs.oci.outputs.digest }}")
        self.assertEqual(ci[True]["workflow_call"]["outputs"]["oci_artifact_id"]["value"], "${{ jobs.oci.outputs.artifact_id }}")
        self.assertEqual(gate[True]["workflow_call"]["outputs"]["digest"]["value"], "${{ jobs.image.outputs.digest }}")
        self.assertEqual(gate["jobs"]["image"]["outputs"]["digest"], "${{ steps.image.outputs.digest }}")
        self.assertEqual(gate["jobs"]["image"]["outputs"]["artifact_id"], "${{ steps.archive.outputs.artifact-id }}")
        image = next(step for step in gate["jobs"]["image"]["steps"] if step.get("id") == "image")
        self.assertEqual(image["with"]["platforms"], "linux/amd64,linux/arm64")
        self.assertIs(image["with"]["push"], False)
        self.assertEqual(image["with"]["provenance"], "mode=max")
        self.assertIs(image["with"]["sbom"], True)
        self.assertIn("type=oci", image["with"]["outputs"])
        gate_steps = gate["jobs"]["image"]["steps"]
        scan_step = next(step for step in gate_steps if "oci-security.py scan" in step.get("run", ""))
        self.assertNotIn("if", scan_step)
        self.assertFalse(scan_step.get("continue-on-error", False))
        self.assertEqual(scan_step["env"]["DIGEST"], "${{ steps.image.outputs.digest }}")
        self.assertIn('--digest "$DIGEST"', scan_step["run"])
        steps = release["jobs"]["publish"]["steps"]
        download = next(step for step in steps if "download-artifact" in step.get("uses", ""))
        self.assertEqual(download["with"]["artifact-ids"], "${{ needs.quality.outputs.oci_artifact_id }}")
        self.assertFalse(any("build-push-action" in step.get("uses", "") or "buildx build" in step.get("run", "") for step in steps))
        bound = "${{ needs.quality.outputs.oci_digest }}"
        for step in steps:
            if "DIGEST" in step.get("env", {}):
                self.assertEqual(step["env"]["DIGEST"], bound)
                self.assertFalse(step.get("continue-on-error", False))
                self.assertNotIn("if", step)
        scan = next(i for i, step in enumerate(steps) if "oci-security.py verify --archive" in step.get("run", ""))
        sign = next(i for i, step in enumerate(steps) if '/tmp/cosign sign --yes' in step.get("run", ""))
        attest = next(i for i, step in enumerate(steps) if 'scripts/attest-release.py --attest' in step.get("run", ""))
        promote = next(i for i, step in enumerate(steps) if 'oras" tag' in step.get("run", ""))
        self.assertLess(scan, sign)
        self.assertLess(sign, attest)
        self.assertLess(attest, promote)
        self.assertIn('image.tar@$DIGEST', steps[scan]["run"])
        self.assertIn('--image "$IMAGE@$DIGEST"', steps[sign]["run"])
        self.assertIn('--image "$IMAGE@$DIGEST"', steps[attest]["run"])
        self.assertIn("scripts/release-contract.py prepare", steps[sign]["run"])
        self.assertIn('--evidence "$RUNNER_TEMP/hankoshell-scanned-oci/evidence"', steps[sign]["run"])
        packaging = (Path(__file__).parents[1] / "scripts/release-contract.py").read_text()
        for filename in ("oci-security.json", "trivy-amd64.json", "trivy-arm64.json"):
            self.assertIn(filename, packaging)
        self.assertIn("shutil.copyfile(security.POLICY", packaging)
        self.assertIn('$IMAGE:staging-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT', steps[scan]["run"])
        self.assertIn('"$IMAGE@$DIGEST" "$VERSION"', steps[promote]["run"])
        self.assertIn('"$IMAGE:$VERSION")" = "$DIGEST"', steps[promote]["run"])
        for workflow in (ci, gate, release):
            for job in workflow["jobs"].values():
                self.assertFalse(job.get("continue-on-error", False))
                for step in job.get("steps", []):
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()

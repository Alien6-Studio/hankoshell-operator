import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("release_contract", Path(__file__).with_name("release-contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
dry_run = contract.module("release_dry_run", "release-dry-run.py")


class ReleaseContractTests(unittest.TestCase):
    def test_exported_rulesets_match_the_required_gate_and_weekly_audit_is_read_only(self):
        rulesets = contract.module("rulesets_contract", "check-rulesets.py")
        exports = rulesets.check_contract()
        self.assertEqual(set(exports), {"default-branch.json", "release-tags.json"})
        ci = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())
        source = ci["jobs"]["source"]
        audit = next(step for step in source["steps"] if "check-rulesets.py" in step.get("run", ""))
        self.assertEqual(audit["if"], "github.event_name == 'schedule'")
        self.assertEqual(audit["env"], {"GH_TOKEN": "${{ github.token }}"})
        self.assertEqual(audit["run"], "python3 scripts/check-rulesets.py --live --allow-hidden-bypass")
        self.assertFalse(audit.get("continue-on-error", False))
        self.assertEqual(source.get("permissions", ci["permissions"]), {"contents": "read"})
        self.assertIn("source", ci["jobs"]["checks"]["needs"])
        security = (contract.ROOT / "SECURITY.md").read_text()
        for statement in (".github/rulesets/default-branch.json", ".github/rulesets/release-tags.json",
                          "zero mandatory approving reviews", "resolved review threads", "verified signatures",
                          "linear", "squash", "refs/tags/v*", "UNVERIFIED", "--allow-hidden-bypass"):
            self.assertIn(statement, security)

    def test_development_pushes_run_preflight_without_weakening_full_qualification(self):
        workflows = contract.ROOT / ".github/workflows"
        development = yaml.safe_load((workflows / "development.yml").read_text())
        ci = yaml.safe_load((workflows / "ci.yml").read_text())
        # PyYAML's YAML 1.1 loader represents the Actions "on" key as True.
        self.assertEqual(development[True], {"push": {"branches": ["feat/1.0.0-dev"]}})
        self.assertEqual(set(development["jobs"]), {"preflight", "security-fuzz"})
        expected = copy.deepcopy(ci["jobs"]["preflight"])
        expected["name"] = "Development source preflight"
        # Development adds the same hooks enforced in source, retaining every
        # existing preflight command and its permissions/timeout.
        install = next(step for step in expected["steps"] if step.get("name") == "Install pinned preflight dependencies")
        install["run"] = install["run"].replace("make install-preflight-tools\n", "make install-preflight-tools install-hook-tools\n")
        validation = next(step for step in expected["steps"] if step.get("run") == "make preflight")
        validation["run"] += " hooks-check"
        self.assertEqual(development["jobs"]["preflight"], expected)
        self.assertTrue(development["concurrency"]["cancel-in-progress"])
        self.assertEqual(ci["concurrency"]["cancel-in-progress"], "${{ github.event_name != 'workflow_dispatch' }}")
        self.assertNotEqual(development["concurrency"]["group"], ci["concurrency"]["group"])
        self.assertEqual(ci[True]["push"], {"branches": ["main"]})
        self.assertIn("pull_request", ci[True])
        self.assertIsNone(ci[True]["pull_request"])
        self.assertIn("workflow_dispatch", ci[True])
        self.assertIn("schedule", ci[True])

    def test_dco_checks_the_pr_head_and_complete_commit_range_without_credentials_in_git(self):
        jobs = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        steps = jobs["source"]["steps"]
        checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
        self.assertIs(checkout["with"]["persist-credentials"], False)
        self.assertEqual(checkout["with"]["fetch-depth"], 0)
        self.assertNotIn("ref", checkout["with"])  # Other source checks still qualify the PR test merge.
        check = next(step for step in steps if "scripts/check-dco.py" in step.get("run", ""))
        self.assertEqual(check["if"], "github.event_name == 'pull_request'")
        self.assertFalse(check.get("continue-on-error", False))
        self.assertEqual(check["env"], {"DCO_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                                       "DCO_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
                                       "GH_TOKEN": "${{ github.token }}"})
        self.assertIn('--base "$DCO_BASE_SHA" --head "$DCO_HEAD_SHA"', check["run"])
        self.assertIn('--repository "$GITHUB_REPOSITORY"', check["run"])
        self.assertLess(steps.index(check), next(i for i, step in enumerate(steps) if "make test" in step.get("run", "")))

    def test_ci_preflight_blocks_every_expensive_job_and_remains_required(self):
        ci = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        self.assertEqual(set(ci), {"preflight", "source", "kubernetes", "keycloak", "keycloak-ordinary", "keycloak-extension", "keycloak-static", "workload", "oci",
                                   "rehearsal", "system", "installed-workload", "installed-delegation", "installed-portable", "installed-fleet", "security-fuzz", "security-mutations", "checks",
                                   "schedule-report", "installed-scale-qualification", "installed-transactions"})
        for job in ("source", "kubernetes", "keycloak", "keycloak-ordinary", "keycloak-extension", "keycloak-static", "workload", "security-fuzz", "security-mutations", "oci"):
            with self.subTest(job=job):
                self.assertEqual(ci[job].get("needs"), ["preflight"])
                self.assertNotIn("if", ci[job])  # Keep implicit success(), including for reusable OCI.
                self.assertFalse(ci[job].get("continue-on-error", False))
        for job in ("rehearsal", "system", "installed-workload", "installed-portable", "installed-fleet"):
            self.assertEqual(ci[job]["needs"], ["source", "oci"])
            self.assertNotIn("if", ci[job])
        self.assertEqual(ci["installed-delegation"]["needs"], ["source", "oci", "keycloak-extension"])
        self.assertNotIn("if", ci["installed-delegation"])
        self.assertEqual(ci["installed-scale-qualification"]["needs"], ["source", "oci"])
        self.assertNotIn("needs", ci["preflight"])
        self.assertNotIn("if", ci["preflight"])
        self.assertFalse(ci["preflight"].get("continue-on-error", False))
        self.assertEqual(set(ci["checks"]["needs"]), set(ci) - {"checks", "schedule-report"})
        self.assertEqual(ci["checks"]["name"], "Source and chart checks")
        self.assertEqual(ci["checks"]["if"], "always()")
        self.assertIn("make preflight", [step.get("run") for step in ci["preflight"]["steps"]])
        makefile = (contract.ROOT / "Makefile").read_text()
        self.assertRegex(makefile, r"(?m)^preflight: fmt-check vet generated-check\n\tpython3 scripts/public-contract\.py check\n\tpython3 scripts/stable-contract\.py\n\tpython3 scripts/security-surface\.py check\n\tpython3 scripts/compatibility-gate\.py check\n\tpython3 scripts/go-api-contract\.py check\n\tpython3 scripts/compatibility-evidence\.py check\n\tpython3 -m unittest discover -s scripts -p 'test_\*\.py'$")
        self.assertIn("make test chart-test arch lint vuln", [step.get("run") for step in ci["source"]["steps"]])

    def test_scheduled_failures_maintain_one_tracking_issue_with_scoped_write(self):
        ci = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())
        job = ci["jobs"]["schedule-report"]
        self.assertEqual(job["if"], "always() && (github.event_name == 'schedule' || "
                                    "(github.event_name == 'workflow_dispatch' && inputs.schedule_report_test == true))")
        self.assertEqual(job["permissions"], {"contents": "read", "issues": "write"})
        self.assertEqual(set(job["needs"]), set(ci["jobs"]) - {"schedule-report"})
        self.assertLessEqual(job["timeout-minutes"], 10)
        self.assertFalse(job.get("continue-on-error", False))
        self.assertEqual(ci[True]["workflow_dispatch"]["inputs"]["schedule_report_test"]["default"], False)
        download = next(step for step in job["steps"] if "download-artifact@" in step.get("uses", ""))
        self.assertEqual(download["with"]["pattern"], "go-tests-*-${{ github.run_id }}-${{ github.run_attempt }}")
        reconcile = next(step for step in job["steps"] if "schedule-report.py" in step.get("run", ""))
        self.assertEqual(reconcile["env"], {"GH_TOKEN": "${{ github.token }}",
                                            "QUALIFICATION_RESULTS": "${{ toJSON(needs) }}"})
        self.assertNotIn("${{", reconcile["run"])  # The token and results reach the script via env only.
        for argument in ('--repository "$GITHUB_REPOSITORY"', '--run-id "$GITHUB_RUN_ID"',
                         '--revision "$GITHUB_SHA"', '--reports "$RUNNER_TEMP/qualification-reports"'):
            self.assertIn(argument, reconcile["run"])

    def test_security_mutation_job_runs_the_complete_catalog_and_preserves_results(self):
        jobs = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        job = jobs["security-mutations"]
        self.assertGreaterEqual(job["timeout-minutes"] * 60, 900)
        self.assertLessEqual(job["timeout-minutes"], 20)
        self.assertIn("security-mutations", jobs["checks"]["needs"])
        self.assertEqual([step["run"] for step in job["steps"] if "run" in step],
                         ['make security-mutations MUTATION_OUTPUT="$RUNNER_TEMP/security-mutations.json"'])
        artifact = next(step for step in job["steps"] if "upload-artifact@" in step.get("uses", ""))
        self.assertEqual(artifact["if"], "always()")
        self.assertEqual(artifact["with"]["path"], "${{ runner.temp }}/security-mutations.json")
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")

    def test_ci_preflight_preserves_release_call_interface(self):
        ci = yaml.load((contract.ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        call = ci["on"]["workflow_call"]
        self.assertEqual(call["inputs"], {"release": {"type": "boolean", "default": "false"}})
        self.assertEqual(call["outputs"], {
            "oci_digest": {"value": "${{ jobs.oci.outputs.digest }}"},
            "oci_artifact_id": {"value": "${{ jobs.oci.outputs.artifact_id }}"},
            "release_candidate": {"value": "${{ jobs.oci.outputs.candidate_digest }}"},
        })
        self.assertEqual(ci["jobs"]["oci"]["with"], {"release": "${{ inputs.release == true }}"})

    def test_reviewed_versions_maturity_and_curated_notes(self):
        notes = contract.check()
        self.assertNotIn("Unreleased", notes)
        self.assertNotIn("release-notes:", notes)
        for requirement in ("26.8.0", "26.7.5", "1.35.0", "1.36.2", "1.37.0",
                            "v1alpha1", "initial development", "HTTPS", "HMAC",
                            "backup/restore", "security/advisories/new", "oci://", "https://hanko.sh"):
            self.assertIn(requirement, notes)
        with self.assertRaises(ValueError):
            contract.check("0.5.0-beta.1")
        for version in ("0.1.1", "0.2.0", "0.5.0", "0.5.1"):
            self.assertEqual(contract.versioning.from_tag("v" + version), version)
            with self.subTest(version=version), self.assertRaises(ValueError):
                contract.check(version)

    def test_note_drift_or_missing_markers_cannot_be_published(self):
        with patch.object(Path, "read_text", return_value="no curated release notes"), self.assertRaises(ValueError):
            contract.notes()
        with self.assertRaises(ValueError):
            contract.notes("99.0.0")

    def test_active_image_scan_and_rehearsal_versions_match_chart_contract(self):
        contract.pins.check()
        result = subprocess.check_output(["make", "--no-print-directory", "-f", "Makefile", "-f", "-", "show-version"],
            cwd=contract.ROOT, input="show-version:\n\t@echo $(VERSION) $(RELEASE_VERSION)\n", text=True)
        self.assertEqual(result.strip(), contract.VERSION + " " + contract.VERSION)
        jobs = yaml.safe_load((contract.ROOT / ".github/workflows/oci-security.yml").read_text())["jobs"]
        steps = jobs["image"]["steps"]
        build = next(step for step in steps if "build-args" in step.get("with", {}))
        self.assertEqual(build["with"]["build-args"], "VERSION=${{ steps.versions.outputs.version }}")
        reader = next(step for step in steps if step.get("id") == "versions")
        self.assertIn('version=$(python3 scripts/versions.py get release version)', reader["run"])
        for name in ("oci-security.yml", "ci.yml"):
            jobs = yaml.safe_load((contract.ROOT / ".github/workflows" / name).read_text())["jobs"]
            consumers = [step["run"] for job in jobs.values() for step in job.get("steps", [])
                         if "--version " in step.get("run", "")]
            self.assertTrue(consumers, name)
            for command in consumers:
                self.assertIn('--version "$(python3 scripts/versions.py get release version)"', command)

    def test_release_and_rehearsal_use_the_same_packaging_and_immutable_image(self):
        workflows = contract.ROOT / ".github/workflows"
        release = yaml.safe_load((workflows / "release.yml").read_text())["jobs"]
        ci = yaml.safe_load((workflows / "ci.yml").read_text())["jobs"]
        steps = release["publish"]["steps"]
        package = next(step["run"] for step in steps if "scripts/release-contract.py prepare" in step.get("run", ""))
        for binding in ('--image "$IMAGE@$DIGEST"', '--revision "$GITHUB_SHA"', '--archive ', '--evidence '):
            self.assertIn(binding, package)
        self.assertIn("contract.prepare(", (contract.ROOT / "scripts/release-dry-run.py").read_text())
        download = next(step for step in ci["rehearsal"]["steps"] if "download-artifact@" in step.get("uses", ""))
        self.assertEqual(download["with"]["artifact-ids"], "${{ needs.oci.outputs.artifact_id }}")
        publish = next(step["run"] for step in steps if "scripts/release-publish.py promote" in step.get("run", ""))
        self.assertIn('--root "$RUNNER_TEMP/hankoshell-delivery"', publish)
        publisher = (contract.ROOT / "scripts/release-publish.py").read_text()
        self.assertIn('contract.notes(version)', publisher)
        self.assertIn('"draft": True, "prerelease": False', publisher)
        self.assertNotIn("--generate-notes", publisher)
        eligibility = "\n".join(step.get("run", "") for step in release["eligibility"]["steps"])
        self.assertIn('python3 scripts/release-eligibility.py', eligibility)
        self.assertEqual(release["quality"]["needs"], "eligibility")
        recheck = next(i for i, step in enumerate(steps)
                       if "scripts/release-eligibility.py" in step.get("run", ""))
        registry_login = next(i for i, step in enumerate(steps) if "docker/login-action@" in step.get("uses", ""))
        self.assertLess(recheck, registry_login)
        self.assertEqual(steps[recheck]["env"]["EXPECTED_TAG_OBJECT"],
                         "${{ needs.eligibility.outputs.tag_object }}")
        trust = next(i for i, step in enumerate(steps)
                     if "scripts/attest-release.py --check-config" in step.get("run", ""))
        staging = next(i for i, step in enumerate(steps)
                       if "oras\" cp --from-oci-layout" in step.get("run", ""))
        self.assertLess(trust, staging)
        self.assertIn('bash scripts/install-attest.sh "$RUNNER_TEMP/hankoshell-attest/attest"', steps[trust]["run"])
        self.assertIn('--check-config --attest "$RUNNER_TEMP/hankoshell-attest/attest"', steps[trust]["run"])
        self.assertEqual(release["eligibility"]["outputs"]["tag_object"],
                         "${{ steps.identity.outputs.tag_object }}")
        self.assertIn('version="$(python3 scripts/release-version.py "$TAG")"', steps[trust]["run"])
        self.assertNotIn('${TAG#v}', yaml.safe_dump(release))
        verifiers = [step["run"] for step in steps if "--certificate-identity" in step.get("run", "")]
        self.assertEqual(len(verifiers), 2)
        for verifier in verifiers:
            self.assertIn('--certificate-identity "https://github.com/$GITHUB_WORKFLOW_REF"', verifier)
            self.assertNotIn('refs/tags/v', verifier)

    def test_actions_are_immutable_checkouts_do_not_persist_and_writes_are_scoped(self):
        for path in (contract.ROOT / ".github/workflows").glob("*.yml"):
            workflow = yaml.safe_load(path.read_text())
            self.assertEqual(workflow["permissions"], {"contents": "read"}, path)
            for name, job in workflow["jobs"].items():
                if "permissions" in job:
                    if path.name == "release.yml" and name == "publish":
                        self.assertEqual(job["permissions"], {"contents": "write", "packages": "write", "id-token": "write"})
                    elif (path.name, name) == ("support-window.yml", "draft"):
                        self.assertEqual(job["permissions"], {"contents": "write", "pull-requests": "write"})
                        self.assertEqual(job["if"], "github.event_name == 'workflow_dispatch' && inputs.create_pull_request == true")
                        self.assertEqual(job["needs"], ["proposal"])
                        self.assertIs(workflow[True]["workflow_dispatch"]["inputs"]["create_pull_request"]["default"], False)
                    elif (path.name, name) in (("ci.yml", "schedule-report"), ("test-history.yml", "issue")):
                        self.assertEqual(job["permissions"], {"contents": "read", "issues": "write"})
                    else:
                        self.assertTrue(all(value == "read" for value in job["permissions"].values()), (path, name))
                for step in job.get("steps", []):
                    action = step.get("uses", "")
                    if action and not action.startswith("./"):
                        self.assertRegex(action, r"^[\w./-]+@[0-9a-f]{40}$")
                    if action.startswith("actions/checkout@"):
                        self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertNotRegex(step.get("run", ""), r"curl[^\n]*\|\s*(?:sh|bash)")
        ci = yaml.safe_load((contract.ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        self.assertNotIn("environment", ci["rehearsal"])
        self.assertNotIn("secrets.", yaml.safe_dump(ci["rehearsal"]))

    def test_embedded_cosign_and_native_verifier_use_the_same_reviewed_dependency_pins(self):
        contract.pins.check()
        pins = contract.pins.DATA["tools"]["cosign"]
        result = subprocess.check_output(["sh", "-c", '. ./scripts/cosign-pins.sh; printf "%s\\n%s\\n" "$COSIGN_VERSION" "$COSIGN_DEPENDENCIES"'],
                                         cwd=contract.ROOT, text=True).splitlines()
        self.assertEqual(result[0], pins["version"])
        self.assertEqual(result[1].split(), [module + "@" + version for module, version in pins["dependencies"].items()])
        for filename in ("Dockerfile", "scripts/install-cosign.sh"):
            source = (contract.ROOT / filename).read_text()
            self.assertIn('go get "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION"', source)
            self.assertIn('go get $COSIGN_DEPENDENCIES', source)
            self.assertIn('sigs.k8s.io/release-utils/version.gitVersion=$COSIGN_VERSION', source)

    def test_packaging_dependencies_require_committed_archive_hashes(self):
        requirements = (contract.ROOT / "scripts/requirements.txt").read_text()
        self.assertIn("--require-hashes", requirements)
        self.assertIn("PyYAML==6.0.2", requirements)
        self.assertTrue(re.findall(r"--hash=sha256:[0-9a-f]{64}", requirements))

    def test_leader_election_boolean_reaches_the_manager(self):
        chart = contract.ROOT / "charts/hankoshell-operator"
        for value in ("true", "false"):
            rendered = subprocess.check_output(["helm", "template", "test", str(chart), "--kube-version", contract.pins.DATA["kubernetes"]["default"],
                "--set-string", "image.tag=test", "--set", "leaderElect=" + value], text=True)
            deployment = next(item for item in yaml.safe_load_all(rendered) if item and item["kind"] == "Deployment")
            args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
            self.assertIn("--leader-elect=" + value, args)
        result = subprocess.run(["helm", "template", "test", str(chart), "--kube-version", contract.pins.DATA["kubernetes"]["default"],
            "--set-string", "image.tag=test", "--set-string", "leaderElect=false"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("leaderElect must be a boolean", result.stderr)

    def test_fixture_blob_digest_tampering_and_public_transparency_entries_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload, bundle = root / "payload", root / "bundle.json"
            payload.write_text("synthetic checksums\n")
            document = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                        "verificationMaterial": {}, "messageSignature": {
                            "messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(hashlib.sha256(payload.read_bytes()).digest()).decode()},
                            "signature": base64.b64encode(b"synthetic signature").decode()}}
            bundle.write_text(json.dumps(document))
            with patch.object(dry_run, "run") as crypto:
                dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")
                crypto.assert_called_once()
                payload.write_text("changed")
                with self.assertRaises(ValueError):
                    dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")
                payload.write_text("synthetic checksums\n")
                document["verificationMaterial"]["tlogEntries"] = [{"logIndex": "1"}]
                bundle.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    dry_run.verify_blob(Path("openssl"), root / "public", bundle, payload, root / "signature")


if __name__ == "__main__":
    unittest.main()

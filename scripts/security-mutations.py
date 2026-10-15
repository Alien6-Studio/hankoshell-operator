"""Prove targeted tests reject removed security protections in a disposable copy.

Run `make security-mutations`, or use --only NAME during local development.
Anchors are deliberately exact: source refactors require reviewing the mutation.
Only a failing, completed test counts as detection; build errors, timeouts,
panics, missing/skipped tests and failing baselines fail this gate.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_LIMIT = 2 * 1024**2
COMMAND_SECONDS = 120
TOTAL_SECONDS = 480


def mutation(name, file, before, after, package, test):
    return {"name": name, "file": file, "before": before, "after": after, "test": test,
            "package": "github.com/Alien6-Studio/hankoshell-operator/" + package,
            "command": ["go", "test", "-json", "-race", "-count=1", "-timeout=45s",
                        "-run", "^" + test + "$", "./" + package]}


MUTATIONS = [
    mutation("fleet-signature", "internal/fleetplan/verify.go",
             "!ed25519.Verify(key, SigningInput(payload), signature)",
             "false && !ed25519.Verify(key, SigningInput(payload), signature)",
             "internal/fleetplan", "TestFleetPlanClosedDecodingAndSignature"),
    mutation("fleet-target", "internal/fleetplan/verify.go",
             "p.Target != target", "false && p.Target != target",
             "internal/fleetplan", "TestFleetPlanClosedDecodingAndSignature"),
    mutation("fleet-sequence", "internal/fleetplan/verify.go",
             "sequence < checkpoint.Sequence", "false && sequence < checkpoint.Sequence",
             "internal/fleetplan", "TestFleetDecodingAndCheckpointReasons"),
    mutation("fleet-sticky-signature-mode", "internal/controller/hankotenant_controller.go",
             'r.FleetTrustConfigMapName != "" || tenant.Status.FleetPlan != nil',
             'r.FleetTrustConfigMapName != ""',
             "internal/controller", "TestSignedFleetPlanControllerRecovery"),
    mutation("hub-hmac", "internal/hub/client.go",
             "return hmac.Equal([]byte(expected), []byte(sb.Signature))",
             "return hmac.Equal([]byte(expected), []byte(expected))",
             "internal/hub", "TestBundleHMACRejectsTamperingAndOtherCredentials"),
    mutation("image-sha256", "internal/imagevalidator/approval.go",
             'return ok && digested.Digest().Algorithm().String() == "sha256"',
             'return ok && digested.Digest().Algorithm().String() != ""',
             "internal/imagevalidator", "TestApprovalCannotAuthorizeMutableOrUnsupportedDigest"),
    mutation("image-keyless-identity", "internal/imagevalidator/approval.go",
             "approval.CertificateIdentity == releaseIdentityPrefix+approval.ReleaseVersion &&",
             'approval.CertificateIdentity != "" &&',
             "internal/imagevalidator", "TestOperatorApprovalRejectsOtherWorkflowsAndAmbiguousTrust"),
    mutation("tls-peer-verification", "internal/httpsecurity/client.go",
             "transport.TLSClientConfig.InsecureSkipVerify = false",
             "transport.TLSClientConfig.InsecureSkipVerify = true",
             "internal/httpsecurity", "TestEnterpriseClientRejectsUntrustedPeersAndTLS12"),
    mutation("tls-minimum", "internal/httpsecurity/client.go",
             "transport.TLSClientConfig.MinVersion = tls.VersionTLS13",
             "transport.TLSClientConfig.MinVersion = tls.VersionTLS12",
             "internal/httpsecurity", "TestEnterpriseClientRejectsUntrustedPeersAndTLS12"),
    mutation("keycloak-redirect", "internal/keycloak/permissions.go",
             "func rejectKeycloakRedirect(*http.Request, []*http.Request) error {\n\treturn http.ErrUseLastResponse\n}",
             "func rejectKeycloakRedirect(*http.Request, []*http.Request) error {\n\treturn nil\n}",
             "internal/keycloak", "TestPermissionGatewayDoesNotFollowRedirects"),
    mutation("unowned-realm-deletion", "internal/controller/hankorealm_controller.go",
             '\tif observe {\n\t\tlog.FromContext(ctx).Info("Observe mode: dropping legacy finalizer without deleting Keycloak realm", "realm", realm.Name)',
             '\tif false && observe {\n\t\tlog.FromContext(ctx).Info("Observe mode: dropping legacy finalizer without deleting Keycloak realm", "realm", realm.Name)',
             "internal/controller", "TestImportedRealmDeletionDoesNotDeleteKeycloakRealm"),
    mutation("unowned-client-role-deletion", "internal/controller/hankoapplication_controller.go",
             "\t// Only reconcile deletions when the operator explicitly owns roles for this app.\n\tif len(app.Spec.Roles) == 0 {",
             "\t// Only reconcile deletions when the operator explicitly owns roles for this app.\n\tif false && len(app.Spec.Roles) == 0 {",
             "internal/controller", "TestApplicationWithoutDeclaredRolesPreservesProviderRoles"),
    mutation("bundle-tenant-namespace", "internal/controller/hankotenant_bundle.go",
             "desired.SetNamespace(tenant.Namespace)",
             "desired.SetNamespace(desired.GetNamespace())",
             "internal/controller", "TestTenantBundleApplyPreservesExplicitValuesAndTenantBoundary"),
    mutation("bundle-live-tenant-ownership", "internal/controller/hankotenant_bundle.go",
             'if current.GetLabels()["hanko.sh/tenant"] != tenant {',
             'if false && current.GetLabels()["hanko.sh/tenant"] != tenant {',
             "internal/controller", "TestTenantBundleUsesCurrentOwnershipForEveryKind"),
    mutation("bundle-forced-ownership", "internal/controller/hankotenant_bundle.go",
             'client.ApplyConfigurationFromUnstructured(object.desired), client.FieldOwner(bundleFieldManager))',
             'client.ApplyConfigurationFromUnstructured(object.desired), client.FieldOwner(bundleFieldManager), client.ForceOwnership)',
             "internal/controller", "TestTenantBundleApplyPreservesExplicitValuesAndTenantBoundary"),
    mutation("bundle-write-version-precondition", "internal/controller/hankotenant_bundle.go",
             'object.desired.SetResourceVersion(current.GetResourceVersion())',
             'object.desired.SetResourceVersion("")',
             "internal/controller", "TestTenantBundleApplyPreservesExplicitValuesAndTenantBoundary"),
    mutation("secret-cache-exclusion", "cmd/operator/main.go",
             "DisableFor: []client.Object{&corev1.Secret{}},",
             "DisableFor: []client.Object{},",
             "cmd/operator", "TestManagerOptionsConfineCacheAndLeaderElection"),
    mutation("snapshot-tenant-inventory", "internal/controller/hankosnapshot_controller.go",
             "r.snapshotReader().List(ctx, &realms, options...)",
             "r.snapshotReader().List(ctx, &realms, client.InNamespace(snapshot.Namespace))",
             "internal/controller", "TestSnapshotCaptureIsTenantScoped"),
    mutation("snapshot-stored-tenant-scope", "internal/controller/hankosnapshot_checkpoint.go",
             "!snapshotPayloadInScope(snapshot, raw)", "false",
             "internal/controller", "TestSnapshotRecoveryRejectsCrossScopeStoredCapture"),
    mutation("operation-child-tenant-presence", "internal/controller/hankooperation_checkpoint.go",
             "child.SetLabels(tenantScopeLabels(op))",
             'child.SetLabels(map[string]string{"hanko.sh/tenant": op.Labels["hanko.sh/tenant"]})',
             "internal/controller", "TestOperationSnapshotRetainsExactTenantScope"),
    mutation("operation-managed-provider-binding", "internal/controller/hankooperation_controller.go",
             'if instance.Spec.Mode == "managed" {', 'if false && instance.Spec.Mode == "managed" {',
             "internal/controller", "TestOperationProviderObservationBindsManagedRollout"),
    mutation("managed-probe-rollout-fence", "internal/controller/hankokeycloakinstance_controller.go",
             'observation == nil || current == nil || *observation != *current',
             'observation == nil || current == nil',
             "internal/controller", "TestManagedProbeRequiresStableDeployment"),
    mutation("managed-infrastructure-owner", "internal/controller/managed_infrastructure.go",
             "if !managedInfrastructureOwned(instance, object) {", "if false && !managedInfrastructureOwned(instance, object) {",
             "internal/controller", "TestManagedInfrastructurePreservesForeignObjects"),
    mutation("managed-infrastructure-live-owner", "internal/controller/managed_infrastructure.go",
             "r.instanceReader().Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: name}, object)",
             "r.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: name}, object)",
             "internal/controller", "TestManagedInfrastructurePreservesForeignObjects"),
    mutation("managed-infrastructure-write-version", "internal/controller/managed_infrastructure.go",
             "client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})",
             "client.MergeFrom(before)",
             "internal/controller", "TestManagedInfrastructureRejectsConcurrentOwnerChanges"),
    mutation("managed-pdb-delete-identity", "internal/controller/hankokeycloakinstance_controller.go",
             "r.Delete(ctx, &existingPDB, client.Preconditions{UID: &existingPDB.UID, ResourceVersion: &existingPDB.ResourceVersion})",
             "r.Delete(ctx, &existingPDB)",
             "internal/controller", "TestManagedInfrastructureRejectsConcurrentOwnerChanges"),
    mutation("managed-instance-live-intent", "internal/controller/hankokeycloakinstance_controller.go",
             "r.instanceReader().Get(ctx, req.NamespacedName, &instance)", "r.Get(ctx, req.NamespacedName, &instance)",
             "internal/controller", "TestDeletingKeycloakInstanceStopsReconciliation"),
    mutation("managed-instance-deletion", "internal/controller/hankokeycloakinstance_controller.go",
             "if !instance.DeletionTimestamp.IsZero() {", "if false && !instance.DeletionTimestamp.IsZero() {",
             "internal/controller", "TestDeletingKeycloakInstanceStopsReconciliation"),
]


class GateError(Exception):
    pass


def apply_mutation(root, item):
    path = root / item["file"]
    original = path.read_bytes()
    before, after = item["before"].encode(), item["after"].encode()
    count = original.count(before)
    if count != 1:
        reason = "already applied" if count == 0 and after in original else f"anchor occurs {count} times"
        raise GateError(reason)
    if before == after:
        raise GateError("mutation does not change the source")
    path.write_bytes(original.replace(before, after, 1))
    return original


def snapshot(source, destination):
    """Copy current tracked/unignored files, including uncommitted development."""
    if destination.resolve().is_relative_to(source.resolve()):
        raise GateError("disposable copy must be outside the working tree")
    result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                            cwd=source, capture_output=True, check=True, timeout=30)
    for name in sorted(set(os.fsdecode(result.stdout).split("\0")) - {""}):
        relative = Path(name)
        path = source / relative
        if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
            raise GateError("invalid snapshot path")
        if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
            raise GateError("snapshot refuses symlinks")
        if not path.exists():  # Preserve a deletion in the caller's working copy.
            continue
        if not path.is_file():
            raise GateError("snapshot requires regular files")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def run_command(command, root, seconds):
    if seconds <= 0:
        raise GateError("total mutation budget exhausted")
    # A file avoids retaining arbitrary compiler/test output in memory. Kill the
    # process group on expiry/overflow, including test servers started by Go.
    # Go emits module downloads and tool diagnostics on stderr, outside the
    # stdout JSON protocol. Bound both streams but parse only test events.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen(command, cwd=root, stdout=output, stderr=diagnostics, start_new_session=True)
        deadline = time.monotonic() + seconds
        try:
            while True:
                if os.fstat(output.fileno()).st_size + os.fstat(diagnostics.fileno()).st_size > OUTPUT_LIMIT:
                    raise GateError("test command exceeded output budget")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GateError("test command timed out")
                try:
                    process.wait(timeout=min(0.25, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
            output.seek(0)
            data = output.read(OUTPUT_LIMIT + 1)
            if len(data) + os.fstat(diagnostics.fileno()).st_size > OUTPUT_LIMIT:
                raise GateError("test command exceeded output budget")
            return process.returncode, data.decode("utf-8", errors="replace")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def outcome(returncode, output, item):
    """Use Go events, not an arbitrary nonzero process status, as the oracle."""
    ran = False
    test_results, package_results = [], []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as error:
            raise GateError("test command did not produce a complete Go JSON stream") from error
        if not isinstance(event, dict):
            raise GateError("malformed Go test event")
        if re.search(r"panic:|fatal error:|\[build failed\]|DATA RACE", event.get("Output", "")):
            raise GateError("panic, build failure or race is not a security assertion")
        if event.get("Package") != item["package"]:
            continue
        action, test = event.get("Action"), event.get("Test")
        if test == item["test"]:
            ran |= action == "run"
            if action in ("pass", "fail", "skip"):
                test_results.append(action)
        elif test is None and action in ("pass", "fail", "skip"):
            package_results.append(action)
    if (not ran or len(test_results) != 1 or test_results[0] not in ("pass", "fail")
            or package_results != test_results or returncode != (0 if test_results[0] == "pass" else 1)):
        raise GateError("expected test did not finish with a matching package result")
    return test_results[0]


def qualify(source, items, runner=run_command):
    if not items:
        raise GateError("at least one reviewed mutation is required")
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    results, baselines = [], set()
    with tempfile.TemporaryDirectory(prefix="hanko-security-mutations-") as directory:
        root = Path(directory)
        snapshot(source, root)
        for item in items:
            entry = {"name": item["name"], "file": item["file"], "test": item["test"]}
            original = None
            step_started = time.monotonic()
            try:
                key = tuple(item["command"])
                if key not in baselines:
                    code, output = runner(item["command"], root, min(COMMAND_SECONDS, deadline - time.monotonic()))
                    if outcome(code, output, item) != "pass":
                        raise GateError("unmodified baseline test failed")
                    baselines.add(key)
                original = apply_mutation(root, item)
                code, output = runner(item["command"], root, min(COMMAND_SECONDS, deadline - time.monotonic()))
                entry["result"] = "detected" if outcome(code, output, item) == "fail" else "survived"
            except (GateError, OSError, subprocess.SubprocessError) as error:
                entry["result"] = "error"
                # Exception messages from subprocess/OSError can include paths or
                # output. Only our fixed gate diagnostics belong in the report.
                entry["reason"] = str(error) if isinstance(error, GateError) else type(error).__name__
            finally:
                if original is not None:
                    (root / item["file"]).write_bytes(original)
            entry["seconds"] = round(time.monotonic() - step_started, 3)
            results.append(entry)
            print(item["name"] + ": " + entry["result"], flush=True)
            if time.monotonic() >= deadline:
                break
    return {"complete": len(results) == len(items), "result": "pass" if len(results) == len(items)
            and all(r["result"] == "detected" for r in results) else "fail",
            "seconds": round(time.monotonic() - started, 3), "mutations": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=[item["name"] for item in MUTATIONS])
    parser.add_argument("--output", type=Path, default=ROOT / ".tools/security-mutations.json")
    args = parser.parse_args()
    items = [item for item in MUTATIONS if not args.only or item["name"] == args.only]
    report = qualify(ROOT, items)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as output:
            output.write("Security mutations: " + report["result"] + "\n\n| Protection | Result |\n| --- | --- |\n")
            for item in report["mutations"]:
                output.write("| " + item["name"] + " | " + item["result"] + " |\n")
    if report["result"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

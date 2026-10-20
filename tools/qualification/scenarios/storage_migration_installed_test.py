"""Qualify real storage rewrites in an owned, disposable kind control plane.

No provider or operator image is needed: this fixture tests the administrator
tool, native migrator and actual etcd encoding, not reconciliation or public
release upgrades. Never point the fixture at an existing installation.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import yaml

from tools.qualification.lib import api_conversion_contract as conversion
from tools.operations import storage_migration as migration
from tools import versions

ROOT = Path(__file__).resolve().parents[3]

CLI_REFUSALS = {"ConcurrentModification", "KubernetesRequestRefused", "KubernetesReadUnavailable", "KubernetesWriteOutcomeUnknown",
    "NativeMigrationDeadline", "NativeMigrationFailed", "NativeMigrationIncomplete", "NativeMigrationIdentityChanged",
    "StorageEncoderUnconfirmed", "StorageVersionChanged", "StorageVersionNotApplied", "MigratedObjectChanged",
    "ReviewSnapshotChanged", "ObjectIdentityChanged", "ConversionContractMismatch", "UnknownStoredVersion",
    "MigrationJournalConflict", "MigrationJournalReplaced", "InvalidMigrationInput", "StoredVersionCommitUnconfirmed",
    "OperatorNotQuiescent", "InvalidKubernetesList", "InventoryTooLarge", "InvalidContinueToken"}
FIXTURE_REFUSALS = {"FixtureCommandFailed", "StoredObjectNotFound", "UnexpectedInitialEncoding", "PlanFileIsNotPrivate",
    "MigrationCheckpointNotReached", "MigrationInterruptionNotConfirmed", "InterruptedMigrationChangedObjectMeaning",
    "InterruptedRewriteNativeProofInvalid", "InterruptedRewriteNativeProofDeadline", "InterruptedRewritePhysicalEncodingMismatch",
    "MigrationChangedObjectMeaning", "PhysicalEncodingNotMigrated", "StoredVersionCommitMissing", "UpgradeWouldResetLiveStorage",
    "ChartDidNotRefuseUnreadableStorage", "InterruptedCommitChangedObjectMeaning", "ResumeChangedObjectMeaning", "NativeMigrationProofMissing",
    "FixtureClusterAlreadyExists", "PinnedNodeArchiveRequired", "NodeArchiveChecksumMismatch", "UnexpectedKubernetesVersion",
    "ConcurrentMetadataConflictNotObserved", "ConcurrentMetadataProofInvalid"}


class FixtureCommandFailure(RuntimeError):
    def __init__(self, code, returncode, stderr):
        super().__init__(code)
        self.returncode = returncode
        # Publish only fixed classifications, never command text or stderr.
        self.diagnostic = "UnclassifiedCommandFailure"
        if isinstance(stderr, bytes) and len(stderr) <= 65536:
            value = stderr.lower()
            for needles, label in (
                ((b"toomanyrequests", b"too many requests"), "RegistryRateLimited"),
                ((b"no space left on device",), "StorageExhausted"),
                ((b"cannot connect to the docker daemon",), "ContainerRuntimeUnavailable"),
                ((b"error response from daemon",), "ContainerRuntimeRefused"),
                ((b"connection refused",), "EndpointUnavailable"),
                ((b"tls handshake timeout", b"i/o timeout", b"context deadline exceeded"), "EndpointDeadline"),
                ((b"error from server (invalid)",), "KubernetesValidationRefused"),
                ((b"error from server (forbidden)",), "KubernetesPermissionRefused"),
            ):
                if any(needle in value for needle in needles):
                    self.diagnostic = label
                    break


def execute(command, value=None, *, timeout=120):
    result = subprocess.run([str(v) for v in command], input=None if value is None else json.dumps(value).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        code = "FixtureCommandFailed"
        if len(result.stderr) < 65536:
            try:
                failure = migration.decode(result.stderr)
                if (isinstance(failure, dict) and set(failure) == {"complete", "reason"}
                        and failure["complete"] is False and failure["reason"] in CLI_REFUSALS):
                    code = failure["reason"]
            except (migration.Refused, TypeError, ValueError):
                pass
        raise FixtureCommandFailure(code, result.returncode, result.stderr)
    return result.stdout


def record_failure(report, error):
    report["failure_type"] = type(error).__name__
    code = str(error)
    report["failure_code"] = code if isinstance(error, RuntimeError) and code in CLI_REFUSALS | FIXTURE_REFUSALS else "FixtureOperationFailed"
    if isinstance(error, FixtureCommandFailure):
        report["failure_returncode"] = error.returncode
        report["failure_diagnostic"] = error.diagnostic


def run_with_crd_conflict(command, target, report):
    """A real intervening metadata PUT must cause 409, then ordinary CLI recovery."""
    with tempfile.TemporaryDirectory(prefix="hanko-migration-conflict-") as directory:
        marker = Path(directory) / "conflict.json"
        program = """
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, sys.argv.pop(1))
marker = Path(sys.argv.pop(1))
import tools.operations.storage_migration as migration
original = migration.Kubernetes.request
injected = False
def request(self, method, path, value=None, *, optional=False):
    global injected
    if not injected and method == 'PUT' and path.startswith(migration.CRDS) and not path.endswith('/status'):
        injected = True
        current = original(self, 'GET', path)
        # Change metadata on both forward and rollback runs. Repeating the
        # same annotation value can be an API no-op with no new resourceVersion.
        current['metadata'].setdefault('annotations', {})['fixture.example/concurrent-storage-writer'] = next(v['name'] for v in value['spec']['versions'] if v['storage'])
        updated = original(self, 'PUT', path, current)
        proof = {'metadata_write': True, 'generation_unchanged': updated['metadata']['generation'] == value['metadata']['generation'], 'actual_conflict': False}
        try:
            result = original(self, method, path, value, optional=optional)
        except migration.Refused as error:
            proof['actual_conflict'] = str(error) == 'ConcurrentModification'
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(proof, stream)
            raise
        raise migration.Refused('ConcurrentMetadataConflictNotObserved')
    return original(self, method, path, value, optional=optional)
migration.Kubernetes.request = request
try:
    migration.main()
except (migration.Refused, KeyError, TypeError, ValueError, AttributeError, OSError, subprocess.SubprocessError) as error:
    reason = str(error) if isinstance(error, migration.Refused) else 'InvalidMigrationInput'
    print(json.dumps({'complete': False, 'reason': reason}), file=sys.stderr)
    raise SystemExit(1) from None
"""
        try:
            result = execute([command[0], "-c", program, ROOT, marker, *command[3:]], timeout=600)
        finally:
            if marker.exists():
                if marker.stat().st_size > 1024:
                    raise RuntimeError("ConcurrentMetadataProofInvalid")
                try:
                    proof = migration.decode(marker.read_bytes())
                except (migration.Refused, TypeError, ValueError):
                    raise RuntimeError("ConcurrentMetadataProofInvalid") from None
                if (not isinstance(proof, dict) or set(proof) != {"metadata_write", "generation_unchanged", "actual_conflict"}
                        or any(value is not True for value in proof.values())):
                    raise RuntimeError("ConcurrentMetadataProofInvalid")
                report.setdefault("conflict_evidence", []).append({"target": target, **proof})
        if not marker.exists():
            raise RuntimeError("ConcurrentMetadataConflictNotObserved")
        return result


def interrupt_after_checkpoint(command, boundary):
    """Stop a real CLI process after a durable native/journal boundary.

    The wrapper exists only in this disposable test. It pauses after the real
    checkpoint method returns; production migration has no fault switches.
    SIGINT unwinds the CLI's proxy context before a fresh process resumes it.
    """
    if boundary not in ("Rewriting", "Committed"):
        raise ValueError("UnknownInterruptionBoundary")
    with tempfile.TemporaryDirectory(prefix="hanko-migration-interrupt-") as directory:
        marker = Path(directory) / "checkpoint"
        program = """
import os
from pathlib import Path
import signal
import sys
sys.path.insert(0, sys.argv.pop(1))
import tools.operations.storage_migration as migration
marker, boundary = Path(sys.argv.pop(1)), sys.argv.pop(1)
checkpoint = migration.Migration.checkpoint
def pause(self):
    checkpoint(self)
    if self.progress['phase'] == 'Migrating' and any(value['phase'] == boundary for value in self.progress['resources'].values()):
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        signal.pause()
migration.Migration.checkpoint = pause
try:
    migration.main()
except KeyboardInterrupt:
    raise SystemExit(130) from None
"""
        process = subprocess.Popen([str(command[0]), "-c", program, str(ROOT), str(marker), boundary,
                                    *[str(value) for value in command[3:]]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 180
            while not marker.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("MigrationCheckpointNotReached")
                time.sleep(0.1)
            process.send_signal(signal.SIGINT)
            if process.wait(timeout=15) != 130:
                raise RuntimeError("MigrationInterruptionNotConfirmed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)


def qualify(kubectl, kubeconfig, control_plane, output, helm, report):
    command = [kubectl, "--kubeconfig", kubeconfig]

    def kube(*args, value=None):
        return json.loads(execute([*command, *args, "-o", "json"], value))

    contract = conversion.load()
    crds = ROOT / "charts/hankoshell-operator/crds"
    report["active_phase"] = "install_crds"
    for entry in contract["resources"].values():
        execute([*command, "create", "-f", crds / ("hanko.sh_" + entry["plural"] + ".yaml")])
        execute([*command, "wait", "--for=condition=Established", "crd/" + entry["plural"] + ".hanko.sh", "--timeout=60s"])
    report["active_phase"] = "create_namespace"
    kube("create", "-f", "-", value={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "migration-fixture"}})
    # This zero-replica deployment models the required stopped controller. It
    # never starts a Pod and cannot touch a provider, Secret or IAM object.
    report["active_phase"] = "seed_stopped_operator"
    kube("create", "-f", "-", value={"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "stopped-operator", "namespace": "migration-fixture", "labels": {"app.kubernetes.io/name": "hankoshell-operator"}},
        "spec": {"replicas": 0, "selector": {"matchLabels": {"fixture": "stopped"}}, "template": {"metadata": {"labels": {"fixture": "stopped"}}, "spec": {"containers": [{"name": "stopped", "image": "registry.invalid/never-started"}]}}}})
    specs = {"HankoApplication": {"realmRef": "realm", "clientID": "app"}, "HankoRole": {"realmRef": "realm", "name": "role"},
             "HankoResourceServer": {"realmRef": "realm", "applicationRef": "app", "audience": "urn:migration-fixture"}}
    for kind in sorted(contract["resources"]):
        report.update(active_phase="seed_declaration", active_kind=kind)
        value = kube("create", "-f", "-", value={"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
            "metadata": {"name": "owned", "namespace": "migration-fixture", "annotations": {"fixture.example/approval": "reviewed-uid", "hanko.sh/runtime-bindings-journal": "opaque-checkpoint"},
                "finalizers": ["fixture.example/preserve"]}, "spec": specs[kind]})
        value["status"] = {"phase": "Ready", "observedGeneration": value["metadata"]["generation"], "appliedGeneration": value["metadata"]["generation"], "observationComplete": True, "driftState": "InSync"}
        report["active_phase"] = "seed_status"
        kube("replace", "--subresource=status", "-f", "-", value=value)

    def snapshot():
        result = {}
        for kind, entry in contract["resources"].items():
            obj = kube("get", entry["plural"], "owned", "-n", "migration-fixture")
            result[kind] = migration.semantic_hash(obj)
        return result

    def encoded_version(plural):
        key = "/registry/hanko.sh/" + plural + "/migration-fixture/owned"
        raw = execute([*command, "-n", "kube-system", "exec", "etcd-" + control_plane, "--", "etcdctl", "--endpoints=https://127.0.0.1:2379",
            "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key", "get", key, "--write-out=json"])
        entries = json.loads(raw).get("kvs", [])
        if len(entries) != 1 or base64.b64decode(entries[0]["key"]).decode() != key:
            raise RuntimeError("StoredObjectNotFound")
        return json.loads(base64.b64decode(entries[0]["value"]))["apiVersion"]

    report.pop("active_kind", None)
    report["active_phase"] = "initial_snapshot"
    before, stages = snapshot(), []
    report["active_phase"] = "initial_physical_encoding"
    for entry in contract["resources"].values():
        if encoded_version(entry["plural"]) != "hanko.sh/v1alpha1":
            raise RuntimeError("UnexpectedInitialEncoding")
    cli = [sys.executable, "-m", "tools.operations.storage_migration", "--kubectl", kubectl, "--kubeconfig", kubeconfig]
    report["interruption_evidence"] = []
    report["conflict_evidence"] = []
    for target in ("v1beta1", "v1alpha1"):
        report.update(active_target=target, active_phase="review")
        path = output / (target + "-plan.json")
        review = json.loads(execute([*cli, "plan", "--target", target, "--namespace", "migration-fixture", "--plan", path]))
        if path.stat().st_mode & 0o077:
            raise RuntimeError("PlanFileIsNotPrivate")
        run = [*cli, "run", "--plan", path, "--approve", review["plan"], "--timeout", "180"]
        report["active_phase"] = "interrupted_rewrite"
        interrupt_after_checkpoint(run, "Rewriting")
        progress = json.loads(execute([*cli, "status", "--plan", path, "--approve", review["plan"]]))
        if progress.get("phase") != "Migrating" or progress.get("authorizes_completion") is not False or snapshot() != before:
            raise RuntimeError("InterruptedMigrationChangedObjectMeaning")
        first = contract["resources"][sorted(contract["resources"])[0]]["plural"]
        # The native controller can finish and prune storedVersions while the
        # CLI is paused. A missing predecessor requires that exact native job
        # to have succeeded and the actual bytes to use the target encoding.
        source = "v1alpha1" if target == "v1beta1" else "v1beta1"
        if source not in kube("get", "crd", first + ".hanko.sh")["status"]["storedVersions"]:
            journal = kube("get", "configmap", "hanko-storage-" + review["plan"][:32], "-n", "migration-fixture")
            resource = json.loads(journal["data"][migration.JOURNAL_KEY])["resources"][sorted(contract["resources"])[0]]
            proof = {"target": target, "predecessor_pruned_by_native_controller": True, "native_succeeded": False}
            report["interruption_evidence"].append(proof)
            # Native CRD cleanup and the migration's success condition are two
            # asynchronous writes. Keep the CLI stopped and wait for the exact
            # native job; never mistake their short visibility gap for failure.
            deadline = time.monotonic() + 180
            while True:
                job = kube("get", "storageversionmigrations.storagemigration.k8s.io", resource["migration"])
                conditions = job.get("status", {}).get("conditions", [])
                proof.update(uid_matches=job["metadata"]["uid"] == resource["uid"],
                    resource_matches=job["spec"]["resource"] == {"group": "hanko.sh", "resource": first},
                    native_failed=any(c["type"] == "Failed" and c["status"] == "True" for c in conditions),
                    native_succeeded=any(c["type"] == "Succeeded" and c["status"] == "True" for c in conditions))
                if not proof["uid_matches"] or not proof["resource_matches"] or proof["native_failed"]:
                    raise RuntimeError("InterruptedRewriteNativeProofInvalid")
                if proof["native_succeeded"]:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("InterruptedRewriteNativeProofDeadline")
                time.sleep(0.5)
            proof["physical_encoding_matches"] = encoded_version(first) == "hanko.sh/" + target
            if not proof["physical_encoding_matches"]:
                raise RuntimeError("InterruptedRewritePhysicalEncodingMismatch")
        report["active_phase"] = "resume_rewrite"
        result = json.loads(run_with_crd_conflict(run, target, report))
        if result.get("complete") is not True or snapshot() != before:
            raise RuntimeError("MigrationChangedObjectMeaning")
        for entry in contract["resources"].values():
            if encoded_version(entry["plural"]) != "hanko.sh/" + target:
                raise RuntimeError("PhysicalEncodingNotMigrated")
            crd = kube("get", "crd", entry["plural"] + ".hanko.sh")
            if crd["status"]["storedVersions"] != [target]:
                raise RuntimeError("StoredVersionCommitMissing")
        rendered = list(yaml.safe_load_all(execute([*cli, "render-crds", "--crds", crds])))
        if any(next(v["name"] for v in crd["spec"]["versions"] if v["storage"]) != target for crd in rendered if crd["spec"]["names"]["kind"] in contract["resources"]):
            raise RuntimeError("UpgradeWouldResetLiveStorage")
        if target == "v1beta1":
            chart = ROOT / "charts/hankoshell-operator"
            server_version = kube("version")["serverVersion"]["gitVersion"]
            options = ["--namespace", "migration-fixture", "--kubeconfig", kubeconfig, "--dry-run=server", "--kube-version", server_version, "--set-string", "image.tag=fixture"]
            execute([helm, "template", "fixture", chart, *options])
            with tempfile.TemporaryDirectory(prefix="hanko-old-chart-") as directory:
                older = Path(directory) / "chart"
                shutil.copytree(chart, older)
                for entry in contract["resources"].values():
                    older_crd_path = older / "crds" / ("hanko.sh_" + entry["plural"] + ".yaml")
                    crd = yaml.safe_load(older_crd_path.read_text())
                    crd["spec"]["versions"] = crd["spec"]["versions"][:1]
                    older_crd_path.write_text(yaml.safe_dump(crd))
                refused = subprocess.run([str(v) for v in [helm, "template", "fixture", older, *options]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
                if refused.returncode == 0 or b"still stores v1beta1" not in refused.stderr:
                    raise RuntimeError("ChartDidNotRefuseUnreadableStorage")
        # Interrupt a second real process after the first storedVersion commit.
        # Completion still requires three fresh native successes; neither an
        # incomplete nor a completed journal can substitute for physical proof.
        interrupt_after_checkpoint(run, "Committed")
        report["active_phase"] = "resume_commit"
        progress = json.loads(execute([*cli, "status", "--plan", path, "--approve", review["plan"]]))
        if progress.get("phase") != "Migrating" or snapshot() != before:
            raise RuntimeError("InterruptedCommitChangedObjectMeaning")
        resumed = json.loads(execute(run, timeout=600))
        if not resumed.get("complete") or snapshot() != before:
            raise RuntimeError("ResumeChangedObjectMeaning")
        stages.append({"target": target, "objects": 3, "physical_encoding_verified": True, "resume_verified": True,
            "process_interruptions": ["Rewriting", "Committed"], "interrupted_storage_readability_proven": True})
    jobs = kube("get", "storageversionmigrations.storagemigration.k8s.io")["items"]
    if len(jobs) != 16 or any(not any(c["type"] == "Succeeded" and c["status"] == "True" for c in j["status"]["conditions"]) for j in jobs):
        raise RuntimeError("NativeMigrationProofMissing")
    return {"complete": True, "scope": "experimental-local-storage", "stages": stages, "native_migrations": len(jobs),
            "preserved": ["uid", "spec", "status", "generation", "annotations", "finalizers", "managedFields"], "chart_live_guard_verified": True, "public_release_compatibility": False}


def cleanup(kind, cluster, built_image, kubeconfig, output, report):
    """Retain the qualification result even when disposable cleanup fails."""
    failures = []
    commands = [("cluster_delete", [kind, "delete", "cluster", "--name", cluster])]
    if built_image:
        commands.append(("image_delete", ["docker", "image", "rm", built_image]))
    for label, command in commands:
        try:
            execute(command, timeout=120)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            failures.append(label)
    try:
        report["cleanup"] = cluster not in execute([kind, "get", "clusters"]).decode().splitlines()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        failures.append("cluster_inspect")
        report["cleanup"] = False
    report["cleanup_failures"] = failures
    report["complete"] = report["complete"] and report["cleanup"] and not failures
    try:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        kubeconfig.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument("--node-archive", type=Path, help="Checksum-pinned server archive required for the built-node Kubernetes version")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kubernetes-version", choices=versions.DATA["kubernetes"]["versions"], default=versions.DATA["kubernetes"]["default"])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cluster = "hanko-storage-" + uuid.uuid4().hex[:12]
    if cluster in execute([args.kind, "get", "clusters"]).decode().splitlines():
        raise RuntimeError("FixtureClusterAlreadyExists")
    kubeconfig = args.output.resolve() / "kubeconfig"
    config = {"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": [{"role": "control-plane"}]}
    if args.kubernetes_version != "1.37.0":
        config["featureGates"] = {"StorageVersionMigrator": True}
        config["runtimeConfig"] = {"storagemigration.k8s.io/v1beta1": "true"}
    report = {"complete": False, "kubernetes": args.kubernetes_version, "cleanup": False, "active_phase": "prepare_node",
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "api_contract_sha256": conversion.digest(conversion.load())}
    built_image = None
    try:
        image = versions.DATA["kubernetes"]["node_images"].get(args.kubernetes_version)
        if image is None:
            pin = versions.DATA["kubernetes"]["built_node"]
            architecture = execute(["docker", "info", "--format", "{{.Architecture}}"]).decode().strip()
            architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(architecture, architecture)
            if args.node_archive is None or architecture not in pin["sha256"]:
                raise RuntimeError("PinnedNodeArchiveRequired")
            with args.node_archive.open("rb") as stream:
                archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            if archive_hash != pin["sha256"][architecture]:
                raise RuntimeError("NodeArchiveChecksumMismatch")
            built_image = cluster + "-node:v" + args.kubernetes_version
            execute([args.kind, "build", "node-image", "--type", "file", "--base-image", pin["base_image"], "--image", built_image, args.node_archive], timeout=600)
            image = built_image
            report["node_archive_sha256"] = archive_hash
        report["node_image"] = image
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as stream:
            yaml.safe_dump(config, stream); stream.flush()
            report["active_phase"] = "create_cluster"
            execute([args.kind, "create", "cluster", "--name", cluster, "--image", image, "--kubeconfig", kubeconfig, "--config", stream.name, "--wait", "60s"], timeout=180)
        report["active_phase"] = "server_version"
        server = json.loads(execute([args.kubectl, "--kubeconfig", kubeconfig, "version", "-o", "json"]))
        if server["serverVersion"]["gitVersion"] != "v" + args.kubernetes_version:
            raise RuntimeError("UnexpectedKubernetesVersion")
        report.update(qualify(args.kubectl.resolve(), kubeconfig, cluster + "-control-plane", args.output, args.helm.resolve(), report), active_phase="complete")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        record_failure(report, error)
    finally:
        cleanup(args.kind, cluster, built_image, kubeconfig, args.output, report)
    print(json.dumps(report, sort_keys=True))
    return int(not report["complete"])


if __name__ == "__main__":
    sys.exit(main())

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
import subprocess
import sys
import tempfile
import uuid

import yaml

import api_conversion_contract as conversion
import storage_migration as migration
import versions

ROOT = Path(__file__).resolve().parents[1]


def execute(command, value=None, *, timeout=120):
    result = subprocess.run([str(v) for v in command], input=None if value is None else json.dumps(value).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("FixtureCommandFailed")
    return result.stdout


def qualify(kubectl, kubeconfig, control_plane, output, helm):
    command = [kubectl, "--kubeconfig", kubeconfig]

    def kube(*args, value=None):
        return json.loads(execute([*command, *args, "-o", "json"], value))

    contract = conversion.load()
    crds = ROOT / "charts/hankoshell-operator/crds"
    for entry in contract["resources"].values():
        execute([*command, "create", "-f", crds / ("hanko.sh_" + entry["plural"] + ".yaml")])
        execute([*command, "wait", "--for=condition=Established", "crd/" + entry["plural"] + ".hanko.sh", "--timeout=60s"])
    kube("create", "-f", "-", value={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "migration-fixture"}})
    # This zero-replica deployment models the required stopped controller. It
    # never starts a Pod and cannot touch a provider, Secret or IAM object.
    kube("create", "-f", "-", value={"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "stopped-operator", "namespace": "migration-fixture", "labels": {"app.kubernetes.io/name": "hankoshell-operator"}},
        "spec": {"replicas": 0, "selector": {"matchLabels": {"fixture": "stopped"}}, "template": {"metadata": {"labels": {"fixture": "stopped"}}, "spec": {"containers": [{"name": "stopped", "image": "registry.invalid/never-started"}]}}}})
    specs = {"HankoApplication": {"realmRef": "realm", "clientID": "app"}, "HankoRole": {"realmRef": "realm", "name": "role"},
             "HankoResourceServer": {"realmRef": "realm", "applicationRef": "app", "audience": "urn:migration-fixture"}}
    for kind in sorted(contract["resources"]):
        value = kube("create", "-f", "-", value={"apiVersion": "hanko.sh/v1alpha1", "kind": kind,
            "metadata": {"name": "owned", "namespace": "migration-fixture", "annotations": {"fixture.example/approval": "reviewed-uid", "hanko.sh/runtime-bindings-journal": "opaque-checkpoint"},
                "finalizers": ["fixture.example/preserve"]}, "spec": specs[kind]})
        value["status"] = {"phase": "Ready", "observedGeneration": value["metadata"]["generation"], "appliedGeneration": value["metadata"]["generation"], "observationComplete": True, "driftState": "InSync"}
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

    before, stages = snapshot(), []
    for entry in contract["resources"].values():
        if encoded_version(entry["plural"]) != "hanko.sh/v1alpha1":
            raise RuntimeError("UnexpectedInitialEncoding")
    cli = [sys.executable, ROOT / "scripts/storage_migration.py", "--kubectl", kubectl, "--kubeconfig", kubeconfig]
    for target in ("v1beta1", "v1alpha1"):
        path = output / (target + "-plan.json")
        review = json.loads(execute([*cli, "plan", "--target", target, "--namespace", "migration-fixture", "--plan", path]))
        if path.stat().st_mode & 0o077:
            raise RuntimeError("PlanFileIsNotPrivate")
        run = [*cli, "run", "--plan", path, "--approve", review["plan"], "--timeout", "180"]
        result = json.loads(execute(run, timeout=600))
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
                    path = older / "crds" / ("hanko.sh_" + entry["plural"] + ".yaml")
                    crd = yaml.safe_load(path.read_text())
                    crd["spec"]["versions"] = crd["spec"]["versions"][:1]
                    path.write_text(yaml.safe_dump(crd))
                refused = subprocess.run([str(v) for v in [helm, "template", "fixture", older, *options]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
                if refused.returncode == 0 or b"still stores v1beta1" not in refused.stderr:
                    raise RuntimeError("ChartDidNotRefuseUnreadableStorage")
        # Same approved plan remains safe on resume. Completion still requires
        # three fresh native successes; forged progress cannot bypass proof.
        resumed = json.loads(execute(run, timeout=600))
        if not resumed.get("complete") or snapshot() != before:
            raise RuntimeError("ResumeChangedObjectMeaning")
        stages.append({"target": target, "objects": 3, "physical_encoding_verified": True, "resume_verified": True})
    jobs = kube("get", "storageversionmigrations.storagemigration.k8s.io")["items"]
    if len(jobs) != 12 or any(not any(c["type"] == "Succeeded" and c["status"] == "True" for c in j["status"]["conditions"]) for j in jobs):
        raise RuntimeError("NativeMigrationProofMissing")
    return {"complete": True, "scope": "experimental-local-storage", "stages": stages, "native_migrations": len(jobs),
            "preserved": ["uid", "spec", "status", "generation", "annotations", "finalizers", "managedFields"], "chart_live_guard_verified": True, "public_release_compatibility": False}


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
    report = {"complete": False, "kubernetes": args.kubernetes_version, "cleanup": False}
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
            execute([args.kind, "create", "cluster", "--name", cluster, "--image", image, "--kubeconfig", kubeconfig, "--config", stream.name, "--wait", "60s"], timeout=180)
        server = json.loads(execute([args.kubectl, "--kubeconfig", kubeconfig, "version", "-o", "json"]))
        if server["serverVersion"]["gitVersion"] != "v" + args.kubernetes_version:
            raise RuntimeError("UnexpectedKubernetesVersion")
        report.update(qualify(args.kubectl.resolve(), kubeconfig, cluster + "-control-plane", args.output, args.helm.resolve()))
    finally:
        execute([args.kind, "delete", "cluster", "--name", cluster], timeout=120)
        if built_image:
            execute(["docker", "image", "rm", built_image], timeout=120)
        report["cleanup"] = cluster not in execute([args.kind, "get", "clusters"]).decode().splitlines()
        report["complete"] = report["complete"] and report["cleanup"]
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        kubeconfig.unlink(missing_ok=True)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()

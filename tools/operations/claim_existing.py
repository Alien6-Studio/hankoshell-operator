"""Claim reviewed existing Keycloak resources in batches through the operator.

This administrator tool patches Kubernetes consent only. The operator re-reads
provider identity and semantics, writes ownership checkpoints and verifies them.
It never reads credentials, calls Keycloak, creates objects or removes an owner.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from tools.operations import storage_migration as migration

FORMAT = "hanko.sh/claim-batch/v1alpha1"
CONTRACT = "hanko.sh/adoption-contract/v1alpha1"
SOURCE = "hanko.sh/adoption-source"
APPROVAL = "hanko.sh/adoption-contract"
CANDIDATE = "hanko.sh/adoption-candidate"
LEGACY = {"hanko.sh/migrate-keycloak-client-uuid", "hanko.sh/migrate-keycloak-observation"}
KINDS = {kind: plural for kind, plural in (
    ("HankoApplication", "hankoapplications"), ("HankoServiceAccount", "hankoserviceaccounts"),
    ("HankoRole", "hankoroles"), ("HankoOrganization", "hankoorganizations"),
    ("HankoResourceServer", "hankoresourceservers"))}
MAX_TARGETS = 1024
MANAGED_FINALIZERS = {
    "HankoApplication": "hanko.sh/client-cleanup",
    "HankoServiceAccount": "hanko.sh/sa-cleanup",
    "HankoRole": "hanko.sh/role-cleanup",
    "HankoOrganization": "hanko.sh/organization-cleanup",
    "HankoResourceServer": "hanko.sh/resource-server-cleanup",
}
HASH = re.compile(r"sha256:[a-f0-9]{64}")
require = migration.require
Refused = migration.Refused


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0 and info.st_size <= migration.LIMIT, "PrivateClaimFileRequired")
        return migration.decode(stream.read(migration.LIMIT + 1))


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def identity(obj):
    meta = obj["metadata"]
    return {"kind": obj["kind"], **{key: meta[key] for key in ("namespace", "name", "uid")}}


def target_identity(obj):
    meta = obj["metadata"]
    labels = meta.get("labels") or {}
    return {**identity(obj), "generation": meta["generation"],
            "importRef": labels.get("hanko.sh/imported-by", ""), "tenantRef": labels.get("hanko.sh/tenant", "")}


def binding(obj):
    """Bind all spec/metadata meaning; status and API bookkeeping are outputs."""
    meta = copy.deepcopy(obj["metadata"])
    for key in ("resourceVersion", "managedFields"):
        meta.pop(key, None)
    annotations = meta.setdefault("annotations", {})
    for key in (APPROVAL, CANDIDATE):
        annotations.pop(key, None)
    return digest({"apiVersion": obj["apiVersion"], "kind": obj["kind"], "metadata": meta, "spec": obj["spec"]})


def validate_selection(targets, namespace):
    require(isinstance(targets, list) and 0 < len(targets) <= MAX_TARGETS, "InvalidClaimSelection")
    seen = set()
    migration.name(namespace, namespace=True)
    for target in targets:
        require(isinstance(target, dict) and set(target) == {"kind", "namespace", "name", "uid"}
                and target["kind"] in KINDS and target["namespace"] == namespace
                and isinstance(target["uid"], str) and 0 < len(target["uid"]) <= 128
                and not any(ord(c) < 32 for c in target["uid"]), "InvalidClaimSelection")
        migration.name(target["name"])
        key = (target["kind"], target["name"])
        require(key not in seen, "DuplicateClaimTarget")
        seen.add(key)


class Kubernetes:
    def __init__(self, executable, context):
        require(isinstance(context, str) and 0 < len(context) <= 1024, "ExplicitContextRequired")
        self.context = context
        self.command = [str(executable), "--context", context, "--request-timeout=30s"]

    def run(self, args, value=None):
        try:
            result = subprocess.run([*self.command, *args], input=None if value is None else json.dumps(value).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45, check=False)
        except (OSError, subprocess.SubprocessError):
            raise Refused("KubernetesCommandUnavailable") from None
        require(result.returncode == 0, "KubernetesRequestUnconfirmed")
        return migration.decode(result.stdout)

    def get(self, target):
        return self.run(["get", KINDS.get(target["kind"], "hankokeycloakinstances") + ".hanko.sh",
                         target["name"], "--namespace", target["namespace"], "-o", "json"])

    def cluster_uid(self):
        return self.run(["get", "namespace", "kube-system", "-o", "json"])["metadata"]["uid"]

    def patch(self, target, operations):
        return self.run(["patch", KINDS[target["kind"]] + ".hanko.sh", target["name"], "--namespace", target["namespace"],
                         "--type=json", "--patch-file=/dev/stdin", "-o", "json"], operations)


def source_identity(kube, namespace, name):
    migration.name(name)
    obj = kube.get({"kind": "HankoKeycloakInstance", "namespace": namespace, "name": name})
    meta = obj["metadata"]
    require(obj["kind"] == "HankoKeycloakInstance" and meta["namespace"] == namespace and meta["name"] == name
            and meta.get("uid") and not meta.get("deletionTimestamp"), "ClaimSourceUnavailable")
    return {**identity(obj), "generation": meta["generation"], "binding": binding(obj)}


def candidate(obj, source, resume):
    meta = obj["metadata"]
    require(not meta.get("deletionTimestamp") and obj["spec"].get("mode") == "Observe", "ClaimRequiresObserve")
    annotations = meta.get("annotations") or {}
    require(annotations.get(SOURCE) == source["name"] and not LEGACY.intersection(annotations), "ClaimSourceMismatch")
    value = obj.get("status", {}).get("adoptionCandidate") or {}
    require(value.get("contractVersion") == CONTRACT and value.get("complete") is True
            and value.get("truncated") is False and value.get("approvable") is True
            and HASH.fullmatch(value.get("candidateHash", "")) is not None, "ClaimCandidateUnavailable")
    expected = target_identity(obj)
    observed = value["target"]
    require(all(observed.get(key, "") == item for key, item in expected.items()), "ClaimTargetChanged")
    instance = value["providerIdentity"]["instance"]
    require(all(instance.get(key) == source[key] for key in ("kind", "namespace", "name", "uid")), "ClaimSourceMismatch")
    requested = APPROVAL in annotations or CANDIDATE in annotations
    require(not requested or annotations.get(APPROVAL) == CONTRACT
            and annotations.get(CANDIDATE) == value["candidateHash"], "ClaimApprovalConflict")
    if resume:
        require(not meta.get("labels", {}).get("hanko.sh/imported-by"), "ImportedClaimCannotResumeManage")
        require(not any(diff["code"] in ("would-change", "recreation-required", "unsupported")
                        or diff["code"] == "would-manage" and diff.get("field") not in ("mode", "realmRef", "importLatch")
                        for diff in value.get("diff", [])), "ClaimWouldChangeConfiguration")
    return value["candidateHash"]


def plan(kube, namespace, source_name, targets, resume=False):
    validate_selection(targets, namespace)
    source = source_identity(kube, namespace, source_name)
    value = {"format": FORMAT, "context": kube.context, "clusterUID": kube.cluster_uid(), "namespace": namespace,
             "source": source, "resumeManage": resume, "targets": [], "deferred": []}
    for target in targets:
        obj = kube.get(target)
        require(identity(obj) == target, "ClaimTargetReplaced")
        try:
            reviewed_hash = candidate(obj, source, resume)
        except Refused as error:
            value["deferred"].append({**target, "reason": str(error)})
            continue
        entry = {**target, "binding": binding(obj), "generation": obj["metadata"]["generation"],
                 "candidateHash": reviewed_hash}
        if resume:
            entry["finalizers"] = copy.deepcopy(obj["metadata"].get("finalizers"))
        value["targets"].append(entry)
    value["approvalHash"] = digest(value)
    return value


def validate_plan(value, approval):
    require(isinstance(value, dict) and value.get("format") == FORMAT and value.get("approvalHash") == approval
            and HASH.fullmatch(approval) is not None, "ClaimApprovalRequired")
    content = {key: item for key, item in value.items() if key != "approvalHash"}
    require(digest(content) == approval and type(value["resumeManage"]) is bool, "ClaimPlanChanged")
    selection = [{key: item[key] for key in ("kind", "namespace", "name", "uid")} for item in value["targets"]]
    require(selection, "NoEligibleClaimTargets")
    validate_selection(selection, value["namespace"])


def check_cluster(kube, value):
    require(kube.context == value["context"] and kube.cluster_uid() == value["clusterUID"], "ClaimClusterChanged")
    require(source_identity(kube, value["namespace"], value["source"]["name"]) == value["source"], "ClaimSourceChanged")


def reviewed_object(kube, value, target, *, finish=False):
    obj = kube.get(target)
    require(identity(obj) == {key: target[key] for key in ("kind", "namespace", "name", "uid")}, "ClaimTargetReplaced")
    original = copy.deepcopy(obj)
    if finish and obj["spec"].get("mode") == "Manage":
        require(obj["metadata"]["generation"] == target["generation"] + 1, "ClaimTargetChanged")
        original["spec"]["mode"] = "Observe"
        original["metadata"]["generation"] = target["generation"]
        if "finalizers" in target:
            # A controller may append its own cleanup finalizer immediately
            # after the explicitly consented mode change, before our read-back.
            # Bind every original finalizer and tolerate only this exact addition;
            # old plans without the snapshot keep their strict binding behavior.
            prior = target["finalizers"]
            require(prior is None or isinstance(prior, list) and all(isinstance(v, str) for v in prior), "InvalidClaimInput")
            actual = original["metadata"].get("finalizers")
            if actual != prior:
                managed = MANAGED_FINALIZERS[target["kind"]]
                require(isinstance(actual, list) and managed not in (prior or [])
                        and actual.count(managed) == 1
                        and [v for v in actual if v != managed] == (prior or []), "ClaimTargetChanged")
                if prior is None:
                    original["metadata"].pop("finalizers", None)
                else:
                    original["metadata"]["finalizers"] = copy.deepcopy(prior)
    require(binding(original) == target["binding"], "ClaimTargetChanged")
    if finish:
        annotations = obj["metadata"].get("annotations") or {}
        require(annotations.get(APPROVAL) == CONTRACT and annotations.get(CANDIDATE) == target["candidateHash"], "ClaimApprovalConflict")
        receipt = obj.get("status", {}).get("adoptionReceipt") or {}
        require(receipt == {"contractVersion": CONTRACT, "candidateHash": target["candidateHash"], "state": "Verified"}, "ClaimNotVerified")
        # Status is only a prerequisite for explicit Manage consent. The
        # controller independently verifies the durable native receipt again.
    else:
        receipt = obj.get("status", {}).get("adoptionReceipt") or {}
        annotations = obj["metadata"].get("annotations") or {}
        verified = (receipt == {"contractVersion": CONTRACT, "candidateHash": target["candidateHash"], "state": "Verified"}
                    and annotations.get(APPROVAL) == CONTRACT and annotations.get(CANDIDATE) == target["candidateHash"])
        if not verified:
            require(candidate(obj, value["source"], value["resumeManage"]) == target["candidateHash"], "ClaimObservationChanged")
    return obj


def patch_operations(obj, *, finish=False, reviewed_hash=None):
    meta = obj["metadata"]
    operations = [{"op": "test", "path": "/metadata/" + key, "value": meta[key]}
                  for key in ("uid", "generation", "resourceVersion")]
    if finish:
        operations.append({"op": "replace", "path": "/spec/mode", "value": "Manage"})
    else:
        annotations = dict(meta.get("annotations") or {})
        annotations.update({APPROVAL: CONTRACT, CANDIDATE: reviewed_hash})
        operations.append({"op": "add", "path": "/metadata/annotations", "value": annotations})
    return operations


def execute(kube, value, approval, *, finish=False):
    validate_plan(value, approval)
    require(not finish or value["resumeManage"], "ManageNotApprovedInClaimPlan")
    check_cluster(kube, value)
    # Reject a stale member before approving any member of this invocation.
    for target in value["targets"]:
        reviewed_object(kube, value, target, finish=finish)
    completed = 0
    for target in value["targets"]:
        for attempt in range(3):
            check_cluster(kube, value)
            obj = reviewed_object(kube, value, target, finish=finish)
            annotations = obj["metadata"].get("annotations") or {}
            done = obj["spec"].get("mode") == "Manage" if finish else (
                annotations.get(APPROVAL) == CONTRACT and annotations.get(CANDIDATE) == target["candidateHash"])
            if done:
                break
            try:
                kube.patch(target, patch_operations(obj, finish=finish, reviewed_hash=target["candidateHash"]))
            except Refused:
                # Lost acknowledgement or CAS conflict: a fresh exact review
                # is mandatory before another conditional, idempotent patch.
                pass
            if attempt == 2:
                current = reviewed_object(kube, value, target, finish=finish)
                done = current["spec"].get("mode") == "Manage" if finish else (
                    current["metadata"].get("annotations", {}).get(APPROVAL) == CONTRACT
                    and current["metadata"].get("annotations", {}).get(CANDIDATE) == target["candidateHash"])
                require(done, "ClaimPatchUnconfirmed")
        completed += 1
    return {"complete": True, "phase": "ManageRequested" if finish else "AcquisitionRequested", "targets": completed,
            "deferred": len(value["deferred"]), "providerOwnershipVerifiedByThisTool": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", type=Path, default=Path("kubectl"))
    parser.add_argument("--context", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    review = commands.add_parser("plan")
    review.add_argument("--namespace", required=True)
    review.add_argument("--source", required=True)
    review.add_argument("--targets", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)
    review.add_argument("--resume-manage", action="store_true")
    for command in ("apply", "finish"):
        sub = commands.add_parser(command)
        sub.add_argument("--plan", type=Path, required=True)
        sub.add_argument("--approve", required=True)
    args = parser.parse_args()
    kube = Kubernetes(args.kubectl, args.context)
    if args.command == "plan":
        value = plan(kube, args.namespace, args.source, private_read(args.targets), args.resume_manage)
        private_write(args.output, value)
        result = {"complete": True, "phase": "Planned", "targets": len(value["targets"]),
                  "deferred": len(value["deferred"]), "approvalHash": value["approvalHash"]}
    else:
        result = execute(kube, private_read(args.plan), args.approve, finish=args.command == "finish")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (Refused, KeyError, TypeError, ValueError, AttributeError, OSError, RecursionError) as error:
        print(json.dumps({"complete": False, "reason": str(error) if isinstance(error, Refused) else "InvalidClaimInput"}), file=sys.stderr)
        raise SystemExit(1) from None

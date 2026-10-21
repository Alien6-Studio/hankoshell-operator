"""Two-person, administrator-only release of one terminating Hanko finalizer.

This tool never cleans provider state. Immutable admission-protected records
precede the single compare-and-swap patch; an uncertain write is never replayed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
import uuid

import yaml

from tools.operations.common import NoRedirect, Refused, name, require

ROOT = Path(__file__).resolve().parents[2]

FORMAT = "hanko.sh/finalizer-release/v1alpha1"
AUDIT_NAMESPACE = "hanko-recovery-audit"
POLICY_NAME = "hanko-finalizer-release-audit"
EXECUTORS = "hanko:recovery-executors"
APPROVERS = "hanko:recovery-approvers"
CONSENT = "OrphanProviderStateAndAllowKubernetesGarbageCollection"
MAX_BYTES = 2_097_152
MAX_DEPTH = 64
MAX_TTL = 3600
SELECTOR = "app.kubernetes.io/name=hankoshell-operator"
RESOURCES = {
    "HankoApplication": ("hankoapplications", ["hanko.sh/client-cleanup", "hanko.sh/experimental-provider-cleanup"]),
    "HankoRealm": ("hankorealms", ["hanko.sh/realm-cleanup"]),
    "HankoRole": ("hankoroles", ["hanko.sh/role-cleanup"]),
    "HankoOrganization": ("hankoorganizations", ["hanko.sh/organization-cleanup"]),
    "HankoServiceAccount": ("hankoserviceaccounts", ["hanko.sh/sa-cleanup", "hanko.sh/workload-runtime-cleanup"]),
    "HankoWorkloadTrust": ("hankoworkloadtrusts", ["hanko.sh/workload-trust-cleanup"]),
    "HankoTheme": ("hankothemes", ["hanko.sh/theme-cleanup"]),
    "HankoResourceServer": ("hankoresourceservers", ["hanko.sh/resource-server-cleanup"]),
}
ADMISSION = "/apis/admissionregistration.k8s.io/v1/"
RECORDS = "/api/v1/namespaces/" + AUDIT_NAMESPACE + "/configmaps"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def decode(raw):
    require(len(raw) <= MAX_BYTES, "InputTooLarge")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= MAX_DEPTH, "InputTooDeep")
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, "InvalidJSON")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "AmbiguousJSON")
            value[key] = item
        return value

    def invalid(_):
        raise Refused("InvalidJSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, TypeError, RecursionError):
        raise Refused("InvalidJSON") from None


class Kubernetes:
    """Native kubeconfig auth, bounded responses, no provider/Secret/delete API."""

    def __init__(self, executable, kubeconfig=None, context=None):
        self.command = [str(executable)]
        if kubeconfig:
            self.command += ["--kubeconfig", str(kubeconfig)]
        if context:
            self.command += ["--context", context]
        self.process = self.directory = self.stream = None
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hanko-release-private-")
        path = Path(self.directory.name) / "proxy.log"
        self.stream = path.open("wb")
        allowed = (r"^/(api/v1/(pods|namespaces/[^/]+(/configmaps(/[^/]+)?)?)|apis/apps/v1/deployments"
                   r"|apis/authentication\.k8s\.io/v1/selfsubjectreviews"
                   r"|apis/admissionregistration\.k8s\.io/v1/validatingadmissionpolic(ybindings|ies)/[^/]+"
                   r"|apis/hanko\.sh/v1alpha1/namespaces/[^/]+/[^/]+/[^/]+)$")
        self.process = subprocess.Popen(self.command + ["proxy", "--port=0", "--address=127.0.0.1", "--accept-hosts=^127\\.0\\.0\\.1$",
            "--accept-paths=" + allowed, "--reject-methods=^(PUT|DELETE|CONNECT)$"], stdout=self.stream, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                raw = path.read_bytes()
                require(len(raw) < 65536 and self.process.poll() is None, "KubernetesProxyUnavailable")
                match = re.search(rb"127\.0\.0\.1:([0-9]{1,5})", raw)
                if match:
                    self.origin = "http://127.0.0.1:" + match[1].decode()
                    return self
                time.sleep(0.1)
            raise Refused("KubernetesProxyUnavailable")
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.stream:
            self.stream.close()
        if self.directory:
            self.directory.cleanup()

    def request(self, method, path, value=None, *, optional=False, probe=False):
        base = path.split("?", 1)[0]
        target = re.fullmatch(r"/apis/hanko\.sh/v1alpha1/namespaces/([^/]+)/([^/]+)/([^/]+)", base)
        target_ok = target and target[2] in {r[0] for r in RESOURCES.values()}
        allowed_get = base in ("/api/v1/pods", "/apis/apps/v1/deployments") or re.fullmatch(
            r"/api/v1/namespaces/[a-z0-9.-]+", base) or base.startswith(RECORDS + "/hanko-release-") or base in (
                ADMISSION + "validatingadmissionpolicies/" + POLICY_NAME,
                ADMISSION + "validatingadmissionpolicybindings/" + POLICY_NAME)
        require((method == "GET" and (target_ok or allowed_get))
                or (method == "POST" and base in (RECORDS, "/apis/authentication.k8s.io/v1/selfsubjectreviews"))
                or (method == "PATCH" and target_ok), "InvalidKubernetesOperation")
        require(not probe or (method == "POST" and path == RECORDS + "?dryRun=All"), "InvalidAuditProbe")
        if method == "PATCH":
            require(isinstance(value, list) and len(value) == 5 and [p.get("op") for p in value] == ["test"] * 4 + ["remove"]
                    and [p.get("path") for p in value[:4]] == ["/metadata/uid", "/metadata/resourceVersion", "/metadata/deletionTimestamp", "/metadata/finalizers"]
                    and re.fullmatch(r"/metadata/finalizers/[0-9]{1,3}", value[4].get("path", "")), "InvalidFinalizerPatch")
        data = None if value is None else canonical(value).encode()
        content_type = "application/json-patch+json" if method == "PATCH" else "application/json"
        try:
            request = Request(self.origin + path, data=data, method=method, headers={"Content-Type": content_type, "Accept": "application/json"})
            with self.opener.open(request, timeout=15) as response:
                result = decode(response.read(MAX_BYTES + 1))
                require(not probe, "AuditGuardNotEnforcing")
                return result
        except HTTPError as error:
            if probe and error.code == 403:
                result = decode(error.read(MAX_BYTES + 1))
                message = result.get("message", "")
                require(POLICY_NAME in message and "Finalizer release requires authenticated independent administrator provenance" in message,
                        "AuditGuardNotEnforcing")
                return None
            if error.code == 404 and optional:
                return None
            raise Refused("ConcurrentModification" if error.code in (409, 422) else "KubernetesRequestRefused") from None
        except (URLError, TimeoutError, OSError):
            raise Refused("KubernetesReadUnavailable" if method == "GET" else "KubernetesWriteOutcomeUnknown") from None


def identity(kube, group):
    review = kube.request("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
    info = review.get("status", {}).get("userInfo", {})
    actor = info.get("username", "")
    require(isinstance(actor, str) and 0 < len(actor) <= 1024 and not actor.startswith("system:")
            and group in info.get("groups", []), "IndependentAdministratorRequired")
    return actor


def guard(kube):
    installed = {}
    documents = list(yaml.safe_load_all((ROOT / "config/recovery/approval-policy.yaml").read_text()))
    for expected in documents:
        if expected["kind"] == "Namespace":
            path = "/api/v1/namespaces/" + AUDIT_NAMESPACE
        else:
            resource = "validatingadmissionpolicies" if expected["kind"] == "ValidatingAdmissionPolicy" else "validatingadmissionpolicybindings"
            path = ADMISSION + resource + "/" + POLICY_NAME
        actual = kube.request("GET", path)
        metadata = actual.get("metadata", {})
        require(metadata.get("uid") and not metadata.get("deletionTimestamp") and not metadata.get("ownerReferences"), "AuditGuardUnavailable")
        if expected["kind"] != "Namespace":
            require(actual.get("spec") == expected["spec"], "AuditGuardChanged")
            if expected["kind"] == "ValidatingAdmissionPolicy":
                status = actual.get("status", {})
                require(not status.get("typeChecking", {}).get("expressionWarnings"), "AuditGuardNotReady")
        installed[expected["kind"]] = {"uid": metadata["uid"], "spec": digest(expected.get("spec", {}))}
    # The optional controller-maintained status alone does not prove that the
    # API server has activated this binding. Exercise admission itself.
    # A dry-run denial must name this policy and its fixed provenance message.
    kube.request("POST", RECORDS + "?dryRun=All", {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": "hanko-release-guard-probe", "namespace": AUDIT_NAMESPACE}, "data": {"probe": "invalid"}}, probe=True)
    return installed


def quiescent(kube):
    query = "?" + urlencode({"labelSelector": SELECTOR, "limit": 100})
    results = [kube.request("GET", path + query) for path in ("/apis/apps/v1/deployments", "/api/v1/pods")]
    require(all(isinstance(p.get("items"), list) and not p.get("metadata", {}).get("continue") for p in results), "OperatorInventoryIncomplete")
    deployments, pods = (p["items"] for p in results)
    require(deployments and not pods and all(d.get("spec", {}).get("replicas", 1) == 0
            and d.get("status", {}).get("replicas", 0) == 0 for d in deployments), "OperatorNotQuiescent")


def target_path(plan):
    target = plan["target"]
    return "/apis/hanko.sh/v1alpha1/namespaces/" + name(target["namespace"], namespace=True) + "/" + RESOURCES[target["kind"]][0] + "/" + name(target["name"])


def fingerprint(obj):
    metadata = obj.get("metadata", {})
    finalizers = metadata.get("finalizers", [])
    require(isinstance(finalizers, list) and 0 < len(finalizers) <= 256 and all(isinstance(f, str) and len(f) <= 253 for f in finalizers)
            and len(finalizers) == len(set(finalizers)), "InvalidFinalizers")
    require(all(isinstance(metadata.get(k), str) and 0 < len(metadata[k]) <= 1024 for k in ("uid", "resourceVersion", "deletionTimestamp")), "TerminatingObjectRequired")
    require(type(metadata.get("generation")) is int and metadata["generation"] > 0, "InvalidGeneration")
    return {key: metadata[key] for key in ("uid", "resourceVersion", "deletionTimestamp", "generation")} | {"finalizersDigest": digest(finalizers)}


def plan(kube, kind, namespace, object_name, finalizer, ttl=900, now=None):
    require(kind in RESOURCES and finalizer in RESOURCES[kind][1] and type(ttl) is int and 60 <= ttl <= MAX_TTL, "InvalidRecoveryRequest")
    name(namespace, namespace=True)
    name(object_name)
    actor = identity(kube, EXECUTORS)
    installed = guard(kube)
    quiescent(kube)
    now = int(time.time()) if now is None else now
    value = {"format": FORMAT, "requestor": actor, "createdAt": now, "expiresAt": now + ttl,
             "nonce": str(uuid.uuid4()), "consent": CONSENT, "guard": installed,
             "target": {"kind": kind, "namespace": namespace, "name": object_name, "finalizer": finalizer}}
    value["clusterUID"] = kube.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"]
    ns = kube.request("GET", "/api/v1/namespaces/" + namespace)["metadata"]
    require(not ns.get("deletionTimestamp"), "NamespaceTerminating")
    value["namespaceUID"] = ns["uid"]
    obj = kube.request("GET", target_path(value))
    require(finalizer in obj.get("metadata", {}).get("finalizers", []), "SelectedFinalizerAbsent")
    value["target"].update(fingerprint(obj))
    return value


def validate_plan(value, now, *, expired=False):
    require(isinstance(value, dict) and set(value) == {"format", "requestor", "createdAt", "expiresAt", "nonce", "consent", "guard", "target", "clusterUID", "namespaceUID"}
            and value["format"] == FORMAT and value["consent"] == CONSENT, "InvalidPlan")
    target = value["target"]
    require(isinstance(target, dict) and set(target) == {"kind", "namespace", "name", "finalizer", "uid", "resourceVersion", "deletionTimestamp", "generation", "finalizersDigest"}
            and target["kind"] in RESOURCES and target["finalizer"] in RESOURCES[target["kind"]][1], "InvalidPlan")
    name(target["namespace"], namespace=True)
    name(target["name"])
    require(type(value["createdAt"]) is int and type(value["expiresAt"]) is int
            and 60 <= value["expiresAt"] - value["createdAt"] <= MAX_TTL
            and value["createdAt"] <= now + 30 and (expired or now < value["expiresAt"]), "PlanExpiredOrInvalid")
    require(isinstance(value["nonce"], str) and re.fullmatch(r"[0-9a-f-]{36}", value["nonce"]), "InvalidPlan")
    require(all(isinstance(value[k], str) and 0 < len(value[k]) <= 1024 for k in ("requestor", "clusterUID", "namespaceUID")), "InvalidPlan")
    require(type(target["generation"]) is int and target["generation"] > 0
            and all(isinstance(target[k], str) and 0 < len(target[k]) <= 1024 for k in ("uid", "resourceVersion", "deletionTimestamp"))
            and isinstance(target["finalizersDigest"], str) and re.fullmatch(r"[0-9a-f]{64}", target["finalizersDigest"]), "InvalidPlan")


def current(kube, value, *, expired=False, now=None):
    now = int(time.time()) if now is None else now
    validate_plan(value, now, expired=expired)
    require(guard(kube) == value["guard"], "AuditGuardChanged")
    require(kube.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"] == value["clusterUID"], "ClusterChanged")
    ns = kube.request("GET", "/api/v1/namespaces/" + value["target"]["namespace"])["metadata"]
    require(ns.get("uid") == value["namespaceUID"] and not ns.get("deletionTimestamp"), "NamespaceChanged")


def record_name(value, phase):
    return "hanko-release-" + digest(value) + "-" + phase


def record(kube, value, phase, actor, payload, *, create=False):
    expected = {"format": FORMAT, "phase": phase, "digest": digest(value), "actor": actor,
                "requestor": value["requestor"], "payload": canonical(payload)}
    path = RECORDS + "/" + record_name(value, phase)
    result = kube.request("GET", path, optional=True)
    if result is None and create:
        kube.request("POST", RECORDS, {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
            "metadata": {"name": record_name(value, phase), "namespace": AUDIT_NAMESPACE}, "data": expected})
        result = kube.request("GET", path)
    require(result is not None and result.get("data") == expected and result.get("immutable") is True
            and result.get("metadata", {}).get("uid") and not result["metadata"].get("deletionTimestamp")
            and not result["metadata"].get("ownerReferences") and not result.get("binaryData"), "AuditRecordMissingOrChanged")
    return result["metadata"]["uid"]


def unchanged(kube, value):
    obj = kube.request("GET", target_path(value))
    expected = {k: value["target"][k] for k in ("uid", "resourceVersion", "deletionTimestamp", "generation", "finalizersDigest")}
    require(fingerprint(obj) == expected, "TargetChanged")
    return obj


def request(kube, value, *, now=None):
    current(kube, value, now=now)
    actor = identity(kube, EXECUTORS)
    require(actor == value["requestor"], "RequestorChanged")
    quiescent(kube)
    unchanged(kube, value)
    return record(kube, value, "request", actor, value, create=True)


def approve(kube, value, *, now=None):
    current(kube, value, now=now)
    actor = identity(kube, APPROVERS)
    require(actor != value["requestor"], "IndependentApproverRequired")
    request_uid = record(kube, value, "request", value["requestor"], value)
    unchanged(kube, value)
    return record(kube, value, "approval", actor, {"requestUID": request_uid, "decision": CONSENT}, create=True)


def approved(kube, value):
    request_uid = record(kube, value, "request", value["requestor"], value)
    approval = kube.request("GET", RECORDS + "/" + record_name(value, "approval"))
    actor = approval.get("data", {}).get("actor")
    require(isinstance(actor, str) and actor != value["requestor"], "IndependentApproverRequired")
    approval_uid = record(kube, value, "approval", actor, {"requestUID": request_uid, "decision": CONSENT})
    return {"requestUID": request_uid, "approvalUID": approval_uid, "decision": CONSENT}


def observe(kube, value, *, now=None):
    current(kube, value, expired=True, now=now)
    actor = identity(kube, EXECUTORS)
    require(actor == value["requestor"], "RequestorChanged")
    intent_uid = record(kube, value, "intent", actor, approved(kube, value))
    obj = kube.request("GET", target_path(value), optional=True)
    outcome = ("TargetAbsent" if obj is None else "TargetReplaced" if obj.get("metadata", {}).get("uid") != value["target"]["uid"]
               else "SelectedFinalizerPresent" if value["target"]["finalizer"] in obj.get("metadata", {}).get("finalizers", [])
               else "SelectedFinalizerAbsent")
    # This is an observation, never proof of cleanup or proof of who changed it.
    payload = {"intentUID": intent_uid, "observation": outcome}
    existing = kube.request("GET", RECORDS + "/" + record_name(value, "receipt"), optional=True)
    if existing is not None:
        payload = decode(existing.get("data", {}).get("payload", "").encode())
        require(set(payload) == {"intentUID", "observation"} and payload["intentUID"] == intent_uid
                and payload["observation"] in {"TargetAbsent", "TargetReplaced", "SelectedFinalizerPresent", "SelectedFinalizerAbsent"}, "InvalidReceipt")
    record(kube, value, "receipt", actor, payload, create=True)
    return payload


def execute(kube, value, *, now=None):
    current(kube, value, now=now)
    actor = identity(kube, EXECUTORS)
    require(actor == value["requestor"], "RequestorChanged")
    authorization = approved(kube, value)
    require(kube.request("GET", RECORDS + "/" + record_name(value, "intent"), optional=True) is None, "IntentAlreadyRecordedUseObserve")
    quiescent(kube)
    obj = unchanged(kube, value)
    record(kube, value, "intent", actor, authorization, create=True)
    # Recheck after the durable intent acknowledgement. No target write is made
    # if the recorder, approval, policy, namespace or maintenance checks fail.
    current(kube, value, now=now)
    require(approved(kube, value) == authorization, "ApprovalChanged")
    quiescent(kube)
    obj = unchanged(kube, value)
    metadata = obj["metadata"]
    patch = [{"op": "test", "path": "/metadata/" + key, "value": metadata[key]}
             for key in ("uid", "resourceVersion", "deletionTimestamp", "finalizers")]
    patch.append({"op": "remove", "path": "/metadata/finalizers/" + str(metadata["finalizers"].index(value["target"]["finalizer"]))})
    kube.request("PATCH", target_path(value), patch)
    return observe(kube, value, now=now)


def private_output(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(canonical(value) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--context")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("plan")
    prepare.add_argument("--kind", choices=sorted(RESOURCES), required=True)
    prepare.add_argument("--namespace", required=True)
    prepare.add_argument("--name", required=True)
    prepare.add_argument("--finalizer", required=True)
    prepare.add_argument("--ttl", type=int, default=900)
    prepare.add_argument("--output", type=Path, required=True)
    for phase in ("request", "approve", "execute", "observe"):
        command = commands.add_parser(phase)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--accept-orphaned-provider-state-and-garbage-collection", action="store_true", required=phase in ("approve", "execute"))
    args = parser.parse_args(argv)
    try:
        with Kubernetes(args.kubectl, args.kubeconfig, args.context) as kube:
            if args.command == "plan":
                value = plan(kube, args.kind, args.namespace, args.name, args.finalizer, args.ttl)
                private_output(args.output, value)
            else:
                with args.plan.open("rb") as stream:
                    value = decode(stream.read(MAX_BYTES + 1))
                {"request": request, "approve": approve, "execute": execute, "observe": observe}[args.command](kube, value)
            print(canonical({"phase": args.command, "planDigest": digest(value)}))
        return 0
    except (Refused, OSError, KeyError, TypeError, ValueError) as error:
        print(str(error) if isinstance(error, Refused) else "RecoveryInputOrIORefused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

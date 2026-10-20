"""Administrator-driven, resumable storage migration using Kubernetes' native migrator.

The journal is progress evidence, never proof that bytes were migrated. Every
execution obtains a fresh native migration success before removing storedVersions.
Only the three reviewed, structurally equivalent IAM APIs may be selected.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

import yaml

from tools.qualification.lib import api_conversion_contract as conversion
from tools import versions

ROOT = Path(__file__).resolve().parents[2]


FORMAT = "hanko.sh/storage-migration/v1alpha1"
CRDS = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"
OPERATOR_NAMES = {"hankoshell-operator", "hanko-operator"}
LIMIT = 32 * 1024 * 1024
MAX_OBJECTS = 10_000
JOURNAL_KEY = "migration.json"
CONFLICT_ATTEMPTS = 4


class Refused(Exception):
    """Fixed diagnostic codes only; never an API body or user-controlled string."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "AmbiguousJSON")
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= LIMIT, "ResponseTooLarge")
    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(Refused("InvalidJSON")))
    except (ValueError, TypeError, RecursionError):
        raise Refused("InvalidJSON") from None


def name(value, *, namespace=False):
    require(isinstance(value, str) and 0 < len(value) <= (63 if namespace else 253)
            and re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", value) and ".." not in value
            and (not namespace or "." not in value), "InvalidObjectName")
    return quote(value, safe="")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Kubernetes:
    """A short-lived, loopback-only kubectl proxy keeps kubeconfig auth native."""
    def __init__(self, executable, kubeconfig=None, context=None):
        self.command = [str(executable)]
        if kubeconfig:
            self.command += ["--kubeconfig", str(kubeconfig)]
        if context:
            self.command += ["--context", context]
        self.process = self.directory = self.stream = None
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hanko-storage-private-")
        path = Path(self.directory.name) / "proxy.log"
        self.stream = path.open("wb")
        # No exec, token/Secret, provider, delete or PATCH endpoint is exposed.
        allowed = (r"^/(version|apis/storagemigration\.k8s\.io|api/v1/(pods|namespaces(/[^/]+(/configmaps(/[^/]+)?)?)?)"
                   r"|apis/apps/v1/deployments|apis/apiextensions\.k8s\.io/v1/customresourcedefinitions/[^/]+(/status)?"
                   r"|apis/hanko\.sh/(v1alpha1|v1beta1)(/[^/]+)?|apis/storagemigration\.k8s\.io/(v1|v1beta1)(/storageversionmigrations(/[^/]+)?)?)$")
        self.process = subprocess.Popen(self.command + ["proxy", "--port=0", "--address=127.0.0.1", "--accept-hosts=^127\\.0\\.0\\.1$",
            "--accept-paths=" + allowed, "--reject-methods=^(DELETE|PATCH|CONNECT)$"], stdout=self.stream, stderr=subprocess.DEVNULL)
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

    def request(self, method, path, value=None, *, optional=False):
        require(method in ("GET", "POST", "PUT") and path.startswith("/") and not path.startswith("//"), "InvalidKubernetesOperation")
        data = None if value is None else json.dumps(value, allow_nan=False).encode()
        try:
            request = Request(self.origin + path, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json"})
            with self.opener.open(request, timeout=15) as response:
                return decode(response.read(LIMIT + 1))
        except HTTPError as error:
            if error.code == 404 and optional:
                return None
            raise Refused("ConcurrentModification" if error.code == 409 else "KubernetesRequestRefused") from None
        except (URLError, TimeoutError, OSError):
            # A sent mutation may already be accepted. Never auto-retry it.
            raise Refused("KubernetesReadUnavailable" if method == "GET" else "KubernetesWriteOutcomeUnknown") from None


def listed(kube, path, maximum=MAX_OBJECTS):
    result, cursor, seen = [], "", set()
    while True:
        query = {"limit": 25}
        if cursor:
            query["continue"] = cursor
        page = kube.request("GET", path + "?" + urlencode(query))
        require(isinstance(page, dict) and isinstance(page.get("items"), list), "InvalidKubernetesList")
        result.extend(page["items"])
        require(len(result) <= maximum, "InventoryTooLarge")
        cursor = page.get("metadata", {}).get("continue", "")
        if not cursor:
            return result
        require(isinstance(cursor, str) and len(cursor) <= 65536 and cursor not in seen, "InvalidContinueToken")
        seen.add(cursor)


def operator_workload(value):
    labels = [value.get("metadata", {}).get("labels") or {},
              value.get("spec", {}).get("template", {}).get("metadata", {}).get("labels") or {}]
    return any(v.get("app.kubernetes.io/name") in OPERATOR_NAMES or v.get("app") == "hanko-operator" for v in labels)


def quiescent(kube):
    # One name selector misses the chart's default name and can ignore a live
    # legacy writer beside a stopped canonical deployment. Inspect all pages;
    # custom chart names retain the fixed Pod/template app marker.
    deployments = [v for v in listed(kube, "/apis/apps/v1/deployments") if operator_workload(v)]
    pods = [v for v in listed(kube, "/api/v1/pods") if operator_workload(v)]
    require(deployments and not pods and all(d.get("spec", {}).get("replicas", 1) == 0
        and d.get("status", {}).get("replicas", 0) == 0 for d in deployments), "OperatorNotQuiescent")


def migration_api(kube):
    server = kube.request("GET", "/version").get("gitVersion", "").removeprefix("v")
    require(server in versions.DATA["kubernetes"]["versions"], "UnqualifiedKubernetesVersion")
    group = kube.request("GET", "/apis/storagemigration.k8s.io", optional=True)
    require(group is not None, "NativeStorageMigratorUnavailable")
    available = {v["version"] for v in group.get("versions", [])}
    api = "v1" if "v1" in available else "v1beta1" if "v1beta1" in available else None
    require(api is not None, "NativeStorageMigratorUnavailable")
    discovery = kube.request("GET", "/apis/storagemigration.k8s.io/" + api)
    require(any(r.get("name") == "storageversionmigrations" and r.get("kind") == "StorageVersionMigration"
        and not r.get("namespaced") and {"get", "list", "create"} <= set(r.get("verbs", [])) for r in discovery.get("resources", [])), "NativeStorageMigratorUnavailable")
    return api


def idle(obj):
    metadata, spec, status = obj.get("metadata", {}), obj.get("spec", {}), obj.get("status", {})
    require(metadata.get("uid") and metadata.get("resourceVersion") and not metadata.get("deletionTimestamp"), "PendingDeletion")
    generation = metadata.get("generation")
    observe = spec.get("mode") == "Observe" or bool(metadata.get("labels", {}).get("hanko.sh/imported-by"))
    require(status.get("phase") == "Ready" and status.get("observedGeneration") == generation
        and (status.get("observationGeneration") == generation and status.get("appliedGeneration", 0) == 0 if observe
             else status.get("appliedGeneration") == generation) and status.get("observationComplete") is True
        and status.get("driftState") == "InSync", "PendingReconciliation")
    receipt = status.get("adoptionReceipt")
    annotations = metadata.get("annotations", {})
    if receipt is not None or any(k in annotations for k in ("hanko.sh/adoption-contract", "hanko.sh/adoption-candidate")):
        require(isinstance(receipt, dict) and receipt.get("state") == "Verified"
                and ("hanko.sh/adoption-candidate" not in annotations or receipt.get("candidateHash") == annotations["hanko.sh/adoption-candidate"]), "PendingAdoption")
    # Native rotation/delegation journals cannot be proven idle from CR status.
    # These experimental transactions require a separate native inspection path.
    require(not spec.get("secretRotationPolicy"), "RotationInspectionRequired")
    require(not any(p.get("delegation") for p in spec.get("permissions", [])), "DelegationInspectionRequired")


def objects(kube, contract, kind):
    entry = contract["resources"][kind]
    values = listed(kube, "/apis/hanko.sh/" + contract["hub_version"] + "/" + entry["plural"])
    result = {}
    for obj in values:
        idle(obj)
        metadata = obj["metadata"]
        require(metadata["uid"] not in result and obj.get("kind") == kind, "InvalidObjectInventory")
        name(metadata.get("name")); name(metadata.get("namespace"), namespace=True)
        result[metadata["uid"]] = obj
    return result


def semantic_hash(obj):
    obj = copy.deepcopy(obj)
    obj.pop("apiVersion", None)
    obj["metadata"].pop("resourceVersion", None)
    # This private in-memory hash may cover legacy sensitive fields. It never
    # enters a plan, journal, diagnostic or public report.
    return conversion.digest(obj)


def crd_state(kube, contract, kind):
    crd = kube.request("GET", CRDS + contract["resources"][kind]["plural"] + ".hanko.sh")
    try:
        conversion.validate_crd(crd, contract, live=True)
    except (ValueError, KeyError, TypeError):
        raise Refused("ConversionContractMismatch") from None
    stored = crd.get("status", {}).get("storedVersions", [])
    require(stored and set(stored) <= set(conversion.VERSIONS) and len(stored) == len(set(stored)), "UnknownStoredVersion")
    require(crd.get("metadata", {}).get("uid") and crd["metadata"].get("resourceVersion"), "InvalidCRDIdentity")
    return crd


def render_crds(kube, directory):
    """Read-only upgrade preflight. Keep live storage; never manufacture proof."""
    rendered, seen = [], set()
    contract = conversion.load()
    for path in sorted(directory.glob("*.yaml")):
        target = yaml.safe_load(path.read_text())
        require(isinstance(target, dict) and target.get("kind") == "CustomResourceDefinition"
                and target.get("apiVersion") == "apiextensions.k8s.io/v1", "InvalidCRDBundle")
        identity = target.get("metadata", {}).get("name")
        require(identity not in seen, "DuplicateCRD")
        seen.add(identity)
        name(identity)
        spec = target["spec"]
        require(spec.get("group") == "hanko.sh" and identity == spec["names"]["plural"] + ".hanko.sh", "ForeignCRDBundle")
        require(set(target["metadata"]) <= {"name", "annotations", "labels"}, "CRDBundleContainsServerState")
        proposed = {v["name"]: v for v in spec["versions"]}
        require(len(proposed) == len(spec["versions"]) and sum(v.get("storage") is True for v in proposed.values()) == 1, "InvalidCRDBundle")
        if len(proposed) > 1:
            try:
                conversion.validate_crd(target, contract, live=True)
            except (ValueError, KeyError, TypeError):
                raise Refused("ConversionContractMismatch") from None
        else:
            require(set(proposed) == {contract["hub_version"]}, "UnknownTargetVersion")
        live = kube.request("GET", CRDS + identity, optional=True)
        if live is not None:
            current = live["spec"]
            require(not live["metadata"].get("deletionTimestamp"), "CRDBeingDeleted")
            require(all(current.get(k) == spec.get(k) for k in ("group", "scope", "names"))
                    and current.get("conversion", {}).get("strategy", "None") == spec.get("conversion", {}).get("strategy", "None") == "None", "CRDIdentityOrConversionChanged")
            stored = live.get("status", {}).get("storedVersions", [])
            require(stored and set(stored) <= set(proposed), "StoredVersionWouldBeOrphaned")
            sources = [v["name"] for v in current["versions"] if v.get("storage") is True]
            require(len(sources) == 1 and sources[0] in proposed and proposed[sources[0]].get("served") is True, "StorageVersionWouldChange")
            for version in current["versions"]:
                if version["name"] not in proposed:
                    require(not version.get("served"), "ServedVersionWouldBeRemoved")
                    continue
                replacement = proposed[version["name"]]
                require(not version.get("served") or replacement.get("served") is True, "ServedVersionWouldBeRemoved")
                require(version.get("schema") == replacement.get("schema")
                        and all(version.get(k) == replacement.get(k) for k in ("subresources", "selectableFields")), "CRDSchemaChangeNeedsReview")
            for version in proposed.values():
                version["storage"] = version["name"] == sources[0]
        # This is an input for administrator review/apply, never a server object
        # or a replacement for a successful native storage migration.
        require(set(target) <= {"apiVersion", "kind", "metadata", "spec"}, "CRDBundleContainsServerState")
        rendered.append(target)
    require(rendered, "EmptyCRDBundle")
    return rendered


def plan(kube, contract, target, namespace):
    require(target in conversion.VERSIONS, "UnknownTargetVersion"); name(namespace, namespace=True)
    api = migration_api(kube)
    quiescent(kube)
    value = {"format": FORMAT, "cluster_uid": kube.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"],
        "contract_sha256": conversion.digest(contract), "target": target, "namespace": namespace, "native_api": api, "resources": {}}
    for kind in sorted(contract["resources"]):
        crd = crd_state(kube, contract, kind)
        value["resources"][kind] = {"crd_uid": crd["metadata"]["uid"],
            "source": next(v["name"] for v in crd["spec"]["versions"] if v["storage"]),
            "objects": [{k: obj["metadata"][k] for k in ("uid", "namespace", "name", "generation", "resourceVersion")}
                for _, obj in sorted(objects(kube, contract, kind).items())]}
    return value


class Migration:
    def __init__(self, kube, contract, approved_plan, approval, *, timeout=1800):
        self.kube, self.contract, self.plan, self.timeout = kube, contract, approved_plan, timeout
        require(conversion.digest(approved_plan) == approval, "PlanApprovalMismatch")
        require(set(approved_plan) == {"format", "cluster_uid", "contract_sha256", "target", "namespace", "native_api", "resources"}
            and approved_plan["format"] == FORMAT and approved_plan["contract_sha256"] == conversion.digest(contract)
            and approved_plan["target"] in conversion.VERSIONS and set(approved_plan["resources"]) == set(contract["resources"]), "InvalidMigrationPlan")
        for entry in approved_plan["resources"].values():
            require(isinstance(entry, dict) and set(entry) == {"crd_uid", "source", "objects"}
                and isinstance(entry["crd_uid"], str) and entry["source"] in conversion.VERSIONS
                and isinstance(entry["objects"], list) and len(entry["objects"]) <= MAX_OBJECTS, "InvalidMigrationPlan")
            for obj in entry["objects"]:
                require(isinstance(obj, dict) and set(obj) == {"uid", "namespace", "name", "generation", "resourceVersion"}
                    and type(obj["generation"]) is int and obj["generation"] >= 1
                    and all(isinstance(v, str) and 0 < len(v) <= 253 for k, v in obj.items() if k != "generation"), "InvalidMigrationPlan")
                name(obj["name"]); name(obj["namespace"], namespace=True)
        self.identity, self.session = approval, uuid.uuid4().hex[:12]
        namespace = name(approved_plan["namespace"], namespace=True)
        self.journal_name = "hanko-storage-" + approval[:32]
        self.journal_path = "/api/v1/namespaces/" + namespace + "/configmaps/" + self.journal_name
        self.progress = {"format": FORMAT, "plan": approval, "session": self.session, "phase": "Prepared", "resources": {}}

    def guard(self, kind=None):
        require(self.kube.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"] == self.plan["cluster_uid"], "ClusterIdentityChanged")
        quiescent(self.kube)
        if kind:
            crd = crd_state(self.kube, self.contract, kind)
            require(crd["metadata"]["uid"] == self.plan["resources"][kind]["crd_uid"], "CRDIdentityChanged")
            return crd

    def checkpoint(self):
        value = self.kube.request("GET", self.journal_path)
        require(value.get("metadata", {}).get("uid") == self.journal_uid and not value["metadata"].get("deletionTimestamp"), "MigrationJournalReplaced")
        require(set(value.get("data", {})) == {JOURNAL_KEY} and not value.get("binaryData") and not value["metadata"].get("ownerReferences"), "MigrationJournalConflict")
        previous = decode(value["data"][JOURNAL_KEY])
        require(isinstance(previous, dict) and previous.get("format") == FORMAT and previous.get("plan") == self.identity, "MigrationJournalConflict")
        value["data"] = {JOURNAL_KEY: json.dumps(self.progress, sort_keys=True, separators=(",", ":"))}
        self.kube.request("PUT", self.journal_path, value)

    def snapshot(self, kind):
        current = objects(self.kube, self.contract, kind)
        approved = self.plan["resources"][kind]["objects"]
        require(isinstance(approved, list) and len(approved) <= MAX_OBJECTS, "InvalidMigrationPlan")
        identities = {o["uid"]: o for o in approved}
        require(len(identities) == len(approved), "InvalidMigrationPlan")
        require(set(current) == set(identities) and all(current[uid]["metadata"][k] == expected[k]
            for uid, expected in identities.items() for k in ("name", "namespace", "generation")), "ObjectIdentityChanged")
        return {uid: semantic_hash(obj) for uid, obj in current.items()}

    def wait_native(self, path, uid, spec, *, kind=None, generation=None):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            crd = self.guard(kind)
            if kind:
                require(crd["metadata"].get("generation") == generation and next(v["name"] for v in crd["spec"]["versions"] if v["storage"]) == self.plan["target"], "StorageVersionChanged")
            if self.native_succeeded(path, uid, spec):
                return
            time.sleep(2)
        raise Refused("NativeMigrationDeadline")

    def native_succeeded(self, path, uid, spec):
        value = self.kube.request("GET", path)
        require(value["metadata"].get("uid") == uid and value.get("spec") == spec and not value["metadata"].get("deletionTimestamp"), "NativeMigrationIdentityChanged")
        conditions = value.get("status", {}).get("conditions", [])
        require(not any(c.get("type") == "Failed" and c.get("status") == "True" for c in conditions), "NativeMigrationFailed")
        # Older native REST storage omits optional generation fields. Only
        # the unchanged immutable GroupResource at its initial generation may.
        succeeded = any(c.get("type") == "Succeeded" and c.get("status") == "True" and
            (type(c.get("observedGeneration")) is int and c["observedGeneration"] == value["metadata"].get("generation", 0)
             or c.get("observedGeneration", 0) == 0 and value["metadata"].get("generation", 0) in (0, 1)) for c in conditions)
        if succeeded:
            require(value.get("status", {}).get("resourceVersion"), "NativeMigrationIncomplete")
        return succeeded

    def set_storage_version(self, kind, crd, before):
        generation = crd["metadata"].get("generation")
        require(type(generation) is int, "InvalidCRDIdentity")
        source = next(v["name"] for v in crd["spec"]["versions"] if v["storage"])
        path = CRDS + self.contract["resources"][kind]["plural"] + ".hanko.sh"
        for attempt in range(CONFLICT_ATTEMPTS):
            if attempt:
                crd = self.guard(kind)
            require(crd["metadata"].get("generation") == generation and
                next(v["name"] for v in crd["spec"]["versions"] if v["storage"]) == source, "StorageVersionChanged")
            require(self.snapshot(kind) == before, "MigratedObjectChanged")
            if source == self.plan["target"]:
                return crd
            for version in crd["spec"]["versions"]:
                version["storage"] = version["name"] == self.plan["target"]
            try:
                return self.kube.request("PUT", path, crd)
            except Refused as error:
                if str(error) != "ConcurrentModification" or attempt == CONFLICT_ATTEMPTS - 1:
                    raise

    def commit_stored_versions(self, kind, generation, before, proof):
        path = CRDS + self.contract["resources"][kind]["plural"] + ".hanko.sh/status"
        for attempt in range(CONFLICT_ATTEMPTS):
            current = self.guard(kind)
            require(current["metadata"].get("generation") == generation and
                next(v["name"] for v in current["spec"]["versions"] if v["storage"]) == self.plan["target"], "StorageVersionChanged")
            require(self.snapshot(kind) == before, "MigratedObjectChanged")
            require(self.native_succeeded(**proof), "NativeMigrationIncomplete")
            if current["status"]["storedVersions"] == [self.plan["target"]]:
                return
            current["status"]["storedVersions"] = [self.plan["target"]]
            try:
                self.kube.request("PUT", path, current)
                return
            except Refused as error:
                if str(error) != "ConcurrentModification" or attempt == CONFLICT_ATTEMPTS - 1:
                    raise

    def await_encoder(self, kind, generation):
        expected = base64.b64encode(hashlib.sha256(("hanko.sh/" + self.plan["target"] + "/" + kind).encode()).digest()[:8]).decode()
        deadline = time.monotonic() + min(self.timeout, 60)
        while time.monotonic() < deadline:
            crd = self.guard(kind)
            require(crd["metadata"].get("generation") == generation, "StorageVersionChanged")
            discovery = self.kube.request("GET", "/apis/hanko.sh/" + self.plan["target"])
            if any(r.get("name") == self.contract["resources"][kind]["plural"] and r.get("storageVersionHash") == expected for r in discovery.get("resources", [])):
                return
            time.sleep(0.5)
        raise Refused("StorageEncoderUnconfirmed")

    def execute(self):
        self.guard()
        require(migration_api(self.kube) == self.plan["native_api"], "NativeMigrationAPIChanged")
        existing = self.kube.request("GET", self.journal_path, optional=True)
        # Refuse every pending transaction and identity replacement before any
        # journal creation or storage flip, including a resumed execution.
        for kind in self.contract["resources"]:
            current = self.guard(kind)
            self.snapshot(kind)
            if existing is None:
                require(next(v["name"] for v in current["spec"]["versions"] if v["storage"]) == self.plan["resources"][kind]["source"], "ReviewSnapshotChanged")
        if existing is not None:
            require(set(existing.get("data", {})) == {JOURNAL_KEY} and not existing.get("binaryData") and not existing.get("metadata", {}).get("ownerReferences"), "MigrationJournalConflict")
            previous = decode(existing.get("data", {}).get(JOURNAL_KEY, ""))
            require(isinstance(previous, dict) and previous.get("format") == FORMAT and previous.get("plan") == self.identity, "MigrationJournalConflict")
        else:
            # Initial approval binds the precise review snapshot. On resume the
            # same UID set is revalidated, but native rewrites may have moved RVs.
            for kind in self.contract["resources"]:
                live = objects(self.kube, self.contract, kind)
                require({uid: obj["metadata"]["resourceVersion"] for uid, obj in live.items()} ==
                    {obj["uid"]: obj["resourceVersion"] for obj in self.plan["resources"][kind]["objects"]}, "ReviewSnapshotChanged")
            existing = self.kube.request("POST", self.journal_path.rsplit("/", 1)[0], {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": self.journal_name, "namespace": self.plan["namespace"]}, "data": {JOURNAL_KEY: json.dumps(self.progress)}})
        self.journal_uid = existing.get("metadata", {}).get("uid")
        require(self.journal_uid and not existing["metadata"].get("deletionTimestamp"), "MigrationJournalReplaced")
        base = "/apis/storagemigration.k8s.io/" + self.plan["native_api"] + "/storageversionmigrations"
        for prior in listed(self.kube, base):
            resource = prior.get("spec", {}).get("resource", {})
            if resource.get("group") == "hanko.sh" and resource.get("resource") in {r["plural"] for r in self.contract["resources"].values()}:
                if not any(c.get("type") in ("Succeeded", "Failed") and c.get("status") == "True" for c in prior.get("status", {}).get("conditions", [])):
                    self.wait_native(base + "/" + name(prior["metadata"]["name"]), prior["metadata"]["uid"], prior["spec"])
        for index, kind in enumerate(sorted(self.contract["resources"])):
            before = self.snapshot(kind)
            crd = self.guard(kind)
            self.progress["phase"] = "Migrating"
            self.progress["resources"][kind] = {"phase": "Prepared", "objects": len(before)}
            self.checkpoint()
            written = self.set_storage_version(kind, crd, before)
            generation = written["metadata"].get("generation")
            require(type(generation) is int, "InvalidCRDIdentity")
            current = self.guard(kind)
            require(current["metadata"].get("generation") == generation and next(v["name"] for v in current["spec"]["versions"] if v["storage"]) == self.plan["target"], "StorageVersionNotApplied")
            self.await_encoder(kind, generation)
            # A fresh request on every execution prevents forged/stale journal
            # completion from becoming proof of a physical storage rewrite.
            job_name = "hanko-storage-" + self.identity[:12] + "-" + self.session + "-" + str(index)
            spec = {"resource": {"group": "hanko.sh", "resource": self.contract["resources"][kind]["plural"]}}
            job = self.kube.request("POST", base, {"apiVersion": "storagemigration.k8s.io/" + self.plan["native_api"], "kind": "StorageVersionMigration",
                "metadata": {"name": job_name, "annotations": {"hanko.sh/storage-migration-plan": self.identity, "hanko.sh/storage-migration-target": self.plan["target"]}}, "spec": spec})
            self.progress["resources"][kind].update(phase="Rewriting", migration=job_name, uid=job["metadata"]["uid"])
            self.checkpoint()
            self.wait_native(base + "/" + job_name, job["metadata"]["uid"], spec, kind=kind, generation=generation)
            self.commit_stored_versions(kind, generation, before,
                {"path": base + "/" + job_name, "uid": job["metadata"]["uid"], "spec": spec})
            require(self.guard(kind)["status"]["storedVersions"] == [self.plan["target"]], "StoredVersionCommitUnconfirmed")
            self.progress["resources"][kind]["phase"] = "Committed"
            self.checkpoint()
        self.progress["phase"] = "Committed"
        self.checkpoint()
        return {"complete": True, "plan": self.identity, "target": self.plan["target"], "resources": len(self.contract["resources"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "run", "status", "check-crds", "render-crds"))
    parser.add_argument("--kubectl", type=Path, default=Path("kubectl"))
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--context")
    parser.add_argument("--target", choices=conversion.VERSIONS)
    parser.add_argument("--namespace", default="hanko-migrations")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--crds", type=Path, default=conversion.ROOT / "charts/hankoshell-operator/crds")
    parser.add_argument("--approve")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    require(1 <= args.timeout <= 3600, "InvalidMigrationDeadline")
    contract = conversion.load()
    with Kubernetes(args.kubectl, args.kubeconfig, args.context) as kube:
        if args.command in ("check-crds", "render-crds"):
            rendered = render_crds(kube, args.crds)
            if args.command == "render-crds":
                print(yaml.safe_dump_all(rendered, sort_keys=False), end="")
                return
            result = {"compatible": True, "crds": len(rendered), "preserves_live_storage": True}
        elif args.command == "plan":
            require(args.plan is not None, "PlanPathRequired")
            require(args.target is not None, "TargetVersionRequired")
            value = plan(kube, contract, args.target, args.namespace)
            fd = os.open(args.plan, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, indent=2)
                stream.write("\n")
            result = {"plan": conversion.digest(value), "resources": len(value["resources"]), "objects": sum(len(r["objects"]) for r in value["resources"].values())}
        else:
            require(args.plan is not None, "PlanPathRequired")
            require(args.plan.stat().st_size <= LIMIT, "PlanTooLarge")
            value = decode(args.plan.read_bytes())
            migration = Migration(kube, contract, value, args.approve or "", timeout=args.timeout)
            if args.command == "run":
                result = migration.execute()
            else:
                require(kube.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"] == value["cluster_uid"], "ClusterIdentityChanged")
                journal = kube.request("GET", migration.journal_path, optional=True)
                progress = decode(journal.get("data", {}).get(JOURNAL_KEY, "")) if journal else {}
                result = {"plan": migration.identity, "phase": progress.get("phase") if progress.get("phase") in ("Prepared", "Migrating", "Committed") else "Unknown",
                          "resources": len(progress.get("resources", {})), "authorizes_completion": False}
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Refused, KeyError, TypeError, ValueError, AttributeError, OSError, subprocess.SubprocessError):
        # API bodies and object fields must never escape through exceptions.
        import sys
        error = sys.exc_info()[1]
        print(json.dumps({"complete": False, "reason": str(error) if isinstance(error, Refused) else "InvalidMigrationInput"}), file=sys.stderr)
        raise SystemExit(1) from None

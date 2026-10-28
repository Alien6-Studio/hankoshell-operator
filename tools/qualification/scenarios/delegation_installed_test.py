"""Exact-image installed software delegation, independent HTTPS enforcement and recovery."""

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from tools.qualification.lib import keycloak_extension_source as extension
from tools.qualification.scenarios import agentic_installed

ROOT = Path(__file__).resolve().parents[3]

spec = importlib.util.spec_from_file_location("delegation_installed_base", ROOT / "tools/qualification/scenarios/workload_installed_test.py")
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)
spec = importlib.util.spec_from_file_location("delegation_scale", ROOT / "tools/qualification/scenarios/scale_installed_test.py")
scale = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scale)
native, system, run, wait = installed.native, installed.system, installed.run, installed.wait
ATTRIBUTE = "oauth.bounded-delegation.v1"
PHASES = ("Prepared", "Applied", "Verified", "Committed")
WITHDRAWAL_BOUND_SECONDS = 180
WITHDRAWAL_TOKEN_SECONDS = 300
IDENTITIES = {"delegation-actor": "worker", "delegation-subject": "subject-worker", "delegation-foreign": "foreign-worker"}


def checkout(revision):
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, timeout=10).strip()
    if actual != revision or dirty:
        raise ValueError("Installed delegation qualification requires the exact clean source")


def validate_build(version, revision):
    jar = extension.artifact(version)
    extension.verify_artifact(version, jar)
    build = json.loads((jar.parent / "build.json").read_text())
    cases = build.get("java_tests", [])
    if (build.get("revision") != revision or build.get("worktree_dirty") is not False
            or not isinstance(cases, list) or len(cases) < 16 or any(not isinstance(case, str) for case in cases) or len(cases) != len(set(cases))):
        raise ValueError("Extension build is not qualified on the exact clean operator source")


def server_spec(ttl=30, delegated=True):
    principals = [{"kind": "service_account", "ref": name} for name in IDENTITIES]
    permissions = [{"name": "ordinary", "resources": ["allowed", "denied"], "scopes": ["read", "write"], "principals": principals}]
    if delegated:
        permissions.append({"name": "bounded-read", "resources": ["allowed"], "scopes": ["read"], "principals": principals[:2],
            "delegation": {"actor": principals[0], "subject": principals[1], "maxDepth": 2, "maxTTLSeconds": ttl}})
    return {"realmRef": "managed", "applicationRef": "installed-api", "audience": "installed-api",
            "scopes": [{"name": name} for name in ("read", "write")],
            "resources": [{"name": name, "scopes": ["read", "write"]} for name in ("allowed", "denied")], "permissions": permissions}


def post_commit_status_fault(path):
    # Failed reconciles can report Error before native recovery has committed.
    # Only refuse the successful write after the driver verified its journal.
    return {"method": "PATCH", "path": path, "action": "deny", "json_path": ["status", "phase"], "equals": "Ready"}


def validate_handoff(state, old_peer, new_peer, phase):
    """Require each durable phase once and only the current holder's changes."""
    transitions = state.get("document_transitions", [])
    if (phase not in PHASES or not old_peer or not new_peer or old_peer == new_peer
            or state.get("document_transitions_overflow") or len(transitions) != len(PHASES)
            or [item.get("phase") for item in transitions] != list(PHASES)):
        raise ValueError("Delegation handoff has missing, repeated or regressed journal transitions")
    boundary = PHASES.index(phase)
    if any(item.get("peer") != (old_peer if index <= boundary else new_peer) for index, item in enumerate(transitions)):
        raise ValueError("Delegation journal changed through the wrong lease holder")
    if any(count for route, count in state.get("attempted_counts", {}).items()
           if route.startswith(("POST ", "DELETE ")) and not route.endswith("/protocol/openid-connect/token")):
        raise ValueError("Delegation handoff attempted native object creation or deletion")


def stable_client_attributes(client):
    return {key: value for key, value in client.get("attributes", {}).items()
            if key not in (ATTRIBUTE, "hanko.sh/resource-server-ownership")}


def ownership_summary(current, kind, uid, resource_uid):
    """Fixed booleans/counts only; no native values or private representations."""
    attrs = current.get("attributes", {})
    key = "hanko.sh/application-owner" if kind == "HankoApplication" else "hanko.sh/client-owner-uid"
    result = {"kind": kind, "uid_matches": bool(uid) and attrs.get(key) == uid,
              "kind_matches": kind == "HankoApplication" or attrs.get("hanko.sh/client-owner-kind") == kind,
              "protocol_matches": current.get("protocol") == "openid-connect",
              "client_enabled": current.get("enabled") is True,
              "service_accounts_enabled": current.get("serviceAccountsEnabled") is True,
              "authorization_enabled": current.get("authorizationServicesEnabled") is True,
              "exchange_enabled": attrs.get("standard.token.exchange.enabled") == "true"}
    for label, attribute in (("delegation", ATTRIBUTE), ("actor", "oauth.bounded-delegation.actor.v1"),
                             ("authorization", "hanko.sh/resource-server-ownership")):
        result[label + "_present"] = attribute in attrs
        if attribute not in attrs:
            continue
        try:
            document = json.loads(attrs[attribute])
            if not isinstance(document, dict):
                raise ValueError()
            result[label + "_json_object"] = True
            result[label + "_version_supported"] = type(document.get("version")) is int and document["version"] in ((1, 2) if label == "authorization" else (1,))
            if label == "actor":
                result["actor_self_matches"] = document.get("actor") == {"id": current.get("id"), "attribute": key, "value": uid}
                result["actor_owner_count"] = len(document["owners"]) if isinstance(document.get("owners"), dict) else 0
            else:
                result[label + "_owner_matches"] = document.get("ownerUID") == resource_uid
                if label == "delegation":
                    result["delegation_audience_matches"] = document.get("audience") == {"id": current.get("id"), "attribute": key, "value": uid}
                    result["delegation_phase"] = document.get("phase") if document.get("phase") in PHASES else "unknown"
                else:
                    result["journal_client_matches"] = document.get("objects", {}).get("resourceServerID") == current.get("id")
                    result["journal_counts"] = {name: len(document.get("objects", {}).get(name, []))
                                                for name in ("scopes", "resources", "policies", "permissions")}
        except (ValueError, TypeError, KeyError, AttributeError):
            result[label + "_json_object"] = False
    return result


class Delegation(installed.Installed):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.additional_operator_roles = ["view-users"]
        self.extra_certificate_names += ",DNS:delegation-resource.auth.svc"
        self.workload_grants[0]["serviceAccounts"] = list(IDENTITIES.values())
        self.install_values = {}
        self.ha_only = getattr(args, "ha_only", False)
        self.scraper = None
        self.certificate_days = 1
        if self.ha_only:
            self.install_values = {"replicaCount": 2, "reconciliation": {"maxConcurrent": 4},
                "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "2", "memory": "512Mi"}}}
        self.report.update({"layer": "installed-delegation", "deep_migration": False, "recovery": [],
            "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "limits": ["single-node disposable Kubernetes and single Keycloak replica", "fixed native JWKS; signing-key rotation is not qualified", "offline JWT withdrawal takes effect at expiry"]})
        self.resource_image = None
        if self.ha_only:
            self.report.update(layer="installed-delegation-ha", ha_recovery=[],
                limits=[*self.report["limits"], "four accepted-write pod-loss boundaries; not clock skew or arbitrary partitions"])

    def keycloak_build(self, build, image):
        jar = extension.artifact(self.args.keycloak_version)
        extension.verify_artifact(self.args.keycloak_version, jar)
        shutil.copyfile(jar, build / "bounded-delegation.jar")
        dockerfile = build / "Dockerfile"
        dockerfile.write_text(f"FROM {image}\nCOPY --chown=keycloak:keycloak bounded-delegation.jar /opt/keycloak/providers/\nRUN /opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true --features=stateless\n")
        self.report["extension"] = {**extension.pin(), "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest()}
        return dockerfile

    def server_ready(self, timeout=180):
        self.resource_ready(timeout=timeout)
        value = self.get("hankoresourceserver", "installed-server")
        self.record("bounded_provider_capability", value["status"]["capabilities"].get("boundedDelegation") is True)
        document = self.document()
        self.record("native_committed_single_grant", document.get("phase") == "Committed" and len(document.get("grants", [])) == 1)

    def document(self):
        raw = self.client("managed", "installed-api").get("attributes", {}).get(ATTRIBUTE)
        return json.loads(raw) if raw else {}

    def set_spec(self, ttl=30, delegated=True):
        self.patch("hankoresourceserver", "installed-server", {"spec": server_spec(ttl, delegated)})

    def resource_server(self):
        build = self.private / "resource-build"
        build.mkdir()
        architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[platform.machine()]
        environment = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=architecture)
        subprocess.run(["go", "build", "-trimpath", "-o", str(build / "resource"), "./tools/qualification/fixtures/delegation-resource-server"], cwd=ROOT, env=environment, timeout=180, check=True)
        (build / "Dockerfile").write_text(f"FROM {native.POD_IMAGE}\nCOPY --chmod=0555 resource /resource\nUSER 1000\nENTRYPOINT [\"/resource\"]\n")
        self.resource_image = self.name + "-resource:fixture"
        run(["docker", "build", "--network=none", "--tag", self.resource_image, build])
        run([self.args.kind, "load", "docker-image", self.resource_image, "--name", self.name])
        self.report["resource_verifier_sha256"] = hashlib.sha256((build / "resource").read_bytes()).hexdigest()
        settings = {"issuer": native.REALM_ISSUER, "audience": "installed-api", "resources": {"/" + name: value for name, value in self.resource_ids.items()}}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "delegation-resource", "namespace": "auth"},
                    "data": {"settings.json": json.dumps(settings), "ca.crt": (self.private / "tls.crt").read_text()}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "delegation-resource", "namespace": "auth", "labels": {"app": "delegation-resource"}}, "spec": {
                "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "resource", "image": self.resource_image, "imagePullPolicy": "Never",
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "ports": [{"containerPort": 8445}], "readinessProbe": {"tcpSocket": {"port": 8445}},
                    "volumeMounts": [{"name": "settings", "mountPath": "/fixture", "readOnly": True}, {"name": "settings", "mountPath": "/ca", "readOnly": True},
                                     {"name": "tls", "mountPath": "/tls", "readOnly": True}]}],
                "volumes": [{"name": "settings", "configMap": {"name": "delegation-resource"}}, {"name": "tls", "secret": {"secretName": "keycloak-tls", "defaultMode": 288}}]}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "delegation-resource", "namespace": "auth"},
             "spec": {"selector": {"app": "delegation-resource"}, "ports": [{"port": 8445, "targetPort": 8445}]}})
        self.kubectl("wait", "--for=condition=Ready", "pod/delegation-resource", "-n", "auth", "--timeout=180s")

    def probe(self, action, client="delegation-actor", **private):
        anchor = self.workload_anchors[client]
        settings = {"action": action, "issuer": native.REALM_ISSUER, "endpoint": native.REALM_ISSUER + "/protocol/openid-connect/token",
            "audience": "installed-api", "client": client, "account": anchor["account"], "uid": anchor["uid"], **private}
        command = [str(self.args.kubectl), "--kubeconfig", str(self.config), "exec", "-i", "-n", "workload", anchor["pod"], "--", "python", "-"]
        script = (ROOT / "tools/qualification/fixtures/delegation_pod_probe.py").read_text()
        # Settings are input to the in-memory program, never a Pod command/env or ConfigMap.
        wrapper = "import sys,io\nsys.stdin=io.StringIO(" + repr(json.dumps(settings)) + ")\n" + script
        process = subprocess.run(command, input=wrapper.encode(), capture_output=True, timeout=45, check=False)
        if process.returncode or len(process.stdout) > 65536:
            raise ValueError("In-Pod delegation probe failed; private response withheld")
        result = json.loads(process.stdout)
        if result.get("probe_failed"):
            raise ValueError("In-Pod delegation probe refused its inputs")
        token = result.get("access_token")
        if token:
            self.sensitive.append(token)
        return result

    def input(self, client="delegation-actor", narrow=False):
        permissions = ["allowed#read"] if narrow else [name + "#" + scope for name in ("allowed", "denied") for scope in ("read", "write")]
        result = self.probe("input", client, permissions=permissions)
        if result["http_status"] != 200:
            raise ValueError("Native workload input issuance failed")
        return result["access_token"]

    def exchange(self, subject, actor=None, client="delegation-actor", **fields):
        return self.probe("exchange", client, subject=subject, actor=actor if actor is not None else self.input(client), fields=fields)

    def refused(self, name, result):
        self.record(name, result.get("http_status") == 400 and result.get("oauth_error") == "invalid_request" and not result.get("access_token"))

    def access(self, token, resource="allowed", scope="read"):
        return self.probe("access", token=token, resource_endpoint="https://delegation-resource.auth.svc:8445/" + resource + "?scope=" + scope)

    def positive(self, subject=None):
        permission = next(p for p in self.get("hankoresourceserver", "installed-server")["spec"]["permissions"] if p.get("delegation"))
        max_ttl = permission["delegation"]["maxTTLSeconds"]
        subject = self.input("delegation-subject") if subject is None else subject
        actor = self.input()
        if "independent_broad_input_allows_more_authority" not in self.report["checks"]:
            self.record("independent_broad_input_allows_more_authority", self.access(actor, "denied", "write") == {"http_status": 200, "allowed": True})
        result = self.exchange(subject, actor)
        self.record("native_token_boundaries", result.get("http_status") == 200 and result.get("depth") == 1 and result.get("issuer_matches") is True
            and result.get("ordinary_claims_absent") is True and result.get("refresh_token_absent") is True
            and 0 < result["expires_at"] - result["checked_at"] <= max_ttl
            and result["expires_at"] <= min(native.claims(actor)["exp"], native.claims(subject)["exp"]))
        token = result["access_token"]
        self.record("independent_resource_read_allowed", self.access(token) == {"http_status": 200, "allowed": True})
        self.record("independent_resource_outside_grant_denied", self.access(token, "denied") == {"http_status": 403, "allowed": False})
        self.record("independent_scope_outside_grant_denied", self.access(token, scope="write") == {"http_status": 403, "allowed": False})
        return result

    def application_coexistence(self):
        document, inventory = self.document(), self.native_inventory()
        prior_plan = self.get("hankoresourceserver", "installed-server")["status"]["appliedPlanHash"]
        self.patch("hankoapplication", "installed-api", {"spec": {"attributes": {"locale": "en"}}})
        wait("application update coexists with native delegation", lambda: self.ready("hankoapplication", "installed-api"), 180)
        wait("resource re-evaluates the changed application reference", lambda: self.get("hankoresourceserver", "installed-server").get("status", {}).get("appliedPlanHash") not in (None, "", prior_plan), 180)
        self.server_ready()
        # The changed application generation intentionally changes the sealed
        # plan revision. Authority, ownership and native object IDs must agree.
        after = self.document()
        authority = lambda value: {key: item for key, item in value.items() if key != "revision"}
        self.record("application_update_preserves_native_delegation", authority(after) == authority(document) and self.native_inventory() == inventory)
        self.positive()

    def audience_isolation(self):
        self.apply_approved(installed.object_value("HankoApplication", "other-api", {"realmRef": "managed", "clientID": "other-api", "type": "m2m"}))
        wait("other audience application", lambda: self.ready("hankoapplication", "other-api"), 180)
        spec = server_spec(delegated=False)
        spec.update(applicationRef="other-api", audience="other-api")
        self.apply(installed.object_value("HankoResourceServer", "other-server", spec))
        wait("other audience ordinary authorization", lambda: self.iam_reconciled("hankoresourceserver", "other-server"), 180)
        result = self.probe("input", audience="other-api", permissions=["allowed#read"])
        if result.get("http_status") != 200 or not result.get("access_token"):
            raise ValueError("Other-audience native input issuance failed")
        token = result["access_token"]
        claims = native.claims(token)
        self.record("independent_undeclared_audience_refused", claims.get("iss") == native.REALM_ISSUER
            and claims.get("aud") in ("other-api", ["other-api"]) and claims.get("exp", 0) > time.time()
            and result.get("permissions_present") is True
            and self.access(token) == {"http_status": 401, "allowed": False})
        self.refused("subject_for_other_audience_refused", self.exchange(token))
        master = self.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password})
        self.token, self.token_at = master, time.monotonic()
        claims = native.claims(master)
        self.record("independent_foreign_issuer_refused", claims.get("iss") != native.REALM_ISSUER
            and claims.get("exp", 0) > time.time() and self.access(master) == {"http_status": 401, "allowed": False})

    def negatives(self):
        self.audience_isolation()
        subject = self.input("delegation-subject")
        actor = self.input()
        for label, fields in (("invalid_actor", {"actor_token": "invalid"}), ("omitted_actor", {"actor_token": None, "actor_token_type": None}),
                              ("foreign_issuer_actor", {"actor_token": self.token}),
                              ("foreign_realm_subject", {"subject_token": self.token}), ("undeclared_audience", {"audience": "delegation-subject"}),
                              ("unknown_audience", {"audience": "missing-api"}), ("undeclared_resource", {"resource": "https://foreign.invalid/resource"}),
                              ("ambient_scope", {"scope": "email"}), ("human_impersonation", {"requested_subject": "denial-target"}),
                              ("refresh_requested", {"requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token"})):
            self.refused(label, self.exchange(subject, actor, **fields))
        foreign = self.input("delegation-foreign")
        self.refused("valid_foreign_client_without_delegation", self.exchange(subject, foreign, "delegation-foreign"))
        self.refused("wrong_subject_identity", self.exchange(foreign, actor))
        first = self.positive(subject)
        second = self.exchange(first["access_token"])
        self.record("second_native_hop", second.get("http_status") == 200 and second.get("depth") == 2)
        self.refused("native_third_hop_refused", self.exchange(second["access_token"]))
        self.record("second_hop_resource_access", self.access(second["access_token"]) == {"http_status": 200, "allowed": True})
        actor = self.input()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.exchange(subject, actor), range(8)))
        self.record("atomic_native_replay_one_success", sum(r["http_status"] == 200 for r in results) == 1
            and sum(r["http_status"] == 400 and r.get("oauth_error") == "invalid_request" for r in results) == 7)
        self.refused("consumed_actor_cannot_issue_again", self.exchange(subject, actor))
        self.record("subject_narrowing_preserved", self.exchange(self.input("delegation-subject", True)).get("http_status") == 200)

    def stop_operator(self):
        self.stop_log_capture()
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "--timeout=90s")

    def start_operator(self):
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=1")
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.start_log_capture()

    def native_inventory(self):
        value = self.client("managed", "installed-api")
        prefix = f'/admin/realms/managed/clients/{value["id"]}/authz/resource-server/'
        return {kind: sorted(item.get("id", item.get("_id")) for item in self.api("GET", prefix + kind)) for kind in ("resource", "scope", "policy", "permission")}

    def phase_recovery(self):
        baseline = self.native_inventory()
        path = "/admin/realms/managed/clients/" + self.client("managed", "installed-api")["id"]
        status_path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankoresourceservers/installed-server/status"
        for index, phase in enumerate(PHASES):
            self.report["active_phase"] = "recovery_" + phase
            self.control("keycloak", {"method": "PUT", "path": path, "document_attribute": ATTRIBUTE, "phase": phase, "action": "lost-ack"}, reset=True)
            self.set_spec(29 - index)
            accepted = self.await_fault("keycloak")
            self.record("accepted_native_write_" + phase, accepted["upstream_status"] in (200, 204) and self.document()["phase"] == phase)
            self.stop_operator()
            self.patch("hankoresourceserver", "installed-server", {"status": None}, subresource="status")
            self.control("keycloak", None)
            self.control("api", post_commit_status_fault(status_path), reset=True)
            self.start_operator()
            failure = self.await_fault("api")
            observed_phase = self.document().get("phase")
            print("Post-commit boundary: " + phase + " native_phase=" + (observed_phase if observed_phase in PHASES else "unavailable"), flush=True)
            self.record("post_commit_status_failure_after_" + phase, failure["triggered"] is True and observed_phase == "Committed")
            self.stop_operator()
            self.control("api", None)
            self.patch("hankoresourceserver", "installed-server", {"status": None}, subresource="status")
            self.start_operator()
            self.server_ready()
            same = self.native_inventory() == baseline
            methods = all(self.client("managed", name)["clientAuthenticatorType"] == "federated-jwt" for name in IDENTITIES)
            self.record("no_duplicate_authority_or_method_loss_" + phase, same and methods)
            self.positive()
            self.report["recovery"].append({"phase": phase, "accepted_write_status": accepted["upstream_status"],
                "lost_acknowledgement": True, "status_lost": True, "status_failure": "post_commit_after_native_recovery", "inventory_preserved": same, "methods_preserved": methods})

    def ha_phase_recovery(self):
        baseline, original = self.native_inventory(), self.document()
        clients = {name: self.client("managed", name) for name in ("installed-api", *IDENTITIES)}
        identities = {name: client["id"] for name, client in clients.items()}
        path = "/admin/realms/managed/clients/" + identities["installed-api"]
        for index, phase in enumerate(PHASES):
            self.report["active_phase"] = "ha_recovery_" + phase
            scale.Scale.await_leader(self)
            holder = self.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"]
            pod = holder.rsplit("_", 1)[0]
            peer = self.get("pod", pod)["status"].get("podIP")
            if not peer:
                raise ValueError("Cannot attribute the delegation leader to a socket peer")
            raw = self.client("managed", "installed-api")["attributes"][ATTRIBUTE]
            self.control("keycloak", {"method": "PUT", "path": path, "document_attribute": ATTRIBUTE,
                "phase": phase, "action": "lost-ack"}, reset=True, track_document={"path": path, "attribute": ATTRIBUTE,
                    "initial_digest": hashlib.sha256(raw.encode()).hexdigest()})
            self.set_spec(23 - index)
            accepted = self.await_fault("keycloak")
            checkpoint = self.document()
            if (accepted.get("upstream_status") not in (200, 204) or checkpoint.get("phase") != phase
                    or self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity") != holder):
                raise ValueError("Delegation checkpoint was not accepted under the selected holder")
            # Keep provider writes blocked until this exact old process is gone.
            # The standby retains its API/lease access throughout; no status,
            # journal, approval or replica-count rewrite completes the handoff.
            self.stop_log_capture()
            self.kubectl("delete", "pod", pod, "-n", "auth", "--wait=true", "--timeout=90s")
            self.control("keycloak", None)
            self.scraper.close()
            self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
            scale.Scale.await_leader(self)
            current = self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity")
            if not current or current == holder:
                raise ValueError("Delegation did not replace the actual lease holder")
            self.start_log_capture()
            self.server_ready()
            state = self.observe_control("keycloak")
            new_peer = self.get("pod", current.rsplit("_", 1)[0])["status"].get("podIP")
            validate_handoff(state, peer, new_peer, phase)
            expected = copy.deepcopy(original)
            expected["revision"] = checkpoint["revision"]
            expected["grants"][0]["maxTTLSeconds"] = 23 - index
            same = self.native_inventory() == baseline and self.document() == expected
            for name, identity in identities.items():
                client = self.client("managed", name)
                same = same and client["id"] == identity and stable_client_attributes(client) == stable_client_attributes(clients[name])
                if name in IDENTITIES:
                    same = same and client["clientAuthenticatorType"] == "federated-jwt"
            if not same:
                raise ValueError("Delegation handoff changed native identity, authority or authentication")
            self.positive()
            self.report["ha_recovery"].append({"phase": phase, "complete": True, "leader_replaced": True,
                "accepted_write_status": accepted["upstream_status"], "lost_acknowledgement": True,
                "status_rewritten": False, "journal_transitions": len(PHASES), "native_object_creates": 0,
                "native_object_deletes": 0, "inventory_and_authority_preserved": True})
            self.record("delegation_ha_recovers_" + phase)

    def drift_and_outage(self):
        path = "/admin/realms/managed/clients/" + self.client("managed", "installed-api")["id"]
        self.control("keycloak", {"method": "PUT", "path": path, "document_attribute": ATTRIBUTE, "phase": "Prepared", "action": "deny"}, reset=True)
        self.set_spec(24)
        self.await_fault("keycloak")
        self.set_spec(23)
        self.control("keycloak", None)
        self.server_ready()
        self.record("fresh_spec_wins_after_refused_stale_write", self.document()["grants"][0]["maxTTLSeconds"] == 23)
        self.control("keycloak", {"method": "GET", "path": "/admin/realms/managed/clients", "path_prefix": True, "action": "http-status", "status": 503}, reset=True)
        before = self.document()
        self.set_spec(22)
        self.await_fault("keycloak")
        self.record("provider_outage_does_not_expand_grant", self.document() == before)
        self.control("keycloak", None)
        self.server_ready()
        self.positive()
        # A disabled native actor must fail before any delegated output exists.
        actor = self.input()
        subject = self.input("delegation-subject")
        self.stop_operator()
        current = self.client("managed", "delegation-actor")
        current["attributes"]["standard.token.exchange.enabled"] = "false"
        self.api("PUT", "/admin/realms/managed/clients/" + current["id"], current)
        self.refused("disabled_exchange_refused", self.exchange(subject, actor))
        current["attributes"]["standard.token.exchange.enabled"] = "true"
        self.api("PUT", "/admin/realms/managed/clients/" + current["id"], current)
        self.start_operator()
        self.server_ready()

    def expiry_and_withdrawal(self):
        self.set_spec(8)
        self.server_ready()
        result = self.positive()
        wait("delegated JWT real expiry", lambda: time.time() > result["expires_at"] + 1, 20)
        self.record("independent_expired_token_refused", self.access(result["access_token"]) == {"http_status": 401, "allowed": False})
        self.refused("expired_subject_cannot_chain", self.exchange(result["access_token"]))
        # The offline comparison must remain possible throughout the entire
        # withdrawal budget. Real short expiry is independently tested above.
        self.set_spec(WITHDRAWAL_TOKEN_SECONDS)
        self.server_ready()
        issued = self.positive()
        actor, subject = self.input(), self.input("delegation-subject")
        started = time.monotonic()
        self.set_spec(delegated=False)
        self.resource_ready()
        wait("native grant withdrawal", lambda: not self.document().get("grants"), WITHDRAWAL_BOUND_SECONDS)
        self.refused("withdrawn_grant_refuses_unused_inputs", self.exchange(subject, actor))
        elapsed = round(time.monotonic() - started, 3)
        self.report["revocation_seconds"] = elapsed
        self.record("withdrawal_observed_within_180_seconds", elapsed < WITHDRAWAL_BOUND_SECONDS)
        self.refused("withdrawn_ancestor_refuses_chaining", self.exchange(issued["access_token"]))
        self.record("offline_jwt_remains_valid_before_expiry", time.time() < issued["expires_at"] and self.access(issued["access_token"]) == {"http_status": 200, "allowed": True})
        self.set_spec()
        self.server_ready()
        self.positive()

    def deletion_recovery(self):
        self.stop_operator()
        client = self.client("managed", "installed-api")
        prefix = "/admin/realms/managed/clients/" + client["id"] + "/authz/resource-server/"
        self.api("POST", prefix + "scope", {"name": "foreign-scope"})
        scope = next(v for v in self.api("GET", prefix + "scope") if v["name"] == "foreign-scope")
        self.api("POST", prefix + "resource", {"name": "foreign-resource", "uris": ["https://foreign.invalid/private"], "scopes": [{"id": scope["id"], "name": scope["name"]}]})
        resource = next(v for v in self.api("GET", prefix + "resource") if v["name"] == "foreign-resource")
        self.api("POST", prefix + "policy/client", {"name": "foreign-reader", "type": "client", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS",
                 "clients": [self.client("managed", "delegation-foreign")["id"]]})
        policy = next(v for v in self.api("GET", prefix + "policy/client") if v["name"] == "foreign-reader")
        original_policy = self.api("GET", prefix + "policy/client/" + policy["id"])
        self.api("POST", prefix + "permission/resource", {"name": "foreign-dependency", "type": "resource", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS",
                 "resources": [self.resource_ids["allowed"]], "policies": [policy["id"]]})
        permission = next(v for v in self.api("GET", prefix + "permission/resource?fields=*") if v["name"] == "foreign-dependency")
        original = self.api("GET", prefix + "permission/resource/" + permission["id"])
        owned = [value["id"] for value in self.get("hankoresourceserver", "installed-server")["status"]["managedObjects"]["permissions"]]
        actor, subject = self.input(), self.input("delegation-subject")
        self.kubectl("delete", "hankoresourceserver", "installed-server", "-n", "auth", "--wait=false")
        self.start_operator()
        def blocked():
            value = self.get("hankoresourceserver", "installed-server")
            return bool(value["metadata"].get("deletionTimestamp") and value["metadata"].get("finalizers")) and any(
                c.get("reason") == "CleanupConflict" and c.get("status") == "False" for c in value.get("status", {}).get("conditions", []))
        wait("foreign incoming dependency retains the finalizer", blocked, 180)
        self.record("foreign_dependency_preserved_on_cleanup_refusal", self.api("GET", prefix + "permission/resource/" + permission["id"]) == original)
        self.refused("blocked_deletion_already_stops_issuance", self.exchange(subject, actor))
        self.control("keycloak", {"method": "DELETE", "path": prefix + "permission/" + owned[0], "action": "lost-ack"}, reset=True)
        self.api("DELETE", prefix + "permission/resource/" + permission["id"])
        accepted = self.await_fault("keycloak")
        self.record("accepted_cleanup_delete_acknowledgement_lost", accepted["upstream_status"] in (200, 204))
        self.stop_operator()
        self.patch("hankoresourceserver", "installed-server", {"status": None}, subresource="status")
        self.control("keycloak", None)
        self.start_operator()
        wait("interrupted resource cleanup completes", lambda: not self.exists("hankoresourceserver", "installed-server"), 180)
        remaining = {v["name"]: v for v in self.api("GET", prefix + "resource")}
        self.record("foreign_resource_survives_owned_cleanup", remaining == {"foreign-resource": resource})
        self.record("foreign_scope_survives_owned_cleanup", self.api("GET", prefix + "scope") == [scope])
        self.record("foreign_policy_survives_owned_cleanup", self.api("GET", prefix + "policy/client/" + policy["id"]) == original_policy)
        self.record("foreign_graph_keeps_authorization_enabled", self.client("managed", "installed-api")["authorizationServicesEnabled"] is True)
        self.record("cleanup_preserves_federated_authenticators", all(self.client("managed", name)["clientAuthenticatorType"] == "federated-jwt" for name in IDENTITIES))
        self.record("owned_delegation_removed", not self.document())

    def qualify_delegation(self):
        self.report["active_phase"] = "provision"
        self.create_cluster()
        self.record("exact_kubernetes_version")
        self.mirror_scanned_image()
        self.keycloak()
        self.record("exact_keycloak_version", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.provider_url = "https://keycloak.auth.svc:8443"
        self.fault_proxies()
        self.identities()
        if self.ha_only:
            self.scraper = scale.Metrics(self)
        self.install()
        self.start_log_capture()
        self.record("exact_scanned_image_installed")
        self.configure_api_proxy()
        if self.ha_only:
            scale.Scale.await_leader(self)
        self.trust()
        self.api("PUT", "/admin/realms/managed", {"attributes": {"oauth.bounded-delegation.profile": "software-v1"}})
        for index, (name, account) in enumerate(IDENTITIES.items()):
            self.workload_anchors[name] = self.workload_pod("delegation-" + str(index), account)
            self.create_hsa(name)
            self.native_secret(name)  # Administrator-only sentinel for leak detection.
        self.apply_approved(installed.object_value("HankoApplication", "installed-api", {"realmRef": "managed", "clientID": "installed-api", "type": "m2m"}))
        wait("installed audience application", lambda: self.ready("hankoapplication", "installed-api"), 180)
        initial_started = time.monotonic()
        self.apply(installed.object_value("HankoResourceServer", "installed-server", server_spec()))
        self.server_ready(timeout=600)
        self.report["initial_convergence_seconds"] = round(time.monotonic() - initial_started, 3)
        self.record("initial_graph_converged_within_600_seconds", self.report["initial_convergence_seconds"] < 600)
        self.resource_server()
        self.kubernetes_permissions()
        self.report["active_phase"] = "native_flows"
        self.positive()
        if self.ha_only:
            self.ha_phase_recovery()
            self.record("all_ha_native_phases_recovered", [r["phase"] for r in self.report["ha_recovery"]] == list(PHASES))
        else:
            self.application_coexistence()
            self.negatives()
            self.phase_recovery()
            self.report["active_phase"] = "drift_outage"
            self.drift_and_outage()
            self.report["active_phase"] = "expiry_withdrawal"
            self.expiry_and_withdrawal()
            self.report["active_phase"] = "deletion_recovery"
            self.deletion_recovery()
            self.record("all_native_phases_recovered", [r["phase"] for r in self.report["recovery"]] == list(PHASES))
        self.report["active_phase"] = "agentic_exchanges"
        agentic_installed.qualify(self, wait)
        self.report["active_phase"] = "leak_scan"
        self.leak_scan()
        self.report.update(complete=True, completed_at=datetime.now(timezone.utc).isoformat(), active_phase="complete")

    def public_evidence(self):
        keys = ("schema_version", "layer", "revision", "image_digest", "extension", "resource_verifier_sha256", "fixture_sha256", "node_image", "node_build", "keycloak_image",
                "keycloak_version", "kubernetes_version", "complete", "publishable", "started_at", "completed_at", "checks", "recovery", "ha_recovery", "initial_convergence_seconds", "revocation_seconds", "keycloak_profiles", "hub_payloads_inspected", "limits", "active_phase", "failure_ownership")
        return {key: self.report[key] for key in (*keys, "agentic") if key in self.report}

    def capture_ownership_failure(self):
        # Best effort, read-only, <=25 seconds plus a final token/read pair
        # (<=4 seconds). Diagnostic failures never replace the original error.
        snapshot = {"complete": False, "clients": [], "native_counts": {}, "journal_coverage": {}}
        self.report["failure_ownership"] = snapshot
        deadline = time.monotonic() + 25
        diagnostic_token = None

        def kube(kind, name):
            if time.monotonic() >= deadline:
                raise ValueError()
            raw = system.diagnostics.bounded_command([str(self.args.kubectl), "--kubeconfig", str(self.config),
                "--request-timeout=2s", "get", kind, name, "-n", "auth", "-o", "json"], 2)
            return json.loads(raw)["metadata"]["uid"]

        def get(path):
            nonlocal diagnostic_token
            if time.monotonic() >= deadline:
                raise ValueError()
            if diagnostic_token is None:
                fields = {"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": self.password}
                request = Request(self.endpoint + "/realms/master/protocol/openid-connect/token", data=urlencode(fields).encode())
                with urlopen(request, context=self.http, timeout=2) as response:
                    raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise ValueError()
                diagnostic_token = json.loads(raw)["access_token"]
                if not isinstance(diagnostic_token, str) or not diagnostic_token:
                    raise ValueError()
                self.sensitive.append(diagnostic_token)
            request = Request(self.endpoint + path, headers={"Authorization": "Bearer " + diagnostic_token})
            with urlopen(request, context=self.http, timeout=2) as response:
                raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError()
            return json.loads(raw)

        try:
            resource_uid = kube("hankoresourceserver", "installed-server")
            clients = get("/admin/realms/managed/clients?first=0&max=100")
            if not isinstance(clients, list) or len(clients) >= 100:
                raise ValueError()
            by_name = {value["clientId"]: value["id"] for value in clients}
            audience_objects = {}
            for name, kind, resource in [("installed-api", "HankoApplication", "hankoapplication"),
                                          *((name, "HankoServiceAccount", "hankoserviceaccount") for name in IDENTITIES)]:
                uid = kube(resource, name)
                identifier = by_name[name]
                if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", identifier):
                    raise ValueError()
                current = get("/admin/realms/managed/clients/" + quote(identifier, safe=""))
                summary = ownership_summary(current, kind, uid, resource_uid)
                summary["native_id_matches"] = current.get("id") == identifier
                snapshot["clients"].append(summary)
                if name == "installed-api":
                    try:
                        journal = json.loads(current.get("attributes", {}).get("hanko.sh/resource-server-ownership", "{}"))
                        audience_objects = journal.get("objects", {})
                    except (ValueError, TypeError, AttributeError):
                        pass
            audience = quote(by_name["installed-api"], safe="")
            for name, key in (("scope", "scopes"), ("resource", "resources"), ("policy", "policies"), ("permission", "permissions")):
                values = get(f"/admin/realms/managed/clients/{audience}/authz/resource-server/{name}?first=0&max=100")
                if not isinstance(values, list) or len(values) >= 100:
                    raise ValueError()
                snapshot["native_counts"][name] = len(values)
                owned = {value.get("id") for value in audience_objects.get(key, []) if isinstance(value, dict) and isinstance(value.get("id"), str)}
                live = {value.get("id") or value.get("_id") for value in values if isinstance(value, dict)
                        and isinstance(value.get("id") or value.get("_id"), str)}
                snapshot["journal_coverage"][name] = {"recorded": len(owned), "recorded_missing_live": len(owned - live), "live_unrecorded": len(live - owned)}
            snapshot["complete"] = True
        except Exception:
            pass

    def cleanup(self):
        try:
            if self.scraper:
                self.scraper.close()
            super().cleanup()
        finally:
            if self.resource_image:
                subprocess.run(["docker", "image", "rm", self.resource_image], capture_output=True, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path)
    parser.add_argument("--ha-only", action="store_true", help="Qualify two-replica delegation handoff separately from restart/status-loss coverage")
    args = parser.parse_args()
    args.deep_migration = False
    checkout(args.revision)
    validate_build(args.keycloak_version, args.revision)
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    if args.output.exists():
        raise ValueError("Installed delegation evidence output must be fresh")
    with tempfile.TemporaryDirectory(prefix="hankoshell-installed-delegation-private-") as temporary:
        fixture = Delegation(args, Path(temporary))
        try:
            fixture.qualify_delegation()
            checkout(args.revision)
        except Exception as error:
            fixture.report["complete"] = False
            fixture.capture_ownership_failure()
            system.diagnostics.capture(fixture, error)
            raise
        finally:
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
            finally:
                fixture.cleanup()


if __name__ == "__main__":
    main()

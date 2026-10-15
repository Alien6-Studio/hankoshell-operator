"""Exercise installed Fleet authority using the exact scanned OCI graph.

Disposable clusters and fixture identities only. Private keys, Hub bearers and
native representations stay in private temporary storage/memory; uploaded output
contains only allowlisted versions, hashes, counts and assertion decisions.
"""

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installed_workload", ROOT / "scripts/workload-installed-test.py")
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)
native, system, run, wait = installed.native, installed.system, installed.run, installed.wait
ENVELOPE = "hanko.sh/fleet-envelope/v1alpha1"


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def timestamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


def command_identity(target, command):
    raw = json.dumps({"target": target, "requestedAt": command["requestedAt"], "deadline": command["deadline"]}, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(b"hanko.sh/fleet-decommission/v1alpha1\0" + raw).hexdigest()


def public_state(value):
    return {"uid": value["metadata"]["uid"], "spec": value.get("spec", {}),
            "tenant": value["metadata"].get("labels", {}).get("hanko.sh/tenant")}


class Fleet(installed.Installed):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.report["layer"] = "installed-fleet"
        self.report["fixture_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.extra_certificate_names += ",DNS:hub.auth.svc,DNS:hub-alt.auth.svc"
        self.workload_grants = []
        self.hub_token = {name: secrets.token_hex(32) for name in ("tenant-a", "tenant-b")}
        self.hub_control = secrets.token_hex(32)
        self.canary = "private-fixture-person@example.invalid"
        self.sensitive += [*self.hub_token.values(), self.hub_control, self.canary]
        self.targets, self.plans = {}, {}
        self.realm = {"tenant-a": "managed", "tenant-b": "managed-b"}
        self.key = private / "publisher.pem"
        self.unapproved_key = private / "unapproved.pem"
        self.local = {"version": "hanko.sh/fleet-rollout/v1alpha1", "providers": [], "hubs": []}

    def record(self, name, valid=True):
        self.report["checks"][name] = bool(valid)
        if not valid:
            raise ValueError("Installed Fleet qualification failed: " + name)
        print("Installed Fleet: " + name + " passed", flush=True)

    def signing_keys(self):
        for key in (self.key, self.unapproved_key):
            run([self.args.openssl, "genpkey", "-algorithm", "ED25519", "-out", key])
            key.chmod(0o600)
            self.sensitive.append(key.read_text().strip())
        public = self.private / "publisher.der"
        run([self.args.openssl, "pkey", "-in", self.key, "-pubout", "-outform", "DER", "-out", public])
        data = public.read_bytes()
        if len(data) != 44 or data[:12].hex() != "302a300506032b6570032100":
            raise ValueError("Unexpected Ed25519 public key encoding")
        self.public_key = encoded(data[-32:])

    def sign(self, plan, key=None):
        raw = json.dumps(plan, separators=(",", ":")).encode()
        payload, signature = self.private / "signing-input", self.private / "signature"
        payload.write_bytes(ENVELOPE.encode() + b"\0" + raw)
        run([self.args.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key or self.key,
             "-in", payload, "-out", signature])
        return json.dumps({"version": ENVELOPE, "payload": encoded(raw), "signature": encoded(signature.read_bytes())})

    def identity(self, plan):
        raw = json.dumps(plan, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(ENVELOPE.encode() + b"\0" + raw).hexdigest()

    def hub(self, tenant=None, **changes):
        data = None if tenant is None else json.dumps({"tenant": tenant, **changes}).encode()
        req = Request(self.hub_endpoint + "/__fixture/control", data=data,
                      headers={"Authorization": "Bearer " + self.hub_control})
        with urlopen(req, context=self.http, timeout=10) as response:
            body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("Oversize fixture evidence")
        return json.loads(body)

    def start_hub(self):
        settings = {"control": self.hub_control, "tokens": self.hub_token, "canary": self.canary}
        self.apply(self.secret("hub-fixture-private", {"settings.json": json.dumps(settings)}),
            self.secret("hub-ca", {"tls.crt": (self.private / "tls.crt").read_text()}),
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "hub-code", "namespace": "auth"},
             "data": {"hub.py": (ROOT / "scripts/fleet-hub-fixture.py").read_text()}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "hub", "namespace": "auth"}, "spec": {
                "replicas": 1, "selector": {"matchLabels": {"app": "hanko-hub"}}, "template": {
                    "metadata": {"labels": {"app": "hanko-hub"}}, "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "hub", "image": native.POD_IMAGE, "command": ["python", "/fixture/hub.py"],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                             {"name": "private", "mountPath": "/private", "readOnly": True},
                                             {"name": "tls", "mountPath": "/tls", "readOnly": True}]}],
                        "volumes": [{"name": "code", "configMap": {"name": "hub-code"}},
                                    {"name": "private", "secret": {"secretName": "hub-fixture-private", "defaultMode": 288}},
                                    {"name": "tls", "secret": {"secretName": "keycloak-tls", "defaultMode": 288}}]}}}},
            *[{"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": "auth"},
               "spec": {"selector": {"app": "hanko-hub"}, "ports": [{"port": 9090, "targetPort": 9090}]}}
              for name in ("hub", "hub-alt")])
        self.kubectl("rollout", "status", "deployment/hub", "-n", "auth", "--timeout=120s")
        self.forward_hub()

    def forward_hub(self):
        log = self.private / ("hub-forward-" + secrets.token_hex(4))
        stream = log.open("wb")
        process = subprocess.Popen([str(self.args.kubectl), "--kubeconfig", str(self.config), "port-forward", "-n", "auth",
            "service/hub", ":9090", "--address", "127.0.0.1"], stdout=stream, stderr=subprocess.STDOUT)
        self.proxy_forwards.append((process, stream))
        wait("Hub fixture forwarding", lambda: re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text()), 30)
        self.hub_endpoint = "https://localhost:" + re.search(r"Forwarding from 127.0.0.1:(\d+)", log.read_text())[1]

    def identities(self):
        self.api("POST", "/admin/realms", {"realm": "managed-b", "enabled": True})
        for name, realm in [("system-operator", "managed"), ("tenant-a", "managed"), ("tenant-b", "managed-b")]:
            credential = secrets.token_hex(32)
            self.sensitive.append(credential)
            self.api("POST", "/admin/realms/master/clients", {"clientId": name, "secret": credential,
                "protocol": "openid-connect", "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
                "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False})
            kc, proxy = self.client("master", name), self.client("master", realm + "-realm")
            user = self.api("GET", f'/admin/realms/master/clients/{kc["id"]}/service-account-user')
            roles = [self.api("GET", f'/admin/realms/master/clients/{proxy["id"]}/roles/{role}')
                     for role in ("manage-realm", "manage-clients", "manage-events")]
            self.api("POST", f'/admin/realms/master/users/{user["id"]}/role-mappings/clients/{proxy["id"]}', roles)
            self.api("POST", f'/admin/realms/master/clients/{kc["id"]}/scope-mappings/clients/{proxy["id"]}', roles)
            if name == "system-operator":
                self.apply(self.secret("operator-credentials", {"client-id": name, "client-secret": credential}))
            else:
                self.apply(self.secret(name + "-keycloak", {"HANKO_KEYCLOAK_URL": "https://keycloak.auth.svc:8443",
                    "HANKO_KC_CLIENT_ID": name, "HANKO_KC_CLIENT_SECRET": credential, "ca.crt": (self.private / "tls.crt").read_text()}))
        self.apply(self.secret("operator-ca", {"ca.crt": (self.private / "tls.crt").read_text()}))

    def setup_tenants(self):
        now = datetime.now(timezone.utc)
        for name in self.hub_token:
            self.apply(self.secret(name + "-hub", {"hub_token": self.hub_token[name], "tenant_id": name,
                "cluster_id": name + "-cluster", "expires_at": timestamp(now + timedelta(hours=12))}),
                installed.object_value("HankoTenant", name, {"hubEndpoint": "https://hub.auth.svc:9090", "hubTenantID": name,
                    "hubTokenSecretRef": {"name": name + "-hub"}, "isolationMode": "keycloak",
                    "keycloakSecretRef": {"name": name + "-keycloak"}, "realmRef": self.realm[name]}))
            tenant = self.get("hankotenant", name)
            self.targets[name] = {"tenantID": name, "clusterID": name + "-cluster", "namespace": "auth",
                                  "tenantName": name, "tenantUID": tenant["metadata"]["uid"]}
            self.local["providers"].append({"target": self.targets[name], "endpoint": "https://keycloak.auth.svc:8443",
                                             "version": self.args.keycloak_version})
            self.local["hubs"].append({"target": self.targets[name], "endpoint": "https://hub.auth.svc:9090"})
        self.trust = {"version": "hanko.sh/fleet-trust/v1alpha1", "keys": [{"id": "publisher", "issuer": "fixture-publisher",
            "publicKey": self.public_key, "notBefore": timestamp(now - timedelta(minutes=1)), "notAfter": timestamp(now + timedelta(hours=2)),
            "scopes": [{k: v for k, v in target.items() if k != "tenantUID"} for target in self.targets.values()], "sources": ["fixture/config"]}]}
        self.save_policy()
        policy = (ROOT / "config/security/fleet-plan-trust-admission.yaml").read_text().replace("hanko-fleet-plan-trust", "fleet-trust")
        self.apply(*list(yaml.safe_load_all(policy)))
        def independent():
            result = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "patch", "configmap", "fleet-trust", "-n", "auth",
                "--as=system:serviceaccount:auth:system-operator", "--type=merge", "-p", '{"metadata":{"annotations":{"fixture.example/attempt":"1"}}}'],
                capture_output=True, timeout=20, check=False)
            return result.returncode != 0 and b"independent local fleet policy administrators" in result.stderr
        wait("independent Fleet trust admission", independent, 30)
        self.record("operator_cannot_rewrite_fleet_trust")

    def save_policy(self):
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fleet-trust", "namespace": "auth"},
                    "data": {"trust.json": json.dumps(self.trust), "rollout.json": json.dumps(self.local)}})

    def plan(self, name, sequence, display="Fleet baseline", seconds=1800):
        now = datetime.now(timezone.utc)
        realm = self.realm[name]
        return {"issuer": "fixture-publisher", "keyID": "publisher", "target": self.targets[name],
            "source": {"repository": "fixture/config", "revision": "a" * 40, "digest": "sha256:" + "b" * 64},
            "contractVersion": "hanko.sh/iam-contract/v1alpha1", "sequence": sequence,
            "issuedAt": timestamp(now), "notBefore": timestamp(now), "expiresAt": timestamp(now + timedelta(seconds=seconds)),
            "mode": "all-or-refuse", "content": {
                "realms": [installed.object_value("HankoRealm", realm, {"displayName": display, "otpRequired": True}, labels={"hanko.sh/tenant": name})],
                "apps": [installed.object_value("HankoApplication", name + "-app", {"realmRef": realm, "clientID": name + "-app",
                    "type": "spa", "redirectURIs": ["https://synthetic.example.invalid/callback"]}, labels={"hanko.sh/tenant": name})]}}

    def tick(self, name):
        self.patch("hankotenant", name, {"metadata": {"annotations": {"fixture.example/reconcile": secrets.token_hex(8)}}})

    def condition(self, name, reason):
        value = self.get("hankotenant", name)
        return any(c.get("type") == "Synced" and c.get("reason") == reason and
                   c.get("observedGeneration") == value["metadata"]["generation"] for c in value.get("status", {}).get("conditions", []))

    def expect(self, name, reason, event=False):
        self.tick(name)
        wait("Fleet condition " + reason, lambda: self.condition(name, reason), 120)
        if event:
            uid = self.get("hankotenant", name)["metadata"]["uid"]
            wait("Fleet Event " + reason, lambda: any(e.get("reason") == reason and e.get("regarding", e.get("involvedObject", {})).get("uid") == uid
                 for e in json.loads(self.kubectl("get", "events", "-n", "auth", "-o", "json"))["items"]), 30)

    def publish(self, name, plan, reason="FleetPlanApplied"):
        self.hub(name, envelope=self.sign(plan), status=200, ack={"ok": True})
        if reason == "FleetPlanApplied":
            self.tick(name)
            def accepted():
                status = self.get("hankotenant", name).get("status", {})
                current = status.get("fleetPlan", {})
                return current.get("identity") == self.identity(plan) and current.get("appliedIdentity") == current.get("identity") and any(
                    c.get("type") == "Synced" and c.get("reason") in ("FleetPlanApplied", "FleetPlanCurrent") for c in status.get("conditions", []))
            wait("complete Fleet plan delivery", accepted, 120)
        else:
            self.expect(name, reason)
        self.plans[name] = copy.deepcopy(plan)

    def converged(self, name, display):
        realm = self.realm[name]
        wait("native Fleet desired state", lambda: self.api("GET", "/admin/realms/" + realm).get("displayName") == display
             and self.ready("hankoapplication", name + "-app"), 120)

    def state(self):
        kube = [public_state(self.get(kind, name)) for tenant, realm in self.realm.items()
                for kind, name in (("hankorealm", realm), ("hankoapplication", tenant + "-app"))]
        provider = []
        for name, realm in self.realm.items():
            value = self.api("GET", "/admin/realms/" + realm)
            app = self.client(realm, name + "-app")
            provider.append({"realm": {k: value.get(k) for k in ("id", "realm", "displayName", "enabled", "otpPolicyType")},
                             "app": {k: app.get(k) for k in ("id", "clientId", "name", "enabled", "publicClient", "protocol", "redirectUris", "attributes")}})
        return digest({"kubernetes": kube, "provider": provider})

    def protected_state(self):
        return digest([public_state(self.get(kind, "system-operator")) for kind in ("deployment", "role", "rolebinding", "serviceaccount")])

    def reject(self, label, envelope, reason, status=200):
        # Drift has converged before each negative. Conditions and Events may
        # change, desired Kubernetes/provider state and accepted identity may not.
        self.converged("tenant-a", self.plans["tenant-a"]["content"]["realms"][0]["spec"]["displayName"])
        before = self.state()
        accepted = self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]["identity"]
        self.hub("tenant-a", envelope=envelope, status=status, ack={"ok": True})
        self.expect("tenant-a", reason, event=True)
        self.record(label, self.state() == before and self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]["identity"] == accepted)
        self.publish("tenant-a", self.plans["tenant-a"], "FleetPlanCurrent")

    def negatives(self):
        base = self.plans["tenant-a"]
        self.reject("hub_bearer_cannot_forge_signature", self.sign(base, self.unapproved_key), "FleetSignatureInvalid")
        wire = json.loads(self.sign(base))
        wire["signature"] = "A" * 86
        self.reject("tampered_signature", json.dumps(wire), "FleetSignatureInvalid")
        for label, change, reason in (
            ("sequence_conflict", lambda p: p["source"].update(revision="c" * 40), "FleetSequenceConflict"),
            ("wrong_tenant", lambda p: p.update(target=self.targets["tenant-b"]), "FleetTargetMismatch"),
            ("wrong_uid", lambda p: p["target"].update(tenantUID="replaced"), "FleetTargetMismatch"),
            ("wrong_source", lambda p: p["source"].update(repository="foreign/config"), "FleetIssuerAuthorityMismatch"),
            ("unknown_key", lambda p: p.update(keyID="unapproved"), "FleetKeyUnapproved"),
            ("expired", lambda p: p.update(issuedAt=timestamp(datetime.now(timezone.utc)-timedelta(minutes=2)),
                                           notBefore=timestamp(datetime.now(timezone.utc)-timedelta(minutes=2)),
                                           expiresAt=timestamp(datetime.now(timezone.utc)-timedelta(minutes=1))), "FleetPlanExpired"),
            ("future", lambda p: p.update(issuedAt=timestamp(datetime.now(timezone.utc)+timedelta(minutes=2)),
                                          notBefore=timestamp(datetime.now(timezone.utc)+timedelta(minutes=2))), "FleetPlanNotYetValid"),
            ("invalid_contract", lambda p: p.update(contractVersion="unsupported/v1"), "FleetSourceInvalid"),
            ("invalid_digest", lambda p: p["source"].update(digest="not-sha256"), "FleetSourceInvalid"),
            ("short_revision", lambda p: p["source"].update(revision="a" * 7), "FleetSourceInvalid"),
            ("invalid_sequence", lambda p: p.update(sequence=0), "FleetValidityInvalid"),
            ("excessive_validity", lambda p: p.update(expiresAt=timestamp(datetime.now(timezone.utc)+timedelta(hours=2))), "FleetValidityInvalid"),
            ("invalid_mode", lambda p: p.update(mode="force"), "FleetCapabilitiesUnsupported"),
            ("unavailable_global_capability", lambda p: p.update(requirements=["unknown.capability"]), "FleetCapabilityUnsupported"),
            ("minimum_operator", lambda p: p.update(minimumOperatorVersion="99.0.0"), "FleetOperatorVersionUnsupported"),
            ("unverified_rollback", lambda p: p.update(rollbackOf="sha256:"+"e"*64), "FleetRollbackReferenceInvalid"),
            ("reserved_metadata", lambda p: p["content"]["apps"][0]["metadata"].update(annotations={"hanko.sh/ownership-approval":"forged"}), "FleetContentAuthorityInvalid"),
            ("status_in_content", lambda p: p["content"]["apps"][0].update(status={"phase":"Ready"}), "FleetContentInvalid"),
            ("unknown_typed_field", lambda p: p["content"]["apps"][0]["spec"].update(unknown=True), "FleetContentInvalid"),
            ("overlapping_foreign_object", lambda p: p["content"]["apps"][0]["metadata"].update(name="tenant-b-app"), "BundleTenantConflict")):
            changed = copy.deepcopy(base)
            if label != "sequence_conflict":
                changed["sequence"] += 1
            change(changed)
            self.reject(label, self.sign(changed), reason)
        self.reject("private_error_body_withheld", self.canary, "FleetPlanFetchFailed", 403)
        self.reject("duplicate_envelope_member", self.sign(base)[:-1]+',"version":"'+ENVELOPE+'"}', "FleetEnvelopeInvalid")
        self.reject("oversize_response", "x"*(1024**2+1), "FleetPlanFetchFailed")
        self.reject("unknown_envelope_field", json.dumps({**json.loads(self.sign(base)), "private": self.canary}), "FleetEnvelopeInvalid")
        revoked = copy.deepcopy(self.trust)
        self.trust["keys"][0]["publicKey"] = encoded(bytes(32))
        before = self.state()
        self.save_policy()
        self.expect("tenant-a", "FleetSignatureInvalid", event=True)
        self.record("key_revocation_preserves_desired_provider_state", self.state() == before)
        self.record("revoked_compromised_key", self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]["sequence"] == base["sequence"])
        self.trust = revoked
        self.save_policy()
        self.publish("tenant-a", base, "FleetPlanCurrent")

    def rollout_reconnect(self):
        old = copy.deepcopy(self.plans["tenant-a"])
        newer = self.plan("tenant-a", old["sequence"]+1, "Fleet newer")
        self.publish("tenant-a", newer)
        self.converged("tenant-a", "Fleet newer")
        self.reject("downgrade_and_old_replay", self.sign(old), "FleetPlanDowngrade")
        current = self.get("hankoapplication", "tenant-a-app")
        before = public_state(current)
        self.publish("tenant-a", newer, "FleetPlanCurrent")
        self.record("same_identity_no_content_replay", public_state(self.get("hankoapplication", "tenant-a-app")) == before)
        partial = self.plan("tenant-a", newer["sequence"]+1, "Fleet partial")
        partial["mode"] = "partial"
        partial["content"]["themes"] = [installed.object_value("HankoTheme", "unsupported-theme", {"buildImage": "registry.example.invalid/theme", "keycloakPVC": "unused"}, labels={"hanko.sh/tenant": "tenant-a"})]
        self.publish("tenant-a", partial, "FleetPlanPartial")
        self.converged("tenant-a", "Fleet partial")
        status = self.get("hankotenant", "tenant-a")["status"]
        self.record("partial_not_full_convergence", status["fleetRollout"]["refused"] == 1 and status["fleetPlan"].get("appliedIdentity") != status["fleetPlan"]["identity"]
                    and not self.exists("hankotheme", "unsupported-theme"))
        rollback = copy.deepcopy(newer)
        now = datetime.now(timezone.utc)
        rollback.update(sequence=partial["sequence"]+1, rollbackOf=self.identity(newer), issuedAt=timestamp(now),
                        notBefore=timestamp(now), expiresAt=timestamp(now+timedelta(minutes=30)))
        self.publish("tenant-a", rollback)
        self.converged("tenant-a", "Fleet newer")
        status = self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]
        self.record("referenced_versioned_rollback", status["sequence"] == rollback["sequence"] and status["journal"][-1]["rollbackOf"] == self.identity(newer)
                    and self.ready("hankoapplication", "tenant-b-app"))

    def offline(self):
        self.kubectl("scale", "deployment/hub", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app=hanko-hub", "--timeout=90s")
        self.expect("tenant-a", "FleetPlanDisconnected", event=True)
        self.restart()
        self.expect("tenant-a", "FleetPlanDisconnected")
        # Native drift is injected by the bootstrap fixture, repaired by the
        # restarted installed controller through the still-valid retained plan.
        self.api("PUT", "/admin/realms/managed", {"displayName": "Offline drift"})
        self.patch("hankorealm", "managed", {"metadata": {"annotations": {"fixture.example/reconcile": secrets.token_hex(8)}}})
        wait("offline provider drift recovery", lambda: self.api("GET", "/admin/realms/managed").get("displayName") == "Fleet newer", 120)
        self.record("offline_restart_repairs_native_drift")
        self.kubectl("scale", "deployment/hub", "-n", "auth", "--replicas=1")
        self.kubectl("rollout", "status", "deployment/hub", "-n", "auth", "--timeout=120s")
        self.forward_hub()
        for name, plan in self.plans.items():
            self.publish(name, plan, "FleetPlanCurrent")
        self.record("reconnect_same_verified_plan")
        misrouted = copy.deepcopy(self.plans["tenant-a"])
        misrouted.update(sequence=misrouted["sequence"]+1, target=self.targets["tenant-b"])
        self.reject("reconnect_wrong_tenant_refused", self.sign(misrouted), "FleetTargetMismatch")

    def boundaries(self):
        before = self.protected_state()
        update = {"ok": True, "agentUpdate": {"version": "99.0.0", "digest": "sha256:" + "c" * 64}}
        self.hub("tenant-a", ack=update)
        self.expect("tenant-a", "AgentUpdateFailed", event=True)
        self.record("unsigned_update_cannot_change_image", self.protected_state() == before)
        candidate = self.plan("tenant-a", self.plans["tenant-a"]["sequence"]+1, "Fleet during blocked update")
        self.hub("tenant-a", envelope=self.sign(candidate), ack=update)
        self.tick("tenant-a")
        wait("new plan while image update is refused", lambda: self.get("hankotenant", "tenant-a").get("status", {}).get("fleetPlan", {}).get("appliedIdentity") == self.identity(candidate), 120)
        self.converged("tenant-a", "Fleet during blocked update")
        self.plans["tenant-a"] = candidate
        self.record("plan_during_self_update_retains_independent_image_guard", self.protected_state() == before)
        command = {"requestedAt": timestamp(datetime.now(timezone.utc)-timedelta(seconds=1)),
                   "deadline": timestamp(datetime.now(timezone.utc)+timedelta(minutes=2))}
        expired = {"requestedAt": timestamp(datetime.now(timezone.utc)-timedelta(minutes=2)),
                   "deadline": timestamp(datetime.now(timezone.utc)-timedelta(minutes=1))}
        for value, reason, label in ((command, "FleetCommandUnapproved", "unapproved_decommission_preserves_rbac_deployment"),
                                     (expired, "DecommissionExpired", "expired_decommission_preserves_rbac_deployment")):
            self.hub("tenant-a", ack={"ok": True, "decommission": value})
            self.expect("tenant-a", reason, event=True)
            self.record(label, self.protected_state() == before)
            self.hub("tenant-a", ack={"ok": True})
            self.expect("tenant-a", "FleetPlanCurrent")
        self.local["commands"] = [{"target": self.targets["tenant-a"], "action": "decommission",
                                   "identity": command_identity(self.targets["tenant-a"], command)}]
        self.save_policy()
        tampered = copy.deepcopy(command)
        tampered["deadline"] = timestamp(datetime.fromisoformat(command["deadline"].replace("Z", "+00:00"))+timedelta(seconds=1))
        self.hub("tenant-a", ack={"ok": True, "decommission": tampered})
        self.expect("tenant-a", "FleetCommandUnapproved", event=True)
        self.record("tampered_ack_cannot_reuse_exact_local_approval", self.protected_state() == before)
        self.local.pop("commands")
        self.save_policy()
        self.hub("tenant-a", ack={"ok": True})
        self.expect("tenant-a", "FleetPlanCurrent")
        # Freeze before changing the destination to exclude an old in-flight GET.
        self.stop_log_capture()
        self.kubectl("scale", "deployment/system-operator", "-n", "auth", "--replicas=0")
        self.kubectl("wait", "--for=delete", "pods", "-n", "auth", "-l", "app.kubernetes.io/instance=system", "--timeout=90s")
        self.patch("hankotenant", "tenant-a", {"spec": {"hubEndpoint": "https://hub-alt.auth.svc:9090"}})
        fetches = self.hub()["tenant-a"]["fetches"]
        self.restart()
        self.expect("tenant-a", "FleetHubEndpointUnapproved", event=True)
        self.record("endpoint_change_no_credential_forwarding", self.hub()["tenant-a"]["fetches"] == fetches)
        self.patch("hankotenant", "tenant-a", {"spec": {"hubEndpoint": "https://hub.auth.svc:9090"}})
        self.expect("tenant-a", "FleetPlanCurrent")

    def missing_registration(self):
        name = "no-tenant-routing"
        self.apply(installed.object_value("HankoApplication", name, {"realmRef": "managed", "clientID": name, "type": "spa"},
                                          labels={"hanko.sh/tenant": "unregistered"}))
        wait("unregistered tenant refusal", lambda: any(c.get("reason") == "TenantClientUnavailable"
             for c in self.get("hankoapplication", name).get("status", {}).get("conditions", [])), 60)
        self.record("named_tenant_never_falls_back", not self.api("GET", "/admin/realms/managed/clients?clientId=" + name))
        self.kubectl("delete", "hankoapplication", name, "-n", "auth", "--timeout=60s")

    def cache_clock_cases(self):
        status = self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]
        before = self.state()
        self.patch("hankotenant", "tenant-a", {"status": {"fleetPlan": {
            "verifiedAt": timestamp(datetime.now(timezone.utc)+timedelta(minutes=2))}}}, subresource="status")
        self.expect("tenant-a", "FleetClockRegression", event=True)
        self.record("durable_clock_regression_fails_closed", self.state() == before)
        self.patch("hankotenant", "tenant-a", {"status": {"fleetPlan": {"verifiedAt": status["verifiedAt"]}}}, subresource="status")
        self.publish("tenant-a", self.plans["tenant-a"], "FleetPlanCurrent")
        cache = self.get("configmap", status["cache"]["name"])
        denied = subprocess.run([str(self.args.kubectl), "--kubeconfig", str(self.config), "patch", "configmap", cache["metadata"]["name"],
            "-n", "auth", "--type=merge", "-p", '{"data":{"envelope.json":"{}"}}'], capture_output=True, timeout=20, check=False)
        self.record("cached_envelope_immutable", denied.returncode != 0 and b"immutable" in denied.stderr)
        self.kubectl("delete", "configmap", cache["metadata"]["name"], "-n", "auth", "--timeout=30s")
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": cache["metadata"]["name"], "namespace": "auth", "labels": cache["metadata"]["labels"],
            "ownerReferences": cache["metadata"]["ownerReferences"]}, "immutable": True, "data": {"envelope.json": "{}"}})
        self.expect("tenant-a", "FleetCacheInvalid", event=True)
        self.record("tampered_replaced_cache_not_authority", self.state() == before)
        renewed = self.plan("tenant-a", self.plans["tenant-a"]["sequence"]+1)
        self.publish("tenant-a", renewed)
        self.converged("tenant-a", "Fleet baseline")
        self.record("fresh_signed_sequence_recovers_cache_loss")

    def checkpoint_restart(self):
        # Externally lose the acknowledgement of the durable verification
        # checkpoint. All later API traffic is held until the process stops.
        self.fault_proxies()
        self.configure_api_proxy()
        candidate = self.plan("tenant-a", self.plans["tenant-a"]["sequence"]+1, "Fleet after checkpoint restart")
        extra = installed.object_value("HankoApplication", "checkpoint-app", {"realmRef": "managed", "clientID": "checkpoint-app", "type": "spa"},
                                       labels={"hanko.sh/tenant": "tenant-a"})
        candidate["content"]["apps"].append(extra)
        path = "/apis/hanko.sh/v1alpha1/namespaces/auth/hankotenants/tenant-a/status"
        self.control("api", {"method": "PATCH", "path": path, "action": "lost-ack"}, reset=True)
        self.hub("tenant-a", envelope=self.sign(candidate), status=200)
        self.tick("tenant-a")
        self.await_fault("api")
        checkpoint = self.get("hankotenant", "tenant-a")["status"]["fleetPlan"]
        self.record("verified_checkpoint_before_child_write", checkpoint["identity"] == self.identity(candidate)
                    and checkpoint.get("appliedIdentity") != checkpoint["identity"] and not self.exists("hankoapplication", "checkpoint-app"))
        self.restart()
        self.publish("tenant-a", candidate)
        self.converged("tenant-a", "Fleet after checkpoint restart")
        wait("recovered checkpoint child", lambda: self.ready("hankoapplication", "checkpoint-app"), 120)
        self.record("checkpoint_restart_recovers_without_force_or_duplicate", len(self.api("GET", "/admin/realms/managed/clients?clientId=checkpoint-app")) == 1)

    def expiry(self):
        plan = self.plan("tenant-a", self.plans["tenant-a"]["sequence"]+1, "Fleet expiring", seconds=30)
        self.publish("tenant-a", plan)
        self.converged("tenant-a", "Fleet expiring")
        wait("signed expiry refusal", lambda: self.condition("tenant-a", "FleetPlanExpired"), 90)
        self.api("PUT", "/admin/realms/managed", {"displayName": "Preserve expired drift"})
        self.control("keycloak", None, reset=True)
        self.patch("hankorealm", "managed", {"spec": {"displayName": "Forbidden expired write"}})
        time.sleep(3)
        self.record("expired_plan_no_native_mutation", self.api("GET", "/admin/realms/managed")["displayName"] == "Preserve expired drift"
                    and self.control("keycloak", None)["attempted_counts"].get("PUT /admin/realms/managed", 0) == 0)
        self.restart()
        self.expect("tenant-a", "FleetPlanExpired")
        self.record("expired_identity_survives_restart", self.api("GET", "/admin/realms/managed")["displayName"] == "Preserve expired drift")

    def leak_scan(self):
        self.stop_log_capture()
        self.record("operator_logs_no_private_inputs", not self.operator_log_failed and self.operator_log_bytes > 0)
        for namespace in ("auth", "other"):
            text = self.kubectl("get", "events,configmaps,pods", "-n", namespace, "-o", "json")
            for crd in json.loads(self.kubectl("get", "crds", "-o", "json"))["items"]:
                if crd["spec"]["group"] == "hanko.sh":
                    text += self.kubectl("get", crd["metadata"]["name"], "-n", namespace, "-o", "json")
            # Decode signed envelopes too: base64 is not a leakage boundary.
            for cm in json.loads(self.kubectl("get", "configmaps", "-n", namespace, "-o", "json"))["items"]:
                raw = cm.get("data", {}).get("envelope.json")
                if raw:
                    payload = json.loads(raw)["payload"]
                    text += base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
            native.safe_report({"surface": text}, self.sensitive)
        hub = self.hub()
        self.record("hub_payloads_public_and_no_decommission_confirmation", all(t["reports_safe"] and t["reports"] > 0 and t["confirmations"] == 0 for t in hub.values()))
        self.report["hub_payloads_inspected"] = sum(t["reports"] for t in hub.values())
        self.record("no_managed_credential_secret", all(not self.exists("secret", "hanko-app-" + name + "-app") for name in self.hub_token))
        native.safe_report(self.public_evidence(), self.sensitive)
        self.record("no_private_artifact_inputs")

    def public_evidence(self):
        keys = ("schema_version", "layer", "keycloak_version", "kubernetes_version", "publishable", "complete", "started_at", "completed_at",
                "fixture_sha256", "node_image", "node_build", "keycloak_image", "revision", "image_digest", "checks", "hub_payloads_inspected")
        return {k: self.report[k] for k in keys if k in self.report}

    def qualify(self):
        self.create_cluster()
        self.mirror_scanned_image()
        self.keycloak()
        self.record("exact_kubernetes_and_keycloak", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.provider_url = "https://keycloak.auth.svc:8443"
        self.identities()
        self.signing_keys()
        self.start_hub()
        self.install_values = {"fleetPlanVerification": {"trustConfigMap": "fleet-trust"},
            "hub": {"enabled": True, "caSecret": "hub-ca", "selector": {"app": "hanko-hub"}}}
        self.install()
        self.start_log_capture()
        self.setup_tenants()
        for name in self.hub_token:
            self.publish(name, self.plan(name, 1))
            self.converged(name, "Fleet baseline")
        self.record("two_dedicated_tenants_real_provider_converged")
        self.missing_registration()
        self.negatives()
        self.cache_clock_cases()
        self.rollout_reconnect()
        self.offline()
        self.checkpoint_restart()
        self.boundaries()
        self.expiry()
        self.leak_scan()
        self.report["complete"] = True
        self.report["completed_at"] = datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    parser.add_argument("--node-archive", type=Path)
    args = parser.parse_args()
    args.deep_migration = False
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    with tempfile.TemporaryDirectory(prefix="hankoshell-installed-fleet-private-") as directory:
        fixture = Fleet(args, Path(directory))
        try:
            fixture.qualify()
        except Exception as error:
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

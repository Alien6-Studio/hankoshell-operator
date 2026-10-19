"""Installed five-minute API transport outage and owned-realm cleanup recovery.

The operator alone uses the external API fault proxy. The administrator observes
the real API and HTTPS provider independently. No production failure switches,
host clock changes, manual finalizer removal or status resets are used.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_scale", ROOT / "scripts/scale-installed-test.py")
scale = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scale)
wait, native, system = scale.wait, scale.native, scale.system
OUTAGE_SECONDS = 300


class Recovery(scale.Scale):
    def __init__(self, args, private):
        super().__init__(args, private)
        self.report.update(layer="installed-recovery", profile="recovery",
            fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            scale_fixture_sha256=hashlib.sha256((ROOT / "scripts/scale-installed-test.py").read_bytes()).hexdigest())
        self.report["limitations"] = ["single disposable kind node and dev-file provider",
            "five-minute loss of operator API transport; administrator API remains available",
            "owned realm cleanup waits for explicit child deletion; no automatic cascading mutation",
            "realm delete acknowledgement checkpoint only; other journals, split brain and clock skew remain unqualified",
            "not production HA, full six-cell qualification or a 24-hour soak"]

    @staticmethod
    def writes(state):
        return {route: count for route, count in state["counts"].items()
                if not route.endswith("/protocol/openid-connect/token")}

    def api_outage(self):
        before = self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")
        identities = self.snapshot_clients()
        armed = self.control("api", {"method": "GET", "path": "/api", "path_prefix": True,
            "action": "http-status", "status": 503, "retry_after": 2})
        self.patch("hankorole", "scale-role-000000", {"spec": {"description": "after-api-outage"}})
        self.await_fault("api")
        started = previous = time.monotonic()
        self.report["active_phase"] = "api_outage"
        evidence = {"required_seconds": OUTAGE_SECONDS, "observed_seconds": 0, "samples": 0,
                    "max_sample_gap_seconds": 0, "complete": False}
        self.report["outage"] = evidence
        self.scraper.close()
        # Drain calls already in flight when the fault was triggered. This
        # interval remains part of the independently observed outage duration.
        time.sleep(10)
        baseline = self.writes(self.control("keycloak", None))
        lease = self.get("lease", "hanko-operator.hanko.sh")["spec"]
        while time.monotonic() - started < OUTAGE_SECONDS:
            now = time.monotonic()
            gap = scale.measure.sampling_gap(previous, now)
            evidence["max_sample_gap_seconds"] = round(max(evidence["max_sample_gap_seconds"], gap), 3)
            previous = now
            current = self.get("hankorole", "scale-role-000000")
            if current.get("status", {}).get("observedGeneration") == current["metadata"]["generation"] and current.get("status", {}).get("phase") == "Ready":
                raise ValueError("API outage allowed current-generation Ready")
            if self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")["description"] != before["description"]:
                raise ValueError("API outage allowed provider mutation without fresh authority")
            if self.writes(self.control("keycloak", None)) != baseline:
                raise ValueError("Provider configuration writes continued after outage drain")
            if self.get("lease", "hanko-operator.hanko.sh")["spec"].get("renewTime") != lease.get("renewTime"):
                raise ValueError("Operator API outage did not block lease renewal")
            evidence.update(observed_seconds=round(time.monotonic() - started, 3), samples=evidence["samples"] + 1)
            self.persist_progress()
            scale.checkout(self.args.revision)
            time.sleep(max(0, min(10, OUTAGE_SECONDS - (time.monotonic() - started))))
        elapsed = time.monotonic() - started
        gap = scale.measure.sampling_gap(previous, started + elapsed)
        evidence["max_sample_gap_seconds"] = round(max(evidence["max_sample_gap_seconds"], gap), 3)
        state = self.control("api", None)
        evidence.update(observed_seconds=round(elapsed, 3), complete=True,
            refused_requests=state["traffic"].get("refused_requests", 0) - armed["traffic"].get("refused_requests", 0))
        self.record("five_minute_api_transport_outage_refuses_fresh_authority_and_lease_renewal", elapsed >= OUTAGE_SECONDS and evidence["refused_requests"] > 0)
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.await_leader()
        self.await_converged(phase="api_outage_recovery")
        self.record("api_outage_recovers_without_manual_restart_or_status_reset",
            self.api("GET", "/admin/realms/scale-000/roles/scale-role-000000")["description"] == "after-api-outage"
            and self.snapshot_clients() == identities)

    def exists(self, kind, name):
        return bool(self.kubectl("get", kind, name, "-n", "auth", "--ignore-not-found", "-o", "name"))

    def delete_children(self, objects):
        if not objects:
            return
        kind = objects[0]["kind"]
        names = [obj["metadata"]["name"] for obj in objects]
        self.kubectl("delete", scale.RESOURCE[kind], *names, "-n", "auth", "--wait=false")
        wait("explicit realm child cleanup", lambda: not any(self.exists(scale.RESOURCE[kind], name) for name in names), self.args.converge_timeout)

    def owned_deletion(self):
        target = "scale-001"
        cohort = [obj for obj in self.objects if obj["spec"].get("realmRef") == target]
        applications = [obj for obj in cohort if obj["kind"] == "HankoApplication"]
        self.record("owned_realm_fixture_has_at_least_200_application_dependents", len(applications) >= 200)
        survivor_ids = {name: identity for name, identity in self.snapshot_clients().items()
                        if int(name.rsplit("-", 1)[1]) % 2 == 0}
        self.report["active_phase"] = "owned_realm_deletion"
        evidence = {"dependents": len(cohort), "applications": len(applications), "complete": False}
        self.report["owned_deletion"] = evidence
        self.kubectl("delete", "hankorealm", target, "-n", "auth", "--wait=false")
        def blocked():
            current = self.get("hankorealm", target)
            return current.get("metadata", {}).get("deletionTimestamp") and any(
                c.get("type") == "Synced" and c.get("status") == "False" and c.get("reason") == "DependenciesRemain"
                for c in current.get("status", {}).get("conditions", []))
        wait("owned realm waits for dependents", blocked, 90)
        self.api("GET", "/admin/realms/" + target)
        self.delete_children([obj for obj in cohort if obj["kind"] == "HankoResourceServer"])
        self.delete_children(applications)
        self.api("GET", "/admin/realms/" + target)
        self.record("realm_survives_application_cleanup_while_roles_and_organizations_remain", blocked())
        organizations = [obj for obj in cohort if obj["kind"] == "HankoOrganization"]
        self.delete_children([obj for obj in organizations if obj["spec"].get("parentRef")])
        self.delete_children([obj for obj in organizations if not obj["spec"].get("parentRef")])
        self.api("GET", "/admin/realms/" + target)
        self.record("realm_survives_until_last_role_dependency_is_removed", blocked())
        path = "/admin/realms/" + target
        self.control("keycloak", {"method": "DELETE", "path": path, "action": "lost-ack"}, reset=True)
        self.delete_children([obj for obj in cohort if obj["kind"] == "HankoRole"])
        self.await_fault("keycloak")
        self.api("GET", path, expected=(404,))
        self.record("accepted_realm_delete_retains_finalizer_when_acknowledgement_is_lost",
                    "hanko.sh/realm-cleanup" in self.get("hankorealm", target)["metadata"].get("finalizers", []))
        old = self.get("lease", "hanko-operator.hanko.sh")["spec"]["holderIdentity"]
        self.kubectl("delete", "pod", old.rsplit("_", 1)[0], "-n", "auth", "--wait=false")
        self.scraper.close()
        self.control("keycloak", None)
        wait("realm cleanup leader replacement", lambda: self.get("lease", "hanko-operator.hanko.sh")["spec"].get("holderIdentity") not in (None, "", old), 120)
        self.kubectl("rollout", "status", "deployment/system-operator", "-n", "auth", "--timeout=180s")
        self.await_leader()
        wait("realm finalizer resumes after accepted DELETE", lambda: not self.exists("hankorealm", target), 180)
        state = self.control("keycloak", None)
        accepted = state["counts"].get("DELETE " + path, 0)
        self.record("realm_delete_commits_once_across_lost_ack_and_leader_replacement", accepted == 1)
        # Read survivor identities directly: the deleted realm is intentionally
        # absent, so the ordinary full-load inventory no longer applies.
        clients, first = {}, 0
        while True:
            page = self.api("GET", f"/admin/realms/scale-000/clients?first={first}&max=100")
            clients.update({obj["clientId"]: obj["id"] for obj in page if obj.get("clientId", "").startswith("scale-app-")})
            if len(page) < 100:
                break
            first += 100
            if first > self.counts["applications"] + 100:
                raise ValueError("Surviving realm inventory exceeds its bound")
        self.record("other_realm_client_identities_survive_owned_cleanup", clients == survivor_ids)
        evidence.update(complete=True, accepted_realm_deletes=accepted, leader_replaced=True,
            surviving_applications=len(clients))

    def qualify(self):
        self.started = time.monotonic()
        self.create_cluster()
        self.mirror_scanned_image()
        self.keycloak()
        self.provider_url = "https://keycloak.auth.svc:8443"
        self.record("exact_keycloak_version", self.api("GET", "/admin/serverinfo")["systemInfo"]["version"] == self.args.keycloak_version)
        self.provision()
        self.fault_proxies()
        self.scraper = scale.Metrics(self)
        self.install()
        self.configure_api_proxy()
        self.await_leader()
        self.create_load()
        self.api_outage()
        self.owned_deletion()
        self.report.update(complete=True, completed_at=datetime.now(timezone.utc).isoformat())

    def public_evidence(self):
        return {**super().public_evidence(), **{key: self.report[key] for key in
            ("scale_fixture_sha256", "outage", "owned_deletion") if key in self.report}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keycloak-version", choices=native.KEYCLOAK_IMAGES, required=True)
    parser.add_argument("--kubernetes-version", choices=system.PINS["kubernetes"]["versions"], required=True)
    args = parser.parse_args()
    args.profile, args.workers, args.seconds, args.converge_timeout = "smoke", 4, 90, 900
    args.realms, args.applications, args.roles, args.organizations, args.grants = 2, 400, 20, 20, 4
    args.deep_migration, args.node_archive = False, None
    scale.checkout(args.revision)
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="hankoshell-recovery-private-") as directory:
        fixture, error = Recovery(args, Path(directory)), None
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        try:
            fixture.qualify()
            scale.checkout(args.revision)
        except BaseException as caught:
            error = caught
            fixture.report.update(complete=False, failure_type=type(caught).__name__)
            if isinstance(caught, Exception):
                system.diagnostics.capture(fixture, caught)
        finally:
            try:
                fixture.cleanup()
                fixture.report["cleanup_complete"] = True
            except Exception:
                fixture.report.update(complete=False, cleanup_complete=False)
                error = error or RuntimeError("Disposable recovery cleanup failed")
            (args.output / "report.json").write_text(native.safe_report(fixture.public_evidence(), fixture.sensitive))
        if error:
            raise error


if __name__ == "__main__":
    main()

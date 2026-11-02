"""Upgrade the pinned public operator, then qualify native M2M API access."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time
from urllib.request import urlopen

from tools.qualification.scenarios import system_test as system, cross_version_installed_test as historical
from tools.qualification.scenarios import service_account_scopes_installed as scopes

ROOT = Path(__file__).resolve().parents[3]


def retained(fixture, name):
    client = fixture.client("managed", name)
    secret = fixture.get("secret", "hanko-sa-" + name)
    base = "/admin/realms/managed/clients/" + client["id"]
    return {"client": client["id"], "secret_uid": secret["metadata"]["uid"], "credential": secret["data"]["client_secret"],
            "defaults": sorted(fixture.api("GET", base + "/default-client-scopes"), key=lambda s: s["id"]),
            "optional": sorted(fixture.api("GET", base + "/optional-client-scopes"), key=lambda s: s["id"])}


def qualify(args, predecessor):
    candidate = args.digest
    old_digest = predecessor["image"].split("@", 1)[1]
    with tempfile.TemporaryDirectory(prefix="hanko-m2m-scopes-private-") as directory:
        fixture = historical.HistoricalSystem(args, Path(directory))
        try:
            fixture.create_cluster()
            system.run([args.oras, "cp", predecessor["image"], "--to-plain-http", fixture.registry + "/hankoshell-operator:predecessor"])
            if system.publication.publish.Registry(args.oras, args.helm, plain_http=True).resolve(fixture.registry + "/hankoshell-operator:predecessor") != old_digest:
                raise ValueError("Public predecessor image digest changed")
            fixture.keycloak()
            chart = fixture.private / ("hankoshell-operator-" + predecessor["version"] + ".tgz")
            with urlopen(predecessor["chart"], timeout=60) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if hashlib.sha256(data).hexdigest() != predecessor["chart_sha256"]:
                raise ValueError("Public predecessor chart differs from the reviewed release")
            chart.write_bytes(data)
            fixture.chart_path, args.digest = chart, old_digest
            fixture.install()
            fixture.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoRealm", "metadata": {"name": "managed", "namespace": "auth"},
                                    "spec": {"displayName": "M2M upgrade qualification"}})
            system.wait("public predecessor realm", lambda: fixture.ready("hankorealm", "managed"))
            fixture.token = fixture.access_token({"client_id": "admin-cli", "grant_type": "password", "username": "fixture-admin", "password": fixture.password})
            fixture.token_at = time.monotonic()
            for name in (scopes.READ, scopes.WRITE):
                fixture.api("POST", "/admin/realms/managed/client-scopes", {"name": name, "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"}})
            for name in ("scope-reader", "scope-unmanaged"):
                spec = {"realmRef": "managed", "clientID": name, "tokenClaims": [{"name": "artifact-audience", "claim": "aud", "value": scopes.AUDIENCE,
                        "addToAccessToken": True, "addToIDToken": False, "addToUserInfo": False, "addToIntrospection": True}]}
                if name == "scope-reader":
                    spec["scopes"] = ["basic", "service_account", scopes.READ]
                fixture.apply_approved({"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": {"name": name, "namespace": "auth"}, "spec": spec})
                system.wait("public predecessor service account", lambda name=name: fixture.ready("hankoserviceaccount", name))
            before = {name: retained(fixture, name) for name in ("scope-reader", "scope-unmanaged")}
            reconciled = {name: fixture.get("hankoserviceaccount", name).get("status", {}).get("lastReconciled") for name in before}
            if scopes.READ in {s["name"] for s in before["scope-reader"]["defaults"]}:
                raise ValueError("Predecessor did not reproduce the missing scope behavior")
            values = json.loads(system.run([args.helm, "get", "values", "system", "-n", "auth", "--kubeconfig", fixture.config, "-o", "json"]))
            args.digest, fixture.chart_path = candidate, ROOT / "charts/hankoshell-operator"
            historical.transition(fixture, fixture.chart_path, candidate, [("auth", "system-operator", "system", values)])
            for name in before:
                system.wait("fresh upgraded service account reconciliation", lambda name=name: fixture.ready("hankoserviceaccount", name) and
                            fixture.get("hankoserviceaccount", name).get("status", {}).get("lastReconciled") not in (None, reconciled[name]))
                current = retained(fixture, name)
                for field in ("client", "secret_uid", "credential"):
                    if current[field] != before[name][field]:
                        raise ValueError("M2M upgrade replaced native identity or rotated a credential")
                if name == "scope-unmanaged" and current != before[name]:
                    raise ValueError("M2M upgrade changed omitted-scope attachments")
            if scopes.READ not in {s["name"] for s in retained(fixture, "scope-reader")["defaults"]}:
                raise ValueError("Upgrade did not apply the existing scope declaration")
            print("Installed OAuth scopes: public 1.2.0 upgrade applies existing declarations and preserves omitted scopes, UUIDs and credentials passed", flush=True)
            report = scopes.qualify(fixture, system.run, system.wait)
            private_values = []
            for values in before.values():
                private_values.extend((values["credential"], base64.b64decode(values["credential"]).decode()))
            public = fixture.kubectl("logs", "deployment/system-operator", "-n", "auth") + fixture.kubectl("get", "events", "-n", "auth", "-o", "json")
            if system.contains_jwt(public) or any(value in public for value in fixture.sensitive + private_values):
                raise ValueError("M2M credential detected in fixture logs or events; withheld")
            report.update({"version": system.VERSION, "revision": args.revision, "image_digest": candidate, "predecessor": predecessor,
                           "keycloak": system.KEYCLOAK_VERSION, "kubernetes": system.KUBERNETES_VERSION,
                           "upgrade_preserves_identity_credentials_and_unmanaged_scopes": True, "no_credentials_in_logs_events": True})
            return report
        finally:
            args.digest = candidate
            fixture.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--all-keycloak-versions", action="store_true")
    args = parser.parse_args()
    args.kubernetes_version = system.KUBERNETES_VERSION
    system.publication.publish.contract.security.verify(args.evidence, args.revision, system.VERSION, args.digest, args.archive)
    predecessor = json.loads((ROOT / "tools/qualification/config/m2m-public-predecessor.json").read_text())
    reports = []
    for version in system.PINS["keycloak"]["versions"] if args.all_keycloak_versions else [system.KEYCLOAK_VERSION]:
        system.KEYCLOAK_VERSION, system.KEYCLOAK = version, system.PINS["keycloak"]["images"][version]
        reports.append(qualify(args, predecessor))
    args.output.write_text(json.dumps({"result": "pass", "cells": reports}, indent=2) + "\n")


if __name__ == "__main__":
    main()

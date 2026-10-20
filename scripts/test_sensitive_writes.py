import json
from pathlib import Path
import unittest

from sensitive_writes import credential_name, declared_targets


class SensitiveWriteIntentTests(unittest.TestCase):
    def test_go_and_administrator_fixture_use_the_same_reviewed_names(self):
        cases = json.loads((Path(__file__).resolve().parents[1] / "internal/credentialname/testdata/names.json").read_text())
        for case in cases:
            self.assertEqual(credential_name("hanko-app-", case["clientID"]), case["application"])
            self.assertEqual(credential_name("hanko-sa-", case["clientID"]), case["serviceAccount"])

    def test_declarations_do_not_grant_input_secrets_forged_status_or_foreign_namespaces(self):
        app = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoApplication", "metadata": {"name": "app", "namespace": "auth"},
            "spec": {"clientID": "urn:example:client", "clientSecretProjections": [{"namespace": "other", "name": "foreign"}]},
            "status": {"clientSecret": {"secretRef": {"name": "privileged-input"}}}}
        names = declared_targets([app, {"apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": "auth", "name": "admin-input"}}])
        self.assertEqual(names["secrets"], {credential_name("hanko-app-", "urn:example:client")})
        app["spec"]["mode"] = "Observe"
        self.assertFalse(any(declared_targets([app]).values()))
        del app["spec"]["mode"]
        app["metadata"]["labels"] = {"hanko.sh/imported-by": "inventory"}
        self.assertFalse(any(declared_targets([app]).values()))

    def test_managed_instances_clones_and_rotation_require_declared_exact_targets(self):
        def obj(kind, spec):
            return {"apiVersion": "hanko.sh/v1alpha1", "kind": kind, "metadata": {"name": "managed", "namespace": "auth"}, "spec": spec}
        names = declared_targets([
            obj("HankoKeycloakInstance", {"mode": "managed", "adminRef": {"name": "read-only-input"}}),
            obj("HankoKeycloakInstance", {"rotateAdminCredentials": True, "adminRef": {"name": "rotate-approved"}}),
            obj("HankoOperation", {"type": "Clone", "clone": {"targetName": "approved-clone"}}),
            obj("HankoOperation", {"type": "Clone", "clone": {"targetName": "foreign-clone", "targetNamespace": "other"}}),
            obj("HankoTenant", {"hubTokenSecretRef": {"name": "approved-hub-token"}}),
        ])
        self.assertEqual(names, {"deployments": {"managed", "approved-clone"}, "secrets": {"rotate-approved", "approved-hub-token"}})

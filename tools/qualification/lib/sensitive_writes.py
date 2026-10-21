"""Exact targets approved by the disposable fixture administrator, never runtime.

This helper does not apply grants or grant authority to a CR author. The installed
fixture's independent administrator reviews its own requested corpus before
submitting it; the operator identity cannot change its Role or admission policy.
"""
import hashlib
import re

NAME = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*")


def exact_name(value):
    return isinstance(value, str) and len(value) <= 253 and NAME.fullmatch(value) is not None


def credential_name(prefix, client_id):
    value = prefix + client_id
    return value if exact_name(value) else prefix[:-1] + "." + hashlib.sha256(client_id.encode()).hexdigest()


def declared_targets(objects, namespace="auth"):
    result = {"secrets": set(), "deployments": set()}

    def approve(kind, name, target_namespace=namespace):
        if target_namespace == namespace and exact_name(name):
            result[kind].add(name)

    for obj in objects:
        if obj.get("apiVersion", "").split("/")[0] != "hanko.sh":
            continue
        metadata, spec = obj.get("metadata") or {}, obj.get("spec") or {}
        if metadata.get("namespace", "default") != namespace:
            continue
        if spec.get("mode") == "Observe" or "hanko.sh/imported-by" in (metadata.get("labels") or {}):
            continue
        kind, client_id = obj.get("kind"), spec.get("clientID")
        if isinstance(client_id, str) and client_id:
            if kind == "HankoApplication" and spec.get("type") != "spa":
                approve("secrets", credential_name("hanko-app-", client_id))
            if kind == "HankoServiceAccount" and (spec.get("authentication") or {}).get("mode", "Secret") == "Secret":
                approve("secrets", credential_name("hanko-sa-", client_id))
        if kind == "HankoApplication":
            for target in (spec.get("clientSecretProjections") or []):
                approve("secrets", target.get("name"), target.get("namespace"))
            for target in (spec.get("runtimeBindings") or []):
                approve("secrets", (target.get("credentials") or {}).get("secretRef"), (target.get("workload") or {}).get("namespace"))
        if kind == "HankoKeycloakInstance":
            if spec.get("mode") == "managed":
                approve("deployments", metadata.get("name"))
            if spec.get("rotateAdminCredentials") is True:
                approve("secrets", (spec.get("adminRef") or {}).get("name"))
        if kind == "HankoTenant":
            approve("secrets", (spec.get("hubTokenSecretRef") or {}).get("name"))
        if kind == "HankoOperation" and spec.get("type") == "Clone":
            clone = spec.get("clone") or {}
            approve("deployments", clone.get("targetName"), clone.get("targetNamespace", namespace))
    return result

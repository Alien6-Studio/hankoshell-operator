"""Freeze CRD validation bounds and rendered RBAC for explicit security review.

Missing explicit bounds are inventory gaps, not automatically vulnerabilities.
This gate detects drift; it does not certify the stable contract or accept risk.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/security-surface.json"
LIMITS = ("minLength", "maxLength", "pattern", "format", "enum", "minItems", "maxItems", "minProperties", "maxProperties")
PROFILES = {
    "standard": {},
    "without-lifecycle": {"lifecycle": {"enabled": False}},
    "cilium": {"networkPolicy": {"cilium": {"enabled": True}}},
    "connected-with-grants": {
        "profile": "enterprise", "image": {"digest": "sha256:" + "0" * 64},
        "keycloak": {"enabled": False},
        "hub": {"enabled": True, "realmRef": "review-realm", "tenantID": "review-tenant", "endpoint": "https://hub.mesh.example:9443"},
        "continuum": {"enabled": True, "hubAddress": "10.250.0.1", "hubHostname": "hub.mesh.example"},
        "meshPolicyAudit": {"enabled": True, "targetNamespace": "transport", "egressNamespaces": ["egress"]},
        "transportDecommission": {"namespace": "transport", "release": "continuum"},
        "workloadBinding": {"grants": [{"namespace": "workloads", "serviceAccounts": ["worker"], "configMaps": ["worker-identity"]}]},
    },
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def schema_nodes(schema, path):
    result = {}
    kind = schema.get("type")
    if kind in ("string", "array") or kind == "object" and isinstance(schema.get("additionalProperties"), dict):
        limits = {key: schema[key] for key in LIMITS if key in schema}
        bound = {"string": "maxLength", "array": "maxItems", "object": "maxProperties"}[kind]
        result[path] = {"type": kind, "limits": limits,
                        "missing_explicit_bound": bound not in schema and not (kind == "string" and schema.get("enum"))}
    for name, child in sorted(schema.get("properties", {}).items()):
        result.update(schema_nodes(child, path + "." + name))
    for key, suffix in (("items", "[]"), ("additionalProperties", "{}")):
        if isinstance(schema.get(key), dict):
            result.update(schema_nodes(schema[key], path + suffix))
    return result


def schemas(root=ROOT):
    result = {}
    for path in sorted((root / "charts/hankoshell-operator/crds").glob("*.yaml")):
        spec = yaml.safe_load(path.read_text())["spec"]
        for version in spec["versions"]:
            if not version["served"]:
                continue
            key = spec["names"]["kind"] + "/" + version["name"]
            if key in result:
                raise ValueError("Duplicate served security schema")
            schema = version["schema"]["openAPIV3Schema"]
            nodes = {}
            for group in ("spec", "status"):
                nodes.update(schema_nodes(schema["properties"].get(group, {}), group))
            result[key] = {"schema_sha256": digest(schema), "nodes": nodes}
    if not result:
        raise ValueError("No CRD security inventory")
    return result


def rationale(rule):
    resources, verbs, names = rule["resources"], rule["verbs"], rule["resourceNames"]
    if rule["nonResourceURLs"]:
        if set(rule["nonResourceURLs"]) - {"/.well-known/openid-configuration", "/openid/v1/jwks"} or verbs != ["get"]:
            raise ValueError("Unreviewed non-resource authority")
        return "Read current-cluster public issuer and signing keys; no token issuance or review."
    if rule["apiGroups"] == ["hanko.sh"]:
        return "CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work."
    if resources == ["leases"]:
        if names == [] and verbs == ["create"]:
            return "Create the leader lock; Kubernetes RBAC cannot name-scope CREATE. Namespace-scoped residual authority."
        if names == ["hanko-operator.hanko.sh"] and verbs == ["get", "update"]:
            return "Read and renew only the configured client-go LeaseLock; no list/watch/patch/delete."
        raise ValueError("Leader election authority exceeds the named lock")
    if resources == ["secrets"]:
        if not names and "delete" in verbs:
            return "Opt-in transport Helm bookkeeping: namespace-wide get/list/delete. Dedicated namespace prerequisite is documented, not admission-enforced."
        if set(verbs) <= {"get", "delete"}:
            return "Read referenced credentials without caching, or delete exact release bootstrap/CA Secrets at approved decommission."
        return "Dynamic canonical credential creation/rotation and projections; controller owner/UID/consent checks. These are not Kubernetes admission isolation."
    purposes = {
        "namespaces": "Read the exact kube-system UID used to bind this physical cluster.",
        "nodes": "Read Pod.nodeName-derived node identity; names are discovered dynamically; no list/watch or writes.",
        "configmaps": "Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad.",
        "services": "Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service.",
        "serviceaccounts": "Observe workload identities; decommission patches only the release-owned account. No token minting.",
        "pods": "Observe managed workload readiness and node identity; no Pod writes or exec.",
        "persistentvolumeclaims": "Observe explicitly selected managed/theme storage; no volume writes.",
        "jobs": "Run and observe approved theme/snapshot Jobs, then clean owned jobs; dynamic names require namespace scope.",
        "deployments": "Manage provider infrastructure or approved self-update; release deletion is named. Controller ownership checks are not universal admission isolation.",
        "networkpolicies": "Reconcile managed provider network boundaries; delete exact release policies during decommission.",
        "poddisruptionbudgets": "Maintain managed replica availability; remove the owned budget after scale-down.",
        "events": "Record reconciliation Events through both Kubernetes Event APIs; no list/read/delete.",
        "ciliumnetworkpolicies": "Read/delete the exact optional release Cilium policy at decommission.",
        "servicemonitors": "Read/delete the exact optional release metrics monitor at decommission.",
        "daemonsets": "Read/delete only the configured transport release DaemonSet after decommission approval.",
        "roles": "Adopt or remove exact release RBAC objects at decommission; native Kubernetes escalation protection still applies.",
        "rolebindings": "Adopt or remove exact release RBAC objects at decommission; no general role binding authority.",
        "clusterroles": "Adopt/remove exact release cluster-reader RBAC through the release anchor; no wildcard or escalation verbs.",
        "clusterrolebindings": "Adopt/remove exact release cluster-reader bindings through the release anchor.",
    }
    if any(resource not in purposes for resource in resources):
        raise ValueError("RBAC resource needs a justification: " + str(resources))
    return " ".join(dict.fromkeys(purposes[resource] for resource in resources))


def rbac(documents):
    rules, bindings = [], []
    for document in documents:
        kind = document.get("kind")
        if kind not in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            continue
        metadata = document["metadata"]
        identity = {"kind": kind, "name": metadata["name"], "namespace": metadata.get("namespace", "")}
        if kind.endswith("Binding"):
            bindings.append({**identity, "roleRef": document["roleRef"], "subjects": document.get("subjects", [])})
            continue
        for entry in document["rules"]:
            row = {**identity, **{key: sorted(entry.get(key, [])) for key in
                   ("apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs")}}
            if any("*" in item for key in ("apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs") for item in row[key]):
                raise ValueError("Wildcard RBAC is forbidden")
            if set(row["verbs"]) & {"impersonate", "bind", "escalate"} or set(row["resources"]) & {"serviceaccounts/token", "tokenreviews", "pods/exec"}:
                raise ValueError("Operator received runtime identity or escalation authority")
            if row["resourceNames"] and "create" in row["verbs"]:
                raise ValueError("resourceNames cannot constrain CREATE")
            row["justification"] = rationale(row)
            rules.append(row)
    if not rules or not bindings:
        raise ValueError("Missing rendered RBAC")
    return {"rules": sorted(rules, key=lambda row: json.dumps(row, sort_keys=True)),
            "bindings": sorted(bindings, key=lambda row: json.dumps(row, sort_keys=True))}


def inventory(root=ROOT):
    profiles = {}
    version = json.loads((root / "versions.json").read_text())["kubernetes"]["default"]
    for name, values in PROFILES.items():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as file:
            yaml.safe_dump(values, file)
            file.flush()
            output = subprocess.check_output(["helm", "template", "security-review", str(root / "charts/hankoshell-operator"),
                     "--namespace", "auth", "--api-versions", "cilium.io/v2/CiliumNetworkPolicy", "--kube-version", version, "--set-string", "image.tag=qualification", "--values", file.name],
                     text=True, timeout=45)
        profiles[name] = rbac([d for d in yaml.safe_load_all(output) if d])
    return {"schemaVersion": 1, "stage": "development-inventory-not-security-acceptance", "schemas": schemas(root), "rbac": profiles}


def summary(data):
    nodes = [node for schema in data["schemas"].values() for node in schema["nodes"].values()]
    return {"served_schemas": len(data["schemas"]), "schema_nodes": len(nodes),
            "missing_explicit_bounds": sum(bool(n["missing_explicit_bound"]) for n in nodes), "rbac_profiles": len(data["rbac"])}


def drift(before, after):
    result = []
    if set(before) != set(after) or before.get("schemaVersion") != after.get("schemaVersion") or before.get("stage") != after.get("stage"):
        result.append("inventory metadata")
    old_schemas, new_schemas = before.get("schemas", {}), after.get("schemas", {})
    for key in sorted(set(old_schemas) | set(new_schemas)):
        old, new = old_schemas.get(key, {}), new_schemas.get(key, {})
        for path in sorted(set(old.get("nodes", {})) | set(new.get("nodes", {}))):
            if old.get("nodes", {}).get(path) != new.get("nodes", {}).get(path):
                result.append(key + ":" + path)
        if old.get("schema_sha256") != new.get("schema_sha256"):
            result.append(key + ":schema")
    for profile in sorted(set(before.get("rbac", {})) | set(after.get("rbac", {}))):
        if before.get("rbac", {}).get(profile) != after.get("rbac", {}).get(profile):
            result.append("RBAC:" + profile)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "snapshot"))
    parser.add_argument("--output", type=Path, default=ROOT / ".tools/security-surface.json")
    args = parser.parse_args()
    current = inventory()
    if args.command == "snapshot":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    else:
        changed = drift(json.loads(BASELINE.read_text()), current)
        if changed:
            raise ValueError("Security surface drift: " + ", ".join(changed[:30]) + "; review a candidate snapshot and migration notice")
    print(json.dumps(summary(current), sort_keys=True))


if __name__ == "__main__":
    main()

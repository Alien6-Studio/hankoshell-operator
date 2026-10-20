#!/usr/bin/env python3
"""Export bounded anonymous condition evidence from explicitly selected Hanko objects.

Reads JSON on stdin only. No cluster/provider calls, spec, messages, names, UIDs,
annotations, journals, Events or credential objects are exported.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

MAX_BYTES = 2_097_152
MAX_OBJECTS = 1000
MAX_DEPTH = 64
KINDS = {
    "HankoRealm", "HankoIAMProfile", "HankoIssuer", "HankoApplication", "HankoRole",
    "HankoOrganization", "HankoServiceAccount", "HankoWorkloadTrust", "HankoTheme",
    "HankoTenant", "HankoKeycloakInstance", "HankoImport", "HankoOperation",
    "HankoSnapshot", "HankoResourceServer", "HankoMeshService", "HankoEmailProvider",
}
BETA_KINDS = {"HankoApplication", "HankoRole", "HankoResourceServer"}
PHASES = {"Pending", "Ready", "Error", "Reconciling", "Failed", "Blocked", "Scanning",
          "Running", "Done", "Snapshotting", "Upgrading", "Cloning", "Restoring", "Deleting"}
CONDITIONS = {"Ready", "Synced", "Authorized", "Degraded", "Progressing", "Adopted",
              "CredentialRotationReady", "Projected", "Available", "Healthy", "Connected"}
GENERATIONS = ("observedGeneration", "evaluatedGeneration", "appliedGeneration")


def require(value):
    if not value:
        raise ValueError("IncidentInputInvalid")


def decode(raw):
    require(len(raw) <= MAX_BYTES)
    # Limit nesting before the JSON decoder allocates recursive containers.
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
            require(depth <= MAX_DEPTH)
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0)

    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result)
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("IncidentInputInvalid")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def number(value):
    require(type(value) is int and 0 <= value <= 2**63 - 1)
    return value


def collect(value, contract):
    require(isinstance(value, dict))
    objects = value.get("items") if value.get("kind") == "List" else [value]
    require(isinstance(objects, list) and len(objects) <= MAX_OBJECTS)
    reasons = set(contract["iam_failure_reasons"]) | set(contract["event_reasons"]) | {
        "CleanupConflict", "RotationFailed", "SecretRotationFailed", "SecretRotationRecoveryRequired",
        "AuditRecorderUnavailable", "AdoptionRequired", "AdoptionConflict", "ApprovalRequired",
        "ReconcileFailed", "ProviderUnavailable", "PlanRejected", "Reconciled", "Succeeded",
    }
    result = []
    for index, obj in enumerate(objects, 1):
        require(isinstance(obj, dict) and isinstance(obj.get("kind"), str) and obj["kind"] in KINDS)
        kind, version = obj["kind"], obj.get("apiVersion")
        require(version == "hanko.sh/v1alpha1" or version == "hanko.sh/v1beta1" and kind in BETA_KINDS)
        metadata, status = obj.get("metadata", {}), obj.get("status", {})
        require(isinstance(metadata, dict) and isinstance(status, dict))
        generation = number(metadata.get("generation", 0))
        finalizers = metadata.get("finalizers", [])
        require(isinstance(finalizers, list) and len(finalizers) <= 128 and all(isinstance(x, str) for x in finalizers))
        phase = status.get("phase", "")
        require(isinstance(phase, str))
        entry = {"object": index, "kind": kind, "apiVersion": version, "generation": generation,
                 "deleting": bool(metadata.get("deletionTimestamp")), "finalizer_count": len(finalizers),
                 "phase": phase if phase in PHASES else "Other", "conditions": []}
        for key in GENERATIONS:
            if key in status:
                entry[key] = number(status[key])
        conditions = status.get("conditions", [])
        require(isinstance(conditions, list) and len(conditions) <= 64)
        for condition in conditions:
            require(isinstance(condition, dict) and condition.get("status") in ("True", "False", "Unknown"))
            kind_value, reason = condition.get("type"), condition.get("reason")
            require(isinstance(kind_value, str) and isinstance(reason, str))
            observed = number(condition.get("observedGeneration", 0))
            entry["conditions"].append({"type": kind_value if kind_value in CONDITIONS else "Other",
                "status": condition["status"], "reason": reason if reason in reasons else "Other",
                "observedGeneration": observed, "current": observed == generation})
        result.append(entry)
    return {"schema_version": 1, "scope": "selected objects only; not cluster inventory or native-provider proof",
            "object_count": len(result), "objects": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New private output file; existing paths are refused")
    args = parser.parse_args()
    try:
        contract = json.loads((Path(__file__).resolve().parents[2] / "tools/qualification/config/contracts/operational-contract.json").read_text())
        report = collect(decode(sys.stdin.buffer.read(MAX_BYTES + 1)), contract)
        report["collected_at"] = datetime.now(timezone.utc).isoformat()
        report["collector_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        raw = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode()
        # O_EXCL also refuses symlinks; never overwrite an incident or follow a link.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        print(json.dumps({"result": "written", "objects": report["object_count"]}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print("IncidentEvidenceRefused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

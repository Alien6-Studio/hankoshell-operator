#!/usr/bin/env python3
"""Prepare a public merge patch from a current lifecycle approval request.

Read kubectl JSON on stdin. This utility does not contact Kubernetes or approve
anything: an independent administrator reviews the spec and applies its output.
"""

import json
import re
import sys


def prepare(value):
    if value.get("apiVersion") != "hanko.sh/v1alpha1" or value.get("kind") not in ("HankoOperation", "HankoSnapshot"):
        raise ValueError("expected an experimental lifecycle object")
    metadata = value["metadata"]
    conditions = value.get("status", {}).get("conditions", [])
    requests = [c for c in conditions if c.get("type") == "Authorized" and c.get("status") == "False"
                and c.get("reason") == "ApprovalRequired" and c.get("observedGeneration") == metadata.get("generation")]
    if len(requests) != 1 or metadata.get("deletionTimestamp"):
        raise ValueError("a single current approval request is required")
    message = requests[0].get("message", "")
    prefix = "Approval required: "
    parts = message.removeprefix(prefix).split("|")
    if (not message.startswith(prefix) or len(parts) != 5 or parts[0] != "v1"
            or not metadata.get("uid") or parts[1] != metadata["uid"]
            or not isinstance(metadata.get("generation"), int) or metadata["generation"] < 1
            or parts[2] != str(metadata["generation"]) or not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", parts[3])
            or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", parts[4])):
        raise ValueError("approval request is malformed or stale")
    return {"metadata": {"annotations": {"hanko.sh/lifecycle-approval": "|".join(parts)}}}


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise SystemExit("lifecycle input exceeds the byte budget")
    try:
        print(json.dumps(prepare(json.loads(raw))))
    except (ValueError, KeyError, TypeError):
        raise SystemExit("current lifecycle approval request is required") from None

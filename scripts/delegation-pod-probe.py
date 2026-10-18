"""Disposable in-Pod delegation client; private tokens return only to driver memory."""

import base64
import json
from pathlib import Path
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ACCESS = "urn:ietf:params:oauth:token-type:access_token"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def decode(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def request(url, context, fields=None, bearer=None):
    headers = {} if bearer is None else {"Authorization": "Bearer " + bearer}
    try:
        with urlopen(Request(url, data=None if fields is None else urlencode(fields, doseq=True).encode(), headers=headers), context=context, timeout=20) as response:
            status, raw = response.status, response.read(65537)
    except HTTPError as error:
        status, raw = error.code, error.read(65537)
    if len(raw) > 65536:
        raise ValueError("Oversized private fixture response")
    return status, json.loads(raw)


def execute(settings):
    context = ssl.create_default_context(cafile="/ca/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if settings["action"] == "access":
        status, body = request(settings["resource_endpoint"], context, bearer=settings["token"])
        return {"http_status": status, "allowed": body.get("allowed") is True}
    assertion = Path("/var/run/hanko/assertion.jwt").read_text().strip()
    projected = decode(assertion)
    if (projected.get("aud") != [settings["issuer"]] or projected["exp"] - projected["iat"] != 600
            or projected["sub"] != "system:serviceaccount:workload:" + settings["account"]
            or projected["kubernetes.io"]["serviceaccount"]["uid"] != settings["uid"]):
        raise ValueError("Unexpected projected workload identity")
    authentication = {"client_id": settings["client"], "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion}
    if settings["action"] == "input":
        status, body = request(settings["endpoint"], context, {**authentication, "grant_type": "client_credentials"})
        if status != 200 or not body.get("access_token"):
            raise ValueError("Workload authentication refused")
        status, body = request(settings["endpoint"], context, {"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": settings["audience"], "permission": settings["permissions"]}, body["access_token"])
    elif settings["action"] == "exchange":
        fields = {**authentication, "grant_type": GRANT, "subject_token": settings["subject"], "subject_token_type": ACCESS,
                  "actor_token": settings["actor"], "actor_token_type": ACCESS, "audience": settings["audience"]}
        for key, value in settings.get("fields", {}).items():
            if value is None:
                fields.pop(key, None)
            else:
                fields[key] = value
        status, body = request(settings["endpoint"], context, fields)
    else:
        raise ValueError("Unknown private fixture action")
    if status != 200:
        code = body.get("error")
        return {"http_status": status, "oauth_error": code if code in ("invalid_request", "invalid_client", "invalid_token", "access_denied") else "withheld"}
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise ValueError("No native token returned")
    claims = decode(token)
    depth, actor = 0, claims.get("act")
    while isinstance(actor, dict):
        depth, actor = depth + 1, actor.get("act")
        if depth > 4:
            raise ValueError("Over-limit native actor history")
    return {"http_status": status, "access_token": token, "expires_at": claims.get("exp"),
            "depth": depth, "refresh_token_absent": not body.get("refresh_token"),
            "ordinary_claims_absent": not ((claims.get("realm_access") or {}).get("roles") or claims.get("resource_access") or claims.get("scope")),
            "issuer_matches": claims.get("iss") == settings["issuer"], "checked_at": int(time.time())}


if __name__ == "__main__":
    try:
        data = sys.stdin.read(65537)
        if len(data) > 65536:
            raise ValueError("Oversized fixture input")
        print(json.dumps(execute(json.loads(data))))
    except Exception:
        # No raw OAuth body, command argument or traceback may enter Pod logs.
        print(json.dumps({"probe_failed": True}))
        sys.exit(1)

"""In-Pod HTTPS/UMA probe. Credentials live only in memory and projected volumes."""

import base64
import json
from pathlib import Path
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def decode(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def request(endpoint, fields, context, bearer=None):
    headers = {} if bearer is None else {"Authorization": "Bearer " + bearer}
    try:
        with urlopen(Request(endpoint, data=urlencode(fields).encode(), headers=headers), context=context, timeout=15) as response:
            return response.status, json.loads(response.read(65537))
    except HTTPError as error:
        return error.code, json.loads(error.read(8193))


def authenticate(assertion, settings, context):
    return request(settings["endpoint"], {"grant_type": "client_credentials", "client_id": settings["client"],
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion}, context)


def decisions(assertion, settings, context):
    status, body = authenticate(assertion, settings, context)
    if status != 200 or not body.get("access_token"):
        raise ValueError("authentication refused")
    token = body["access_token"]
    claims = decode(token)
    if claims.get("iss") != settings["issuer"] or claims.get("azp") != settings["client"] or claims.get("exp", 0) <= time.time():
        raise ValueError("access token claims differ")
    results = {"client_assertion": True, "access_token": True, "public_claims_valid": True}
    # The same still-valid bearer is independently evaluated for both objects.
    for resource, expected in (("allowed", 200), ("denied", 403)):
        status, response = request(settings["endpoint"], {"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": settings["audience"], "permission": settings["resources"][resource] + "#read",
            "response_mode": "decision"}, context, token)
        valid = (status == expected and (response.get("result") is True if expected == 200 else response.get("error") == "access_denied"))
        if not valid:
            raise ValueError("native UMA decision differs")
        results["resource_" + resource] = True
    return results


def probe(settings):
    context = ssl.create_default_context(cafile="/ca/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    path = Path("/var/run/hanko/assertion.jwt")
    first = path.read_text().strip()
    claims = decode(first)
    if (claims.get("aud") != [settings["issuer"]] or claims["exp"] - claims["iat"] != 600
            or claims["sub"] != "system:serviceaccount:" + settings["namespace"] + ":" + settings["account"]
            or claims["kubernetes.io"]["serviceaccount"]["uid"] != settings["uid"]):
        raise ValueError("projected identity differs")
    results = decisions(first, settings, context)
    results["projection_600_seconds"] = True
    if settings.get("rotation"):
        started = time.monotonic()
        deadline = claims["exp"] + 10  # Real exp, allowing native clock skew.
        rotated = False
        while time.time() <= deadline:
            rotated = rotated or path.read_text().strip() != first
            time.sleep(min(5, max(0.1, deadline - time.time())))
        old_status, body = authenticate(first, settings, context)
        if old_status not in (400, 401) or body.get("error") != "invalid_client":
            raise ValueError("expired projected assertion accepted")
        # A fresh authentication always rereads the kubelet-managed file.
        fresh = path.read_text().strip()
        if not rotated or fresh == first or decode(fresh)["exp"] <= time.time():
            raise ValueError("kubelet rotation not observed")
        decisions(fresh, settings, context)
        results.update({"rotation": True, "old_assertion_expired_refused": True, "rotated_assertion_accepted": True,
            "first_iat": claims["iat"], "first_exp": claims["exp"], "checked_at": int(time.time()),
            "elapsed_seconds": round(time.monotonic() - started, 2)})
    return results


if __name__ == "__main__":
    try:
        print(json.dumps(probe(json.loads(sys.stdin.read(16385)))))
    except Exception:
        # Never emit a traceback or raw OAuth response containing a token.
        print(json.dumps({"probe_failed": True}))
        sys.exit(1)

"""Private installed A2A/MCP client. OAuth material travels only over stdin/TLS."""
import json
import os
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def execute(settings):
    context = ssl.create_default_context(cafile="/ca/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    def request(url, fields=None, bearer=None, body=None, headers=None, method=None):
        headers = dict(headers or {})
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        data = None
        if fields is not None:
            data = urlencode(fields, doseq=True).encode()
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        started = time.monotonic()
        try:
            with urlopen(Request(url, data=data, headers=headers, method=method), context=context, timeout=45) as response:
                status, raw = response.status, response.read(65537)
        except HTTPError as error:
            status, raw = error.code, error.read(65537)
        if len(raw) > 65536:
            raise ValueError("response limit")
        return status, json.loads(raw) if raw else {}, round((time.monotonic() - started) * 1000, 3)

    if settings["action"] == "input":
        endpoint = settings["issuer"] + "/protocol/openid-connect/token"
        status, body, _ = request(endpoint, {"grant_type": "client_credentials", "client_id": settings["client"],
                                            "client_secret": settings["private_secret"]})
        if status != 200 or not body.get("access_token"):
            raise ValueError("native identity refused")
        status, body, _ = request(endpoint, {"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": settings["audience"], "permission": settings["permissions"]}, body["access_token"])
        return {"http_status": status, "access_token": body.get("access_token")}
    if settings["action"] == "exchange":
        status, body, elapsed = request(settings["issuer"] + "/protocol/openid-connect/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": settings["client"],
            "client_secret": settings["private_secret"], "actor_token": settings["actor"],
            "subject_token": settings["subject"], "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": settings["audience"]})
        return {"http_status": status, "issued": bool(body.get("access_token")), "elapsed_ms": elapsed}
    if settings["action"] != "request":
        raise ValueError("unknown action")
    status, body, elapsed = request(settings["endpoint"], bearer=settings.get("bearer"), body=settings.get("body"),
                                    headers=settings.get("headers"), method=settings.get("method"))
    return {"http_status": status, "completed": body.get("task", {}).get("status", {}).get("state") == "TASK_STATE_COMPLETED",
            "rpc_result": isinstance(body.get("result"), dict), "elapsed_ms": elapsed}


if __name__ == "__main__":
    try:
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            raise ValueError("input limit")
        settings = json.loads(raw)
        if settings.pop("fork", False):
            child = os.fork()
            if child:
                _, status = os.waitpid(child, 0)
                sys.exit(os.waitstatus_to_exitcode(status))
        print(json.dumps(execute(settings)), flush=True)
    except Exception:
        print(json.dumps({"probe_failed": True}))
        sys.exit(1)

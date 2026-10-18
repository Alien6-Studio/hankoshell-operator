"""Disposable external HTTPS fault harness; never packaged with the operator.

Forwards caller authority unchanged. It retains only request counts and boolean
fault decisions. Control is reached by the administrator's port-forward, and the
fixture's disposable namespace is not a production trust boundary.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import threading
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

LOCK = threading.Lock()
STATE = {"rule": None, "blocked": False, "triggered": False, "counts": {}, "attempted_counts": {}, "metadata_activations": {}, "upstream_status": None, "traffic": {}}


def persisted_application_create(method, path, status):
    route = urlsplit(path)
    parts = route.path.strip("/").split("/")
    dry_run = any("All" in value.split(",") for value in parse_qs(route.query).get("dryRun", []))
    return (status == 201 and method in ("POST", "PATCH") and not dry_run and len(parts) in (6, 7)
            and parts[0:2] == ["apis", "hanko.sh"] and parts[3] == "namespaces" and parts[5] == "hankoapplications")


def matches(rule, method, path, body):
    if not rule or method != rule["method"]:
        return False
    actual = path.split("?")[0]
    if not (actual.startswith(rule["path"]) if rule.get("path_prefix") else actual == rule["path"]):
        return False
    if "step" in rule:
        try:
            value = json.loads(body).get("metadata", {}).get("annotations", {}).get(
                rule.get("annotation", "hanko.sh/workload-auth-transition"), "{}")
            if json.loads(value).get("step") != rule["step"]:
                return False
        except (ValueError, TypeError, AttributeError):
            return False
    if "json_path" in rule:
        try:
            value = json.loads(body)
            for key in rule["json_path"]:
                value = value[key]
            if value != rule["equals"]:
                return False
        except (ValueError, TypeError, KeyError, IndexError):
            return False
    if "document_attribute" in rule:
        try:
            value = json.loads(json.loads(body)["attributes"][rule["document_attribute"]])
            if value.get("phase") != rule["phase"]:
                return False
        except (ValueError, TypeError, KeyError, AttributeError):
            return False
    return True


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, content_type="application/json", retry_after=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        self.wfile.write(body)

    def handle_request(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 2**20:
            self.reply(413, b"{}")
            return
        body = self.rfile.read(size)
        if self.path == "/__fixture/control":
            with LOCK:
                if self.command == "POST":
                    value = json.loads(body)
                    STATE.update({"rule": value.get("rule"), "blocked": False, "triggered": False, "upstream_status": None})
                    if value.get("reset_counts"):
                        STATE["counts"] = {}
                        STATE["attempted_counts"] = {}
                        STATE["metadata_activations"] = {}
                        STATE["traffic"] = {}
                result = json.dumps(STATE).encode()
            self.reply(200, result)
            return
        with LOCK:
            traffic = STATE.setdefault("traffic", {})
            traffic["requests"] = traffic.get("requests", 0) + 1
            if self.path.split("?")[0].endswith("/protocol/openid-connect/token"):
                traffic["token_requests"] = traffic.get("token_requests", 0) + 1
            if self.command == "GET" and self.path.split("?")[0].endswith("/client-secret"):
                traffic["credential_read_requests"] = traffic.get("credential_read_requests", 0) + 1
            rule = STATE["rule"]
            selected = matches(rule, self.command, self.path, body) and not STATE["triggered"]
            blocked = STATE["blocked"]
            if selected and rule["action"] in ("deny", "conflict", "http-status"):
                STATE["triggered"] = True
                STATE["blocked"] = True
            status_fault = rule and rule["action"] == "http-status" and (selected or blocked)
            if status_fault:
                status = rule.get("status")
                retry_after = rule.get("retry_after", 1)
                if type(status) is not int or status not in (429, 503) or type(retry_after) is not int or not 1 <= retry_after <= 30:
                    status, retry_after = 503, 1
                traffic["refused_requests"] = traffic.get("refused_requests", 0) + 1
        if status_fault:
            self.reply(status, b"{}", retry_after=retry_after)
            return
        if blocked:
            self.reply(503, b"{}")
            return
        if selected and rule["action"] in ("deny", "conflict"):
            self.reply(403 if rule["action"] == "deny" else 409, b"{}")
            return
        # Go automatically requests gzip. This relay asks upstream for identity
        # bytes and preserves the actual media type (including Kubernetes
        # protobuf); otherwise valid token/API responses become decode errors.
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length", "accept-encoding")}
        if selected and rule["action"] == "resource-version-conflict":
            value = json.loads(body)
            value.setdefault("metadata", {})["resourceVersion"] = "1"
            body = json.dumps(value).encode()
        payload = body if size else None
        request = Request(self.server.upstream + self.path, data=payload, method=self.command, headers=headers)
        if self.command in ("POST", "PUT", "PATCH", "DELETE"):
            with LOCK:
                key = self.command + " " + self.path.split("?")[0]
                attempts = STATE.setdefault("attempted_counts", {})
                attempts[key] = attempts.get(key, 0) + 1
        try:
            with urlopen(request, context=self.server.context, timeout=35) as response:
                content_type = response.headers.get("Content-Type", "application/json")
                if self.command == "GET" and "watch=true" in self.path:
                    self.send_response(response.status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    while chunk := response.read1(65536):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    self.close_connection = True
                    return
                status, response_body = response.status, response.read(8 * 2**20)
        except HTTPError as error:
            content_type = error.headers.get("Content-Type", "application/json")
            status, response_body = error.code, error.read(2**20)
        except Exception:
            self.reply(502, b"{}")
            return
        # A conflict/rejection is not an accepted write with a lost ACK. Relay
        # it normally and keep the rule armed for the successful retry. Only
        # the explicit resource-version-conflict scenario gates a rejection.
        with LOCK:
            selected = (selected and STATE["rule"] is rule and not STATE["triggered"]
                        and (200 <= status < 300 or rule["action"] == "resource-version-conflict"))
            if self.command in ("POST", "PUT", "PATCH", "DELETE") and 200 <= status < 300:
                key = self.command + " " + self.path.split("?")[0]
                STATE["counts"][key] = STATE["counts"].get(key, 0) + 1
                if persisted_application_create(self.command, self.path, status):
                    traffic = STATE.setdefault("traffic", {})
                    traffic["kubernetes_application_creates"] = traffic.get("kubernetes_application_creates", 0) + 1
                if self.command == "PATCH" and "/configmaps/" in self.path:
                    try:
                        document = json.loads(json.loads(body).get("data", {}).get("workload-identity.json", "{}"))
                        activation = document.get("authenticationActivation")
                        if document.get("schemaVersion") == "hanko.sh/workload-runtime/v1alpha1" and activation in ("ManagedSeparately", "Federated"):
                            phases = STATE.setdefault("metadata_activations", {}).setdefault(key, {})
                            phases[activation] = phases.get(activation, 0) + 1
                    except (ValueError, TypeError):
                        pass
            if selected:
                STATE.update({"triggered": True, "blocked": True, "upstream_status": status})
        if selected and rule["action"] == "lost-ack":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.reply(status, response_body, content_type)

    do_GET = handle_request
    do_POST = handle_request
    do_PUT = handle_request
    do_PATCH = handle_request
    do_DELETE = handle_request


class FixtureServer(ThreadingHTTPServer):
    # Watch connections and concurrent API readers share the listener. The
    # stdlib backlog of five can reset legitimate requests during a burst.
    request_queue_size = 128
    daemon_threads = True


def serve(port, upstream, ca):
    server = FixtureServer(("0.0.0.0", port), Proxy)
    server.upstream = upstream
    server.context = ssl.create_default_context(cafile=ca)
    front = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    front.minimum_version = ssl.TLSVersion.TLSv1_3
    front.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = front.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    config = json.loads(Path("/fixture/settings.json").read_text())
    serve(config["port"], config["upstream"], config["ca"])

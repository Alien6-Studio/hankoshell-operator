"""Disposable bounded HTTPS Hub. No signing key or production feature lives here."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import ssl
import threading

LIMIT = 2 * 1024**2
LOCK = threading.Lock()


class Hub(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value):
        body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= LIMIT:
            raise ValueError("fixture body size")
        return json.loads(self.rfile.read(size))

    def handle_request(self):
        settings = self.server.settings
        if self.path == "/__fixture/control":
            if self.headers.get("Authorization") != "Bearer " + settings["control"]:
                self.reply(403, {})
                return
            with LOCK:
                if self.command == "POST":
                    data = self.read_json()
                    tenant = self.server.tenants[data["tenant"]]
                    for key in ("envelope", "status", "ack"):
                        if key in data:
                            tenant[key] = data[key]
                    if "hold" in data:
                        previous = tenant.get("_gate")
                        if previous is not None:
                            previous.set()
                        tenant["_gate"] = threading.Event() if data["hold"] else None
                public = {name: {**{key: t[key] for key in ("fetches", "reports", "confirmations", "reports_safe")},
                                 "waiting": t.get("waiting", False)}
                          for name, t in self.server.tenants.items()}
            self.reply(200, public)
            return
        name = self.headers.get("X-Tenant-ID", "")
        if name not in settings["tokens"] or self.headers.get("Authorization") != "Bearer " + settings["tokens"][name]:
            self.reply(401, {})
            return
        if self.path == "/api/v1/bundles/latest" and self.command == "GET":
            with LOCK:
                tenant = self.server.tenants[name]
                tenant["fetches"] += 1
                status, envelope, gate = tenant["status"], tenant["envelope"], tenant.get("_gate")
                tenant["waiting"] = gate is not None
            if gate is not None:
                gate.wait(8)  # Below the operator's ten-second HTTP deadline.
            with LOCK:
                tenant["waiting"] = False
            if self.headers.get("Accept") != "application/vnd.hanko.fleet-plan+json":
                self.reply(406, {})
            else:
                self.reply(status, envelope)
            return
        with LOCK:
            tenant = self.server.tenants[name]
            if self.path == "/api/v1/operators/status" and self.command == "POST":
                data = self.read_json()
                tenant["reports"] += 1
                encoded = json.dumps(data)
                blocked = [settings["control"], *settings["tokens"].values(), settings["canary"]]
                tenant["reports_safe"] &= (not any(v in encoded for v in blocked)
                                            and not re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]+|PRIVATE KEY", encoded))
                self.reply(200, tenant["ack"])
            elif self.path == "/api/v1/operators/decommission/confirm":
                tenant["confirmations"] += 1
                self.reply(503, {})
            else:
                self.reply(404, {})

    def do_GET(self):
        try:
            self.handle_request()
        except (ValueError, KeyError, TypeError):
            self.reply(400, {})

    do_POST = do_GET


def serve(settings):
    server = ThreadingHTTPServer(("0.0.0.0", 9090), Hub)
    server.settings = settings
    server.tenants = {name: {"envelope": "{}", "status": 503, "ack": {"ok": True},
                             "fetches": 0, "reports": 0, "confirmations": 0, "reports_safe": True}
                      for name in settings["tokens"]}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(json.loads(Path("/private/settings.json").read_text()))

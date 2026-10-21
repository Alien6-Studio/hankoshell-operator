"""Qualify the opt-in adapter on a real pinned, disposable authentik server.

Private bootstrap output and ephemeral credentials never become CI artifacts.
The verified TLS test edge forwards only to a loopback-published server port.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[3]

SERVER = "ghcr.io/goauthentik/server@sha256:e7226ae116dac5aa0a5643803e735b010038f492c401e08e16b3bf1ac54c090c"
# PostgreSQL is fixture infrastructure, not a shipped operator dependency.
POSTGRES = "postgres@sha256:6f30057d31f5861b66f3545d4821f987aacf1dd920765f0acadea0c58ff975b1"


def connection_file(path, connection):
    # Public connection metadata only. Never persist bootstrap passwords/tokens.
    fixed = {"schemaVersion": 1, "provider": "authentik", "version": "2026.8.4", "endpoint": "", "realm": "portable", "tokenSecret": "provider-token"}
    identifiers = ("authorizationFlow", "invalidationFlow", "signingKey")
    if (not isinstance(connection, dict) or set(connection) != set(fixed) | set(identifiers) | {"scopeMappings"}
            or any(connection[k] != v for k, v in fixed.items()) or type(connection["schemaVersion"]) is not int
            or not isinstance(connection["scopeMappings"], list) or not 1 <= len(connection["scopeMappings"]) <= 64):
        raise ValueError("fixture connection metadata is malformed")
    try:
        values = [connection[k] for k in identifiers] + connection["scopeMappings"]
        if any(not isinstance(value, str) or str(uuid.UUID(value)) != value for value in values):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ValueError("fixture connection identifiers are malformed") from None
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(connection, stream)
    return path


def qualify(output, gotestsum):
    output.mkdir(parents=True, exist_ok=True)
    prefix = "hanko-authentik-" + secrets.token_hex(6)
    containers = [prefix + "-db", prefix + "-server"]
    env = dict(os.environ)

    def docker(*arguments, timeout=180, stdin=None, variables=None):
        result = subprocess.run(["docker", *arguments], input=stdin, env={**env, **(variables or {})},
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError("disposable authentik fixture command failed (private output withheld)")
        return result.stdout.strip()

    result = None
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        private = Path(directory)
        try:
            password = secrets.token_urlsafe(32)
            variables = {"AUTHENTIK_SECRET_KEY": secrets.token_urlsafe(48),
                         "AUTHENTIK_POSTGRESQL__HOST": containers[0],
                         "AUTHENTIK_POSTGRESQL__USER": "authentik",
                         "AUTHENTIK_POSTGRESQL__PASSWORD": password,
                         "AUTHENTIK_POSTGRESQL__NAME": "authentik",
                         "AUTHENTIK_ERROR_REPORTING__ENABLED": "false",
                         "AUTHENTIK_LOG_LEVEL": "warning"}
            db_variables = {"POSTGRES_USER": "authentik", "POSTGRES_DB": "authentik", "POSTGRES_PASSWORD": password}
            # Docker forwards named child environment variables. Values never
            # appear in argv, an env file, test artifacts or command diagnostics.
            server_options = [item for key in variables for item in ("-e", key)]
            db_options = [item for key in db_variables for item in ("-e", key)]
            docker("network", "create", prefix)
            docker("run", "-d", "--name", containers[0], "--network", prefix,
                   *db_options, POSTGRES, variables=db_variables)
            docker("run", "-d", "--name", containers[1], "--network", prefix,
                   *server_options, "-p", "127.0.0.1::9000", SERVER, "server", variables=variables)
            address = docker("port", containers[1], "9000/tcp")
            if not address.startswith("127.0.0.1:") or not address.rsplit(":", 1)[1].isdigit():
                raise ValueError("provider fixture is not loopback-bound")
            upstream = "http://" + address
            deadline = time.monotonic() + 240
            while True:
                try:
                    with urllib.request.urlopen(upstream + "/-/health/ready/", timeout=3) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("provider fixture readiness timed out")
                time.sleep(1)
            env["HANKO_FIXTURE_TOKEN"] = secrets.token_urlsafe(40)
            env["HANKO_FIXTURE_DENIED_TOKEN"] = secrets.token_urlsafe(40)
            seed = docker("exec", "-i", "-e", "HANKO_FIXTURE_TOKEN", "-e", "HANKO_FIXTURE_DENIED_TOKEN",
                          containers[1], "ak", "shell", stdin=(ROOT / "tools/qualification/fixtures/authentik_seed.py").read_text())
            configs = [line.split("=", 1)[1] for line in seed.splitlines() if line.startswith("HANKO_FIXTURE_CONFIG=")]
            if len(configs) != 1:
                raise ValueError("fixture lacks its exact typed connection")
            config = json.loads(configs[0])
            connection = connection_file(private / "connection.json", config)
            env.update(AUTHENTIK_FIXTURE_DIRECTORY=str(private), AUTHENTIK_FIXTURE_UPSTREAM=upstream,
                       AUTHENTIK_FIXTURE_CONNECTION=str(connection))
            command = [gotestsum, "--format=standard-verbose", "--junitfile", str(output / "junit.xml"),
                       "--", "-race", "-count=1", "-tags=authentik_integration", "-timeout=5m",
                       "-run", "^TestRealAuthentikPortableCorpus$", "./internal/controller"]
            result = subprocess.run(command, env=env, cwd=ROOT, check=False, timeout=360)
        finally:
            for container in reversed(containers):
                subprocess.run(["docker", "rm", "-f", "-v", container], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False, timeout=60)
            subprocess.run(["docker", "network", "rm", prefix], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=60)
    if result is None:
        raise RuntimeError("provider qualification did not execute")
    spec = importlib.util.spec_from_file_location("go_tests", ROOT / "tools/qualification/runners/go_tests.py")
    reports = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reports)
    reports.write_summary(output, "authentik-2026.8.4", result.returncode, ["TestRealAuthentikPortableCorpus"])
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gotestsum", required=True)
    arguments = parser.parse_args()
    try:
        return qualify(arguments.output.resolve(), str(Path(arguments.gotestsum).resolve()))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("Experimental provider qualification failed: " + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

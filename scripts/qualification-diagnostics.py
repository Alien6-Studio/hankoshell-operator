"""Best-effort failure artifacts for disposable qualification fixtures.

Budgets: 256 KiB read per command, 64 KiB per artifact file, 2 MiB total,
three seconds per command and 30 seconds for collection. Raw over-budget or
failed command output is withheld. No Secrets, ConfigMaps, kubeconfig, provider
responses or Pod environment are collected. Artifacts are NONPUBLISHABLE.
"""

import base64
import html
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from urllib.parse import quote

import yaml

from evidence_privacy import redact_jwts

READ_LIMIT = 256 * 1024
FILE_LIMIT = 64 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024
COLLECTION_SECONDS = 30
SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|credential|private.?key|(?:access|refresh|id|hub|actor)?[_-]?token|client.?assertion|kubeconfig)")


class DeadlineExceeded(RuntimeError):
    def __init__(self, label, seconds, elapsed):
        super().__init__(label + " deadline exceeded")
        self.label, self.seconds, self.elapsed = label, seconds, elapsed


def bounded_command(command, seconds, *, include_stderr=False):
    """Never retain a partial credential when a read or time budget is exceeded."""
    chunks, size = [], 0
    with subprocess.Popen([str(value) for value in command], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT if include_stderr else subprocess.DEVNULL,
                          stdin=subprocess.DEVNULL) as process:
        try:
            deadline = time.monotonic() + seconds
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    for key, _ in selector.select(remaining):
                        data = os.read(key.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(key.fileobj)
                            break
                        size += len(data)
                        if size > READ_LIMIT:
                            return None
                        chunks.append(data)
            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                return None
            return b"".join(chunks).decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return None
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


class Collector:
    def __init__(self, output, sensitive):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.deadline = time.monotonic() + COLLECTION_SECONDS
        self.written = 0
        self.secrets = set()
        for value in sensitive:
            if value:
                self.secrets.update((value, base64.b64encode(value.encode()).decode(),
                                     quote(value, safe=""), json.dumps(value)[1:-1]))

    def redact(self, text):
        for value in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
                      "[REDACTED PRIVATE KEY]", text, flags=re.S)
        # Consume complete components once, including hostile dot-free runs.
        text = redact_jwts(text, json_header=False)
        text = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[^\s\"',}]+", "[REDACTED AUTHORIZATION]", text)
        text = re.sub(r'''(?ix)(["']?(?:password|passwd|secret|client[_-]?secret|private[_-]?key|(?:access|refresh|id|hub|actor)[_-]?token|token|credential|client[_-]?assertion)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s,;}]+)''',
                      r'\1"[REDACTED]"', text)
        return text

    def public_object(self, value):
        if isinstance(value, dict):
            if value.get("kind") in ("Secret", "SecretList", "ConfigMap", "ConfigMapList"):
                return {"kind": "Withheld"}
            return {key: ("[REDACTED]" if SECRET_KEY.search(key) else self.public_object(item))
                    for key, item in value.items() if key not in ("annotations", "managedFields")}
        if isinstance(value, list):
            return [self.public_object(item) for item in value]
        if isinstance(value, str):
            return self.redact(value)
        return value

    def write(self, name, text):
        # Redact the complete value before applying the output budget.
        encoded = self.redact(text).encode()
        if len(encoded) > FILE_LIMIT:
            encoded = b"# Diagnostic omitted: sanitized file exceeds 64 KiB.\n"
        if self.written + len(encoded) <= TOTAL_LIMIT:
            (self.output / name).write_bytes(encoded)
            self.written += len(encoded)

    def command(self, command, *, include_stderr=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            return bounded_command(command, min(3, remaining), include_stderr=include_stderr)
        except OSError:
            return None

    def document(self, name, command):
        raw = self.command(command)
        try:
            value = self.public_object(json.loads(raw)) if raw is not None else {"unavailable": True}
        except ValueError:
            value = {"unavailable": True}
        self.write(name, yaml.safe_dump(value, sort_keys=False))
        return value

    def failure(self, error, events=None, *, summary=True):
        report = {"publishable": False, "error_type": type(error).__name__}
        if isinstance(error, DeadlineExceeded):
            report.update(wait=self.redact(error.label), elapsed_seconds=round(error.elapsed, 3), deadline_seconds=error.seconds)
        elif isinstance(error, subprocess.TimeoutExpired):
            report.update(wait="fixture command", elapsed_seconds=error.timeout, deadline_seconds=error.timeout)
        else:
            # Exception text may contain a failed command's credentials or body.
            report["wait"] = "fixture command or check"
        self.write("failure.json", json.dumps(report, indent=2) + "\n")
        warnings = [item for item in (events or {}).get("items", []) if item.get("type") == "Warning"][-5:]
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary and summary_path:
            def cell(value):
                return html.escape(self.redact(str(value))).replace("|", "&#124;").replace("\n", " ")[:512]
            lines = ["\n### Qualification failure diagnostics", "", "| Wait | Elapsed (s) | Deadline (s) |",
                     "| --- | --- | --- |", f"| {cell(report['wait'])} | {cell(report.get('elapsed_seconds', 'unknown'))} | {cell(report.get('deadline_seconds', 'unknown'))} |",
                     "", "| Warning reason | Message |", "| --- | --- |"]
            lines += [f"| {cell(item.get('reason', ''))} | {cell(item.get('message', ''))} |" for item in warnings]
            with Path(summary_path).open("a") as destination:
                destination.write("\n".join(lines) + "\n")


def capture(fixture, error):
    """Collect before fixture teardown; diagnostics must never replace failure."""
    collector, events = None, None
    try:
        collector = Collector(fixture.args.output.with_suffix(".diagnostics"), fixture.sensitive)
        collector.failure(error, summary=False)
        if not fixture.config.exists():
            return
        base = [fixture.args.kubectl, "--kubeconfig", fixture.config, "--request-timeout=3s"]
        events = collector.document("events.yaml", [*base, "get", "events", "-A", "--sort-by=.lastTimestamp", "-o", "json"])
        collector.document("nodes.yaml", [*base, "get", "nodes", "-o", "json"])
        # Pod specs can contain credentials in env/args; use only identities and
        # status for diagnostics and select logs of the fixture's known writers.
        raw = collector.command([*base, "get", "pods", "-A", "-o", "json"])
        pods = json.loads(raw).get("items", []) if raw else []
        statuses = [{"metadata": {key: pod["metadata"].get(key) for key in ("name", "namespace", "uid")},
                     "status": pod.get("status", {})} for pod in pods]
        collector.write("pods.yaml", yaml.safe_dump(collector.public_object(statuses)))
        writers = set(fixture.scanned_operators) | {("auth", "keycloak")}
        selected = [pod for pod in pods if any(pod["metadata"].get("namespace") == namespace and
                    pod["metadata"]["name"].startswith(deployment + "-") for namespace, deployment in writers)]
        for index, pod in enumerate(selected[:8]):
            metadata = pod["metadata"]
            for previous in (False, True):
                command = [*base, "logs", metadata["name"], "-n", metadata["namespace"], "--all-containers=true", "--tail=30"]
                if previous:
                    command.append("--previous")
                text = collector.command(command)
                prefix = f"pod-{index}-{'previous' if previous else 'current'}.log"
                collector.write(prefix, f"Pod: {metadata['namespace']}/{metadata['name']}\n" + (text if text is not None else "Diagnostics unavailable or exceeded budget.\n"))
        if hasattr(fixture, "external_name"):
            text = collector.command(["docker", "logs", "--tail=200", fixture.external_name], include_stderr=True)
            collector.write("external-keycloak.log", text if text is not None else "Diagnostics unavailable.\n")
        resources = collector.command([*base, "api-resources", "--api-group=hanko.sh", "--verbs=list", "--namespaced", "-o", "name"])
        for resource in sorted(set((resources or "").splitlines()))[:64]:
            if time.monotonic() >= collector.deadline:
                break
            if not re.fullmatch(r"[a-z]+\.hanko\.sh", resource):
                continue
            collector.document(resource + ".yaml", [*base, "get", resource, "-A", "-o", "json"])
    except Exception:
        # Disk, API or redaction failures cannot hide or turn the original
        # failed qualification into a pass. Never print a diagnostic exception.
        return
    finally:
        if collector is not None:
            try:
                collector.failure(error, events)
            except Exception:
                pass


def capture_registry(output, name, error):
    """The release-system fixture has a local registry, no Kubernetes cluster."""
    try:
        collector = Collector(Path(output) / "NONPUBLISHABLE-diagnostics", [])
        text = collector.command(["docker", "logs", "--tail=200", name], include_stderr=True)
        collector.write("registry.log", text if text is not None else "Registry diagnostics unavailable.\n")
        collector.failure(error)
    except Exception:
        return

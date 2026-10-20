#!/usr/bin/env python3
"""Exercise the actual recovery CLI against a disposable authenticated API server."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from tools.operations import finalizer_recovery as recovery

ROOT = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executor", type=Path, required=True)
    parser.add_argument("--approver", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hanko-release-fixture-") as directory:
        plan_path = Path(directory) / "plan.json"
        with recovery.Kubernetes(args.kubectl, args.executor) as kube:
            deadline = time.monotonic() + 15
            while True:
                try:
                    recovery.guard(kube)
                    break
                except recovery.Refused:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

        def invoke(config, phase, *options, refused=None):
            command = [sys.executable, "-m", "tools.operations.finalizer_release", "--kubectl", str(args.kubectl), "--kubeconfig", str(config), phase, *options]
            # A timeout must also remove the CLI's short-lived kubectl proxy.
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
                try:
                    stdout, stderr = process.communicate(timeout=25)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            if refused:
                if result.returncode != 1 or result.stderr.strip() != refused or result.stdout:
                    raise RuntimeError("UnexpectedRecoveryRefusal")
            elif result.returncode != 0:
                # Fixed CLI diagnostics only, never a Kubernetes body/configuration.
                raise RuntimeError("RecoveryCLIRefused:" + result.stderr.strip())
            else:
                report = json.loads(result.stdout)
                if set(report) != {"phase", "planDigest"} or report["phase"] != phase:
                    raise RuntimeError("UnexpectedRecoveryOutput")

        invoke(args.executor, "plan", "--kind", "HankoRole", "--namespace", "auth", "--name", "release-blocked",
               "--finalizer", "hanko.sh/role-cleanup", "--output", str(plan_path))
        value = recovery.decode(plan_path.read_bytes())
        if plan_path.stat().st_mode & 0o777 != 0o600 or "private-fixture-canary" in plan_path.read_text():
            raise RuntimeError("PrivatePlanBoundaryFailed")
        invoke(args.executor, "request", "--plan", str(plan_path))
        consent = "--accept-orphaned-provider-state-and-garbage-collection"
        invoke(args.executor, "approve", "--plan", str(plan_path), consent, refused="IndependentApproverRequired")
        invoke(args.approver, "approve", "--plan", str(plan_path), consent)
        invoke(args.approver, "execute", "--plan", str(plan_path), consent, refused="IndependentAdministratorRequired")
        invoke(args.executor, "execute", "--plan", str(plan_path), consent)
        invoke(args.executor, "execute", "--plan", str(plan_path), consent, refused="IntentAlreadyRecordedUseObserve")
        invoke(args.executor, "observe", "--plan", str(plan_path))
        with recovery.Kubernetes(args.kubectl, args.executor) as kube:
            obj = kube.request("GET", recovery.target_path(value))
            if obj["metadata"]["finalizers"] != ["fixture.hanko.sh/hold"]:
                raise RuntimeError("ForeignFinalizerLost")
            for phase in ("request", "approval", "intent", "receipt"):
                record = kube.request("GET", recovery.RECORDS + "/" + recovery.record_name(value, phase))
                if not record.get("immutable") or "private-fixture-canary" in recovery.canonical(record):
                    raise RuntimeError("AuditRecordBoundaryFailed")
        print(json.dumps({"result": "pass", "checks": ["actual-cli", "independent-approval", "approver-cannot-execute",
            "foreign-finalizer-preserved", "durable-immutable-audit", "no-replay", "private-plan", "secret-free-records"]}))


if __name__ == "__main__":
    main()

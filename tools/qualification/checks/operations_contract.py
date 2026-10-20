"""Freeze operational names, output boundaries, runbook links and diagnostic limits."""
import json
import ast
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def check_procedure_coverage(root, contract):
    covered, identities = set(), set()
    for entry in contract["procedure_coverage"]:
        identity, group = entry["id"], entry["runbook"]
        if identity in identities or group not in contract["runbooks"]:
            raise ValueError("Duplicate or unknown operational procedure")
        identities.add(identity)
        covered.add(group)
        path = (root / entry["document"]).resolve()
        if not path.is_relative_to((root / "docs").resolve()):
            raise ValueError("Operational procedures must be repository documentation")
        text = path.read_text()
        heading = re.search(r"^(#{1,6}) " + re.escape(entry["heading"]) + r"\s*$", text, re.M)
        if heading is None:
            raise ValueError("Operational procedure heading is missing: " + identity)
        remaining = text[heading.end():]
        end = re.search(r"^#{1," + str(len(heading[1])) + r"} ", remaining, re.M)
        section = remaining[:end.start()] if end else remaining
        commands = "\n".join(re.findall(r"```sh\n(.*?)```", section, re.S))
        if not entry["commands"] or any(command not in commands for command in entry["commands"]):
            raise ValueError("Operational procedure lacks its exact command: " + identity)
        if entry["unqualified"] and "UNQUALIFIED" not in section:
            raise ValueError("Untested operational procedure must retain its qualification limit: " + identity)
        if not entry["fixtures"] or any(not (root / fixture).is_file() or fixture not in text for fixture in entry["fixtures"]):
            raise ValueError("Operational procedure lacks its executable fixture: " + identity)
    if covered != set(contract["runbooks"]):
        raise ValueError("Operational procedures do not cover the complete runbook inventory")


def check(root=ROOT):
    contract = json.loads((root / "docs/operational-contract.json").read_text())
    if contract["maturity"] != "initial development" or contract["api_version"] != "v1alpha1":
        raise ValueError("Operational docs cannot grant stable API maturity")
    metrics = (root / "internal/observability/metrics.go").read_text()
    actual = set(re.findall(r'Name:\s*"(hanko_operator_[a-z_]+)"', metrics))
    if actual != set(contract["metrics"]):
        raise ValueError("Metric name inventory differs from runtime")
    for name, labels in contract["metrics"].items():
        pattern = re.escape(name) + r'"[^\n]+\[\]string\{([^}]+)\}'
        found = re.search(pattern, metrics)
        actual_labels = re.findall(r'"([a-z]+)"', found[1]) if found else []
        if actual_labels != labels:
            raise ValueError("Metric label inventory differs: " + name)
    events = (root / "internal/observability/events.go").read_text()
    reasons = set(re.findall(r'^\s*"([A-Za-z]+)":\s*"', events, re.M))
    if reasons != set(contract["event_reasons"]):
        raise ValueError("Event catalog differs from operational inventory")
    tenant = (root / "internal/controller/hankotenant_controller.go").read_text()
    if "observability.TenantRefusalReason(reason)" not in tenant:
        raise ValueError("Tenant Fleet refusal Events must preserve bounded decision identity")
    installed = (root / "tools/qualification/scenarios/fleet_installed_test.py").read_text()
    expected = set(re.findall(r'"((?:Fleet|Bundle)[A-Z][A-Za-z]+)"', installed))
    # Include table-driven reasons passed through a loop variable (for example
    # DecommissionExpired), rather than relying on a reason-name prefix.
    expected.update(node.value for node in ast.walk(ast.parse(installed))
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and re.fullmatch(r"[A-Z][A-Za-z0-9]*(?:Failed|Expired|Invalid|Mismatch|Blocked|Unsupported|Unapproved|Unavailable|Refused|Conflict)", node.value))
    for call in ast.walk(ast.parse(installed)):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "expect"
                and len(call.args) > 1 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str)
                and any(key.arg == "event" and isinstance(key.value, ast.Constant) and key.value.value is True for key in call.keywords)):
            expected.add(call.args[1].value)
    tenant_source = "\n".join(p.read_text() for p in (root / "internal/controller").glob("hankotenant*.go") if not p.name.endswith("_test.go"))
    expected.update(re.findall(r'\.setError\([^";]{0,400}"([A-Z][A-Za-z0-9]+)"', tenant_source))
    allowed = set(re.findall(r'^\s*"([A-Za-z]+)":\s*true,', events, re.M))
    if not expected.issubset(reasons & allowed):
        raise ValueError("Tenant decision/Event missing from bounded catalog or router: " + ", ".join(sorted(expected - (reasons & allowed))))
    main = (root / "cmd/operator/main.go").read_text()
    if main.count('mgr.GetEventRecorder(operatorRecorderName)') != main.count('observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName))'):
        raise ValueError("Unfiltered production Event recorder")
    observed = set()
    for path in (root / "internal/controller").glob("*_controller.go"):
        text = path.read_text()
        observed.update(re.findall(r'Complete\(observeReconciler\("(Hanko\w+)"', text))
        for reason in re.findall(r'\.Eventf\([^\n]*?,\s*"(\w+)",\s*"(?:Reconcile|Finalize)"', text):
            if reason not in reasons:
                raise ValueError("Unreviewed emitted Event reason: " + reason)
    if len(observed) != 17:
        raise ValueError("All 17 registered reconcilers require operational outcomes")
    for path in ("README.md", "charts/hankoshell-operator/README.md", "docs/secure-deployment.md"):
        text = (root / path).read_text()
        if not all(name in text for name in ("operations-runbooks.md", "operational-observability.md", "operational-contract.json")):
            raise ValueError("Missing operational contract link: " + path)
    runbook = (root / "docs/operations-runbooks.md").read_text()
    check_procedure_coverage(root, contract)
    iam = (root / "internal/controller/iam_evidence.go").read_text().split("func iamFailureReason(", 1)[1].split("func iamCondition(", 1)[0]
    iam_reasons = sorted(set(re.findall(r'return "([A-Za-z]+)"', iam)))
    if iam_reasons != contract.get("iam_failure_reasons"):
        raise ValueError("IAM refusal reason inventory differs from runtime")
    if any("`" + reason + "`" not in runbook for reason in iam_reasons):
        raise ValueError("Missing typed IAM refusal recovery procedure")
    for state in ("CleanupConflict", "RotationFailed", "AuditRecorderUnavailable", "FleetSignatureInvalid", "UNQUALIFIED"):
        if state not in runbook:
            raise ValueError("Missing fail-closed runbook coverage: " + state)
    incident = contract["incident_evidence"]
    source = ast.parse((root / incident["collector"]).read_text())
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in source.body
              if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id in {"MAX_BYTES", "MAX_OBJECTS", "MAX_DEPTH", "KINDS", "BETA_KINDS"}}
    if any(values[key] != incident[field] for key, field in (("MAX_BYTES", "input_bytes"), ("MAX_OBJECTS", "objects"), ("MAX_DEPTH", "depth"))):
        raise ValueError("Incident collection budget differs from the reviewed contract")
    support = json.loads((root / "docs/api-support.json").read_text())
    conversion = json.loads((root / "docs/api-conversion.json").read_text())
    if values["KINDS"] != {r["kind"] for r in support["resources"]} or values["BETA_KINDS"] != set(conversion["resources"]):
        raise ValueError("Incident collection must explicitly cover every reviewed resource/version")
    if incident["collector"] not in runbook or incident["tests"] not in runbook or not (root / incident["tests"]).is_file():
        raise ValueError("Missing executable incident evidence runbook/fixture")
    recovery = contract["finalizer_recovery"]
    profile = recovery["profile"]
    source = ast.parse((root / recovery["module"]).read_text())
    actual = {node.targets[0].id: ast.literal_eval(node.value) for node in source.body
              if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in profile}
    if json.loads(json.dumps(actual)) != profile:
        raise ValueError("Finalizer release authority or budget differs from the reviewed profile")
    detailed = (root / recovery["runbook"]).read_text()
    if Path(recovery["runbook"]).name not in runbook:
        raise ValueError("Missing administrator recovery procedure link")
    for key in ("cli", "module", "tests", "fixture", "api_fixture"):
        if not (root / recovery[key]).is_file() or recovery[key] not in detailed:
            raise ValueError("Missing executable finalizer release fixture or procedure")
    for manifest in recovery["manifests"]:
        path = root / manifest["path"]
        if not path.is_relative_to(root / "config/recovery") or hashlib.sha256(path.read_bytes()).hexdigest() != manifest["sha256"]:
            raise ValueError("Administrator recovery admission or RBAC differs from the reviewed manifest")
        if manifest["path"] not in detailed:
            raise ValueError("Missing exact administrator recovery manifest command")
    for path in re.findall(r'`((?:tools|tests|internal|api)/[^` ]+\.py|(?:internal|api)/[^` ]+\.go)`', runbook):
        if not (root / path).is_file():
            raise ValueError("Runbook references missing executable fixture: " + path)
    dashboard = json.loads((root / "docs/observability-dashboard.json").read_text())
    if len(dashboard["panels"]) < 6:
        raise ValueError("Missing operational dashboard coverage")
    for evidence in contract["installedEvidence"]:
        path = root / evidence["report"]
        if not path.resolve().is_relative_to((root / "docs/qualification/operations").resolve()):
            raise ValueError("Operational evidence must be a retained public report")
        raw = path.read_bytes()
        report = json.loads(raw)
        if hashlib.sha256(raw).hexdigest() != evidence["sha256"] or report["result"] != "pass":
            raise ValueError("Operational installed evidence is altered or failed")
        if not re.fullmatch(r"[0-9a-f]{40}", report["revision"]) or not re.fullmatch(r"sha256:[0-9a-f]{64}", report["image_digest"]):
            raise ValueError("Operational evidence lacks immutable runtime identity")
        for key, filename in (("harness_sha256", "tools/qualification/scenarios/observability_installed_test.py"), ("system_harness_sha256", "tools/qualification/scenarios/system_test.py"),
                              ("privacy_harness_sha256", "tools/qualification/lib/evidence_privacy.py")):
            if report.get(key) != hashlib.sha256((root / filename).read_bytes()).hexdigest():
                raise ValueError("Operational harness changed; retain new installed qualification")
        if "not production HA" not in report["scope"] or len(report["checks"]) < 9:
            raise ValueError("Operational smoke evidence cannot claim production HA")
    return contract


if __name__ == "__main__":
    check()

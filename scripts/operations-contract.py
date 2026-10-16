"""Freeze operational names, output boundaries, runbook links and diagnostic limits."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


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
    for state in ("CleanupConflict", "RotationFailed", "AuditRecorderUnavailable", "FleetSignatureInvalid", "UNQUALIFIED"):
        if state not in runbook:
            raise ValueError("Missing fail-closed runbook coverage: " + state)
    for path in re.findall(r'`((?:scripts|internal|api)/[^` ]+\.py|(?:internal|api)/[^` ]+\.go)`', runbook):
        if not (root / path).is_file():
            raise ValueError("Runbook references missing executable fixture: " + path)
    dashboard = json.loads((root / "docs/observability-dashboard.json").read_text())
    if len(dashboard["panels"]) < 6:
        raise ValueError("Missing operational dashboard coverage")
    return contract


if __name__ == "__main__":
    check()

#!/usr/bin/env python3
"""Qualify listener, discovery and the conjunctive metrics ingress contract."""
import copy
from pathlib import Path
import subprocess
import tempfile

import yaml

CHART = Path(__file__).resolve().parents[1]
BASE = ["helm", "template", "observability-test", str(CHART), "--namespace", "auth",
        "--kube-version", "1.37.0", "--set-string", "image.tag=fixture"]
IDENTITY = {
    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}},
    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "prometheus", "prometheus": "platform"}},
}


def render(values=None, valid=True, monitor_api=True, cilium_api=False, error=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as config:
        yaml.safe_dump(values or {}, config)
        config.flush()
        args = BASE + ["-f", config.name]
        if monitor_api:
            args += ["--api-versions", "monitoring.coreos.com/v1/ServiceMonitor"]
        if cilium_api:
            args += ["--api-versions", "cilium.io/v2/CiliumNetworkPolicy"]
        result = subprocess.run(args, text=True, capture_output=True)
    assert (result.returncode == 0) == valid, (values, result.stderr)
    if error:
        assert error in result.stderr, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc] if valid else []


def resources(docs, kind):
    return [doc for doc in docs if doc["kind"] == kind]


def deployment(docs):
    return resources(docs, "Deployment")[0]["spec"]["template"]


def operator_policies(docs):
    return [policy for policy in resources(docs, "NetworkPolicy")
            if policy["metadata"]["name"] == "observability-test-hanko-operator"]


def check_disabled(docs):
    assert not resources(docs, "Service") and not resources(docs, "ServiceMonitor")
    pod = deployment(docs)
    manager = pod["spec"]["containers"][0]
    assert "--metrics-bind-address=0" in manager["args"]
    assert not any(port["containerPort"] == 8080 or port["name"] == "metrics" for port in manager["ports"])
    assert manager["livenessProbe"]["httpGet"]["port"] == 8081
    assert manager["readinessProbe"]["httpGet"]["port"] == 8081
    assert not pod["metadata"].get("annotations")
    assert operator_policies(docs)[0]["spec"]["ingress"] == []


def check_enabled(docs, service_monitor=False):
    pod = deployment(docs)
    manager = pod["spec"]["containers"][0]
    assert "--metrics-bind-address=:8080" in manager["args"]
    assert {"name": "metrics", "containerPort": 8080, "protocol": "TCP"} in manager["ports"]
    service, = resources(docs, "Service")
    assert service["metadata"]["name"] == "observability-test-hanko-operator-metrics"
    assert service["spec"]["type"] == "ClusterIP"
    assert not service["spec"].get("externalIPs")
    assert service["spec"]["selector"] == {
        "app.kubernetes.io/name": "hanko-operator", "app.kubernetes.io/instance": "observability-test"}
    assert all(pod["metadata"]["labels"][key] == value for key, value in service["spec"]["selector"].items())
    assert service["spec"]["ports"] == [{"name": "metrics", "port": 8080, "targetPort": "metrics", "protocol": "TCP"}]
    assert bool(resources(docs, "ServiceMonitor")) == service_monitor
    annotations = pod["metadata"].get("annotations", {})
    if service_monitor:
        assert not annotations
        monitor, = resources(docs, "ServiceMonitor")
        assert monitor["spec"]["selector"]["matchLabels"] == service["spec"]["selector"]
        assert monitor["spec"]["namespaceSelector"] == {"matchNames": ["auth"]}
        assert monitor["spec"]["endpoints"] == [{"port": "metrics", "interval": "30s", "path": "/metrics", "scheme": "http"}]
    else:
        assert annotations == {"prometheus.io/scrape": "true", "prometheus.io/port": "8080", "prometheus.io/path": "/metrics"}
    for policy in operator_policies(docs):
        assert policy["spec"]["podSelector"]["matchLabels"] == service["spec"]["selector"]
        assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
        # A single peer gives namespace AND pod identity. Two peers would be OR.
        assert policy["spec"]["ingress"] == [{"from": [IDENTITY], "ports": [{"port": 8080, "protocol": "TCP"}]}]


for values in ({}, {"metrics": {"enabled": False, "networkPolicy": IDENTITY}},
               {"metrics": {"enabled": False, "serviceMonitor": {"enabled": True}}}):
    check_disabled(render(values, monitor_api=False))

enabled = {"metrics": {"enabled": True, "networkPolicy": IDENTITY}}
check_enabled(render(enabled, monitor_api=False))
monitor = copy.deepcopy(enabled)
monitor["metrics"]["serviceMonitor"] = {"enabled": True, "labels": {"release": "prometheus-stack", "on": "off"}}
docs = render(monitor)
check_enabled(docs, service_monitor=True)
assert resources(docs, "ServiceMonitor")[0]["metadata"]["labels"]["release"] == "prometheus-stack"
assert resources(docs, "ServiceMonitor")[0]["metadata"]["labels"]["on"] == "off"
render(monitor, valid=False, monitor_api=False, error="installed monitoring.coreos.com/v1/ServiceMonitor API")

for service_monitor in (False, True):
    for identity in ({}, {"namespaceSelector": IDENTITY["namespaceSelector"]}, {"podSelector": IDENTITY["podSelector"]}):
        render({"metrics": {"enabled": True, "serviceMonitor": {"enabled": service_monitor}, "networkPolicy": identity}},
               valid=False, error="requires explicit Prometheus namespaceSelector and podSelector")
    independent = copy.deepcopy(monitor if service_monitor else enabled)
    independent["networkPolicy"] = {"enabled": False}
    independent["metrics"]["networkPolicy"] = {"namespaceSelector": {}, "podSelector": {}}
    docs = render(independent)
    assert not operator_policies(docs)
    check_enabled(docs, service_monitor)

for selector in ({"matchLabels": {}}, {"matchExpressions": [{"key": "app", "operator": "Exists"}]},
                 {"matchLabels": {"app": "prometheus"}, "matchExpressions": []},
                 {"ipBlock": {"cidr": "0.0.0.0/0"}}, {"matchLabels": {"app": "*"}},
                 {"matchLabels": {"app": True}}, {"matchLabels": {"app": 1}},
                 {"matchLabels": {"bad key": "prometheus"}}, {"matchLabels": {"/app": "prometheus"}},
                 {"matchLabels": {"UPPER.example/app": "prometheus"}},
                 {"matchLabels": {"a..example/app": "prometheus"}},
                 {"matchLabels": {"app": "a" * 64}}, {"matchLabels": {"a" * 64: "prometheus"}},
                 {"matchLabels": {"a/second/app": "prometheus"}}, [], "app=prometheus", None):
    invalid = copy.deepcopy(enabled)
    invalid["metrics"]["networkPolicy"]["podSelector"] = selector
    render(invalid, valid=False)

for labels in ({"team": "monitoring"}, {"kubernetes.io/metadata.name": "*"},
               {"kubernetes.io/metadata.name": ""}, {"kubernetes.io/metadata.name": "monitoring.prod"}):
    invalid = copy.deepcopy(enabled)
    invalid["metrics"]["networkPolicy"]["namespaceSelector"] = {"matchLabels": labels}
    render(invalid, valid=False)

for values in ({"metrics": {"enabled": "false"}}, {"metrics": {"enabled": None}}, {"metrics": []},
               {"metrics": {"unknown": True}}, {"metrics": {"serviceMonitor": {"enabled": "false"}}},
               {"metrics": {"serviceMonitor": {"unknown": True}}},
               {"metrics": {"serviceMonitor": {"labels": {"app.kubernetes.io/name": "unrelated"}}}},
               {"metrics": {"networkPolicy": {"namespaceSelector": None}}},
               {"metrics": {"networkPolicy": {"from": []}}}, {"networkPolicy": {"enabled": "false"}}):
    render(values, valid=False)

# The same narrow baseline ingress remains authoritative with additive Cilium egress.
cilium = copy.deepcopy(monitor)
cilium["networkPolicy"] = {"cilium": {"enabled": True}}
docs = render(cilium, cilium_api=True)
check_enabled(docs, service_monitor=True)
assert not resources(docs, "CiliumNetworkPolicy")[0]["spec"].get("ingress")
assert operator_policies(docs)[0]["spec"]["egress"] == operator_policies(render())[0]["spec"]["egress"]

enterprise = copy.deepcopy(monitor)
enterprise.update({
    "profile": "enterprise", "image": {"digest": "sha256:" + "0" * 64},
    "hub": {"enabled": True, "tenantID": "fixture", "endpoint": "https://hub.mesh.example:9443"},
    "continuum": {"enabled": True, "hubAddress": "10.250.0.1", "hubHostname": "hub.mesh.example"},
})
check_enabled(render(enterprise), service_monitor=True)
enterprise["metrics"] = {"enabled": False}
check_disabled(render(enterprise))

print("Observability: disabled listener, explicit Service/discovery, exact Prometheus identity and TCP/8080-only ingress passed")

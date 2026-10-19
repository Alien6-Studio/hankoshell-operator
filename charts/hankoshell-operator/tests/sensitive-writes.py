"""Check named RBAC and mandatory admission across default and optional writers."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("projection", Path(__file__).with_name("organization-projection.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


for values in ({}, {"sensitiveWrites": {"secrets": ["hanko-app-app", "reviewed-projection"], "deployments": ["managed-provider"]}},
               {"hub": {"enabled": True}, "transportDecommission": {"namespace": "transport", "release": "continuum"}}):
    docs = fixture.render(values)
    rules = [r for d in docs if d["kind"] in ("Role", "ClusterRole") for r in d["rules"]]
    for rule in rules:
        if set(rule.get("resources", [])) & {"secrets", "deployments"} and set(rule["verbs"]) & {"update", "patch"}:
            assert rule.get("resourceNames"), rule
    policies = [d for d in docs if d["kind"] == "ValidatingAdmissionPolicy" and "-sensitive-" in d["metadata"]["name"]]
    assert len(policies) == 2
    for policy in policies:
        assert policy["spec"]["failurePolicy"] == "Fail"
        assert "system:serviceaccount:auth:" in policy["spec"]["matchConditions"][0]["expression"]
        binding = next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicyBinding" and d["spec"]["policyName"] == policy["metadata"]["name"])
        assert binding["spec"]["validationActions"] == ["Deny", "Audit"]
    jobs = next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicy" and "-execution-jobs-" in d["metadata"]["name"])
    assert jobs["spec"]["failurePolicy"] == "Fail"
    assert jobs["spec"]["matchConstraints"]["resourceRules"][0]["resources"] == ["jobs"]
    if not values:
        assert not any("create" in r["verbs"] and set(r.get("resources", [])) & {"secrets", "deployments"} for r in rules)
projected = fixture.render({"sensitiveWrites": {"projections": [{"namespace": "workloads", "secrets": ["reviewed-output"], "create": False}]}})
for doc in projected:
    if doc["kind"] in ("Role", "RoleBinding") and doc["metadata"].get("namespace") == "workloads":
        assert doc["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "Helm"
        assert doc["metadata"]["annotations"] == {"meta.helm.sh/release-name": "projection-test", "meta.helm.sh/release-namespace": "auth"}
for bad in (["*"], ["prefix-*"], [""], ["a", "a"], ["../other"], [1], ["A"], ["a" * 254], "name"):
    fixture.render({"sensitiveWrites": {"secrets": bad}}, valid=False)
    fixture.render({"sensitiveWrites": {"deployments": bad}}, valid=False)
for bad in ({"namespace": "other/*", "release": "continuum"}, {"namespace": "transport", "release": "continuum.*"},
            {"namespace": "transport", "release": "continuum", "secrets": ["*"]}):
    fixture.render({"hub": {"enabled": True}, "transportDecommission": bad}, valid=False)
print("Sensitive writes: exact named RBAC, mandatory fail-closed CREATE/UPDATE/DELETE admission and bounded transport cleanup passed")

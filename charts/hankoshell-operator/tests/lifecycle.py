"""Exercise the complete lifecycle opt-out and retained approval protection."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("projection", Path(__file__).with_name("organization-projection.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


for enabled in (False, True):
    docs = fixture.render({"lifecycle": {"enabled": enabled}})
    role = next(d for d in docs if d["kind"] == "Role")
    resources = {r for rule in role["rules"] for r in rule["resources"]}
    for kind in ("hankooperations", "hankosnapshots"):
        for suffix in ("", "/status", "/finalizers"):
            assert (kind + suffix in resources) == enabled
    manager = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert "--lifecycle-enabled=" + str(enabled).lower() in manager["args"]
    policy = next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicy" and "-lifecycle-" in d["metadata"]["name"])
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert len(policy["spec"]["validations"]) == 2
    assert "variables.operator" not in policy["spec"]["validations"][0]["expression"]
    assert next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicyBinding")["spec"]["validationActions"] == ["Deny", "Audit"]
for change in ({"enabled": "true"}, {"adminGroups": "admins"}, {"adminGroups": [""]},
               {"adminGroups": ["system:authenticated"]}, {"adminGroups": ["system:serviceaccounts:auth"]}):
    fixture.render({"lifecycle": change}, valid=False)
print("Lifecycle opt-in, RBAC removal and independent approval protection passed")

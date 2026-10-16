"""Check explicit provider opt-in and conjunctive optional egress."""

import copy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("projection", Path(__file__).with_name("organization-projection.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def resource(documents, kind):
    return next(document for document in documents if document["kind"] == kind)


def flag(documents):
    container = resource(documents, "Deployment")["spec"]["template"]["spec"]["containers"][0]
    return next(item["value"] for item in container["env"] if item["name"] == "HANKO_EXPERIMENTAL_AUTHENTIK_ENABLED")


base = fixture.render()
assert flag(base) == "false"
values = {"experimental": {"authentik": {"enabled": True, "connectionNames": ["experimental"], "egress": {
    "namespace": "identity", "selector": {"app": "private-authentik-edge"}, "port": 9443}}}}
documents = fixture.render(values)
assert flag(documents) == "true"
expected = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "identity"}},
                    "podSelector": {"matchLabels": {"app": "private-authentik-edge"}}}],
            "ports": [{"port": 9443, "protocol": "TCP"}]}
assert expected in resource(documents, "NetworkPolicy")["spec"]["egress"]
assert expected not in resource(base, "NetworkPolicy")["spec"]["egress"]
for change in [
    {"experimental": {"authentik": {"enabled": True}}},
    {"env": {"HANKO_EXPERIMENTAL_AUTHENTIK_ENABLED": "true"}},
    {"experimental": {"authentik": {"enabled": "true"}}},
]:
    fixture.render(change, valid=False)
for field, value in [("selector", {}), ("namespace", "*"), ("port", 0), ("port", 65536)]:
    invalid = copy.deepcopy(values)
    invalid["experimental"]["authentik"]["egress"][field] = value
    fixture.render(invalid, valid=False)
invalid = copy.deepcopy(values)
invalid["networkPolicy"] = {"enabled": False}
fixture.render(invalid, valid=False)
print("Experimental provider chart opt-in and exact egress passed")

policy = resource(documents, "ValidatingAdmissionPolicy")
assert policy["spec"]["failurePolicy"] == "Fail"
assert policy["spec"]["matchConstraints"]["resourceRules"][0]["operations"] == ["CREATE", "UPDATE", "DELETE"]
expression = policy["spec"]["validations"][0]["expression"]
assert '"auth"' in expression and '"experimental"' in expression and '"system:masters"' in expression
assert "serviceaccount" not in expression.lower()
assert resource(documents, "ValidatingAdmissionPolicyBinding")["spec"]["validationActions"] == ["Deny", "Audit"]
assert not any(item["kind"] == "ValidatingAdmissionPolicy" for item in base)

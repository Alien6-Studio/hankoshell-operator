#!/usr/bin/env bash
# Local render-only checks. No cluster access or real credentials are used.
set -euo pipefail
ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd -P)"
python3 - "$ROOT_DIR" <<'PY'
import pathlib
import subprocess
import sys
import yaml

root = pathlib.Path(sys.argv[1])
chart = root / 'charts/hankoshell-operator'

def render(*values):
    command = ['helm', 'template', 'identity-test', str(chart), '--namespace', 'auth', '--kube-version', '1.37.0',
               '--set-string', 'fullnameOverride=hanko-operator', '--set-string', 'image.tag=test']
    for value in values:
        command.extend(['--set-string', value])
    return [item for item in yaml.safe_load_all(subprocess.check_output(command, text=True)) if item]

for documents in [render(), render('hub.endpoint=https://hub.example.test', 'hub.enrollToken=fixture', 'hub.clusterName=Équipe Paris_1.prod')]:
    cluster_roles = [item for item in documents if item['kind'] == 'ClusterRole']
    identity_role = next(item for item in cluster_roles if item['metadata']['name'] == 'hanko-operator-cluster-identity-reader')
    expected_rule = {'apiGroups': [''], 'resources': ['namespaces'], 'resourceNames': ['kube-system'], 'verbs': ['get']}
    identity_rules = [rule for rule in identity_role['rules'] if 'namespaces' in rule.get('resources', [])]
    assert identity_rules == [expected_rule], 'Identity reader permissions exceeded exact Namespace GET'
    ownership_rules = [rule for rule in identity_role['rules'] if rule.get('apiGroups') == ['rbac.authorization.k8s.io']]
    assert ownership_rules == [{'apiGroups': ['rbac.authorization.k8s.io'], 'resources': ['clusterroles', 'clusterrolebindings'], 'resourceNames': ['hanko-operator-cluster-identity-reader', 'hanko-operator-node-reader'], 'verbs': ['get', 'patch', 'delete']}], 'Decommission permissions exceeded release-owned RBAC'
    namespace_rules = [rule for item in documents if item['kind'] in ('Role', 'ClusterRole') for rule in item['rules'] if 'namespaces' in rule.get('resources', [])]
    assert namespace_rules == [expected_rule], 'Namespace access was added outside the dedicated reader'
    binding = next(item for item in documents if item['kind'] == 'ClusterRoleBinding' and item['metadata']['name'] == identity_role['metadata']['name'])
    assert binding['roleRef'] == {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': identity_role['metadata']['name']}
    assert binding['subjects'] == [{'kind': 'ServiceAccount', 'name': 'hanko-operator', 'namespace': 'auth'}]
    for item in documents:
        if item['kind'] == 'HankoTenant':
            assert item['spec']['clusterName'] == 'Équipe Paris_1.prod'
            assert item['spec']['hubEnrollSecretRef']['name'] == 'hanko-hub-enroll'
            assert 'clusterUID' not in item['spec'], 'Cluster UID must not be supplied by Helm'

legacy = render('hub.endpoint=https://hub.example.test', 'hub.tenantID=existing-tenant')
tenant = next(item for item in legacy if item['kind'] == 'HankoTenant')
assert 'clusterName' not in tenant['spec'], 'Optional name broke legacy values'
assert 'hubEnrollSecretRef' not in tenant['spec'], 'Existing tenant unexpectedly reenrolls'
crd_paths = [chart / 'crds/hanko.sh_hankotenants.yaml']
for path in crd_paths:
    crd = yaml.safe_load(path.read_text())
    spec = crd['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']
    field = spec['properties']['clusterName']
    assert field['type'] == 'string' and field['minLength'] == 1 and field['maxLength'] == 80
    assert 'clusterName' not in spec.get('required', []), 'Cluster name must remain optional for existing CRs'
    assert 'clusterUID' not in spec['properties'], 'Cluster UID must be discovered rather than declared'
print('Operator cluster identity: optional name, canonical CRD and exact kube-system GET permissions passed')
PY

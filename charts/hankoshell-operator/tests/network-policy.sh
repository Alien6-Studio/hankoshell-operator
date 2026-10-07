#!/usr/bin/env bash
# Check portable network configuration and reject fail-open policy renders.
set -euo pipefail
ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd -P)"
python3 - "$ROOT_DIR" <<'PY'
import pathlib
import copy
import subprocess
import sys
import tempfile
import yaml

chart = pathlib.Path(sys.argv[1]) / 'charts/hankoshell-operator'
base = ['helm', 'template', 'network-test', str(chart), '--namespace', 'auth',
        '--set-string', 'image.tag=fixture']

def render(values=None, cilium_api=False, invalid=False):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml') as config:
        yaml.safe_dump(values or {}, config)
        config.flush()
        args = base + ['-f', config.name]
        if cilium_api:
            args += ['--api-versions', 'cilium.io/v2/CiliumNetworkPolicy']
        result = subprocess.run(args, text=True, capture_output=True)
        if invalid:
            assert result.returncode != 0, values
            return
        assert result.returncode == 0, result.stderr
        return [d for d in yaml.safe_load_all(result.stdout) if d]

def resource(docs, kind):
    return next(d for d in docs if d['kind'] == kind and
                d['metadata']['name'] == 'network-test-hanko-operator')

default = render()
assert not any(d['kind'].startswith('Cilium') for d in default)
assert not any('cilium.io' in r['apiGroups'] for r in resource(default, 'Role')['rules'])
assert 'delete' in next(r for r in resource(default, 'Role')['rules']
                        if r['resources'] == ['poddisruptionbudgets'])['verbs']
pod = resource(default, 'Deployment')['spec']['template']['spec']
assert pod['securityContext']['runAsNonRoot']
assert pod['securityContext']['seccompProfile']['type'] == 'RuntimeDefault'
assert not any(pod.get(k, False) for k in ('hostNetwork', 'hostPID', 'hostIPC'))
security = pod['containers'][0]['securityContext']
assert security['capabilities']['drop'] == ['ALL'] and not security.get('privileged', False)
assert not security['allowPrivilegeEscalation'] and security['readOnlyRootFilesystem']
dns = next(r for r in resource(default, 'NetworkPolicy')['spec']['egress']
           if any(p['port'] == 53 for p in r['ports']))
assert dns['to'] == [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                      'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}]

cross = render({'networkPolicy': {
    'kubernetesAPIServiceCIDRs': ['10.96.0.1/32'],
    'kubernetesAPIEndpointCIDRs': ['192.0.2.10/32', '2001:db8::10/128'],
    'kubernetesAPIEndpointPorts': [443],
    'keycloakNamespace': 'identity', 'keycloakSelector': {'app': 'official-keycloak'},
    'keycloakPorts': [443, 8443], 'dnsCIDRs': ['169.254.20.10/32'],
}})
rules = resource(cross, 'NetworkPolicy')['spec']['egress']
assert {'to': [{'ipBlock': {'cidr': '192.0.2.10/32'}}, {'ipBlock': {'cidr': '2001:db8::10/128'}}],
        'ports': [{'port': 443, 'protocol': 'TCP'}]} in rules
kc = next(r for r in rules if any(p.get('podSelector', {}).get('matchLabels', {}).get('app') == 'official-keycloak'
                                for p in r['to']))
assert kc['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'] == 'identity'
assert {p['port'] for p in kc['ports']} == {443, 8443}
assert any({'ipBlock': {'cidr': '169.254.20.10/32'}} in r['to'] for r in rules)

external = render({'keycloak': {'url': 'https://iam.example.com', 'caSecret': 'iam-ca'},
                   'networkPolicy': {'keycloakSelector': None, 'keycloakExternalCIDRs': ['192.0.2.11/32']}})
assert {'to': [{'ipBlock': {'cidr': '192.0.2.11/32'}}], 'ports': [{'port': 443, 'protocol': 'TCP'}]} in resource(external, 'NetworkPolicy')['spec']['egress']
pod = resource(external, 'Deployment')['spec']['template']['spec']
env = {e['name']: e for e in pod['containers'][0]['env']}
assert env['HANKO_KEYCLOAK_CA_FILE']['value'] == '/etc/hanko/keycloak-ca/ca.crt'
assert next(m for m in pod['containers'][0]['volumeMounts'] if m['name'] == 'keycloak-ca')['readOnly']
assert next(v for v in pod['volumes'] if v['name'] == 'keycloak-ca')['secret'] == {
    'secretName': 'iam-ca', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}
spoke = render({'keycloak': {'enabled': False}})
assert not any(p.get('podSelector', {}).get('matchLabels', {}).get('app') == 'keycloak'
               for r in resource(spoke, 'NetworkPolicy')['spec']['egress'] for p in r['to'])

cilium = {'networkPolicy': {'cilium': {'enabled': True,
          'fqdnEgress': [{'matchName': 'iam.example.com', 'ports': [443]}]}}}
render(cilium, invalid=True)  # A Cilium-based data plane alone is insufficient.
docs = render(cilium, cilium_api=True)
cnp = resource(docs, 'CiliumNetworkPolicy')
assert cnp['metadata']['namespace'] == 'auth'
assert cnp['spec']['endpointSelector']['matchLabels'] == resource(docs, 'NetworkPolicy')['spec']['podSelector']['matchLabels']
assert {'toEntities': ['kube-apiserver'], 'toPorts': [{'ports': [
    {'port': '443', 'protocol': 'TCP'}, {'port': '6443', 'protocol': 'TCP'}]}]} in cnp['spec']['egress']
assert {'toFQDNs': [{'matchName': 'iam.example.com'}],
        'toPorts': [{'ports': [{'port': '443', 'protocol': 'TCP'}]}]} in cnp['spec']['egress']
dns_proxy = next(r for r in cnp['spec']['egress'] if 'toEndpoints' in r)
assert dns_proxy['toEndpoints'] == [{'matchLabels': {
    'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}]
assert dns_proxy['toPorts'][0]['rules'] == {'dns': [{'matchPattern': '*'}]}
authority = [r for r in resource(docs, 'Role')['rules'] if r['apiGroups'] == ['cilium.io']]
assert authority == [{'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'],
                      'resourceNames': ['network-test-hanko-operator'], 'verbs': ['get', 'delete']}]

for values in [
    {'networkPolicy': {'externalEmailEgress': {'enabled': True, 'cidrs': []}}},
    {'networkPolicy': {'dnsSelector': None}},
    {'networkPolicy': {'dnsNamespace': ''}},
    {'networkPolicy': {'dnsSelector': {'io.kubernetes.pod.namespace': 'untrusted'}}},
    {'networkPolicy': {'kubernetesAPIEndpointPorts': []}},
    {'networkPolicy': {'keycloakExternalPorts': []}},
    {'networkPolicy': {'keycloakPorts': [0]}},
    {'networkPolicy': {'keycloakExternalCIDRs': ['0.0.0.0/0']}},
    {'keycloak': {'caSecret': 'iam-ca'}},
    {'env': {'HANKO_KEYCLOAK_CA_FILE': '/unreviewed.crt'}},
    {'env': {'HANKO_CILIUM_POLICY_ENABLED': 'true'}},
    {'networkPolicy': {'enabled': False, 'cilium': {'enabled': True}}},
    {'networkPolicy': {'cilium': {'enabled': True, 'kubernetesAPI': False}}},
    {'networkPolicy': {'cilium': {'enabled': True, 'fqdnEgress': [{'matchName': '*.example.com', 'ports': [443]}]}}},
    {'networkPolicy': {'cilium': {'enabled': True, 'fqdnEgress': [{'matchName': 'iam.example.com', 'ports': []}]}}},
    {'networkPolicy': {'cilium': {'enabled': True, 'fqdnEgress': [{'matchName': 'iam.example.com', 'ports': [65536]}]}}},
    {'networkPolicy': {'externalEmailEgress': {'enabled': True}, **cilium['networkPolicy']}},
    {'networkPolicy': {'dnsCIDRs': ['169.254.20.10/32'], **cilium['networkPolicy']}},
]:
    render(values, cilium_api=True, invalid=True)

# Every allowed destination and port must remain explicit in both profiles.
for docs in (default, cross, external, spoke, render(cilium, cilium_api=True)):
    for rule in resource(docs, 'NetworkPolicy')['spec']['egress']:
        assert rule.get('to') and rule.get('ports'), rule
        assert all(peer.get('ipBlock') or peer.get('podSelector', {}).get('matchLabels') for peer in rule['to']), rule
print('Network policy: TLS, external/cross-namespace Keycloak, API ports, DNS and optional Cilium gates passed')

enterprise = {
    'profile': 'enterprise',
    'image': {'digest': 'sha256:' + '0' * 64},
    'keycloak': {'enabled': False},
    'hub': {'enabled': True, 'tenantID': 'tenant-acme', 'endpoint': 'https://hub.mesh.example:9443'},
    'continuum': {'enabled': True, 'hubAddress': '10.250.0.1', 'hubHostname': 'hub.mesh.example'},
}
docs = render(enterprise)
pod = resource(docs, 'Deployment')['spec']['template']['spec']
env = {item['name']: item.get('value') for item in pod['containers'][0]['env']}
assert env['HANKO_SECURITY_PROFILE'] == 'enterprise'
assert env['HANKO_ENTERPRISE_HUB_ENDPOINT'] == enterprise['hub']['endpoint']
assert env['HANKO_CONTINUUM_HUB_ADDRESS'] == enterprise['continuum']['hubAddress']
assert pod['containers'][0]['image'].endswith('@' + enterprise['image']['digest'])
assert len(pod['containers']) == 1 and not pod.get('hostNetwork', False)
tenant = next(d for d in docs if d['kind'] == 'HankoTenant')
assert tenant['spec']['hubTransport'] == 'continuum'
rules = resource(docs, 'NetworkPolicy')['spec']['egress']
assert {'to': [{'ipBlock': {'cidr': '10.250.0.1/32'}}],
        'ports': [{'port': 9443, 'protocol': 'TCP'}]} in rules
assert not any(peer.get('podSelector', {}).get('matchLabels', {}).get('app') == 'hanko-hub'
               for rule in rules for peer in rule['to'])
assert not any(peer.get('ipBlock', {}).get('cidr') == '192.0.2.10/32'
               for rule in rules for peer in rule['to'])

bootstrap = copy.deepcopy(enterprise)
bootstrap['hub'].update({'enrollToken': 'bootstrap-fixture', 'enrollmentEndpoint': 'https://enroll.example/hub'})
bootstrap['continuum']['bootstrap'] = {'cidrs': ['192.0.2.10/32']}
bootstrap_docs = render(bootstrap)
bootstrap_pod = resource(bootstrap_docs, 'Deployment')['spec']['template']['spec']
assert next(e for e in bootstrap_pod['containers'][0]['env']
            if e['name'] == 'HANKO_ENTERPRISE_ENROLLMENT_ENDPOINT')['value'] == 'https://enroll.example/hub'

for path, value in [
    (('profile',), 'unknown'),
    (('hub', 'enabled'), False),
    (('continuum', 'enabled'), False),
    (('networkPolicy', 'enabled'), False),
    (('image', 'digest'), ''),
    (('image', 'digest'), 'sha256:short'),
    (('hub', 'endpoint'), 'https://public.example'),
    (('hub', 'endpoint'), 'http://hub.mesh.example:9443'),
    (('hub', 'endpoint'), 'https://hub.mesh.example:9443/hub'),
    (('hub', 'externalCIDRs'), ['192.0.2.10/32']),
    (('hub', 'tenantID'), ''),
    (('continuum', 'hubAddress'), '192.0.2.10'),
    (('continuum', 'hubPort'), 0),
    (('continuum', 'hubPort'), 65536),
    (('continuum', 'hubHostname'), '*.mesh.example'),
    (('continuum', 'bootstrap', 'cidrs'), ['192.0.2.10/32']),
    (('keycloak', 'enabled'), True),
    (('organizationProjection', 'enabled'), True),
    (('env', 'HANKO_SECURITY_PROFILE'), 'standard'),
    (('env', 'HANKO_ENTERPRISE_HUB_ENDPOINT'), 'https://public.example'),
    (('env', 'HANKO_CONTINUUM_HUB_ADDRESS'), '192.0.2.10'),
    (('env', 'HANKO_ENTERPRISE_ENROLLMENT_ENDPOINT'), 'https://public.example'),
    (('env', 'HANKO_SPOKE_MODE'), 'true'),
    (('env', 'HANKO_KEYCLOAK_URL'), 'http://keycloak.auth.svc'),
]:
    invalid = copy.deepcopy(enterprise)
    target = invalid
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value
    render(invalid, invalid=True)
invalid = copy.deepcopy(enterprise)
invalid['supervision'] = {'enabled': True, 'apiURL': 'http://hanko-api.auth.svc'}
render(invalid, invalid=True)
invalid = copy.deepcopy(bootstrap)
invalid['hub']['enrollmentEndpoint'] = ''
render(invalid, invalid=True)

tls_apis = copy.deepcopy(enterprise)
tls_apis['organizationProjection'] = {'enabled': True, 'apiURL': 'https://hanko-api.auth.svc:443', 'apiPorts': [443, 8443]}
tls_apis['supervision'] = {'enabled': True, 'apiURL': 'https://hanko-api.auth.svc:443', 'apiPorts': [443, 8443]}
tls_docs = render(tls_apis)
api_rules = [r for r in resource(tls_docs, 'NetworkPolicy')['spec']['egress']
             if any(peer.get('podSelector', {}).get('matchLabels', {}).get('app') == 'hanko-api' for peer in r['to'])]
assert len(api_rules) == 2
assert all({p['port'] for p in r['ports']} == {443, 8443} for r in api_rules)
for integration in ('organizationProjection', 'supervision'):
    for ports in ([], [0], [65536]):
        invalid = copy.deepcopy(tls_apis)
        invalid[integration]['apiPorts'] = ports
        render(invalid, invalid=True)

with_mesh = copy.deepcopy(enterprise)
with_mesh['hub']['realmRef'] = 'acme'
with_mesh['meshPolicyAudit'] = {'enabled': True}
mesh_docs = render(with_mesh)
mesh_env = {item['name']: item.get('value') for item in resource(mesh_docs, 'Deployment')['spec']['template']['spec']['containers'][0]['env']}
assert mesh_env['HANKO_MESH_POLICY_CONFIGMAP_NAME'] == 'hanko-mesh-policy'
assert not any(item['name'] == 'HANKO_MESH_ENFORCEMENT' for item in resource(mesh_docs, 'Deployment')['spec']['template']['spec']['containers'][0]['env'])
print('Enterprise: private Continuum relay, immutable image, bootstrap retirement and downgrade guards passed')
PY

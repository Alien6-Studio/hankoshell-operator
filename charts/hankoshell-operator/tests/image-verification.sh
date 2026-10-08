#!/usr/bin/env bash
# Validate public-key mounts and the execution policy without cluster access.
set -euo pipefail
ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd -P)"
python3 - "$ROOT_DIR" <<'PY'
import pathlib
import subprocess
import sys
import yaml

root = pathlib.Path(sys.argv[1])
chart = root / 'charts/hankoshell-operator'
base = ['helm', 'template', 'image-policy-test', str(chart), '--namespace', 'auth', '--kube-version', '1.37.0',
        '--set-string', 'image.tag=fixture']
def render(*values):
    args = base.copy()
    for value in values:
        args += ['--set-string', value]
    return list(yaml.safe_load_all(subprocess.check_output(args, text=True)))

docs = render('imageVerification.policyConfigMap=hanko-image-policy',
              'imageVerification.credentialsSecret=registry-pull-only',
              'imageVerification.egressCIDRs[0]=203.0.113.10/32')
pod = next(d for d in docs if d and d['kind'] == 'Deployment')['spec']['template']['spec']
container = pod['containers'][0]
env = {e['name']: e for e in container['env']}
assert env['HANKO_IMAGE_POLICY_FILE']['value'] == '/etc/hanko/image-policy/policy.json'
assert env['HANKO_IMAGE_VERIFY_DOCKER_CONFIG']['value'] == '/etc/hanko/image-pull'
mounts = {m['name']: m for m in container['volumeMounts']}
assert mounts['image-policy']['readOnly'] and mounts['image-verification-pull']['readOnly']
assert not any('subPath' in m for m in mounts.values()), 'Revocation must reach projected files'
volumes = {v['name']: v for v in pod['volumes']}
assert volumes['image-policy']['configMap']['name'] == 'hanko-image-policy'
assert volumes['image-verification-pull']['secret']['items'] == [{'key': '.dockerconfigjson', 'path': 'config.json'}]
assert container['securityContext']['readOnlyRootFilesystem']
assert volumes['verifier-tmp']['emptyDir'] == {'medium': 'Memory', 'sizeLimit': '16Mi'}
network = next(d for d in docs if d and d['kind'] == 'NetworkPolicy' and d['metadata']['name'] == 'image-policy-test-hanko-operator')
assert {'to': [{'ipBlock': {'cidr': '203.0.113.10/32'}}], 'ports': [{'port': 443, 'protocol': 'TCP'}]} in network['spec']['egress']
for invalid in [
    ['imageVerification.credentialsSecret=registry-pull-only'],
    ['imageVerification.policyConfigMap=hanko-image-policy'],
    ['imageVerification.policyConfigMap=hanko-image-policy', 'imageVerification.egressCIDRs[0]=0.0.0.0/0'],
    ['env.HANKO_IMAGE_POLICY_FILE=/attacker/policy.json'],
    ['imageVerification.policyConfigMap=unprotected'],
]:
    args = base.copy()
    for value in invalid:
        args += ['--set-string', value]
    assert subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0, invalid

print('Image verification: public/pull-only mounts, revocation, bounded scratch and exact HTTPS egress passed')
PY

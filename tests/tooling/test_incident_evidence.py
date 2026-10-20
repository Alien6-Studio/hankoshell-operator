import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location('incident_evidence', ROOT / 'tools/operations/incident_evidence.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
CONTRACT = json.loads((Path(__file__).resolve().parents[2] / 'docs/operational-contract.json').read_text())


class IncidentEvidenceTests(unittest.TestCase):
    def fixture(self):
        return {'apiVersion': 'hanko.sh/v1alpha1', 'kind': 'HankoApplication',
                'metadata': {'name': 'private-name', 'uid': 'private-uid', 'generation': 9,
                             'annotations': {'hanko.sh/runtime-bindings-journal': 'private-journal'},
                             'finalizers': ['private-finalizer']},
                'spec': {'clientID': 'private-client', 'attributes': {'secret': 'private-value'}},
                'status': {'phase': 'Error', 'observedGeneration': 9, 'appliedGeneration': 8,
                           'conditions': [{'type': 'Synced', 'status': 'False', 'reason': 'ProviderPermissionDenied',
                                           'observedGeneration': 9, 'message': 'private-native-response'}]}}

    def test_only_public_fixed_decisions_and_generation_numbers_are_retained(self):
        value = self.fixture()
        report = collector.collect(value, CONTRACT)
        text = json.dumps(report)
        self.assertNotIn('private-', text)
        entry = report['objects'][0]
        self.assertEqual(entry['appliedGeneration'], 8)
        self.assertEqual(entry['finalizer_count'], 1)
        self.assertEqual(entry['conditions'][0]['reason'], 'ProviderPermissionDenied')
        self.assertTrue(entry['conditions'][0]['current'])
        value['status']['conditions'][0]['observedGeneration'] = 8
        self.assertFalse(collector.collect(value, CONTRACT)['objects'][0]['conditions'][0]['current'])

    def test_untrusted_phase_reason_type_and_messages_cannot_exfiltrate_tokens(self):
        value = self.fixture()
        token = 'eyJ' + 'private' * 10 + '.payload.signature'
        value['status']['phase'] = token
        value['status']['conditions'][0].update(type=token, reason=token, message=token)
        entry = collector.collect(value, CONTRACT)['objects'][0]
        self.assertEqual(entry['phase'], 'Other')
        self.assertEqual(entry['conditions'][0]['type'], 'Other')
        self.assertEqual(entry['conditions'][0]['reason'], 'Other')
        self.assertNotIn(token, json.dumps(entry))

    def test_all_resource_versions_are_explicit_and_credential_objects_are_refused(self):
        for kind in collector.KINDS:
            for version in ('hanko.sh/v1alpha1', 'hanko.sh/v1beta1'):
                value = self.fixture(); value.update(kind=kind, apiVersion=version)
                if version.endswith('v1alpha1') or kind in collector.BETA_KINDS:
                    self.assertEqual(collector.collect(value, CONTRACT)['object_count'], 1)
                else:
                    with self.assertRaises(ValueError): collector.collect(value, CONTRACT)
        for kind in ('Secret', 'ConfigMap', 'Event', 'Pod', 'HankoUnreviewed'):
            value = self.fixture(); value['kind'] = kind
            with self.assertRaises(ValueError): collector.collect(value, CONTRACT)

    def test_size_depth_duplicates_nonfinite_values_and_object_budget_fail_closed(self):
        for raw in (b'{"kind":"List","kind":"Secret"}', b'NaN', b'{"value":Infinity}',
                    b'[' * 65 + b']' * 65, b'x' * (collector.MAX_BYTES + 1)):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError): collector.decode(raw)
        value = {'kind': 'List', 'items': [self.fixture()] * (collector.MAX_OBJECTS + 1)}
        with self.assertRaises(ValueError): collector.collect(value, CONTRACT)
        self.assertEqual(collector.collect({'kind': 'List', 'items': []}, CONTRACT)['object_count'], 0)
        self.assertEqual(collector.decode(b'{"quoted":"[[[\\\"{"}'), {'quoted': '[[["{'})

    def test_malformed_and_unbounded_conditions_never_reach_output(self):
        for mutation in ('condition-count', 'bad-generation', 'boolean-generation', 'bad-status', 'bad-phase', 'bad-metadata'):
            value = self.fixture()
            if mutation == 'condition-count': value['status']['conditions'] *= 65
            elif mutation == 'bad-generation': value['metadata']['generation'] = 2**64
            elif mutation == 'boolean-generation': value['metadata']['generation'] = True
            elif mutation == 'bad-status': value['status']['conditions'][0]['status'] = 'private-sentinel'
            elif mutation == 'bad-phase': value['status']['phase'] = []
            else: value['metadata'] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): collector.collect(value, CONTRACT)

    def test_cli_creates_private_exclusive_file_and_refuses_symlink_or_invalid_input(self):
        script = str(Path(collector.__file__))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'incident.json'
            command = [sys.executable, script, '--output', str(output)]
            good = subprocess.run(command, input=json.dumps(self.fixture()), text=True, capture_output=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            original = output.read_bytes()
            refused = subprocess.run(command, input=json.dumps(self.fixture()), text=True, capture_output=True)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(output.read_bytes(), original)
            link = Path(directory) / 'link.json'; link.symlink_to(output)
            refused = subprocess.run([sys.executable, script, '--output', str(link)], input=json.dumps(self.fixture()), text=True, capture_output=True)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(output.read_bytes(), original)
            absent = Path(directory) / 'invalid.json'
            refused = subprocess.run([sys.executable, script, '--output', str(absent)], input='private-bad-json', text=True, capture_output=True)
            self.assertEqual(refused.returncode, 1)
            self.assertNotIn('private-', refused.stdout + refused.stderr)
            self.assertFalse(absent.exists())

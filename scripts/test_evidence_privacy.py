import json
from pathlib import Path
import random
import re
import subprocess
import sys
import unittest

from evidence_privacy import contains_jwt, redact_jwts


class EvidencePrivacyTests(unittest.TestCase):
    def test_detection_and_redaction_preserve_unrelated_public_text(self):
        token = "eyJheader.payload.signature"
        for text in (token, "Bearer " + token, json.dumps({"message": token}), "prefix" + token, "é" + token,
                     "before " + token + " between " + token + " after", "x." + token):
            with self.subTest(text=text):
                self.assertTrue(contains_jwt(text))
                redacted = redact_jwts(text)
                self.assertNotIn(token, redacted)
                self.assertFalse(contains_jwt(redacted))
        for text in ("public status", "eyJ.payload.signature", "eyJa..signature", "eyJa.payload.", "eyJa payload.signature", "eyJa.payload .signature"):
            with self.subTest(text=text):
                self.assertFalse(contains_jwt(text))
                self.assertEqual(redact_jwts(text), text)
        self.assertEqual(redact_jwts("before " + token + " after"), "before [REDACTED JWT] after")
        self.assertEqual(redact_jwts("abcdefghijkl.payload.signature", json_header=False), "[REDACTED JWT]")

    def test_bounded_oracle_preserves_existing_detection_semantics(self):
        # The legacy expression is used only on tiny locally generated inputs.
        legacy = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
        randomizer = random.Random(17)
        vocabulary = ["eyJ", "eyJa", "header", "prefixeyJtail", "payload", "signature", ".", "..", "é", " ", "_", "-", '"', "\n"]
        for _ in range(2500):
            text = "".join(randomizer.choices(vocabulary, k=12))
            self.assertEqual(contains_jwt(text), bool(legacy.search(text)), repr(text))
            redacted = redact_jwts(text)
            self.assertFalse(contains_jwt(redacted), repr(text))

    def test_long_hostile_prefixes_finish_in_a_bounded_child_process(self):
        # The old unanchored expression retries every eyJ prefix on these inputs.
        source = """
from evidence_privacy import contains_jwt, redact_jwts
for text in ('eyJ' * 250000, 'eyJ' * 250000 + '.payload', 'eyJ' * 250000 + '.' + 'a' * 750000 + '.'):
    assert not contains_jwt(text)
    assert redact_jwts(text) == text
    assert redact_jwts(text, json_header=False) == text
print('bounded')
"""
        result = subprocess.run([sys.executable, "-c", source], cwd=Path(__file__).parent,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "bounded\n")

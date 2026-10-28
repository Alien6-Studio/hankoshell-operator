"""Fault selection must distinguish an exchange from credential acquisition."""
import unittest

from tools.qualification.fixtures.workload_fault_proxy import matches, source_matches


class ExchangeFaultTests(unittest.TestCase):
    def test_exchange_discriminator_is_exact_and_rejects_ambiguous_forms(self):
        rule = {"method": "POST", "path": "/token", "oauth_grant": "urn:ietf:params:oauth:grant-type:token-exchange"}
        exchange = b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&actor_token=synthetic"
        self.assertTrue(matches(rule, "POST", "/token", exchange))
        for body in (b"grant_type=client_credentials", exchange + b"&grant_type=client_credentials",
                     exchange + b"&" + b"x=y&" * 24, b"\xff", b"actor_token=synthetic"):
            self.assertFalse(matches(rule, "POST", "/token", body))
        self.assertFalse(matches(rule, "GET", "/token", exchange))
        self.assertFalse(matches(rule, "POST", "/other", exchange))
        self.assertFalse(matches({**rule, "oauth_grant": "unsupported"}, "POST", "/token", b"grant_type=unsupported"))

    def test_source_scope_uses_socket_peer(self):
        rule = {"client_ip": "192.0.2.10"}
        self.assertTrue(source_matches(rule, "192.0.2.10"))
        self.assertFalse(source_matches(rule, "192.0.2.11"))
        self.assertFalse(source_matches(rule, ""))


if __name__ == "__main__":
    unittest.main()

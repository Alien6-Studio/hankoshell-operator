"""The adversarial probe must never fall back to administrator authentication."""
import base64
from io import BytesIO
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from sensitive_write_probe import NoRedirect, TokenAPI


class OperatorProbeTests(unittest.TestCase):
    cluster = {"server": "https://127.0.0.1:6443", "certificate-authority-data": base64.b64encode(b"public-ca-fixture").decode()}

    def client(self):
        with patch("sensitive_write_probe.ssl.create_default_context") as tls, patch("sensitive_write_probe.build_opener") as opener:
            api = TokenAPI(self.cluster, "private-token-fixture")
            tls.assert_called_once_with(cadata="public-ca-fixture")
            handlers = opener.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[2], NoRedirect)
            self.assertIsNone(handlers[2].redirect_request(None, None, 302, None, {}, "https://other.invalid/"))
            self.assertFalse(tls.return_value.load_cert_chain.called)
        return api

    def test_token_only_verified_connection_without_redirect_proxy_or_client_key(self):
        api = self.client()
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value, response.code = b'{"kind":"Status"}', 201
        api.opener.open.return_value = response
        self.assertEqual(api("POST", "/api/v1/probe", {"public-fixture": True}, dry=True), (201, {"kind": "Status"}))
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://127.0.0.1:6443/api/v1/probe?dryRun=All")
        self.assertEqual(request.get_header("Authorization"), "Bearer private-token-fixture")
        response.read.assert_called_once_with(1048577)
        with self.assertRaisesRegex(ValueError, "verified HTTPS"):
            TokenAPI({**self.cluster, "server": "http://127.0.0.1:6443"}, "private-token-fixture")

    def test_error_is_classified_by_http_status_not_attacker_supplied_message(self):
        api = self.client()
        for code, message in ((403, "Success"), (201, "Forbidden"), (409, "PermissionDenied")):
            api.opener.open.side_effect = HTTPError("https://fixture", code, "withheld", {}, BytesIO(('{"message":"'+message+'"}').encode()))
            self.assertEqual(api("PATCH", "/probe", {})[0], code)

    def test_oversized_or_malformed_api_bodies_cannot_count_as_success(self):
        api = self.client()
        for raw in (b"a" * 1048577, b"not json"):
            response = MagicMock()
            response.__enter__.return_value = response
            response.read.return_value, response.code = raw, 201
            api.opener.open.return_value = response
            with self.assertRaises(ValueError):
                api("POST", "/probe", {})

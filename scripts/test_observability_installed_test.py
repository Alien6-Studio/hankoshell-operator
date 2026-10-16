import importlib.util
from pathlib import Path
import types
import ssl
import subprocess
from urllib.error import HTTPError, URLError
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("observability_installed", Path(__file__).with_name("observability-installed-test.py"))
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)


class InstalledObservabilityTrustTests(unittest.TestCase):
    def test_explicit_peer_alert_is_required_without_accepting_eof_reset_or_local_trust_failure(self):
        for text, code, valid in (
                (b"tlsv13 alert certificate required", 1, True), (b"tlsv1 alert bad certificate", 1, True),
                (b"unexpected eof while reading", 1, False), (b"Connection reset by peer", 1, False),
                (b"certificate verify failed: alert bad certificate", 1, False), (b"", 0, False)):
            with self.subTest(error=text), patch.object(installed.subprocess, "run", return_value=subprocess.CompletedProcess([], code, b"private-session-sentinel", text)) as run:
                if valid:
                    installed.require_tls_authentication_refusal("openssl", "https://localhost:12345/metrics", "ca.crt")
                else:
                    with self.assertRaises(ValueError):
                        installed.require_tls_authentication_refusal("openssl", "https://localhost:12345/metrics", "ca.crt")
                self.assertIn("-verify_return_error", run.call_args.args[0])
                self.assertIn("-verify_hostname", run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs["timeout"], 10)
        with patch.object(installed.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 10)), self.assertRaisesRegex(ValueError, "transport"):
            installed.require_tls_authentication_refusal("openssl", "https://localhost:12345/metrics", "ca.crt")

    def test_transport_failure_is_never_counted_as_authorization_refusal(self):
        for error in (URLError(ConnectionRefusedError()), URLError(TimeoutError()), HTTPError("https://localhost", 500, "withheld", {}, None)):
            with self.subTest(error=type(error).__name__), self.assertRaisesRegex(ValueError, "transport"):
                installed.require_authentication_refusal(error)
        for error in (URLError(ssl.SSLError("TLS client authentication refused")), ssl.SSLError("refused"),
                      HTTPError("https://localhost", 403, "withheld", {}, None)):
            installed.require_authentication_refusal(error)

    def test_scanned_graph_is_verified_before_any_cluster_or_container(self):
        publication = MagicMock()
        publication.publish.contract.security.verify.side_effect = ValueError("scan mismatch")
        fixture = types.SimpleNamespace(VERSION="0.1.0-dev.0", publication=publication, System=MagicMock())
        args = ["observability-test"]
        for name in ("archive", "evidence", "output", "kind", "kubectl", "helm", "oras", "openssl", "digest", "revision"):
            args += ["--" + name, "fixture"]
        with patch.object(installed, "load_system", return_value=fixture), patch("sys.argv", args):
            with self.assertRaisesRegex(ValueError, "scan mismatch"):
                installed.main()
        publication.publish.contract.security.verify.assert_called_once()
        fixture.System.assert_not_called()

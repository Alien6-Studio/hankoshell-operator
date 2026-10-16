import importlib.util
from pathlib import Path
import types
import ssl
from urllib.error import HTTPError, URLError
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("observability_installed", Path(__file__).with_name("observability-installed-test.py"))
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)


class InstalledObservabilityTrustTests(unittest.TestCase):
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

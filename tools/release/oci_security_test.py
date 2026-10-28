"""Unrated advisories with a published fix must not pass the image gate."""
import unittest

from tools.release import oci_security


class OCISecurityTest(unittest.TestCase):
    def test_fixable_unknown_is_blocked_and_unfixed_findings_remain_in_raw_report(self):
        fixable = {"VulnerabilityID": "CVE-2026-78661", "PkgName": "golang.org/x/net",
                   "InstalledVersion": "v0.61.0", "FixedVersion": "0.62.0", "Severity": "UNKNOWN"}
        unfixed = {"VulnerabilityID": "GO-2026-5932", "PkgName": "golang.org/x/crypto",
                   "InstalledVersion": "v0.58.0", "Severity": "UNKNOWN"}
        report = {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": "sha256:fixture"}, "Results": [
            {"Target": "hankoshell-operator", "Type": "gobinary", "Packages": [{"Name": "stdlib"}], "Vulnerabilities": [fixable]},
            {"Target": "usr/local/bin/cosign", "Type": "gobinary", "Packages": [{"Name": "stdlib"},
                {"Name": "github.com/sigstore/cosign/v3", "Version": "v3.1.4"}], "Vulnerabilities": [unfixed]},
            {"Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "base-files"}]}]}
        policy = oci_security.read_policy()
        verdict = oci_security.evaluate(report, "sha256:fixture", policy)
        self.assertEqual([finding["cve"] for finding in verdict["blocked"]], [fixable["VulnerabilityID"]])
        self.assertEqual(verdict["exceptions_applied"], [])
        self.assertEqual(verdict["unfixed_high_critical"], [])
        self.assertEqual(report["Results"][1]["Vulnerabilities"], [unfixed])
        # An UNKNOWN finding cannot borrow a HIGH-only temporary exception.
        policy["exceptions"] = [{"cve": fixable["VulnerabilityID"], "package": fixable["PkgName"],
            "target": "hankoshell-operator", "installed_version": "v0.61.0"}]
        self.assertEqual(len(oci_security.evaluate(report, "sha256:fixture", policy)["blocked"]), 1)
        report["Results"][0]["Vulnerabilities"] = []
        self.assertEqual(oci_security.evaluate(report, "sha256:fixture", policy)["blocked"], [])


if __name__ == "__main__":
    unittest.main()

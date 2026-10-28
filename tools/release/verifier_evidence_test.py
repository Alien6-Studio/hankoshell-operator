"""Security regressions for evidence tied to the shipped verifier, not just modules."""
import copy
import unittest

from tools import versions
from tools.release import verifier_evidence


class VerifierEvidenceTest(unittest.TestCase):
    def test_rejects_unbound_or_incomplete_package_proof(self):
        binary = "a" * 64
        data = {"schema": 1, "binary_sha256": binary, "go_version": "go" + versions.get("go", "toolchain"),
                "os": "linux", "arch": "amd64", "main": {"path": "github.com/sigstore/cosign/v3",
                "version": versions.get("tools", "cosign", "version"), "sum": "h1:fixture"},
                "modules": [{"path": path, "version": value, "sum": "h1:fixture"}
                            for path, value in versions.get("tools", "cosign", "dependencies").items()],
                "packages": sorted(["github.com/sigstore/cosign/v3/cmd/cosign"] + [f"fixture/package{i}" for i in range(100)])}
        self.assertTrue(verifier_evidence.validate(data, binary, "linux/amd64")["deprecated_openpgp_absent"])
        mutations = [lambda d: d.update(binary_sha256="b" * 64), lambda d: d.update(arch="arm64"),
                     lambda d: d.update(packages=[]), lambda d: d.update(modules=[]),
                     lambda d: d["modules"][0].update(version="v0.0.1"),
                     lambda d: d["modules"].append(d["modules"][0]),
                     lambda d: d["packages"].append(d["packages"][0]),
                     lambda d: d["main"].update(version="v0.0.1")]
        for path in ("golang.org/x/crypto/openpgp", "golang.org/x/crypto/openpgp/armor"):
            mutations.append(lambda d, path=path: d.update(packages=sorted(d["packages"] + [path])))
        for mutate in mutations:
            changed = copy.deepcopy(data)
            mutate(changed)
            with self.assertRaises(ValueError):
                verifier_evidence.validate(changed, binary, "linux/amd64")


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("versions", ROOT / 'tools/versions.py')
versions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(versions)
spec = importlib.util.spec_from_file_location("install_helm", ROOT / 'tools/bootstrap/install_helm.py')
helm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helm)


class VersionContractTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        files = set(versions.generated()) | {"Dockerfile", "Makefile", "tools/bootstrap/install_cosign.sh",
            "tools/release/release_version.py", "tools/bootstrap/install_system_tools.py", "tools/qualification/scenarios/system_test.py",
            "tools/qualification/fixtures/workload_identity_probe.py"}
        files |= {str(p.relative_to(versions.ROOT)) for p in (versions.ROOT / ".github/workflows").glob("*.yml")}
        for filename in files:
            destination = root / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(versions.ROOT / filename, destination)
        for directory in (versions.DATA["api"]["crds"], versions.DATA["api"]["types"],
                          *(v["types"] for v in versions.DATA["api"].get("candidate_versions", {}).values())):
            shutil.copytree(versions.ROOT / directory, root / directory)
        return root

    def test_current_pins_and_all_consumers_agree(self):
        result = versions.check()
        self.assertEqual(result["crd_count"], len(result["kinds"]))
        self.assertGreater(result["crd_count"], 0)
        self.assertEqual(versions.get("release", "version"), versions.DATA["release"]["version"])
        self.assertRegex(versions.get("tools", "gotestsum"), r"^v\d+\.\d+\.\d+$")
        with self.assertRaisesRegex(ValueError, "not enabled/pinned"):
            versions.get("disabled", data={"disabled": None})

    def test_drift_is_rejected_at_each_build_entry_point(self):
        mutations = {
            "Dockerfile": [("ARG VERSION=", "ARG VERSION=99."), ("golang:", "golang:99.")],
            "go.mod": [("toolchain go", "toolchain go99.")],
            "internal/version/version.go": [('var Agent = "', 'var Agent = "99.')],
            "tools/bootstrap/cosign_pins.sh": [("COSIGN_VERSION='", "COSIGN_VERSION='v99.")],
            "tools/bootstrap/install_cosign.sh": [('go get $COSIGN_DEPENDENCIES', 'go get golang.org/x/crypto@v0.1.0')],
            "Makefile": [("CONTROLLER_GEN_VERSION := $(shell python3 -m tools.versions get tools controller_gen)",
                          "CONTROLLER_GEN_VERSION := v0.1.0")],
            "tools/bootstrap/install_system_tools.py": [('KIND = PINS["kind"]["version"]', 'KIND = "v99.0.0"')],
            ".github/workflows/ci.yml": [("go-version-file: go.mod", "go-version: '9.9.9'"),
                                         ('version: ["1.', 'version: ["9.'),
                                         ('oras/cmd/oras@$(python3 -m tools.versions get tools oras)', 'oras/cmd/oras@v0.1.0')],
            ".github/workflows/oci-security.yml": [("VERSION=${{ steps.versions.outputs.version }}", "VERSION=9.9.9")],
            "charts/hankoshell-operator/Chart.yaml": [('appVersion: "', 'appVersion: "99.')],
        }
        # Use one real source tree and restore each mutation; no network/build required.
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            for filename, changes in mutations.items():
                path = root / filename
                original = path.read_text()
                for old, new in changes:
                    self.assertIn(old, original)
                    with self.subTest(filename=filename, mutation=old):
                        path.write_text(original.replace(old, new))
                        with self.assertRaises(ValueError):
                            versions.check(root)
                        path.write_text(original)
            versions.check(root)

    def test_single_manifest_change_regenerates_every_owned_release_literal(self):
        data = copy.deepcopy(versions.DATA)
        data["release"]["version"] = "0.1.0-dev.99"
        data["tools"]["cosign"]["dependencies"]["golang.org/x/crypto"] = "v0.99.0"
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, "Version drift"):
                versions.check(root, data)
            output = versions.generated(root, data)
            for filename, content in output.items():
                (root / filename).write_text(content)
            versions.check(root, data)
            self.assertEqual(versions.generated(root, data), output)  # Idempotent.
            for filename in ("Dockerfile", "internal/version/version.go", "charts/hankoshell-operator/Chart.yaml"):
                self.assertIn(data["release"]["version"], output[filename])
            self.assertIn("golang.org/x/crypto@v0.99.0", output["tools/bootstrap/cosign_pins.sh"])

    def test_new_api_needs_matching_manifest_type_and_registration_without_a_count_edit(self):
        # Filesystem order differs across Linux and macOS. Exercise both a
        # single-version and a candidate-version donor explicitly. Future has
        # no reviewed beta profile, so its fixture must retain only the hub.
        for donor in ("hanko.sh_hankorealms.yaml", "hanko.sh_hankoapplications.yaml"):
            with self.subTest(donor=donor), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                initial = versions.crd_inventory(root)["crd_count"]
                crds = root / versions.DATA["api"]["crds"]
                types = root / versions.DATA["api"]["types"]
                crd = yaml.safe_load((crds / donor).read_text())
                crd["metadata"]["name"] = "hankofutures.hanko.sh"
                crd["spec"]["names"] = {"kind": "HankoFuture", "plural": "hankofutures", "singular": "hankofuture", "listKind": "HankoFutureList"}
                crd["spec"]["versions"] = [entry for entry in crd["spec"]["versions"] if entry["name"] == versions.DATA["api"]["version"]]
                extra = crds / "hanko.sh_hankofutures.yaml"
                extra.write_text(yaml.safe_dump(crd))
                with self.assertRaisesRegex(ValueError, "kinds differ"):
                    versions.crd_inventory(root)
                (types / "hankofuture_types.go").write_text('type HankoFuture struct {\n\tmetav1.TypeMeta\n}\n')
                with self.assertRaisesRegex(ValueError, "kinds differ"):
                    versions.crd_inventory(root)
                registration = types / "groupversion_info.go"
                registration.write_text(registration.read_text().replace("scheme.AddKnownTypes(GroupVersion,", "scheme.AddKnownTypes(GroupVersion,\n &HankoFuture{},"))
                self.assertEqual(versions.check(root)["crd_count"], initial + 1)
                crd["spec"]["versions"][0]["served"] = False
                extra.write_text(yaml.safe_dump(crd))
                with self.assertRaisesRegex(ValueError, "Invalid or duplicate"):
                    versions.crd_inventory(root)

    def test_missing_fixture_checksums_and_unqualified_matrix_entries_fail_closed(self):
        for family, entry in (("kubernetes", "1.99.0"), ("keycloak", "99.0.0")):
            data = copy.deepcopy(versions.DATA)
            data[family]["versions"].append(entry)
            with self.assertRaisesRegex(ValueError, "fixture pins"):
                versions.validate(data)
        data = copy.deepcopy(versions.DATA)
        data["tools"]["helm"]["sha256"]["linux-amd64"] = "bad"
        with self.assertRaisesRegex(ValueError, "checksum"):
            versions.validate(data)

    def test_native_cosign_keeps_the_reviewed_toolchain_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "go-invocations"
            command = root / "go"
            command.write_text('#!/bin/sh\nprintf "%s\\n" "$GOTOOLCHAIN" >> "$FIXTURE_GO_LOG"\n')
            command.chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "GOTOOLCHAIN": "auto", "FIXTURE_GO_LOG": str(log)}
            subprocess.run(["bash", str(versions.ROOT / "tools/bootstrap/install_cosign.sh"), str(root / "cosign")],
                           cwd=root, env=env, check=True, timeout=30)
            self.assertEqual(log.read_text().splitlines(), ["go" + versions.DATA["go"]["toolchain"]] * 4)


class HelmInstallerTests(unittest.TestCase):
    def archive(self, link=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("linux-amd64/helm")
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                archive.addfile(member)
            else:
                binary = b"test executable"
                member.size = len(binary)
                archive.addfile(member, io.BytesIO(binary))
        return stream.getvalue()

    def test_archive_and_binary_versions_are_verified(self):
        payload = self.archive()
        pins = {"version": "1.2.3", "sha256": {"linux-amd64": hashlib.sha256(payload).hexdigest()}}
        with tempfile.TemporaryDirectory() as directory, patch.object(helm, "urlopen", return_value=io.BytesIO(payload)) as download, \
                patch.object(helm.subprocess, "check_output", return_value="v1.2.3") as command:
            destination = Path(directory) / "bin/helm"
            helm.install(destination, "linux-amd64", pins)
            self.assertEqual(destination.read_bytes(), b"test executable")
            self.assertTrue(destination.stat().st_mode & 0o111)
            self.assertIn("helm-v1.2.3-linux-amd64.tar.gz", download.call_args.args[0])
            command.assert_called_once()

    def test_corrupt_archives_links_and_unsupported_hosts_are_rejected(self):
        for link, digest in ((False, "0" * 64), (True, None)):
            payload = self.archive(link)
            pins = {"version": "1.2.3", "sha256": {"linux-amd64": digest or hashlib.sha256(payload).hexdigest()}}
            with tempfile.TemporaryDirectory() as directory, patch.object(helm, "urlopen", return_value=io.BytesIO(payload)), \
                    patch.object(helm.subprocess, "check_output") as command:
                destination = Path(directory) / "helm"
                with self.assertRaises(ValueError):
                    helm.install(destination, "linux-amd64", pins)
                self.assertFalse(destination.exists())
                command.assert_not_called()
        with patch.object(helm, "urlopen") as download, self.assertRaises(KeyError):
            helm.install(Path("/unused"), "unsupported")
        download.assert_not_called()


if __name__ == "__main__":
    unittest.main()

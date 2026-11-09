"""Chart documentation updates cannot silently replace application or runtime files."""
import copy
from contextlib import ExitStack
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from tools import versions
from tools.release import chart_revision
from tools.release import release_publish as delivery


class ChartRevisionTest(unittest.TestCase):
    def fixture(self):
        old = {"name": "hankoshell-operator", "version": "1.2.1", "appVersion": "1.2.1",
               "description": "Manage Keycloak", "annotations": {"artifacthub.io/changes": "old", "other": "retained"}}
        base = {"hankoshell-operator/Chart.yaml": yaml.safe_dump(old).encode(),
                "hankoshell-operator/README.md": b"old instructions",
                "hankoshell-operator/values.yaml": b"immutable operator digest",
                "hankoshell-operator/templates/deployment.yaml": b"reviewed deployment"}
        revised = dict(base)
        new = copy.deepcopy(old)
        new.update(version="1.2.2", description="Manage sign-in and access")
        new["annotations"]["artifacthub.io/changes"] = "new guidance"
        revised["hankoshell-operator/Chart.yaml"] = yaml.safe_dump(new).encode()
        revised["hankoshell-operator/README.md"] = b"current installation instructions"
        return base, revised

    def test_only_catalogue_and_readme_changes_are_accepted(self):
        base, revised = self.fixture()
        self.assertEqual(chart_revision.documentation_only(base, revised),
                         ["hankoshell-operator/Chart.yaml", "hankoshell-operator/README.md"])

    def test_operator_change_new_resource_and_policy_annotation_are_rejected(self):
        for mutation in ("image", "deployment", "new-resource", "app-version", "other-annotation"):
            with self.subTest(mutation=mutation):
                base, revised = self.fixture()
                if mutation == "image":
                    revised["hankoshell-operator/values.yaml"] = b"different digest"
                elif mutation == "deployment":
                    revised["hankoshell-operator/templates/deployment.yaml"] = b"different permissions"
                elif mutation == "new-resource":
                    revised["hankoshell-operator/templates/extra.yaml"] = b"new resource"
                else:
                    metadata = yaml.safe_load(revised["hankoshell-operator/Chart.yaml"])
                    if mutation == "app-version":
                        metadata["appVersion"] = "1.2.2"
                    else:
                        metadata["annotations"]["other"] = "changed"
                    revised["hankoshell-operator/Chart.yaml"] = yaml.safe_dump(metadata).encode()
                with self.assertRaises(ValueError):
                    chart_revision.documentation_only(base, revised)

    def test_documented_chart_and_operator_versions_are_independent(self):
        data = copy.deepcopy(versions.DATA)
        data["release"]["version"] = "1.2.1"
        data["chart"] = {"version": "1.2.2"}
        output = versions.generated(data=data)
        self.assertIn('version: "1.2.2"', output["charts/hankoshell-operator/Chart.yaml"])
        self.assertIn('appVersion: "1.2.1"', output["charts/hankoshell-operator/Chart.yaml"])
        self.assertIn("--version 1.2.2", output["README.md"])
        self.assertIn("ARG VERSION=1.2.1", output["Dockerfile"])

    def test_joint_release_without_revision_pins_is_refused(self):
        with patch.dict(versions.DATA, {"release": {"version": "1.2.3", "status": "ready"},
                                        "chart": {"version": "1.2.3"}, "chart_revision": None}):
            with self.assertRaisesRegex(ValueError, "Release workflow"):
                chart_revision.configuration()


# Chart 1.2.2 republished operator 1.2.1; joint releases carry no revision pins.
REVISION_PINS = {
    "release": {"version": "1.2.1", "status": "ready"},
    "chart": {"version": "1.2.2"},
    "chart_revision": {
        "operator_version": "1.2.1",
        "operator_revision": "6030aaa29bfb9855535703e384b2fee512459377",
        "image": "ghcr.io/alien6-studio/hankoshell-operator@sha256:b64a9e03719fdf14c086531876e918524b401dbd3913198639898ddda6222427",
        "base_chart_sha256": "a76cbee0952cf77ca47d0d672470d009b3cbf839eac415efa2390f94c567a846",
    },
}


class ChartPublicationTest(unittest.TestCase):
    def setUp(self):
        pins = patch.dict(versions.DATA, REVISION_PINS)
        pins.start()
        self.addCleanup(pins.stop)

    def exercise(self, mutation=None):
        """A lost OCI push response must resume without a GitHub product release."""
        config = chart_revision.configuration()
        revision, tag = "a" * 40, "chart-v" + config["chart_version"]
        state = {"chart": None, "writes": [], "interrupt": mutation is None}
        operator_digest = config["image"].split("@")[1]

        class Registry:
            def __init__(self, oras, helm):
                pass

            def resolve(self, reference):
                if reference == delivery.IMAGE + ":" + config["operator_version"]:
                    return "sha256:" + "f" * 64 if mutation == "operator" else operator_digest
                assert reference == delivery.CHART + ":" + config["chart_version"]
                return "sha256:" + "e" * 64 if state["chart"] is not None else None

            def file_matches(self, reference, digest, expected):
                return state["chart"] == expected.read_bytes()

            def push_chart(self, path, reference):
                assert reference == delivery.CHART and state["chart"] is None
                state["chart"] = path.read_bytes()
                state["writes"].append("chart")
                if state["interrupt"]:
                    state["interrupt"] = False
                    raise ConnectionError("fixture lost OCI push response after commit")

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary) / "delivery"
            dist = root / "dist"
            dist.mkdir(parents=True)
            chart = dist / ("hankoshell-operator-" + config["chart_version"] + ".tgz")
            metadata = yaml.safe_dump({"name": "hankoshell-operator", "version": config["chart_version"],
                                       "appVersion": config["operator_version"]}).encode()
            with tarfile.open(chart, "w:gz") as archive:
                entry = tarfile.TarInfo("hankoshell-operator/Chart.yaml")
                entry.size = len(metadata)
                archive.addfile(entry, io.BytesIO(metadata))
            (root / "checkpoint.json").write_text(json.dumps(chart_revision.binding(root, config, revision)))
            if mutation == "chart":
                state["chart"] = b"other immutable published bytes"
            stack.enter_context(patch.object(chart_revision, "identity", return_value=(config, revision, tag)))
            stack.enter_context(patch.object(chart_revision, "verify_signatures"))
            stack.enter_context(patch.object(chart_revision.oci_security, "verify"))
            stack.enter_context(patch.object(delivery, "Registry", Registry))
            github = stack.enter_context(patch.object(delivery, "GitHub", side_effect=AssertionError(
                "Chart packaging must not access GitHub product releases")))
            args = SimpleNamespace(root=root, oras=None, helm=None)
            if mutation:
                with self.assertRaises(ValueError):
                    chart_revision.publish(args)
                self.assertEqual(state["writes"], [])
            else:
                with self.assertRaises(ConnectionError):
                    chart_revision.publish(args)
                self.assertEqual(state["chart"], chart.read_bytes())
                chart_revision.publish(args)
                chart_revision.publish(args)
                self.assertEqual(state["writes"], ["chart"])
                self.assertEqual(state["chart"], chart.read_bytes())
            github.assert_not_called()

    def test_interrupted_oci_delivery_resumes_without_a_github_release(self):
        self.exercise()

    def test_conflicting_chart_or_operator_blocks_all_public_writes(self):
        for mutation in ("chart", "operator"):
            with self.subTest(mutation=mutation):
                self.exercise(mutation)


if __name__ == "__main__":
    unittest.main()

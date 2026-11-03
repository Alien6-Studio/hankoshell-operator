"""Chart documentation updates cannot silently replace application or runtime files."""
import copy
from contextlib import ExitStack
import hashlib
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


class ChartPublicationTest(unittest.TestCase):
    def exercise(self, mutation=None):
        """Exercise publication/retry with persistent storage and real API signatures."""
        config = chart_revision.configuration()
        revision, tag = "a" * 40, "chart-v" + config["chart_version"]
        state = {"release": None, "assets": {}, "chart": None, "writes": [], "interrupt": mutation is None}
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

        # Retain the real constructor: an omitted credential argument must fail.
        class GitHub(delivery.GitHub):
            def request(self, method, path, data=None, content_type="application/json"):
                assert self.token == "local-publication-fixture"
                if method == "GET":
                    assert "/releases?" in path
                    return [state["release"]] if state["release"] else []
                payload = json.loads(data)
                if method == "POST":
                    assert state["release"] is None and payload["draft"] is True
                    state["release"] = dict(payload, id=1)
                    state["writes"].append("draft")
                else:
                    assert method == "PATCH" and payload == {"draft": False, "make_latest": "false"}
                    assert set(state["assets"]) == set(expected_files)
                    state["release"].update(payload, published_at="2026-11-03T00:00:00Z")
                    state["writes"].append("publish")
                return state["release"]

            def assets(self, release):
                return [dict(name=name, id=name, state="uploaded" if value is not None else "starter",
                             size=len(value) if value is not None else 0) for name, value in state["assets"].items()]

            def asset(self, asset):
                return state["assets"][asset["name"]]

            def upload(self, release, path):
                assert path.name not in state["assets"]
                if state["interrupt"] and len(state["assets"]) == 1:
                    state["assets"][path.name] = None
                    state["interrupt"] = False
                    raise ConnectionError("fixture interrupted upload")
                state["assets"][path.name] = path.read_bytes()
                state["writes"].append("upload:" + path.name)

            def delete_incomplete(self, release, asset):
                assert release["draft"] and asset["state"] == "starter" and asset["size"] == 0
                del state["assets"][asset["name"]]

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary) / "delivery"
            dist, evidence = root / "dist", root / "release-evidence"
            dist.mkdir(parents=True)
            evidence.mkdir()
            chart = dist / ("hankoshell-operator-" + config["chart_version"] + ".tgz")
            metadata = yaml.safe_dump({"name": "hankoshell-operator", "version": config["chart_version"],
                                       "appVersion": config["operator_version"]}).encode()
            with tarfile.open(chart, "w:gz") as archive:
                entry = tarfile.TarInfo("hankoshell-operator/Chart.yaml")
                entry.size = len(metadata)
                archive.addfile(entry, io.BytesIO(metadata))
            (dist / "checksums.txt").write_text(hashlib.sha256(chart.read_bytes()).hexdigest())
            (evidence / "receipt.json").write_text("verified signing fixture")
            expected_files = {p.name: p.read_bytes() for folder in (dist, evidence) for p in folder.iterdir()}
            (root / "checkpoint.json").write_text(json.dumps(chart_revision.binding(root, config, revision)))
            if mutation == "chart":
                state["chart"] = b"other immutable published bytes"
            stack.enter_context(patch.object(chart_revision, "identity", return_value=(config, revision, tag)))
            stack.enter_context(patch.object(chart_revision, "verify_signatures"))
            stack.enter_context(patch.object(chart_revision.oci_security, "verify"))
            stack.enter_context(patch.object(delivery, "Registry", Registry))
            stack.enter_context(patch.object(delivery, "GitHub", GitHub))
            stack.enter_context(patch.dict(chart_revision.os.environ, GH_TOKEN="local-publication-fixture"))
            args = SimpleNamespace(root=root, oras=None, helm=None)
            if mutation:
                with self.assertRaises(ValueError):
                    chart_revision.publish(args)
                self.assertEqual(state["writes"], [])
                self.assertIsNone(state["release"])
                return
            with self.assertRaises(ConnectionError):
                chart_revision.publish(args)
            self.assertTrue(state["release"]["draft"])
            self.assertEqual(state["writes"].count("chart"), 1)
            retained = {name: value for name, value in state["assets"].items() if value is not None}
            chart_revision.publish(args)
            self.assertFalse(state["release"]["draft"])
            self.assertEqual(state["assets"], expected_files)
            self.assertEqual(state["writes"].count("chart"), 1)
            for name in retained:
                self.assertEqual(state["writes"].count("upload:" + name), 1)
            writes = list(state["writes"])
            chart_revision.publish(args)
            self.assertEqual(state["writes"], writes)

    def test_interrupted_delivery_resumes_without_replacing_chart_assets_or_latest_operator(self):
        self.exercise()

    def test_conflicting_chart_or_operator_blocks_all_public_writes(self):
        for mutation in ("chart", "operator"):
            with self.subTest(mutation=mutation):
                self.exercise(mutation)


if __name__ == "__main__":
    unittest.main()

import copy
from pathlib import Path
import tempfile
import unittest

import yaml

import api_conversion_contract as conversion
import storage_migration as migration
from test_storage_migration import NativeCluster


class ConversionContractTests(unittest.TestCase):
    def test_loss_or_semantic_change_in_either_version_is_rejected(self):
        contract = conversion.load()
        cluster = NativeCluster()
        for plural, source in cluster.crds.items():
            conversion.validate_crd(source, contract)
            for index in (0, 1):
                for change in ("field", "default", "validation", "topology", "subresource", "selector", "served", "storage"):
                    with self.subTest(plural=plural, index=index, change=change):
                        value = copy.deepcopy(source)
                        version = value["spec"]["versions"][index]
                        schema = version["schema"]["openAPIV3Schema"]
                        if change == "field": schema["properties"].pop("status")
                        elif change == "default": schema["properties"]["spec"]["properties"]["realmRef"]["default"] = "different"
                        elif change == "validation": schema["properties"]["spec"]["properties"]["realmRef"]["maxLength"] = 1
                        elif change == "topology": schema["x-kubernetes-validations"] = [{"rule": "false"}]
                        elif change == "subresource": version["subresources"] = {}
                        elif change == "selector": version["selectableFields"] = [{"jsonPath": ".spec.other"}]
                        elif change == "served": version["served"] = False
                        elif change == "storage": version["storage"] = not version["storage"]
                        with self.assertRaises(ValueError): conversion.validate_crd(value, contract)

    def test_upgrade_render_preserves_migrated_storage_and_never_writes(self):
        cluster = NativeCluster()
        for value in cluster.crds.values():
            for version in value["spec"]["versions"]:
                version["storage"] = version["name"] == "v1beta1"
            value["status"]["storedVersions"] = ["v1beta1"]
        with tempfile.TemporaryDirectory() as directory:
            for plural, live in cluster.crds.items():
                source = copy.deepcopy(live)
                source.pop("status")
                source["metadata"] = {"name": plural + ".hanko.sh"}
                for version in source["spec"]["versions"]:
                    version["storage"] = version["name"] == "v1alpha1"
                (Path(directory) / (plural + ".yaml")).write_text(yaml.safe_dump(source))
            rendered = migration.render_crds(cluster, Path(directory))
        self.assertEqual(len(rendered), 3)
        self.assertTrue(all(next(v["name"] for v in crd["spec"]["versions"] if v["storage"]) == "v1beta1" for crd in rendered))
        self.assertEqual(cluster.writes, [])

    def test_crd_downgrade_or_schema_rewrite_refuses_before_any_write(self):
        for change in ("stored", "served", "schema", "conversion", "identity"):
            cluster = NativeCluster()
            live = next(iter(cluster.crds.values()))
            if change == "stored": live["status"]["storedVersions"] = ["v1alpha1", "v1beta1"]
            source = copy.deepcopy(live)
            source.pop("status")
            source["metadata"] = {"name": live["metadata"]["name"]}
            if change in ("stored", "served"): source["spec"]["versions"].pop()
            elif change == "schema": source["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"].pop("status")
            elif change == "conversion": source["spec"]["conversion"] = {"strategy": "Webhook"}
            elif change == "identity": source["spec"]["names"]["kind"] = "Other"
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "crd.yaml").write_text(yaml.safe_dump(source))
                with self.subTest(change=change), self.assertRaises(migration.Refused):
                    migration.render_crds(cluster, Path(directory))
            self.assertEqual(cluster.writes, [])

    def test_new_reader_schema_cannot_escape_conversion_review_on_install(self):
        cluster = NativeCluster()
        source = copy.deepcopy(next(iter(cluster.crds.values())))
        source.pop("status")
        source["metadata"] = {"name": source["metadata"]["name"]}
        source["spec"]["versions"][1]["schema"]["openAPIV3Schema"]["properties"].pop("status")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "crd.yaml").write_text(yaml.safe_dump(source))
            with self.assertRaisesRegex(migration.Refused, "ConversionContractMismatch"):
                migration.render_crds(cluster, Path(directory))
        self.assertEqual(cluster.writes, [])


if __name__ == "__main__":
    unittest.main()

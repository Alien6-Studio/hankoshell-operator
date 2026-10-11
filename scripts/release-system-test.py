"""Exercise native OCI publication and interrupted retries in an isolated registry.

GitHub release storage is an in-memory service fixture; no GitHub write is made.
Signing, timestamping and vulnerability evidence come from the native rehearsal.
"""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import uuid

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location("release_publish", Path(__file__).with_name("release-publish.py"))
publish = module_from_spec(spec)
spec.loader.exec_module(publish)
REGISTRY_IMAGE = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"


class Releases(publish.NonpublishableGitHubFixture):
    def __init__(self, interrupted_after=None):
        self.current, self.stored = None, {}
        self.pending, self.partial_asset = {}, None
        self.writes, self.interrupted_after = 0, interrupted_after

    def wrote(self):
        self.writes += 1
        if self.writes == self.interrupted_after:
            raise ConnectionError("Fixture lost the successful write acknowledgement")

    def release(self, _tag):
        return copy.deepcopy(self.current)

    def assets(self, _release):
        return [{"id": name, "name": name, "state": "uploaded", "size": len(data)} for name, data in self.stored.items()] + list(self.pending.values())

    def asset(self, asset):
        return self.stored[asset["name"]]

    def create(self, tag, revision, notes):
        if self.current is not None:
            raise AssertionError("Duplicate draft creation")
        self.current = {"tag_name": tag, "target_commitish": revision,
                        "name": "v" + publish.contract.versioning.from_tag(tag),
                        "body": notes, "draft": True, "prerelease": "-" in publish.contract.versioning.from_tag(tag)}
        self.wrote()
        return copy.deepcopy(self.current)

    def upload(self, _release, path):
        if path.name in self.stored or path.name in self.pending:
            raise AssertionError("Release asset was uploaded twice")
        if path.name == self.partial_asset:
            self.partial_asset = None
            self.pending[path.name] = {"id": path.name, "name": path.name, "state": "starter", "size": 0}
            self.wrote()
            raise ConnectionError("Fixture failed upload left an empty starter asset")
        self.stored[path.name] = path.read_bytes()
        self.wrote()

    def delete_incomplete(self, release, asset):
        if not release["draft"] or asset["state"] != "starter" or asset["size"] != 0:
            raise AssertionError("Attempted deletion of a complete or published asset")
        del self.pending[asset["name"]]
        self.wrote()


class InterruptedRegistry:
    def __init__(self, registry, releases):
        self.registry, self.releases = registry, releases

    def __getattr__(self, name):
        target = getattr(self.registry, name)
        if name not in ("tag", "push_chart", "push_file"):
            return target
        def interrupted(*args, **kwargs):
            target(*args, **kwargs)
            self.releases.wrote()
        return interrupted


def qualify(output, archive, evidence, image, revision, oras, helm, attest, config):
    name = "hankoshell-release-system-" + uuid.uuid4().hex[:12]
    try:
        publish.run(["docker", "run", "--detach", "--name", name, "--publish", "127.0.0.1::5000",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", REGISTRY_IMAGE])
        address = publish.run(["docker", "port", name, "5000/tcp"])
        if not address.startswith("127.0.0.1:") or "\n" in address:
            raise ValueError("Registry fixture must bind only loopback")
        registry = publish.Registry(oras, helm, plain_http=True)
        local = "localhost:" + address.split(":")[1]
        digest = image.split("@")[1]
        publish.run([oras, "cp", "--from-oci-layout", str(archive) + "@" + digest,
                     "--to-plain-http", local + "/operator:staging"])
        root = output / "checkpoint"
        root.mkdir()
        for directory in ("dist", "release-evidence"):
            shutil.copytree(output / directory, root / directory)
        shutil.copyfile(archive, root / "image.tar")
        reference = local + "/operator:delivery-candidate-0.1.0-dev.0"
        publish.save(registry, reference, root, "0.1.0-dev.0", revision, image)
        committed = registry.resolve(reference)
        # Simulate an interrupted save whose registry acknowledgement was lost.
        publish.save(registry, reference, root, "0.1.0-dev.0", revision, image)
        if registry.resolve(reference) != committed:
            raise ValueError("Retry replaced the committed checkpoint")
        with tempfile.TemporaryDirectory() as temp:
            restored = Path(temp) / "delivery"
            publish.restore(registry, reference, restored, "0.1.0-dev.0", revision)
            publish.verify_attest(restored, attest, config)
            if publish.hashes(restored) != publish.hashes(root):
                raise ValueError("Restored delivery differs from signed bytes")
            try:
                publish.verify_checkpoint(restored, "0.1.0-dev.0", "0" * 40)
            except ValueError:
                pass
            else:
                raise ValueError("Checkpoint from another source revision was accepted")
            releases = Releases(None)
            transport = InterruptedRegistry(registry, releases)
            try:
                publish.promote(transport, releases, restored, image_repository=local + "/operator",
                                chart_repository=local + "/charts/hankoshell-operator", fresh_evidence=evidence)
            except ValueError as error:
                if "blocked" not in str(error) or releases.writes:
                    raise
            else:
                raise ValueError("Development checkpoint was accepted by production promotion")
            # Native ORAS/Helm writes plus every GitHub fixture write. Inject a
            # loss AFTER each write, then retry and require zero repeated writes.
            count = 4 + len(list((root / "dist").iterdir())) + len(list((root / "release-evidence").iterdir()))
            for interruption in range(1, count + 1):
                releases = Releases(interruption)
                transport = InterruptedRegistry(registry, releases)
                image_repo = local + f"/operator-{interruption}"
                chart_repo = local + f"/charts-{interruption}/hankoshell-operator"
                publish.run([oras, "cp", "--from-plain-http", local + "/operator@" + digest,
                             "--to-plain-http", image_repo + ":staging"])
                args = {"image_repository": image_repo, "chart_repository": chart_repo, "fresh_evidence": evidence}
                try:
                    publish.rehearse_promotion(transport, releases, restored, **args)
                except ConnectionError:
                    pass
                else:
                    raise ValueError("Interruption point was not exercised")
                releases.interrupted_after = None
                publish.rehearse_promotion(transport, releases, restored, **args)
                writes = releases.writes
                if releases.current["tag_name"] != "v0.1.0-dev.0" or releases.current["name"] != "v0.1.0-dev.0":
                    raise ValueError("Development fixture tag or display name differs")
                publish.rehearse_promotion(transport, releases, restored, **args)
                if releases.writes != writes or writes != count:
                    raise ValueError("Retry repeated an already completed external write")
                # A manually published, matching release is also a read-only retry.
                releases.current["draft"] = False
                publish.rehearse_promotion(transport, releases, restored, **args)
                if releases.writes != writes:
                    raise ValueError("Retry mutated a published release")
            # GitHub 502 may leave a zero-byte starter row. Exercise both the
            # failed upload and a lost acknowledgement after safe placeholder
            # deletion, then prove recovery and subsequent read-only retry.
            for filename in ("checksums.sigstore.json", "hankoshell-operator-attest.tar.gz"):
                releases = Releases()
                releases.partial_asset = filename
                transport = InterruptedRegistry(registry, releases)
                try:
                    publish.rehearse_promotion(transport, releases, restored, **args)
                except ConnectionError:
                    pass
                else:
                    raise ValueError("Incomplete upload was not exercised")
                releases.interrupted_after = releases.writes + 1
                try:
                    publish.rehearse_promotion(transport, releases, restored, **args)
                except ConnectionError:
                    pass
                else:
                    raise ValueError("Interrupted placeholder deletion was not exercised")
                releases.interrupted_after = None
                publish.rehearse_promotion(transport, releases, restored, **args)
                writes = releases.writes
                publish.rehearse_promotion(transport, releases, restored, **args)
                if releases.pending or releases.writes != writes:
                    raise ValueError("Incomplete upload recovery was not idempotent")
            # Conflicting existing asset must fail before any registry/GitHub write.
            releases.current["draft"] = True
            for field, wrong in (("tag_name", "v0.1.0"), ("name", "release/v0.1.0-dev.0"),
                                 ("target_commitish", "0" * 40)):
                original = releases.current[field]
                releases.current[field] = wrong
                try:
                    publish.rehearse_promotion(transport, releases, restored, **args)
                except ValueError:
                    pass
                else:
                    raise ValueError("Conflicting release identity was accepted: " + field)
                finally:
                    releases.current[field] = original
                if releases.writes != writes:
                    raise ValueError("Release identity conflict produced a publication write")
            releases.stored["image-digest.txt"] = b"tampered\n"
            try:
                publish.rehearse_promotion(transport, releases, restored, **args)
            except ValueError:
                pass
            else:
                raise ValueError("Conflicting existing asset was accepted")
            if releases.writes != writes:
                raise ValueError("Conflict produced a publication write")
            # A conflicting image tag must be detected before chart/catalog or
            # release mutations, even when it exists under the expected version.
            conflict = local + "/conflicting-operator"
            fake = Path(temp) / "fake-image"
            fake.write_bytes(b"unrelated OCI artifact")
            registry.push_file(conflict + ":0.1.0-dev.0", fake, "application/octet-stream")
            try:
                publish.rehearse_promotion(transport, releases, restored, image_repository=conflict,
                                chart_repository=chart_repo, fresh_evidence=evidence)
            except ValueError:
                pass
            else:
                raise ValueError("Conflicting versioned image digest was accepted")
            if releases.writes != writes:
                raise ValueError("Image conflict produced a publication write")
            # A historical signed delivery is retained unchanged, but cannot
            # substitute for a fresh current-policy scan on a resumed attempt.
            stale = Path(temp) / "stale-scan"
            shutil.copytree(evidence, stale)
            summary = json.loads((stale / "oci-security.json").read_text())
            summary["scanned_at"] = "2020-01-01T00:00:00+00:00"
            (stale / "oci-security.json").write_text(json.dumps(summary))
            try:
                publish.rehearse_promotion(transport, releases, restored, image_repository=image_repo,
                                chart_repository=chart_repo, fresh_evidence=stale)
            except ValueError:
                pass
            else:
                raise ValueError("Stale scan permitted publication")
        (output / "publication-system.json").write_text(json.dumps({
            "publishable": False, "image": image, "revision": revision,
            "native_registry_and_helm": "pass", "checkpoint_restore_and_attest_recompute": "pass",
            "lost_acknowledgement_points": count, "idempotent_retries": "pass", "conflict_rejection": "pass",
            "empty_starter_upload_and_interrupted_deletion_recovery": "pass",
            "release_identity": {"product_version": "0.1.0-dev.0", "fixture_tag": "v0.1.0-dev.0", "prerelease": True,
                                 "target_public_version": "0.1.0", "future_git_ref": "refs/tags/v0.1.0",
                                 "github_release_name": releases.current["name"], "chart_version": "0.1.0-dev.0",
                                 "image_tag": "0.1.0-dev.0"},
            "release_identity_conflict_rejection": "pass",
            "production_development_rejection": "pass",
            "limitations": ["loopback OCI fixture; no public registry or Artifact Hub indexing",
                            "GitHub release/asset storage fixture; no production API or OIDC qualification"],
        }, indent=2) + "\n")
    finally:
        publish.run(["docker", "rm", "--force", name])

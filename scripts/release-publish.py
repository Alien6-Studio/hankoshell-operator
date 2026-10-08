"""Resume a verified delivery without replacing versioned OCI content or assets."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_contract", ROOT / "scripts/release-contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
attest = contract.module("attest_release", "attest-release.py")
REPOSITORY = "Alien6-Studio/hankoshell-operator"
IMAGE = contract.metadata.IMAGE
CHART = "ghcr.io/alien6-studio/charts/hankoshell-operator"
MAX_CHECKPOINT = 2 * 1024**3


def run(command, **kwargs):
    result = subprocess.run([str(value) for value in command], capture_output=True, timeout=600, **kwargs)
    if result.returncode:
        # Tool output can include credentials. Do not echo it into Actions logs.
        raise RuntimeError(f"{Path(str(command[0])).name} {command[1]} failed")
    return result.stdout.decode().strip()


class Registry:
    def __init__(self, oras, helm, *, plain_http=False):
        self.oras, self.helm = oras, helm
        # Only the isolated system-test registry uses cleartext, never production.
        self.flags = ["--plain-http"] if plain_http else []

    def resolve(self, reference):
        result = subprocess.run([str(self.oras), "resolve", *self.flags, reference], capture_output=True, timeout=120)
        if result.returncode:
            # Treat only an explicit registry MANIFEST_UNKNOWN / HTTP 404 as absence.
            # Authentication, TLS, network and throttling errors must stop publication.
            missing = ("Error response from registry: failed to resolve digest: " + reference + ": not found").encode()
            if result.stderr.strip() == missing:
                return None
            raise RuntimeError("Registry lookup failed; absence was not established")
        digest = result.stdout.decode().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid registry digest")
        return digest

    def pull(self, reference, output):
        run([self.oras, "pull", *self.flags, reference, "--output", output])

    def push_file(self, reference, path, media_type, config=None):
        command = [self.oras, "push", *self.flags, reference]
        if config:
            command += ["--config", config]
        command += [path.name + ":" + media_type]
        run(command, cwd=path.parent)

    def tag(self, reference, version):
        run([self.oras, "tag", *self.flags, reference, version])

    def push_chart(self, path, chart):
        run([self.helm, "push", path, "oci://" + chart.rsplit("/", 1)[0], *self.flags])

    def file_matches(self, reference, digest, expected):
        repository = reference.rsplit(":", 1)[0]
        manifest = json.loads(run([self.oras, "manifest", "fetch", *self.flags, repository + "@" + digest]))
        layers = manifest.get("layers", [])
        chart = expected.suffix == ".tgz"
        media_type = "application/vnd.cncf.helm.chart.content.v1.tar+gzip" if chart else "application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml"
        if (len(layers) != 1 or layers[0]["mediaType"] != media_type or layers[0]["size"] != expected.stat().st_size
                or layers[0]["digest"] != "sha256:" + contract.security.sha256(expected)):
            return False
        with tempfile.TemporaryDirectory() as temp:
            payload = Path(temp) / "payload"
            run([self.oras, "blob", "fetch", *self.flags, repository + "@" + layers[0]["digest"], "--output", payload])
            if payload.read_bytes() != expected.read_bytes():
                return False
            if chart:
                if manifest["config"]["mediaType"] != "application/vnd.cncf.helm.config.v1+json":
                    return False
                run([self.oras, "blob", "fetch", *self.flags, repository + "@" + manifest["config"]["digest"], "--output", payload])
                metadata = json.loads(payload.read_text())
                if metadata.get("name") != "hankoshell-operator" or metadata.get("version") != contract.VERSION or metadata.get("appVersion") != contract.VERSION:
                    return False
        return True


def hashes(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError("Unexpected delivery filesystem entry")
        if path.is_file() and path.name != "checkpoint.json":
            result[path.relative_to(root).as_posix()] = contract.security.sha256(path)
    return result


def checkpoint(root, version, revision, image):
    contract.check(version)
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("Unexpected delivery identity")
    return {"schema": 1, "version": version, "revision": revision, "image": image,
            "files": hashes(root)}


def verify_checkpoint(root, version, revision):
    record = json.loads((root / "checkpoint.json").read_text())
    if record != checkpoint(root, version, revision, record["image"]):
        raise ValueError("Release checkpoint content or identity changed")
    expected = {"image.tar"} | {"dist/" + name for name in attest.delivery_files(
        root / "dist", version, revision, record["image"], fresh_scan=False)} | {
        "release-evidence/attest-verification.json", "release-evidence/hankoshell-operator-attest.tar.gz"}
    if set(record["files"]) != expected:
        raise ValueError("Unexpected checkpoint artifacts")
    contract.security.verify(root / "dist", revision, version, record["image"].split("@")[1],
                             root / "image.tar", fresh=False)
    return record


def extract(archive, output):
    if output.exists():
        raise ValueError("Checkpoint extraction requires fresh output")
    with tarfile.open(archive) as package:
        members = package.getmembers()
        names = set()
        for member in members:
            path = Path(member.name)
            if (not member.isfile() or path.as_posix() != member.name or path.is_absolute() or ".." in path.parts
                    or member.name in names or member.size > MAX_CHECKPOINT):
                raise ValueError("Unsafe checkpoint archive")
            names.add(member.name)
        if sum(member.size for member in members) > MAX_CHECKPOINT:
            raise ValueError("Checkpoint archive exceeds the size budget")
        output.mkdir(parents=True)
        package.extractall(output, filter="data")


def restore(registry, reference, output, version, revision):
    digest = registry.resolve(reference)
    if digest is None:
        return None
    with tempfile.TemporaryDirectory() as temp:
        downloaded = Path(temp)
        # Resolve once, then pull by immutable digest, never by a moving tag.
        repository = reference.split("@", 1)[0] if "@" in reference else reference.rsplit(":", 1)[0]
        registry.pull(repository + "@" + digest, downloaded)
        if {path.name for path in downloaded.iterdir()} != {"delivery.tar"}:
            raise ValueError("Unexpected checkpoint OCI layers")
        extract(downloaded / "delivery.tar", output)
    return verify_checkpoint(output, version, revision)


def save(registry, reference, root, version, revision, image):
    record = checkpoint(root, version, revision, image)
    (root / "checkpoint.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    verify_checkpoint(root, version, revision)
    # Workflow concurrency serializes cooperating releases. Never overwrite an
    # already committed candidate, including after a lost push acknowledgement.
    with tempfile.TemporaryDirectory() as temp:
        existing = restore(registry, reference, Path(temp) / "existing", version, revision)
        if existing is not None:
            if existing != record:
                raise ValueError("Another delivery is already committed for this version")
            return
        archive = Path(temp) / "delivery.tar"
        with tarfile.open(archive, "w") as package:
            for name in ["checkpoint.json", *sorted(record["files"])]:
                package.add(root / name, arcname=name, recursive=False)
        registry.push_file(reference, archive, "application/vnd.hankoshell.release.checkpoint.v1.tar")
        stored = restore(registry, reference, Path(temp) / "stored", version, revision)
        if stored != record:
            raise ValueError("Stored delivery checkpoint differs")


def verify_attest(root, tool, config):
    record = verify_checkpoint(root, contract.VERSION, json.loads((root / "checkpoint.json").read_text())["revision"])
    if (root / "dist" / attest.PUBLIC_KEY_FILE).read_text() != attest.public_key_pem(config["PUBLIC_KEY"]):
        raise ValueError("Checkpoint signer is not the configured trusted Attest signer")
    with tempfile.TemporaryDirectory() as temp:
        workspace = Path(temp) / "workspace"
        # The delivery evidence tar contains directories as well as files.
        with tarfile.open(root / "release-evidence/hankoshell-operator-attest.tar.gz") as package:
            members = package.getmembers()
            allowed = {"attest.yaml", "receipt.yaml", "delivery", "delivery/manifest.json"} | {
                "delivery/" + path.name for path in (root / "dist").iterdir()}
            if {member.name for member in members} != allowed:
                raise ValueError("Unexpected files or private material in the Attest workspace")
            if any(not (m.isdir() or m.isfile()) or Path(m.name).is_absolute() or ".." in Path(m.name).parts for m in members):
                raise ValueError("Unsafe Attest workspace")
            if sum(m.size for m in members) > 64 * 1024**2 or len({m.name for m in members}) != len(members):
                raise ValueError("Invalid Attest workspace size or duplicate entries")
            package.extractall(workspace, filter="data")
        if (workspace / "attest.yaml").read_bytes() != (ROOT / "attest.yaml").read_bytes():
            raise ValueError("Checkpoint uses a different Attest verification pipeline")
        delivery = workspace / "delivery"
        if set(path.name for path in delivery.iterdir()) != set(path.name for path in (root / "dist").iterdir()) | {"manifest.json"}:
            raise ValueError("Unexpected Attest delivery artifacts")
        for path in (root / "dist").iterdir():
            if (delivery / path.name).read_bytes() != path.read_bytes():
                raise ValueError("Attest receipt does not bind the restored distribution")
        manifest = json.loads((delivery / "manifest.json").read_text())
        if manifest.get("repository") != REPOSITORY or manifest.get("scope") != "verified-release-delivery; build not supervised by Attest":
            raise ValueError("Unexpected Attest repository or evidence scope")
        if any(manifest[key] != record[field] for key, field in (("source_revision", "revision"), ("image", "image"), ("version", "version"))):
            raise ValueError("Attest manifest identity differs")
        trust = workspace / ".attest/trust"
        (trust / "tsa").mkdir(parents=True)
        (trust / f'{config["KEY_ID"]}.pub').write_text(attest.public_key_pem(config["PUBLIC_KEY"]))
        (trust / "trust.toml").write_text('version = 1\n\n[[key]]\n' + f'id = "{config["KEY_ID"]}"\nname = "hankoShell Operator release"\nstatus = "trusted"\n')
        (trust / "tsa/issuer.crt").write_text(config["TSA_CERTIFICATE"])
        receipt = workspace / "receipt.yaml"
        verdict = json.loads(run([tool, "verify", receipt, "--recompute", "--workspace", workspace,
                                  "--trust-store", trust, "--offline", "--format", "json"]))
        attest.validate_verdict(verdict, config["PUBLIC_KEY"], receipt)


class GitHub:
    def __init__(self, token, api="https://api.github.com"):
        self.token, self.api = token, api

    def request(self, method, path, data=None, content_type="application/json"):
        url = path if path.startswith("https://") else self.api + path
        endpoint = urlsplit(url)
        if (endpoint.scheme != "https" or endpoint.hostname not in ("api.github.com", "uploads.github.com")
                or endpoint.username or endpoint.password or endpoint.fragment or endpoint.port not in (None, 443)):
            raise ValueError("Unexpected GitHub credential destination")
        # Never follow redirects carrying the administrative GitHub credential.
        # Asset verification uses its API endpoint with Accept: octet-stream;
        # the redirect is fetched separately, without the Authorization header.
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "Content-Type": content_type}
        if content_type == "application/octet-stream" and method == "GET":
            headers["Accept"] = content_type
        budget = 64 * 1024**2 if headers["Accept"] == "application/octet-stream" else 1024**2
        from urllib.request import HTTPRedirectHandler, build_opener
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        request = Request(url, data=data, headers=headers, method=method)
        try:
            response = build_opener(NoRedirect()).open(request, timeout=120)
        except HTTPError as error:
            if method == "GET" and error.code == 404:
                return None
            if method == "GET" and error.code == 302 and headers["Accept"] == "application/octet-stream":
                location = error.headers["Location"]
                redirect = urlsplit(location)
                if redirect.scheme != "https" or redirect.username or redirect.password or redirect.fragment:
                    raise ValueError("Unsafe release asset redirect")
                with build_opener(NoRedirect()).open(location, timeout=120) as response:
                    body = response.read(budget + 1)
                if len(body) > budget:
                    raise ValueError("GitHub asset exceeds the size budget")
                return body
            raise RuntimeError("GitHub API request failed") from None
        with response:
            body = response.read(budget + 1)
        if len(body) > budget:
            raise ValueError("GitHub API response exceeds the size budget")
        return body if headers["Accept"] == "application/octet-stream" else json.loads(body) if body else None

    def release(self, tag):
        return self.request("GET", f"/repos/{REPOSITORY}/releases/tags/{tag}")

    def assets(self, release):
        result = []
        page = 1
        while True:
            chunk = self.request("GET", f'/repos/{REPOSITORY}/releases/{release["id"]}/assets?per_page=100&page={page}')
            result.extend(chunk)
            if len(chunk) < 100:
                return result
            page += 1
            if page > 10:
                raise ValueError("Unexpected release asset count")

    def asset(self, asset):
        return self.request("GET", f'/repos/{REPOSITORY}/releases/assets/{asset["id"]}', content_type="application/octet-stream")

    def create(self, tag, revision, notes):
        payload = {"tag_name": tag, "target_commitish": revision, "name": f"hankoShell Operator {tag}",
                   "body": notes, "draft": True, "prerelease": False}
        return self.request("POST", f"/repos/{REPOSITORY}/releases", json.dumps(payload).encode())

    def upload(self, release, path):
        from urllib.parse import quote
        url = release["upload_url"].split("{")[0] + "?name=" + quote(path.name)
        self.request("POST", url, path.read_bytes(), "application/octet-stream")

    def delete_incomplete(self, release, asset):
        if not release["draft"] or asset.get("state") != "starter" or asset.get("size") != 0:
            raise ValueError("Only an empty failed-upload placeholder in a draft may be deleted")
        self.request("DELETE", f'/repos/{REPOSITORY}/releases/assets/{asset["id"]}')


def matching_file(registry, reference, expected):
    digest = registry.resolve(reference)
    if digest is None:
        return False
    if not registry.file_matches(reference, digest, expected):
        raise ValueError("Existing OCI artifact differs; versioned content must not be replaced")
    return True


def promote(registry, github, root, *, image_repository=IMAGE, chart_repository=CHART, fresh_evidence=None):
    record = verify_checkpoint(root, contract.VERSION, json.loads((root / "checkpoint.json").read_text())["revision"])
    # A historical signed report is not a current security gate. Every attempt
    # must also pass a fresh scan of the committed archive under today's policy.
    digest = record["image"].split("@")[1]
    contract.security.verify(fresh_evidence or root.parent / "fresh-scan", record["revision"], record["version"], digest, root / "image.tar")
    version, dist = record["version"], root / "dist"
    tag = "v" + version
    image_tag, chart_tag = image_repository + ":" + version, chart_repository + ":" + version
    metadata_tag = chart_repository + ":artifacthub.io"
    chart = dist / f"hankoshell-operator-{version}.tgz"
    files = {path.name: path for directory in (dist, root / "release-evidence") for path in directory.iterdir()}
    # Complete preflight before the first publication write. An existing,
    # conflicting artifact or release is an error, not permission to overwrite.
    existing_image = registry.resolve(image_tag)
    if existing_image not in (None, digest):
        raise ValueError("Existing versioned image has a different digest")
    chart_exists = matching_file(registry, chart_tag, chart)
    metadata_exists = matching_file(registry, metadata_tag, dist / "artifacthub-repo.yml")
    release = github.release(tag)
    existing_assets = {}
    incomplete_assets = {}
    if release:
        if (release["tag_name"] != tag or release["target_commitish"] != record["revision"] or release["name"] != f"hankoShell Operator {tag}"
                or release["body"] != contract.notes(version) or release["prerelease"]):
            raise ValueError("Existing release metadata differs")
        for asset in github.assets(release):
            if asset["name"] not in files or asset["name"] in existing_assets or asset["name"] in incomplete_assets:
                raise ValueError("Unexpected release asset")
            if release["draft"] and asset.get("state") == "starter" and asset.get("size") == 0:
                incomplete_assets[asset["name"]] = asset
                continue
            if asset.get("state") != "uploaded" or asset.get("size") != files[asset["name"]].stat().st_size:
                raise ValueError("Existing release asset is incomplete or has a conflicting size")
            if hashlib.sha256(github.asset(asset)).hexdigest() != contract.security.sha256(files[asset["name"]]):
                raise ValueError("Existing release asset differs")
            existing_assets[asset["name"]] = asset
        if not release["draft"]:
            if set(existing_assets) != set(files) or not (existing_image and chart_exists and metadata_exists):
                raise ValueError("A published release is incomplete; automatic mutation is forbidden")
            return
    if existing_image is None:
        registry.tag(image_repository + "@" + digest, version)
    if registry.resolve(image_tag) != digest:
        raise ValueError("Image promotion did not retain the scanned digest")
    if not chart_exists:
        registry.push_chart(chart, chart_repository)
        if not matching_file(registry, chart_tag, chart):
            raise ValueError("Chart publication was not acknowledged")
    if not metadata_exists:
        registry.push_file(metadata_tag, dist / "artifacthub-repo.yml",
            "application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml",
            "/dev/null:application/vnd.cncf.artifacthub.config.v1+yaml")
        if not matching_file(registry, metadata_tag, dist / "artifacthub-repo.yml"):
            raise ValueError("Catalog metadata publication was not acknowledged")
    if release is None:
        release = github.create(tag, record["revision"], contract.notes(version))
    for name, path in sorted(files.items()):
        if name in incomplete_assets:
            # GitHub documents this empty starter state after a failed upload.
            # No complete asset is ever deleted or clobbered. A lost DELETE
            # acknowledgement is recovered by absence on the next preflight.
            github.delete_incomplete(release, incomplete_assets[name])
        if name not in existing_assets:
            github.upload(release, path)
    # Read back all assets; a lost acknowledgement is recoverable on retry.
    assets = github.assets(release)
    if {asset["name"] for asset in assets} != set(files) or len(assets) != len(files):
        raise ValueError("Incomplete release assets")
    if any(hashlib.sha256(github.asset(asset)).hexdigest() != contract.security.sha256(files[asset["name"]]) for asset in assets):
        raise ValueError("Release asset upload changed content")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("restore", "manifest", "save", "verify-attest", "promote"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--version", default=contract.VERSION)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--image")
    parser.add_argument("--candidate-digest", default="")
    parser.add_argument("--oras", type=Path, required=True)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument("--attest", type=Path)
    args = parser.parse_args()
    registry = Registry(args.oras, args.helm)
    reference = IMAGE + ":delivery-candidate-" + args.version
    if args.mode == "restore":
        candidate = args.candidate_digest or registry.resolve(reference)
        if candidate and not re.fullmatch(r"sha256:[0-9a-f]{64}", candidate):
            raise ValueError("Invalid checkpoint manifest digest")
        record = restore(registry, IMAGE + "@" + candidate, args.root, args.version, args.revision) if candidate else None
        if args.candidate_digest and record is None:
            raise ValueError("The selected immutable release checkpoint is missing")
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write("restored=" + str(record is not None).lower() + "\n")
            if record:
                output.write("digest=" + record["image"].split("@")[1] + "\n")
                output.write("candidate_digest=" + candidate + "\n")
    elif args.mode == "manifest":
        record = checkpoint(args.root, args.version, args.revision, args.image)
        (args.root / "checkpoint.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        verify_checkpoint(args.root, args.version, args.revision)
    elif args.mode == "save":
        save(registry, reference, args.root, args.version, args.revision, args.image)
    elif args.mode == "verify-attest":
        config = {name: os.environ["HANKOSHELL_ATTEST_" + name] for name in ("KEY_ID", "PUBLIC_KEY", "TSA_CERTIFICATE")}
        verify_attest(args.root, args.attest, config)
    else:
        promote(registry, GitHub(os.environ["GH_TOKEN"]), args.root)


if __name__ == "__main__":
    main()

"""Nonpublishing release rehearsal with ephemeral local signing and RFC 3161 trust."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Thread
from types import SimpleNamespace

from importlib.util import module_from_spec, spec_from_file_location

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = spec_from_file_location(name, ROOT / "scripts" / filename)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


contract = load("release_contract", "release-contract.py")
attest = load("attest_release", "attest-release.py")
FIXTURE_REPOSITORY_ID = "8d452bd5-e2f7-47b6-94f1-c3b2ac7b4aac"


def run(command, **kwargs):
    # Do not print private fixture keys or tool output that may contain them.
    return subprocess.run([str(value) for value in command], check=True,
                          capture_output=True, timeout=120, **kwargs)


def verify_blob(openssl, public_key, bundle_path, payload, signature_path):
    bundle = json.loads(bundle_path.read_text())
    if bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ValueError("Unexpected cosign bundle format")
    signature = bundle["messageSignature"]
    digest = signature["messageDigest"]
    if digest["algorithm"] != "SHA2_256" or base64.b64decode(digest["digest"], validate=True) != hashlib.sha256(payload.read_bytes()).digest():
        raise ValueError("Cosign fixture signature is bound to another payload")
    material = bundle["verificationMaterial"]
    if material.get("tlogEntries") or material.get("timestampVerificationData"):
        raise ValueError("The fixture must not write to public transparency/timestamp services")
    signature_path.write_bytes(base64.b64decode(signature["signature"], validate=True))
    run([openssl, "dgst", "-sha256", "-verify", public_key, "-signature", signature_path, payload])


@contextmanager
def timestamp_authority(openssl, private):
    key, cert = private / "tsa.key", private / "tsa.crt"
    run([openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-sha256",
         "-subj", "/CN=hankoShell nonpublishable rehearsal TSA",
         "-addext", "basicConstraints=critical,CA:false",
         "-addext", "keyUsage=critical,digitalSignature",
         "-addext", "extendedKeyUsage=critical,timeStamping"])
    (private / "serial").write_text("01\n")
    config = private / "tsa.conf"
    config.write_text(
        "[tsa]\ndefault_tsa=fixture\n[fixture]\n"
        f"serial={private / 'serial'}\nsigner_cert={cert}\nsigner_key={key}\n"
        "signer_digest=sha256\ndefault_policy=1.2.3.4.1\nother_policies=1.2.3.4.1\n"
        "digests=sha256,sha384,sha512\naccuracy=secs:1\nordering=yes\ntsa_name=yes\n"
        "ess_cert_id_chain=no\ness_cert_id_alg=sha256\n")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                self.send_error(400)
                return
            query, reply = private / "query.tsq", private / "reply.tsr"
            query.write_bytes(self.rfile.read(length))
            try:
                run([openssl, "ts", "-reply", "-config", config, "-queryfile", query, "-out", reply])
                data = reply.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except subprocess.CalledProcessError:
                self.send_error(500)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", cert
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def rehearse(args):
    if args.output.exists():
        raise ValueError("Rehearsal output must be fresh")
    if not run([args.openssl, "version"]).stdout.decode().startswith("OpenSSL 3."):
        raise ValueError("The RFC 3161 fixture requires OpenSSL 3")
    version_info = run([args.cosign, "version", "--json"]).stdout
    if json.loads(version_info)["gitVersion"] != "v3.1.3":
        raise ValueError("Expected the pinned cosign 3.1.3 tool")
    args.output.mkdir(parents=True)
    args.output.chmod(0o700)
    dist = args.output / "dist"
    image = contract.metadata.IMAGE + "@" + args.digest
    with tempfile.TemporaryDirectory(prefix="hankoshell-rehearsal-private-") as temp:
        private = Path(temp)
        # No production secrets or OIDC identity are needed or consumed here.
        env = {name: value for name, value in os.environ.items()
               if not name.startswith(("HANKOSHELL_ATTEST_", "ACTIONS_ID_TOKEN_"))}
        env["COSIGN_PASSWORD"] = ""
        signing = private / "signing.json"
        signing.write_text(json.dumps({"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json"}))
        trusted = private / "root.json"
        trusted.write_text(json.dumps({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}))
        prefix = private / "cosign"
        run([args.cosign, "generate-key-pair", "--output-key-prefix", prefix], env=env)
        key = private / "attest.key"
        run([args.openssl, "genpkey", "-algorithm", "ED25519", "-out", key])
        public_der = run([args.openssl, "pkey", "-in", key, "-pubout", "-outform", "DER"]).stdout
        public_key = public_der[-32:].hex()
        key_id = hashlib.sha256(public_der[-32:]).hexdigest()[:32]
        contract.prepare(args.version, image, args.revision, args.archive, args.evidence,
                         args.output / "chart/hankoshell-operator", dist, args.helm,
                         FIXTURE_REPOSITORY_ID, public_key)
        run([args.cosign, "sign-blob", "--yes", "--key", str(prefix) + ".key",
             "--signing-config", signing, "--trusted-root", trusted,
             "--bundle", dist / "checksums.sigstore.json", dist / "checksums.txt"], env=env)
        shutil.copyfile(str(prefix) + ".pub", args.output / "cosign-fixture.pub")
        verify_blob(args.openssl, args.output / "cosign-fixture.pub", dist / "checksums.sigstore.json",
                    dist / "checksums.txt", private / "signature")
        original = (dist / "checksums.txt").read_bytes()
        (dist / "checksums.txt").write_bytes(original + b"tamper\n")
        try:
            verify_blob(args.openssl, args.output / "cosign-fixture.pub", dist / "checksums.sigstore.json",
                        dist / "checksums.txt", private / "signature")
        except ValueError:
            pass
        else:
            raise ValueError("Tampered signed checksums were accepted")
        finally:
            (dist / "checksums.txt").write_bytes(original)
        with timestamp_authority(args.openssl, private) as (tsa_url, tsa_cert):
            shutil.copyfile(tsa_cert, args.output / "tsa-fixture.crt")
            workspace = args.output / "attest-workspace"
            signing_args = SimpleNamespace(attest=args.attest, dist=dist, workspace=workspace,
                                           output=args.output / "release-evidence", revision=args.revision,
                                           version=args.version, image=image,
                                           run_url="nonpublishable-local-release-rehearsal")
            attest.sign_delivery(signing_args, {
                "KEY_ID": key_id, "PUBLIC_KEY": public_key, "SIGNING_KEY": key.read_text(),
                "TSA_URL": tsa_url, "TSA_CERTIFICATE": tsa_cert.read_text(),
            })
            payload = workspace / "delivery/image-digest.txt"
            original = payload.read_bytes()
            payload.write_bytes(original + b"tamper\n")
            try:
                verification = subprocess.run([str(args.attest), "verify", str(workspace / "receipt.yaml"),
                    "--recompute", "--workspace", str(workspace), "--trust-store", str(workspace / ".attest/trust"),
                    "--offline", "--format", "json"], capture_output=True, timeout=120, check=False)
                if verification.returncode == 0:
                    raise ValueError("Tampered Attest delivery was accepted")
            finally:
                payload.write_bytes(original)
        if list(args.output.rglob("*.key")):
            raise ValueError("Private signing material leaked into rehearsal artifacts")
    report = {
        "publishable": False, "version": args.version, "maturity": "initial development; normal SemVer",
        "revision": args.revision, "image": image,
        "signing_intent": {"oidc_issuer": "https://token.actions.githubusercontent.com",
                           "certificate_identity": f"https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v{args.version}"},
        "checks": {"archive_sbom_provenance_scan_binding": "pass", "chart_and_checksums": "pass",
                   "cosign_local_signature_and_tamper": "pass", "attest_five_checks_and_tamper": "pass"},
        "artifacts": sorted(path.name for path in dist.iterdir()),
        "limitations": ["ephemeral local key/TSA and fixture Artifact Hub ID; not production trust",
                        "no image registry signing, GitHub OIDC, registry promotion or Artifact Hub indexing"],
    }
    (args.output / "dry-run.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Nonpublishable release rehearsal passed; no tag, registry write or GitHub Release created.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "helm", "cosign", "attest", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--version", default=contract.VERSION)
    args = parser.parse_args()
    for name in ("archive", "evidence", "output", "helm", "cosign", "attest", "openssl"):
        setattr(args, name, getattr(args, name).resolve())
    rehearse(args)


if __name__ == "__main__":
    main()

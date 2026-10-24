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

from tools.qualification.checks import release_contract as contract
from tools.release import attest_release as attest
from tools.qualification.scenarios import release_system_test as publication

ROOT = Path(__file__).resolve().parents[2]


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
            if self.path != "/":
                self.send_error(404)
                return
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
    if json.loads(version_info)["gitVersion"] != contract.pins.DATA["tools"]["cosign"]["version"]:
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
        key_id = attest.key_id(args.attest, public_key)
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
            signing_args = SimpleNamespace(attest=args.attest, openssl=args.openssl, dist=dist, workspace=workspace,
                                           output=args.output / "release-evidence", revision=args.revision,
                                           version=args.version, image=image,
                                           run_url="nonpublishable-local-release-rehearsal")
            config = {
                "KEY_ID": key_id, "PUBLIC_KEY": public_key, "SIGNING_KEY": key.read_text(),
                "TSA_URL": tsa_url, "TSA_CERTIFICATE": tsa_cert.read_text(),
            }
            other_private = run([args.openssl, "genpkey", "-algorithm", "ED25519"]).stdout.decode()
            # Native trust checks must reject syntactically valid but unrelated
            # identities, not just malformed/missing environment variables.
            for field, wrong in (("KEY_ID", hashlib.sha256(public_der[-32:]).hexdigest()[:32]),
                                 ("PUBLIC_KEY", "0" * 64),
                                 ("SIGNING_KEY", other_private),
                                 ("SIGNING_KEY", "-----BEGIN " "PRIVATE KEY-----\ninvalid\n"),
                                 ("TSA_CERTIFICATE", "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")):
                try:
                    attest.validate_configuration(dict(config, **{field: wrong}), args.attest, args.openssl)
                except ValueError:
                    pass
                else:
                    raise ValueError("Invalid release trust was accepted: " + field)
            attest.sign_delivery(signing_args, dict(config))
            with tempfile.TemporaryDirectory(prefix="hankoshell-rejected-tsa-") as rejected:
                failed = SimpleNamespace(**dict(vars(signing_args), workspace=Path(rejected) / "workspace",
                                                output=Path(rejected) / "evidence"))
                try:
                    attest.sign_delivery(failed, dict(config, TSA_URL=tsa_url + "/wrong"))
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise ValueError("Wrong TSA endpoint was accepted")
                if list(Path(rejected).rglob("*.key")) or failed.output.exists():
                    raise ValueError("Failed TSA left signing material or accepted delivery evidence")
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
            publication.qualify(args.output, args.archive, args.evidence, image, args.revision,
                                args.oras, args.helm, args.attest, {
                "KEY_ID": key_id, "PUBLIC_KEY": public_key, "TSA_CERTIFICATE": tsa_cert.read_text(),
            })
            for wrong_id in ("0" * 32, hashlib.sha256(public_der[-32:]).hexdigest()[:32]):
                try:
                    publication.publish.verify_attest(args.output / "checkpoint", args.attest, dict(config, KEY_ID=wrong_id))
                except ValueError:
                    pass
                else:
                    raise ValueError("Checkpoint accepted a wrong Attest key ID")
            other = private / "other-tsa"
            other.mkdir()
            with timestamp_authority(args.openssl, other) as (_, wrong_certificate):
                try:
                    publication.publish.verify_attest(args.output / "checkpoint", args.attest,
                                                     dict(config, TSA_CERTIFICATE=wrong_certificate.read_text()))
                except RuntimeError:
                    pass
                else:
                    raise ValueError("Checkpoint timestamp accepted an unrelated TSA certificate")
        if list(args.output.rglob("*.key")):
            raise ValueError("Private signing material leaked into rehearsal artifacts")
    report = {
        "publishable": False, "version": args.version, "maturity": "nonpublishable rehearsal; v1alpha1 API",
        "target_public_version": contract.versioning.VERSION, "production_publication": "not attempted",
        "revision": args.revision, "image": image,
        "signing_intent": {"oidc_issuer": "https://token.actions.githubusercontent.com",
                           "certificate_identity": f"https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/{contract.versioning.public_tag(contract.versioning.VERSION)}"},
        "checks": {"archive_sbom_provenance_scan_binding": "pass", "chart_and_checksums": "pass",
                   "cosign_local_signature_and_tamper": "pass", "attest_five_checks_and_tamper": "pass",
                   "attest_trust_mismatch_and_failed_tsa_cleanup": "pass"},
        "artifacts": sorted(path.name for path in dist.iterdir()),
        "limitations": ["ephemeral local key/TSA and fixture Artifact Hub ID; not production trust",
                        "no production image signing, GitHub OIDC, GitHub API publication or Artifact Hub indexing",
                        "publication/retry uses an isolated registry and GitHub storage fixture"],
    }
    (args.output / "dry-run.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Nonpublishable release rehearsal passed; no tag, public registry write or GitHub Release created.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "evidence", "output", "helm", "cosign", "attest", "openssl", "oras"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("digest", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--version", default=contract.VERSION)
    args = parser.parse_args()
    for name in ("archive", "evidence", "output", "helm", "cosign", "attest", "openssl", "oras"):
        setattr(args, name, getattr(args, name).resolve())
    rehearse(args)


if __name__ == "__main__":
    main()

"""Verify the compiled Cosign inventory inside the exact runtime image.

This supplements raw module-level scanner results; it never filters a finding.
"""
import hashlib
import json
import re
import tarfile

from tools import versions

BINARY = "usr/local/bin/cosign"
EVIDENCE = "usr/share/hankoshell-operator/verifier-evidence.json"


def validate(document, binary_sha256, platform):
    expected = {"schema", "binary_sha256", "go_version", "os", "arch", "main", "modules", "packages"}
    if (not isinstance(document, dict) or set(document) != expected or document["schema"] != 1
            or document["binary_sha256"] != binary_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", binary_sha256)
            or document["go_version"] != "go" + versions.get("go", "toolchain")
            or (document["os"], document["arch"]) != tuple(platform.split("/"))):
        raise ValueError("Verifier evidence differs from the compiled image identity")
    main = document["main"]
    if (not isinstance(main, dict) or set(main) != {"path", "version", "sum"}
            or main["path"] != "github.com/sigstore/cosign/v3"
            or main["version"] != versions.get("tools", "cosign", "version")
            or not isinstance(main["sum"], str) or not main["sum"].startswith("h1:")):
        raise ValueError("Verifier module differs from the reviewed Cosign")
    packages = document["packages"]
    if (not isinstance(packages, list) or not 100 <= len(packages) <= 10000
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", value) for value in packages)
            or packages != sorted(set(packages))
            or main["path"] + "/cmd/cosign" not in packages
            or any(value == "golang.org/x/crypto/openpgp" or value.startswith("golang.org/x/crypto/openpgp/") for value in packages)):
        raise ValueError("Deprecated OpenPGP or incomplete verifier package evidence")
    modules = document["modules"]
    if not isinstance(modules, list) or not 1 <= len(modules) <= 1000:
        raise ValueError("Verifier dependency inventory absent")
    actual = {}
    for module in modules:
        if (not isinstance(module, dict) or set(module) != {"path", "version", "sum"}
                or any(not isinstance(value, str) or not value for value in module.values())
                or module["path"] in actual or not module["sum"].startswith("h1:")):
            raise ValueError("Ambiguous verifier dependency inventory")
        actual[module["path"]] = module["version"]
    if any(actual.get(path) != value for path, value in versions.get("tools", "cosign", "dependencies").items()):
        raise ValueError("Verifier dependency differs from a reviewed security pin")
    return {"binary_sha256": binary_sha256, "package_count": len(packages), "deprecated_openpgp_absent": True}


def inspect(layout, manifest_digest, platform):
    manifest = json.loads((layout / "blobs/sha256" / manifest_digest.split(":")[1]).read_text())
    document, binary_sha256 = None, None
    for layer in manifest["layers"]:
        with tarfile.open(layout / "blobs/sha256" / layer["digest"].split(":")[1], "r:*") as content:
            for member in content:
                name = member.name.removeprefix("./").rstrip("/")
                if name not in (BINARY, EVIDENCE):
                    continue
                if not member.isfile() or member.size > (256 * 1024 * 1024 if name == BINARY else 1024 * 1024):
                    raise ValueError("Unsafe verifier evidence in runtime layer")
                with content.extractfile(member) as stream:
                    if name == BINARY:
                        binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
                    else:
                        document = json.load(stream)
    if document is None or binary_sha256 is None:
        raise ValueError("Runtime image lacks its compiled verifier package evidence")
    result = validate(document, binary_sha256, platform)
    result["evidence_sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    return result

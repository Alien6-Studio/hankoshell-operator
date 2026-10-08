#!/usr/bin/env bash
set -euo pipefail

destination="${1:?Usage: install-attest.sh DESTINATION}"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    platform=linux-x86_64
    archive_sha=f51201745b30be356e066cd615a7ef41fed92b17cf720ceb03e7f2a4d58505ad
    binary_sha=c73ecb92a2ebbf324cb0bdcf631fc3505f3395aa1acad30501284156cef9ce35
    ;;
  Darwin/arm64)
    platform=macos-aarch64
    archive_sha=93d02f9fc90a8c0dd6c8f3df05ce56660b89b83eb334a02aaad4c3f68f9ceb4d
    binary_sha=fa572bbc2c00f55f37be15564661c693d801fd58f6b9b938924698a986bab705
    ;;
  *) echo 'Unsupported Attest host platform.' >&2; exit 1 ;;
esac

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
curl --fail --silent --show-error --location --retry 2 --max-time 90 \
  "https://github.com/Alien6-Studio/continuum-attest/releases/download/v0.1.0/attest-v0.1.0-$platform.tar.gz" \
  -o "$staging/attest.tar.gz"
python3 - "$staging/attest.tar.gz" "$archive_sha" <<'PY'
import hashlib, sys
from pathlib import Path
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('Attest archive checksum mismatch')
PY
tar -xzf "$staging/attest.tar.gz" -C "$staging" attest
python3 - "$staging/attest" "$binary_sha" <<'PY'
import hashlib, sys
from pathlib import Path
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('Attest executable checksum mismatch')
PY
test "$("$staging/attest" --version)" = 'attest 0.1.0'
mkdir -p "$(dirname "$destination")"
install -m 0755 "$staging/attest" "$destination"

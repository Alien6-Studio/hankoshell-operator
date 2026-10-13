#!/usr/bin/env bash
# Build the reviewed verifier with the same patched SDKs as the runtime image.
set -euo pipefail
destination="${1:?Usage: install-cosign.sh /absolute/output/path}"
[[ "$destination" = /* ]]
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$script_dir/cosign-pins.sh"
# A fresh wrapper module otherwise falls back to the workstation's default Go.
GOTOOLCHAIN="go$(python3 "$script_dir/versions.py" get go toolchain)"
export GOTOOLCHAIN
source_dir="$(mktemp -d)"
trap 'rm -rf "$source_dir"' EXIT
cd "$source_dir"
go mod init hankoshell.local/cosign-build
go get "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION"
# Intentional splitting: the generated fragment contains validated module@version words.
# shellcheck disable=SC2086
go get $COSIGN_DEPENDENCIES
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X sigs.k8s.io/release-utils/version.gitVersion=$COSIGN_VERSION" \
  -o "$destination" github.com/sigstore/cosign/v3/cmd/cosign

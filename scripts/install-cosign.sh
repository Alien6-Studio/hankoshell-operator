#!/usr/bin/env bash
# Build the reviewed verifier with the same patched SDKs as the runtime image.
set -euo pipefail
destination="${1:?Usage: install-cosign.sh /absolute/output/path}"
[[ "$destination" = /* ]]
source_dir="$(mktemp -d)"
trap 'rm -rf "$source_dir"' EXIT
cd "$source_dir"
go mod init hankoshell.local/cosign-build
go get github.com/sigstore/cosign/v3/cmd/cosign@v3.1.3
go get golang.org/x/crypto@v0.57.0 golang.org/x/mod@v0.41.0 \
  golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 google.golang.org/grpc@v1.83.2
CGO_ENABLED=0 go build -trimpath \
  -ldflags '-s -w -X sigs.k8s.io/release-utils/version.gitVersion=v3.1.3' \
  -o "$destination" github.com/sigstore/cosign/v3/cmd/cosign

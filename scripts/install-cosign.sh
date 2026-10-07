#!/usr/bin/env bash
# Build the reviewed verifier with the same patched SDKs as the runtime image.
set -euo pipefail
destination="${1:?Usage: install-cosign.sh /absolute/output/path}"
[[ "$destination" = /* ]]
source_dir="$(mktemp -d)"
trap 'rm -rf "$source_dir"' EXIT
go mod download github.com/sigstore/cosign/v3@v3.1.3
cp -R "$(go env GOPATH)/pkg/mod/github.com/sigstore/cosign/v3@v3.1.3/." "$source_dir/"
chmod -R u+w "$source_dir"
cd "$source_dir"
go get golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 \
  golang.org/x/text@v0.41.0 google.golang.org/grpc@v1.83.2
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$destination" ./cmd/cosign

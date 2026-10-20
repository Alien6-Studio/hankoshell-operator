#!/usr/bin/env bash
# Official controller-tools API-server/etcd assets, pinned by version and SHA-512.
set -euo pipefail
version="${1:?Kubernetes fixture version required}"
platform="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in arm64|aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
checksum="$(python3 "$root/tools/versions.py" get kubernetes envtest_sha512 "$version" "$platform-$arch")"
cache="$root/.tools/cache/envtest/$version-$platform-$arch"
mkdir -p "$cache"
archive="$cache/assets.tar.gz"
if [ ! -f "$archive" ]; then
  temporary="$(mktemp "$cache/download.XXXXXX")"
  trap 'rm -f "$temporary"' EXIT
  curl -fLsS --retry 3 "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v$version/envtest-v$version-$platform-$arch.tar.gz" -o "$temporary"
  printf '%s  %s\n' "$checksum" "$temporary" | shasum -a 512 -c - >&2
  mv "$temporary" "$archive"
fi
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 512 -c - >&2
tar -xzf "$archive" -C "$cache"
assets="$cache/controller-tools/envtest"
test -x "$assets/kube-apiserver" && test -x "$assets/etcd"
printf '%s\n' "$assets"

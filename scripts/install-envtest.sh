#!/usr/bin/env bash
# Official controller-tools API-server/etcd assets, pinned by version and SHA-512.
set -euo pipefail
version="${1:?Kubernetes fixture version required}"
platform="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in arm64|aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
case "$version-$platform-$arch" in
  1.35.0-darwin-arm64) checksum=bb5d0bb3975956331b0aa0c039955b4c4dc6c5c288e5af369364c7d2fbeac11a025227dabb127569080b259dd29b697cc77fa77abd27ae26721ddb23e8ee0613 ;;
  1.35.0-linux-amd64) checksum=130369c16f076e724d089189afaede960316f5f5dea6cf57be7a4fc6f09c77342893192509790e4056e116e232dff832ed863f5bd55dcb55d38f3ab834828a11 ;;
  1.36.2-darwin-arm64) checksum=9278f9e5af556b2f1f2d139769c1f0d717c7b4426917fdebdba898bcb725a916e4910d6160886194ff9be9589ea7c5c32c2b8ae0754703874b7c8ba8ddfc41ce ;;
  1.36.2-linux-amd64) checksum=ea743186c8a799f5cf8faf16969f86189d003cb7d130e0ac4b58789f1e5748dcf30ebe91c837a10d5ac415383da3e10b9e64d65785c938c23e739781cfb76f08 ;;
  1.37.0-darwin-arm64) checksum=fb38cfacdd71b5e97a4d4cceac861af5f55069cf783f0e49cf181bfc32eb3e557c2091a534dc5d38f1b92c5ba142bc1979f215a5385b3630ea6a661be6fa161b ;;
  1.37.0-linux-amd64) checksum=1d1c453633b72c161a5d5a886cde7ac850be1a2ac796a9e1d4ffacacc64868295bdd2d57aa66cd0c158f5ce510f5dfe3fbc61ac21bd3dcfb875bd70658aa663a ;;
  *) echo "No reviewed envtest assets for $version-$platform-$arch" >&2; exit 1 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cache="$root/.tools/envtest/$version-$platform-$arch"
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

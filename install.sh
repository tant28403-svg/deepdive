#!/usr/bin/env sh
set -eu

REPO="tant28403-svg/deepdive"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo "deepdive installer"
echo "Fetching latest release..."

# Determine OS/arch
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)  OS_TARGET="unknown-linux-musl" ;;
  Darwin) OS_TARGET="apple-darwin" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64) ARCH_TARGET="x86_64" ;;
  aarch64|arm64) ARCH_TARGET="aarch64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"
ASSET="deepdive-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/latest/download"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "${BASE}/${ASSET}" -o "$TMPDIR/$ASSET"
curl -fsSL "${BASE}/SHA256SUMS" -o "$TMPDIR/SHA256SUMS"

cd "$TMPDIR"
grep " $ASSET\$" SHA256SUMS | sha256sum -c -

tar xzf "$ASSET"
install -m 755 deepdive "$INSTALL_DIR/deepdive"
echo "Installed deepdive to $INSTALL_DIR/deepdive"
#!/bin/sh
# oxAudit installer: downloads a release binary and verifies it against the
# release's SHA256SUMS.txt before installing. Nothing is executed unverified.
#
#   curl -fsSL https://raw.githubusercontent.com/HenryCooper86/oxAudit/main/scripts/install.sh | sh
#
# Installs to $OXAUDIT_INSTALL_DIR (default: $HOME/.oxaudit/bin) and prints
# the PATH line to add.
set -eu

REPO="${OXAUDIT_REPO:-HenryCooper86/oxAudit}"
VERSION="${OXAUDIT_VERSION:-latest}"
PREFIX="${OXAUDIT_INSTALL_DIR:-$HOME/.oxaudit/bin}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)        asset="oxaudit-cli-linux-x86_64" ;;
  Linux-aarch64)       asset="oxaudit-cli-linux-aarch64" ;;
  Darwin-x86_64)       asset="oxaudit-cli-macos-universal" ;;
  Darwin-arm64)        asset="oxaudit-cli-macos-universal" ;;
  *)
    echo "No oxAudit binary for $(uname -s)-$(uname -m); build from source." >&2
    exit 2 ;;
esac

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $asset from $REPO ($VERSION)…"
curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$asset" "$base/$asset"
curl -fsSL --retry 5 --retry-all-errors -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt"
echo "Verifying the checksum…"
grep " $asset\$" "$tmp/SHA256SUMS.txt" | (cd "$tmp" && shasum -a 256 -c -)

mkdir -p "$PREFIX"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$PREFIX/oxaudit-cli"
echo "Installed $PREFIX/oxaudit-cli"
echo "Verify releases independently with cosign (keyless signatures) or gh attestation verify — see the release notes."
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac

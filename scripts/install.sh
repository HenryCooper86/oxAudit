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
if command -v shasum >/dev/null 2>&1; then
  sha256_check() { shasum -a 256 -c -; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha256_check() { sha256sum -c -; }
else
  echo "Neither shasum nor sha256sum is available to verify $asset; nothing was installed." >&2
  exit 2
fi
# Exactly one checksum line must name this asset: an empty selection would
# otherwise give the checker nothing to verify.
sums="$(awk -v a="$asset" '$2 == a || $2 == "*" a' "$tmp/SHA256SUMS.txt")"
if [ -z "$sums" ] || [ "$(printf '%s\n' "$sums" | wc -l)" -ne 1 ]; then
  echo "SHA256SUMS.txt does not list $asset exactly once; nothing was installed." >&2
  exit 2
fi
printf '%s\n' "$sums" | (cd "$tmp" && sha256_check)

mkdir -p "$PREFIX"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$PREFIX/oxaudit-cli"
echo "Installed $PREFIX/oxaudit-cli"
echo "The checksum proves integrity, not who published the binary. For publisher"
echo "identity, verify it with minisign against the committed minisign.pub, with"
echo "cosign (keyless signatures), or with gh attestation verify — for example:"
echo "  curl -fsSL -o oxaudit-cli.minisig $base/$asset.minisig"
echo "  minisign -Vm $PREFIX/oxaudit-cli -x oxaudit-cli.minisig -P \"\$(curl -fsSL https://raw.githubusercontent.com/$REPO/main/minisign.pub | tail -1)\""
echo "  gh attestation verify $PREFIX/oxaudit-cli --repo $REPO"
echo "See docs/getting-started.md#what-verification-proves for the exact commands."
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac

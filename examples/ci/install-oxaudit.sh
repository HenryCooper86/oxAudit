#!/bin/sh
# Download a pinned oxaudit-cli release and verify it before first use.
#
#   OXAUDIT_VERSION  release tag, for example v0.3.1. The `sca` and
#                    `portfolio` commands and the junit / gitlab-* formats
#                    need v0.3.1 or later.
#   OXAUDIT_SHA256   the SHA-256 of the asset for this runner, copied from
#                    that release's SHA256SUMS.txt. Pinning the digest in
#                    your pipeline means a replaced asset fails the job.
#   OXAUDIT_REPO     optional; defaults to HenryCooper86/oxAudit.
#
# Installs to ./.oxaudit-tool/oxaudit-cli. Copy this file into your
# repository and review it; do not pipe it from the network into a shell.
set -eu

: "${OXAUDIT_VERSION:?set OXAUDIT_VERSION to a release tag}"
: "${OXAUDIT_SHA256:?set OXAUDIT_SHA256 to the asset digest from SHA256SUMS.txt}"
repo="${OXAUDIT_REPO:-HenryCooper86/oxAudit}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)             asset=oxaudit-cli-linux-x86_64 ;;
  Linux-aarch64|Linux-arm64) asset=oxaudit-cli-linux-aarch64 ;;
  Darwin-*)                 asset=oxaudit-cli-macos-universal ;;
  *) echo "oxAudit publishes no binary for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

mkdir -p .oxaudit-tool
curl -fsSL --retry 5 --retry-all-errors \
  -o ".oxaudit-tool/$asset" \
  "https://github.com/$repo/releases/download/$OXAUDIT_VERSION/$asset"

if command -v sha256sum >/dev/null 2>&1; then
  echo "$OXAUDIT_SHA256  .oxaudit-tool/$asset" | sha256sum -c -
else
  echo "$OXAUDIT_SHA256  .oxaudit-tool/$asset" | shasum -a 256 -c -
fi

mv ".oxaudit-tool/$asset" .oxaudit-tool/oxaudit-cli
chmod 0755 .oxaudit-tool/oxaudit-cli
.oxaudit-tool/oxaudit-cli --version

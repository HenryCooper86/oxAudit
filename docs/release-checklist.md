# Release checklist

Last reviewed **2026-10-10** against GitHub repository/release metadata and
the release workflow on `main`. Repository visibility is resolved: oxAudit
is public, and its first release is already published. The next release
needs a new version and a reviewed artifact set.

## Observed release state

- [The repository](https://github.com/HenryCooper86/oxAudit) is public.
- [Published v0.1.0](https://github.com/HenryCooper86/oxAudit/releases/tag/v0.1.0)
  (release ID `397101533`) was published on **2026-09-26 at 05:26:54 UTC**
  and is returned by GitHub's latest-release endpoint.
- A separate [draft named oxAudit v0.1.0](https://github.com/HenryCooper86/oxAudit/releases/tag/untagged-08a29b9a10217b961a24)
  (release ID `397102898`) also references tag `v0.1.0`. It has nine assets
  and no cosign bundle or minisign attachments. The published release has
  twenty assets. **Owner review remains:** determine why this duplicate
  draft exists and whether to retain or remove it. It is not evidence that
  the published release is incomplete; do not publish it as another v0.1.0
  without reviewing its origin and artifacts.

The published v0.1.0 asset inventory is:

| Artifact | Published files |
| --- | --- |
| Linux x86_64 CLI | `oxaudit-cli-linux-x86_64` |
| macOS universal CLI | `oxaudit-cli-macos-universal` |
| Windows x86_64 CLI | `oxaudit-cli-windows-x86_64.exe` |
| Linux x86_64 desktop | AppImage, `.deb`, `.rpm` |
| SBOMs | `oxaudit-rust.cdx.json`, `oxaudit-npm.cdx.json` |
| Checksums | `SHA256SUMS.txt` |
| Signature attachments | `.bundle` and `.minisig` for each CLI and the checksum list; `.bundle.minisig` files for the CLI bundles |

There is no Linux aarch64 CLI, macOS/Windows desktop installer, or
`oxaudit-container.txt` in this published asset list. This inventory checks
availability; downloaded checksums, signatures, attestations, and anonymous
container pulls were not independently verified during this maintenance
review.

## What the current workflow is configured to build

The [release workflow](../.github/workflows/release.yml) verifies versions,
frontend and Rust checks before building. A real tag release is configured
to produce Linux x86_64 desktop artifacts; Linux x86_64/aarch64, macOS
universal, and Windows x86_64 CLIs; both SBOMs; checksums; build-provenance
attestations; keyless cosign bundles; and minisign signatures. It creates a
draft release for human review.

The workflow also builds native linux/amd64 and linux/arm64 container images,
merges and cosign-signs their index, and stages its pinned reference as
`oxaudit-container.txt`. These are workflow capabilities, not additional
published v0.1.0 assets. Confirm the reference and anonymous pull at the next
release that includes the container jobs. GitHub's Container registry
[starts new packages as private](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pushing-container-images),
so repository visibility alone does not prove package availability.

macOS/Windows desktop bundles require `DESKTOP_BUNDLES=true`; no repository
variables were returned at this review. The previous owner decision
(2026-09-26) was CLI + Linux-first distribution. Before enabling native
desktop bundles, configure the six `APPLE_*` and two
`WINDOWS_CERTIFICATE*` secrets required by
[`tools/require-release-signing.mjs`](../tools/require-release-signing.mjs)
and validate notarization/Authenticode signing. The workflow fails closed
when required native signing values are missing. Review the generated notes
as well: their desktop-availability paragraph currently assumes these
bundles are absent.

The committed `minisign.pub` is the offline verification key, and CI reads
`MINISIGN_PRIVATE_KEY` from repository secrets. Keep the private key out of
the repository; if it is exposed, rotate the keypair and document the new
verification key before the next release.

## Next release procedure

1. Choose a new, unpublished version. Update `src-tauri/Cargo.toml` and
   `package.json` together and run `node tools/check-versions.mjs`.
   **Do not recreate or move the published `v0.1.0` tag.**
2. Run the checks required by the release workflow and review a manual
   `dry_run=true` build. Confirm platform coverage and expected file names,
   especially the new Linux aarch64 CLI. A dry run skips container publishing;
   verify that reference after the real tag run.
3. Confirm the intended desktop signing posture and secret configuration.
   Keep `DESKTOP_BUNDLES` off until signed native bundles and accurate notes
   have been validated.
4. Tag the reviewed commit with the new `v<version>` tag and push that tag.
   Wait for all required build, signing, attestation, and container jobs.
5. Review the resulting draft by release ID: CLI/Linux/SBOM inventory,
   checksum coverage, cosign/minisign attachments, provenance, container
   digest, and accurate platform notes. Publish only the reviewed new
   release. Review the old duplicate v0.1.0 draft separately.
6. Exercise the pinned release from a clean machine: the composite Action
   against a sample repository, the installer, `minisign -Vm`,
   `cosign verify-blob` with the expected workflow identity/issuer, and
   `gh attestation verify` on a downloaded binary. Confirm a container pull
   by the released digest without credentials; the owner can make the
   package public if needed after reviewing its package settings.
7. Record the tested version, platform, checks, and remaining limitations.
   Brew tap and Action Marketplace publication remain optional owner work.

## Current distribution limits

[`action/action.yml`](../action/action.yml) selects Linux x64, macOS x64/ARM64,
and Windows x64 binaries and verifies their release checksums.
[`scripts/install.sh`](../scripts/install.sh) selects Linux x86_64/aarch64
and macOS x86_64/ARM64. Its Linux aarch64 path needs a later published
release containing `oxaudit-cli-linux-aarch64`; v0.1.0 does not provide that
asset. Pin a release that actually supplies the requested platform when
validating distribution.

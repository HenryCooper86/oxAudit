# Release checklist

Last reviewed **2026-10-20** against the GitHub repository/release API, the
release workflow on `main`, and a live download-and-verify exercise. The
repository is public, `v0.1.0` is the only tag and the only published
release, and the duplicate draft still awaits owner review. The next release
needs a new version and a reviewed artifact set. The previous review
(2026-10-10) established this state; today's pass re-confirms it and adds
exercised evidence below.

## Observed release state

- [The repository](https://github.com/HenryCooper86/oxAudit) is public
  (API `visibility: public`, default branch `main`).
- [Published v0.1.0](https://github.com/HenryCooper86/oxAudit/releases/tag/v0.1.0)
  (release ID `397101533`) was published on **2026-09-26 at 05:26:54 UTC**
  and remains GitHub's latest-release response on 2026-10-20.
- `v0.1.0` is the only tag. A separate [draft named oxAudit v0.1.0](https://github.com/HenryCooper86/oxAudit/releases/tag/untagged-08a29b9a10217b961a24)
  (release ID `397102898`) also references tag `v0.1.0`. Re-confirmed on
  2026-10-20: it has nine core assets (three CLIs, three Linux desktop
  packages, two SBOMs, `SHA256SUMS.txt`) and no cosign bundle or minisign
  attachments, unchanged since 2026-09-26 05:24:34 UTC. **Owner review
  remains:** determine why this duplicate draft exists and whether to retain
  or remove it. It is not evidence that the published release is incomplete;
  do not publish it as another v0.1.0 without reviewing its origin and
  artifacts. Do not delete it as part of documentation work.

The published v0.1.0 release carries **twenty uploaded assets**. The release
page's larger count includes GitHub's two auto-generated source archives
(zip/tarball), which are not uploads and are not covered by
`SHA256SUMS.txt`. The canonical per-platform artifact inventory — exact file
names, what is published versus absent (Linux aarch64 CLI, macOS/Windows
desktop installers, container reference), and which verification applies to
which file — is the single matrix in
[Getting started: platform availability and verification](getting-started.md#platform-availability-and-verification).
Update that matrix instead of copying inventories here.

### Exercised verification (2026-10-20, macOS arm64)

Observed on one macOS arm64 machine, isolated to temporary directories (no
system PATH or user-directory changes):

- `OXAUDIT_VERSION=v0.1.0 sh scripts/install.sh` with a temporary
  `OXAUDIT_INSTALL_DIR` downloaded `oxaudit-cli-macos-universal`, printed
  `oxaudit-cli-macos-universal: OK` against the release `SHA256SUMS.txt`,
  and installed the binary.
- `gh attestation verify <installed oxaudit-cli> --repo HenryCooper86/oxAudit`
  exited 0. A second verification also required the exact certificate identity
  `https://github.com/HenryCooper86/oxAudit/.github/workflows/release.yml@refs/tags/v0.1.0`
  and `--source-ref refs/tags/v0.1.0`; it exited 0. The exercised provenance
  therefore passed both repository-scoped and tagged release-workflow checks.
- The installed binary printed `oxaudit 0.1.0`; its SHA-256 matches the
  GitHub asset digest `2b60f9180484465155c6e2ff600cd4c29a378c177177cafd682ba04b60d8f133`
  from the release API; `lipo` reports x86_64 + arm64 (execution observed on
  arm64 only).
- Scanning one copied inert `handler.js` with
  `--format json --output <file> --fail-on high` (child `HOME` in temp, and
  a loopback HTTP(S) proxy that refuses connections) exited 1 with
  `filesScanned: 1`, rule `js-eval`, and one refused optional enrichment
  request — the published binary behaves like the pilot CLI under the same
  refusal harness.

Not exercised then: Linux or Windows execution of any asset, `minisign -Vm`
and `cosign verify-blob` verification commands, native codesigning or
notarization state, and container pulls. The 2026-10-10 review likewise did
not download assets; its inventory check was availability-only.

## What the current workflow is configured to build

The [release workflow](../.github/workflows/release.yml) verifies versions,
frontend and Rust checks before building. A real tag release is configured
to produce Linux x86_64 desktop artifacts; Linux x86_64/aarch64, macOS
universal, and Windows x86_64 CLIs; both SBOMs; one merged checksum list;
build-provenance attestations; keyless cosign bundles and minisign
signatures for the CLI binaries and the checksum list; and — on real tag
runs only — native linux/amd64 and linux/arm64 container images merged into
one cosign-signed index, staged as `oxaudit-container.txt`. It creates a
draft release for human review, then uploads the signature sidecars.

### Signing posture

[`tools/require-release-signing.mjs`](../tools/require-release-signing.mjs)
requires native credentials per platform: **none for Linux**, six `APPLE_*`
secrets for macOS, two `WINDOWS_CERTIFICATE*` secrets for Windows. The gate
runs only for publishable tag builds (not dry runs), and the CLI-only
`bundle-cli` job has no signing gate at all. **CLI and Linux releases
therefore publish without any macOS/Windows credentials — v0.1.0 did.** The
fail-closed gates matter only when `DESKTOP_BUNDLES=true` enables the
macOS/Windows desktop bundle jobs. No repository variables existed at the
2026-10-10 review and none exist on 2026-10-20, so those jobs stay skipped
(owner decision 2026-09-26: CLI + Linux-first, no Apple/Windows developer
accounts). Earlier doc wording claiming every publishable tag requires
macOS/Windows credentials was wrong; this section is the correction. Before
enabling desktop bundles, configure the six `APPLE_*` and two
`WINDOWS_CERTIFICATE*` secrets and validate
notarization/Authenticode signing. Review the generated notes as well:
their desktop-availability paragraph is accurate only while those bundles
are absent.

The committed `minisign.pub` is the offline verification key, and CI reads
`MINISIGN_PRIVATE_KEY` from repository secrets. Keep the private key out of
the repository; if it is exposed, rotate the keypair and document the new
verification key before the next release.

### Container availability

The workflow can build and push the multi-architecture image to
`ghcr.io/henrycooper86/oxaudit` and cosign-sign its index. As of 2026-10-20
an anonymous ghcr.io manifest request for that reference returns **403**:
the package is not publicly pullable, and GitHub's Container registry
[_starts new packages as private](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pushing-container-images).
Repository visibility alone does not prove package availability; do not
advertise a container image until the owner makes the package public and an
anonymous pull by the released digest is confirmed. `oxaudit-container.txt`
is not a v0.1.0 asset.

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
   `gh attestation verify` on a downloaded binary — the 2026-10-20 pass
   covered the installer, one attestation, and one scan on macOS arm64
   only; the remaining platforms and signature tools are still unexercised.
   Confirm a container pull by the released digest without credentials; the
   owner can make the package public if needed after reviewing its package
   settings.
7. Record the tested version, platform, checks, and remaining limitations.
   Brew tap and Action Marketplace publication remain optional owner work.

## Current distribution limits

[`action/action.yml`](../action/action.yml) selects Linux x64, macOS
x64/ARM64, and Windows x64 binaries and verifies their release checksums.
Public release downloads do not by themselves establish successful Action
execution on every supported runner.
[`scripts/install.sh`](../scripts/install.sh) selects Linux
x86_64/aarch64 and macOS x86_64/ARM64, verifies the release checksum before
installing, and is POSIX `sh` (not PowerShell). Its Linux aarch64 path needs
a later published release containing `oxaudit-cli-linux-aarch64`; v0.1.0
does not provide that asset, so pin a release that actually supplies the
requested platform when validating distribution. The macOS arm64 installer
path is the one exercised on 2026-10-20.

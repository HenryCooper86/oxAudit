# Release checklist

Last reviewed **2026-10-29** against the GitHub repository/release API, the
release workflow runs, the container registry, and a live download-and-verify
exercise. The repository is public and
[v0.2.6](https://github.com/HenryCooper86/oxAudit/releases/tag/v0.2.6) is the
latest published release. `main` at `e9b8de6` and later is unreleased work on
top of the v0.2.6 tag; the [changelog](../CHANGELOG.md) lists it. Earlier
reviews (2026-10-10, 2026-10-20) covered the v0.1.0-only state; their
exercised evidence is kept below.

## Observed release state

- [The repository](https://github.com/HenryCooper86/oxAudit) is public
  (API `visibility: public`, default branch `main`).
- Tags: `v0.1.0`, `v0.2.0`, `v0.2.1`, `v0.2.2`, `v0.2.3`, `v0.2.5`, `v0.2.6`.
  There is no `v0.2.4` tag: commit `7b5e1b8` ("prepare 0.2.4") moved the
  version declarations to 0.2.4 but was never tagged; `v0.2.5` followed it.

| Tag | Commit | Release workflow | GitHub release |
| --- | --- | --- | --- |
| `v0.2.6` | `c9f0568` | succeeded | Published 2026-10-26 08:58:36 UTC (release ID `423719831`, 25 uploaded assets); GitHub's latest-release response on 2026-10-29 |
| `v0.2.5` | `b9a1012` | cancelled | None. Its SBOM selection bug was fixed in v0.2.6 (see [the v0.2.6 notes](releases/v0.2.6.md)); the tag is preserved |
| `v0.2.3` | `27cd5e8` | cancelled | None |
| `v0.2.2` | `460808b` | succeeded | **Draft only** (release ID `423497431`, 25 assets), never published |
| `v0.2.1` | `d45386d` | succeeded | Published 2026-10-25 12:08:19 UTC (release ID `423376730`, 25 assets) |
| `v0.2.0` | `8b07a29` | succeeded after four failed runs | Published 2026-10-25 11:26:30 UTC (release ID `423353387`, 25 assets) |
| `v0.1.0` | `e6614a3` | succeeded | Published 2026-09-26 05:26:54 UTC (release ID `397101533`, 20 assets), plus a duplicate draft (below) |

**Owner review remains** for two drafts. Do not delete either as part of
documentation work, and do not publish either without reviewing its origin
and artifacts:

- The v0.2.2 draft (release ID `423497431`) was created by a successful
  release run on 2026-10-25 but never published;
  v0.2.3, v0.2.5 and v0.2.6 followed. The registry still carries `v0.2.2`
  container tags pushed by that run.
- A separate draft named oxAudit v0.1.0 (release ID `397102898`) also
  references tag `v0.1.0`. Confirmed on 2026-10-20: nine core assets (three
  CLIs, three Linux desktop packages, two SBOMs, `SHA256SUMS.txt`) and no
  cosign bundle or minisign attachments, unchanged since 2026-09-26 05:24:34
  UTC; on 2026-10-29 the release API still lists it with nine assets. It is
  not evidence that the published v0.1.0 release is incomplete.

The published v0.2.6 release carries **twenty-five uploaded assets**: four
CLIs with three signature sidecars each, three Linux desktop packages, two
SBOMs, `oxaudit-container.txt`, and `SHA256SUMS.txt` with its minisign and
Sigstore signatures. The release page's larger count includes GitHub's two
auto-generated source archives (zip/tarball), which are not uploads and are
not covered by `SHA256SUMS.txt`. The canonical per-platform artifact
inventory — exact file names, what is published versus absent (macOS/Windows
desktop installers), the container reference, and which verification applies
to which file — is the single matrix in
[Getting started: platform availability and verification](getting-started.md#platform-availability-and-verification).
Update that matrix instead of copying inventories here.

### Exercised verification

#### 2026-10-29, v0.2.6, macOS arm64

Observed on one macOS arm64 machine, isolated to temporary directories (no
system PATH or user-directory changes):

- `OXAUDIT_VERSION=v0.2.6 sh scripts/install.sh` with a temporary
  `OXAUDIT_INSTALL_DIR` downloaded `oxaudit-cli-macos-universal`, printed
  `oxaudit-cli-macos-universal: OK`, and installed a binary that printed
  `oxaudit 0.2.6`. The same run with `shasum` absent from `PATH` verified
  through `sha256sum`; with neither present the installer exited 2 and
  installed nothing.
- `shasum -a 256 -c` over the release `SHA256SUMS.txt` passed for the
  downloaded `oxaudit-cli-linux-x86_64`, `oxaudit-cli-macos-universal`, and
  `oxaudit-container.txt`.
- `minisign -Vm` against the committed `minisign.pub` verified
  `SHA256SUMS.txt`, `oxaudit-cli-linux-x86_64`, and
  `oxaudit-cli-macos-universal` (and the latter under another file name with
  `-x`).
- `gh attestation verify oxaudit-cli-linux-x86_64 --repo HenryCooper86/oxAudit`
  with `--cert-identity` set to the `refs/tags/v0.2.6` release workflow,
  `--source-ref refs/tags/v0.2.6`, and `--source-digest
  c9f0568dc3ac890fcd9122e08f58cf92c9141b47` exited 0; the same check with a
  wrong `--source-digest` exited 1.
- With an empty Docker configuration (no credentials),
  `docker pull ghcr.io/henrycooper86/oxaudit@sha256:173ebb003c1e9855d3e07ff7140b7f6b827e52f088ce954af98bec9e44ceb4cf`
  succeeded; the index lists linux/amd64 and linux/arm64, and the arm64 image
  printed `oxaudit 0.2.6`. Its headless server started and served the GUI
  (HTTP 200, `/api` without a token 401) only after the `/data` volume was
  made writable by the image's `scanner` user; with a fresh named volume it
  exits with "cannot prepare the data directory". The
  [server guide](headless-server.md#container) documents the workaround.

Not exercised on 2026-10-29: `cosign verify-blob` and `cosign verify`
(cosign was not installed), Linux or Windows execution of any asset, the
composite Action or the consumer CI example in a real GitHub repository, and
native codesigning or notarization state.

#### 2026-10-20, v0.1.0, macOS arm64

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
one cosign-signed index, staged as `oxaudit-container.txt` (and listed in
`SHA256SUMS.txt`). It creates a
draft release for human review, then uploads the signature sidecars.

### Signing posture

[`tools/require-release-signing.mjs`](../tools/require-release-signing.mjs)
requires native credentials per platform: **none for Linux**, six `APPLE_*`
secrets for macOS, two `WINDOWS_CERTIFICATE*` secrets for Windows. The gate
runs only for publishable tag builds (not dry runs), and the CLI-only
`bundle-cli` job has no signing gate at all. **CLI and Linux releases
therefore publish without any macOS/Windows credentials — every published
release so far has.** The
fail-closed gates matter only when `DESKTOP_BUNDLES=true` enables the
macOS/Windows desktop bundle jobs. No repository variables existed at the
2026-10-10 review, on 2026-10-20, or on 2026-10-29, so those jobs stay skipped
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

The workflow builds and pushes the multi-architecture image to
`ghcr.io/henrycooper86/oxaudit`, cosign-signs its index, and stages the
digest-pinned reference as the release asset `oxaudit-container.txt`. On
2026-10-20, before any v0.2.x release, an anonymous manifest request was
refused (**403**). The completed v0.2.0, v0.2.1, v0.2.2 and v0.2.6 runs
pushed images (the registry lists their tags), and on 2026-10-29 the package
was publicly pullable: an anonymous `docker pull` of
the v0.2.6 digest
`sha256:173ebb003c1e9855d3e07ff7140b7f6b827e52f088ce954af98bec9e44ceb4cf`
succeeded (see [exercised verification](#exercised-verification)). Package
visibility is a registry setting, separate from repository visibility, so
re-confirm an anonymous pull by the new digest for each release. Advertise the
digest from `oxaudit-container.txt`, not a tag: `latest` and `v<version>` tags
are mutable, and the registry also holds tags for the unpublished v0.2.2
draft.

With the v0.2.6 image, the documented `docker run … -v oxaudit-data:/data
--entrypoint oxaudit-server` command fails with a fresh named volume, because
`/data` is not created owned by the image's unprivileged `scanner` user. The
[server guide](headless-server.md#container) gives the one-time ownership
step. The `Dockerfile` on `main` now creates `/data` owned by `scanner`, so
the next published image should start on a fresh volume; confirm that as
part of the next release's container check.

## Next release procedure

1. Choose a new, unpublished version. Update `src-tauri/Cargo.toml` and
   `package.json` together and run `node tools/check-versions.mjs`.
   **Do not recreate or move any existing tag**, published or not
   (`v0.2.5` stays, for example, although its run was cancelled).
2. Run the checks required by the release workflow and review a manual
   `dry_run=true` build. Confirm platform coverage and expected file names
   against the [matrix](getting-started.md#platform-availability-and-verification),
   including the application SBOM's name, version and dependencies (the
   v0.2.5 failure). A dry run skips container publishing; verify that
   reference after the real tag run.
3. Confirm the intended desktop signing posture and secret configuration.
   Keep `DESKTOP_BUNDLES` off until signed native bundles and accurate notes
   have been validated.
4. Tag the reviewed commit with the new `v<version>` tag and push that tag.
   Wait for all required build, signing, attestation, and container jobs.
5. Review the resulting draft by release ID: CLI/Linux/SBOM inventory,
   checksum coverage, cosign/minisign attachments, provenance, container
   digest, and accurate platform notes. Publish only the reviewed new
   release. Review the leftover v0.1.0 and v0.2.2 drafts separately.
6. Exercise the pinned release from a clean machine: the composite Action
   against a sample repository, the installer, `minisign -Vm`,
   `cosign verify-blob` with the expected workflow identity/issuer, and
   `gh attestation verify` on a downloaded binary — the 2026-10-29 pass
   covered the installer, minisign, one tag- and commit-bound attestation,
   and the container pull on macOS arm64 only; cosign, Linux and Windows
   execution, and the Action are still unexercised. Confirm a container pull
   by the released digest without credentials.
7. Record the tested version, platform, checks, and remaining limitations,
   update the [changelog](../CHANGELOG.md), and update the pinned version,
   commit and digest in [the consumer CI example](../examples/ci/oxaudit.yml)
   once the release is verified.
   Brew tap and Action Marketplace publication remain optional owner work.

## Current distribution limits

[`action/action.yml`](../action/action.yml) selects Linux x64/ARM64, macOS
x64/ARM64, and Windows x64 binaries and verifies their release checksums.
Public release downloads do not by themselves establish successful Action
execution on every supported runner; none has been exercised and recorded
here.
[`scripts/install.sh`](../scripts/install.sh) selects Linux
x86_64/aarch64 and macOS x86_64/ARM64, verifies the release checksum (with
`shasum` or `sha256sum`) before installing, and is POSIX `sh` (not
PowerShell). Releases from v0.2.0 on publish `oxaudit-cli-linux-aarch64`;
v0.1.0 does not, so its aarch64 path fails. Only the macOS arm64 installer
path has been exercised (2026-10-20 for v0.1.0, 2026-10-29 for v0.2.6).

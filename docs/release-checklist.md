# Release checklist

Everything engineering can do without a decision from the repository owner is
done. This file records exactly what remains, who owns it, and the procedure
to run once answered — so the first release is a short afternoon, not a
project.

## Owner decisions — two answered 2026-09-26

1. **Repository visibility — STILL OPEN, the only remaining blocker.**
   GitHub release assets on a private repository cannot be downloaded by
   consumers, so every distribution path (Action, installer, brew) requires
   either making this repository public or creating a separate public
   distribution repository that mirrors the release assets. A one-way door;
   only the owner can open it.
2. **Signing scheme — ANSWERED: minisign on top of keyless cosign. DONE.**
   Both ship in the release workflow: keyless Sigstore signatures (verifiable
   with `cosign verify-blob`, no key custody) and detached minisign
   signatures verifiable fully offline against `minisign.pub` committed at
   the repository root. The keypair was generated on the owner's machine and
   lives at `~/.oxaudit/release-keys/` (private key never committed); the
   private key is stored as the `MINISIGN_PRIVATE_KEY` repository secret. It
   is unencrypted so CI can sign non-interactively — its confidentiality is
   the secret store's; rotate the keypair if the secret is ever exposed
   (regenerate, push the new `minisign.pub`, re-sign the next release).
3. **macOS/Windows signing credentials — ANSWERED: no developer accounts
   exist yet. DONE: CLI + Linux-first releases.** The desktop bundle job is
   skipped unless the repository variable `DESKTOP_BUNDLES=true` is set;
   when it is, the fail-closed native-signing gate inside that job enforces
   the six `APPLE_*` and `WINDOWS_CERTIFICATE*` secrets before any bundle
   can publish. First releases therefore contain every `oxaudit-cli` binary,
   the Linux desktop artifacts, and both SBOMs — and say so in their notes.
   When the accounts exist: set the secrets, set `DESKTOP_BUNDLES=true`,
   and the next tag ships notarized/Authenticode-signed desktop bundles.

## What already exists

- Tag-driven release workflow: three-platform bundles + CLI, SBOMs,
  SHA256SUMS.txt, SLSA build-provenance attestations, **keyless cosign
  signatures** for `SHA256SUMS.txt` and every `oxaudit-cli-*` binary, draft
  release gated on a human reviewing the artifact list.
- Multi-architecture container image (`ghcr.io/henrycooper86/oxaudit`,
  linux/amd64 + linux/arm64): built natively per architecture, merged into
  one index, cosign-signed; the pinned digest ships as `oxaudit-container.txt`
  and in the release notes.
- `action/action.yml`: composite GitHub Action — downloads a pinned release,
  verifies it against `SHA256SUMS.txt`, runs the scan. Ready for
  `uses: HenryCooper86/oxAudit/action@<tag>` the moment the repo (or the
  distro mirror) is public.
- `scripts/install.sh`: platform-detecting curl|sh installer with checksum
  verification before anything executes.

## The procedure, once visibility is answered

1. Make the repository public **or** create the public distribution repo and
   point `OXAUDIT_REPO` (installer) and the Action's `repo` input at it.
2. Decide the version (`0.1.0` — the manifests already agree).
3. Push the tag: `git tag v0.1.0 && git push origin v0.1.0`.
4. Review the draft release the workflow creates: artifact list (CLI +
   Linux + SBOMs), signing posture (cosign bundles, minisig files), notes.
   Publish it.
5. Exercise the distribution paths from a clean machine: `action/action.yml`
   against a sample repo, `scripts/install.sh`, `minisign -Vm` and
   `cosign verify-blob` and `gh attestation verify` on a downloaded binary.
6. One-time, after the first release that runs the container jobs: flip the
   ghcr.io package to public (GitHub → Packages → oxaudit → Package
   settings → Danger Zone → Change visibility). Packages pushed via
   `GITHUB_TOKEN` start private even on public repos, and a private package
   breaks anonymous `docker pull`. Then verify `docker pull
   ghcr.io/henrycooper86/oxaudit:latest` without credentials.
7. (Optional, public repo) submit the brew tap and mark the Action as
   marketplace-ready.

### Already done (2026-09-26)

- `MINISIGN_PRIVATE_KEY` secret set; `minisign.pub` committed.
- Desktop-bundle job gated behind `DESKTOP_BUNDLES` (off), signing gate
  armed inside it.
- Release notes template documents both signature schemes and states that
  desktop bundles are deliberately absent.

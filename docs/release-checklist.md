# Release checklist

Everything engineering can do without a decision from the repository owner is
done. This file records exactly what remains, who owns it, and the procedure
to run once answered — so the first release is a short afternoon, not a
project.

## The three owner decisions (asked repeatedly, still open)

1. **Repository visibility.** GitHub release assets on a private repository
   cannot be downloaded by consumers, so *every* distribution path below
   (Action, installer, brew) requires either making this repository public or
   creating a separate public distribution repository that mirrors the
   release assets. This is a one-way door and only the owner can open it.
2. **Signing scheme for CLI/Linux artifacts.** Implemented and shipped:
   **Sigstore keyless signing** in the release workflow (no keys to custody;
   signatures verifiable with `cosign verify-blob` by anyone, complementing
   the existing SLSA provenance attestations and native macOS/Windows
   signing). If the owner prefers minisign as an additional offline-verifiable
   scheme, the workflow needs one more step and a published public key — the
   keypair generation is the owner's.
3. **macOS/Windows signing credentials.** The release workflow already fails
   closed without them: all six `APPLE_*` secrets (Developer ID + notary) and
   `WINDOWS_CERTIFICATE*` (Authenticode) must exist as repository secrets
   before a publishable (non-draft-blocked) desktop bundle can be produced.
   If they do not exist, the first release can ship CLI + Linux artifacts
   only, with desktop bundles deferred — the workflow's signing gate makes
   that a deliberate configuration change, not an accident.

## What already exists

- Tag-driven release workflow: three-platform bundles + CLI, SBOMs,
  SHA256SUMS.txt, SLSA build-provenance attestations, **keyless cosign
  signatures** for `SHA256SUMS.txt` and every `oxaudit-cli-*` binary, draft
  release gated on a human reviewing the artifact list.
- `action/action.yml`: composite GitHub Action — downloads a pinned release,
  verifies it against `SHA256SUMS.txt`, runs the scan. Ready for
  `uses: HenryCooper86/oxAudit/action@<tag>` the moment the repo (or the
  distro mirror) is public.
- `scripts/install.sh`: platform-detecting curl|sh installer with checksum
  verification before anything executes.

## The procedure, once the decisions are answered

1. Make the repository public **or** create the public distribution repo and
   point `OXAUDIT_REPO` (installer) and the Action's `repo` input at it.
2. Confirm the Apple/Windows secrets exist (or consciously relax the desktop
   gate for a CLI-first release).
3. Decide the version (`0.1.0` — the manifests already agree).
4. Push the tag: `git tag v0.1.0 && git push origin v0.1.0`.
5. Review the draft release the workflow creates: artifact list, signing
   posture, notes. Publish it.
6. Exercise the distribution paths from a clean machine: `action/action.yml`
   against a sample repo, `scripts/install.sh`, `cosign verify-blob` and
   `gh attestation verify` on a downloaded binary.
7. (Optional, public repo) submit the brew tap and mark the Action as
   marketplace-ready.

# Release and Product Contract Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore deterministic CI/release gates, provider-stream correctness, supply-chain enforcement, and truthful engineering documentation.

**Architecture:** Put policy in small executable helpers, keep workflow wiring declarative, fix the stream state machine at its accumulator, and make documentation state the effective controls.

**Tech Stack:** Rust 1.97.1, Node.js 22, TypeScript/tsx node:test, npm, GitHub Actions, Tauri 2.

**Spec:** `docs/superpowers/specs/2026-08-31-product-hardening-design.md`

## Global Constraints

- Publishable macOS and Windows artifacts fail closed without complete native signing inputs.
- Dry runs may be unsigned and never publish.
- No workflow prints secret values.
- Every external generator and GitHub Action is pinned.
- The pinned rustfmt output is authoritative.

---

### Task 1: Fragmented no-index tool calls

**Files:**
- Modify/Test: `src-tauri/src/ai/mod.rs`

- [ ] Add a failing test that sends one no-index call as an ID/name/argument prefix followed by an arguments-only delta and expects one complete JSON argument object.
- [ ] Run the focused test and confirm the continuation is discarded by the current sequential-slot behavior.
- [ ] Reuse a same-ID entry, route ID/name-free deltas to the latest open entry, and allocate a new slot only when the delta identifies a new call.
- [ ] Re-run all AI accumulator tests, including two complete no-index parallel calls.

### Task 2: Signing preflight

**Files:**
- Create: `tools/require-release-signing.mjs`
- Create: `tests/releaseSigning.test.ts`
- Modify: `.github/workflows/release.yml`
- Modify: `SECURITY.md`

- [ ] Add failing tests for Linux needing no native variables, macOS requiring six Apple variables, and Windows requiring certificate plus password.
- [ ] Run `npx tsx --test tests/releaseSigning.test.ts` and confirm module-not-found.
- [ ] Implement exported `requiredSigningEnvironment` and `missingSigningEnvironment`; direct execution prints names only and exits one when incomplete.
- [ ] Run it before tag-triggered publishable bundle builds with the existing secrets passed as environment variables.
- [ ] Re-run signing tests.

### Task 3: JavaScript advisory gate and deterministic SBOM tools

**Files:**
- Modify: `package.json`
- Modify: `.github/workflows/security.yml`
- Modify: `.github/workflows/release.yml`

- [ ] Add `audit:dependencies` with `npm audit --audit-level=high` and a least-privilege workflow job running `npm ci` then the script.
- [ ] Resolve and pin explicit `cargo-cyclonedx` and `@cyclonedx/cyclonedx-npm` versions; do not use `latest` or an unversioned install.
- [ ] Run `npm run audit:dependencies` and the action-pin checker.

### Task 4: Formatting and stale suppression

**Files:**
- Modify: `src-tauri/src/scanners/mod.rs`
- Mechanically format: Rust workspace sources selected by rustfmt.

- [ ] Remove the obsolete `#[allow(dead_code)]` from `covered_families`.
- [ ] Run `cargo fmt --manifest-path src-tauri/Cargo.toml`.
- [ ] Run the formatter again with `-- --check` and confirm no diff.

### Task 5: Align product promises

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `src/pages/SettingsPage.tsx`
- Modify: `src-tauri/src/cli/mod.rs`
- Modify: relevant resource-budget documentation.

- [ ] State that all model-selected network tools ask, configurable approved fetch hosts may extend named advisory recipients, and private/non-routable addresses remain blocked.
- [ ] State that symlinks are followed only when their canonical target remains inside the project.
- [ ] Document resource ceilings and actionable subpath/ignore guidance.
- [ ] State precise signing, provenance, SBOM, and dry-run guarantees.
- [ ] Update CLI help and Settings copy to match those claims.

### Task 6: Full product verification

**Files:** Verify only.

- [ ] Run `npm run check && npm test && npm run build`.
- [ ] Run `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`.
- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml --workspace --all-features`.
- [ ] Run `cargo clippy --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run version, corpus, action-pin, npm-audit, and cargo-deny checks.
- [ ] Run CLI builds with no default features and with `grammars-core`.
- [ ] Run `git diff --check`, inspect status/stat, and verify only hardening-related files changed.

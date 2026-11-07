# Dependency Refresh Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans and dispatch independent npm and Rust work with superpowers:dispatching-parallel-agents. Track verification here and in ignored local logs.

**Goal:** Update the project's dependencies against current stable registries, close existing PRs without merging, and preserve working desktop, CLI, server, extension, and scanner behavior.

**Architecture:** Keep the existing engine and transports. Update dependency declarations and lockfiles together; make only compatibility changes required by upgraded APIs. Preserve credential-store access and scanner evidence semantics.

**Tech Stack:** Node 22, npm, React, Vite, TypeScript, Rust 1.97.1, Cargo, Tauri 2, GitHub Actions.

**Spec:** User request in this chat, repository AGENTS.md, and docs/dependency-maintenance.md.

## Global Constraints

- Target HenryCooper86/oxAudit-clean; leave the original backup repository untouched.
- Close open PRs without merging. At initial inspection, none are open in the target repository.
- Preserve untracked local work and omit AI attribution from commits.
- Prefer latest stable versions; document any dependency whose latest version cannot preserve a verified platform/API contract.
- Keep the pinned Rust toolchain and Node 22 unless an upgrade requires a deliberate toolchain change.
- Preserve Apache-2.0 licensing boundaries, offline detection, and credential-store compatibility.
- Keep GitHub Actions SHA-pinned.

## Review Focus

- npm peer dependency conflicts and TypeScript/Vite/Vitest migration behavior.
- Rust feature flags, target-specific compilation, and multiple transport behavior.
- Saved credential compatibility across macOS, Windows, and Linux.
- Archive/parser/scanner behavior after dependency API changes.
- Extension editor API floor and CI action/runtime compatibility.

### Task 1: npm application and extension

**Files:** package.json, package-lock.json, editors/vscode/package.json and package-lock.json, affected compiler/test/build configurations and required compatibility call sites.

- [x] Confirm the existing frontend baseline and query stable registry versions.
- [x] Update direct dependencies and lockfiles, preserving coherent peer ranges.
- [x] Resolve upgrade failures with focused compatibility fixes and behavioral regression tests where needed.
- [x] Run build, check, lint, unit/component suites, coverage, CI shell tests, extension compile, and npm audit.

### Task 2: Rust workspace and fuzz dependencies

**Files:** src-tauri/Cargo.toml, crates/*/Cargo.toml, Cargo.lock, fuzz/Cargo.toml and Cargo.lock, required Rust compatibility call sites, docs/dependency-maintenance.md.

- [x] Confirm the existing Rust baseline and query stable crate releases.
- [x] Update all safely migratable direct requirements and both lockfiles, retaining intentional dependency features.
- [x] Diagnose compiler/test failures and adapt API call sites without changing scanner behavior.
- [x] Run workspace/all-feature tests, fmt, clippy, no-default-feature checks, and fuzz-target checks.
- [x] Document any verified compatibility boundary that prevents a latest stable upgrade.

### Task 3: CI dependencies and integration

**Files:** .github/workflows/*.yml, related pinned-tool references, docs/dependency-maintenance.md, this plan.

- [x] Query official releases/refs and update outdated action SHAs and pinned build tools.
- [x] Check version agreement, corpus integrity, and action pins.
- [x] Run the CLI pilot and server/browser integration checks after the upgrades.
- [x] Review the whole diff, verify commit attribution, and prepare the tested update for publication to oxAudit-clean.

## Progress

- Existing target PR inventory confirmed empty through connector search and direct GitHub API; no PRs were merged.
- Baselines passed: 178 Node tests, 728 component tests, and 1,787 Rust tests (one ignored).
- The refresh passed clean npm installs, native TypeScript 7 build/check, lint, unchanged coverage gates, extension API compatibility, and zero-vulnerability npm audits.
- Final Rust validation passed 1,788 tests (one existing ignored), all-target/all-feature clippy, no-default-feature check, workspace/fuzz formatting, fuzz compilation, and all cargo-deny gates.
- Updated CLI pilot, six Chromium scenarios, and all 11 real-CLI CI shell tests passed. A fresh whole-change review found no actionable regressions.
- The Linux/amd64 container release build passed for both CLI and server. The verified commit is prepared for publication to `main`; local receipts are under `.superpowers/dependency-refresh/`.
- Compatibility boundaries and migration details are recorded in `docs/dependency-maintenance.md`.

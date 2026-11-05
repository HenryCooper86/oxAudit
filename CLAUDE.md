# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

oxAudit: a local-first security scanner (source vulnerabilities, secrets, dependency advisories, binaries). One Rust engine exposed three ways: a Tauri 2 + React 19 desktop workbench (the primary product), the `oxaudit-cli` binary, and a feature-gated headless HTTP server (`oxaudit-server`). A finding in CI and on a workstation must be the same finding. Apache-2.0; no GPL rules or code may be copied into the core.

## Toolchain

- Node 22 (`.nvmrc`), `npm ci`. Rust is pinned to 1.97.1 via `rust-toolchain.toml` (clippy + rustfmt); `rust-version` 1.77 in manifests is only the MSRV floor.
- Linux needs the Tauri/WebKitGTK dev packages (see `.github/workflows/ci.yml`, `docs/getting-started.md`).
- The Cargo workspace lives in `src-tauri/`, not the repo root, so always pass `--manifest-path src-tauri/Cargo.toml`.

## Commands

Frontend (run from repo root):
- `npm run dev` (vite only) / `npm run tauri dev` (full desktop app)
- `npm run build` (`tsc && vite build`); `npm run check` (`tsc --noEmit`); `npm run lint` (eslint)
- `npm test` runs both suites below. Two separate runners:
  - `npm run test:unit`: `tsx --test tests/*.test.ts` (node:test, pure modules, no DOM)
  - `npm run test:components`: `vitest run` (jsdom; only `src/**/*.test.ts(x)`, colocated with sources)
  - `npm run test:coverage`: vitest with ratcheted thresholds (CI fails if coverage drops)
- Single test: `npx tsx --test tests/format.test.ts` (node:test; add `--test-name-pattern "name"`), or `npx vitest run src/pages/Assistant.test.tsx -t "name"`.
- `npm run test:ci-shell`: tests for CI shell scripts (`tests/ci/`).
- `npm run test:e2e`: Playwright against a real `oxaudit-server`. Build first: `npm run build` and `cargo build --locked --manifest-path src-tauri/Cargo.toml --all-features --bin oxaudit-server`. Serial, one worker; the fixture in `tests/e2e/helpers.mjs` spawns `src-tauri/target/debug/oxaudit-server` with isolated dirs. CI runs it under a disposable keyring on Linux (Secret Service).

Rust:
- Test everything: `cargo test --manifest-path src-tauri/Cargo.toml --workspace --all-features`
- Single test: append a name filter, e.g. `cargo test --manifest-path src-tauri/Cargo.toml -p oxaudit-scanners <name>` (use `-p oxaudit` for the host crate).
- Format: `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`
- Lint: `cargo clippy --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`
- CLI: `cargo build --locked --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli`, then `npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli`. The `oxaudit-server` bin has `required-features = ["server"]`.

Other CI gates (see `.github/workflows/ci.yml`): `node tools/check-versions.mjs` (versions must agree across package.json/Cargo/tauri.conf), `node tools/build-corpus-suite.mjs --check`, `node tools/check-action-pins.mjs` (workflow actions must be SHA-pinned).

## Architecture

Ports-and-adapters (ADR `docs/architecture/adr/0001-gui-first-ports-and-adapters.md`), enforced by Cargo package boundaries and dependency-wall tests rather than naming:
- `src-tauri/crates/oxaudit-domain`: pure canonical records, identities, invariants (run, artifact, component, observation, evidence, finding, review, verification graph). All scan families produce this same graph.
- `oxaudit-application`: use cases, ports, stage manifests (reject dropped/invented/duplicate candidates), event sequencing.
- `oxaudit-scanners`, `oxaudit-parsers`, `oxaudit-archive`, `oxaudit-compliance`, `oxaudit-benchmark`: deterministic native detectors/rule compilation, tree-sitter grammars, archive handling, compliance mapping, quality benchmarks.
- `src-tauri/src` (the `oxaudit` host crate, lib name `oxaudit_lib`): adapters for SQLite (`findings/`, `history.rs`), HTTP advisories, filesystem, git (`git_context*.rs`), OS credentials, optional external tools (cve-bin-tool/Grype, labelled external evidence), and Tauri `commands/`. Binaries: `main.rs` (desktop), `bin/oxaudit-cli.rs` (logic in `cli/`), `bin/oxaudit-server.rs`.
- Cargo features: `grammars-all` (default; per-language `grammar-*`), `server`. Dropping a grammar makes analysis report Unknown rather than suppress, so recall is preserved.

One engine, multiple transports (ADR 0004): Tauri command bodies are lifted into `*_engine` / `*_inner` functions that both the Tauri command and `src/server/dispatch.rs` call. Add new engine behavior there, never duplicate it per transport. The server exposes `POST /api/invoke/{cmd}` plus an SSE stream at `/api/events` (same event names as desktop, e.g. `scan://progress`, `run://event`). A new command must be registered both in the Tauri `invoke_handler` and the server dispatch; `tests/commandParity.test.ts` and `tests/ipcContract.test.ts` guard this.

Frontend (`src/`): all backend calls go through `src/lib/api.ts`; `src/lib/transport.ts` swaps Tauri `invoke`/`listen` for fetch/SSE when the server's `/env.js` sets `window.OXAUDIT_SERVER` and there is no `__TAURI_INTERNALS__`. Pages pick neither. Backend durable state is authoritative; events are a versioned projection, never the source of truth. Layout: `src/pages/` (workbenches), `src/features/` (project-home, source-scan, dependencies, runs, compliance, verification), `src/components/`, `src/lib/` (zustand stores, helpers). Types in `src/lib/types.ts` mirror Rust models, so IPC changes touch both sides.

## Product invariants worth preserving

- Every ordinary workflow must work without a CLI, cloud account, AI provider, or extra scanner; AI output is advisory and cannot self-verify or mutate review state.
- Absence is never proof: skipped files, cancelled/failed/unsaved runs, or missing coverage are "not evaluated"/"unknown", not "clean" or "resolved". Zero findings is not a safety claim.
- Detection works offline; advisory enrichment is separate.
- Project config lives in `.oxaudit/` (`policy.json` for reviewed suppressions with reason and expiry). Git inspection is read-only with a cleared environment; `scan --staged` scans index blobs.
- Design tokens/theme rules: `docs/design-system.md` (covered by `tests/designSystem.test.ts`, `tests/themeContrast.test.ts`).

## Docs

`docs/cli.md`, `docs/headless-server.md`, `docs/getting-started.md`, and `docs/architecture/` hold detail; `docs/superpowers/{specs,plans}` hold past design/plan work. `CHANGELOG.md` is maintained per release.

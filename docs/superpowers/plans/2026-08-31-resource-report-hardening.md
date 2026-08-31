# Resource and Report Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make hostile or unusually large project inputs bounded, cancellable, and honest about incomplete work, while keeping normal engineering repositories unaffected.

**Architecture:** Enforce limits while inputs are discovered or streamed, before large collections are allocated. Use shared constants across desktop, CLI, and assistant callers, and surface explicit errors instead of partial clean results.

**Tech Stack:** Rust 1.97.1, ignore, Rayon, Tokio, serde parsers, CSV reporting.

**Spec:** `docs/superpowers/specs/2026-08-31-product-hardening-design.md`

## Global Constraints

- Source limits: 100,000 files and 20 GiB eligible bytes.
- Finding limits: 5,000 per file and 100,000 per run.
- Dependency limits: 256 lockfiles, 16 MiB per lockfile, and 100,000 dependencies.
- Binary limits: 100,000 files, 20 GiB, four native workers, and 64 MiB reports/stdout.
- A limit or cancellation never produces a successful clean receipt.

---

### Task 1: Cancellable bounded project collection

**Files:**
- Modify: `src-tauri/src/fs_utils.rs`
- Modify: `src-tauri/src/findings/service.rs`
- Modify: `src-tauri/src/agent/tools.rs`
- Test: `src-tauri/src/fs_utils.rs`

**Interfaces:**
- Produces: `CollectionBudget` and `CollectionError` used by source and assistant collection.

- [ ] Add failing tests for file-count overflow, cumulative-byte overflow, and cancellation during discovery.
- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml fs_utils::tests --all-features` and confirm they fail.
- [ ] Enforce limits and cancellation in both directory walks before inserting paths; return a typed error containing the exceeded limit.
- [ ] Update service and assistant callers to propagate actionable errors and never continue with partial collections.
- [ ] Re-run filesystem, service, and agent tool tests.

### Task 2: Finding count budgets

**Files:**
- Modify: `src-tauri/src/scanners/mod.rs`
- Modify: `src-tauri/src/findings/service.rs`
- Test: `src-tauri/src/scanners/mod.rs`

**Interfaces:**
- Produces: per-file and per-run finding overflow errors.

- [ ] Add failing fixtures that produce more than a deliberately small injected test budget and assert an overflow result rather than truncation-as-clean.
- [ ] Run focused scanner/service tests and confirm failure.
- [ ] Stop collecting after the first over-budget match, propagate overflow through `ScanFileOutcome`, and abort the run before successful persistence.
- [ ] Re-run focused tests.

### Task 3: Bounded dependency parsing and OSV queries

**Files:**
- Modify: `src-tauri/src/deps/lockfiles.rs`
- Modify: `src-tauri/src/deps/osv.rs`
- Modify: `src-tauri/src/commands/dependencies.rs`
- Modify: `src-tauri/src/agent/tools.rs`
- Test: `src-tauri/src/deps/lockfiles.rs`

**Interfaces:**
- Produces: 16 MiB per-file parsing ceiling, 256 lockfile ceiling, and 100,000 dependency/query ceiling.

- [ ] Add failing tests for an oversized lockfile and an aggregate dependency overflow.
- [ ] Run focused dependency tests and confirm failure.
- [ ] Check metadata before `read_to_string`, enforce aggregate limits in desktop and assistant loops, check cancellation between files, and reject oversized OSV batches before chunking.
- [ ] Re-run dependency and agent tests.

### Task 4: Bounded binary discovery and external reports

**Files:**
- Modify: `src-tauri/src/binscan/native/scan.rs`
- Modify: `src-tauri/src/binscan/run.rs`
- Modify: `src-tauri/src/binscan/scan.rs`
- Test: corresponding module tests.

**Interfaces:**
- Produces: bounded binary inventory, four-worker Rayon pool, and 64 MiB output collectors.

- [ ] Add failing tests for file-count/byte overflow and an stdout chunk sequence exceeding 64 MiB using a small injected test limit.
- [ ] Add a failing test that an oversized on-disk JSON report is rejected before `read_to_string`.
- [ ] Run focused binary tests and confirm failure.
- [ ] Enforce inventory budgets during walking, run scans inside a four-thread pool, cap child stdout while draining it, and reject oversized report metadata before reading.
- [ ] Re-run all binary scan tests.

### Task 5: Keep the NVD key out of argv

**Files:**
- Modify: `src-tauri/src/binscan/runtime.rs`
- Modify: `src-tauri/src/binscan/run.rs`
- Test: corresponding module tests.

**Interfaces:**
- Produces: `PreparedCommand` secret environment entries; native `NVD_API_KEY`; Docker `--env NVD_API_KEY` without the value in argv.

- [ ] Replace the current assertion with failing tests proving no argument equals the canary key and the prepared environment contains `NVD_API_KEY` only for online scans.
- [ ] Run focused runtime/run tests and confirm the existing argv behavior fails.
- [ ] Store the key in a zeroizing prepared-command environment, apply it with `Command::env`, and pass only the variable name through Docker.
- [ ] Re-run focused tests and inspect Debug/error paths for secret values.

### Task 6: Spreadsheet-safe compliance CSV

**Files:**
- Modify: `src-tauri/src/adapters/reporting/compliance.rs`
- Test: same file.

**Interfaces:**
- Produces: `csv_cell` that prefixes formula-like values with an apostrophe before RFC 4180 quoting.

- [ ] Add failing literal tests for leading `=`, `+`, `-`, `@`, and whitespace followed by a formula prefix, plus ordinary text unchanged.
- [ ] Run focused compliance adapter tests and confirm formula cases fail.
- [ ] Neutralize the first non-whitespace formula marker and retain quote doubling.
- [ ] Re-run compliance report tests.

### Task 7: Resource/report verification

**Files:** Verify only.

- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml --workspace --all-features`.
- [ ] Run `cargo clippy --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run the CLI source-scan smoke fixture and confirm planted findings still appear.

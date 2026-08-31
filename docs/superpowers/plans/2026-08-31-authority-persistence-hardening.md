# Authority and Persistence Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close assistant authority, secret-handling, session-path, usage-race, and HTTP egress defects without changing public IPC request shapes.

**Architecture:** Classify authority at the tool boundary, sanitize once before data leaves the Rust loop, validate session identity before path construction, serialize mutable JSON stores in application state, and bind web connections to validated addresses.

**Tech Stack:** Rust 1.97.1, Tauri 2, reqwest 0.12, Tokio, tempfile, React 19.

**Spec:** `docs/superpowers/specs/2026-08-31-product-hardening-design.md`

## Global Constraints

- Preserve public Tauri command names and TypeScript payload shapes.
- Never log or print credential values.
- Keep ordinary project-contained source and secret scans automatic.
- Require HITL for every model-selected network request.
- Use red/green TDD for every production behavior change.

---

### Task 1: Network-aware assistant permissions

**Files:**
- Modify: `src-tauri/src/agent/tools.rs`
- Test: `src-tauri/src/agent/tools.rs`

**Interfaces:**
- Consumes: `ToolSpec::{read_only,dangerous}` and `guardrails::classify`.
- Produces: `run_dependency_scan` as a dangerous tool; NVD and OSV tools with `dangerous = true`.

- [ ] Add a failing permission test asserting `search_cve`, `query_osv_package`, and `run_dependency_scan` classify as `Ask`, while `read_file`, `grep_project`, `glob`, and local `run_scan` classify as `Allow`.
- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml agent::tools::permission_tests --all-features` and confirm the network-tool assertion fails.
- [ ] Restrict `run_scan.scan_type` to `source|secrets`, move the dependency branch into `run_dependency_scan`, and mark all three network-backed tools dangerous.
- [ ] Re-run the focused permission tests and confirm they pass.

### Task 2: Central tool-result secret redaction

**Files:**
- Modify: `src-tauri/src/scanners/mod.rs`
- Modify: `src-tauri/src/agent/loop_engine.rs`
- Test: `src-tauri/src/scanners/mod.rs`
- Test: `src-tauri/src/agent/loop_engine.rs`

**Interfaces:**
- Produces: `pub(crate) fn redact_secrets_in_text(text: &str) -> String`.
- Produces: one sanitized serialized tool result reused by model messages and UI previews.

- [ ] Add a failing scanner test with a literal canary token and assert the helper returns `[REDACTED]` without the canary.
- [ ] Run the focused test and confirm the helper is missing.
- [ ] Implement the helper using `secrets::scan_content`, longest-first exact values, and `findings::redaction::redact_exact`.
- [ ] Add a failing loop test proving the exact same sanitized payload feeds the tool message and the 500-character preview.
- [ ] Extract a small pure `safe_tool_result` helper and use it before `ToolFinished` emission and `ChatMessage` insertion.
- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml scanners::tests agent::loop_engine --all-features`.

### Task 3: Bounded assistant file reads

**Files:**
- Modify: `src-tauri/src/agent/tools.rs`
- Test: `src-tauri/src/agent/tools.rs`

**Interfaces:**
- Produces: a 2 MiB bounded line-window reader used by `read_file`.

- [ ] Add failing tests showing a requested line window is returned without loading unrelated lines and a file larger than 2 MiB is rejected with an actionable error.
- [ ] Run the focused tests and confirm the oversized case fails.
- [ ] Replace `read_to_string` plus `Vec<&str>` with metadata validation and `BufRead::lines().skip().take()`, bounding both bytes and returned characters.
- [ ] Re-run the focused tests.

### Task 4: Session identity, containment, and durable writes

**Files:**
- Modify: `src-tauri/src/sessions.rs`
- Modify: `src-tauri/src/commands/sessions.rs`
- Modify: `src-tauri/src/commands/mod.rs`
- Test: `src-tauri/src/sessions.rs`

**Interfaces:**
- Produces: UUID-only trusted transcript paths and index-first access.
- Produces: `AppState.session_store_lock: Mutex<()>`.

- [ ] Add failing tests that `get_messages("../outside")` and `truncate("../outside", 0)` return errors and leave a neighboring `outside.jsonl` unchanged.
- [ ] Add a failing test that truncating a UUID absent from the index performs no write.
- [ ] Run the focused session tests and confirm the traversal cases fail.
- [ ] Parse IDs with `Uuid::parse_str`, require index membership before all transcript I/O, and construct the filename from the parsed UUID.
- [ ] Add private Unix file creation and atomic temporary-file persistence for index/truncate writes; return deletion failures.
- [ ] Lock every session command with `AppState.session_store_lock` while preserving command names and payloads.
- [ ] Re-run `cargo test --manifest-path src-tauri/Cargo.toml sessions --all-features`.

### Task 5: Race-free usage accounting

**Files:**
- Modify: `src-tauri/src/ai/usage.rs`
- Modify: `src-tauri/src/commands/mod.rs`
- Modify: `src-tauri/src/commands/assistant.rs`
- Test: `src-tauri/src/ai/usage.rs`

**Interfaces:**
- Produces: `AppState.usage_store: Mutex<Option<UsageStore>>` and atomic owner-private `UsageStore::save`.

- [ ] Add failing tests for atomic round-trip, malformed-ledger error reporting, and two sequential records retained through the shared update helper.
- [ ] Run focused usage tests and confirm direct-write/silent-reset behavior fails the new assertions.
- [ ] Lazily load the ledger under the application mutex, perform record/save while locked, and read summaries from the same state.
- [ ] Persist through a private temporary file and atomic replacement; make `load` return `Result` rather than silently returning `None` for malformed data.
- [ ] Re-run focused usage and assistant command tests.

### Task 6: Stream-bounded and address-pinned web fetch

**Files:**
- Modify: `src-tauri/src/agent/egress.rs`
- Modify: `src-tauri/src/agent/tools.rs`
- Test: `src-tauri/src/agent/egress.rs`
- Test: `src-tauri/src/agent/tools.rs`

**Interfaces:**
- Produces: validated host/address data from `guard_egress`.
- Produces: a per-hop no-proxy reqwest client pinned with `resolve_to_addrs`.
- Produces: decoded response streaming capped at `max_bytes`.

- [ ] Add failing tests for validated socket-address derivation, oversized declared content length, and chunk streams that cross the limit.
- [ ] Run focused egress/tool tests and confirm the new behavior fails.
- [ ] Return validated addresses from the guard, derive the URL port, create a no-proxy/no-redirect pinned client, and rebuild it after every redirect validation.
- [ ] Replace `response.bytes()` with incremental chunk collection that errors at `max_bytes + 1` and rejects oversized `Content-Length` up front.
- [ ] Re-run all egress and tool tests.

### Task 7: Authority/persistence verification

**Files:** Verify only.

- [ ] Run `cargo test --manifest-path src-tauri/Cargo.toml agent:: ai::usage sessions:: --all-features`.
- [ ] Run `cargo clippy --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run `npm test` to verify the unchanged IPC/event consumers.

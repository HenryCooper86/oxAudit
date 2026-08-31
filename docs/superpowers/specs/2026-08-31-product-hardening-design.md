# oxAudit Product Hardening Design

**Date:** 2026-08-31

**Status:** Approved for implementation

## Purpose

Bring the shipped behavior, CI gates, and documentation into agreement with oxAudit's promises to software engineers. The audit found a healthy automated-test baseline, but also found authority, persistence, resource-budget, release, and provider-streaming failures that are not covered by the current suite.

## Security and Product Invariants

1. Model-selected network activity is never mistaken for a harmless local read. NVD, OSV, general web fetches, and external binary scanners require explicit approval in the assistant loop.
2. Project-contained source reads may remain automatic, but detected credential material is removed before a tool result reaches the model, UI events, or durable transcripts.
3. Renderer-supplied identifiers never form filesystem paths directly. Session access is limited to backend-generated UUIDs that exist in the session index before any I/O occurs.
4. App-owned JSON and JSONL state is owner-private on Unix, updated atomically where replacement is possible, and serialized through application-level locks where concurrent commands can race.
5. Every untrusted input surface has a byte, record, file, result, concurrency, or time budget. Hitting a budget produces an explicit incomplete/failure result rather than a misleading clean scan.
6. Network response limits apply while bytes are streamed and after transparent decompression. The HTTP connection uses the same public addresses that passed egress validation.
7. Credentials retrieved from the OS keyring are never copied into subprocess arguments. cve-bin-tool receives `NVD_API_KEY` through its documented environment-variable interface.
8. Publishable platform artifacts fail closed when native signing material is incomplete. Dry-run artifacts may be unsigned but cannot reach the release publisher.
9. Generated CSV treats repository-controlled and user-controlled fields as data, never spreadsheet formulas.
10. Documentation describes effective behavior precisely, including model-initiated network approval, configurable fetch recipients, project-contained symlink behavior, scan budgets, and release guarantees.

## Design

### 1. Assistant authority and data handling

Keep the current allow/ask/deny pipeline, but classify every network-backed tool as dangerous. Split dependency scanning out of the mixed `run_scan` tool so local source/secret scans remain automatic while OSV traffic asks. Preserve the existing HITL event and response flow.

Add a single Rust sanitizer at the tool-result boundary. It uses the same secret rules and exact-value replacement as canonical findings, then supplies the sanitized JSON string to both the model message and the `ToolFinished` preview. This prevents UI persistence from receiving the raw value and avoids maintaining a second redaction implementation.

`read_file` becomes a bounded streaming line-window read with a 2 MiB input ceiling. It does not materialize the complete file or a vector for every line.

### 2. Session and usage persistence

Parse session IDs as UUIDs and require exact index membership before reads, writes, truncation, or deletion. Construct transcript filenames only from the parsed UUID. Session commands share an application mutex so index and transcript transitions do not interleave.

Index and transcript replacement use a private temporary file followed by atomic persist. Transcript append uses owner-only creation on Unix. A failed transcript deletion is reported rather than silently accepted.

Usage accounting moves behind a lazily loaded application mutex. A completion performs one locked load/record/atomic-save transition, so concurrent runs cannot overwrite one another. Malformed ledgers are surfaced instead of silently resetting totals.

### 3. Egress correctness

Change the egress guard to return the validated public address set. For each URL hop, create a no-proxy, no-redirect reqwest client whose resolver is pinned to those addresses while preserving the original URL host for HTTP Host and TLS SNI. Redirects repeat validation and pinning.

Read response chunks incrementally and stop after the configured decoded-byte limit. Reject a declared `Content-Length` larger than the limit before reading.

### 4. Scanner resource budgets

Introduce named defaults shared by desktop, CLI, and agent callers:

- Source/project discovery: at most 100,000 files and 20 GiB of eligible file metadata.
- Findings: at most 5,000 findings per file and 100,000 per run.
- Lockfiles: at most 256 files, 16 MiB per file, and 100,000 deduplicated dependencies.
- Native binary discovery: at most 100,000 files and 20 GiB; scan on a dedicated Rayon pool with at most four workers.
- External scanner stdout and report files: at most 64 MiB.

Collection loops check cancellation during both policy and selection walks. Limit errors name the exceeded budget and suggest scanning a subpath or adding ignore rules. No limited run is persisted as complete or clean.

### 5. Release and supply-chain enforcement

A testable Node helper determines required signing environment by runner OS and exits non-zero without printing values. Tag-triggered publishable builds run it before bundling. `npm audit --audit-level=high` becomes a package script and a dedicated Security workflow job.

Pin SBOM generators to explicit versions instead of `latest` or an unversioned Cargo install. Keep GitHub Actions pinned by commit as they are today.

### 6. Correctness and documentation

Fix no-index streamed tool-call continuation by correlating a delta with the same call ID or, for an arguments-only continuation, the latest open call. Preserve separate complete no-index calls.

Neutralize formula prefixes in every CSV cell after leading whitespace. Remove the stale dead-code allowance, apply the pinned formatter, and align README, SECURITY, Settings copy, and CLI help with actual controls.

## Error Handling

- Permission denial and cancellation keep the existing typed assistant outcomes.
- Invalid session IDs return a generic invalid-session error and never echo an attacker-controlled filesystem path.
- Budget errors are typed scan failures with actionable messages; partial work is not committed as a successful run.
- Oversized HTTP bodies, lockfiles, scanner reports, or project trees fail before excess data is retained.
- Persistence errors preserve the previous durable snapshot and are shown to the caller.

## Testing Strategy

Every behavioral change follows red/green TDD. Unit tests cover provider deltas, permissions, redaction canaries, path traversal, atomic persistence, stream caps, DNS pin derivation, budget boundaries, subprocess environment handling, and CSV formula prefixes. Existing integration suites verify IPC shapes, CLI behavior, imports/exports, scanning, and UI behavior. Completion requires frontend tests/build, full Rust tests, strict Clippy, rustfmt, reduced-feature builds, corpus/version/action-pin checks, npm audit, cargo-deny, and clean diff checks.

## Non-goals

- Replacing Tauri, SQLite, reqwest, Rayon, or the current findings architecture.
- Adding telemetry, a cloud service, or automatic publication.
- Treating upstream scanner false positives or upstream advisory accuracy as oxAudit security defects.
- Merging into `main` during this implementation session; the finished branch remains available for later review and merge.

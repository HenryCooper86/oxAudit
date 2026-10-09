# Project reliability implementation plan

> **For agentic workers:** Use the execution and parallel-agent skills with the
> file ownership boundaries below. Track steps and evidence in this document.

**Goal:** Complete the six approved reliability, efficiency and usability areas.

**Architecture:** Retain existing services and report/storage adapters. Add a
backend operation registry; share source/image/history workflows across entry
points. Bound retained work and reconcile UI state from durable evidence.

**Tech stack:** Rust 1.97.1, Tauri 2, SQLite, React 19, TypeScript, Node 22.

**Spec:** `docs/superpowers/specs/2026-10-09-project-reliability-design.md`

## Global constraints

- Preserve compatible historic receipts and explicit offline uncertainty.
- Do not execute scanned projects or install their dependencies.
- Keep credentials and raw secret values out of stored evidence and reports.
- Main branch commit/push is authorized; preserve configured human attribution.
- Participant feedback must be observed; the user requested pilot preparation.

## Review focus

- A stale cancellation request must not cancel a replacement operation.
- A delayed response after cancellation must not publish completion.
- Subdirectory source checks must inherit project configuration and exclusions.
- Durable history must refer to Git objects, even if the working tree changes.
- Extraction resource stops must preserve earlier findings and honest coverage.

## Task 1: Backend lifecycle and cancellable bounded registry pulls

**Files:** new `src-tauri/src/scan_work.rs`; `commands/mod.rs`,
`commands/dependencies.rs`, `commands/image.rs`, `commands/history.rs`,
`commands/schedule.rs`, `server/dispatch.rs`, `binscan/registry.rs`.

**Interfaces:** registry begins/finishes operations and exposes active/recent
descriptors with operation ID, kind, target, state and canonical run ID. Leases
own independent `Arc<AtomicBool>` cancellation flags. Legacy category cancellation
and new ID-scoped cancellation use the registry. Registry pull options consume
a cancellation flag, timeout and actual byte allowances.

- [x] Add failing registry tests for conflict, stale cancellation and token isolation.
- [x] Add failing localhost pull tests for stalled manifest/body cancellation,
  understated aggregate size and checked overflow.
- [x] Implement registry leases, engine ownership, scheduled deferral and status API.
- [x] Spool digest-verified pull layers in owned temporary files with bounded reads.
- [x] Run focused tests and the previously failing real server probe with corrected expectations.

## Task 2: Shared durable source workflow and incremental source resources

**Files:** `findings/service.rs`, `findings/service_tests.rs`, `agent/tools.rs`,
new source tool tests, `fs_utils.rs`, scanner models.

**Interfaces:** authorized project/subdirectory scan uses project-relative
identity, project configuration and the existing scan receipt. A compact research
result returns run ID, terminal state, counts, warnings and top findings.

- [x] Add a failing Java-properties parity regression and rule-pack/policy/subdirectory cases.
- [x] Add bounded-read and aggregate finding-limit regressions.
- [x] Use shared service from research tools with independent cancellation/quiet events.
- [x] Bound source reads and incrementally aggregate outcomes; record actual coverage/skips.
- [x] Persist/display skipped enabled rule-pack warnings and validate saved reloads.

## Task 3: Durable image/history evidence across entry points

**Files:** domain run types, image/history shared workflows and commands,
CLI image/history paths, reporting adapters, frontend image/history pages/types.

**Interfaces:** shared workflows return their canonical run ID. Image receipts
store resolved target/layers/options/coverage; history receipts retain blob IDs
and Git context. Stored exports use existing report graph contracts.

- [x] Add failing real-SQLite save/reload/export and failure/cancellation tests.
- [x] Persist target-specific projections, report graphs and terminal attempts.
- [x] Route desktop/server/CLI through shared workflows and add receipt reload UI.
- [x] Verify image-tag and historical-object identity remain immutable.

## Task 4: Native resource allowance (independent worker)

**Files owned by worker:** `crates/oxaudit-archive/src/*`,
`binscan/native/scan.rs`, `binscan/native/strings.rs`, related native tests/docs.
Root owns `binscan/registry.rs` and source resources.

- [x] Add meaningful regressions proving buffer limits and retained evidence.
- [x] Reduce retained member work through streaming/spooling or bounded batches.
- [x] Enforce a process-shared native allowance across workers; release it reliably.
- [x] Preserve distro metadata, Maven metadata, nested archives and cancellation.
- [x] Report focused red/green evidence and actual allowance limitations.

## Task 5: Coverage/recovery/pagination (independent UI worker plus root)

**Worker files:** `lib/transport.ts` and tests, source FindingList, dependency and
binary table pagination helpers/tests. Root owns operation store/API and image/history UI.
Root also owns lockfile discovery response and pack warnings.

**Interfaces:** transport emits `transport://reconnected` and `transport://lagged`
events; root reconciles operation/history state. Pagination retains selection by
identity and keyboard/bulk actions; parsed lockfile count becomes nullable with
optional parse status/error.

- [x] Add failing reconnect/lag and large-list pagination/selection tests.
- [x] Implement bounded rendered lists and explicit transport recovery events.
- [x] Implement unknown/error discovery UI and persisted coverage warnings.
- [x] Integrate backend work state so navigation and reconnect retain ownership/results.
- [x] Measure 10,000-record interactions and test accessibility behavior.

## Task 6: Quality/performance/pilot tooling (independent worker)

**Worker files:** new `.github/workflows/quality-benchmarks.yml`, quality/performance
tools/tests, benchmark fixtures/baselines and pilot docs/forms.

- [x] Add validation regressions for per-category benchmark comparisons and participant data.
- [x] Add scheduled pinned external benchmark execution with retained artifacts and baseline comparison.
- [x] Add end-to-end CLI time/peak-RSS fixtures and a reproducible performance report tool.
- [x] Prepare participant workflow and validated feedback capture; keep observations empty.
- [x] Run portable tooling tests and representative real CLI measurements.

## Integration, review and delivery

- [x] Inspect each worker's edits and integrate shared interfaces.
- [x] Run fmt, strict Clippy, Rust workspace/all-feature suite and corpus validation.
- [x] Run frontend tests, type-check, build and CI shell contracts.
- [x] Run actual CLI/server lifecycle, durability, resource and offline smoke probes.
- [x] Obtain fresh independent whole-change review and fix material findings.
- [x] Record evidence and honest limitations in the reliability guide/plan.
- [ ] Commit validated changes, push main and verify the remote SHA/checks.
  This evidence snapshot precedes delivery; the Git remote and GitHub runs record that outcome.

## Execution record

- Initial main: `1e27c8f0d46abc319e78e643bb5c53e8e1339a92`; working tree clean.
- User approved all six areas and requested pilot preparation with no participant feedback yet.
- Execution uses parallel workers only for disjoint file groups; root integrates backend contracts.

- All six implementation areas completed; UI ownership/recovery integration was delegated to the UI worker, with root integrating backend contracts.
- Fresh independent whole-change review found no outstanding code findings after fixing persistence, identity, export lifecycle and target-switch recovery regressions.
- Final local validation: 1,356 Rust tests passed (one existing ignored); strict Clippy/fmt passed; 167 Node + 304 Vitest tests passed; typecheck/build passed; 10 CI shell tests passed; both reduced grammar builds passed.
- Live server checks passed: stalled manifest cancellation in 26.89 ms, overlap/stale/pre-start cancellation isolation, verified layers, nullable malformed discovery, shared Java configuration, immutable/redacted history export and four receipt reloads after restart. Actual CLI image save/reopen/export passed after deleting its target.
- External pinned benchmark: all 11 category gates passed, 2,740 cases; TP1346/FP724/TN601/FN69 unchanged. Four final CLI performance populations passed. Pilot form remains empty; maintainer smoke passed.
- Reproducible commands, retained receipts and explicit unmeasured limits are recorded in `docs/project-reliability-validation.md`, `docs/quality-performance-validation.md`, and the benchmark artifacts.

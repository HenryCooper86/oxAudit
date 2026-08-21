# oxAudit Architecture Strengthening Implementation Plan

> Implement incrementally. Preserve the current Source Results work and keep
> every shipped workflow usable at the end of each task.

**Goal:** Establish compiler-enforced domain/application boundaries and one
durable, GUI-first run architecture before adding more scanner-specific
features.

**Architecture:** Add small Rust domain and application crates, place ports and
the run coordinator inside them, and wrap existing source/finding behavior as
adapters. Add cross-platform CI and benchmark contracts first so parity and
regressions are measurable. Migrate dependency and binary scans only after the
source workflow passes unchanged through the new seam.

**Primary references:**

- `docs/architecture/2026-08-21-upstream-architecture-study.md`
- `docs/architecture/2026-08-21-gui-first-target-architecture.md`
- `docs/superpowers/specs/2026-08-20-oxaudit-durable-findings-settings-design.md`

## Constraints

- The GUI remains a complete primary workflow; no new CLI-only capability.
- Do not bundle or copy cve-bin-tool or VulHunt GPL code/rules.
- Existing native scans remain available without external tools or AI.
- Raw secret material never crosses scanner redaction boundaries.
- Durable backend state, not React/Zustand/localStorage, is authoritative.
- Every stage reconciles input/output manifests; no silent candidate loss.
- Existing uncommitted work is user-owned. Stage or commit only files belonging
  to the active task after reviewing the exact diff.
- Avoid a repository-wide move. Extract a contract, add a wrapper, prove parity,
  then move ownership.

## Task 1 — Add a reproducible CI baseline

**Files:**

- Create `.github/workflows/ci.yml`
- Modify `package.json` only if a missing deterministic script is required
- Modify Rust files only to remove inherited Clippy warnings, in isolated diffs
- Create `docs/architecture/adr/0001-gui-first-ports-and-adapters.md`

**Work:**

1. Add least-privilege PR/push jobs for `npm ci`, `npm run check`, `npm test`,
   `npm run build`, Rust format, tests, and Clippy.
2. Exercise supported Rust/Tauri code on Linux, macOS, and Windows. Install only
   the documented Linux Tauri build prerequisites.
3. Use concurrency cancellation and bounded timeouts.
4. Pin third-party actions to immutable commit SHAs with version comments.
5. Remove the current Clippy debt in focused behavior-preserving patches, then
   make `-D warnings` a gate. Do not hide warnings with a repository-wide allow.
6. Record the dependency direction and GUI-first decision in ADR 0001.

**Verification:**

```bash
npm ci
npm run check
npm test
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
```

**Exit:** all commands pass locally and the workflow contains no publish,
release, issue-writing, or secret-requiring action.

## Task 2 — Create compiler-enforced core crates

**Files:**

- Modify `src-tauri/Cargo.toml`
- Modify `src-tauri/Cargo.lock`
- Create `src-tauri/crates/oxaudit-domain/Cargo.toml`
- Create `src-tauri/crates/oxaudit-domain/src/lib.rs`
- Create domain modules for ID, run, artifact, component, observation, evidence,
  finding, review, verification, provenance, and error
- Create `src-tauri/crates/oxaudit-application/Cargo.toml`
- Create application modules for ports, manifest, events, and coordinator

**Work:**

1. Make `src-tauri` a Cargo workspace while keeping the existing package as the
   Tauri host.
2. Define stable newtypes for run, artifact, component, observation, evidence,
   finding, rule-pack, provider-snapshot, and verification IDs.
3. Define the run state machine and reject illegal/terminal transitions.
4. Define redacted evidence variants and make raw-secret construction
   impossible through the public API.
5. Define `CapabilityDescriptor` with ID, version, kind, provenance, offline
   support, and availability.
6. Define ports: `Detector`, `ObservationSink`, `RunRepository`, `RunEventSink`,
   `AdvisoryProvider`, `RulePackStore`, `ReportWriter`, and `Verifier`.
7. Add a test that scans dependency metadata/manifests and fails if the domain or
   application crates acquire Tauri, rusqlite, reqwest, or presentation imports.

**Tests first:**

- legal and illegal run transitions;
- stable ID serialization;
- event envelope sequence/schema behavior;
- manifest dropped/invented/duplicate accounting;
- redaction invariants;
- domain/application dependency wall.

**Exit:** `cargo test --workspace` passes; no production workflow uses the new
crates yet.

## Task 3 — Implement the run coordinator without changing UI behavior

**Files:**

- Add coordinator and stage modules in `oxaudit-application`
- Create host adapters under `src-tauri/src/adapters/`
- Create presentation mappings under `src-tauri/src/presentation/`
- Modify `src-tauri/src/lib.rs` composition only

**Work:**

1. Implement sequenced run/stage/artifact/observation/warning/terminal events.
2. Make repository writes and events separate ports; events are never the source
   of truth.
3. Reuse the existing cancellation token and typed command errors through
   adapters.
4. Add recovery semantics for interrupted stages and persistence failures.
5. Add coordinator tests with in-memory ports covering success, cancellation,
   detector failure, event failure, persistence retry, and manifest mismatch.

**Exit:** coordinator behavior is fully tested with fakes, but existing scan
commands still execute their old path.

## Task 4 — Route Source Scan through the new seam

**Files:**

- Modify `src-tauri/src/findings/service.rs`
- Modify `src-tauri/src/findings/repository.rs`
- Modify `src-tauri/src/commands.rs`
- Add source detector/repository/event adapters
- Modify frontend event normalization only if the versioned envelope requires it

**Work:**

1. Wrap current file collection, pattern scanning, secret scanning, coverage,
   scope, fingerprint, policy, diff, retention, and save behavior.
2. Map current findings into Artifact/Observation/Evidence without changing the
   persisted Source Results DTO yet.
3. Reconcile observations before persistence with the generalized manifest.
4. Emit new sequenced events and preserve a compatibility mapper for current
   Source Scan progress.
5. Run the complete durable-source test suite and browser/native acceptance
   workflow.

**Parity gates:**

- same candidates for the same fixture and options;
- identical redaction at DTO, persistence, policy, export, and Assistant edges;
- same fingerprint/diff/review projections;
- cancellation and NotSaved retry remain recoverable;
- last completed results remain visible while scanning.

**Exit:** Source Scan uses `RunCoordinator` with no intended UI behavior change.

## Task 5 — Establish the benchmark and rule provenance contracts

**Files:**

- Create `benchmarks/schema/`
- Create `benchmarks/ground-truth/`
- Create `src-tauri/crates/oxaudit-benchmark/` or a repository-local bounded
  runner after an implementation-language decision
- Create a validator for `src-tauri/src/binscan/native/signatures.toml`
- Add benchmark/provenance jobs to CI

**Work:**

1. Define pinned target, expected observation/evidence, allowed variants,
   expected absence, platform/architecture, and provenance schemas.
2. Persist benchmark state atomically and support resume, force, tally-only, and
   targeted reruns.
3. Report true/false positives, misses, per-rule/component coverage, runtime,
   peak resource estimate where practical, and regressions from the previous
   accepted baseline.
4. Require every binary signature to declare creation method, evidence source,
   licence/provenance, applicable architectures, and positive/negative fixtures.
5. Begin with small deterministic fixtures already in the repository; do not
   claim representative recall until the corpus expands.

**Exit:** CI can detect a rule regression and provenance omission without a
network call or model.

## Task 6 — Migrate dependency and binary scans to durable runs

**Files:**

- Add dependency and binary `Detector` adapters
- Extend canonical SQLite adapter/migrations
- Refactor `src/pages/DepsScan.tsx` and `src/pages/BinaryScan.tsx` around shared
  run controller components
- Add feature tests for reload, history, cancellation, and evidence projection

**Work:**

1. Persist dependency declarations as components/observations before OSV
   enrichment.
2. Persist binary artifacts, component identity evidence, decoder provenance,
   and advisory matches separately.
3. Keep optional cve-bin-tool/Grype results as external adapter evidence with
   tool/version/receipt; never mix their origin into native evidence.
4. Generalize project/run history, retention, diff, policy, and manifest
   accounting.
5. Extract one shared React run timeline/controller while keeping each scan's
   domain-specific result views.

**Exit:** all three scan screens reopen durable results after restart and show
the same lifecycle semantics.

## Task 7 — Build the first GUI-native rule and quality surfaces

**Files:**

- Create `src/features/rules/`
- Create `src/features/quality/`
- Add backend read-only commands for capability, rule, provenance, and benchmark
  status
- Add sidebar routes only after empty/loading/error/ready states are complete

**Work:**

1. Rule Library lists built-in rules, pack/version, engine, provenance,
   architecture/language scope, fixture health, and current enabled snapshot.
2. Quality Lab shows benchmark scope, honest corpus size, passes, misses, false
   positives, runtime, and historical regression—not a vanity score.
3. Both pages work without network access and never expose arbitrary rule-script
   execution.
4. Add accessible keyboard navigation, text status in addition to color, and
   responsive behavior matching the workbench.

**Exit:** the first architecture-specific capabilities are understandable and
auditable from the GUI, not just configuration files.

## Deferred follow-on sequence

After Tasks 1–7 are complete and stable:

1. provider snapshot registry and Data Sources GUI;
2. oxAudit JSON schema and SARIF;
3. normalized inventory with CycloneDX/SPDX;
4. OpenVEX/CycloneDX VEX with conflict preview;
5. independent verifier records and Verify action;
6. declarative public rule packs;
7. optional semantic binary adapter, beginning with function signatures and call
   graph before full IR/decompilation;
8. CLI/MCP/CI automation adapters over the same use cases, never before GUI
   completeness.

## Completion evidence for this plan

- architecture and adoption decisions remain traceable to exact upstream
  commits;
- CI and local verification commands pass;
- dependency-wall tests enforce the intended imports;
- source parity is demonstrated before additional scan families migrate;
- every run stage has manifest accounting;
- benchmark results include corpus size and limitations;
- GUI acceptance covers first scan, cancel, retry, reopen, review, and export;
- no GPL source/rules or mandatory external runtime enter the product.

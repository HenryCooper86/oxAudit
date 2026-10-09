# Project reliability and polish

## Intent and constraints

Implement all six areas approved after the 2026-10-09 gap review: scan lifecycle,
source parity, durable image/history evidence, resource efficiency, visible
coverage/recovery, and broader quality/pilot validation. Keep Rust/Tauri and
React/TypeScript, existing storage/report adapters, compatible saved receipts,
and offline behavior. Do not install or execute scanned projects. Commit and
push validated changes to main, using the configured human identity without
attribution or co-author trailers.

The user has no external participant feedback. Prepare an actionable pilot
workflow and feedback capture/validation; never invent observations or claim
external usability acceptance.

## Design

1. A process-local backend work registry owns one interactive or scheduled scan
   at a time, across source, dependencies, binaries, images and history. Every
   operation gets a unique ID and independent cancellation flag; ID-scoped
   cancellation cannot affect a later run. Scheduled work defers while busy.
   Expose active/recent state so navigation and headless reconnection can recover.
   Progress associates with operation/run identity. Existing legacy cancel
   commands remain supported and target their own scan category.
2. Research source scans use the same durable service as normal source scans,
   including project configuration, enabled rules, policy and coverage. An
   authorized subdirectory preserves project context and records its scope.
   Quiet sinks avoid replacing another page's progress. Cancellation and errors
   never turn partial work into completed empty results.
3. Image and Git-history operations save canonical target-specific receipts,
   including failed/cancelled attempts, effective options, coverage and provider
   provenance. Images preserve resolved digest/layer identity. History preserves
   Git object identities without claiming current working-tree locations.
   CLI, desktop and server return the saved run ID and support stored exports.
4. Registry downloads enforce checked actual aggregate byte counts, deadlines
   and cancellation during requests/body chunks. Verified layers are spooled
   into owned temporary storage and scanned without retaining the entire pull.
   Native extraction uses bounded retained buffers under a shared allowance;
   source results enforce aggregate finding limits as work is produced, and
   source reads remain bounded if files grow. Preserve package metadata and
   detections across member order. Document measured and unmeasured limits.
5. Discovery reports unknown counts and parse errors explicitly. Skipped enabled
   packs are saved/displayed as coverage warnings. Lost SSE frames and reconnect
   trigger reconciliation against backend state. Large source/dependency/binary
   result lists are paginated with usable keyboard and bulk selection behavior.
6. Scheduled pinned external benchmark jobs retain per-category results and
   compare meaningful baselines. End-to-end performance tooling records elapsed
   time and peak memory for owned source/image/archive/dependency fixtures.
   Pilot feedback tooling validates real observation records and remains empty
   until supplied by participants.

## Acceptance

Reproduce each bug before its fix. Cover stalled pull cancellation, concurrent
clients, stale cancellation IDs, scope/policy/configuration parity, save failure,
reload/export identity, understated sizes, overflow, finding-heavy source,
malformed discovery, dropped rules, reconnect and 10,000-record navigation.
Run Rust workspace/all-feature tests, strict Clippy/fmt, frontend tests/check/build,
CI shell contracts, corpus checks and targeted real CLI/server probes. Use a fresh
independent final review; fix material findings before committing/pushing.

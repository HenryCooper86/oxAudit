# Experience completion implementation plan

**Goal:** Complete the six approved refinements and ship verified changes on main.

**Architecture:** Keep scan engines and full-report contracts. Add shared target
and observed-progress controls, distinctly typed paged saved-result APIs backed
by normalized SQL rows, and evidence-based usability validation.

**Tech stack:** Rust, SQLite, Tauri, HTTP/SSE, React, TypeScript, Node tests, Vitest.

**Spec:** [Experience design](../specs/2026-10-10-experience-completion-design.md).

## Global constraints

Preserve exact operation ownership/cancel, complete exports, review precedence,
source diff coverage, native credential persistence and legacy receipts. Page
limits cap at 200. No invented progress, external participant evidence, release
publication, retagging, visibility changes or draft deletion. Existing user
authorization covers the implementation and commit/push to main.

## Review focus

- A page/filter change during a slow response must not show another run's data.
- A later failed/cancelled attempt must retain the original saved receipt identity.
- Secret exports remain redacted and must not accidentally export only one page.
- Legacy receipts and expired/local/policy reviews must retain their prior meaning.
- Narrow layout, picker rejection and keyboard-only operation must remain usable.

## Task 1: Dependency automation and release facts

Owned files: `.github/dependabot.yml`, `docs/release-checklist.md`, focused note.

- [x] Inspect failed resolver evidence and official configuration/backend contracts.
- [x] Ignore only keyring major updates; group npm/Cargo minor/patch updates.
- [x] Replace obsolete release blockers with actual assets and owner review items.
- [x] Parse configuration, run existing relevant contracts and record limitations.

## Task 2: Target and observed progress controls

Owned files: shared target/progress components, five scan pages and focused tests.

- [x] Write behavior tests for dialog cancel/error, server hints and no auto-submit.
- [x] Observe their intended failures, implement shared target controls, rerun tests.
- [x] Write stale-operation/sequence/unknown-stage and truthful counter tests.
- [x] Implement observed progress and preserve ownership/receipt behavior.
- [x] Root fixes backend phase/lifecycle tagging with RED/GREEN regressions.

Expected focused command: `npx vitest run src/components/FolderPicker.test.tsx src/features/runs`.
Expected result: all named meaningful behavior cases pass after observed failures.

## Task 3: Actual paged saved-result reads

Owned files: Rust persistence/query/service/command/server layers; additive TS API
and types. The paging UI worker integrates callers after target/progress page edits are complete.

```ts
loadSourceRunMetadata(runId: string): Promise<SourceRunMetadata>
loadSourceRunPage(runId: string, query: SourceFindingsQuery): Promise<SourceFindingsPage>
loadCanonicalProjectionMetadata<T>(runId: string): Promise<CanonicalProjectionMetadata<T>>
loadCanonicalProjectionPage<T>(runId: string, section: CanonicalProjectionSection,
  query: ResultPageQuery): Promise<ResultPage<T>>
```

- [x] Write legacy round-trip, off-page corrupt-row and filtered count/order tests.
- [x] Observe failures; add transactional normalization and bounded SQL queries.
- [x] Add source review/diff/filter parity tests before query implementation.
- [x] Register equivalent Tauri and HTTP commands, declare distinct partial types.
- [x] Integrate saved restore/search/page UI with request-generation guards.
- [x] Test deep pages, reload, filter reset, complete exports and secret redaction.
- [x] Measure actual saved-read response population/bytes with inert large receipts.

## Task 4: Readability and broader acceptance

Owned files: palette/global shell only where measured faults occur, contrast tests,
pilot/QA documentation and real browser artifacts.

- [x] Test normal text/status colors against actual theme surfaces and badge fills.
- [x] Observe contrast failures; adjust affected colors and rerun the checks.
- [x] Exercise labels, focus, Enter/Space, Escape, narrow sizes and both themes.
- [x] Correct reproducible accessibility/layout failures with targeted regressions.
- [x] Run final CLI pilot smoke, retain receipts and prepare external acceptance form.
- [x] Record observed maintainer checks separately from pending external feedback.

## Integrated delivery

- [x] Run workspace all-feature tests, strict Clippy, fmt, frontend tests and build.
- [x] Check relevant reduced grammar/server builds and actual consumer CI shell.
- [x] Record final preserved CLI checksum, pinned corpus gates and workload receipts.
- [x] Obtain fresh whole-change review; fix validated issues and rerun relevant checks.
- [x] Commit with existing human identity and no attribution/co-author trailers.
- [x] Push main, verify remote SHA/clean tree and inspect hosted workflows/artifacts.

## Execution notes

Independent workers own maintenance, target/progress UI, paging persistence and
paging integration. Root owns event-tagging fixes, readability, real browser/pilot
checks and delivery. No concurrent page edits between integration and target/progress.
User's earlier request for pilot preparation remains applicable: participant
feedback is unavailable, so external acceptance cannot be invented.

Final browser checks exposed a pre-existing Binary Offline defect: the native
scanner ignored the flag, and Grype refresh/Docker pull boundaries also needed
explicit enforcement. The offline network-trap, executable scanner fixture and Docker invocation
regressions passed; final workspace checks, native builds and real browser
validation passed before delivery. Details and limits are retained in
[the QA receipt](../../qa/2026-10-10-experience-completion.md).

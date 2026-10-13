# Remaining workflow implementation plan

**Goal:** Complete the three follow-ups in the [project review](../../qa/2026-10-13-project-review.md).

**Architecture:** Keep report writes on the existing authenticated command with
an explicit server destination. Add paged inventory queries over canonical
storage, with derived search/advisory indexes that leave saved evidence intact.
Reuse the existing result-page hook and navigation controls. Validate the built
client against a temporary local server and fixture database.

**Constraints:** Preserve desktop dialogs, immutable evidence, Unicode search,
advisory associations, exact counts and request ownership. Keep database migration
and page retention bounded. Preserve human Git attribution without co-author
trailers. Existing security policy and server filesystem semantics apply.

## Report saving

- [x] Reproduce browser save failure in the rendered page test with server transport enabled.
- [x] Add a labelled server file path and disable Save for a blank destination.
- [x] Capture that destination with report inputs; destination edits invalidate
  pending save actions. Retain desktop dialog behavior and stale-result guards.
- [x] Exercise successful save, failure/retry, blank paths and edits while pending.

## Inventory queries and UI

Interfaces:

```ts
listInventoryRuns(query: ResultPageQuery): Promise<ResultPage<CanonicalRun>>
loadInventoryPage(runId: string, query: ResultPageQuery): Promise<InventoryPage>
// InventoryPage extends ResultPage<InventoryComponentView> and carries
// runId, targetLabel, runKind, updatedAtMs and providerSnapshotCount.
```

- [x] Write Rust regressions for old inventories crowded out by unrelated runs,
  deep pages, exact totals, Unicode/alias/advisory search, evidence association,
  legacy migration and invalid page inputs.
- [x] Add repository inventory queries and schema v9 derived indexes. Populate
  indexes in the same component/observation transactions; backfill one row at a
  time. Read only the requested component page and its related evidence.
- [x] Expose both queries through desktop commands and HTTP dispatch, preserving
  the existing full-inventory API for compatibility.
- [x] Replace local filtering/paging with bounded requests and visible run-page
  navigation. Keep run selection, request errors and retries correctly owned.
- [x] Verify rendered navigation/search, late responses, page failures/retry,
  empty states and exact counts using component tests.

## Client verification and delivery

- [x] Build and run an isolated headless server with an owned fixture database.
- [x] Verify browser report writing and the actual output, old-run discovery,
  deep inventory search/paging, keyboard operation and accessible status markup.
- [x] Add delayed/reconnect/dialog cases to the pilot protocol and document
  observed checks separately from untested native/screen-reader behavior.
- [x] Run frontend and Rust suites, production build, formatting and Clippy;
  obtain independent review and resolve confirmed findings.

## Review focus

- Edits during report preview must not write to an obsolete destination.
- Unrelated recent runs must not hide completed inventory history.
- Search must retain Unicode matching and advisory-to-component identity.
- Migration, idempotent appends and late advisory arrival must keep indexes complete.
- Old page responses must not overwrite new selection or search state.

## Execution record

Implementation uses the current checkout and existing patterns. The user
requested continuation of these documented follow-ups; no new subsystem or
external service is needed.

Verification evidence and client limitations are recorded in
[the workflow verification report](../../qa/2026-10-13-remaining-workflows.md).
Independent review found a deep-page error reset in the shared pagination hook;
regressions now cover exact-offset retry and navigation away from a failed page.
The final review reported no remaining concrete findings.

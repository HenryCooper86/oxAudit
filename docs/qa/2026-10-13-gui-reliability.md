# GUI reliability review — 2026-10-13

This pass reviewed the existing React/Tauri project for reproducible correctness,
request ownership, error recovery, feature consistency and avoidable GUI work.
Changes are in the working tree; no commit or deployment was made.

## Fixes

| Area | Confirmed problem | Delivered behavior |
| --- | --- | --- |
| Verification history | Switching claims exposed the previous claim's history, verdict, limitations or errors. Delayed saves could append to another claim; a delayed history read could erase a new record. | A keyed claim panel owns drafts and history. Stale reads are ignored; immutable records merge by ID. |
| Verification writes | Navigating A → B → A while a save was pending allowed a duplicate save. Concurrent completions could lose a receipt needed by a remounted panel. | A shared per-finding pending guard and receipt map survive navigation. Receipts are reclaimed only after history confirms that exact record. |
| Verification navigation | Filtering could leave an invisible claim editable; Back selected the first claim again. The entire claim list rendered at once. | Detail follows the visible selection, Back clears it, and the list renders 50 claims per page. Claim and history failures offer retry. |
| Settings themes | A full save could overwrite a newer theme selection in the form. Failed theme persistence left the failed value selected and prevented retry. A pending theme response could override Reset. | Separate theme revisions preserve newer drafts; failed writes restore the persisted selection and allow retry. |
| CVE research | Search completion after navigation could restore stale shared sidebar status. | Search, detail and package request lifetimes are invalidated on teardown. |
| Data sources | Initial registry failures lacked recovery; empty registries lacked an explanation. Terms links could produce unhandled opener rejections. | Registry retry and empty states are explicit, stale loads are ignored, refreshes are guarded, and opener errors produce a toast. |
| Rule library | Searching by pack or engine showed matching packs with their rule rows removed. The server GUI invoked an unsupported native picker; picker errors escaped handling. | Pack/engine matches retain their rules. Server mode accepts a server file path, desktop mode retains its picker, and failures are shown within the validation workflow. |
| Quality reporting | Subtracting each failed rule from the fixture count could underflow or miscount targets. Different corpus versions were compared as though compatible. The first run claimed no regression without a baseline. | The shared scorer counts passing targets once, comparisons require compatible versions, and initial results identify the new baseline. |
| Quality GUI | A grammar-query failure falsely reported text-only scanning; two section labels referenced absent IDs. Benchmark scoring used synchronous GUI command dispatch. | Grammar failures are visible and retryable, sections have named headings, and Tauri dispatches benchmark work asynchronously. |

Verification logic is separated into a claim panel and a small write store;
the touched JSX is expanded for readability. Changes avoid broad rewrites of
working scan engines. Strict TypeScript unused-code checks and Rust Clippy
reported no new issues in their covered code paths.

## Validation

Added 23 frontend regression cases and two Rust cases. Confirmed bugs were
reproduced before their fixes. Timing tests control delayed reads and writes;
component tests use the real components with API/native boundary doubles.

- `npm test`: 173 Node tests and 433 Vitest tests passed (53 Vitest files).
- `npm run check`: passed.
- `npm run build`: passed. The existing warning about the intentionally external
  `/env.js` script remains.
- `npm run test:ci-shell`: nine passed; the existing optional real-CLI case was
  skipped because its externally supplied CLI was not configured.
- `cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --features server`:
  1,401 passed, one existing live OSV test ignored; benchmark smoke targets
  succeeded. Default features include all shipped grammars.
- `cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --features server -- -D warnings`:
  passed.
- `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` and
  `git diff --check`: passed.
- Independent read-only review reproduced the navigation/reset/concurrent-write
  issues, rechecked their fixes, and reported no remaining concrete regressions
  in the reviewed patch.

## Limits

A production frontend and headless server were built for a local GUI check,
but Chrome access was declined. The temporary server was stopped. No live
browser, native interaction, screen-reader, Windows/Linux or hosted CI checks
were completed in this pass. Automated component coverage does not establish
visual layout or actual desktop behavior.

Pagination bounds rendered claim rows; the claims API still returns the full
queue. Asynchronous benchmark dispatch avoids synchronous GUI command handling,
but is not a measured latency improvement. This review does not establish that
every possible defect or unused runtime path has been eliminated.

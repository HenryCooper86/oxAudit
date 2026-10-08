# Bug review — 2026-10-08

Confirmed problems found during this review are fixed in the working tree. The
existing suites passed before the review once test sockets were allowed; new
reproductions exposed gaps in that coverage. Added 29 tests and strengthened the
existing schedule receipt test. An independent, read-only review identified
additional Yarn and history lifecycle issues; those were reproduced, fixed, and
reviewed again.

| Area | Confirmed problem and resulting behavior |
| --- | --- |
| Yarn Classic | `version "1.2.3"` was not recognized. Classic and Berry lockfiles now produce resolved package coordinates. |
| Yarn nested fields | A nested dependency named `version` overwrote the package's resolved version. Only direct entry fields can provide that version. |
| Yarn aliases | npm aliases were queried using their alias selector instead of the registry package name. Simple, scoped, and unversioned Classic aliases and explicit Berry aliases now use the underlying name. |
| pnpm | Legacy slash coordinates and peer suffixes omitted packages or corrupted names/versions. Both coordinate formats retain the package identity while removing peer context; scoped and underscored names remain intact. |
| Python requirements | Extras, inline comments, continued hashes, and local version suffixes prevented correct package queries. Exact pins now preserve these supported forms. |
| Python coverage | Ranges were treated as installed versions, and unpinned packages/includes could be silently omitted beside valid pins. These unresolved inventories now fail with an explicit incomplete-coverage error. No dependency resolver or recursive include reader is implied. |
| Recent scan storage | Valid JSON with the wrong shape could crash `addRecentScan`. Loaded records are validated, invalid entries discarded, and the cache bounded. |
| Server authentication | Unavailable storage could prevent startup or token entry; unconditional reload discarded an in-memory token. Authentication now works for the current session without persistent storage or reload, and rejected tokens leave the gate open. |
| Authentication races | A delayed 401 for an older token could reopen the gate after entering a new token. Only rejection of the current token can trigger the gate. |
| History completeness | A truncated empty history scan reported a clean status and showed the normal empty-result message. Partial coverage now remains explicit in both page and global status. |
| History selection | Filtering retained a hidden finding's detail. Selection now comes from visible findings and clears when no finding matches. |
| History lifecycle | Requests finishing after unmount restored discarded global status or overwrote a remounted page's run. Completed and failed requests now check mount ownership before publishing. |
| Image scan lifecycle | Enter could start another scan while one was running, and delayed event subscriptions leaked after unmount. A synchronous invocation guard and subscription cleanup address both. |
| Portfolio lifecycle | Delayed event subscriptions leaked, and older refresh responses could undo a newly saved schedule in the UI. Cleanup and refresh generations discard stale work. |
| Portfolio evidence | Unavailable counts appeared as zero open findings, and unsaved scans were announced as durable successes. Both conditions are now stated explicitly. |
| Scheduled scan options | Saved ignored directories were dropped. Scheduled scans now honor them and reject settings with both scan categories disabled. |
| Schedule cadence | Tickers advanced the start time before rejected launches, while Scan now did not advance it. The shared runner records a start after acquiring the project and creating the run; refused launches preserve the previous cadence. |
| Schedule receipts | Updating a schedule retained its timestamp in SQLite but returned `lastStartedAt: null`. The upsert now returns the stored timestamp. |
| Schedule events | Desktop events serialized Rust `Result` objects instead of scalar run IDs/counts; unavailable findings storage omitted the completion event; unsaved results looked successful. Desktop and server now share one payload builder with scalar/null fields and explicit failed/unsaved outcomes. |

Validation completed on the local macOS workspace:

- `npm test`: 130 Node tests and 256 Vitest tests passed.
- `cargo test --workspace --all-features --locked --manifest-path src-tauri/Cargo.toml`:
  1,225 tests passed; one pre-existing live OSV test remains ignored.
- `npm run build`: type checking and production build passed. Vite retains its
  existing warning for the deliberately external `/env.js` bootstrap script.
- Workspace/all-target/all-feature Clippy with `-D warnings`, Rust formatting,
  and `git diff --check` passed.
- CI shell tests with `PILOT_REAL_CLI` pointing to the built CLI: all 10 passed,
  including the otherwise optional real-CLI check.
- CLI pilot smoke and benchmark gates at 100% precision/recall passed.
- Version declarations, corpus manifest, and action pin checks passed.
- `npm audit --audit-level=high`: zero vulnerabilities reported.
- `cargo deny check`: advisories, bans, licenses, and sources passed under the
  existing repository exception policy. Existing warnings for exceptions not
  encountered on this target remain.

The review examined dependency parsing, scheduled execution, authentication,
scan presentation, and asynchronous UI ownership, and exercised the complete
automated suites. It does not establish exhaustive absence of defects or replace
Windows/Linux, desktop packaging, or interactive UI acceptance checks.

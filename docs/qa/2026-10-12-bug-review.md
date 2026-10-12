# Bug review — 2026-10-12

This pass reviewed saved-result handling, scan recovery, dialog failures,
advisory database lifecycle, and compliance assessment selection. Confirmed
problems are fixed in the working tree. The existing frontend and Rust suites
passed before changes once local test socket access was available. Added 22
component tests: 21 regression cases observed failing before their fixes, plus
a positive case protecting current-assessment review updates.

| Area | Confirmed problem and resulting behavior |
| --- | --- |
| Source Scan recovery | A review could save successfully while refreshing its results failed. Retry used the same-run navigation guard and did nothing. Recovery now explicitly reloads that run and refreshes its finding views. |
| Source Scan ownership | A delayed review-refresh error could appear in another project's results. The failure path now checks the same request generation as the success path. |
| Export and import dialogs | Rejected native dialogs and synchronous headless-server refusals escaped their click handlers. Both operations now show their errors and allow a subsequent attempt to succeed. Export retries also clear the previous error. |
| Advisory progress lifecycle | A subscription resolving after page teardown leaked its listener; rejected registration became an unhandled rejection. Late subscriptions are released and registration failures are surfaced. |
| Advisory status ownership | Changing the database path retained old counts, errors, progress, and reports, and pending requests could republish them. Path edits clear that state and invalidate requests, including an A → B → A path change. Older responses cannot end a replacement request's loading state. |
| Advisory updates | The path remained editable during a database update, allowing its results to appear under another database. The path is pinned through the update and subsequent status read. |
| Advisory outcome reporting | A successful update followed by a failed status read also announced that the update failed. Update success and its report now remain visible; the separate status failure is reported and old status counts are cleared. |
| Compliance selection | Delayed assessment loads, errors, and loading completion could override a newer selection. Only the current request can update the view or its error/loading state. |
| Compliance review identity | A review finishing after switching assessments could be appended to the new assessment when control IDs overlapped. Visible review updates now require a matching assessment ID. Reviews for the current assessment still update normally. |

Validation on the local macOS workspace:

- `npm test`: 173 Node tests and 380 Vitest tests across 46 files passed.
- `npm run build`: TypeScript checking and the production build passed. Vite
  retains the existing warning for the intentionally external `/env.js` script.
- `cargo test --locked --workspace --all-features --manifest-path src-tauri/Cargo.toml`:
  1,389 tests passed; the pre-existing live OSV test remained ignored.
- `cargo clippy --locked --workspace --all-targets --all-features --manifest-path src-tauri/Cargo.toml -- -D warnings`:
  passed without warnings.
- `git diff --check`: passed.
- Independent read-only reviews of all four changed pages found no additional
  issues in the delivered fixes.

The regressions exercise real rendered pages with native/API boundary doubles.
This pass does not measure browser latency or establish desktop packaging,
cross-platform acceptance, or exhaustive absence of defects. No measured speed
improvement is claimed; the listener cleanup removes a confirmed resource leak.

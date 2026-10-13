# Project review — 2026-10-13

This pass reviewed project structure, CI checks, backend scan ownership,
frontend recovery, saved inventories and compliance reporting. It focused on
reproducible correctness and reliability gaps in existing workflows. It is not
an exhaustive security audit or a new scanner-accuracy measurement.

## Fixed gaps

| Area | Confirmed problem | Delivered behavior |
| --- | --- | --- |
| Report preview | A pending preview or error could appear after changing the assessment, format, metadata or disclosure settings, including A → B → A selection. | Input edits and teardown invalidate the request lifetime; obsolete responses cannot update the preview or error. |
| Report saving | Synchronous dialog refusals and rejected dialogs escaped handling. Save also became enabled while its dialog was still pending. | One busy interval covers compilation, dialog and write. Failures are shown, retries clear them, and cancelling the dialog releases the controls. |
| Report save ownership | A delayed compilation could open a dialog after navigation, or an old dialog could write after report inputs changed. | The operation checks its input lifetime before opening a dialog and before writing. A write already started retains its captured request; its success toast identifies the compiled filename. |
| Inventory coverage | The run selector excluded completed image scans despite the backend persisting their component graph. | Completed image runs can be selected and their component evidence inspected. Incomplete runs remain excluded from this completed-run view. |
| Inventory identity | Selecting another run left the previous run's identity and component count visible during loading. | Replacement loading clears the previous inventory. |
| Slow scan recovery | Every two-second poll superseded the preceding request. When responses consistently took longer than the interval, completed work could remain marked active indefinitely after a lost terminal event. | Periodic refreshes let the current request finish; reconnect and lag notifications can supersede it immediately. An obsolete request cannot block later polling or clear a newer request's pending token. |

## Verification

Added 17 component cases: 14 regressions reproduced against the original code,
one reconnect regression that exposed an issue during implementation, and two
positive report-save cases. Tests render the real components and hook with
native/API boundary doubles; recovery tests control response timing.

- `npm test`: 173 Node tests and 397 Vitest tests across 48 files passed.
- `npm run build`: TypeScript and the production build passed. The existing
  Vite warning for the intentionally external `/env.js` script remains.
- `cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features`:
  1,389 tests passed; one existing live OSV test remained ignored. This baseline
  ran during the review; no Rust code changed.
- `git diff --check`: passed.
- Independent read-only code review approved the final patch after the
  reconnect polling correction.

No native desktop, actual browser, cross-platform or hosted CI execution was
performed in this pass. Slow-response behavior is a deterministic regression
check, not a measured network-performance claim.

## Next priorities

Follow-up: these implementation items and browser fixture checks are now
recorded in [the workflow verification report](2026-10-13-remaining-workflows.md).
The list below preserves the findings that motivated that work; native and
screen-reader checks remain explicitly distinguished from automated coverage.

1. **Complete browser report saving.** Report Studio still invokes the native
   save dialog. `src/lib/dialog.ts` deliberately refuses it in server mode,
   while this page offers no server-path field. The failure is now visible;
   completing the workflow needs an explicit server destination or download
   flow consistent with the [server guide](../headless-server.md).
2. **Make older and large inventories accessible.** Inventory requests the
   latest 100 runs of every kind and then filters them locally. Source/history
   activity can crowd otherwise valid inventories out of the selector. It also
   loads the complete component graph before paging rendered rows. Query
   inventory-capable run kinds on the backend and add inventory paging with
   authoritative counts; retain complete exports as an explicit operation.
3. **Exercise these paths in the actual clients.** Add delayed-response,
   reconnect and native-dialog failure scenarios to the existing
   [pilot protocol](../pilot-validation.md). Check keyboard focus and screen
   reader announcements around loading and error states. Existing component
   tests do not establish those outcomes.

A current status request that never settles still needs a transport deadline
or a reconnect to permit recovery; this patch prevents periodic requests from
starving slow responses without introducing a general timeout policy.

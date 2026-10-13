# Remaining workflow verification — 2026-10-13

This pass implements the three follow-ups from the [project review](2026-10-13-project-review.md): browser report saving, access to older and large inventories, and an expanded client validation protocol.

## Delivered changes

- Report Studio accepts an explicit server destination, disables Save when it is
  blank, catches write failures and identifies the saved path. Destination edits
  invalidate pending compilation before it can write. Desktop dialogs retain the
  existing ownership and error handling.
- Inventory queries completed inventory-capable runs before pagination. Both run
  history and components load 50 rows per page, with authoritative totals and
  server search over package identity, aliases, CPEs and advisory IDs. Unicode
  lowercase and literal substring matching are preserved.
- Schema version 9 adds derived search/advisory tables in one transaction and
  backfills one stored component/evidence row at a time. Normal appends update
  their indexes in the same transaction. Canonical evidence and the complete
  inventory API remain intact.
- Failed later pages retain the requested offset and error. Retry requests that
  page again, and navigation can return to a healthy page. Counts are retained
  only within the same query lifetime; old rows remain hidden during replacement.

## Automated verification

- `npm test`: 173 Node tests and 406 Vitest tests passed across 48 Vitest files.
- `npm run build`: TypeScript and production build passed. Vite still reports
  its existing warning about the intentional external `/env.js` script.
- `cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features`:
  1,394 passed, one pre-existing live OSV test ignored.
- `cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo fmt --manifest-path src-tauri/Cargo.toml --check` and `git diff --check`:
  passed.
- Independent review found and rechecked the deep-page failure/recovery fixes;
  final review reported no remaining concrete findings.

Regression coverage includes server path success/failure/retry and pending edits;
old run pages; delayed component responses after search; deep-page retries and
navigation after failure; exact counts; Unicode, literal and advisory search;
legacy migration/reopen; invalid requests; and unparsed off-page payloads.

## Actual browser and server observations

The production frontend and debug headless server ran on loopback in Chrome on
macOS, with an isolated disposable database and an inert local project. Synthetic
inventory records supplied 105 completed image runs, 150 newer Source runs and
1,410 components. The newest inventory contained 1,000 components; two older
inventories contained 205 each. A real compliance command created the assessment.
These are maintainer fixture checks, not scanner-accuracy or participant results.

| Check | Observed result |
| --- | --- |
| Blank server destination | Save to server was disabled. |
| Bad destination, then retry | A missing parent directory produced a visible error. Entering an existing directory and pressing Enter on Save succeeded without a native dialog. |
| Actual saved output | The 7,655-byte file starts with `%PDF-`; its SHA-256 matches the persisted report receipt: `881c102f6967597a0640c4df64be0a66eac205fca07f18ebaa93430e97e31be7`. No output appeared at the failed destination. |
| Older inventory discovery | Run page 3 displayed rows 101–105 of 105 and selected the expected older inventory, despite the newer Source runs. |
| Deep component page | Keyboard activation reached rows 951–1,000, page 20 of 20. Only 50 component objects were returned by the endpoint. |
| Failed deep page and retry | A reversible invalid payload in the disposable database caused page 20 to fail. The error remained visible; First returned to page 1. After restoring the payload, keyboard activation of Retry loaded rows 951–1,000 on page 20 again. |
| Search and evidence | Searching `éclair` reset to page 1 and found package-0202 with its alias and `CVE-2026-1234`, with a count of 1 of 1,000. HTTP probes also verified literal `%_` search and run-scoped artifact paths. |
| Real migration | Restarting the fixture database from schema 8 created schema 9 and indexed all 1,410 components. Existing advisory associations remained searchable. |
| Accessible state markup | Browser snapshots exposed named fields and pagination controls, `status` loading/count regions, and active search focus. The saved-path status was visible. |

## Limits and follow-up

Native desktop save dialogs, actual screen-reader speech, Windows/Linux clients,
hosted CI and externally recruited participant sessions were not executed here.
Delayed report ownership and reconnect races were exercised by deterministic
component tests, not a browser network-fault campaign. The expanded
[pilot protocol](../pilot-validation.md#delays-reconnects-and-report-destinations)
keeps those observations separate and provides explicit failure procedures.

Page retrieval is bounded by the requested component count; an individual
component can still carry many identity/advisory records. Search scans the
derived text for the selected run. This is not a memory or latency benchmark,
and existing startup work outside the new migration is unchanged.

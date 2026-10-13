# Native, accessibility and recovery verification — 2026-10-13

This follows the [server and inventory verification](2026-10-13-remaining-workflows.md).
The checks used macOS 27.0.1 (26A434), arm64, Chrome, the production frontend,
a loopback headless server, and debug Tauri application bundles. Browser checks
used the existing disposable fixture database; native checks added a QA
assessment without deleting existing desktop data. These are maintainer checks
with user-assisted listening, not an external usability study.

## Native report saving

The normal `oxAudit QA.app` build changes only `productName` through a temporary
Tauri configuration. Application permissions are the shipped defaults.

| Check | Actual result |
| --- | --- |
| Cancel | Escape dismissed the macOS save sheet. Preview and Save controls recovered; the compiled preview remained available. |
| Save | The native sheet saved `native-report.pdf`. The page identified the destination. The 10,915-byte PDF and persisted report receipt had SHA-256 `f087747413274dd2dac4f8477c919bf38cce74bea536b775daf516f66fdb732b`. |
| Refused dialog | A separate debug build selected an inline capability containing `core:default`, `core:event:default`, and `opener:default`, with the dialog permission omitted. The real Tauri call rejected with `dialog.save not allowed`. Report Studio displayed the error and retained enabled controls and the preview. No policy exception or permission change was committed. |
| Restore and retry | Rebuilding with the normal configuration restored the native sheet. A successful saved file and receipt both had SHA-256 `5bfc88bed3c8995b7ec4d7c6411e984cfc81f50a8bae8b8666776b7bbaffc501` (10,915 bytes). |

The restored bundle at parser-fix commit `764b5b9` had executable SHA-256
`a039e4f0fe915f947112338e66c1c97e60e25f70e1558960f6a6c1aa5f194395`.
This identifies a local debug artifact, not a signed distribution.
The macOS save sheet is modal; pending-input changes remain covered by the
component boundary tests, rather than a claim that background controls were
editable through this sheet.

## Spoken announcements

VoiceOver shipped with the above macOS version was enabled for the Chrome
checks. The user listened and supplied these observations directly:

- Successful keyboard-activated Save: “Saved confirmation with the file path.”
- Missing destination directory: “Yes, the error was spoken.”
- Inventory loading and replacement results: “Both loading and result count.”

The success file was `spoken-check.pdf`, 7,655 bytes, SHA-256
`1967d117a42babc0a1859254fe6e114ff378e70bf7b6a1278a621cecf46e9929`.
The failed path had no file. These speech results come from the listener,
not from accessibility roles or an audio capture. VoiceOver was confirmed off
after the checks, matching its original state.

## Browser fault injection

A temporary threaded reverse proxy listened on `127.0.0.1:18474` and forwarded
to the fixture server on port 18473. Delays held completed upstream responses;
event filtering removed selected SSE frames. Closing a stream allowed the
browser's ordinary EventSource retry to reconnect. Authentication and backend
commands were unchanged. The proxy recorded command names, fixture arguments,
timing, dropped events, and stream open/close events, without recording headers.

| Condition | Actual result |
| --- | --- |
| Late inventory page | Page 20 (offset 950) was held for 12 seconds. Searching `éclair` returned one matching component before that page arrived. After the old response arrived, the view still showed package-0202 and “1–1 of 1”; search retained focus. Loading hid old rows. |
| Edited report destination | Compilation was held for 12 seconds. Editing the destination while Save was pending invalidated the operation. No write command ran for it and neither destination was written until a new explicit Save. That retry wrote only `delayed-new.pdf`. |
| Navigate away during Save | Compilation was held for eight seconds. Leaving Report Studio invalidated the operation; the obsolete destination received no write. |
| Format A → B → A | While PDF compilation was held for eight seconds, selecting Markdown and then PDF invalidated the original operation. Save recovered, and no obsolete file was written. |
| Slow local scan response | `work://changed` events were dropped, the scan command response was held for 30 seconds, and one status response for 12 seconds. Reconnection obtained a fresh status before the older status settled. The local invocation retained ownership until its response settled, then displayed the saved completed receipt. |
| Detached scan and reconnect | A second scan response was held for 40 seconds, one status response for 12 seconds, and work events dropped. Navigating to Dashboard detached the local owner. Reconnection refreshed status and cleared the active-work indicator before either delayed response returned. Reopening Source Scan loaded the persisted completed run `10f70420-f4f9-4d18-84c0-e70d439b5ac3`, covering two files with zero skipped. |

The detached case exposed a separate footer bug: Source Scan retained its old
page-level “Scanning” status after showing the completed saved receipt. The fix
clears that stale running status when the page is idle. It preserves terminal
success/error messages and active global scan ownership. A regression test
reproduces start → detach → completion → saved receipt → remount; additional
tests protect those retained statuses and unrelated active work.
Replaying the browser case with the corrected production build, a 45-second
scan-response delay and a 12-second status delay displayed the completed saved
receipt and the neutral “Ready” footer together. The later response did not
restore the obsolete running status.

The observed delays are fault scenarios, not performance benchmarks. A request
that never settles remains a transport-deadline limitation. Assessment changes,
metadata edits, and assessment A → B → A ownership are additionally covered
by deterministic component tests; the browser campaign does not replace every
one of those test permutations.

## Supply-chain correction and automated checks

The previous commit's hosted Security workflow detected the unmaintained
`unsafe-libyaml` dependency, RUSTSEC-2024-0449. Commit `764b5b9` replaces deprecated
`serde_yaml` with `serde-saphyr`, explicitly bounds nesting, events, scalar bytes,
anchors and alias expansion, and preserves YAML package ordering and binary-tag
string behavior. JSON inventory ordering is unchanged. There is no new advisory
waiver. Nonstandard YAML metadata with complex map keys or non-finite numbers
is rejected instead of being interpreted as JSON package metadata.

- The full local Rust suite passed 1,398 tests with one existing live OSV test
  ignored before the final binary-tag regression. The final focused parser suite
  passed all 67 tests, including that additional regression.
- Workspace Clippy with warnings denied, formatting, and diff checks passed.
- `cargo deny --locked` passed advisories, bans, licenses and sources.
- Hosted [Security run 38341577111](https://github.com/HenryCooper86/oxAudit/actions/runs/38341577111)
  passed Rust and JavaScript supply-chain checks and CodeQL for `764b5b9`.
  Dependency review and scheduled fuzz smoke were skipped by their event rules.
- Hosted [CI run 38341577068](https://github.com/HenryCooper86/oxAudit/actions/runs/38341577068)
  passed frontend checks and Rust tests on macOS, Ubuntu and Windows for
  `764b5b9`, including Linux Clippy, reduced grammar builds and the quality gate.
- The footer correction passed type-checking, the production build, 173 Node
  tests and 410 component tests across 48 files. Independent review reran all
  20 evidence-summary tests and found no blocking issue.

## Evidence and scope

Local artifacts are retained under `/private/tmp/oxaudit-workflows-xgijyisp`:
`native-report-saved.png`, `native-dialog-refused.png`, `native-restored-save.png`,
`reconnect-recovered.png`, `reconnect-footer-fixed.png`, `reports/`, and
`fault-log.jsonl`. This temporary
directory is not a durable published artifact store.

Windows and Linux hosted builds/tests are distinct from native interactive
dialog or screen-reader sessions on those systems. This macOS session cannot
supply those platform observations. External participant recruitment and the
blank [pilot feedback form](../pilot-validation.md#empty-feedback-form) remain
separate; no external participant outcomes were invented or prefilled.

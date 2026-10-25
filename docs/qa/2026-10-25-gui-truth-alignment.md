# GUI truth-alignment pass — 2026-10-25

A survey of all 21 GUI pages, the ⌘K palette, the readiness wizard and the
93 registered backend commands found no dead buttons, placeholders or
unresolved `invoke` names. It found a bounded set of copy-vs-wiring gaps
where the UI promised more than the code delivers. This pass fixes those
gaps; it changes no scanner, policy or storage behavior.

## Fixed gaps

| Area | Previous claim | Delivered behavior |
| --- | --- | --- |
| Server build, "Open file" | Rendered unconditionally; the headless server always refuses it | Hidden in server mode (`src/components/FindingDetail.tsx`); Copy finding remains |
| Server build, AI readiness | Any `test_ai` failure became "AI offline" / "Configured but unreachable", blaming a possibly healthy endpoint | New distinct `unsupported` readiness status published without probing in server mode (`src/lib/settingsRequests.ts`); status bar reads "AI not in this build"; Dashboard, Assistant and CVE briefing state the build limitation instead of an endpoint problem; Settings button hidden in that state |
| Assistant approval copy | "Tools require approval" — false for read-only tools, which are auto-allowed by design (`src-tauri/src/agent/tools.rs`) | "Project reads run without asking; other tools ask for approval"; activity panel no longer says "Approved tool activity" |
| Assistant session writes | Clear/rename/delete updated the UI first and swallowed persist failures; a "cleared" conversation reappeared after reload | Persisted writes happen first; UI adopts changes only on success; failures surface as error toasts and prior state stands |
| Rule Library install toast | "its enabled rules apply to every source scan" | "its enabled source and secret regex rules apply to every source scan", matching the page's stated engine limits |
| Export preview validity | "Structure valid" hardcoded | Rendered from `preview.valid`; an invalid preview shows an error-toned "Structure invalid" |
| History Scan hero | "Reads every blob reachable from any ref" | States budgets up front (blob count, blob size, total bytes, findings, wall clock) and that a budget-stopped scan says so; README entry aligned |
| List caps | "Every project oxAudit knows" while requesting 50; run selector capped at 100; palette at 20 | Muted notes state each cap when it is reached |
| Compliance Center | "Run selected checks" (no checks run); Record review disabled by hidden thresholds | "Collect selected evidence"; inline hint states the reviewer/note minimums when they gate the button |
| CVE dossier | "Verified CVE fields"; Open OSV enabled without an OSV record | "Normalized from NVD records"; Open OSV disabled with an inline reason when no record is loaded |
| Settings absolutes | "Scanning stays on this machine"; "oxAudit sends nothing anywhere" | Scoped to the local engines with the external-scanner/advisory network use stated; diagnostics claim kept to what is true (redacted, nothing transmitted automatically) |
| Disabled-without-reason controls | Check project (scan active), Recheck finding (nine-condition gate), Trust (blank name) | Inline reasons shown; Recheck finding states the first blocking condition in the gate's own order (active scan, pending recheck save, target load, run-save retry, review save, invalid policy, incomplete run, unsaved run, finding from another run); Trust disabled until a grantor name is entered, with the toast-error path removed as unreachable |
| Type doc | `InstalledRulePack` comment restated the unqualified pack claim | Qualified to text-engine rules |

## Verification

- `npm run check` (tsc): passed.
- `npm test`: 173 Node tests and 493 Vitest tests across 54 files passed
  (491 before the recheck-reason tests below).
- `npm run build`: production build passed.
- `npx playwright test`: all 5 scenarios passed in real Chromium against a
  real local `oxaudit-server` (built production frontend). The server build
  was observed showing "AI not in this build" in the status bar during the
  daily-workflow scenario, and the onboarding/scan/review/recheck/restart/
  reopen/SARIF-export path completed with the new states in place.
- `VexTrust.test.tsx` updated to assert the disabled-with-reason trust gate;
  the daily-workflow e2e assertion was updated from "AI not configured" to
  the truthful server-build status.
- `FindingDetail.test.tsx` gained cases asserting the recheck disabled reason
  renders when supplied and stays absent otherwise, and
  `fixWorkflow.test.tsx` asserts the page derives "A scan is already running"
  for the shared-ownership case.

## Correction record

The initial delivery of this pass missed the Recheck finding disabled reason
(`FindingDetail.tsx` / `SourceScan.tsx`) while reporting all twelve items
complete; a review catch flagged the omission. The reason derivation, its
rendering, and the tests above were delivered in a correction round after the
first full-suite and e2e runs, and both suites were rerun green afterwards.

## Limits

Desktop-mode visual inspection relied on the component suite; the browser
e2e covers the server-build states exercised by the daily workflow but not
every page's new notes. No native desktop dialogs, screen-reader speech or
external participants were involved. No Rust behavior changed; the
headless dispatch arms that disable AI commands and `open_scan_finding`
are unchanged and now match what the GUI states.

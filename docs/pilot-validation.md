# Local pilot protocol

Use the [installation guide](getting-started.md) and the [inert fixture
instructions](../examples/pilot/README.md). The desktop/browser workflow tasks
below target the **current checkout**, built from source: published v0.1.0 does
not establish acceptance of later workbench changes. Evaluate published-release
installation separately and record the exact artifact/version. Do not combine a
release CLI installation result with a different build's GUI acceptance record.

No AI setup, live credentials, or fixture execution is required. This protocol
collects manual feedback only; oxAudit adds no telemetry. Prepared forms and
automated browser receipts are not external participant feedback.

## Deterministic command-line smoke

Build the current CLI, then run from the checkout:

```bash
cargo build --locked --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli
npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli
# Keep copied inputs, JSON, SARIF and databases for inspection:
npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli --keep
```

On Windows append `.exe` to the CLI path. The executable Node script accepts an
explicit CLI path, spawns it with argument arrays, creates its own temporary
workspace, and removes only that workspace unless `--keep` is supplied. It
returns a JSON receipt and exits nonzero on any failed assertion. It never runs
the fixture JavaScript or installs dependencies.

The assertions cover:

| Task | Required evidence |
| --- | --- |
| Vulnerable source | One source file scanned, no skipped files, `js-eval`, severity gate exit 1, JSON report |
| Saved export | Completed canonical `source` run ID; SARIF 2.1.0 exported from that exact run and containing `js-eval` |
| Unchanged source | Trusted vulnerable JSON baseline; new-only high gate exit 0 |
| Correction | Same copied file replaced with JSON parsing; no `js-eval` observation; new-only gate exit 0 |
| Reintroduction | Vulnerable file restored; corrected JSON baseline; new-only gate exit 1 |
| Malformed dependency | Intentionally truncated lockfile, `--offline`, exit 3 |
| History | Each fresh database still lists its completed canonical source run after scanning/export |

The correction is reported as **no longer observed (coverage unverified)**.
This file-baseline smoke does not exercise the desktop's compatible-run recheck
proof and must not be reported as a verified resolution. Fresh databases also
avoid mixing historical resolved rows with current JSON observations.

Source scans may attempt optional CISA KEV enrichment even though the source
engine is local. The harness supplies child-only HTTP/HTTPS/ALL proxy variables
(upper and lower case), clears both NO_PROXY variants, and binds a refusing HTTP
proxy on `127.0.0.1`. It refuses CONNECT/HTTP requests with 502 and never forwards
them or invents provider responses. The vulnerable cases must observe the CISA
request at that proxy; a CLI that bypasses this expected boundary fails the smoke.
No public network service is required for these cases. This is a tested reqwest
proxy boundary for the supplied CLI, not an OS sandbox for arbitrary executables.
Optional enrichment is unavailable in this exercise. The parent's environment
and network configuration are not changed. CLI acquisition/builds and ordinary
advisory scans can still need internet access.

The consumer workflow shell contracts run separately with `npm run test:ci-shell`
in the [documented Ubuntu/Bash/jq environment](getting-started.md#contributor-workflow-shell-tests).
They remain required in repository CI and are not part of the portable default
`npm test` installation sequence.

## Automated browser smoke

Run the current production frontend in real Chromium against a real local
`oxaudit-server`, separately from the component tests in `npm test`:

```bash
npm ci
npm run build
cargo build --locked --features server --manifest-path src-tauri/Cargo.toml --bin oxaudit-server
npx playwright install chromium
npm run test:e2e
```

Linux machines may also need `npx playwright install --with-deps chromium`.
`OXAUDIT_E2E_SERVER` can select an already built server by absolute or
repository-relative path; Windows uses the `.exe` binary. Missing prerequisites
fail with the corresponding build instruction rather than downloading a server.

The three serial scenarios cover:

- Token onboarding without AI; a real source check and persisted review; a
  corrected-file recheck with compatible coverage; restarting the actual server;
  reopening the saved review and exporting its exact run as a validated SARIF file.
- Delayed metadata for an older saved source run, superseded by target changes
  and a fresh scan. Assertions check run identity as well as finding contents.
- A completed empty dependency inventory followed by backend-confirmed
  cancellation before registration; run-list HTTP 503 and malformed preview JSON;
  same-page recovery and export of the original completed receipt.

Each scenario owns temporary project, data and configuration directories and an
ephemeral access token. A loopback proxy refuses optional backend enrichment;
this is not an OS network sandbox or isolation from the OS credential store.
No fixture JavaScript or package installation is executed. Teardown removes the
owned temporary state, including when server startup fails.

The Linux Rust CI job builds the workbench and executes the same command.
Failed runs retain traces, screenshots and backend diagnostics in `test-results/`.
`playwright-report/` contains the HTML report. CI retains these directories for
14 days. Run only one suite per output
directory at a time. These are automated maintainer checks, not proof of native
desktop dialogs, screen-reader announcements, external acceptance or every
supported platform.

## Manual desktop tasks

Record elapsed times from the point specified and stop if the result is blocked.
Retain screenshots or report paths with actual errors; do not count a failed or
incomplete scan as clean.

1. Install/open the local desktop artifact. Record OS, architecture, bundle name,
   checksum, and any installation/trust failures. Start the first-use timer.
2. Continue through setup without AI, choose the copied vulnerable project, and
   explicitly check it. Open `js-eval`, identify the code location and explain why
   it is relevant to the fixture's JSON input contract. Stop the actionable-finding
   timer. Skip and reopen setup once; confirm it never scans without the action.
3. Choose the preferred editor in Settings, open the finding's file, and replace
   code evaluation with the corrected JSON implementation. Start the resolution
   timer before editing, then use **Recheck finding** after saving. Record the
   exact covered-file result and run IDs. Only count a verified resolution when
   the UI provides compatible completed-run coverage; otherwise record “not
   evaluated” or the actual limitation.
4. Open the separate malformed-dependency fixture and check dependencies. Record
   the coverage error. The project must not appear successfully clean.
5. Close and reopen the app, resume the project from Home, inspect saved results,
   and export a report. Note any lost selection, confusing history, or editor
   navigation friction.
6. Optionally adopt the complete CI example in an authorized repository. Record
   the main baseline commit/run, PR target commit/run, tool pin, artifact paths,
   and the real job outcomes. Local syntax checks alone are not GitHub execution.

## Target, progress and saved-result follow-up

Use these checks alongside the desktop tasks for the experience refinements.
Record each actual result and evidence in the participant's notes; an automated
or maintainer check does not count as an external participant observation.

| Flow | What to observe |
| --- | --- |
| Target setup | On Source, Dependencies and History choose a folder; on Binary choose a file and then a folder; on Image choose an archive or OCI folder, then type a registry reference. Cancel a picker and confirm the prior target remains. Press Enter in the target input and confirm scanning starts only through the explicit scan action. |
| Server target setup | Use a path on the server's filesystem. Confirm the instructions explain this and no local native picker is offered. |
| Progress and cancellation | Start an inert scan and cancel it. Record observed stages/counters, the resulting attempt state and whether older saved evidence remains distinguishable. An unavailable progress count is not an estimated percentage. |
| Large saved results | Reopen a saved receipt with more than 50 rows, move to another page, change a filter and inspect a detail. Check that the total refers to the whole filtered set and the rows belong to the selected receipt. |
| Complete output | Export the saved receipt. For Source, copy JSON and verify secrets are redacted and the output includes the complete result set. For saved Dependencies, explicitly load complete upgrade decisions before reviewing recommendations. |
| Keyboard and reflow | Use Tab, Enter/Space and Escape; try Skip to workspace and narrow navigation. Check both themes, browser zoom and a narrow viewport for clipped controls, focus loss or unreadable text. Record any assistive technology and version actually used. |

No participant results are prefilled. The prepared JSON form remains empty;
keep real notes and artifacts only where the participant has consented to share.

## Delays, reconnects and report destinations

Use disposable local fixtures and an isolated server/database. Record the
transport, build, injected condition, expected result and observed result for
each attempted case. A deterministic component test does not replace an actual
browser, native-dialog or assistive-technology observation.

| Case | Procedure and expected evidence |
| --- | --- |
| Browser report save | Leave **Report file on server** blank and verify Save is disabled. Enter a path whose parent is missing, record the visible error, then retry in an existing writable directory. Compare the saved file's SHA-256 with its receipt. Verify the success status names the server path. |
| Browser Export Center import | Leave **Report file on server** blank and verify Inspect is disabled. Try a missing path, then inspect an inert SBOM and import it as a separate inventory. Edit the path, including A → B → A, and confirm import requires reinspection. Modify the file after inspection and confirm the SHA-256 mismatch blocks import until a fresh preview. Inspect a SARIF/VEX fixture and retain its mapped claims with `external-unverified` trust. |
| Browser Export Center save | Select a saved run and leave **Export file on server** blank; Save must be disabled. Try a missing parent, then retry in a writable directory. Verify the saved path status and the exported run identity and full population, including a report whose preview is truncated at 1 MiB. Check that a pending save cannot be submitted twice. |
| Pending report edits | Delay report compilation, start Save, then change assessment, format, metadata or server destination. The old operation must not open a dialog or write a file. Repeat after navigating away and after A → B → A selection. |
| Desktop dialog failure | On each supported desktop platform, cancel a save dialog and verify controls recover. Exercise a refused/rejected dialog through the native test harness, then retry. Change report inputs while the dialog is pending; the old destination must not receive a write. Record native execution separately from mocked boundary tests. |
| Older inventories | Retain more than 100 completed inventory runs plus newer Source/History runs. Reach the final run page, select an old inventory, and confirm its identity and evidence belong to that run. |
| Large inventory and late responses | Use more than 200 components. Navigate deep, delay its response, then search by alias or advisory. Counts must describe all matching components, and the late old page must not replace the new results. |
| Page failure and recovery | Make a later run/component page request fail. The error must remain visible on that page. Retry must request the same offset; First/Previous must still navigate to an available page. Restore connectivity and confirm recovery. |
| Slow scan recovery | Delay status requests beyond the two-second polling interval and suppress a terminal event. A settled response must restore the persisted terminal state. Interrupt and restore the event stream while an older request remains pending; obsolete results must not overwrite the reconnect refresh. A request that never settles remains a separately recorded transport-deadline limitation. |
| Keyboard and announcements | Use keyboard activation for Save, Retry and pagination. Inspect focus during loading/error/retry; type a search while a page loads. With the named screen reader/version, record whether loading, error and saved-path statuses are spoken. DOM roles alone are not evidence of spoken announcements. |

Maintainer observations for the server and inventory changes are recorded in
[the workflow verification report](qa/2026-10-13-remaining-workflows.md). They are
not external participant feedback. The subsequent
[native, accessibility and recovery pass](qa/2026-10-13-native-accessibility-recovery.md)
adds actual macOS dialog checks, user-assisted VoiceOver listening, network-fault
observations and hosted verification.

## Empty feedback form

Leave blank until an engineer actually performs the tasks. Do not infer success
from an absence of feedback.

| Field | Engineer response |
| --- | --- |
| Participant / date (optional identifier) | |
| OS / architecture / app version / artifact hash | |
| Editor and version | |
| Installation failures or trust prompts | |
| Time to first actionable finding | |
| Time to verified resolution, or why not verified | |
| Useful findings / dismissed findings / unclear findings | |
| Recheck outcome and source run IDs | |
| Malformed-lockfile outcome | |
| Restart/history/export outcome | |
| CI main baseline and PR run outcomes, if attempted | |
| Most confusing step / qualitative friction | |
| Suggested next improvement | |

## Validated participant capture

The [blank JSON form](pilot-feedback.template.json) and
[schema](pilot-feedback.schema.json) prepare capture with **zero observations**.
No external participant has supplied feedback for this reliability change.
Create one local input per actual session, then fill it while the engineer
performs the tasks above:

```bash
node tools/pilot-feedback.mjs init --output /tmp/pilot-engineer-input.json
node tools/pilot-feedback.mjs validate --input /tmp/pilot-engineer-input.json
# After real observations and consent have been recorded:
node tools/pilot-feedback.mjs capture --input /tmp/pilot-engineer-input.json \
  --output /tmp/pilot-engineer-observed.json
```

`init` creates a new file without overwriting another record. `validate` accepts
the blank preparation form and reports `prepared: 0 observations`. `capture`
rejects it until actual observations exist. The capture command writes a new
file, records the capture date and derives per-participant task acceptance;
it never sends a message or uploads feedback. Validation exits 2 on invalid
input and leaves no captured output. External, internal and maintainer sessions
are explicitly distinguished and must not be combined into an external pilot
claim.

Use a pseudonymous participant identifier, the actual UTC observation date,
OS/architecture/app version/editor, artifact SHA-256 and explicit consent to
share the record. Each observation records one task, `completed`, `blocked`, or
`not-evaluated`, measured elapsed seconds (or `null` when blocked/not evaluated),
actual notes, evidence references and canonical run IDs. Evidence references
can be local screenshot/report paths; do not fabricate them to satisfy validation.
Copy an empty observation object into `observations` only when recording a real
task, then fill its fields:

```json
{
  "task": "installation",
  "outcome": "not-evaluated",
  "elapsedSeconds": null,
  "evidence": [],
  "notes": "",
  "runIds": []
}
```

This unfilled example deliberately fails validation until actual notes are
supplied. Valid task IDs are `installation`, `first-actionable-finding`,
`verified-resolution`, `malformed-dependency`, `restart-export`, and optional
`ci-adoption`. A completed finding task needs its canonical run ID. A completed
verified resolution additionally requires `coverageProof` with `state:
"completed"`, `compatible: true`, the actual `coveredFile`, and distinct
`previousRunId`/`currentRunId` also included in `runIds`. A JSON baseline showing
absence without that coverage proof is not a verified resolution; record the
task as blocked or not evaluated with its actual limitation.

All five required desktop tasks must have observed completed outcomes before
that participant's `acceptance.complete` becomes true. A blocked task retains
its evidence and keeps acceptance incomplete. CI adoption is optional and its
actual run outcomes need evidence if attempted. The validator checks the record's
consistency, not whether a human performed it or whether an evidence reference
exists. Maintainer review of the referenced evidence remains required before
making a usability claim. Keep the committed template blank and retain real
records only in a location the participant has consented to share.

Automated detection and performance receipts are documented separately in
[quality/performance validation](quality-performance-validation.md).

## Observed evidence versus pending acceptance

The implementation exercise on 2026-09-07 ran the local CLI smoke and the actual
consumer scan shell against a freshly built macOS CLI, plus component, tooling,
and workflow validation. These are maintainer checks, not external pilot results.
The task report retains command outputs and limitations. Final native app/bundle
inspection, distributable hashes, whole-change review, and pushed Linux/Windows/
security job outcomes are controller-owned acceptance items. Their actual results
belong in [the QA log](qa/2026-09-07-everyday-workflow.md); do not infer them from
this protocol or from macOS unit tests. External engineer feedback remains empty.

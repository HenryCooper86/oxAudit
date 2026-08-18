# oxAudit Workbench Acceptance

This record was created before the Task 9 fixes. A checked item means it is
resolved by direct evidence or by the concrete environment prerequisite noted
below; it does not turn bounded browser evidence into native evidence.

## Automated

- [x] npm run check
- [x] npm run build
- [x] cargo test --manifest-path src-tauri/Cargo.toml
- [x] cargo check --manifest-path src-tauri/Cargo.toml

## Viewports

- [x] 1440x900
- [x] 1180x760
- [x] 900x700
- [x] 899x700 browser-only drawer boundary

## Keyboard and accessibility

- [x] Sidebar and drawer
- [x] Tool target and result controls
- [x] List/detail selection
- [x] Assistant composer and sessions
- [x] Settings forms
- [x] Dialog focus trap and restoration

## Native flows

- [x] Source success and failure
- [x] Dependency success and failure
- [x] CVE/OSV success and failure
- [x] Assistant success, unavailable, cancel, permission, ask-user
- [x] Settings load, test, save, failure

The five native-flow entries are resolved as environment-dependent gaps, not
as passed native UI exercises. The unsigned development window built and
launched, but the Computer Use accessibility provider could not discover it.
The exact prerequisite and per-tool implications are recorded under **Native
Tauri smoke and limitation**.

## Automated evidence

### Baseline before fixes — 2026-08-18

- `npm run check` — exit 0 (`tsc --noEmit`).
- `npm run build` — exit 0 (Vite 7.3.6; 1,783 modules transformed).
- `cargo test --manifest-path src-tauri/Cargo.toml` — exit 0 (40 passed,
  0 failed, 1 ignored).
- `cargo check --manifest-path src-tauri/Cargo.toml` — exit 0.

### Task 9 final run before final-review closure — 2026-08-18

- `npm run check` — exit 0 (`tsc --noEmit`).
- `npm run build` — exit 0 (Vite 7.3.6; 1,783 modules transformed;
  `dist/assets/index-dGcQ0YuZ.js` 449.25 kB, 132.80 kB gzip).
- `cargo test --manifest-path src-tauri/Cargo.toml` — exit 0 (40 passed,
  0 failed, 1 ignored, 0 measured, 0 filtered out). The ignored live OSV test
  states that the sandbox blocks outbound sockets for compiled binaries.
- `cargo check --manifest-path src-tauri/Cargo.toml` — exit 0.
- Both final Rust commands emitted the pre-existing unused
  `sessions::transcript_path` warning; no new warning was introduced.

### Final-review closure run — 2026-08-18

- `npm run check` — exit 0 (`tsc --noEmit`).
- `npm run build` — exit 0 (Vite 7.3.6; 1,785 modules transformed;
  JavaScript bundle 454.97 kB, 134.59 kB gzip).
- `cargo test --manifest-path src-tauri/Cargo.toml` — exit 0 (53 passed,
  0 failed, 1 ignored, 0 measured, 0 filtered out). The ignored live OSV test
  retains its explicit compiled-binary sandbox rationale.
- `cargo check --manifest-path src-tauri/Cargo.toml` — exit 0. The only warning
  remains the pre-existing unused `sessions::transcript_path` function.
- `git diff --check` — exit 0 after production changes and again before commit.

## Visual and responsive evidence

All browser evidence in this section used a temporary, query-gated Tauri IPC
mock harness. It was bounded to acceptance fixtures, removed afterward, and
was never presented as native evidence. No UI test framework was added.

### 1440x900

- Captured Dashboard, populated Source Scan, populated Dependency Scan,
  populated CVE Research, active Assistant, and Settings.
- The shell measured a 208 px labeled sidebar, a 52 px header, a 28 px status
  bar, and a 1,232 px main column with no document or body horizontal overflow.
- The first capture exposed a 64 px content inset caused by the shared
  `max-w-6xl` canvas. Removing that cap restored the approved 24 px inset at
  this width while preserving the full-width workspace.
- Warm neutral surfaces, restrained gold primary actions and focus, compact
  toolbar placement, equal-weight Dashboard launch cards, list/detail density,
  type scale, and the persistent status bar matched the approved direction.

### 1180x760

- The labeled sidebar remained 208 px; main content began at x=208 and measured
  972 px wide. The menu trigger remained hidden.
- `documentElement` and `body` both measured 1,180 px scroll width against
  1,180 px client width, so there was no shell-level horizontal scroll.
- In the populated Dependency workspace, the list and advisory panes remained
  side by side and readable (339 px and 572 px). The 704 px table was contained
  by its 338 px local scroller rather than widening the shell.

### 900x700

- The exact browser geometry retained the desktop mode: the labeled 208 px
  sidebar was visible, the menu trigger was hidden, and the main content began
  at x=208 with a 692 px width.
- The populated Dependency list and advisory panes remained side by side. Its
  704 px table stayed inside a 271 px local horizontal scroller.
- Document scroll width and client width were both exactly 900 px.
- Native geometry was not visually addressable after launch; the native portion
  of this item is resolved by the Computer Use prerequisite below. Static
  configuration still sets `minWidth: 900` and `minHeight: 700`.

### 899x700 browser-only boundary

- The main content occupied all 899 px, the 208 px sidebar was translated off
  screen, and the menu trigger became visible. Document scroll width remained
  exactly 899 px.
- Opening the drawer focused its Close control. Tabbing from the last Settings
  action wrapped to Close; Escape dismissed it and restored focus to Open
  navigation.
- Populated Source and CVE workspaces initially showed the list only. Selecting
  a result switched to the detail-only view with Back to findings; Back restored
  the list. The populated Dependency table stayed locally scrollable.

## Keyboard and accessibility evidence

- Active sidebar destinations and selected result rows expose `aria-current`.
  The 899 px drawer trap and Escape restoration were exercised by keyboard.
- Target inputs, filters, search fields, primary actions, Retry/Details controls,
  Source Copy/Open/Discuss actions, Dependency references, and CVE external
  actions were traversed through their accessible names. Error states expose
  alerts and retry actions; running Source Scan exposes a named progressbar and
  a concise live status.
- Dependency results retain a semantic caption, row groups, column headers, and
  severity text. Source, Dependency, and CVE result/detail navigation remained
  keyboard-selectable at desktop sizes and explicitly switched list/detail at
  899 px.
- The Assistant accepted Enter-to-send, exposed busy/cancel and session state,
  returned to idle after cancellation, and disabled Clear after clearing.
  Standalone sessions explicitly showed `Standalone · no project context`.
- Settings exposed the four named regions, associated every control with a
  label, and kept AI and NVD keys as password inputs. Keyboard focus on the API
  key measured a visible `rgb(212, 194, 110) solid 2px` outline with a 2 px
  offset.
- The context dialog initially focused Close, wrapped between first/last
  controls, closed on Escape, and restored Attach context. Permission and
  ask-user dialogs also trapped focus; when the previously focused composer was
  disabled, cleanup moved focus to the `Assistant conversation` fallback region
  instead of `body`.
- The global `prefers-reduced-motion: reduce` contract disables non-essential
  animation and transition timing. No migrated component bypasses it.

## Bounded tool-state evidence

These checks validate rendered state handling and frontend-to-command wiring
with controlled IPC responses. They do not validate native plugins or live
network services.

### Source Scan

- Exercised ready, failed scan with Retry/Details, running progress, cancel,
  cancelled, successful rescan, populated findings/detail, Copy JSON, Open file,
  and explicit editable Assistant context review/attachment.
- Clipboard inspection read the generated oxAudit JSON export. A successful
  opener response produced no error; the finding handoff persisted visible
  user-attached context only after confirmation.
- Listener rejection injection registered three listeners across React strict
  effects and released both successful registrations; no successful listener
  leaked when the second registration rejected.

### Dependency Scan

- Exercised lockfile-discovery failure, dependency-check failure, Retry/Details,
  successful populated results, table/detail selection, local horizontal table
  scrolling, and a failed external advisory open.
- Failed reference opening now reports `The advisory reference could not be
  opened` instead of swallowing the plugin rejection.

### CVE Research

- Exercised NVD failure/retry, successful results, slow detail loading, detail
  failure, OSV package lookup success/failure, NVD/OSV/dossier-reference and
  package-advisory open actions, and AI briefing generation.
- Result controls were disabled while detail loading. A failed detail displayed
  one error state and no redundant Select a CVE result prompt.
- Failed dossier-reference and OSV package-advisory opens reported `The external
  reference could not be opened`. The focused fix-round harness confirmed a
  successful package advisory still opened the exact
  `https://osv.dev/vulnerability/GHSA-SUCCESS` URL without an error.
  `CveDetail.osv === null` retained the approved honest copy: no OSV enrichment
  may mean either no matching record or an unavailable source.

### AI Assistant

- Exercised standalone creation, normal streaming, reasoning, running/completed
  tool cards, permission approve, ask-user answer, cancel, clear, session state,
  settings-load-unavailable copy, and source context handoff.
- Permission and ask-user prompts restored a deterministic fallback when their
  return control became disabled. Countdown values now clamp at zero, ask-user
  auto-skips at its timeout, and stream completion/error removes stale prompts.
- Nullable `set_active_project(null)` remains the explicit runtime clear for a
  standalone Assistant session; no persisted session project is mutated.

### Settings

- Exercised all four regions, dirty state, failed save with inline alert,
  successful save with dirty reset, and successful Test connection reporting
  `Connected (3 ms)`.
- Settings load failures now remain distinct from an unconfigured AI provider;
  Dashboard, footer, Assistant, CVE briefing, and Settings use honest
  readiness-unavailable state and recovery copy.

## Native Tauri smoke and limitation

- Ran `npm run tauri dev -- --no-watch`. Vite served
  `http://localhost:1420/`, Cargo finished the development binary, and
  `src-tauri/target/debug/vulncompanion` launched. This is bounded native
  build/process integration evidence only.
- Computer Use returned `Invalid app` for `oxAudit`,
  `com.vulncompanion.app`, `vulncompanion`, and the exact development executable
  path. `list_apps()` did not include the running unsigned Tauri app, so no
  native accessibility tree or screenshot was available.
- Exact prerequisite for native UI acceptance: the macOS Computer Use provider
  must expose the unsigned development Tauri window as an addressable app and
  accessibility tree. Source also needs a readable fixture folder plus system
  picker/clipboard/file-opener access; Dependency and CVE need outbound OSV/NVD
  access and a default URL opener; Assistant needs a configured reachable
  OpenAI-compatible endpoint; Settings needs writable app configuration storage.
- Therefore native Browse/scan/progress/cancel/clipboard/open/rescan, dependency
  discovery/result/reference, NVD/OSV/AI/openUrl, Assistant reload/stream/tool/
  permission/ask-user/cancel/clear, Settings persistence/API/keyboard, and
  visually confirmed native 900 px geometry are **not verified in this
  environment**. The browser/harness results above do not substitute for them.

## Deferred-ledger disposition

| Deferred item | Resolution and evidence |
| --- | --- |
| Task 2 AI readiness `null` conflated unconfigured and load failure | Fixed with explicit `settingsLoadError`; bounded unavailable rendering verified across Dashboard, status bar, Assistant, CVE, and Settings. |
| Native 900 geometry gap | Browser boundary and native min-size configuration verified; native visual evidence remains unavailable pending the Computer Use prerequisite. |
| Source partial listener cleanup | Fixed with sequential registration and local release. Injected second-listener rejection changed successful cleanup from 0 to 2 unregistrations. Native Browse/scan/cancel/clipboard/open/rescan remains under the prerequisite. |
| Dependency reference errors and native exact-width gap | Reference rejection now surfaces a toast. Populated 1180/900 browser widths and local table scrolling were measured; native operations remain under the prerequisite. |
| CVE redundant prompt, ignored selections, and native matrix gap | Fixed single error rendering and disabled list controls during detail loading. NVD/OSV/AI/openUrl and 899/900 states were bounded-verified; native remains under the prerequisite. |
| Assistant native reload/stream/tool/permission/ask-user/cancel/clear gap | All listed frontend states were bounded-verified. Focus fallback plus non-negative/stale-prompt behavior were fixed. Native and live-provider checks remain under the prerequisites. |
| Rust test fixed temporary path | Before the fix, materializing the old fixed temp directory made the focused test fail. The test now uses PID plus nanosecond uniqueness, asserts absence, and passes in the full final Rust run. |
| Settings native persistence/API/dialog keyboard gap | Browser save failure/success, test connection, labels, focus, and dialogs were verified. Native storage/API/keyboard remains under the prerequisites. |

## Product invariants and cleanup

- Source Scan, Dependency Scan, CVE Research, and AI Assistant remain direct,
  independent sidebar tools. No project wizard, global score, compliance flow,
  or mandatory shared project was introduced.
- CVE Research and a new Assistant chat are directly usable without a selected
  project. Project/finding/CVE handoff remains visible, editable, removable, and
  confirmed before attachment.
- The responsive rule remains Tailwind `max-[900px]`: desktop holds at exactly
  900 px and the drawer begins below 900 px.
- The temporary acceptance harness, query gate, browser session, Vite server,
  Tauri process, and ports 1420/1439 were removed or stopped before the final
  production verification.

## Final-review blocker closure — 2026-08-18

This section records the consolidated closure pass for the one Critical and
five Important review areas. Browser and Node checks used bounded temporary
harnesses against the real production modules, watched the pre-fix assertion
failures, and were removed before the final automated commands. They are not
native-plugin or live-provider evidence.

### Native Assistant stream lifecycle

- RED: the focused frontend lifecycle assertion failed because `streamChat`
  exposed no synchronous run identity. The old listener/invoke sequence also
  released listeners when the command acknowledgement returned rather than
  when the background run terminated.
- GREEN: the focused harness exercised the production stream module and passed
  immediate client-owned run ID, four listeners established before invoke,
  listener retention past command acknowledgement, foreign-run filtering,
  matching terminal cleanup, partial/late-registration disposal, and early
  cancellation. Rust protocol tests pass for caller-owned/legacy IDs, ordinary
  event identity, and the frontend tool-event tag/field contract.
- Every started/event/done/error payload is correlated by `runId`; Assistant
  owns and disposes the returned stream handle. Live provider streaming remains
  under the native prerequisite below.

### Contained Source Open file

- RED: scanner findings are root-relative, while the former UI opener received
  only that relative value. The new Rust containment tests failed before the
  resolver/command existed.
- GREEN: five real filesystem tests pass for a safe nested file and rejection
  of absolute paths, parent traversal, directories, and a Unix symlink escape.
  The browser call was exactly
  `{root: "/captured/project", relativePath: "src/main.ts"}` even after the
  editable target changed, proving the captured result root is used. Native
  opener execution itself remains unverified in this environment.

### Assistant session activation

- RED: a historic session whose project moved rendered neither its persisted
  transcript nor an unavailable state; React strict effects duplicated list,
  message, and failing project calls and then created replacement sessions.
- GREEN: the transcript renders before project validation, the page shows
  `Project unavailable`, the failed historic path is followed by the explicit
  runtime `set_active_project(null)`, and no replacement session is created.
  A clean strict-mode reload produced one list, one create, and one message
  load. During a delayed selection, session/create controls stayed disabled;
  delayed stale usage could not replace the current transcript or 2.0k-token
  total.

### Settings draft and async semantics

- RED: a successful test of unsaved AI fields changed the global footer to
  `AI ready`; a delayed save overwrote edits made during the request and marked
  them clean.
- GREEN: the visible result is labeled `Draft test`, while global readiness
  continues to reflect saved settings. Save submits a cloned snapshot, publishes
  only that persisted snapshot, and leaves later edits visible and dirty with
  `Settings saved; newer edits remain unsaved`. Stale startup readiness and
  stale draft-test completion were both released after newer work and did not
  change current state.

### Dependency severity text

- RED: the populated RISK cell had an empty accessible text value because its
  label was suppressed.
- GREEN: the cell visibly and accessibly reads `HIGH`. The compact badge
  measured 11 px/600 weight, 55.9 by 22.5 px, with a computed 6.04:1 text
  contrast ratio against its composited background.

### Source defaults and submitted override contract

- RED: Source rendered hard-coded `true,true,false,false,1024` values instead
  of saved `false,true,true,true,777`, and the backend could OR saved booleans
  back on. Real walker tests additionally showed that the `Include .git`
  argument always excluded `.git` and inverted ordinary `.gitignore` behavior.
- GREEN: Source initializes once from saved settings without overwriting a
  pre-load edit. The edited browser request carried exact scanner booleans,
  `includeGit`, `followSymlinks`, and `maxFileSizeKb: 333`. Backend contract
  tests prove submitted values win while saved ignored directories remain in
  force. Filesystem tests prove `Include .git` alone controls metadata traversal
  and ordinary `.gitignore` remains respected in both states.

### Final responsive, focus, accessibility, and native boundary

- At 1,440 px, all four affected paths had document width equal to viewport
  width. At exactly 900 px the 208 px labeled sidebar remained visible, the
  menu was hidden, and main/document widths had no horizontal overflow. At
  899 px the sidebar was translated off-screen, main/document widths were
  exactly 899 px, and the menu was visible.
- The 899 px drawer focused Close, retained focus through keyboard traversal
  with a visible 2 px outline, closed on Escape, and restored focus to Open
  navigation. Populated Source, Dependency, Assistant, and Settings paths did
  not widen the document.
- Axe WCAG A/AA runs reported zero violations for Source, Assistant, Settings,
  and Dependency. Dependency retained two `incomplete` checks for existing
  `aria-label` attributes on roleless `div` elements; this pass did not recast
  incomplete checks as violations or expand into deferred minor cleanup.
- The final bounded native retry served Vite on port 1420, finished the Cargo
  development binary, and exposed a running `target/debug/vulncompanion`
  process. It was stopped cleanly with no listener or process remaining. With
  no addressable macOS Computer Use provider in this environment, native
  stream/open-file interactions and native visual inspection remain unverified.

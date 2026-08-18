# oxAudit Professional Workbench Final Fix Report

Date: 2026-08-18

Base: `f9c292f3a33b1ca39122b43ab7e3017817816e65`

Branch: `agent/oxaudit-professional-workbench`

## Status

Complete. The consolidated pass closes all six final-review issue areas: the
Critical native Assistant stream lifecycle and the five Important Source open,
Assistant activation, Settings async/draft, Dependency severity, and Source
defaults findings. Established rulings for the `max-[900px]` boundary, honest
`osv: null` ambiguity, and nullable runtime project clearing were retained.

## Implemented contracts

### 1. Assistant stream ownership and termination

- The frontend creates and exposes the run ID synchronously, installs all four
  event listeners before invoking the command, filters every callback by run,
  and keeps listeners until the matching terminal event, invoke failure, or
  explicit disposal.
- The returned handle owns cancellation, completion, and cleanup. Assistant
  disposes it on unmount and uses the immediately available identity for early
  cancellation.
- Rust accepts an optional caller run ID for compatibility, rejects empty,
  oversized, or duplicate active IDs, and injects `runId` into every ordinary
  stream event. Event variant and field serialization now matches the existing
  frontend snake-case/camel-field protocol.

### 2. Contained finding opening

- Source passes the root stored in the displayed scan result plus its relative
  finding path to a dedicated backend command.
- The backend canonicalizes root and candidate, rejects absolute/non-normal
  components, traversal, missing paths, directories, and canonical symlink
  escapes, then opens only the validated file.
- Native/open errors remain visible through the existing toast surface.

### 3. Latest session activation

- Strict-mode bootstrap work is shared while in flight and only creates a new
  session after a successful empty list.
- Session activation uses generation guards and a serialized native project
  lane. Conflicting session controls are disabled while activation is pending;
  stale message, usage, selection, model, and store commits are rejected.
- Persisted messages render before project validation. An unavailable historic
  project leaves the transcript intact, clears runtime context with
  `set_active_project(null)`, and renders an explicit project-unavailable state
  without replacing the session.

### 4. Saved versus draft Settings state

- Draft AI connection tests snapshot the form, remain local, and are visibly
  labeled. They never publish global Assistant readiness.
- Save snapshots the whole payload. Completion publishes only the submitted
  persisted snapshot; edits made while saving stay visible and dirty.
- Startup, retry, save readiness, and draft tests use generation/unmount guards
  so stale completions cannot publish state.

### 5. Dependency risk visibility

- Dependency RISK cells now render the severity word as well as the existing
  badge dot/color. Compact density and badge semantics are retained.

### 6. Source defaults and effective options

- Source initializes its scanner controls from loaded persisted settings once,
  while protecting edits made before an asynchronous settings load completes.
- Backend scan behavior uses the submitted booleans, maximum size, and scanner
  toggles exactly; saved ignored directories remain merged because Source has
  no page-level control for them.
- `Include .git` now controls actual `.git` metadata traversal and no longer
  acts as an inverted `.gitignore` switch. Ordinary `.gitignore` behavior stays
  enabled in either metadata state.

## RED/GREEN evidence

- Stream lifecycle: pre-fix harness failed `streamChat must expose a runId
  synchronously`; final production-module harness passed listener ordering,
  identity filtering, acknowledgement retention, cleanup, disposal, and early
  cancellation.
- Source open: new containment tests were unresolved/failing before the helper;
  five filesystem cases pass after the command implementation.
- Assistant activation: pre-fix missing-project fixture lost the transcript and
  created replacements; final fixture preserved history, cleared runtime, and
  created none. Delayed selection/usage remained latest-request-wins.
- Settings: pre-fix draft test changed global readiness and delayed save erased
  newer edits; final fixtures kept draft status local and later edits dirty.
- Dependency: pre-fix RISK text was empty; final cell reads `HIGH` at 6.04:1
  computed contrast.
- Source defaults: pre-fix controls rendered hard-coded values and the real
  walker failed both `.git`/`.gitignore` assertions; final UI payload and Rust
  option/filesystem tests pass.

Temporary Node/browser harnesses and the query gate were removed before final
automated verification.

## Verification

- `npm run check` — pass.
- `npm run build` — pass; Vite 7.3.6, 1,785 modules.
- `cargo test --manifest-path src-tauri/Cargo.toml` — pass; 53 passed, 0 failed,
  1 explicitly ignored live OSV test.
- `cargo check --manifest-path src-tauri/Cargo.toml` — pass with the pre-existing
  unused `sessions::transcript_path` warning only.
- `git diff --check` — pass.
- Browser acceptance — pass at 1440x900, 900x700, and 899x700 for affected
  Source, Dependency, Assistant, and Settings states; drawer focus/restore and
  shell overflow checked.
- Axe WCAG A/AA — zero violations on all four affected paths. Dependency had two
  explicitly recorded incomplete roleless-div ARIA checks.
- Bounded native retry — Vite listened on 1420, Cargo completed, and
  `target/debug/vulncompanion` ran; all were stopped cleanly afterward.

## Concerns and limits

- No live AI provider stream or native opener interaction was available. Stream
  protocol behavior is covered by Rust tests plus the bounded frontend lifecycle
  harness; open containment is covered by real Rust filesystem tests plus exact
  frontend command-payload evidence.
- The unsigned native window was not addressable through a macOS Computer Use
  accessibility provider, so native visual/keyboard claims were not made.
- The single ignored OSV live-network test and the existing dead-code warning
  remain unchanged. Deferred Minor items were not expanded into this wave.

## Cleanup

No temporary harness, query gate, browser session, Vite/native process, port,
or generated test artifact remains in the worktree.

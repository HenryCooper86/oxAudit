# Reliability validation, 2026-10-09

This records the six-area implementation before delivery. Measurements used the
macOS arm64 debug CLI with default grammars and the server feature. The measured
binary SHA-256 is
`e426f1f86a7d04f483d04dcae70f34a8eb3811740dd0568cc1b4fc7ad8782e42`.
Benchmark provenance records base commit
`1e27c8f0d46abc319e78e643bb5c53e8e1339a92` and a dirty working tree; it does not
claim that the base commit alone produced the changed binary.

## Automated checks

| Check | Observed result |
| --- | --- |
| Locked Rust workspace, all features | 1,356 passed; one existing ignored test |
| Strict workspace/all-targets/all-features Clippy | Passed with warnings denied |
| Workspace formatting and diff whitespace | Passed |
| Frontend/tooling tests | 167 Node tests and 304 Vitest tests passed |
| TypeScript check and production build | Passed |
| Consumer CI shell contracts | 10 passed, including the actual CLI contract |
| Reduced grammar builds | No-default-features and grammars-core builds passed |
| Internal corpus | 227 fixtures; 113 TP, 0 FP, 0 FN; 100% precision/recall |
| Corpus/version/action-pin consistency | Passed; all 43 action references pinned |
| New quality workflow Actionlint, including ShellCheck | Passed |
| All workflow structure validation | Passed |
| Maintainer pilot smoke and blank feedback validation | Passed; zero participant observations |

The existing release workflow has ShellCheck findings when all workflows are
linted with shell analysis; this change does not modify that workflow. The
internal corpus is authored with the rules and is a regression check, not an
external accuracy estimate.

Meaningful regressions cover stalled registry headers and bodies, actual byte
allowances and overflow, ID reuse and reordered cancellation, parent-token
isolation, scoped configuration/policy/packs, growing source reads, aggregation
limits, streaming member retention, metadata order, persistence faults,
historical object identity/redaction, reconnect/lag and delayed responses,
cross-page selection, exact export handoff, and A→B→A saved-result recovery.
New failures were reproduced before their fixes. Independent code and validation
review approved the final supplied checks with no outstanding code findings.

## Live CLI and server observations

An owned localhost registry stalled a manifest body while the actual headless
server handled authenticated requests. ID-scoped cancellation returned the scan
error in **26.89 ms** in this single observation. Concurrent work was rejected;
the cancelled run remained reloadable. A replacement operation completed with
the expected BusyBox component and verified layer digest/size. Cancelling the
old ID did not affect it, and cancellation that preceded registration prevented
that exact operation from starting.

Malformed lockfile discovery returned a null count and parser error; the actual
dependency scan rejected the malformed file. A Java configuration fixture found
the configured weak hash and recorded one covered file and two skipped files,
rather than counting unread binary content as scanned.

A deleted inert credential was found in Git history. The receipt and SARIF
contained a redacted finding and `git:<object-id>!deploy.sh`, without the raw
credential. Recreating the working-tree file did not change the export identity.
Four image/history receipts retained their evidence after restarting the server,
including a cancelled attempt and a local image whose original file was removed.

A separate actual CLI image invocation saved to SQLite, then listed and exported
its BusyBox component as CycloneDX after target deletion. The full local-file
SHA-256 and completed canonical state survived reopening. Partial standard
exports preserve lifecycle/coverage; completed execution does not imply complete
advisory or analysis coverage.

## Quality, performance and acceptance limits

The pinned external OWASP run covered all 2,740 labelled cases across 11 rule
categories. Every category passed its unchanged regression thresholds against
the previous fresh measurement; category confusion matrices did not change.
Totals were **TP 1,346, FP 724, TN 601, FN 69**: precision about **65.02%**, recall
about **95.12%**, and false positive rate about **54.64%**. Category coverage means
rules exist; it does not claim complete data-flow analysis. False positive
reduction remains further work.

The [external baseline](../benchmarks/baselines/owasp-java-550021e9.json) and
[CLI performance receipt](../benchmarks/performance/local-debug-2026-10-09.json)
retain provenance. All four owned performance workloads passed population and
identity checks; their elapsed times and command RSS are documented in
[quality/performance validation](quality-performance-validation.md).

These are single local debug observations. They establish neither a cross-host
performance budget nor total process-tree memory bounds. Native payload
reservations exclude documented allocations; pagination bounds rendered rows
while complete result data remains in memory. Local hashes describe bytes
observed before scanning, with explicit mutable-path limitations.

Real-browser paint, screen-reader behavior and external participant acceptance
remain unmeasured. The user requested [pilot preparation](pilot-validation.md)
and supplied no participant feedback. Hosted CI/quality outcomes must come from
actual GitHub runs after delivery; local checks do not substitute for those runs.

## Daily-use recovery validation, 2026-10-19

This pass fixes frontend startup, scan/history request ownership, dependency
cancellation and export recovery. It does not establish glitch-free operation,
a signed release, or cross-platform acceptance.

| Check | Observed result |
| --- | --- |
| `npm run test:unit` | 173 passed |
| `npm run test:components` | 483 passed across 54 files |
| `npm run build` | TypeScript and production bundle passed; Vite retains its warning about the intentionally server-supplied `/env.js` script |
| Locked debug build, server feature, CLI and server binaries | Passed |
| `npm run pilot:smoke -- --cli ./src-tauri/target/debug/oxaudit-cli` | Passed: source finding, unchanged/new baseline gates, correction, SARIF, durable history and malformed dependency rejection |

Live Chromium used the built frontend and actual headless backend with isolated
temporary data/config directories and inert copied scan inputs:

- Before the fix, a throwing `window.localStorage` getter produced a blank
  application and an uncaught `SecurityError`. Afterward, authentication,
  onboarding, Escape dismissal, navigation collapse and a backend-saved theme
  change worked without a page error. Headless setup showed server-path guidance
  without a native Browse button.
- A delayed saved-source metadata request followed by clearing and restoring the
  project path previously left an empty findings list while showing one finding.
  The corrected path restored the actual `eval()` finding and enabled review.
- Starting a real source scan while old metadata remained pending disabled history
  navigation. Releasing the old request afterward left the newly scanned run
  selected with its finding visible.
- User cancellation of a delayed dependency command previously showed a failure
  banner, error toast and Retry. The corrected path showed cancellation without
  a failure/Retry and retained the previous three-advisory receipt. A source-only
  project showed an explicit no-saved-dependency-results state and one Check action.
- A failed default advisory-database path lookup visibly blocked checking.
  Entering an explicit path enabled checking; no scan was submitted with the
  enabled option silently omitted.
- Injected HTTP 503 responses for the export run list and preview were recoverable
  in place. Editing the destination did not hide preview retry. Saving afterward
  wrote a real SARIF document with version `2.1.0`.

Independent review found and corrected two additional request-ownership races:
overlapping A→B→A history loads and discovery retries rearming saved-history
restoration. Regression tests cover these transitions, review-control recovery,
onboarding inspection versus native-picker opening, and advisory-path requirements
on retry/recheck as well as the primary Check action.

Limits: native macOS dialogs/bundles, Windows/Linux desktops, screen readers,
large-project soak behavior and external participant acceptance were not exercised
in this pass. The CLI smoke refused optional enrichment requests; the separate
live dependency receipt used online advisory data. Injected transport failures
establish frontend recovery behavior, not a general network-availability guarantee.

## Installation and automated browser validation, 2026-10-20

The adoption pass reconciles published-release instructions with source-build
instructions and adds a Chromium smoke suite against the real headless backend.
The [pilot protocol](pilot-validation.md#automated-browser-smoke) documents setup,
scenarios, isolated state and diagnostics; the
[release checklist](release-checklist.md#exercised-verification-2026-10-20-macos-arm64)
records downloaded-release verification separately.

| Check | Observed result |
| --- | --- |
| `npm test` | 173 tooling tests and 483 component tests passed |
| `npm run build` and locked server-feature debug build | Passed |
| `npm run check` | Passed |
| `actionlint .github/workflows/ci.yml` and action-pin check | Passed; all 45 action references pinned |
| `npm run test:e2e && npm run test:e2e` | Both consecutive runs passed all three scenarios, 13.5 seconds per run; retries disabled |
| Absent and non-executable server overrides | Both failed with exit 1 and actionable prerequisite/spawn diagnostics; zero owned backend directories left |
| Blank participant form init/validate | Prepared with zero observations; participant acceptance remains incomplete |

The browser suite uses real scans, persistence, review writes, process restart and
on-disk SARIF exports. It verifies distinct run identities rather than merely
non-empty screens. Cancellation must succeed in the backend before the held
command is released; that command must return a cancellation error, and the
export must retain the original completed receipt's identity. Export recovery
covers a run-list HTTP 503 and a successful-HTTP response with malformed preview
JSON. Source cases hold actual older saved-run metadata across target navigation
and a fresh scan, then check the displayed identity after the response and paint.

Independent review corrected false-pass gaps in the initial scenarios and a
missing-prerequisite temporary-directory leak. Fault diagnostics were exercised:
the attachment API now produces backend logs alongside screenshots and traces.
Only one runner may own an output directory: overlapping diagnostic runs removed
shared trace files during initial validation; the final two exclusive runs both
passed without manual artifact cleanup.

This is local macOS arm64 Chromium/server evidence, not a hosted Linux CI result.
The Linux Rust job is wired to run the same suite; its actual hosted outcome must
come from a later GitHub run. Native desktop dialogs, Windows/Linux desktop
acceptance, assistive technology, large-project soak behavior and external
participant sessions were not exercised by these browser checks. Filesystem
state is temporary; the suite is not an OS credential-store or network sandbox.

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

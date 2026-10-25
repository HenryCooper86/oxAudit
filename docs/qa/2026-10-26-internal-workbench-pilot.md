# Internal workbench rehearsal — 2026-10-26

**Completed: agent-run technical rehearsal on oxAudit itself.** No human
participant was observed. This establishes executable workflow behavior and
identifies follow-up work; it does not establish daily adoption, time saved,
representative detection quality or application security.

The [sanitized receipt](2026-10-26-internal-workbench-pilot.json) retains build
hashes, source revision, command arguments/outcomes, benchmark provenance,
first-20 decisions and raw-evidence checksums. The
[one-week pilot](../daily-workbench-pilot.md) remains ready for actual engineers.

## Build and scope

- Repository: `7b5e1b85e1891ecdf94611d3f1395ac140cd346c`, with the pilot documents
  from this task uncommitted. No production implementation changed in this run.
- Fresh debug CLI and server: `cargo build --locked --manifest-path
  src-tauri/Cargo.toml --features server --bin oxaudit-cli --bin oxaudit-server`.
- Fresh frontend: `npm run build`. Build passed with the existing `/env.js`
  external-script warning. Host: macOS arm64; other platforms not exercised.
- The CLI was copied to an isolated evidence folder before measurements.
  Source ignored directory names: `benchmarks`, `pilot`, `node_modules`,
  `target`, `dist`, `.git`. Other tests and documentation were included.
- Source optional enrichment was refused by a loopback proxy. The dependency
  scan used live providers, followed by an offline receipt replay. No secret
  validation, AI endpoint, notification or ticket submission was used.
- Wall times below are individual command observations on a debug build, not
  engineer effort or a controlled performance comparison. Browser testing
  overlapped part of the benchmark work; do not interpret timing differences
  against the earlier retained benchmark as performance changes.

## Executed outcomes

| Exercise | Observed result |
| --- | --- |
| Real repository source scan | 585 files scanned, 27 skipped; 67 findings in 1.062 s wall time |
| Same-revision baseline gate | Exit 0; 0 new, 67 pre-existing; all fingerprints unchanged |
| Saved source history and SARIF | Fresh-process history/export succeeded; run identity and all 67 report entries verified |
| CLI fixture pilot | Passed: finding, baseline, correction, reintroduction, malformed dependency, durable history and SARIF |
| Live dependency check | 4 lockfiles, 1,249 occurrences, 1,136 queried package identities, 23 advisory-match rows; 40.375 s |
| Offline dependency replay | Same package count, advisory identities and original advisory timestamp; 0.941 s |
| Authored corpus | 234/234 fixtures passed; 116 true observations, 0 false positives, 0 false negatives on this corpus |
| Pinned OWASP Java benchmark | 2,740 cases; TP 1,346, FP 689, TN 636, FN 69; comparator passed against committed baseline |
| Browser integration | All 5 Chromium scenarios passed against the freshly built real server, 21.2 s suite duration |

The five browser scenarios exercised cancellation/export retry, onboarding and
scan/review/recheck/restart/export, delayed saved-run metadata, long-list keyboard
and pagination behavior, and the navigation breakpoint. They are automated
fixture checks, not a visual design audit or native desktop acceptance.

The CLI correction remains **no longer observed (coverage unverified)**. The
separate browser test verified the expected compatible-coverage recheck message
and recovered the saved review after an actual server restart. Neither proves
general exploit prevention.

The fresh OWASP precision is **66.14%**, recall **95.12%**, and false-positive
rate **52.00%**. The confusion matrix is unchanged from the committed baseline.
The authored corpus's perfect result must not be substituted for these numbers.
Twenty-seven skipped source files and bounded analysis prevent a clean-project
claim even if the reviewed findings are non-actionable.

## First-20 review and actual open scope

Sampling was fixed to the first 20 entries in the original CLI JSON before
inspection. It is a **raw CLI sample**, not a claim about the desktop's default
queue. All 20 entries are tests or documentation: 16 were non-actionable for
production remediation, and 4 were second detectors on the same fixture sites.
The receipt preserves every position, fingerprint, location and rationale.
No credential validity checks were performed. No participant triage time exists.

| Raw positions | Evidence and disposition |
| --- | --- |
| 1 | Generated private-key canary in a redaction test |
| 2–3 | Documented TempDir fixture; position 3 duplicates the site at 2 |
| 4 | User-info URL used by an egress-policy test |
| 5–8 | Synthetic source files in alias-root tests; positions 6 and 8 duplicate sites 5 and 7 |
| 9–10 | Non-SQL component helper calls flagged because version literals contain `+` |
| 11–14 | Temporary Git/staged-secret fixtures and assertions that their material is absent from reports |
| 15 | History-test fixture constant |
| 16 | Example token in policy rejection tests |
| 17–19 | Failed-save test fixture and redaction assertion; position 18 duplicates site 17 |
| 20 | Explicitly documented synthetic AWS key for history tests |

Across all findings, the scanner classified 63 as test, 2 as documentation and
2 as production. The frontend's [view model](../../src/features/source-scan/resultsModel.ts)
places unreviewed test/documentation findings in **Other scopes**, so the raw
sample must not be used to claim that the engineer's default queue contains 67
production alerts. Both production-scoped entries were also non-actionable on
static inspection:

- `generic-api-key`, [secrets_validation.rs:131](../../src-tauri/src/secrets_validation.rs#L131):
  a rule-name match arm and public provider URL, not credential material.
- `generic-password`, [source.rs:64](../../src-tauri/src/adapters/scanners/source.rs#L64):
  the label `credential material` passed to a redaction constructor, not a password.

CLI gating uses review state rather than the GUI's scope grouping. A team
adopting severity gates must therefore understand that fixtures can still fail
an unbaselined gate. This is a workflow distinction to test with participants,
not a reason to suppress all test-file secrets automatically.

## Concrete follow-up handoffs

### 1. Fix proven source-alert noise before adding workflow surfaces

Follow-up: the [scanner correction report](2026-10-26-alert-quality-follow-up.md)
records implemented fixes for the SQL-literal and alternative-pattern label
cases. The ambiguous redaction-label candidate remains conservative. The
observations below describe the original rehearsal binary.

The smallest independently reproduced case is the Rust SQL rule. This inert
source has no SQL operation and produces one **production-scoped high** finding
for `rs-sql-format` in the current binary:

```rust
struct ComponentQuery;
fn query(_: Option<&str>, _: &str, _: &str) -> ComponentQuery { ComponentQuery }
fn main() {
    let _queries = vec![query(Some("Debian:12"), "libc6", "2.36-9+deb12u3")];
}
```

Reproduce by saving it as `query.rs` in a separate folder and running
`oxaudit-cli scan FOLDER --no-secrets --format json`. Do not execute the fixture.
The same issue appears at
[enrich.rs:1096](../../src-tauri/src/binscan/native/enrich.rs#L1096) and line 1119.
The helper at line 1081 constructs a `ComponentQuery`; it does not execute SQL.
The rule's regex at
[patterns.rs:185](../../src-tauri/src/scanners/patterns.rs#L185) accepts a `+`
inside a string as an assembly signal. Existing argument-boundary checks do not
eliminate this macro-contained case.

Acceptance for a repair: this case and ordinary/raw string variants no longer
alert when syntax proves there is no assembly operation; actual `format!` and
concatenated SQL sinks still alert, including inside macros and nested calls.
Specifically retain a positive case where a string containing `+` is followed
by real concatenation—simply dropping the first regex candidate can hide it.
Preserve stated text-only fallback limits. Run scanner regressions and the
authored corpus before changing any baseline.

The two production secret false positives above are additional small regression
candidates. Keep secret fixture visibility and genuine leaked credentials
separate from syntactically benign labels. These are prepared quality handoffs;
no scanner repair is claimed in this rehearsal.

### 2. Make dependency actionability explicit in the pilot

The 23 results are advisory/package occurrence rows, **not 23 proven exploitable
vulnerabilities**. Some are maintenance notices; aliases and multiple installed
versions also contribute rows. Live coverage was complete for the queries, but
license enrichment reported a 500-package bound and four registry 404s. These
are different coverage dimensions and should remain visible to the engineer.

A concrete developer handoff is prepared for `lopdf 0.35.0`:

- Live evidence: `GHSA-6fj4-rcr3-r7rr` and `RUSTSEC-2026-0187` identify the same
  issue. Preserve both IDs without treating them as two independent defects.
- `cargo tree --locked --offline --manifest-path src-tauri/Cargo.toml -i lopdf`
  established `oxaudit 0.2.4 → printpdf 0.8.2 → lopdf 0.35.0`.
- [The primary RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0187.html)
  describes a denial of service when loading deeply nested untrusted PDFs and
  lists `0.42.0` as the patched version.
- The inspected [report writer](../../src-tauri/src/adapters/reporting/compliance.rs#L459)
  constructs and saves a document. This exercise did not establish an
  attacker-controlled PDF loading path. Direct-usage `false` is not proof that
  a transitive dependency is unreachable.
- Next engineering action: assess a compatible `printpdf`/`lopdf` upgrade and
  check all supported PDF-reading paths and build configurations. Validate report
  generation before accepting an upgrade. Do not force an incompatible transitive
  override merely because a fixed-version chip exists.
- Status: dependency remediation review warranted; application exploitability
  unresolved; no patch or recipient acceptance claimed.

Likewise, `quinn-proto` is present in the lockfile, but `cargo tree -i
quinn-proto` printed no active path for the default host configuration. This is
a reason to inspect target/features, not to dismiss all of its advisory rows.

### 3. Validate the proposed daily queue with humans

The technical loop works in the tested configuration. There is now stronger
evidence for improving alert precision than for adding another dashboard.
Observe real engineers deciding their next task before choosing queue changes,
assignment fields or ticket synchronization. The existing one-week protocol
captures that evidence without fabricating a productivity comparison.

## Evidence retention and remaining work

Local raw receipts currently reside in
`/tmp/oxaudit-internal-pilot-irinq88e` (temporary, not a durable shared location).
The CLI fixture smoke retained its own temporary directory, named in that
folder's `fixture-smoke.stdout`. The sanitized JSON here is durable repository
evidence; its checksums identify raw files without publishing credential context.
No human participant form was populated.

The locally executable rehearsal is complete. Human installation effort,
comparison against an engineer's normal tools, recipient acceptance, voluntary
return over a week, native dialogs and cross-platform behavior remain **not
evaluated**. These need actual participants and environments; successful tests
cannot stand in for them.

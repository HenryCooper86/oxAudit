# Alert quality follow-up — 2026-10-26

This implements two scanner corrections identified by the
[internal workbench rehearsal](2026-10-26-internal-workbench-pilot.md).
The [measurement receipt](2026-10-26-alert-quality-follow-up.json) identifies
the exact before/after CLI binaries, unchanged input hashes and benchmark run.

## Changed behavior

Rust SQL detection no longer treats `+`, `format!` or `write!` inside a parsed
literal or comment as statement construction. This includes literals inside
macro token trees such as `vec![query(...)]`. Only the SQL rule searches a view
with non-code ASCII masked; other rules still inspect literal values as before.
Actual concatenation or formatting after a misleading literal marker remains
eligible for detection, including nested SQL calls.

The mask preserves both byte offsets and Unicode character counts. An initial
byte-space implementation expanded multibyte characters beyond the regex's
160-character window; independent review caught this, a regression was observed
failing, and ASCII-only masking corrected it. Findings retain original source
text and locations. No Rust grammar means the existing conservative text-only
behavior remains. The mask uses one additional file-sized temporary buffer for
parsed Rust input; the caller's existing file-size bounds still apply.

Generic secret detection no longer interprets distinct Rust alternative-pattern
labels, such as `"github-token" | "github-fine-grained-token"`, as a credential
assignment. The filter extends the existing conditional-label distinction.
Credentials inside one pattern/branch, assignments in arm bodies, function
arguments and provider-specific token detections remain covered by regressions.

## Deliberately retained ambiguous case

`RedactedValue::secret("credential material", correlation)` remains a generic
password candidate. This project's constructor uses the first argument as a
label, but syntax alone does not establish that contract for arbitrary scanned
projects. Ignoring the phrase or every `secret(...)` call would also hide
hardcoded credentials. The regression suite retains both a real-looking
credential passed to a function and `password = "credential material"`.

No project-specific allowlist, blanket test exclusion or rule disablement was
introduced to improve the self-scan. Resolving this remaining case automatically
would require justified API semantics or a separately reviewed heuristic.

## Paired measurement

Both binaries scanned the same copies of three unchanged repository files:
`binscan/native/enrich.rs`, `secrets_validation.rs`, and
`adapters/scanners/source.rs`. The target root, bytes and scan options were
identical; optional network enrichment was refused for both runs.

| Measure | Before | After |
| --- | --- | --- |
| Files scanned / skipped | 3 / 0 | 3 / 0 |
| Total findings | 21 | 18 |
| Non-SQL helper alerts in `enrich.rs` | 2 | 0 |
| Generic credential alert on alternative rule-name labels | 1 | 0 |
| Ambiguous redaction-label candidate | 1 | 1 |

The comparison asserts exactly those three removed finding locations and no
added locations. Other fixture detections in these files remain. These are
specific regression observations, not representative precision or recall.
The full changing repository was not used for a before/after count, since the
new regression tests themselves contain deliberate security fixtures.

## Verification

- Two original regressions failed before implementation and passed afterward;
  the additional Unicode regression failed before the review correction.
- Seven new scanner tests cover false positives, retained detections, Unicode,
  text-only fallback, and actual file-report text/coordinates.
- `cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace --all-features`:
  **1,456 passed**, zero failures, one existing test ignored.
- `npm test`: **172 Node tests and 502 frontend tests passed**.
- `cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace --all-targets --all-features -- -D warnings`:
  passed; `cargo fmt --all -- --check` and `git diff --check` passed.
- Fresh CLI build with default grammars and `server` feature passed.
- Authored corpus: **234/234 fixtures**, zero false positives or false negatives.
- Fresh pinned OWASP Java run: **TP 1,346 / FP 689 / TN 636 / FN 69**; baseline
  comparator passed with unchanged counts. This Rust-focused correction does
  not improve the previously measured Java precision.
- CLI workflow smoke passed against the new binary.
- Independent final code review found no remaining actionable issues after the
  Unicode correction. Review did not replace the executed tests above.

Raw local receipts are temporarily retained in
`/tmp/oxaudit-alert-quality-y3gi_9lm`; the sanitized JSON retains provenance and
hashes without credential context. Native desktop, cross-platform execution and
external engineer usability were not reevaluated in this scanner-only change.

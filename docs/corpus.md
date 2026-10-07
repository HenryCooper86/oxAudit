# oxAudit regression corpus

`benchmarks/corpus/suite.json` is generated from the fixture names and contents:

```bash
node tools/build-corpus-suite.mjs
cargo run --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli -- benchmark --corpus benchmarks/corpus --json -q
```

The fixtures are authored by oxAudit contributors and provide regression coverage
for rule behavior. They are not an independent or representative measurement of
real-world detection accuracy.

The Phase 1 additions are paired everyday source scenarios: request-derived and
constant command invocation, concatenated and parameterized SQL, and
request-derived and fixed outbound URLs. On 2026-09-07, the committed runner
measured 220 fixtures (100 expected-positive and 120 expected-negative), with 100
true positives, zero false positives, and zero false negatives. That result
describes this authored corpus only.

On 2026-10-07, the expanded runner measured 227 fixtures (104 expected-positive
and 123 expected-negative), with 113 true positives, zero false positives, and
zero false negatives. Some positive fixtures require both a provider-specific
and a generic detector, so true positives outnumber positive fixtures. The new
regressions cover Rust function declarations, formatted SQL errors and bound
parameters, string concatenation and nested SQL sinks, ternary UI labels, and
hardcoded credential fallbacks. Rebuilding the manifest preserves the
overlapping expectations.

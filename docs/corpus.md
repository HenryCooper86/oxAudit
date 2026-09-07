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
measured 198 fixtures (89 expected-positive and 109 expected-negative), with 89
true positives, zero false positives, and zero false negatives. That result
describes this authored corpus only.

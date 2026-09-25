# Function-level reachability: measured scoping

Function-level reachability — "does this project actually call the vulnerable
function" — has been on the plan as research-heavy with a stated data problem:
advisories rarely enumerate vulnerable symbols, so even a perfect call graph
cannot close the loop. This document records the measurement that settles
what to build and what not to.

## What was measured (2026-09-26)

- **OSV schema**: no field names functions. The only symbol-bearing extension
  point is `affected[].ecosystem_specific`, which each database fills as it
  chooses.
- **crates.io dump** (RustSec records, 2,854 advisories): `ecosystem_specific`
  carries either `affected_functions` or `affects.functions` — **275 records
  (9.6%) name at least one affected function**, e.g. RUSTSEC-2023-0018 names
  `remove_dir_all::remove_dir_all` and two companions.
  By publication year the coverage is improving, not shrinking:
  2019: 20 · 2020: 23 · 2021: 34 · 2022: 13 · 2023: 20 · 2024: 35 ·
  2025: 56 · 2026 (partial): 73.
- **npm/GHSA, PyPI, Maven, Go, RubyGems** (spot-checked via the live API and
  the dumps): no symbol fields anywhere. For these ecosystems there is
  nothing for a call graph to be right or wrong about.

## Conclusion

1. **Build for crates.io, where the data exists.** oxAudit already parses
   `Cargo.lock`, parses Rust with tree-sitter, and indexes project imports.
   The implemented slice extracts the affected functions from OSV records
   onto the vulnerability, and checks which of them the project's own Rust
   sources reference — honestly, by literal path match
   (`crate::function` text, which covers call sites and `use` lines), not by
   a guessed call graph. A vulnerability that names functions the project
   references is a different object from one that names functions it never
   touches.
2. **Do not build for ecosystems without symbol data.** For npm and friends,
   function-level reachability would mean inventing the mapping from CVE to
   function — the exact class of guess this tool refuses everywhere else.
   Import-level reachability (`reachability.rs`, tri-state `DirectUsage`)
   remains the honest ceiling there.
3. **Call graphs remain unbuilt, deliberately.** Even on crates.io the data
   names full paths, which literal matching answers without a call graph.
   A call graph would add precision the advisory data cannot reward and
   wrong-call-graph confidence the tool would rather not have.

## Limits of the implemented slice

- Literal path matching: a macro or re-export that hides the `crate::func`
  text will read as unreferenced; a string literal containing the text will
  read as referenced. Both directions are stated, not hidden.
- Only the project's own `.rs` sources are searched. A vulnerable function
  called by a transitive dependency's code is invisible to this check —
  that is the same boundary import-level reachability has.
- Coverage is 9.6% of RustSec records; where a record names no functions
  the vulnerability simply carries an empty list, and nothing is inferred.

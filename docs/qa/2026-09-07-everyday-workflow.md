# Everyday workflow delivery validation

## Phase 1 — trustworthy results

- Dependency parse/provider failures cannot produce completed empty results. Legacy batch-only caches require an online refresh; newly complete receipts preserve full advisory detail offline.
- Valid empty npm inventories succeed without advisory requests; malformed package metadata fails before lookup.
- Source findings expose syntax/text analysis evidence without claiming exploitability. Six authored paired corpus scenarios bring the corpus to 198 cases, with 89 true positives and zero false positives/negatives on that corpus.
- Validation: Rust workspace/all-features 912 passing tests (one ignored) before final parser amendment; focused parser/CLI tests passed after amendment. Frontend 120 Node +96 Vitest tests, type-check and production build passed. Final strict Clippy and formatting passed. Independent task review approved after two fix rounds.

Existing GitHub CI failures at starting commit f2c3e8f are tracked for phase 6: Linux build disk usage, Windows test loader failure, and private-repository SARIF upload permission/capability. Local macOS validation does not establish cross-platform success.

## Phase 2 — project home

- Durable source/dependency history now drives home; selected project preference is restored and validated without an automatic scan. Source counts explicitly describe completed evidence; unknown dependency counts remain unknown.
- An explicit project check runs source and dependency stages with shared ownership and cancellation across navigation. Failed/cancelled/incomplete stages remain separate from prior completed results.
- Validation: type-check,121 Node tests,131 Vitest tests,production build and native debug app bundle passed.
- Native macOS checks: Browse selected the owned QA project; combined check reported one source finding and complete empty dependency inventory; source and dependency result links opened correct receipts; restart restored selection/history without starting scans; global cancel from Settings preserved completed source and prior dependency timestamp while labelling dependencies cancelled.
- The exact restart → Home Dependency results sequence was re-tested in the final amended bundle and restored its saved receipt, showing No packages to query. Deferred selection and retry-save recovery regressions are covered by component/coordinator tests.
- Local QA used a generated project with inert source text; no package installation or live advisory query was required. Native testing used the freshly built debug bundle, not the previously installed app.

## Phase 3 — review changes

- Native macOS validation used the rebuilt debug bundle and an owned Git fixture: one file had both staged and unstaged edits, and a second source file was untracked. The full run scanned four files, finding three issues: two new and one unchanged against the saved baseline.
- New since baseline showed two findings. Combining it with staged paths showed the one new finding in the partially staged file, with explicit working-tree/index-content warnings. The unstaged/untracked path view retained findings in both changed files. No repository source was executed.
- Choosing the earlier saved baseline produced the expected comparison; returning through Project home restored the original automatic baseline, confirming the choice did not replace the saved baseline. Saved revision and coverage survived the reload; pre-phase-3 history displayed revision unavailable.
- An invalid Git base retained normal saved results, and stale context disabled filtering until refresh. Clear filters removed the search, new-only, and Git filters and restored all three findings. Project home reflected the saved three open/two new counts. The rendered native layout was inspected.
- Automated validation: Rust workspace/all-features939 passed with one pre-existing ignored test; frontend121 Node +145 Vitest passed; type-check, production build, strict workspace/all-target Clippy, formatting and authored corpus smoke passed. The corpus remains198 authored fixtures with89 true positives and zero false positives/negatives, not independent effectiveness evidence. Independent review approved the phase and all corrections; no findings remain open.

- Correction validation: an invalid owned QA policy reproduced two incorrectly closed findings when changing baseline. The corrected bundle retained all three as open under both normal and explicit comparison. Returning from run A to B to A reset baseline/Git choices; policy-aware Home counts also matched three open. Temporarily moving the owned folder preserved its history and showed counts unavailable in the command palette; restoring it recovered the counts. The temporary policy was removed and the folder restored after testing.
- Windows Git module and platform tests passed an isolated MSVC compile-only check against the actual source and locked dependency versions. This does not establish Windows runtime behavior. Final Rust checks ran serially after native packaging; an earlier overlapping-build rustdoc artifact error did not recur.

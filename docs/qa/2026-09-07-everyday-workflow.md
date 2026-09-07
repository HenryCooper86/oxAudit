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

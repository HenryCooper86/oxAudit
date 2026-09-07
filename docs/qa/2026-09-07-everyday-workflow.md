# Everyday workflow delivery validation

## Phase 1 — trustworthy results

- Dependency parse/provider failures cannot produce completed empty results. Legacy batch-only caches require an online refresh; newly complete receipts preserve full advisory detail offline.
- Valid empty npm inventories succeed without advisory requests; malformed package metadata fails before lookup.
- Source findings expose syntax/text analysis evidence without claiming exploitability. Six authored paired corpus scenarios bring the corpus to 198 cases, with 89 true positives and zero false positives/negatives on that corpus.
- Validation: Rust workspace/all-features 912 passing tests (one ignored) before final parser amendment; focused parser/CLI tests passed after amendment. Frontend 120 Node +96 Vitest tests, type-check and production build passed. Final strict Clippy and formatting passed. Independent task review approved after two fix rounds.

Existing GitHub CI failures at starting commit f2c3e8f are tracked for phase 6: Linux build disk usage, Windows test loader failure, and private-repository SARIF upload permission/capability. Local macOS validation does not establish cross-platform success.

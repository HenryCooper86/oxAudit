# Audit gap fixes (groups A–C) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the wrong-result, CI-noise and documentation gaps found by the 2026-11-02 four-area audit, each with a regression test.

**Architecture:** Every change lands in an existing module and follows that module's established pattern (`LockedPackage.source` for non-registry packages, the shared version-vector fixture for comparator parity, `srule!`/`rule!` tables plus post-filters for rules). No new crates or dependencies.

**Tech Stack:** Rust (workspace in `src-tauri/`), TypeScript/React (`src/`), VS Code extension (`editors/vscode/`), Node tooling (`tools/`).

**Spec:** The audit summary approved in conversation on 2026-11-02 (groups A, B, C). Group D (larger expansions) gets its own plan after this one ships.

## Global Constraints

- Never weaken recall to gain precision: when a decision cannot be made, keep the finding/advisory (existing "Undetermined keeps the advisory" rule).
- Rust and TypeScript version comparators must agree; every comparator change adds vectors to `src-tauri/tests/fixtures/version-ordering-vectors.json`.
- Non-registry packages are inventoried with `source` set and are never registry queries (existing `is_queryable_dependency` contract).
- No AI attribution in commits. Commit only after the user approves committing.
- Every task finishes with `cargo test --locked --workspace --manifest-path src-tauri/Cargo.toml` (or the narrower crate run named in the task) green, and `npm test` green when TS changed.
- User-facing behaviour changes get a line under `## [Unreleased]` in `CHANGELOG.md`, in the existing voice (what changed, and why it matters).

## Review Focus

1. Comparator refusal while sorting OSV events: a boundary pair the comparator cannot order must yield `Undetermined`, not a panic or silent clean (Task 1 test `unorderable_boundaries_are_undetermined`).
2. Workflow expressions that are *safe*: `env:` values, `with:` inputs other than `script`, and `if:` conditions must not fire the injection rule (Task 4 test `workflow_expressions_outside_scripts_stay_quiet`).
3. Templated connection strings (`postgres://app:${DB_PASSWORD}@db`) must not be reported as leaked credentials (Task 5 test `templated_url_passwords_are_not_secrets`).
4. A non-distro grype artifact (npm `1.0.0-rc.1`) must keep its prerelease and not merge with `1.0.0` (Task 6 test `grype_keeps_language_package_versions_verbatim`).
5. An existing user hook ending in `exec something` must still run oxAudit after install (Task 9 test `hook_block_runs_before_a_user_hook_that_execs`).

---

### Task 1: OSV matching ignores withdrawn records and evaluates events in sorted order

**Files:**
- Modify: `src-tauri/src/advisories/matching.rs` (`MatchNotes`, `range_affects`, `record_affects`, module doc comment, tests)
- Modify: `docs/advisory-database.md` (matching rules section: "walked in event order" → sorted; withdrawn records skipped)

**Interfaces:**
- Produces: `MatchNotes.withdrawn_skipped: usize`; `MatchNotes::warnings()` adds `"{n} withdrawn advisory record(s) were ignored"` when n > 0.

- [ ] **Step 1: Write failing tests** in `matching.rs` tests:
  - `withdrawn_records_never_affect`: a record with `"withdrawn": "2024-01-01T00:00:00Z"` and range `introduced 0` → `Verdict::NotAffected`, `notes.withdrawn_skipped == 1`.
  - `unsorted_events_are_sorted_before_walking`: npm range events `[introduced 2.0.0, fixed 2.5.0, introduced 0, fixed 1.0.0]`; `2.2.0` → `Affected`, `1.5.0` → `NotAffected`, `0.5.0` → `Affected`.
  - `limit_is_an_upper_gate_not_an_event`: events `[introduced 0, limit 2.0.0]`; `1.0.0` → `Affected`, `2.0.0` → `NotAffected`.
  - `unorderable_boundaries_are_undetermined`: Maven-family range with one boundary the comparator refuses (use a whitespace version `"1 0"`) → `Undetermined`.
  - `simultaneous_transitions_are_undetermined`: events `[introduced 1.0.0, fixed 1.0.0]` → `Undetermined` (mirrors the TS rule "do not guess tie order").
  - Rename `introduced_fixed_intervals_walk_in_event_order` → `introduced_fixed_intervals_union` (assertions unchanged).
- [ ] **Step 2:** `cargo test --locked --manifest-path src-tauri/Cargo.toml -p oxaudit advisories::matching` → new tests FAIL.
- [ ] **Step 3: Implement.** In `record_affects`, return `NotAffected` and bump `withdrawn_skipped` when `record["withdrawn"]` is a non-empty string. Rewrite `range_affects` to mirror `affectedBy` in `src/features/dependencies/decisions.ts:880-915`: split `limit` events out; collect `introduced`/`fixed`/`last_affected` transitions (`introduced "0"` sorts first); sort with the family comparator; any refused boundary comparison or equal adjacent boundaries → `Undetermined`; walk sorted transitions against the installed version as today; affected only if inside a transition interval **and** below at least one limit (or no limits; `limit "*"` is unbounded).
- [ ] **Step 4:** Same command → all `advisories::` tests PASS (existing tests must not change expectations).
- [ ] **Step 5:** CHANGELOG `### Fixed`: offline/`--advisory-db` matching no longer reports withdrawn advisories, and evaluates ranges whose events are out of order instead of missing them.

### Task 2: Separate NuGet and Composer version orderings

**Files:**
- Modify: `src-tauri/src/advisories/versioning.rs` (replace `Loose` with `NuGet` and `Composer`; `family_for`; `compare`; `mod loose` → `mod nuget` + `mod composer`; tests incl. `shared_vectors_hold_for_the_frontend_mirror` name map)
- Modify: `src/features/dependencies/decisions.ts` (`VersionFamily` union, `versionFamilyForEcosystem`, `compareVersions`, replace `parseLoose`/`compareLoose`)
- Modify: `src/features/dependencies/decisions.test.ts`
- Modify: `src-tauri/tests/fixtures/version-ordering-vectors.json`

**Interfaces:**
- Produces: `VersionFamily::NuGet`, `VersionFamily::Composer` (Rust); `'nuget' | 'composer'` (TS, replacing `'loose'`). Fixture family names `"nuget"`, `"composer"`.

Orderings to implement:
- **NuGet** (NuGet SemVer 2.0): up to four numeric release segments (missing = 0); a release outranks its prereleases; prerelease labels split on `.`, numeric identifiers compare numerically and below alphanumeric ones, alphanumeric compare **case-insensitively** ordinal; more identifiers wins on equal prefix; build metadata (`+…`) ignored; the 4th segment compares **before** the prerelease (it is part of the release).
- **Composer** (`composer/semver` `VersionParser::normalize` + `version_compare`): up to four numeric segments; suffix stability order `dev < alpha|a < beta|b < RC|rc < (release) < patch|pl|p`, each with an optional number (`RC2 < RC10`), case-insensitive, separators `-`, `.`, `_` or none; `dev-*` branch names and `*.x-dev` refuse (`None`).

- [ ] **Step 1: Add fixture vectors** (both engines read them): nuget `1.0.0-rc.9 < 1.0.0-rc.10`, `1.0.0-Beta == 1.0.0-beta`, `1.0.0-alpha < 1.0.0-alpha.1`, `1.2.3.5-beta > 1.2.3.4`, `1.0.0+build == 1.0.0`, `1.0 == 1.0.0.0`; composer `1.0.0-RC1 > 1.0.0-beta2`, `1.0.0-alpha9 < 1.0.0-alpha10`, `2.0.0-p1 > 2.0.0`, `2.0.0-patch1 > 2.0.0-RC5`, `1.0.0-dev < 1.0.0-alpha`, `v1.2 == 1.2.0`; refusals: composer `dev-main`, `1.0.x-dev`; nuget `""`, `1.0.x`. Family table: `NuGet → nuget`, `Packagist → composer`.
- [ ] **Step 2:** `cargo test ... versioning` and `npx vitest run src/features/dependencies` → FAIL (unknown family names).
- [ ] **Step 3:** Implement both orderings in Rust and TS per the rules above; delete `Loose`/`loose`. Update `docs/advisory-database.md` matching table rows for NuGet and Packagist.
- [ ] **Step 4:** Both commands PASS, plus `npm run check`.
- [ ] **Step 5:** CHANGELOG `### Fixed`: NuGet and Packagist versions use their registries' own orderings (`rc.10` after `rc.9`, Composer `-patch` after the release); the shared loose ordering misplaced both.

### Task 3: Skip non-registry yarn, Composer and Pub packages

**Files:**
- Modify: `src-tauri/crates/oxaudit-parsers/src/lockfiles.rs` (`parse_yarn_lock`, `parse_composer_lock`, `parse_pubspec_lock` return `Vec<LockedPackage>`; dispatch in `parse_lockfile_text` drops their `registry_packages(...)` wrappers; tests)

**Interfaces:**
- Consumes: existing `LockedPackage { name, version, source: Option<&'static str> }` with sources `"local" | "git" | "url"`.

Rules:
- **yarn** (per selector in a block header; the block's source is the first non-registry protocol found, else registry): range after the package name starting with `workspace:`, `file:`, `link:`, `portal:` → `local`; `git+`, `git:`, `git@`, `github:`, `gitlab:`, `bitbucket:`, or a `.git` URL / `#commit` hash → `git`; `http:`/`https:` tarballs → `url`; `exec:` → `local`. A Berry version of `0.0.0-use.local` → `local`. `patch:` descriptors: percent-decode the inner descriptor (`resolve@npm%3A1.22.1` → `resolve@npm:1.22.1`) and treat it as that registry package, named `resolve`, never `resolve@patch:resolve`.
- **Composer:** `dist.type == "path"` or `source.type == "path"` → `local`; version starting `dev-` or ending `-dev` → `git` (a branch, not a release).
- **Pub:** `source: git` → `git` (keep `path`/`sdk` skipped as today).

- [ ] **Step 1: Write failing tests:** `yarn_berry_workspace_file_link_portal_and_git_entries_are_not_registry_queries` (each listed protocol plus `0.0.0-use.local`; assert `source` per entry and that a plain `lodash@npm:^4.17.21` stays `None`); `yarn_patch_descriptors_name_the_patched_package`; `yarn_classic_git_and_tarball_entries_are_not_registry_queries`; `composer_path_repositories_and_dev_branches_are_not_registry_queries`; `pub_git_packages_are_not_registry_queries`. Assert via `parse_lockfile_content(...)` that the dependency's `occurrence.source` is set and `crate::models::is_queryable_dependency` is false.
- [ ] **Step 2:** `cargo test --locked --manifest-path src-tauri/Cargo.toml -p oxaudit-parsers lockfiles` → FAIL.
- [ ] **Step 3:** Implement per the rules.
- [ ] **Step 4:** Same command PASS; run `cargo build --manifest-path src-tauri/fuzz/Cargo.toml` only if the fuzz crate builds in this environment (skip with a note otherwise).
- [ ] **Step 5:** CHANGELOG `### Fixed`, alongside the 0.2.7 wording: yarn workspace/file/link/portal/git/tarball entries, Composer path repositories and dev branches, and Pub git packages are inventoried but no longer queried against the public registry.

### Task 4: GitHub Actions script-injection rule covers real workflows

**Files:**
- Modify: `src-tauri/src/scanners/patterns.rs:225` (`gha-script-injection` regex)
- Modify: `src-tauri/src/scanners/mod.rs` (post-filter next to `pattern_hit_stays_in_sink`; tests near `workflow_rules_stand_down_on_pinned_actions_and_bound_expressions`)

**Interfaces:**
- Produces: `fn workflow_expression_in_script(content: &str, offset: usize) -> bool` in `scanners/mod.rs`.

- [ ] **Step 1: Write failing tests** using the existing `workflow_rules_firing` helper:
  - `workflow_injection_fires_inside_block_scripts`: `run: |` block whose second line is `echo "${{ github.event.pull_request.title }}"` → contains `gha-script-injection`.
  - `workflow_injection_fires_on_quoted_and_head_ref_forms`: `- run: echo "${{ github.event.issue.title }}"` and `- run: git checkout ${{ github.head_ref }}` each fire.
  - `workflow_injection_fires_in_github_script`: `uses: actions/github-script@<sha>` with `with:\n  script: |\n    const t = "${{ github.event.comment.body }}"` fires.
  - `workflow_expressions_outside_scripts_stay_quiet`: the expression in `env: TITLE:`, in `with: ref: ${{ github.head_ref }}`, and in `if: ${{ github.event.pull_request.draft == false }}` → no `gha-script-injection`.
  - Edit `workflow_rules_stand_down_on_pinned_actions_and_bound_expressions`: drop the quoted `run: echo "${{ github.event.issue.title }}"` line (it is a true positive), keep the rest.
- [ ] **Step 2:** `cargo test ... scanners::tests::workflow` → FAIL.
- [ ] **Step 3: Implement.** Regex becomes the expression alone: `\$\{\{\s*(?:github\s*\.\s*(?:event\s*\.|head_ref\b)|inputs\s*\.)[^}]*\}\}`. `workflow_expression_in_script` finds the YAML key that owns the offset: the key on the hit's own line if the expression follows `key:` there, otherwise the nearest preceding non-blank line with smaller indentation (strip a leading `- ` before reading its key); returns true when that key is `run` or `script`. Apply it to `gha-script-injection` hits only, where pattern hits are filtered. Keep the rule's description/recommendation; add one sentence: quoting does not help, because GitHub expands the expression before the shell parses the script.
- [ ] **Step 4:** `cargo test ... scanners` PASS.
- [ ] **Step 5:** CHANGELOG `### Fixed`: workflow script-injection detection covers multi-line `run:` blocks, quoted expressions, `github.head_ref` and `actions/github-script` scripts.

### Task 5: Secret detection fixes and a test for every rule

**Files:**
- Modify: `src-tauri/src/scanners/secrets.rs` (`SecretRule` gains `reports_in_comments: bool`; macro arg; `vault-token` and `basic-auth-url` regexes; new `#[cfg(test)] mod tests`)
- Modify: `src-tauri/src/scanners/mod.rs:63-69` (`secret_hit_is_reportable`) and `:701` (rule-pack path keeps today's behaviour)
- Modify: `README.md:954` (rule count — compute it, do not hard-code a guess)

**Interfaces:**
- Produces: `SecretRule.reports_in_comments`.

Rules:
- `reports_in_comments = true` for vendor-prefixed, low-false-positive rules: `aws-access-key-id`, `github-token`, `github-fine-grained-token`, `gitlab-pat`, `slack-token`, `slack-webhook`, `stripe-key`, `google-api-key`, `openai-api-key`, `anthropic-api-key`, `huggingface-token`, `npm-token`, `pypi-token`, `private-key`, `sendgrid-api-key`, `discord-webhook`, `digitalocean-token`, `shopify-token`, `vault-token`, `telegram-bot-token`, `sentry-token`, `newrelic-api-key`, `postman-api-key`, `linear-api-key`, `figma-token`, `grafana-service-account-token`, `square-access-token`. Every other rule stays comment-suppressed. Placeholder filtering (`is_placeholder`) still applies to all.
- `vault-token`: `\b(?:hv[sbr]\.[A-Za-z0-9_-]{24,}|s\.[A-Za-z0-9]{24,})\b`.
- `basic-auth-url`: schemes `https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?`; empty user allowed; the password must not begin with `$`, `%`, `{` or `<` (templating), i.e. `(?:SCHEMES)://[^/\s:@]*:([^@\s/$%{<][^@\s/]*)@` with `secret_group` 1.

- [ ] **Step 1: Write failing tests** in `secrets.rs`:
  - `every_rule_detects_its_canonical_example`: a table `&[(rule_id, sample_line)]` with one realistic (non-placeholder, high-entropy) sample per rule; assert each sample yields a hit for exactly that rule id, and assert the table's ids equal `SECRET_RULES` ids (so a new rule without a sample fails).
  - `vault_service_batch_and_recovery_tokens_match`: `hvs.`, `hvb.`, legacy `s.` samples.
  - `database_connection_string_passwords_match`: postgres, mysql, `mongodb+srv`, `redis://:pw@cache`, amqp.
  - `templated_url_passwords_are_not_secrets`: `${DB_PASSWORD}`, `%(pw)s`, `{{password}}`, `<password>` → no `basic-auth-url` hit.
  - In `scanners/mod.rs` tests: `prefixed_tokens_in_comments_are_reported` (`# token = "ghp_<36>"` in `.py` → `github-token`) and `generic_passwords_in_comments_stay_suppressed` (`# password = "hunter2hunter2"` → none).
- [ ] **Step 2:** `cargo test ... scanners` → FAIL.
- [ ] **Step 3:** Implement; set the README count from `SECRET_RULES.len()` after the change.
- [ ] **Step 4:** `cargo test ... scanners` PASS; run the benchmark corpus check if one exists for secrets (`grep -rn secret benchmarks/ | head`) and note any recall change in the commit message.
- [ ] **Step 5:** CHANGELOG `### Fixed`: vendor-prefixed tokens and private keys are reported inside comments (history and `--staged` already did); modern Vault tokens and database/cache connection-string passwords are detected.

### Task 6: Merge grype distro packages with native results

**Files:**
- Modify: `src-tauri/src/binscan/grype.rs` (`Artifact` gains `#[serde(default, rename = "type")] kind: String`; `parse_report` grouping key and `version`)
- Modify: `docs/binary-scanning-runtime.md:333-340` ("Still open": remove the merge-key bullet; signature count 22 → current count from `signatures.toml`)

- [ ] **Step 1: Write failing tests** in `grype.rs`: `grype_distro_versions_merge_with_native_upstream_versions` (deb `mariadb 1:11.8.6-0+deb13u1` → component version `11.8.6`; then `report::merge` with a native `mariadb 11.8.6` yields one component with both scanners in `detected_by`); `grype_keeps_language_package_versions_verbatim` (npm `1.0.0-rc.1` stays `1.0.0-rc.1`).
- [ ] **Step 2:** `cargo test ... binscan` → FAIL.
- [ ] **Step 3:** For `kind` in `deb | rpm | apk`, use `oxaudit_parsers::package_note::upstream_version` for both the grouping key and `component.version`; others verbatim.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** CHANGELOG `### Fixed`: grype's Debian/RPM/apk components merge with oxAudit's native and cve-bin-tool rows instead of appearing twice.

### Task 7: Dismissed findings stop producing CI annotations and editor diagnostics

**Files:**
- Modify: `src-tauri/src/cli/mod.rs` (`emit_github_annotations` call site at ~1427 and `render_summary_markdown` input)
- Modify: `editors/vscode/src/extension.ts` (`CliFinding.review?: { state: string }`; filter before capping); `editors/vscode/CHANGELOG.md` (add 0.2.7 + Unreleased entries)
- Create: `editors/vscode/src/findings.ts` (pure helper) and `editors/vscode/src/findings.test.ts` only if the extension has a test runner; otherwise put the helper test in root `tests/vscodeFindings.test.ts` run by `npm run test:unit` (import the helper by relative path)

**Interfaces:**
- Produces (TS): `export function reportableFindings<T extends { review?: { state?: string } }>(findings: T[]): T[]` — drops `falsePositive`, `acceptedRisk`, `suppressed`.

- [ ] **Step 1: Write failing tests:** Rust `annotations_skip_dismissed_findings` — factor the per-finding loop into `fn github_annotation_lines(findings, prefix) -> Vec<String>` and assert a `Suppressed` finding yields no line while a `Confirmed` one does; TS test for `reportableFindings` with all five states.
- [ ] **Step 2:** Run `cargo test ... cli::tests::annotations` and `npm run test:unit` → FAIL.
- [ ] **Step 3:** Filter with the existing `gates_the_build` (Rust) and `reportableFindings` (TS). The step summary keeps dismissed findings but labels the count line "N dismissed by policy (not annotated)".
- [ ] **Step 4:** PASS; `npx tsc -p editors/vscode` compiles.
- [ ] **Step 5:** CHANGELOG `### Fixed`.

### Task 8: SARIF paths resolve from the repository root

**Files:**
- Modify: `src-tauri/src/cli/mod.rs` (`ScanArgs`, deps args, `ExportArgs`: `--sarif-uri-prefix <PREFIX>`; helper; write sites for SARIF)
- Modify: `docs/cli.md`, `examples/ci/oxaudit.yml` (replace the jq prefix step with `--sarif-uri-prefix target/`)

**Interfaces:**
- Produces: `fn prefix_sarif_uris(sarif: &[u8], prefix: &str) -> Result<Vec<u8>, CliError>` — prefixes every `runs[].results[].locations[].physicalLocation.artifactLocation.uri` (and `relatedLocations`) that is relative and not already prefixed; prefix normalised to end in `/`; empty prefix returns input unchanged.

- [ ] **Step 1: Write failing tests:** `sarif_uris_gain_the_prefix_once` (relative uri prefixed; already-prefixed and absolute `file:` uris untouched; idempotent when applied twice); `scan_defaults_sarif_prefix_from_github_workspace` (with `GITHUB_ACTIONS`/`GITHUB_WORKSPACE` set to a parent of the scan root, the default prefix equals `github_workspace_prefix(root)`; explicit `--sarif-uri-prefix ""` disables it). Use the existing env-var test pattern in `cli/mod.rs` tests (serialise env mutation the same way existing tests do).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Implement. `scan`/`deps`: default = `github_workspace_prefix(root)` when the flag is absent; `export`: no default (scan root unknown), flag only.
- [ ] **Step 4:** PASS; validate a prefixed SARIF still passes the bundled SARIF schema check used by reporting tests.
- [ ] **Step 5:** CHANGELOG `### Added`.

### Task 9: `hook install` works with hook managers

**Files:**
- Modify: `src-tauri/src/cli/staged.rs` (`managed_block`, `install_hook`, `hook_status`, `run_hook` output; tests)
- Create: `.pre-commit-hooks.yaml`
- Modify: `docs/cli.md` hook section; README pre-commit paragraph

**Interfaces:**
- Produces: `fn configured_hooks_path(root: &Path) -> Option<String>` — repo-local or global `core.hooksPath` (read-only `git config --get`; the hardened command nulls global config, so read global with a separate minimal `git config --global --get core.hooksPath`).

- [ ] **Step 1: Write failing tests:**
  - `hook_block_runs_before_a_user_hook_that_execs`: existing hook `#!/bin/sh\nexec npx lint-staged\n` → after install the managed block sits directly after the shebang, before `exec npx lint-staged`.
  - `managed_block_does_not_exec`: block contains `{HOOK_COMMAND} || exit $?` and no `exec `.
  - `install_refuses_when_core_hooks_path_is_set`: `git config core.hooksPath .husky` in the temp repo → `install_hook` errors, message names `.husky` and says to add `oxaudit-cli scan --staged --quiet` to that directory's `pre-commit`; nothing written to `.git/hooks`.
  - `status_reports_inactive_under_core_hooks_path`.
  - Update `hook_install_refresh_and_uninstall_roundtrip` and `hook_install_preserves_an_existing_hook` to the new block text/placement (uninstall still restores the user's content byte-for-byte).
- [ ] **Step 2:** `cargo test ... cli::staged` → FAIL.
- [ ] **Step 3:** Implement. Status output when hooksPath is set: `Not active: core.hooksPath is {path}; git does not run {hook path}`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** `.pre-commit-hooks.yaml`: one hook `id: oxaudit-secrets`, `name: oxAudit staged secrets scan`, `entry: oxaudit-cli scan --staged --quiet`, `language: system`, `pass_filenames: false`, `stages: [pre-commit]`. CHANGELOG `### Fixed` + `### Added`.

### Task 10: CLI exports GitHub Issues and Jira CSV

**Files:**
- Modify: `src-tauri/src/cli/mod.rs:646-700` (`OutputFormat`, `ExportFormat`, mappings); `docs/cli.md`; `tests/commandParity.test.ts` if it enumerates CLI formats

- [ ] **Step 1: Failing test:** `export_offers_ticket_csv_formats` — `Cli::try_parse_from(["oxaudit","export","--db",x,"--run",y,"--format","github-issues-csv"])` and `jira-csv` parse and map to `ReportFormat::GithubIssuesCsv`/`JiraCsv`; an end-to-end export of a stored fixture run produces CSV whose header row matches what `ExportCenter` gets for the same format.
- [ ] **Step 2:** FAIL. **Step 3:** add variants to both enums. **Step 4:** PASS. **Step 5:** CHANGELOG `### Added`.

### Task 11: Docs match the published v0.2.7 release, and CI catches the drift

**Files:**
- Modify: `README.md` (lines ~26, 537, 552, 562), `CHANGELOG.md:7-8`, `docs/getting-started.md` (7, 31, 45, 52, 81, 93, 113, 132, 148, 277), `docs/headless-server.md:31`, `docs/cli.md:4`, `docs/release-checklist.md` (5-8, 16, 22-28, step 7), `examples/ci/oxaudit.yml:24-26`
- Modify: `tools/check-versions.mjs`

- [ ] **Step 1:** Collect facts with `gh release view v0.2.7 --json assets,publishedAt,tagName`, `git rev-parse v0.2.7^{commit}`, the release's `SHA256SUMS.txt` (linux-x86_64 line), and the image digest from the release notes or registry (`docker buildx imagetools inspect` if available). Do not copy digests from this plan; read them.
- [ ] **Step 2:** Update every listed location. The README Action note at ~562 becomes: v0.2.7 includes the environment-variable input handling.
- [ ] **Step 3:** Extend `check-versions.mjs`: newest dated `## [x.y.z] - YYYY-MM-DD` in CHANGELOG must equal (a) the README "latest release … vX" marker, (b) getting-started's "checked against published vX", (c) `OXAUDIT_TOOL_VERSION`-style pin in `examples/ci/oxaudit.yml`; `docs/cli.md`'s `oxaudit X` header must equal the Cargo version. Each mismatch is an actionable `problems.push(...)` like the existing ones.
- [ ] **Step 4:** `node tools/check-versions.mjs` exits 0; temporarily change one marker and confirm it exits 1, then revert.
- [ ] **Step 5:** Release checklist step 7 lists the files the script guards.

### Final verification

- [ ] `cargo test --locked --workspace --manifest-path src-tauri/Cargo.toml`, `cargo clippy --locked --workspace --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings`, `cargo fmt --check --manifest-path src-tauri/Cargo.toml`
- [ ] `npm test`, `npm run lint`, `npm run check`, `node tools/check-versions.mjs`
- [ ] Rebuild the CLI and run it on scratch fixtures for Tasks 4, 5 and 9 (workflow file, commented token, husky repo) to confirm behaviour outside unit tests.
- [ ] Whole-branch review by a fresh reviewer.

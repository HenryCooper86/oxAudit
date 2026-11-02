# Project Config File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a repository keep its `oxaudit-cli scan` and `deps` settings (ignored directories, gate thresholds, rule-pack files, scanner switches) in a committed `.oxaudit/config.toml`, so CI, the pre-commit hook, the GitHub Action and the VS Code extension all behave the same without repeating flags.

**Architecture:** A new `src-tauri/src/cli/project_config.rs` loads and validates `.oxaudit/config.toml` from the scan root through the same hardened opener as `policy.json`. `run_scan`, the staged hook path and `run_deps` merge it under one rule: an explicit flag beats the config, and the config beats the built-in default. Ignore lists are the one exception: config and flags are combined. The CLI prints where each gate came from.

**Tech Stack:** Rust, `toml 0.8` (already a dependency), clap.

**Spec:** No separate spec. This plan's Design section is the design (group D, 2026-11-02).

## Design

```toml
version = 1

[scan]
ignore_dirs = ["node_modules", "target", "dist"]  # added to any --ignore-dir flags
fail_on = "high"            # none|info|low|medium|high|critical; applies to --staged too
fail_on_new = "medium"      # used only with --baseline
max_file_size_kb = 2048
secrets = true              # false acts like --no-secrets
patterns = true             # false acts like --no-patterns
rule_pack_files = ["security/team-rules.toml"]  # relative to the project root; must stay inside it

[deps]
ignore_dirs = ["examples"]
fail_on = "critical"
fail_on_new = "high"
```

- **Location:** `<scan root>/.oxaudit/config.toml`. For `--staged` the scan root is the repository root. The CLI never walks up to parent directories, which matches how `policy.json` is found.
- **Who reads it:** `scan` (including `--staged`) and `deps` read it.
  - `image`, `history` and the other commands do not.
  - The desktop app and the headless server do not. ADR work in `docs/y-agent-adoption.md:50` defers project config in the app until workspace trust exists.
  - The VS Code extension, the GitHub Action and the pre-commit hook pick it up for free, because they run the CLI.
- **Precedence:** an explicit flag wins, then the config, then the built-in default.
  - `ignore_dirs` is combined with `--ignore-dir`.
  - `--no-config` (on `scan` and `deps`) ignores the file entirely.
- **Validation:** the file is strict, and an invalid file fails with exit 2 (usage) and the reason. Usage errors are what a bad config is closest to, and failing loudly keeps a typo from silently loosening a gate.
  - `version` must be exactly 1.
  - Unknown tables or keys are an error.
  - The size cap is 256 KiB, and symlinks and non-regular files are refused.
  - `rule_pack_files` entries must be relative, contain no `..`, and resolve (after canonicalizing) inside the root.
- **Gate visibility:** unless `--quiet`, stderr prints `Gate: --fail-on high (from .oxaudit/config.toml)` whenever the config set a gate. The GitHub step summary adds the same line. A config change that loosens the gate shows up in CI logs, and `docs/getting-started.md` already treats `.oxaudit/` changes as gate changes.
- **Dogfooding:** add this repo's own `.oxaudit/config.toml` with the `--ignore-dir` list from `.github/workflows/self-scan.yml`, and drop those flags from the workflow.

**Non-goals:**
- Machine-specific settings in the config (`--db`, `--advisory-db`, `--offline`, output paths).
- Per-rule enable/disable or severity overrides. No such mechanism exists today, and adding one is a separate feature.
- YAML or JSON variants of the file.

## Global Constraints

- No AI attribution in commits or PRs. Commit only after the user approves, on a branch.
- The file path is exactly `.oxaudit/config.toml`, `version = 1`, and the cap is 256 KiB.
- Keys are snake_case, matching TOML convention and the existing rule-pack files.
- Exit codes are unchanged. An invalid config exits 2.
- With no config file present, behaviour and output are byte-identical to today, except that `--no-config` is accepted.

## Review Focus

1. `--staged` with `scan.fail_on = "none"`: the hook stops blocking. That is intended, but the stderr gate line must say so.
2. A `rule_pack_files` entry that is absolute, `../x.toml`, or a symlink that points outside the root: refused with exit 2, and never read.
3. `max_file_size_kb` given in config and `--max-file-size` also passed: the flag wins. This needs the flag to become `Option<u64>` so "not passed" can be told apart from the default of 1024.
4. A config with `secrets = false` and `patterns = false`: the same usage error as passing `--no-secrets --no-patterns`.
5. A subdirectory scan (`scan mysite/`): it reads `mysite/.oxaudit/config.toml`, not the repository root's file.

---

### Task 1: Config model and loader

**Files:**
- Create: `src-tauri/src/cli/project_config.rs` (tests inline)
- Modify: `src-tauri/src/cli/mod.rs` (`mod project_config;`; add `serde::Deserialize` with `#[serde(rename_all = "lowercase")]` to `FailOn`)
- Modify: `src-tauri/src/findings/policy.rs` (reuse its hardened opener with a file-name parameter, if `advisory-suppression` Task 1 has not already generalized it)

**Interfaces:**
- Produces:
  - `pub struct ProjectConfig { pub scan: ScanConfig, pub deps: DepsConfig }`
  - `ScanConfig { ignore_dirs: Vec<String>, fail_on: Option<FailOn>, fail_on_new: Option<FailOn>, max_file_size_kb: Option<u64>, secrets: Option<bool>, patterns: Option<bool>, rule_pack_files: Vec<PathBuf> }`
  - `DepsConfig { ignore_dirs, fail_on, fail_on_new }`
  - `pub fn load_project_config(root: &Path) -> Result<Option<ProjectConfig>, String>`: `Ok(None)` when the file is missing, and `rule_pack_files` already resolved to absolute paths inside `root`.
  - `pub const PROJECT_CONFIG_PATH: &str = ".oxaudit/config.toml";`

- [ ] **Step 1: Write the failing tests**
  - `a_missing_config_is_none`
  - `a_full_config_parses_every_key`: the Design example round-trips to the expected struct.
  - `unknown_keys_and_tables_are_rejected`: `[scan] fail_onn = "high"` and `[image]` each give an `Err` that names the key.
  - `version_must_be_one`: missing, `0` and `2` are all `Err`.
  - `rule_pack_paths_must_stay_inside_the_root`: absolute, `../x.toml` and an outward symlink (`#[cfg(unix)]`) are each `Err`. `rules/a.toml` (existing) resolves to `root.join("rules/a.toml")` canonicalized.
  - `an_oversized_or_symlinked_config_is_refused`
- [ ] **Step 2: Run** `cargo test --manifest-path src-tauri/Cargo.toml --lib project_config`. Expected: compile failure.
- [ ] **Step 3: Implement.** Use `toml::from_str` into `#[serde(deny_unknown_fields)]` structs, with a private `RawConfig { version: u16, #[serde(default)] scan, #[serde(default)] deps }`, then validate.
- [ ] **Step 4: Run.** Expected: 6 passed.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Add the project config file loader"`

### Task 2: Apply the config to `scan` and `--staged`

**Files:**
- Modify: `src-tauri/src/cli/mod.rs`:
  - `ScanArgs.max_file_size` becomes `Option<u64>`, with the 1024 default applied after the merge.
  - Add `--no-config`.
  - `run_scan` loads and merges the config and prints the gate line.
  - Update every `ScanArgs { … }` test literal.
- Modify: `src-tauri/src/cli/staged.rs`: the gate default is `args.fail_on.or(config.fail_on).unwrap_or(FailOn::High)`, and it uses the merged ignore list and rule packs.
- Modify: the step-summary renderer (`render_summary_markdown`): add the gate-source line.
- Test: `src-tauri/src/cli/mod.rs` tests and `src-tauri/tests/cli_end_to_end.rs`.

**Interfaces:**
- Consumes: Task 1's `load_project_config`.
- Produces: `fn merge_scan(args: &ScanArgs, config: Option<&ScanConfig>) -> EffectiveScan`. `EffectiveScan { ignore_dirs, fail_on: FailOn, fail_on_source: GateSource, fail_on_new, max_file_size_kb, scan_secrets, scan_patterns, rule_pack_files }`, where `enum GateSource { Flag, Config, Default }`.

- [ ] **Step 1: Write the failing tests**
  - Unit: `flags_override_config_and_config_overrides_defaults`. A table of cases over `merge_scan`: fail_on from the flag, from the config, or the default; max_file_size from the flag, from the config, or 1024; ignore_dirs is the union in config-then-flags order with no duplicates.
  - Unit: `config_disabling_both_scanners_is_a_usage_error`.
  - End-to-end: `a_committed_config_ignores_directories_and_sets_the_gate`. In `project()`, write `.oxaudit/config.toml` with `ignore_dirs = ["vendored"]` and `fail_on = "high"`, and plant a finding under `vendored/`. Expect exit 1 from the remaining high finding, no `vendored/` paths in the JSON, and stderr containing `Gate: --fail-on high (from .oxaudit/config.toml)`.
  - End-to-end: `no_config_ignores_the_file`. With `--no-config`, the `vendored/` finding is present and the exit is 0 (no gate).
  - End-to-end: `an_invalid_config_is_a_usage_error`. Exit 2, and stderr names `config.toml` and the bad key.
  - End-to-end: `a_subdirectory_scan_reads_its_own_config` (Review Focus 5).
  - `staged.rs` unit test: `staged_scans_take_the_gate_from_config`. A config with `fail_on = "critical"` and a staged high finding gives exit 0.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --manifest-path src-tauri/Cargo.toml --workspace`. Expected: all pass.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Read scan settings from .oxaudit/config.toml"`

### Task 3: Apply the config to `deps`

**Files:**
- Modify: `src-tauri/src/cli/mod.rs`: add `DepsArgs --no-config`, merge `ignore_dirs`, `fail_on` and `fail_on_new` in `run_deps`, print the gate line, and update the `DepsArgs` test literals.
- Test: `src-tauri/tests/cli_end_to_end.rs`.

- [ ] **Step 1: Write the failing test**

`deps_reads_its_gate_and_ignores_from_config`: use the offline fixture from `advisory_database_supports_offline_dependency_matching`, and add a second lockfile under `examples/`. The config sets `[deps] ignore_dirs = ["examples"]` and `fail_on = "low"`. Expect exit 1, and the JSON `lockfilesFound` excludes `examples/`.

- [ ] **Step 2: Run it to verify it fails.**
- [ ] **Step 3: Implement**, reusing `merge_scan`'s precedence helper for the shared fields.
- [ ] **Step 4: Run** the workspace tests. Expected: all pass.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Read deps settings from .oxaudit/config.toml"`

### Task 4: Dogfood and document

**Files:**
- Create: `.oxaudit/config.toml` for this repo, with `[scan] ignore_dirs = ["benchmarks", "pilot", "node_modules", "target", "dist"]`.
- Modify: `.github/workflows/self-scan.yml`: drop the five `--ignore-dir` flags.
- Modify:
  - `docs/cli.md`: a "Project config" section with the example and the precedence rule, plus `--no-config` rows.
  - `README.md`: a short section linking to it.
  - `docs/getting-started.md`: one line noting that `config.toml` is a gate file, beside the existing `policy.json` line.
  - `CHANGELOG.md` `[Unreleased]` → Added.

- [ ] **Step 1: Run the self-scan locally**

Run: `cargo run --manifest-path src-tauri/Cargo.toml --bin oxaudit-cli -- scan . --format json --quiet > before.json` before the change and `after.json` after it.
Expected: the same findings count (the config replaces the flags exactly).

- [ ] **Step 2: Run** `node tools/check-versions.mjs`. Expected: OK.
- [ ] **Step 3: Commit** (after approval): `git commit -m "Use a project config for the self-scan and document it"`

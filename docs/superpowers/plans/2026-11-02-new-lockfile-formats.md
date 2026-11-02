# New Lockfile Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cover the common dependency files that `deps` silently skips today: `npm-shrinkwrap.json`, `gems.locked`, `pdm.lock`, `deno.lock`, and .NET project files (`*.csproj`, `*.fsproj`, `*.vbproj` with `Directory.Packages.props`). Also say so, instead of staying silent, when a project only has Bun's binary `bun.lockb`.

**Architecture:** Every format goes through the existing pipeline in `src-tauri/crates/oxaudit-parsers/src/lockfiles.rs`:
- `LOCKFILE_NAMES`
- `lockfile_kind`
- `ecosystem_for_kind`
- the `parse_lockfile_text` match
- `fs_utils::is_lockfile_name` for discovery

Each maps to an ecosystem that already has an advisory comparator (npm, RubyGems, PyPI, NuGet), so matching needs no change. .NET project files are discovered by extension, the same way `is_requirements_file` already handles patterns.

**Tech Stack:** Rust, `toml 0.8`, `quick-xml 0.42`, `serde_json`, the existing `parse_bun_jsonc`, and cargo-fuzz seeds.

**Spec:** No separate spec. This plan's Design section is the design (group D, 2026-11-02).

## Design

| File | Kind | Ecosystem | Rules |
|---|---|---|---|
| `npm-shrinkwrap.json` | `npm` | npm | Same parser as `package-lock.json` (v2/v3 graph). If both sit in one directory, npm uses the shrinkwrap, so `package-lock.json` is skipped with an inventory note. |
| `gems.locked` | `bundler` | RubyGems | Same parser as `Gemfile.lock`. If both are present, `Gemfile.lock` is skipped with a note. |
| `pdm.lock` | `pdm` | PyPI | TOML `[[package]]` `name`/`version`. Entries with `path` or `editable = true` are local, `git` is git, and `url` without a `version`-matching file is url. An empty `[[package]]` list is a valid empty inventory. |
| `deno.lock` | `deno` | npm | JSON (via `parse_bun_jsonc`). Versions 3 to 5. npm entries come from `packages.npm` (v3) or top-level `npm` (v4+). Keys are `name@version` and may carry peer suffixes (`_react@18.2.0`); split at the last `@` after a leading scope `@` and strip everything from the first `_`. `jsr` and `remote` entries are not queried, and are counted in one inventory note. |
| `*.csproj` / `*.fsproj` / `*.vbproj` | `msbuild` | NuGet | `<PackageReference Include=… Version=…/>` (attribute or child element). With no `Version`, the `<PackageVersion>` from the nearest `Directory.Packages.props` at or above the project file, up to the scan root, is used; `VersionOverride` wins. Only exact versions are queried (`1.2.3`, `[1.2.3]`). Floating (`1.*`), ranges and `$(Property)` values are recorded as unchecked inventory notes, the way requirements.txt ranges are. A project file whose directory has a `packages.lock.json` is skipped with a note, because the lockfile is authoritative. |
| `bun.lockb` alone | — | — | Not parsed. Discovery records the inventory note `bun.lockb is Bun's binary lockfile and is not read; run "bun install --save-text-lockfile" to write bun.lock`. |

**Non-goals:**
- Swift, CocoaPods, conan, renv, Haskell and Nix files. They need new OSV ecosystems and comparators.
- `paket.lock`, Gradle build scripts, `rebar.lock`.

## Global Constraints

- No AI attribution in commits or PRs. Commit only after the user approves, on a branch.
- Keep the existing limits: 16 MiB per file, 256 lockfiles, 100k dependencies. Budget errors start with `resource limit:`.
- A malformed file fails the whole file with `invalid <file name>: …`. A structurally valid empty file is an empty inventory.
- Non-registry packages get `source: Some("local" | "git" | "url")` and are never queried.
- After `LOCKFILE_NAMES` grows, regenerate every seed in `src-tauri/fuzz/seeds/parse_lockfile/`. The fuzz target selects the format by `byte % len`, so each seed's first byte must be recomputed for the new length.

## Review Focus

1. A `deno.lock` npm key for a scoped package with a peer suffix (`@scope/pkg@1.0.0_react@18.2.0`): it must become `@scope/pkg` at `1.0.0`.
2. A .NET repo with central package management, where a nested project sits under two `Directory.Packages.props` files: the nearest one wins, and nothing above the scan root is read.
3. `npm-shrinkwrap.json` and `package-lock.json` in one directory: each package is inventoried once.
4. A `.csproj` with a UTF-8 BOM or an MSBuild condition attribute: it parses, the condition is ignored, and a note lists conditional references.
5. Discovery inside `node_modules/**/npm-shrinkwrap.json` (published packages ship them): ignored the same way nested `package-lock.json` files are today. Check what discovery does for those and match it.

---

### Task 1: `npm-shrinkwrap.json` and `gems.locked`

**Files:**
- Modify: `src-tauri/crates/oxaudit-parsers/src/lockfiles.rs`: grow `LOCKFILE_NAMES` (and its array length), and update `lockfile_kind`, the `package-lock.json` branch of `parse_lockfile_text` (match on both names) and the Gemfile branch.
- Modify: `src-tauri/src/fs_utils.rs` (`is_lockfile_name`).
- Modify: `src-tauri/src/deps/service.rs` (or wherever per-directory lockfile sets are assembled): skip a shadowed file and add the note.
- Modify: `src-tauri/src/advisories/ingest.rs:504` kinds list: add `"uv"`, which was missing, plus the new kinds.
- Test: `lockfiles.rs` `mod coverage_gap_tests`, `src-tauri/src/deps/service_tests.rs`.

- [ ] **Step 1: Write the failing tests**
  - `npm_shrinkwrap_parses_as_a_package_lock`: same assertions as an existing package-lock v3 test, under the new name.
  - `gems_locked_parses_as_a_gemfile_lock`
  - service-level `a_shrinkwrap_shadows_the_package_lock_beside_it`: one directory with both files, the packages are counted once, and `inventory_notes` contains `package-lock.json was skipped because npm-shrinkwrap.json takes precedence`.
- [ ] **Step 2: Run** `cargo test --manifest-path src-tauri/Cargo.toml -p oxaudit-parsers shrinkwrap`, then `gems_locked`. Expected: FAIL (unknown name).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the parsers crate and the `deps::` tests. Expected: pass. `every_supported_name_has_a_kind_and_a_parser` passes too.
- [ ] **Step 5: Regenerate the fuzz seeds.** Write a short script in the scratchpad that rewrites each seed's first byte to `index_of(name) % LOCKFILE_NAMES.len()`. Add seeds `npm-shrinkwrap_json` and `gems_locked`. Then run `cargo +nightly fuzz build parse_lockfile` in `src-tauri/fuzz`, if a nightly toolchain is present; otherwise ledger that the build was not run.
- [ ] **Step 6: Commit** (after approval): `git commit -m "Read npm-shrinkwrap.json and gems.locked"`

### Task 2: `pdm.lock`

**Files:** `lockfiles.rs` (new `fn parse_pdm_lock(content: &str) -> Result<Vec<LockedPackage>, String>` beside `parse_uv_lock`), `fs_utils.rs`, `ingest.rs` kinds, a fuzz seed.

- [ ] **Step 1: Write the failing tests**
  - `pdm_lock_reads_registry_packages_and_marks_local_git_and_url_sources`: four packages (a registry one, `path` + `editable`, `git` + `revision`, `url`). The queried set is the registry one only, and the sources are `[None, local, git, url]`.
  - `pdm_lock_kind_maps_to_pypi`
  - `pdm_lock_empty_and_malformed_documents`: no packages gives `Ok(empty)`; a package missing `version` gives `Err` starting `invalid pdm.lock`.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement**, modelled on `parse_uv_lock`.
- [ ] **Step 4: Run them to verify they pass.**
- [ ] **Step 5: Commit** (after approval): `git commit -m "Read pdm.lock"`

### Task 3: `deno.lock`

**Files:** `lockfiles.rs` (new `fn parse_deno_lock(content: &str) -> Result<(Vec<LockedPackage>, Vec<String>), String>`, returning packages and notes), `fs_utils.rs`, `ingest.rs` kinds, a fuzz seed.

- [ ] **Step 1: Write the failing tests**
  - `deno_lock_v3_reads_packages_npm`
  - `deno_lock_v4_reads_top_level_npm_and_strips_peer_suffixes`: covers `chalk@5.3.0`, `@scope/pkg@1.0.0_react@18.2.0` and `react-dom@18.2.0_react@18.2.0`.
  - `deno_lock_counts_jsr_and_remote_entries_in_a_note`: two jsr entries and one remote entry produce a note `3 Deno jsr/remote module(s) are not checked against npm advisories`.
  - `deno_lock_rejects_unknown_versions_and_malformed_keys`: `"version": "9"` gives `Err`, and a key without `@version` gives `Err`.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement**, routing notes through the inventory-notes mechanism the pom/requirements parsers already use.
- [ ] **Step 4: Run them to verify they pass.**
- [ ] **Step 5: Commit** (after approval): `git commit -m "Read npm packages from deno.lock"`

### Task 4: .NET project files with central package management

**Files:**
- Create: `src-tauri/crates/oxaudit-parsers/src/msbuild.rs`:
  - `pub fn parse_project(content: &str, central: &CentralVersions) -> Result<MsbuildInventory, String>`
  - `pub fn parse_central_versions(content: &str) -> Result<CentralVersions, String>`
  - `MsbuildInventory { packages: Vec<(String, String)>, unchecked: Vec<String> }`
- Modify:
  - `lockfiles.rs`: an `is_msbuild_project(path)` sibling of `is_requirements_file`. The kind is `msbuild` and the ecosystem NuGet. The file entry point finds the nearest `Directory.Packages.props` between the project's directory and the scan root.
  - `fs_utils.rs` discovery (accept by extension).
  - The deps service: skip a project file when `packages.lock.json` is in the same directory.
- Test: inline in `msbuild.rs`, plus a service-level test.

- [ ] **Step 1: Write the failing tests**
  - `package_references_with_exact_versions_are_queried`: attribute and child-element forms, and `[1.2.3]` becomes `1.2.3`.
  - `floating_ranged_and_property_versions_are_unchecked_notes`: `1.*`, `[1.0,2.0)` and `$(NewtonsoftVersion)` each appear in `unchecked` with the package name.
  - `central_versions_fill_missing_versions_and_version_override_wins`
  - `the_nearest_directory_packages_props_wins_and_nothing_above_the_root_is_read`: a tempdir tree (Review Focus 2).
  - `a_bom_and_conditions_do_not_break_parsing` (Review Focus 4).
  - service-level `a_packages_lock_json_makes_the_project_file_redundant`.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement** with `quick-xml`, using the same reader settings as the pom parser (no DTD and no entity expansion).
- [ ] **Step 4: Run them to verify they pass.** Add a fuzz seed `example_csproj`, plus the selector-byte regeneration from Task 1 if the names array changed.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Read NuGet references from .NET project files"`

### Task 5: `bun.lockb` note and docs

**Files:**
- Modify: discovery in `src-tauri/src/fs_utils.rs` / the deps service. When a directory has `bun.lockb` and no `bun.lock`, add the note from the Design table.
- Modify:
  - `README.md:230` (the supported-files row).
  - `docs/dependency-scanning-reliability.md` (a short section per new format).
  - `CHANGELOG.md` `[Unreleased]` → Added.

- [ ] **Step 1: Write the failing service test**

`a_binary_bun_lockfile_is_named_not_silently_skipped`

- [ ] **Step 2: Run it**, implement, and run it again. Expected: FAIL, then pass.
- [ ] **Step 3: Run** the full workspace tests and `node tools/check-versions.mjs`. Expected: all pass.
- [ ] **Step 4: Commit** (after approval): `git commit -m "Name binary bun.lockb files and document the new lockfiles"`

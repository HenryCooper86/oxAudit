# Close the Deferred Minors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every item the final reviews of the audit-gap work and of group D deferred as "minor", including the three larger ones: layer supersession for image package databases, concurrent online OSV lookups for images, and VEX exports that reflect advisory-policy dismissals.

**Architecture:** Nine independent tasks, grouped by area. Each one is a set of small, test-first fixes in code that already exists. Task 8 adds a layer-order context to the native image scanner, and Task 6 adds bounded concurrency to `binscan::native::enrich::enrich`.

**Tech Stack:** Rust (src-tauri, `oxaudit-parsers`), React + TypeScript (one badge), shell and YAML for the hook files.

**Spec:** No separate spec. The items are the "Deferred minors" lists in the review ledgers, as reported to the user on 2026-11-02 and 2026-11-03. The user asked to close them all.

## Global Constraints

- No AI attribution in commits or PRs. Commit once after the final review, then merge to `main` and push (the user's standing instruction).
- Every fix comes with a test that fails first. Behaviour that isn't named here stays byte-identical.
- No new crate dependencies unless they are already in the lock file (check `memchr` and `percent-encoding` in `Cargo.lock` before using them).
- Untrusted input never panics. Every limit that trips produces a note.

## Review Focus

1. Layer supersession: one image whose layers 1 and 3 both write `var/lib/dpkg/status`. Only layer 3's packages are reported, a note counts the superseded ones, and a non-image directory scan is unchanged.
2. Concurrent lookups: results and notes come out in the same deterministic order as the sequential run, cancellation still stops promptly, and an error from one lookup is a note, not a failed scan.
3. VEX: an export of a run with policy-dismissed advisories still validates against the bundled schemas.
4. Hook placement: a user hook that sets `PATH` before running tools keeps working once the oxAudit block is inserted.
5. SARIF URI encoding: a path containing a space, `#`, `%` or non-ASCII characters is percent-encoded exactly once, and an already-prefixed run is not double-encoded.

---

### Task 1: Advisory-policy polish

**Files:**
- `src-tauri/src/cli/mod.rs`
- `src-tauri/src/findings/policy.rs` (`read_regular_file`, `read_project_file`)
- `src-tauri/src/findings/advisory_policy.rs`
- `src-tauri/src/agent/tools.rs` (~135)
- `src/components/PolicyDismissedBadge.tsx` and its test
- `README.md`
- `src-tauri/tests/cli_end_to_end.rs`

- [ ] **Move the doc comment.** "Decide the exit code from the severities reported…" goes back above `fn gate`, off `gating_ranks`.
- [ ] **Explicit `--advisory-policy` follows a final symlink.** `read_regular_file` takes a flag. With `follow: true` it uses `metadata` (follows) instead of `symlink_metadata`. The `.oxaudit/` project read stays no-follow. Test: `an_explicit_policy_path_may_be_a_symlink` (a ConfigMap-style link to a regular file loads).
- [ ] **Better error messages:**
  - A directory at the path says `is a directory, not a file`, not "os error 22".
  - The project-file error names the path once.
  - Test: `policy_read_errors_name_the_problem_plainly`.
- [ ] **Non-unix fallback.** On targets that are neither unix nor windows, a missing file or directory returns `Ok(None)`. This is the cfg branch in `read_project_file`; there's no test on this host, so check the branch by reading it.
- [ ] **Agent output.** `agent/tools.rs` adds `"dismissed": v.review.is_some()` (and the state) to each advisory it returns. Test in the existing agent dependency tool tests.
- [ ] **Badge accessibility.** The badge gets `aria-label="Dismissed by policy: <state>, <reason>"` and visually hidden reason text. Component test: `exposes the reason to assistive technology`.
- [ ] **README, "Dependency and image advisories" section.** Add four points:
  - An entry with only `advisory` dismisses it in every package, including ones added later.
  - The project root means the scanned `PATH`.
  - `monitor` does not apply the policy.
  - Protect `.oxaudit/` with CODEOWNERS (or point CI at a trusted file with `--advisory-policy`).
- [ ] **End-to-end tests:**
  - `fail_on_new_gates_the_undismissed_and_not_the_dismissed_in_one_run`: two new advisories, one dismissed, so the run exits 1 for the other.
  - `a_version_narrowed_entry_dismisses_only_that_version`: two installed versions; only one is dismissed.
  - `a_directory_at_the_policy_path_is_refused`: exit 3.

### Task 2: VEX exports reflect advisory-policy dismissals

**Files:**
- `src-tauri/src/adapters/reporting/mod.rs` (`vex_statements` ~618-633; CycloneDX VEX ~308-315)
- `src-tauri/src/adapters/reporting/dependencies.rs` (detail lookup already reads `review`)

**Mapping (my call):**

| Policy state | OpenVEX | CycloneDX `analysis` |
|---|---|---|
| `falsePositive` | `status: not_affected`, `impact_statement: <reason>` (no justification enum is claimed) | `state: false_positive`, `detail: <reason>` |
| `acceptedRisk` | `status: affected`, `action_statement: "Risk accepted: <reason>"` | `state: exploitable`, `response: ["will_not_fix"]`, `detail: <reason>` |
| `suppressed` | `status: affected`, `action_statement: "Suppressed by policy: <reason>"` | `state: exploitable`, `response: ["will_not_fix"]`, `detail: <reason>` |

Undismissed advisories keep today's output.

- [ ] **Tests:**
  - `openvex_marks_policy_false_positives_not_affected`
  - `cyclonedx_vex_carries_policy_analysis`
  - Both exports of a run with dismissals validate (`reporting::validate`).
- [ ] **Docs:** add one CHANGELOG line.

### Task 3: Project-config polish

**Files:**
- `src-tauri/src/cli/project_config.rs`
- `src-tauri/src/cli/mod.rs`
- `src-tauri/tests/cli_end_to_end.rs`

- [ ] **Read errors.** A `.oxaudit` that exists but cannot be read (symlinked directory, permission) is a failure (exit 3), as it was before the config existed. The "(at most N bytes, not a symlink)" hint appears only for size and symlink refusals. Test: `an_unreadable_oxaudit_directory_is_a_failure_not_a_usage_error`.
- [ ] **Both scanners off.** The message names the source: flags, config, or both. Test: extend `config_disabling_both_scanners_is_a_usage_error`.
- [ ] **TOML errors keep line and column.** Use `error.to_string()`, prefixed. Test: an unknown key's error contains `line`.
- [ ] **Help text.** The `scan --fail-on` help mentions the project config, as `deps` does.
- [ ] **Tests:**
  - `the_config_notice_reaches_the_github_step_summary` (sets `GITHUB_STEP_SUMMARY` to a temp file).
  - `config_rule_pack_files_are_applied` (a pack rule fires from a config-listed file, including under a subdirectory scan).
  - `a_deps_fail_on_flag_overrides_the_config`.

### Task 4: .NET and lockfile polish

**Files:**
- `src-tauri/crates/oxaudit-parsers/src/msbuild.rs`
- `src-tauri/crates/oxaudit-parsers/src/lockfiles.rs`
- `src-tauri/src/advisories/ingest.rs`
- `src-tauri/src/deps/service_tests.rs`

- [ ] **Conditional versions.** A `Condition` on a `<Version>`/`<VersionOverride>` child, or a reference inside `<Choose>`/`<When>`/`<Otherwise>`, marks the reference conditional and adds the note. Duplicate `<PackageVersion>` pins of one id in props note "pinned more than once; the last pin is used". Tests: `conditional_version_children_and_choose_blocks_are_noted`, `duplicate_central_pins_are_noted`.
- [ ] **Symlinked props.** When the nearest `Directory.Packages.props` (or `Directory.Build.*`) is a symlink, the walk stops there with a note naming it, instead of falling through to an outer file. Test: `a_symlinked_nearest_props_file_stops_the_walk_with_a_note`.
- [ ] **Ingest test list.** `ingest.rs` default-ecosystems test kinds list gains `"msbuild"`.
- [ ] **Service-level routing test.** `a_dotnet_project_is_parsed_with_its_central_versions_in_a_scan` uses an offline fixture DB for NuGet (extend `advisory_db_with` to take an ecosystem) and asserts the centrally pinned package reaches the scan.
- [ ] **One bounded-read helper.** `read_bounded_text` becomes the single helper; `parse_lockfile_inventory_with_limit` calls it, so the error text is identical. Existing size-limit tests cover this.

### Task 5: Go polish

**Files:**
- `src-tauri/crates/oxaudit-parsers/src/go_buildinfo.rs`
- `src-tauri/src/binscan/native/scan.rs`
- `docs/binary-scanning-runtime.md`

- [ ] **Sentinel framing.** When the sentinel check fails, module info is treated as empty (mirrors Go's `debug/buildinfo`), and the binary still reports `stdlib`. Test: `unframed_module_information_is_ignored`.
- [ ] **Varint accumulation.** Accumulate in `u64` with `checked_shl` and convert at the end. Test: `varints_never_overflow_the_accumulator` (a 10-byte varint).
- [ ] **Faster magic search.** Use `memchr::memmem::find_iter` if `memchr` is already in `Cargo.lock` (it is a dependency of `regex`); otherwise keep the scan and record a ruling. Existing tests cover behaviour.
- [ ] **Display name.** The standard library shows as product `go-stdlib`; `package_name` stays `stdlib` for OSV. Update the tests that look up `stdlib` by product. Test: `the_standard_library_component_is_named_go_stdlib`.
- [ ] **Coexistence test.** `a_package_note_and_go_build_info_coexist_in_one_elf`.

### Task 6: Concurrent online OSV lookups for images

**Files:**
- `src-tauri/src/binscan/native/enrich.rs` (`enrich`)

- [ ] **Bounded concurrency.** Run the OSV lookups with at most 8 in flight, using `futures::stream::iter(..).buffered(8)` (check that `futures` is in the lock file; otherwise use `tokio::task::JoinSet` with a semaphore).
  - `buffered` keeps input order, so `found` and `notes` stay deterministic.
  - Check cancellation before each lookup starts. After cancelling, the existing "cancelled after N of M" note is emitted with N equal to the number of completed lookups.
  - Progress messages stay per lookup.
- [ ] **Test.** `osv_lookups_run_concurrently_and_keep_their_order` uses a fake OSV source behind the trait or the existing test seam (find the one `enrich` tests use; if there is none, extract `fn osv_lookup_results(lookups, query: impl Fn(..) -> Future)` and test that function). It asserts:
  - concurrency greater than 1, via a counter of in-flight calls;
  - results in input order;
  - a failing lookup becomes a note.

### Task 7: RPM and image polish

**Files:**
- `src-tauri/crates/oxaudit-parsers/src/os_packages.rs`
- `src-tauri/src/binscan/native/enrich.rs` (`enrich_local`)
- `src-tauri/crates/oxaudit-parsers/src/bdb_hash.rs`
- `src-tauri/src/binscan/native/rpmdb.rs`
- `docs/advisory-database.md`

- [ ] **Map Mariner and Tumbleweed.** Verify against OSV first: query `Azure Linux:2` for a CBL-Mariner 2.0 package such as `openssl`, and `openSUSE:Tumbleweed`. Map `ID=mariner VERSION_ID=2.0` → `Azure Linux:2`, and `ID=opensuse-tumbleweed` → `openSUSE:Tumbleweed` (source naming). If either cannot be confirmed, keep it Unsupported but fix the note so it doesn't claim OSV lacks the ecosystem. Test: extend `rpm_distros_map_to_their_osv_ecosystems`.
- [ ] **`enrich_local` counting.** It counts uncovered components, not per-stream queries, and passes `query_local` each `(ecosystem, name, version)` once. Test: `a_rhel_component_missing_streams_is_counted_once`.
- [ ] **BDB value types.** Count `H_DUPLICATE`/`H_OFFDUP` value items and surface them as "unreadable" through `read_bdb` (a note). A database with the checksum metaflag set is read as before, and the checksum is not verified; record a ruling. Test: `duplicate_value_items_are_counted_not_dropped`.
- [ ] **Corrupt-database test.** Tighten `a_corrupt_or_foreign_database_is_an_error_not_a_panic`: a half-truncated database must be `Err`.
- [ ] **Docs.** One sentence in `docs/advisory-database.md`: for Debian binNMU packages the image receipt's `rawVersion` is the source version that was queried.

### Task 8: Superseded package databases across image layers

**Files:**
- `src-tauri/src/binscan/native/scan.rs` (layer context; `scan_member`; `finish_metadata`)

**Design (my call):**
- A package database written again by a later layer replaces the earlier copy, as the image's merged filesystem does.
- For each database path suffix (`var/lib/dpkg/status`, `lib/apk/db/installed`, the rpm paths), only detections from the topmost layer that contains it are kept.
- Layer rank comes from:
  - the registry layer index (`layer-NNNN`);
  - for a saved image, the order of the `Layers` array in `manifest.json` (or `index.json` → manifest for OCI layouts inside a tar).
- Detections whose layer has no known rank are left alone.
- A note says `N package(s) from lower image layers are superseded by a later layer's package database and are not reported`.
- A whiteout of a database path (`.wh.status`) removes that database from lower layers. This is optional: implement it only if the whiteout marker's path reaches the scanner. Otherwise record a ruling and list it in the docs' Still open.

- [ ] **Tests:**
  - `a_later_layer_package_database_supersedes_an_earlier_one`: a saved-image tar with `manifest.json` listing two layers, each with `var/lib/dpkg/status` (libssl3 1.0 vs 1.1). Only 1.1 is reported, with the note. The tar member order is the reverse of the manifest order, to prove the manifest is what decides.
  - `registry_layers_supersede_in_pull_order`: two in-memory layers via `scan_image_layers`.
  - `a_directory_scan_without_layers_is_unchanged`.
- [ ] **Docs.** `docs/binary-scanning-runtime.md` "Still open": update the layer-whiteouts bullet to what remains.

### Task 9: First-round minors

**Files:**
- `src-tauri/src/cli/mod.rs` (`prefix_sarif_uris`)
- `src-tauri/src/binscan/grype.rs`
- `src-tauri/src/cli/staged.rs`
- `src-tauri/src/scanners/mod.rs` (workflow script detection)
- `.pre-commit-hooks.yaml`
- `src-tauri/src/scanners/secrets.rs` (placeholder filter)

- [ ] **SARIF percent-encoding.** Percent-encode the prefix (and only the prefix) per RFC 3986 path rules (`%`, space, `#`, `?`, non-ASCII). Existing result URIs are already encoded by the reporter, so they are not re-encoded. Test: `sarif_prefixes_are_percent_encoded_once`.
- [ ] **grype upstream versions.** The distro-to-upstream merge does not collapse a pre-release (`1.0~rc1`) into its release (`1.0`). Keep `~…` in the merge key. Test: `grype_does_not_merge_a_prerelease_with_its_release`.
- [ ] **Hook placement.** The managed block goes after the shebang and after a leading run of blank, comment, `export`, `PATH=`/variable-assignment and `set -…` lines, and before the first other command. Test: `the_block_is_placed_after_the_user_s_environment_setup`.
- [ ] **`core.hooksPath` from any scope.** Detect it with `git config --get core.hooksPath` (no scope flag), which covers system, global, local, worktree and `include` files. Keep the standard-directory exemption. Test: `a_hooks_path_from_an_included_config_is_honoured` (a local config `include.path` pointing at a file that sets `core.hooksPath`).
- [ ] **Flow-style workflow steps.** `{ run: "echo ${{ github.event.issue.title }}" }` and `- {name: x, run: …}` are recognised as script context. Test: extend `workflow_injection_fires_inside_block_scripts` with the flow-style forms; a flow-style `with:` stays quiet.
- [ ] **pre-commit minimum version.** `.pre-commit-hooks.yaml` gains `minimum_pre_commit_version: "3.2.0"`.
- [ ] **Short credential URLs.** The placeholder filter for `basic-auth-url` looks at the password part only, so a short real URL whose host or user contains a word like `example` is still reported, while a placeholder password (`changeme`, `password`) stays filtered. Test: `short_credential_urls_are_judged_by_their_password`.
- [ ] **CHANGELOG.** `[Unreleased]` → Fixed gets one line per user-visible change in Tasks 1–9.

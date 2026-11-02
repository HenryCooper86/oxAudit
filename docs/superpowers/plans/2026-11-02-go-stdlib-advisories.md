# Go Standard-Library Advisories Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report Go standard-library and toolchain advisories, which are most Go CVEs. They come from a `go.mod` that pins a toolchain, and from the exact Go version and module list embedded in compiled Go binaries found in images and directories.

**Architecture:**
- A normalizer turns Go version spellings (`go1.22rc1`, `1.21`) into OSV's form (`1.22.0-rc.1`, `1.21.0`).
- `go_inventory::parse` emits synthetic `stdlib` and `toolchain` packages when `go.mod` has a `toolchain` directive.
- A new pure parser reads Go build info (`\xff Go buildinf:`) from ELF, Mach-O and PE binaries. binscan turns it into detections for `stdlib` plus every embedded module.
- All of it flows through the existing OSV and local-database matching with ecosystem `Go`, which already uses the SemVer comparator.

**Tech Stack:** Rust, in the `oxaudit-parsers` crate (fuzzed) and `src-tauri/src/binscan/native`.

**Spec:** No separate spec. This plan's Design section is the design (group D, 2026-11-02).

## Design

Facts checked against live OSV on 2026-11-02:
- `Go`/`stdlib` at `1.21.3` returns 84 advisories, and `v1.21.3` returns the same 84.
- `go1.21.3` returns 163, because an unparseable version matches every record. Normalizing is therefore required.
- `Go`/`toolchain` holds the cmd/go advisories (15 at 1.21.3).

**Normalizer.** `pub fn osv_go_version(raw: &str) -> Option<String>` lives in `oxaudit-parsers/src/go_inventory.rs`.
- Strip a leading `go`.
- Accept `MAJOR.MINOR[.PATCH][(rc|beta)N]` followed by an optional `-suffix` or `+suffix` (custom toolchain builds), and drop the suffix.
- A missing patch becomes `.0`.
- `rcN` and `betaN` become `-rc.N` and `-beta.N` on the `.0` patch.
- `default`, `go1`, `(devel)`, `devel go1.23-abcdef` and anything else give `None`.

**go.mod.**
- If a `toolchain goX.Y.Z` directive normalizes, the parser emits two dependencies: `stdlib` and `toolchain`. Both have ecosystem `Go`, that version, and the go.mod as their lockfile.
- Each gets the warning `Go standard-library version comes from the go.mod toolchain directive; the Go that actually builds this module can be newer`.
- **The `go X.Y` line alone emits nothing** (my call, on noise grounds). It is a minimum language version, and real builds almost always use a newer toolchain. Matching on it would put ~90 stale stdlib advisories on nearly every Go repository. An inventory note says: `Go standard-library advisories need a toolchain directive in go.mod, or a scan of the built binary`.

**Binaries.**
- The build-info blob is a 32-byte header: the 14-byte magic `\xff Go buildinf:`, then the pointer-size byte at 14 and the flags byte at 15.
- When `flags & 0x2`, which covers Go 1.18 and later, two varint-length-prefixed strings follow at offset 32: the Go version and the modinfo.
- Modinfo is wrapped in 16-byte sentinels; strip the first 16 and last 16 bytes when the length is at least 32. Its lines are:
  - `path\t<p>`
  - `mod\t<p>\t<v>\t<sum>`
  - `dep\t<p>\t<v>\t<sum>`
  - `=>\t<p>\t<v>\t<sum>`, which replaces the previous dep
  - `build\t…`
- Pre-1.18 pointer-format binaries return a reason (`pre-1.18 Go binary; build info not read`), and binscan adds it as a note once per scan with a count.
- Only the first magic in a file counts.
- The search is limited by binscan's existing 128 MiB member cap. Module and line counts are capped: 10,000 deps, and the cap gives a note.
- binscan emits a `Detection` with `ecosystem: Some("Go")` and `source: DetectionSource::GoBuildInfo`:
  - one for `stdlib` at the normalized Go version;
  - one for each `dep` or replacement with a `v`-version, with `v` stripped as go.mod parsing already does;
  - none for `(devel)` versions;
  - no `toolchain` detection for binaries, because toolchain advisories affect the machine that builds, not the program.

**Non-goals:**
- Pre-1.18 binaries.
- Reachability or symbol-level filtering (govulncheck-style).
- The `pkg:golang` purl rename.

## Global Constraints

- No AI attribution in commits or PRs. Commit only after the user approves, on a branch.
- The parser never panics, and every length and offset is checked arithmetic. Malformed input returns `None` or an `Err` reason.
- Versions are stored without `v` (the existing go.mod convention, and what OSV uses for stdlib).
- New `Detection`/`DetectionSource` fields and variants are additive. Existing image results are unchanged except for added detections.

## Review Focus

1. A stripped Go binary (`-ldflags=-s -w`): build info survives stripping, and the test fixture must not rely on symbols.
2. A Go binary embedded inside a container layer: it goes through the same `scan_buffer_at_depth` path as ELF package notes, and the package-note and Go detections coexist on one file.
3. `toolchain go1.21.0-custom+auto`: it normalizes to `1.21.0`.
4. A module dep line with `+incompatible` (`v2.0.0+incompatible`): the version keeps `+incompatible`, as go.mod parsing does.
5. A varint length that claims more bytes than remain: `None`, no panic, and no allocation of the claimed size.

---

### Task 1: The Go version normalizer and go.mod stdlib packages

**Files:**
- Modify: `src-tauri/crates/oxaudit-parsers/src/go_inventory.rs`: add `osv_go_version`, keep the `toolchain` value (it is currently discarded at `:259-267`), and emit the two packages at the end of `parse`.
- Modify: `src-tauri/src/deps/service.rs`: surface the new inventory note.
- Test: `src-tauri/crates/oxaudit-parsers/src/lockfiles.rs` go tests (helpers `parse`), and `go_inventory.rs` inline tests.

**Interfaces:**
- Produces:
  - `pub fn osv_go_version(raw: &str) -> Option<String>`, consumed by Task 3.
  - `stdlib` and `toolchain` `Dependency` rows.

- [ ] **Step 1: Write the failing tests**
  - `go_versions_normalize_to_osv_form`: a table covering `1.21`→`1.21.0`, `1.21.3`, `go1.21.3`, `1.22rc1`→`1.22.0-rc.1`, `go1.22beta2`→`1.22.0-beta.2`, `go1.21.0-custom+auto`→`1.21.0`, and `default`, `go1`, `(devel)`, `devel go1.23-abc`, `1`, `x.y` → `None`.
  - `a_toolchain_directive_yields_stdlib_and_toolchain_packages`: `go 1.22` plus `toolchain go1.22.4` gives `("stdlib","1.22.4")` and `("toolchain","1.22.4")` alongside the requires.
  - `the_go_directive_alone_yields_no_stdlib_package`: `go 1.22` only gives no stdlib row, and the inventory notes contain the Design's note.
  - `toolchain_default_yields_nothing`
- [ ] **Step 2: Run** `cargo test --manifest-path src-tauri/Cargo.toml -p oxaudit-parsers go_`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to verify they pass.** Also run `cargo test … --lib deps::` (the existing `go_scan_excludes_history_and_persists_static_inventory_limits` may need its expected package count updated; if so, ledger it as a ruling).
- [ ] **Step 5: Commit** (after approval): `git commit -m "Report Go standard-library advisories from a go.mod toolchain"`

### Task 2: Go build-info parser

**Files:**
- Create: `src-tauri/crates/oxaudit-parsers/src/go_buildinfo.rs`, exported from the crate's `lib.rs`.
- Modify: `src-tauri/fuzz/fuzz_targets/package_metadata.rs`: also call `go_buildinfo::read`. Add seed `src-tauri/fuzz/seeds/package_metadata/go-buildinfo`.

**Interfaces:**
- Produces:
  - `pub fn read(bytes: &[u8]) -> Result<Option<GoBuildInfo>, &'static str>`: `Ok(None)` when there is no magic, and `Err(reason)` for the pre-1.18 form or a malformed blob.
  - `pub struct GoBuildInfo { pub go_version: String, pub main: Option<(String, String)>, pub deps: Vec<(String, String)>, pub truncated: bool }`

- [ ] **Step 1: Write the failing tests** with a test builder `fn blob(version: &str, modinfo: &str) -> Vec<u8>` that writes the header, the varints and the sentinels, padded inside random-looking bytes.
  - `reads_the_go_version_and_modules`: main, two deps, and a `=>` replacement that replaces the second dep's path and version.
  - `devel_versions_are_skipped`
  - `pre_1_18_pointer_format_is_a_reason_not_a_guess`: flags `0`.
  - `oversized_varints_and_truncated_blobs_are_rejected` (Review Focus 5).
  - `only_the_first_magic_counts`
  - `incompatible_suffixes_are_kept` (Review Focus 4).
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to verify they pass.** Run `cargo +nightly fuzz build package_metadata` if nightly is present; otherwise ledger that it was not built.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Parse Go build info from binaries"`

### Task 3: binscan detections from Go binaries

**Files:**
- Modify: `src-tauri/src/binscan/native/scan.rs`:
  - add `DetectionSource::GoBuildInfo`;
  - in `scan_buffer_at_depth`, beside the ELF package-note block (`:419-443`), call `go_buildinfo::read` for `Format::{Elf, MachO, Pe}`;
  - push the detections and the pre-1.18 count note.
- Modify: `src-tauri/src/binscan/native/enrich.rs`, only if `osv_dependency_for` needs the `Go` case. It should not, since ecosystem and name flow through.
- Modify: `docs/binary-scanning-runtime.md`, `README.md` (the binary scanning row) and `CHANGELOG.md`.
- Test: inline in `scan.rs` (`:1270+` style) and `src-tauri/tests/cli_end_to_end.rs`.

- [ ] **Step 1: Write the failing tests**
  - `go_binaries_yield_stdlib_and_module_detections`: an ELF built by the existing `elf_with_note`-style builder, with Task 2's `blob` placed in a section. The detections include `stdlib@1.22.4` and `golang.org/x/net@0.17.0`, all with ecosystem `Go`.
  - `a_go_binary_inside_an_image_layer_is_detected` (Review Focus 2, using `tar_with`).
  - End-to-end `image_scans_answer_go_stdlib_offline`: an image tar holding that ELF, plus an offline dump containing a `Go`/`stdlib` advisory `GO-2099-0001` fixed in `1.22.5`. Expect the finding to be reported, and a `--fail-on high` exit of 1.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full workspace tests. Expected: all pass.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Detect Go standard library and modules in compiled binaries"`

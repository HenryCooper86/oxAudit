# OS Package Names and RPM Databases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- First, fix a missed-advisory bug that ships today. Debian, Ubuntu and Alpine image packages are looked up by binary package name, but OSV files those advisories under the source package. A `libc6` or `libssl3` vulnerability is therefore reported clean.
- Then read RPM package databases in images (RHEL/UBI, Rocky, Alma, openSUSE/SLES, Azure Linux, openEuler) with the same source-versus-binary care.

**Architecture:**
- The dpkg and apk parsers return a package struct that carries the source name and version. `Detection` carries the name OSV expects for that distro.
- `parse_os_release` gains RPM distros. Each distro also declares which name its OSV records use.
- RPM headers are decoded by a new pure parser in `oxaudit-parsers`, which is fuzzed.
- `rpmdb.sqlite` is opened in memory through rusqlite's `serialize` feature in `src-tauri`, never written to disk. Berkeley DB `Packages` (RHEL 7/8, Amazon Linux 2, Rocky/Alma 8) is read by a new pure-Rust hash-page reader.

**Tech Stack:** Rust, rusqlite 0.40 (`bundled` + `serialize`), `oxaudit-parsers`, cargo-fuzz.

**Spec:** No separate spec. This plan's Design section is the design (group D, 2026-11-02).

## Design

Naming, checked against live OSV on 2026-11-02:

| Distro | os-release `ID` | OSV ecosystem(s) | Name OSV uses |
|---|---|---|---|
| Debian | `debian` | `Debian:N` (existing) | source: `glibc` (48 hits), not `libc6` (0) |
| Ubuntu | `ubuntu` | `Ubuntu:YY.MM[:LTS]` (existing) | source: `openssl` (96), not `libssl3` (0) |
| Alpine | `alpine` | `Alpine:vX.Y` (existing) | origin: `openssl` (19), not `libcrypto3` (0) |
| Red Hat / UBI | `rhel` | `Red Hat:enterprise_linux:N::baseos` and `…::appstream` | binary: `openssl-libs` (17) |
| AlmaLinux | `almalinux` | `AlmaLinux:N` | binary: `openssl-libs` (17) |
| Rocky Linux | `rocky` | `Rocky Linux:N` | source: `openssl` (12), not `openssl-libs` (0) |
| openSUSE Leap | `opensuse-leap` | `openSUSE:Leap X.Y` | source: `openssl-3` (14), not `libopenssl3` (0) |
| SLES | `sles` | `SUSE:Linux Enterprise Server X SPn` | source, assumed from openSUSE. **Verify in Task 3 Step 1**; if it can't be confirmed, keep SLES Unsupported. |
| Azure Linux | `azurelinux` | `Azure Linux:N` | source: `openssl` (55), not `openssl-libs` (0) |
| openEuler | `openEuler` | `openEuler:X.Y-LTS[-SPn]` | source: `openssl` (8) |
| Fedora, Amazon Linux, Oracle, CentOS, Photon, Mariner | — | not in OSV's `ecosystems.txt` | stay Unsupported, with the existing note |

- **Version passed to OSV.** dpkg uses the source version from `Source: name (version)` when given, and otherwise the binary version. apk uses the package version. RPM uses `[epoch:]version-release` with the epoch only when set.
- **Which name is queried.** Per-distro naming picks the source or binary name. A missing source name falls back to the binary name. Components are still shown by binary name; the query name appears in evidence.
- **Query de-duplication.** Queries are keyed on `(ecosystem, query name, query version)`, so `libssl3` and `libcrypto3` share one `openssl` query. Results attach to every component that produced the key.
- **RHEL** queries both streams and merges by advisory id. Local-database coverage needs both streams downloaded; otherwise the existing incomplete-coverage error names them.
- **RPM database locations** (real paths, because the extractor skips symlinks):
  - `var/lib/rpm/rpmdb.sqlite`
  - `usr/lib/sysimage/rpm/rpmdb.sqlite`
  - `var/lib/rpm/Packages` (Berkeley DB hash)
- **Package filters.** `gpg-pubkey` pseudo-packages are skipped. The 10,000-package cap and its note apply as for dpkg.
- **SQLite safety.**
  - The member's bytes go to `Connection::deserialize` read-only, in memory.
  - Defensive settings are on: `SQLITE_DBCONFIG_DEFENSIVE` and `PRAGMA trusted_schema=OFF`.
  - One fixed query runs: `SELECT blob FROM Packages`.
  - Any SQLite error becomes the note `rpm database at <path> could not be read: <error>`.
  - If a non-empty `rpmdb.sqlite-wal` member sits beside the database, the scan adds the note `rpm database has an uncheckpointed write-ahead log; the newest package changes may be missing`.

**Non-goals (deferred):**
- SUSE's NDB `Packages.db` and Azure Linux distroless `container-manifest-2`.
- Applying layer whiteouts. Every layer's database is still read, so a package upgraded in a later layer can show both versions. This is a known false-positive source that already affects dpkg; it is out of scope here and should get its own plan.
- ELF package-note mappings for RPM distros.

## Global Constraints

- No AI attribution in commits or PRs. Commit only after the user approves, on a branch.
- The extractor's "in memory, never on disk" rule holds, so no temp files are written for databases.
- Parsers return an empty result plus a note on malformed input and never panic. Offsets use checked arithmetic. Fuzz targets cover every new byte parser.
- SQLite stays out of `oxaudit-parsers`, which keeps C code out of the sanitizer fuzz build. Only the header-blob and BDB decoders live there.
- Existing Debian, Ubuntu and Alpine results change only by finding more advisories. The component list is unchanged.

## Review Focus

1. A dpkg `Source:` line carrying a version (`Source: glibc (2.36-9+deb12u4)`) while the binary version differs because of a binNMU (`2.36-9+deb12u4+b1`): query `glibc` at `2.36-9+deb12u4`.
2. Two binaries from one source at the same version: one OSV query, and both components get the findings.
3. An RPM header whose index claims more entries or data than the blob holds, or a string tag that isn't NUL-terminated: skip the package and count it in a note.
4. A RHEL image scanned offline with only `::baseos` downloaded: incomplete coverage naming `::appstream`, never a clean result.
5. A BDB `Packages` file with overflow-page chains that loop or point past the end of the file: stop and add a note, with no hang and no panic.

---

### Task 1: Query Debian, Ubuntu and Alpine packages by source name (bug fix)

**Files:**
- Modify: `src-tauri/crates/oxaudit-parsers/src/os_packages.rs`:
  - `parse_dpkg_status` and `parse_apk_installed` return `Vec<OsPackage>`.
  - `pub struct OsPackage { pub name: String, pub version: String, pub source_name: Option<String>, pub source_version: Option<String> }`
  - dpkg reads `Source:`; apk reads `o:`.
- Modify: `src-tauri/src/binscan/native/scan.rs`: `Detection` gains `query_name: Option<String>` and `query_version: Option<String>`, filled per distro naming.
- Modify: `src-tauri/src/binscan/native/enrich.rs`: `queries_from` keys on `(ecosystem, query name, query version)`; `osv_dependency_for` uses the query name and version; results fan back out to every component with that key.
- Modify: `src-tauri/fuzz/fuzz_targets/package_metadata.rs` (the signature changed).
- Modify: `src-tauri/tests/cli_end_to_end.rs`: the `debian_image_tar` fixture's stanza gains `Source: glibc`, and `debian_dump_zip`'s record names `glibc`.

**Interfaces:**
- Produces:
  - `OsPackage`
  - `pub enum PackageNaming { Source, Binary }`
  - `DistroIdentity` gains `naming: PackageNaming`.

- [ ] **Step 1: Write the failing tests**
  - `os_packages.rs`: `dpkg_status_reads_source_names_and_versions` (covers `Source: glibc (2.36-9+deb12u4)`, `Source: openssl`, and no `Source` line).
  - `os_packages.rs`: `apk_installed_reads_origins`
  - `scan.rs`: `debian_packages_are_queried_by_source_name`. Update `package_databases_inside_an_image_are_matched_to_their_distribution` so `osv_name == "glibc"` while the product stays `libc6`.
  - `enrich.rs`: `binaries_from_one_source_share_one_query_and_both_get_findings` (Review Focus 2).
  - End-to-end: rename and extend `image_scans_answer_distro_packages_offline_from_the_advisory_database`. The dump record is keyed `glibc`, the image has `libc6` with `Source: glibc`, and the finding is reported on `libc6`. **Before changing the fixture, run the test with the dump keyed `glibc` and the old code to watch it fail.** That is the bug reproduction.
- [ ] **Step 2: Run them to verify they fail** (`cargo test --manifest-path src-tauri/Cargo.toml -p oxaudit-parsers os_packages` and `--test cli_end_to_end image_scans`).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full workspace tests. Expected: all pass.
- [ ] **Step 5: Commit** (after approval): `git commit -m "Query Debian, Ubuntu and Alpine image packages by source name"`

### Task 2: RPM header-blob decoder

**Files:**
- Create: `src-tauri/crates/oxaudit-parsers/src/rpm_header.rs`
  - `pub struct RpmPackage { pub name, pub epoch: Option<u32>, pub version, pub release, pub arch: Option<String>, pub source_rpm: Option<String> }`
  - `pub fn parse_header_blob(blob: &[u8]) -> Result<RpmPackage, &'static str>`
  - `impl RpmPackage { pub fn evr(&self) -> String; pub fn source_name(&self) -> Option<String> }`
- Modify: the `package_metadata` fuzz target and a seed.

The blob layout is big-endian: `il: u32`, `dl: u32`, then `il` × 16-byte index entries (`tag`, `type`, `offset`, `count`), then `dl` data bytes. The tags used are:
- NAME 1000, VERSION 1001, RELEASE 1002 (STRING, type 6)
- EPOCH 1003 (INT32, type 4)
- ARCH 1022
- SOURCERPM 1044

Caps: `il` ≤ 4096 and `dl` ≤ 16 MiB. `source_name` strips `.src.rpm` / `.nosrc.rpm` and then the last two `-` segments (`openssl-3.0.7-27.el9.src.rpm` gives `openssl`).

- [ ] **Step 1: Write the failing tests** with a builder `fn header(tags: &[(u32, Value)]) -> Vec<u8>`:
  - `decodes_name_epoch_version_release_and_source`
  - `evr_omits_a_missing_epoch` (`3.0.7-27.el9` versus `1:3.0.7-27.el9`)
  - `source_names_strip_version_release_and_suffix`
  - `malformed_headers_are_errors_not_panics` (Review Focus 3: the index runs past the blob, an offset is out of data, a string has no NUL, `il` is huge)
- [ ] **Step 2: Run** them to verify they fail, implement, and run them to verify they pass.
- [ ] **Step 3: Commit** (after approval): `git commit -m "Decode RPM package headers"`

### Task 3: RPM distros in os-release, and `rpmdb.sqlite` in images

**Files:**
- Modify: `src-tauri/Cargo.toml`: rusqlite `features = ["bundled", "serialize"]`.
- Modify: `os_packages.rs`:
  - `parse_os_release` gains the RPM arms from the Design table. RHEL produces two ecosystems, so `DistroIdentity.osv_ecosystems: Vec<String>` replaces `osv_ecosystem`; update the callers.
  - Add `"var/lib/rpm/rpmdb.sqlite"` and `"usr/lib/sysimage/rpm/rpmdb.sqlite"` to the recognized suffixes.
- Create: `src-tauri/src/binscan/native/rpmdb.rs`: `pub fn read_sqlite(bytes: &[u8]) -> Result<Vec<RpmPackage>, String>`.
- Modify: `scan.rs` `scan_member`: route rpmdb members, track a sibling `-wal`, and emit detections (`gpg-pubkey` skipped).
- Modify: `src-tauri/src/binscan/native/os_packages.rs:20-36` test: every new ecosystem passes `versioning::family_for`.
- Modify: `enrich.rs`: expand multi-ecosystem identities into one query per ecosystem and merge results by advisory id.

- [ ] **Step 1: Verify SLES naming against OSV.** Run `curl -s https://api.osv.dev/v1/query -d '{"package":{"ecosystem":"SUSE:Linux Enterprise Server 15 SP5","name":"openssl-3"},"version":"3.0.8-150500.1.1"}'` and try `glibc` as well. If neither returns advisories, try `curl https://api.osv.dev/v1/vulns/SUSE-SU-2023:2620-1` and read its `affected[].package.ecosystem` spelling. Ledger the result as a ruling, and keep `sles` Unsupported if the spelling can't be confirmed.
- [ ] **Step 2: Write the failing tests**
  - `os_packages.rs`: `rpm_distros_map_to_their_osv_ecosystems_and_naming`. A table with one os-release per row; RHEL `VERSION_ID=9.4` gives both streams with Binary naming; Rocky `9.4` gives `Rocky Linux:9` with Source naming; openEuler `VERSION_ID="22.03"` with `VERSION="22.03 (LTS-SP4)"` gives `openEuler:22.03-LTS-SP4`; Fedora stays Unsupported.
  - `rpmdb.rs`: `reads_packages_from_an_in_memory_rpmdb_sqlite`. The test builds the database with rusqlite in memory, creates `Packages(hnum INTEGER PRIMARY KEY, blob BLOB)`, inserts Task 2 headers, and calls `serialize` to get bytes.
  - `rpmdb.rs`: `a_corrupt_sqlite_file_is_a_note_not_a_failure`
  - `scan.rs`: `rocky_images_are_queried_by_source_rpm_name` and `rhel_images_query_both_streams_by_binary_name`
  - `scan.rs`: `an_uncheckpointed_wal_is_noted`
  - End-to-end: `image_scans_answer_rpm_packages_offline`. A Rocky 9 image tar holding `etc/os-release` and `var/lib/rpm/rpmdb.sqlite` with `openssl-libs` from `openssl-3.0.1-1.el9.src.rpm`, and an offline dump for `Rocky Linux:9` with a record on `openssl` fixed in `1:3.0.7-16.el9_2`. Expect the finding to be reported on `openssl-libs`.
  - End-to-end: `a_rhel_image_with_one_stream_downloaded_is_incomplete_coverage` (Review Focus 4).
- [ ] **Step 3: Run** them to verify they fail, implement, and run the full workspace tests. Expected: all pass.
- [ ] **Step 4: Commit** (after approval): `git commit -m "Read rpmdb.sqlite package databases in RPM-based images"`

### Task 4: Berkeley DB `Packages` reader

**Files:**
- Create: `src-tauri/crates/oxaudit-parsers/src/bdb_hash.rs`: `pub fn values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str>` returns every hash-database value, reassembled from overflow chains.
- Modify: `os_packages.rs` suffixes (`var/lib/rpm/Packages`), `scan.rs` routing (`values` → `parse_header_blob`), and the fuzz target plus a seed.

Format notes for the implementer:
- Page 0 is the hash metadata page: magic `0x00061561` at byte 12 (its byte order gives the file's endianness), page size at byte 20, last page number at byte 32.
- Hash pages are page type 13 (`P_HASH`), or 2 in older versions. Items alternate key and value.
- A value item of type `H_OFFPAGE` (3) points at an overflow chain of `P_OVERFLOW` (7) pages, linked by next-page number with a per-page data length.
- Caps: page size between 512 and 65536 bytes, at most `file_len / page_size` page visits per chain, a visited-page set to stop loops, and a 16 MiB value cap.

- [ ] **Step 1: Write the failing tests** with a test-only writer `fn bdb(values: &[Vec<u8>], page_size: u32) -> Vec<u8>` that lays out a metadata page, one hash page and the overflow chains:
  - `reads_values_across_overflow_chains`
  - `big_and_little_endian_files_both_read`
  - `looping_or_out_of_range_chains_stop_with_an_error` (Review Focus 5)
  - `scan.rs`: `rhel8_style_bdb_package_databases_are_read`
- [ ] **Step 2: Run** them to verify they fail, implement, and run the workspace tests plus the fuzz build (if nightly is present).
- [ ] **Step 3: Commit** (after approval): `git commit -m "Read Berkeley DB rpm package databases"`

### Task 5: Docs

**Files:**
- `README.md:233` (the image-scanning scope: RPM databases, source-name matching).
- `docs/binary-scanning-runtime.md`: "Still open" gains NDB, the distroless manifest and layer whiteouts.
- `docs/advisory-database.md` "Image scans": add the RHEL two-stream download note (`--ecosystem 'Red Hat:enterprise_linux:9::baseos' --ecosystem 'Red Hat:enterprise_linux:9::appstream'`).
- `CHANGELOG.md` `[Unreleased]`: Fixed (source names) and Added (RPM).

- [ ] **Step 1:** Write the docs and run `node tools/check-versions.mjs`. Expected: OK.
- [ ] **Step 2: Commit** (after approval): `git commit -m "Document RPM image scanning and source-name matching"`

# Dependency Evidence Reliability Implementation Plan

> **For implementers:** Execute each task with a failing regression test, a focused fix, and a passing regression suite. Use the test-driven-development and verification-before-completion skills.

**Goal:** Correct the four remaining dependency evidence issues identified after commit `99c1c77`.

**Architecture:** Keep inventory and advisory decisions in the shared dependency service. Resolve npm edges by installation identity, distinguish authoritative declarations from checksum history, and reuse only validated offline receipts covering the requested coordinates.

**Tech Stack:** Rust, Tokio, rusqlite, serde_json, Tauri; existing standards reporting adapters.

**Spec:** `docs/dependency-scanning-reliability.md`, plus the four reproduced issues recorded in this plan.

## Global Constraints

- Preserve project confinement, ignore rules, cancellation, immutable receipts, and durable failed/cancelled runs.
- Keep the existing 16 MiB lockfile, 256 file, and 100,000 dependency limits.
- Do not execute project dependency code or invoke package managers to infer an inventory.
- A checksum, a constraint, or a local replacement cannot prove a registry package is installed.
- Keep changes reviewable in the working tree; commit and push when requested.

## Review Focus

- Identical npm installation paths in different lockfiles must not share a version lookup.
- Alias and workspace paths must resolve to the evidenced package identity.
- Go replacements and Ruby source/platform variants must not produce invented registry versions.
- Malformed mixed inventories and pending provider requests must fail or cancel through every entry point.
- An unrelated or corrupt newer offline receipt must not hide an older valid covering receipt.

### Task 1: Installation-aware canonical relationships

**Files:** `src-tauri/src/adapters/scanners/dependency.rs`, `src-tauri/src/deps/service_tests.rs`.

**Interface:** Preserve `dependency_graph`; index component ids by lockfile, ecosystem, package name and installation path.

- [x] Add a real npm inventory with root and nested `shared` versions and a second workspace with a third version; verify canonical and CycloneDX edges.
- [x] Run `cargo test --manifest-path src-tauri/Cargo.toml --lib dependency_edges_resolve` and observe the incorrect version edges.
- [x] Replace first-name version lookup with installation identity lookup; omit unresolvable steps.
- [x] Run the focused test and `cargo test --manifest-path src-tauri/Cargo.toml --lib deps::service::tests`.

### Task 2: Authoritative Ruby and Go declarations

**Files:** `src-tauri/src/deps/lockfiles.rs`, new focused Go parser module and tests, `src-tauri/src/deps/service.rs`, `docs/dependency-scanning-reliability.md`.

**Interface:** Preserve `parse_lockfile`; enrich occurrence warnings where static evidence has limited scope.

- [x] Add Ruby tests for nested constraints, malformed specification rows, platform versions and non-registry sources. Add Go tests for historical sums, version-specific/global replacements, local replacements, malformed directives and valid empty requirements.
- [x] Run those regression tests and observe the current false inventories.
- [x] Parse Ruby specification indentation separately from constraints. Parse Go requirements/replacements, treat sums as checksum evidence, and expose static build-list uncertainty in scan notes.
- [x] Run the parser and dependency-service suites. Check that checksum history and replaced coordinates are absent from canonical components.

### Task 3: Shared research dependency workflow

**Files:** `src-tauri/src/agent/tools.rs`, focused dependency-tool helper and tests.

**Interface:** The production tool delegates to `deps::service::scan(ScanRequest)` and projects its durable result into the existing compact tool response.

- [x] Add tests that invoke the production helper with deterministic full-advisory, failing-detail and pending providers; include mixed malformed inventories and ignored roots.
- [x] Confirm the old entry point cannot satisfy these tests.
- [x] Wire findings storage, the tool cancellation flag, network providers and cache directory into the shared service. Preserve approved scope and tool approval metadata.
- [x] Run the tool tests and the shared dependency-service suite.

### Task 4: Coverage-aware offline receipt selection

**Files:** `src-tauri/src/findings/repository.rs`, `src-tauri/src/deps/service.rs`, `src-tauri/src/deps/service_tests.rs`.

**Interface:** Add a bounded newest-first candidate lookup scoped to provider and expected query keys. Retain hash, schema, record membership and identity validation before use.

- [x] Add alternating-project/version tests, covering receipt freshness tests and corrupt-candidate/missing-coverage tests.
- [x] Run the new tests and observe the global-latest selection failures.
- [x] Search covering candidates newest first, skip invalid candidates with explicit notes, and fail when no validated receipt covers the request.
- [x] Run the dependency-service and repository suites.

### Final verification

- [x] Review the full diff and the five review-focus conditions.
- [x] Run Rust workspace tests with all features, Clippy with warnings denied, and formatting checks.
- [x] Run frontend tests, type checks and build; run existing CI shell checks.
- [x] Document the final semantics, tests, and remaining static Go inventory limitation.


### Review and validation record

- The npm, Ruby/Go, research-tool and cache regressions failed for the reproduced behavior before their fixes.
- Independent review found local dot-path, empty-block, interpreted-string and malformed-version issues in the new Go parser. Regression tests now cover these cases; hex, octal and Unicode string escapes follow Go syntax.
- Follow-up CLI checks caught omitted inventory notes in text output and rejected baselines containing unversioned Go local replacements. Both are corrected; missing registry versions remain invalid baselines.
- Source filtering happens before query deduplication and again before attaching findings. Git/local gem components do not shadow equal registry coordinates or inherit their licenses or purls.
- Existing npm workspace queryability and merging of equal registry coordinates across installations remain established behavior. Source-specific Ruby/Go declarations retain occurrence evidence and uncertainty rather than changing that broader contract.
- Static Go declarations cannot prove the resolved transitive/workspace build list. This limitation remains visible in desktop, JSON, text and research-tool output.


Final verification: 1,283 Rust workspace tests passed with all features (one live OSV test ignored), 387 frontend tests passed, and all 10 CI shell checks passed, including the freshly built CLI under refusing proxies. Clippy with warnings denied, Rust formatting, whitespace checks, TypeScript checks and production frontend build passed. Actual offline CLI probes verified npm CycloneDX links, Ruby constraint exclusion, Go replacement/history handling, local Go baseline round-trips, visible text inventory notes, valid older cache selection, and a nonzero failure with no report when coverage is missing. These checks cover the implementation prepared for commit.

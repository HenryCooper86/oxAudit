# Advisory Suppression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a project dismiss specific dependency and container-image advisories (accepted risk, false positive, suppressed) from a committed file, so `deps` and `image` stop failing CI on them while still reporting them.

**Architecture:** A new committed file, `.oxaudit/advisory-policy.json`, holds advisory entries keyed by advisory id or alias, optionally narrowed by package, ecosystem and exact version. A pure matcher in `src-tauri/src/findings/advisory_policy.rs` attaches an `AdvisoryReview` to each matching `Vulnerability` (dependencies) and `BinaryVulnerability` (images) before the run projection is saved. Gating, text and JSON output, SARIF `suppressions` and the desktop pages all read that one field.

**Tech Stack:** Rust (serde, chrono), the existing hardened `.oxaudit/` loader in `findings/policy.rs`, React + TypeScript for two badges.

**Spec:** No separate spec. This plan's Design section is the design, approved in chat on 2026-11-02 when the user asked to plan group D and skip questions.

## Design

The file lives at `<project root>/.oxaudit/advisory-policy.json`:

```json
{
  "version": 1,
  "entries": [
    {
      "advisory": "GHSA-29mw-wpgm-hmr9",
      "package": "lodash",
      "ecosystem": "npm",
      "version": "4.17.20",
      "state": "acceptedRisk",
      "reason": "Build-time only; never shipped to users",
      "expiresAt": "2027-01-31T00:00:00Z"
    }
  ]
}
```

- `advisory` (required) matches the vulnerability's id or any alias, ignoring case. For images it matches `cve_id`.
- `package`, `ecosystem` and `version` are optional narrowers. When present, each must match:
  - `package` compares through `advisories::versioning::normalize_package(ecosystem, name)` when the subject has an ecosystem, and exactly otherwise. For images it compares against `BinaryComponent.product`.
  - `ecosystem` compares exactly, so `Debian:12` does not match `Debian`.
  - `version` compares exactly against the installed version.
- `state` is `falsePositive`, `acceptedRisk` or `suppressed`. `reason` is required and passes the same safe-text check as `policy.json`. `expiresAt` is RFC 3339; once past, the entry stops dismissing and the scan says so.
- The last matching unexpired entry wins, the same precedence as `policy.json` suppressions.
- **Why a separate file and not a new kind in `policy.json`:** `policy.json` has a closed schema, and an older oxAudit sees any unknown entry kind as an invalid policy and refuses to run source scans. A separate file keeps a pinned older CLI in CI working.
- **Loading:**
  - `deps` reads the file from the project root by default.
  - `--advisory-policy <FILE>` points `deps` or `image` at another file. `image` has no project root, so it reads a file only when this flag is given.
  - A missing file is not an error.
  - An invalid file stops the scan, with exit 3 and the reason, unless `--ignore-invalid-policy` is passed. In that case a note says the file was ignored.
- **Effect:** dismissed advisories are still reported everywhere, but they never count toward `--fail-on` or `--fail-on-new`.
  - Text output: marked `dismissed (acceptedRisk): <reason>`, plus a line `N dismissed by advisory policy (not gating)`.
  - JSON: carries `review`.
  - SARIF: dependency results carry `suppressions: [{kind: external, status: accepted, justification}]`.
  - Desktop: dependency and image pages show a "Dismissed by policy" badge with the reason.

**Non-goals:**
- Writing entries from the desktop app.
- Applying trusted VEX claims. ADR 0003 says claims suggest and never decide.
- Monitor gating.
- Image SARIF, which produces no results today.

## Global Constraints

- No AI attribution in commits or PRs (user rule).
- Commit only after the user approves committing; work on a branch, never on `main`.
- The file name is exactly `.oxaudit/advisory-policy.json`, `version` is exactly `1`, and the size cap is 1 MiB (same as `MAX_POLICY_BYTES`).
- Field names are camelCase. Unknown fields and duplicate JSON keys are rejected.
- New serialized fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`, so stored runs from 0.2.7 still load and unchanged output stays byte-identical.
- Exit codes are unchanged: 0 OK, 1 findings, 2 usage, 3 failure.
- Every new parser path returns an error and never panics on malformed input.

## Review Focus

1. An advisory whose id is a GHSA while the entry names the CVE alias, or the reverse: it must match through `aliases`. Mixed case must match too.
2. An expired entry: the advisory gates again, and a note says how many findings matched only expired entries. The scan does not fail. An unparseable `expiresAt` rejects the whole file at load time, the way `policy.json` does, so a typo can never become a silent dismissal.
3. A policy file that is a symlink, a directory, oversized, or has duplicate keys: refused the same way `policy.json` is.
4. `deps --fail-on-new` with a baseline: a dismissed new advisory does not gate, and an undismissed new advisory still does.
5. An entry narrowed by `version`, when the same advisory affects two installed versions: only the named version is dismissed.

---

### Task 1: Advisory policy model, loader and matcher

**Files:**
- Create: `src-tauri/src/findings/advisory_policy.rs` (tests inline in `#[cfg(test)] mod tests`)
- Modify: `src-tauri/src/findings/mod.rs` (add `pub mod advisory_policy;`)
- Modify: `src-tauri/src/findings/policy.rs` (make `safe_required_text`, `parse_json_without_duplicates`, `unix_fs::open_project_policy_dir` and `unix_fs::open_regular_at` `pub(crate)`; generalize the opener to take a file name if it hard-codes `policy.json`)

**Interfaces:**
- Produces:
  - `pub struct AdvisoryReview { pub state: ReviewState, pub reason: String, pub expires_at: Option<String> }`: serde camelCase, Serialize + Deserialize + Clone + Debug + PartialEq, with `ReviewState` from `findings::domain`.
  - `pub enum AdvisoryPolicyStatus { Missing, Loaded(AdvisoryPolicy), Invalid(String) }`
  - `pub fn load_project_advisory_policy(project_root: &Path) -> AdvisoryPolicyStatus`
  - `pub fn load_advisory_policy_file(path: &Path) -> AdvisoryPolicyStatus`
  - `pub struct AdvisorySubject<'a> { pub ids: Vec<&'a str>, pub ecosystem: Option<&'a str>, pub package: &'a str, pub version: &'a str }`
  - `impl AdvisoryPolicy { pub fn decide(&self, subject: &AdvisorySubject<'_>, now: DateTime<Utc>) -> Decision }`, where `pub enum Decision { Dismissed(AdvisoryReview), Expired, None }`.
  - `pub const ADVISORY_POLICY_PATH: &str = ".oxaudit/advisory-policy.json";`

- [ ] **Step 1: Write the failing tests**

All tests live in `advisory_policy.rs` and parse inline JSON through a test helper `policy(json: &str) -> AdvisoryPolicy` that panics on `Invalid`.
- `an_entry_matches_the_advisory_id_or_any_alias_ignoring_case`: the entry `"advisory": "cve-2024-1"` dismisses the subject `ids ["GHSA-aaaa-bbbb-cccc", "CVE-2024-1"]`.
- `narrowers_must_all_match`: an entry with `package lodash, version 4.17.20` dismisses `lodash@4.17.20`, but not `lodash@4.17.21` and not `underscore@4.17.20`.
- `npm_and_pypi_package_names_compare_normalized`: `"package": "Django_Rest"` with `ecosystem PyPI` dismisses the subject package `django-rest`.
- `the_last_matching_entry_wins`: two matching entries with different states; the second one's state is returned.
- `an_expired_entry_reports_expired_not_dismissed`: `expiresAt` in the past gives `Decision::Expired`. `expiresAt: "soon"` is rejected at load time as Invalid.
- `invalid_files_are_refused_with_a_reason`: each case gives `Invalid` with a non-empty message:
  - `version: 2`
  - an unknown field `"severity"`
  - a duplicate `"advisory"` key
  - an empty `reason`
  - a `reason` shaped like a URL
  - `state: "confirmed"`
  - an empty `advisory`
- `a_missing_file_is_missing_and_an_oversized_file_is_invalid`: use a tempdir. With no file the result is `Missing`. A file of 1 MiB + 1 byte is `Invalid`.
- `a_symlinked_policy_is_refused` (`#[cfg(unix)]`): `.oxaudit/advisory-policy.json` is a symlink to a valid file and the result is `Invalid`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib advisory_policy`
Expected: compile failure, because the module does not exist.

- [ ] **Step 3: Implement the module**

- Parse with `parse_json_without_duplicates`, then `serde_json::from_value` into structs marked `#[serde(deny_unknown_fields, rename_all = "camelCase")]`.
- Validate:
  - version is 1;
  - `advisory` matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`;
  - optional strings are non-empty and at most 256 bytes;
  - `reason` passes `safe_required_text`;
  - `expiresAt` parses with `DateTime::parse_from_rfc3339`.
- Open the file through the same hardened Unix path `load_policy` uses (no symlinks, regular file only, size checked before reading), and through `.oxaudit` join plus `symlink_metadata` on Windows.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib advisory_policy`
Expected: 8 passed.

- [ ] **Step 5: Commit** (after user approval): `git commit -m "Add the advisory policy file model and matcher"`

### Task 2: Apply the policy to dependency scans

**Files:**
- Modify: `src-tauri/src/models.rs` (`Vulnerability` gains `review: Option<AdvisoryReview>`)
- Modify: `src-tauri/src/deps/service.rs` (`ScanRequest` gains `advisory_policy: AdvisoryPolicySource<'a>` and `ignore_invalid_policy: bool`; apply the policy before `canonical_save_projection`)
- Modify: every `ScanRequest { … }` literal (find them with `grep -rn "ScanRequest {" src-tauri/src`), including the desktop and server command paths, which pass `AdvisoryPolicySource::Project` and `false`
- Test: `src-tauri/src/deps/service_tests.rs`

**Interfaces:**
- Consumes: Task 1's `load_project_advisory_policy`, `load_advisory_policy_file`, `AdvisoryPolicy::decide`, `AdvisorySubject`.
- Produces:
  - `pub enum AdvisoryPolicySource<'a> { Project, File(&'a Path) }` in `deps::service`.
  - `Vulnerability.review` is set for dismissed advisories.
  - `summary.advisory_notes` gains `"{n} advisory finding(s) dismissed by {path}"` and `"{n} advisory policy entr(y|ies) matched but expired; those advisories gate again"`.

- [ ] **Step 1: Write the failing tests** in `service_tests.rs`, following the existing fixture-provider style:
  - `project_advisory_policy_marks_matching_vulnerabilities_reviewed`: write `.oxaudit/advisory-policy.json` dismissing the fixture advisory by its alias. The resulting vulnerability has `review.state == AcceptedRisk`, and `advisory_notes` contains `"1 advisory finding(s) dismissed by .oxaudit/advisory-policy.json"`.
  - `an_invalid_advisory_policy_fails_the_scan_unless_ignored`: with `version: 2`, `scan` returns `Err` containing `advisory-policy.json`. With `ignore_invalid_policy: true` the scan succeeds, `review` is `None`, and a note contains `"ignored"`.
  - `an_explicit_policy_file_replaces_the_project_file`: `AdvisoryPolicySource::File(other)` applies `other` and not the project file.
  - `stored_runs_without_reviews_still_load`: deserialize a 0.2.7-shaped `Vulnerability` JSON with no `review` key, and confirm the serialized form omits `review`.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib advisory_policy` and then `... --lib deps::service`
Expected: compile errors on the new fields.

- [ ] **Step 3: Implement**

- After vulnerabilities are final and before the projection is saved, load the policy.
  - `Project` loads from `request.project_root`; `File` loads from the given path.
  - `Invalid` without the ignore flag returns `Err(format!("invalid {path}: {reason}; fix it or pass --ignore-invalid-policy"))`.
- For each vulnerability, decide with `AdvisorySubject { ids: [id] + aliases, ecosystem: Some(ecosystem), package: package_name, version: installed_version }` and `Utc::now()`.

- [ ] **Step 4: Run them to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib deps::`
Expected: all pass.

- [ ] **Step 5: Commit** (after approval): `git commit -m "Apply the advisory policy to dependency scans"`

### Task 3: Apply the policy to image scans

**Files:**
- Modify: `src-tauri/src/binscan/report.rs` (`BinaryVulnerability` gains `review: Option<AdvisoryReview>` with the same serde attributes)
- Modify: `src-tauri/src/commands/image.rs`:
  - `ImageScanRequest` gains `#[serde(default)] advisory_policy_path: Option<String>` and `#[serde(default)] ignore_invalid_policy: bool`.
  - Apply the policy after enrichment and before the projection save, and push notes into `ImageScanOutcome.notes`.
- Modify: every struct literal that builds `BinaryVulnerability` (grype, cve-bin-tool and native enrich): add `review: None`.
- Test: inline tests in `commands/image.rs`, or wherever existing image workflow tests live.

**Interfaces:**
- Consumes: Task 1's `load_advisory_policy_file` and `decide`.
- Produces: `BinaryVulnerability.review`, plus notes in the same wording as Task 2, naming the given path.

- [ ] **Step 1: Write the failing test**

Extract the step as `pub(crate) fn apply_advisory_policy(result: &mut BinaryScanResult, policy: &AdvisoryPolicy, now: DateTime<Utc>) -> (usize, usize)`, which returns the dismissed and expired counts, and test it directly. `image_advisory_policy_dismisses_by_cve_and_component`: a hand-built `BinaryScanResult` holds `libc6@2.36-9` with `CVE-2099-2222` and `curl@7.88.1` with the same CVE. A policy dismissing `CVE-2099-2222` for package `libc6` gives `libc6`'s vulnerability `review.state == AcceptedRisk`, leaves `curl`'s `review` as `None`, and returns `(1, 0)`. The full image workflow is covered end to end in Task 4.

- [ ] **Step 2: Run it to verify it fails**

Expected: compile error on `review`.

- [ ] **Step 3: Implement**

The subject is `ids: [cve_id]`, `ecosystem: None`, `package: component.product`, `version: component.version`. With no path, the scan does nothing.

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib image`
Expected: pass.

- [ ] **Step 5: Commit** (after approval): `git commit -m "Apply an advisory policy file to image scans"`

### Task 4: CLI flags, gating, text, JSON and SARIF

**Files:**
- Modify: `src-tauri/src/cli/mod.rs`:
  - `DepsArgs` and `ImageArgs` gain `--advisory-policy <FILE>` (`Option<PathBuf>`) and `--ignore-invalid-policy` (bool).
  - Wire them into the requests.
  - Filter `review.is_none()` in both `run_deps` gates and in the `run_image` gate.
  - `render_deps_text` and `render_image_text` mark dismissed rows and add the count line.
  - Add `advisory_policy: None, ignore_invalid_policy: false` to every existing `DepsArgs { … }` and `ImageArgs { … }` test literal.
- Modify: `src-tauri/src/adapters/reporting/dependencies.rs`: when `vulnerability.review` is `Some`, add `"suppressions": [{"kind":"external","status":"accepted","justification": reason}]` to that result.
- Test: `src-tauri/src/cli/mod.rs` tests and `src-tauri/tests/cli_end_to_end.rs`.

**Interfaces:**
- Consumes: Tasks 2 and 3. `AdvisoryPolicySource::File(path)` when the flag is set, `Project` otherwise.

- [ ] **Step 1: Write the failing tests**
  - `src-tauri/src/cli/mod.rs`: `deps_and_image_accept_advisory_policy_flags` (`Cli::try_parse_from` for both commands, including `--ignore-invalid-policy`).
  - `src-tauri/src/cli/mod.rs`: `dismissed_advisories_do_not_gate` (build two vulnerabilities, one critical and dismissed, one low; `--fail-on high` gives `EXIT_OK`, `--fail-on low` gives `EXIT_FINDINGS`). Extract the gating iterator into `fn gating_severities<'a>(v: impl Iterator<Item=&'a Vulnerability>) -> impl Iterator<Item=u8>` so it can be tested directly.
  - `src-tauri/tests/cli_end_to_end.rs`: `a_committed_advisory_policy_stops_a_dependency_gating_the_build`. Reuse the offline fixture from `advisory_database_supports_offline_dependency_matching` (`GHSA-e2e-fixture` on `example@1.0.0`), write a policy dismissing it, and check that `deps --offline --advisory-db … --fail-on low` exits 0, that stdout JSON's vulnerability has `review.state == "acceptedRisk"`, and that text output contains `dismissed by advisory policy`.
  - `src-tauri/tests/cli_end_to_end.rs`: `dependency_sarif_carries_advisory_policy_suppressions`. With `--format sarif`, the result for `GHSA-e2e-fixture` has `suppressions[0].status == "accepted"`.
  - `src-tauri/tests/cli_end_to_end.rs`: `an_image_advisory_policy_stops_the_image_gating`. Use the offline Debian image fixture with `--advisory-policy <file> --fail-on high`; it exits 0, and without the flag it exits 1.
  - `src-tauri/tests/cli_end_to_end.rs`: `an_invalid_advisory_policy_stops_the_dependency_scan`. It exits 3 and stderr contains `advisory-policy.json`. With `--ignore-invalid-policy` it exits 1 (the advisory gates).
  - `src-tauri/tests/cli_end_to_end.rs`: `a_dismissed_new_advisory_does_not_gate_fail_on_new` (Review Focus 4).

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test cli_end_to_end advisory_policy` and `... --lib cli::tests`
Expected: unknown-flag failures and compile errors.

- [ ] **Step 3: Implement** the flags, the wiring, the gating filter, the text markers and the SARIF suppressions.

- [ ] **Step 4: Run them to verify they pass**, then run the full workspace: `cargo test --manifest-path src-tauri/Cargo.toml --workspace`.

- [ ] **Step 5: Commit** (after approval): `git commit -m "Gate deps and image on undismissed advisories only"`

### Task 5: Desktop badges and docs

**Files:**
- Modify: `src/lib/types.ts` (`Vulnerability.review?: { state: 'falsePositive' | 'acceptedRisk' | 'suppressed'; reason: string; expiresAt?: string | null }`; the same on the image vulnerability type)
- Modify: the dependency results row component used by `src/pages/DepsScan.tsx`, and the image results row in the image page. Show a "Dismissed by policy" badge with the reason as its title text, using the existing badge component.
- Test: the component tests beside those components (`*.test.tsx`). Name: `shows a dismissed-by-policy badge with the reason`.
- Docs:
  - `README.md`, "Suppressing a finding": a new "Dependency and image advisories" subsection with the JSON example, matching rules, flags, and the reason for a separate file.
  - `docs/cli.md`: the two flags on `deps` and `image`.
  - `CHANGELOG.md` `[Unreleased]` → Added.

- [ ] **Step 1: Write the failing component test**, then run `npm test -- <file>`. Expected: FAIL (no badge).
- [ ] **Step 2: Implement the badge**, then run `npm test`, `npm run lint` and `npm run check`. Expected: all pass.
- [ ] **Step 3: Write the docs**, then run `node tools/check-versions.mjs`. Expected: OK.
- [ ] **Step 4: Commit** (after approval): `git commit -m "Show policy-dismissed advisories in the app and document the file"`

# oxAudit Durable Scan Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a sanitized, durable Rust foundation for Source Scan history, finding identity, scope, comparison, review, policy, and recovery while keeping the current Source Scan UI functional.

**Architecture:** Keep scanning and persistence in Rust. Scanner output is sanitized before it can become a serializable model, then a findings service fingerprints and classifies every candidate, applies policy, records coverage, and commits a completed run through a SQLite repository. Tauri commands expose typed DTOs; the current React page may ignore newly added fields until the workflow plan consumes them.

**Tech Stack:** Rust 2021, Tauri 2.11, rayon, serde/serde_json, sha2 0.10, uuid 1, chrono 0.4, ignore 0.4, rusqlite 0.40.2 with bundled SQLite.

**Spec:** docs/superpowers/specs/2026-08-20-oxaudit-durable-findings-settings-design.md

## Global Constraints

- SQLite is the local source of truth for projects, scan runs, observations, and local reviews.
- The optional repository source of truth is .oxaudit/policy.json; never write it without an explicit project-policy action.
- Retain every scanner candidate. Scope changes the default view, never candidate existence.
- Use a versioned SHA-256 fingerprint over scanner family, rule ID, normalized project-relative path, and redacted normalized context; never use line or column.
- A completed run may resolve a prior finding only when fingerprint version, scanner family, and file coverage are compatible.
- Raw detected secrets must never enter a serializable DTO, SQLite, JSON, logs, policy, sessions, frontend payloads, or AI prompts.
- Incomplete runs never become baselines and never resolve prior findings.
- The current independent-tool workbench and existing Dependency, CVE, Binary, and Assistant behavior remain usable.
- Use owner-only permissions for the database directory and database on Unix.
- Do not rename the package, crate, bundle identifier, or persisted browser keys in this plan; that belongs to the identity-migration plan.
- The existing untracked artifacts/ directory is user-visible audit material and must not be staged by any task.
- Before every commit, inspect git status and the staged diff, then stage only paths named by the current task. Directory-wide staging is allowed only after proving the directory contains no unrelated user changes.

## Repository Baseline

- npm test: 62 passing.
- npm run check: passing.
- cargo test --manifest-path src-tauri/Cargo.toml: 282 passing, 2 failing, 1 ignored.
- The two failures are tests::fixture_scan_finds_secrets_and_vulnerabilities and tests::fixture_lockfile_parses because both assume /tmp/vc_fixture exists.
- cargo fmt --check currently reports pre-existing formatting differences.
- strict cargo clippy currently reports pre-existing warnings; Task 1 records and normalizes the touched baseline before feature work.

## File Structure

### New Rust feature files

- src-tauri/src/findings/mod.rs — public module boundary and re-exports.
- src-tauri/src/findings/domain.rs — durable enums, request/response DTOs, and review models.
- src-tauri/src/findings/error.rs — serializable error codes and safe messages.
- src-tauri/src/findings/redaction.rs — secret replacement and sanitized-evidence construction.
- src-tauri/src/findings/fingerprint.rs — versioned canonical fingerprint and duplicate suffix assignment.
- src-tauri/src/findings/coverage.rs — per-path scanner coverage and compatible-baseline rules.
- src-tauri/src/findings/repository.rs — SQLite schema, migrations, transactions, queries, retention, and recovery.
- src-tauri/src/findings/policy.rs — policy parsing, validation, matching, hashing, and atomic replacement.
- src-tauri/src/findings/review.rs — review-state validation and gate integration.
- src-tauri/src/findings/service.rs — scan orchestration and persistence retry.

### Existing Rust files modified

- src-tauri/Cargo.toml and src-tauri/Cargo.lock — bundled rusqlite dependency.
- src-tauri/src/lib.rs — module registration, database startup, recovery, commands, and fixture baseline.
- src-tauri/src/models.rs — safe Source Scan response fields and serde defaults.
- src-tauri/src/scanners/mod.rs — sanitized file outcome instead of a raw vector.
- src-tauri/src/scanners/secrets.rs — keep raw value private to the scanner hit and remove dead-code suppression.
- src-tauri/src/triage/scope.rs — Fixture and Unknown scopes plus classification rationale.
- src-tauri/src/triage/manifest.rs — exact candidate-ID reconciliation.
- src-tauri/src/commands.rs — delegate Source Scan and finding commands to the service.
- src-tauri/src/agent/tools.rs — consume sanitized ScanFileOutcome.

---

### Task 1: Restore a trustworthy Rust baseline

**Files:**
- Modify: src-tauri/src/lib.rs:85-174
- Modify: src-tauri/src/sessions.rs:235-237
- Modify: Rust files reported by cargo fmt

**Interfaces:**
- Consumes: tempfile 3, existing scanner and lockfile parser.
- Produces: self-contained fixture tests and a formatted baseline; no production behavior change.

- [ ] **Step 1: Replace the external fixture with a TempDir builder**

Add this helper inside src-tauri/src/lib.rs test module:

~~~rust
fn source_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let files = [
        ("app.js", "eval(userInput);\nconst token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';\n"),
        ("shell.js", "exec('ls ' + userInput);\n"),
        ("query.js", "db.query('SELECT * FROM users WHERE id=' + id);\n"),
        ("worker.py", "eval(payload)\npickle.loads(blob)\nos.system(command)\n"),
        ("query.py", "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"),
    ];
    for (name, content) in files {
        std::fs::write(dir.path().join(name), content).expect("write source fixture");
    }
    dir
}
~~~

Change fixture_scan_finds_secrets_and_vulnerabilities to use source_fixture().path(), assert only rules represented by those files, and keep the relative-path and 1-based-line assertions.

- [ ] **Step 2: Build the lockfile fixture in its own TempDir**

Use this exact minimum lockfile:

~~~rust
let dir = tempfile::tempdir().expect("lockfile tempdir");
let path = dir.path().join("package-lock.json");
std::fs::write(
    &path,
    r#"{
      "name": "fixture",
      "lockfileVersion": 2,
      "packages": {
        "": {"name": "fixture"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/express": {"version": "4.18.2"}
      }
    }"#,
)
.expect("write package lock");
let deps = crate::deps::lockfiles::parse_lockfile(&path, "npm").expect("parse lockfile");
~~~

Keep the lodash name, version, and ecosystem assertions.

- [ ] **Step 3: Remove the unused public session helper**

Delete src-tauri/src/sessions.rs transcript_path. SessionStore::new remains the only path constructor.

- [ ] **Step 4: Format the Rust workspace**

Run:

~~~bash
cargo fmt --manifest-path src-tauri/Cargo.toml
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
~~~

Expected: the check exits 0. Review the mechanical formatting diff and confirm it contains no semantic edits.

- [ ] **Step 5: Verify the repaired baseline**

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml --lib --quiet
~~~

Expected: 284 passed, 0 failed, 1 ignored, subject only to additional tests concurrently added to main.

- [ ] **Step 6: Commit the baseline**

~~~bash
git add src-tauri/src
git commit -m "test: make Rust fixtures self-contained"
~~~

Before committing, run git diff --cached --name-only and verify artifacts/ is absent.

---

### Task 2: Define durable finding types and typed errors

**Files:**
- Create: src-tauri/src/findings/mod.rs
- Create: src-tauri/src/findings/domain.rs
- Create: src-tauri/src/findings/error.rs
- Modify: src-tauri/src/lib.rs:1-16
- Modify: src-tauri/src/models.rs:35-101

**Interfaces:**
- Consumes: existing Finding, ScanSummary, ScanOptions, and triage gate DTOs.
- Produces: FindingScope, ReviewState, DiffStatus, RunStatus, PolicyStatus, ScanRunDetail, ScanRunSummary, ReviewRequest, ProjectContext, RecentProject, and CommandError.

- [ ] **Step 1: Write serialization tests for the public contract**

In findings/domain.rs, start with tests that serialize enum values exactly:

~~~rust
#[test]
fn public_enums_use_stable_camel_case_values() {
    assert_eq!(serde_json::to_string(&FindingScope::Infrastructure).unwrap(), "\"infrastructure\"");
    assert_eq!(serde_json::to_string(&ReviewState::FalsePositive).unwrap(), "\"falsePositive\"");
    assert_eq!(serde_json::to_string(&DiffStatus::NotEvaluated).unwrap(), "\"notEvaluated\"");
    assert_eq!(serde_json::to_string(&RunStatus::Incomplete).unwrap(), "\"incomplete\"");
    assert_eq!(
        serde_json::to_value(RunPersistence::NotSaved { retry_token: "retry-1".into() }).unwrap(),
        serde_json::json!({"status": "notSaved", "retryToken": "retry-1"}),
    );
}
~~~

- [ ] **Step 2: Run the domain test and observe the compile failure**

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::domain::tests::public_enums_use_stable_camel_case_values
~~~

Expected: FAIL because the findings module and enum types are undefined.

- [ ] **Step 3: Add the durable enums and DTOs**

Define these exact public shapes:

~~~rust
pub const FINGERPRINT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FindingScope {
    Production,
    Infrastructure,
    Test,
    Fixture,
    Generated,
    Vendored,
    Documentation,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReviewState {
    Candidate,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Suppressed,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DiffStatus { New, Unchanged, Resolved, NotEvaluated }

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RunStatus { Running, Completed, Incomplete }

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReviewOrigin { Local, ProjectPolicy }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecord {
    pub id: String,
    pub project_id: String,
    pub fingerprint_version: u16,
    pub fingerprint: String,
    pub state: ReviewState,
    pub reason: String,
    pub evidence: Option<String>,
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gates: Vec<crate::triage::gates::GateNote>,
    pub deciding_gate: Option<crate::triage::gates::Gate>,
    pub expires_at: Option<String>,
    pub origin: ReviewOrigin,
    pub policy_hash: Option<String>,
    pub updated_at: String,
    pub superseded_at: Option<String>,
}
~~~

Also define ReviewOrigin { Local, ProjectPolicy }, PolicyStatus { Missing, Valid { hash }, Invalid { message } }, RunPersistence { Saved, NotSaved { retry_token } }, ScanRunDetail, ProjectContext, RecentProject, and ReviewRequest. Every struct uses camelCase serde.

Use tagged status objects for the two state-bearing responses:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PolicyStatus {
    Missing,
    Valid { hash: String },
    Invalid { message: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RunPersistence {
    Saved,
    NotSaved { retry_token: String },
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunDetail {
    pub project_id: String,
    pub run_id: String,
    pub baseline_run_id: Option<String>,
    pub status: RunStatus,
    pub persistence: RunPersistence,
    pub policy: PolicyStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub summary: crate::models::ScanSummary,
    pub findings: Vec<crate::models::Finding>,
    pub maintenance_warning: Option<String>,
}
~~~

Use these exact project and review interfaces:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectContext {
    pub project_id: String,
    pub canonical_path: String,
    pub display_name: String,
    pub policy: PolicyStatus,
    pub last_completed_run_id: Option<String>,
    pub last_options: Option<crate::models::ScanOptions>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecentProject {
    pub project_id: String,
    pub canonical_path: String,
    pub display_name: String,
    pub last_opened_at: String,
    pub last_completed_run_id: Option<String>,
    pub last_completed_at: Option<String>,
    pub open_findings: usize,
    pub critical: usize,
    pub high: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunSummary {
    pub run_id: String,
    pub project_id: String,
    pub status: RunStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_findings: usize,
    pub new_findings: usize,
    pub resolved_findings: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRequest {
    pub project_id: String,
    pub fingerprint_version: u16,
    pub fingerprint: String,
    pub category: String,
    pub state: ReviewState,
    pub reason: String,
    pub evidence: Option<String>,
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gates: Vec<crate::triage::gates::GateNote>,
    pub deciding_gate: Option<crate::triage::gates::Gate>,
    pub expires_at: Option<String>,
    pub origin: ReviewOrigin,
}
~~~

- [ ] **Step 4: Add a serializable command error**

Use this contract in findings/error.rs:

~~~rust
#[derive(Serialize, Clone, Debug, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{message}")]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidTarget,
    ScanCancelled,
    ScanFailed,
    ScanAlreadyRunning,
    PersistenceUnavailable,
    PolicyInvalid,
    PolicyWriteFailed,
    ReviewInvalid,
    NotFound,
    CredentialUnavailable,
    CredentialRollbackFailed,
    MigrationFailed,
    DataOperationFailed,
}
~~~

Add constructors that keep source paths, SQL text, evidence, and credential-like values out of message. detail may contain a sanitized local diagnostic.

- [ ] **Step 5: Extend the existing response without breaking current React**

Add serde-defaulted fields to models::Finding:

~~~rust
#[serde(default)]
pub observation_run_id: String,
#[serde(default)]
pub resolved_by_run_id: Option<String>,
#[serde(default)]
pub fingerprint_version: u16,
#[serde(default)]
pub fingerprint: String,
#[serde(default)]
pub scope: Option<crate::findings::domain::FindingScope>,
#[serde(default)]
pub scope_reason: Option<String>,
#[serde(default)]
pub review: Option<crate::findings::domain::ReviewRecord>,
#[serde(default)]
pub review_history: Vec<crate::findings::domain::ReviewRecord>,
#[serde(default)]
pub diff_status: Option<crate::findings::domain::DiffStatus>,
~~~

Keep ScanResult as the scanner-internal compatibility payload. ScanRunDetail preserves the same top-level summary and findings fields, then adds durable run metadata, so the current React conversion is mechanical rather than a nested-response rewrite.

- [ ] **Step 6: Verify and commit the contract**

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::domain
cargo check --manifest-path src-tauri/Cargo.toml
~~~

Expected: both commands pass.

~~~bash
git add src-tauri/src/findings src-tauri/src/lib.rs src-tauri/src/models.rs
git commit -m "feat(scan): define durable finding contract"
~~~

---

### Task 3: Redact secrets and assign stable fingerprints

**Files:**
- Create: src-tauri/src/findings/redaction.rs
- Create: src-tauri/src/findings/fingerprint.rs
- Modify: src-tauri/src/scanners/mod.rs:35-124
- Modify: src-tauri/src/scanners/secrets.rs:441-500
- Modify: src-tauri/src/models.rs:55-91
- Modify: src-tauri/src/agent/tools.rs:169-225

**Interfaces:**
- Consumes: Finding, SecretHit.secret_value, project-relative path.
- Produces: redact_exact(text, secret), fingerprint_base(finding), assign_fingerprints(findings), and ScanFileOutcome.

- [ ] **Step 1: Write tests that use a distinctive canary secret**

Add tests covering every boundary:

~~~rust
const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";

#[test]
fn redaction_removes_the_exact_secret_from_match_and_context() {
    let source = format!("const token = \"{CANARY}\";\nuse(token);");
    let safe = redact_exact(&source, CANARY);
    assert!(!safe.contains(CANARY));
    assert_eq!(safe, "const token = \"[REDACTED]\";\nuse(token);");
}

#[test]
fn fingerprint_survives_line_insertion_and_never_contains_secret_material() {
    let first = finding("src/auth.ts", 4, "const token = \"[REDACTED]\";");
    let shifted = finding("src/auth.ts", 40, "  const   token = \"[REDACTED]\"; ");
    assert_eq!(fingerprint_base(&first), fingerprint_base(&shifted));
    assert!(!fingerprint_base(&first).contains(CANARY));
}
~~~

Add path-separator, line-ending, different-rule, different-path, and duplicate-occurrence tests.

Add a scanner test with 30 matches for the same rule in one file and assert all 30 survive. The durable pipeline must not inherit the current MAX_MATCHES_PER_RULE silent truncation.

- [ ] **Step 2: Run the tests and observe undefined functions**

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::redaction findings::fingerprint
~~~

Expected: FAIL because the modules and functions are undefined.

- [ ] **Step 3: Redact inside the scanner before Finding construction**

Implement:

~~~rust
pub fn redact_exact(text: &str, value: &str) -> String {
    if value.is_empty() {
        return text.to_owned();
    }
    text.replace(value, "[REDACTED]")
}
~~~

For a SecretHit, compute context once, replace secret_value in match_text and context, and only then construct Finding. Remove secret_value from any derived Debug/Serialize type. SecretHit stays private to scanners::secrets and is dropped at the end of the loop.

Remove MAX_MATCHES_PER_RULE and the per-rule counts map from scanners/mod.rs. Keep all regex matches in deterministic rule/source order; noise belongs in result views or explicit policy, not silent scanner deletion.

- [ ] **Step 4: Return scan coverage explicitly**

Change the scanner signature to:

~~~rust
pub struct ScanFileOutcome {
    pub findings: Vec<Finding>,
    pub covered_families: Vec<String>,
}

pub fn scan_file_with_relative_path(
    path: &Path,
    relative_path: &str,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
) -> ScanFileOutcome;
~~~

If the file is unreadable, binary, or over the size limit, return no findings and an empty covered_families vector. Add secret when a text file was read and secret scanning was enabled. Add vulnerability only when language detection supports the file and vulnerability scanning was enabled. Update agent/tools.rs to flat_map outcome.findings.

- [ ] **Step 5: Implement versioned canonical fingerprints**

Use length-delimited canonical fields so concatenation cannot collide:

~~~rust
fn canonical_context(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

pub fn fingerprint_base(finding: &Finding) -> String {
    let fields = [
        FINGERPRINT_VERSION.to_string(),
        finding.category.clone(),
        finding.rule_id.clone(),
        finding.file_path.replace('\\', "/"),
        canonical_context(&finding.context),
    ];
    let mut hasher = sha2::Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
~~~

assign_fingerprints walks deterministic file/rule/source order, counts each base, and assigns base for the first occurrence and base + ":" + zero-based occurrence for later indistinguishable duplicates.

- [ ] **Step 6: Prove the canary cannot cross serializable boundaries**

Serialize every secret Finding returned by a scanner test and assert the JSON does not contain CANARY. Pass the same finding through the agent top-findings JSON builder and assert the resulting Value does not contain CANARY.

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::redaction
cargo test --manifest-path src-tauri/Cargo.toml findings::fingerprint
cargo test --manifest-path src-tauri/Cargo.toml scanners
~~~

Expected: all pass.

- [ ] **Step 7: Commit the sanitized identity boundary**

~~~bash
git add src-tauri/src/findings/mod.rs src-tauri/src/findings/redaction.rs src-tauri/src/findings/fingerprint.rs src-tauri/src/scanners/mod.rs src-tauri/src/scanners/secrets.rs src-tauri/src/models.rs src-tauri/src/agent/tools.rs
git commit -m "feat(scan): redact secrets and fingerprint findings"
~~~

---

### Task 4: Classify all scopes and record compatible coverage

**Files:**
- Create: src-tauri/src/findings/coverage.rs
- Modify: src-tauri/src/triage/scope.rs:17-132
- Modify: src-tauri/src/triage/manifest.rs:65-157

**Interfaces:**
- Consumes: project-relative paths and ScanFileOutcome.covered_families.
- Produces: ScopeDecision, CoverageManifest, is_covered(path, family), is_compatible_with(other), and Manifest::reconcile_ids.

- [ ] **Step 1: Write scope and coverage tests**

Add these cases:

~~~rust
assert_eq!(classify("tests/fixtures/key.json").scope, FindingScope::Fixture);
assert_eq!(classify("vendor/pkg/test/a.js").scope, FindingScope::Vendored);
assert_eq!(classify("tests/nginx.conf").scope, FindingScope::Infrastructure);
assert_eq!(classify("").scope, FindingScope::Unknown);
assert_eq!(classify("src/test.rs").scope, FindingScope::Production);

let coverage = CoverageManifest::from_entries([
    ("src/a.rs", ["vulnerability"]),
    ("config.env", ["secret"]),
]);
assert!(coverage.is_covered("src/a.rs", "vulnerability"));
assert!(!coverage.is_covered("src/a.rs", "secret"));
~~~

Also test Windows separators, generated output, documentation, and a disabled scanner.

- [ ] **Step 2: Run the focused tests and verify they fail**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml triage::scope findings::coverage
~~~

Expected: FAIL because Fixture, Unknown, ScopeDecision, and CoverageManifest are missing.

- [ ] **Step 3: Return the deciding reason with scope**

Use:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDecision {
    pub scope: FindingScope,
    pub reason: String,
}
~~~

Classification precedence is infrastructure, vendored, fixture, test, generated, documentation, production. Empty or non-normalizable input is Unknown. Reasons are stable slugs such as infrastructure-file, vendored-directory, fixture-directory, test-name, generated-directory, documentation-directory, production-default, and unknown-path.

- [ ] **Step 4: Implement coverage as sorted portable data**

Define:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageManifest {
    pub fingerprint_version: u16,
    pub paths: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
}
~~~

normalize_path converts separators to / and removes empty and . segments. It rejects .. rather than resolving it. compatible means equal fingerprint_version and at least one shared scanner family; per-finding resolution still requires is_covered.

- [ ] **Step 5: Add exact manifest reconciliation**

Add:

~~~rust
pub fn reconcile_ids<I, S>(&self, observed: I) -> Result<(), ManifestError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>;
~~~

It rejects unsolicited, duplicate, or missing IDs using the same error variants as triage reconciliation. The service will call it immediately before completion so scope/policy/filter stages cannot silently drop a candidate.

- [ ] **Step 6: Verify and commit scope plus coverage**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml triage::scope
cargo test --manifest-path src-tauri/Cargo.toml findings::coverage
cargo test --manifest-path src-tauri/Cargo.toml triage::manifest
~~~

Expected: all pass.

~~~bash
git add src-tauri/src/findings/coverage.rs src-tauri/src/triage/scope.rs src-tauri/src/triage/manifest.rs
git commit -m "feat(scan): classify scope and record coverage"
~~~

---

### Task 5: Create the SQLite schema and repository

**Files:**
- Modify: src-tauri/Cargo.toml
- Modify: src-tauri/Cargo.lock
- Create: src-tauri/src/findings/repository.rs

**Interfaces:**
- Consumes: ScanRunDetail inputs, sanitized Finding values, CoverageManifest, ReviewRecord.
- Produces: FindingsRepository::open, open_in_memory, upsert_project, start_run, complete_run, mark_incomplete, recover_interrupted_runs, load_run, list_recent_projects, upsert_review, and apply_retention.

- [ ] **Step 1: Add SQLite and write a migration test**

Add:

~~~toml
rusqlite = { version = "0.40.2", features = ["bundled"] }
~~~

Write a test that opens an in-memory repository, queries all expected tables, checks PRAGMA foreign_keys = 1, and checks schema_migrations contains version 1.

- [ ] **Step 2: Run the migration test and verify it fails**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::repository::tests::creates_version_one_schema
~~~

Expected: FAIL because FindingsRepository is undefined.

- [ ] **Step 3: Implement connection initialization and migration 1**

On every connection set foreign_keys = ON, journal_mode = WAL for file databases, synchronous = NORMAL, and busy_timeout = 5 seconds. Run this SQL in one transaction:

~~~sql
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  canonical_path TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_opened_at TEXT NOT NULL,
  last_options_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE scan_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_run_id TEXT REFERENCES scan_runs(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK(status IN ('running','completed','incomplete')),
  scanner_version TEXT NOT NULL,
  fingerprint_version INTEGER NOT NULL,
  options_json TEXT NOT NULL,
  policy_status_json TEXT NOT NULL,
  policy_hash TEXT,
  coverage_json TEXT,
  summary_json TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  error_code TEXT
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  fingerprint_version INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  scope TEXT NOT NULL,
  scope_reason TEXT NOT NULL,
  UNIQUE(run_id, fingerprint_version, fingerprint)
);

CREATE INDEX findings_run_idx ON findings(run_id);
CREATE INDEX findings_fingerprint_idx ON findings(fingerprint_version, fingerprint);
CREATE INDEX runs_project_completed_idx ON scan_runs(project_id, status, completed_at DESC);

CREATE TABLE reviews (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint_version INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence TEXT,
  entry_point TEXT,
  data_flow TEXT,
  gates_json TEXT NOT NULL DEFAULT '[]',
  deciding_gate TEXT,
  expires_at TEXT,
  origin TEXT NOT NULL,
  policy_hash TEXT,
  updated_at TEXT NOT NULL,
  superseded_at TEXT
);

CREATE INDEX reviews_history_idx
  ON reviews(project_id, fingerprint_version, fingerprint, updated_at DESC);
CREATE UNIQUE INDEX reviews_active_origin_idx
  ON reviews(project_id, fingerprint_version, fingerprint, origin)
  WHERE superseded_at IS NULL;
~~~

Insert schema_migrations version 1 only after all statements succeed.

- [ ] **Step 4: Implement transactional run completion**

Define a private StoredFindingPayload with the scanner-owned, already-sanitized fields: rule_name, severity, title, description, file_path, line, column, match_text, context, language, cwe, cwe_exploited, cwe_exploited_count, recommendation, entropy, and verified. It deliberately excludes id, observation_run_id, resolved_by_run_id, fingerprint identity, scope, scope_reason, review, review_history, and diff_status because those are stored in relational columns or derived when loading. Convert Finding into this allowlisted payload at the repository boundary and reconstruct the public Finding from payload plus relational and active-review data. Add a serialization test proving a loaded review never becomes duplicated inside payload_json.

Use a transaction and this order:

1. verify the run exists in running state;
2. build Manifest from every input fingerprint;
3. insert every sanitized observation;
4. query inserted fingerprints and reconcile_ids;
5. store coverage and summary JSON;
6. set completed_at and status = completed;
7. commit.

Use INSERT ... ON CONFLICT(id) DO UPDATE only for retrying the same run ID. A second successful retry returns the already completed run and does not duplicate observations.

- [ ] **Step 5: Implement owner-only file creation**

Create the parent directory before Connection::open. On Unix, set directory mode 0700 and database mode 0600 after creation:

~~~rust
#[cfg(unix)]
fn protect(path: &std::path::Path, mode: u32) -> Result<(), CommandError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(CommandError::persistence)?
        .permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(CommandError::persistence)
}
~~~

Test modes on Unix and test that a migration failure leaves no applied version row.

- [ ] **Step 6: Add interrupted-run recovery**

recover_interrupted_runs updates running rows to incomplete with error_code = process_interrupted and completed_at = current UTC. Test that completed rows remain unchanged and the recovered row is not selected by latest_completed_run.

- [ ] **Step 7: Verify and commit persistence**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::repository
cargo check --manifest-path src-tauri/Cargo.toml
~~~

Expected: all pass.

~~~bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/findings/repository.rs
git commit -m "feat(scan): persist runs and findings in SQLite"
~~~

---

### Task 6: Compare compatible runs and enforce retention

**Files:**
- Modify: src-tauri/src/findings/repository.rs
- Modify: src-tauri/src/findings/coverage.rs
- Modify: src-tauri/src/findings/domain.rs

**Interfaces:**
- Consumes: current and baseline fingerprints plus CoverageManifest.
- Produces: compare_runs, latest_compatible_baseline, resolved projections, and RetentionPolicy.

- [ ] **Step 1: Write comparison tests**

Create baseline observations A, B, and C and a current run containing A and D. Assert A is unchanged, D is new, B is resolved only when its path/family is covered, and C is notEvaluated when its scanner is disabled.

Also test that an incomplete current run, a fingerprint-version mismatch, and an unreadable prior path produce no resolved finding.

- [ ] **Step 2: Run the tests and verify they fail**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::repository::tests::run_comparison
~~~

Expected: FAIL because comparison queries are absent.

- [ ] **Step 3: Implement the comparison rules**

For current observations, set observation_run_id to the current run and resolved_by_run_id to None, then set Unchanged when baseline contains the same version plus fingerprint; otherwise New. For baseline-only observations, preserve the baseline observation_run_id and return a projection with resolved_by_run_id equal to the current run plus Resolved only when current coverage contains the baseline path and category scanner family. Otherwise return NotEvaluated with no resolution boundary and keep it out of the Resolved view count.

latest_compatible_baseline selects the newest completed run for the same project and fingerprint version with at least one scanner family shared with current coverage.

- [ ] **Step 4: Implement retention without deleting reviews**

Define:

~~~rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_completed_runs_per_project: u32,
    pub max_age_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self { max_completed_runs_per_project: 20, max_age_days: 90 }
    }
}
~~~

apply_retention deletes completed scan_runs older than the age cutoff, then deletes all but the newest max count per project. Foreign keys remove observations. It never deletes projects or reviews.

- [ ] **Step 5: Test the maintenance-failure boundary**

Inject a repository test hook that fails retention after a run commits. Assert the completed run remains loadable and the returned maintenance warning is separate from run persistence status.

- [ ] **Step 6: Verify and commit comparison**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::repository
~~~

Expected: all repository tests pass.

~~~bash
git add src-tauri/src/findings/repository.rs src-tauri/src/findings/coverage.rs src-tauri/src/findings/domain.rs
git commit -m "feat(scan): compare runs and retain history"
~~~

---

### Task 7: Parse and atomically update project policy

**Files:**
- Create: src-tauri/src/findings/policy.rs

**Interfaces:**
- Consumes: project root, fingerprint, rule ID, relative path, current UTC.
- Produces: load_policy, apply_policy, update_policy_decision, PolicyFile, PolicyEntry, and PolicyStatus.

- [ ] **Step 1: Write valid, invalid, expired, and atomicity tests**

Use this fixture:

~~~json
{
  "version": 1,
  "entries": [
    {
      "kind": "finding",
      "fingerprintVersion": 1,
      "fingerprint": "abc123",
      "category": "vulnerability",
      "state": "falsePositive",
      "reason": "The affected branch is excluded from production",
      "gates": [
        {
          "gate": "reachable",
          "verdict": "eliminates",
          "evidence": "The production feature manifest excludes this branch"
        }
      ],
      "decidingGate": "reachable"
    },
    {
      "kind": "suppression",
      "ruleId": "gen-hardcoded-password",
      "pathPattern": "tests/**",
      "state": "suppressed",
      "reason": "Synthetic credential fixtures",
      "expiresAt": "2027-01-01T00:00:00Z"
    }
  ]
}
~~~

Assert absolute paths, missing reasons, candidate state, unknown versions, and invalid timestamps are rejected. Build an update from a sanitized secret finding whose original scanner input contains the canary and assert the serialized policy does not contain it. Use a write-failure injection to prove the prior file remains byte-identical.

- [ ] **Step 2: Run the policy tests and observe the failure**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::policy
~~~

Expected: FAIL because policy types are undefined.

- [ ] **Step 3: Define and validate the policy schema**

Use a tagged enum:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PolicyEntry {
    Finding {
        fingerprint_version: u16,
        fingerprint: String,
        category: String,
        state: ReviewState,
        reason: String,
        evidence: Option<String>,
        entry_point: Option<String>,
        data_flow: Option<String>,
        #[serde(default)]
        gates: Vec<crate::triage::gates::GateNote>,
        deciding_gate: Option<crate::triage::gates::Gate>,
        expires_at: Option<String>,
    },
    Suppression {
        rule_id: String,
        path_pattern: String,
        state: ReviewState,
        reason: String,
        expires_at: Option<String>,
    },
}
~~~

Only FalsePositive, AcceptedRisk, and Suppressed are portable closure states in version 1. Confirmed remains local because its full confirmation evidence may contain private source details. Validate Finding entries with the same category-specific review matrix as local decisions: vulnerability FalsePositive retains its sanitized eliminating gate/evidence, while secret decisions reject evidence, entry/data flow, and gates. Paths embedded in evidence must be project-relative with / separators; reject drive prefixes, leading /, .. segments, raw secret match/context fields, and credential-shaped values. Suppression entries carry no source evidence.

- [ ] **Step 4: Implement deterministic matching**

Ignore expired entries. Precedence is local active review, exact fingerprint policy entry, last matching suppression entry, then Candidate. Use ignore::gitignore::GitignoreBuilder for path patterns. An exact fingerprint entry whose category disagrees with the observed finding makes policy application invalid rather than selecting a weaker validator. Return all validated decision fields plus policy hash and ProjectPolicy origin in the active ReviewRecord so reload reproduces the auditable decision rather than only its label.

- [ ] **Step 5: Implement atomic same-directory replacement**

Serialize pretty JSON with a trailing newline, write a unique .oxaudit/.policy.json.<uuid>.tmp in the same directory with create_new, sync_all, parse the temporary file again, rename it over policy.json, then sync the .oxaudit directory on supported platforms. Remove only the temporary file created by this attempt after a failed write; a stale temp from a killed process cannot block future saves, and the prior policy is never truncated.

- [ ] **Step 6: Verify and commit project policy**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::policy
~~~

Expected: all policy tests pass.

~~~bash
git add src-tauri/src/findings/policy.rs
git commit -m "feat(scan): add repository-owned finding policy"
~~~

---

### Task 8: Validate and persist analyst reviews

**Files:**
- Create: src-tauri/src/findings/review.rs
- Modify: src-tauri/src/findings/repository.rs
- Modify: src-tauri/src/triage/gates.rs

**Interfaces:**
- Consumes: ReviewRequest and finding category.
- Produces: validate_review(request, category), save_local_review, and save_project_policy_review.

- [ ] **Step 1: Write the review-state matrix tests**

Cover these exact rules:

- every non-Candidate decision requires a non-empty analyst reason;
- vulnerability Confirmed requires exactly one note for each of the five gates, every verdict Survives, and non-empty evidence on every note;
- vulnerability FalsePositive requires one deciding Eliminates gate with non-empty evidence;
- secret Confirmed and FalsePositive require a reason but never gate answers;
- AcceptedRisk and Suppressed require a reason for both categories;
- Candidate clears the selected origin's review;
- expiry must parse as RFC3339 and be in the future when saved;
- ProjectPolicy rejects Confirmed and any evidence containing source context.
- an unknown fingerprint or a request category that disagrees with the latest project observation is rejected before any write.

- [ ] **Step 2: Run the tests and verify they fail**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::review
~~~

Expected: FAIL because validate_review does not exist.

- [ ] **Step 3: Reuse the existing falsification gate invariant**

Before category-specific validation, load the newest observation for project_id plus fingerprint_version plus fingerprint. Return NotFound if it does not exist, and ReviewInvalid if request.category differs; never trust the frontend category to choose weaker validation.

For vulnerabilities, translate Confirmed to Triage::new with Disposition::Confirmed. Strengthen the existing Triage confirmation invariant so it rejects duplicate/missing gates, Unknown, Eliminates, and empty evidence; add focused regression tests in triage/gates.rs. Translate FalsePositive to Disposition::Eliminated { gate: deciding_gate }. Store the validated gate vector, deciding gate, entry point, and data flow in ReviewRecord.

For secrets, reject any gate vector and accept a non-empty reason. No review path reads, reveals, or validates a credential.

- [ ] **Step 4: Persist local review transactionally**

save_review opens one transaction, sets superseded_at on the current row for the same project/fingerprint/origin, and inserts a new UUID-keyed event. Candidate records an explicit clearing event so the prior decision remains auditable. Query the latest non-expired non-Candidate event for active state; history queries include Candidate, expired, and superseded events in descending updated_at order.

- [ ] **Step 5: Persist project policy before refreshing SQLite**

For ProjectPolicy:

1. load and validate current policy;
2. atomically write the updated policy;
3. reload it as the source of truth;
4. reconcile its derived review into SQLite.

If step 2 fails, neither file nor database changes. If step 4 fails, return PolicyWriteFailed with retryable true; the next project load reconciles the valid file.

Reconciliation is idempotent: when the active project-policy event already has the same state, reason, evidence, entry point, data flow, gates, deciding gate, expiry, and policy hash, do not append another history event. A changed or removed policy entry supersedes the old active event and appends exactly one replacement event.

- [ ] **Step 6: Verify and commit review behavior**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::review
cargo test --manifest-path src-tauri/Cargo.toml triage::gates
~~~

Expected: all pass.

~~~bash
git add src-tauri/src/findings/review.rs src-tauri/src/findings/repository.rs src-tauri/src/triage/gates.rs
git commit -m "feat(scan): persist evidence-backed reviews"
~~~

---

### Task 9: Orchestrate durable scans and persistence retry

**Files:**
- Create: src-tauri/src/findings/service.rs
- Modify: src-tauri/src/commands.rs:24-72, 271-419
- Modify: src-tauri/src/agent/tools.rs:169-225

**Interfaces:**
- Consumes: FindingsRepository, ScanOptions, CveState, cancellation flag, event emitter.
- Produces: FindingsService::scan, retry_save, inspect_project, load_run, list_recent_projects, and save_review.

- [ ] **Step 1: Write a service integration test**

Use a TempDir project and in-memory repository. Run a scan, assert status Completed and persistence Saved, close the service, construct another service over the same temporary database, and load the same run by ID. Insert lines above the finding, rescan, and assert Unchanged.

Add a repository failure hook after scanning and assert the returned run has NotSaved { retryToken }; retry_save with the token persists exactly one completed run.

Hold one scan open with a test barrier. Assert a second scan for that project returns ScanAlreadyRunning, while a different project can scan concurrently. Release the barrier and prove the project guard is cleared after success and after an injected scanner failure.

- [ ] **Step 2: Run the integration test and observe the failure**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::service
~~~

Expected: FAIL because FindingsService is undefined.

- [ ] **Step 3: Implement the service pipeline in the approved order**

The scan method performs:

1. canonicalize and upsert project;
2. inspect policy and reject invalid policy unless ScanOptions.ignore_invalid_policy is true;
3. create running run row;
4. collect files and sanitized ScanFileOutcome values;
5. mark incomplete on cancellation or scanner failure;
6. enrich CWE exploitation signals;
7. assign fingerprints;
8. classify scope and attach rationale to every finding;
9. apply active local review and valid policy;
10. build coverage and compare baseline;
11. complete the run transaction;
12. apply retention as separate maintenance work.

Guard active work with a project-ID keyed set in FindingsService. Acquire after canonicalization and before creating the running row, then release through an RAII guard on success, cancellation, or error. Reject only a duplicate scan of the same project with ScanAlreadyRunning; unrelated projects remain independent.

Add #[serde(default)] ignore_invalid_policy: bool to ScanOptions so the current frontend remains source-compatible and sends false.

- [ ] **Step 4: Keep failed completion results in bounded memory**

Define:

~~~rust
pub struct PendingSave {
    pub run_id: String,
    pub project_id: String,
    pub result: ScanResult,
    pub coverage: CoverageManifest,
    pub policy: PolicyStatus,
    pub baseline_run_id: Option<String>,
}
~~~

Store at most three sanitized pending saves behind a Mutex inside FindingsService, evicting oldest first. retry_save removes an item only after successful idempotent completion. PendingSave never contains raw secret values.

- [ ] **Step 5: Replace only the Source Scan command body**

commands::scan_project resolves FindingsService through FindingsState, delegates to it, and returns Result<ScanRunDetail, CommandError>. Preserve progress event names scan://progress and scan://done so the current page still receives progress. Keep cancel_scan behavior but ensure the service marks the active run incomplete.

Do not alter dependency, CVE, binary, session, or assistant commands.

- [ ] **Step 6: Verify scan, retry, cancel, and restart**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml findings::service
cargo test --manifest-path src-tauri/Cargo.toml scan_option_contract_tests
~~~

Expected: all pass.

- [ ] **Step 7: Commit orchestration**

~~~bash
git add src-tauri/src/findings/service.rs src-tauri/src/commands.rs src-tauri/src/models.rs src-tauri/src/agent/tools.rs
git commit -m "feat(scan): orchestrate durable source scans"
~~~

---

### Task 10: Initialize persistence and expose finding commands

**Files:**
- Modify: src-tauri/src/lib.rs:20-82
- Modify: src-tauri/src/commands.rs:24-72 and command registration area
- Modify: src-tauri/src/findings/mod.rs

**Interfaces:**
- Consumes: Tauri app_data_dir and AppState.
- Produces Tauri commands: inspect_source_project, list_source_projects, list_source_runs, load_source_run, retry_source_run_save, save_finding_review, and delete_finding_review.

- [ ] **Step 1: Write command-service tests without a Tauri window**

Test the plain command adapters against an injected FindingsService:

~~~rust
let context = inspect_source_project_inner(&service, project.path()).unwrap();
assert_eq!(
    context.canonical_path,
    project.path().canonicalize().unwrap().to_string_lossy().into_owned(),
);

let recent = list_source_projects_inner(&service, 12).unwrap();
assert_eq!(recent[0].project_id, context.project_id);
~~~

Also test limit clamping to 1..=100, unknown run NotFound, and invalid policy PolicyInvalid.

- [ ] **Step 2: Run the focused tests and verify they fail**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml source_finding_command_tests
~~~

Expected: FAIL because the inner adapters are missing.

- [ ] **Step 3: Initialize the database during setup**

Resolve:

~~~rust
let data_dir = app.path().app_data_dir()?;
let initialized = (|| {
    let database_path = findings::database_path(&data_dir);
    let repository = FindingsRepository::open(database_path)?;
    repository.recover_interrupted_runs(chrono::Utc::now())?;
    Ok::<_, CommandError>(FindingsService::new(repository))
})();
let state = match initialized {
    Ok(service) => FindingsState::available(service),
    Err(error) => FindingsState::unavailable(error),
};
app.manage(state);
~~~

`findings::database_path` is the single path authority and resolves to
`<app-data>/findings/findings.sqlite3`. Before nested initialization, reject any
entry at the unsupported root-level `<app-data>/findings.sqlite3` path with the
sanitized unavailable state. Do not create or open the nested database and do
not mutate either entry when that ambiguity exists. The root-level layout was
present only in unreleased intermediary foundation commits; this task does not
silently migrate it. Any future authority transition belongs to the explicit
identity-migration workflow.

FindingsState owns Option<FindingsService> plus the sanitized initialization CommandError and has service() -> Result<&FindingsService, CommandError>. If initialization fails, keep the app launchable with an unavailable FindingsState so Settings and non-Source tools still work; Source finding commands return the typed error.

- [ ] **Step 4: Add and register the commands**

Use these signatures:

~~~rust
#[tauri::command]
pub fn inspect_source_project(
    state: State<'_, FindingsState>,
    path: String,
) -> Result<ProjectContext, CommandError>;

#[tauri::command]
pub fn list_source_projects(
    state: State<'_, FindingsState>,
    limit: u32,
) -> Result<Vec<RecentProject>, CommandError>;

#[tauri::command]
pub fn list_source_runs(
    state: State<'_, FindingsState>,
    project_id: String,
    limit: u32,
) -> Result<Vec<ScanRunSummary>, CommandError>;

#[tauri::command]
pub fn load_source_run(
    state: State<'_, FindingsState>,
    run_id: String,
) -> Result<ScanRunDetail, CommandError>;

#[tauri::command]
pub fn retry_source_run_save(
    state: State<'_, FindingsState>,
    retry_token: String,
) -> Result<ScanRunDetail, CommandError>;

#[tauri::command]
pub fn save_finding_review(
    state: State<'_, FindingsState>,
    request: ReviewRequest,
) -> Result<ReviewRecord, CommandError>;
~~~

delete_finding_review is the same ReviewRequest with state Candidate and explicit origin.

- [ ] **Step 5: Verify restart recovery through a file database**

Write a test that opens a temp file database, creates a running row, drops the repository without completion, reopens it, calls recover_interrupted_runs, and asserts the row is Incomplete while the prior completed baseline remains selected.

- [ ] **Step 6: Commit command registration**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml source_finding_command_tests
cargo check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/lib.rs src-tauri/src/commands.rs src-tauri/src/findings/mod.rs
git commit -m "feat(scan): expose durable finding commands"
~~~

---

### Task 11: Verify the complete foundation and document its contract

**Files:**
- Create: docs/superpowers/qa/2026-08-20-oxaudit-durable-scan-foundation.md
- Modify: docs/superpowers/plans/2026-08-20-oxaudit-durable-scan-foundation.md (checkboxes only during execution)

**Interfaces:**
- Consumes: all preceding foundation tasks.
- Produces: reproducible verification evidence for the workflow plan.

- [ ] **Step 1: Run the sensitive-data canary suite**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml redaction
cargo test --manifest-path src-tauri/Cargo.toml fingerprint
cargo test --manifest-path src-tauri/Cargo.toml policy
~~~

Expected: all tests pass and every canary absence assertion succeeds.

- [ ] **Step 2: Run the complete automated baseline**

~~~bash
npm test
npm run check
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
~~~

Expected: every command exits 0. Clippy may report pre-existing advisory warnings but must introduce no warning in src-tauri/src/findings, scanners/mod.rs, triage/scope.rs, triage/manifest.rs, or modified Source Scan command code.

- [ ] **Step 3: Inspect a disposable file database directly**

Add a file_database_survives_restart_and_contains_no_secret_canary test that creates a TempDir database, runs the service, drops and reopens the repository, queries sqlite_master for the five logical tables, loads the completed run, and executes this parameterized assertion:

~~~rust
let leaked: i64 = connection.query_row(
    "SELECT count(*) FROM findings WHERE payload_json LIKE '%' || ?1 || '%'",
    [CANARY],
    |row| row.get(0),
)?;
assert_eq!(leaked, 0);
~~~

Run:

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml file_database_survives_restart_and_contains_no_secret_canary -- --exact --nocapture
~~~

Expected: the disposable database reopens, all tables are present, the completed run loads, and the canary count is zero.

- [ ] **Step 4: Record QA evidence**

The QA document records command, exit code, test counts, test database path, redaction canary used, restart outcome, and any pre-existing advisory lint warnings. Do not include source excerpts or credentials.

- [ ] **Step 5: Commit foundation verification**

~~~bash
git add docs/superpowers/qa/2026-08-20-oxaudit-durable-scan-foundation.md
git commit -m "docs: verify durable scan foundation"
~~~

## Foundation Completion Gate

Do not begin the Source Scan/Results workflow plan until:

- a sanitized completed scan survives a real process restart;
- line insertion preserves finding identity;
- disabled or failed coverage cannot create a resolved finding;
- test, fixture, generated, vendored, documentation, and unknown candidates remain queryable;
- review and policy validation tests pass;
- a failed completion returns NotSaved and an idempotent retry succeeds;
- the current Source Scan page still builds and can display the compatibility result.

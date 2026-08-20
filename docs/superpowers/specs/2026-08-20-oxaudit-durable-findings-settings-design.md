# oxAudit Durable Findings and Settings Design

Date: 2026-08-20

Status: Draft for final review

Extends: `2026-08-17-oxaudit-professional-workbench-design.md`

## Objective

Make Source Scan, finding review, and Settings durable and trustworthy enough for a professional desktop security tool.

The design adds persistent scan history, stable finding identity, explicit analyst review states, visible scope classification, repository-owned policy, secure credential storage, and a safe product/data migration from VulnCompanion to oxAudit.

The existing independent-tool workbench remains the product model. Source Scan gains durable project-aware history, but Dependency Scan, CVE Research, and AI Assistant do not become steps in a mandatory audit workflow.

## Relationship to the Existing Workbench Design

The 2026-08-17 Professional Workbench design remains authoritative for the shell, visual system, navigation, accessibility, and independent-tool architecture.

This design supersedes only these earlier constraints:

- Source Scan results no longer live solely in transient frontend state.
- Scan engines and settings persistence may change where needed for durability, review workflow, secure storage, and migration.
- Settings becomes a categorized editor rather than one long page that retains the existing plaintext persistence model.

## Approved Direction

Use a local SQLite database plus an optional source-controlled `.oxaudit/policy.json` file:

- SQLite is the local source of truth for projects, scan runs, observed findings, and local review decisions.
- `.oxaudit/policy.json` is the portable, repository-owned source of truth for review or suppression decisions the user explicitly chooses to share with a project.
- Every scanner match is retained. Scope classification changes its default view, not whether it exists.
- Stable, versioned fingerprints reconcile a finding between compatible completed runs.
- Raw detected secrets never enter durable storage, logs, policy files, or AI prompts.
- Provider credentials live in the operating system's protected credential store.

## Scope

This design covers:

- Source Scan target selection and execution;
- durable run history and comparison;
- Results views and finding detail;
- analyst review states and supporting evidence;
- scope classification and policy application;
- Settings information architecture and save behavior;
- credential protection;
- the VulnCompanion-to-oxAudit identity and data migration;
- retention, export, deletion, failure recovery, and verification.

## Non-goals

- Cloud accounts, synchronization, collaboration, or a remote database.
- A mandatory global project that gates unrelated oxAudit tools.
- Live validation or use of a detected credential.
- Silently allowing AI output to confirm, close, accept, or suppress a finding.
- Automatically editing `.oxaudit/policy.json` because a local review changed.
- A general-purpose policy language or organization-wide policy service.
- Treating an incomplete or coverage-incompatible scan as evidence that an earlier finding was resolved.

## Domain Model

### Project

A project represents a canonical local scan root. It stores a generated project ID, normalized canonical path, display name, creation time, last-opened time, and the last successfully used scan configuration.

Paths shown to the user remain normal native paths. Finding identity and policy use project-relative paths with `/` separators so records remain portable across machines.

### Scan run

A scan run is created before scanner work begins and has one of these states:

- `running`
- `completed`
- `incomplete`

Cancellation, scanner failure, process termination, or application crash produces an incomplete run. Incomplete runs are never selected as a comparison baseline and never cause older findings to become resolved.

A completed run records:

- project and run IDs;
- start and completion timestamps;
- scanner and fingerprint schema versions;
- normalized scan options;
- active policy hash or the fact that policy loading failed;
- coverage information sufficient to decide which prior locations were actually rescanned;
- aggregate counts and duration;
- an optional compatible baseline run ID.

### Finding observation

A finding row is an immutable observation from one scan run. It contains:

- run ID and stable fingerprint;
- scanner family and rule ID;
- title, severity, CWE or advisory metadata when available;
- project-relative path and current source location;
- classified scope;
- a sanitized evidence excerpt or redacted secret preview;
- sanitized scanner metadata needed by the UI;
- the comparison status `new`, `unchanged`, or `resolved` as applicable.

The existing random scanner result ID may remain an observation identifier, but it is not used for cross-run identity.

### Review

A review belongs to a project and stable finding fingerprint. Its state is one of:

- `candidate`
- `confirmed`
- `false_positive`
- `accepted_risk`
- `suppressed`

Non-candidate decisions store the decision time, reason, evidence or gate answers when applicable, optional expiry, and origin (`local` or `project_policy`). Expired decisions no longer affect the active view but remain auditable in history.

`accepted_risk` means the finding is believed valid but intentionally tolerated. `suppressed` prevents a matching candidate from appearing in the default open queue until the decision expires or is removed. Neither state deletes observations.

### Scope

Every observation receives exactly one scope:

- `production`
- `infrastructure`
- `test`
- `fixture`
- `generated`
- `vendored`
- `documentation`
- `unknown`

Scope classification is deterministic and records the rule or path pattern that decided it. Ambiguous paths use `unknown`; oxAudit must not silently discard them.

## Persistence Architecture

All database access remains in Rust behind a narrow repository/service boundary. React obtains typed data through Tauri commands and does not query or mutate SQLite directly.

The initial schema contains these logical tables:

- `schema_migrations`
- `projects`
- `scan_runs`
- `findings`
- `reviews`

Foreign keys are enabled. Schema changes are versioned, transactional, and safe to retry. Database creation and migrations happen before commands that depend on durable findings become available.

The database and its parent directory use owner-only permissions where the platform supports them. Vulnerability evidence can contain private source code, so it follows the configured run-retention policy. Secret evidence is sanitized before a persistence object is constructed.

Run completion uses one transaction to persist observations, coverage, comparison metadata, and final counts before setting the run to `completed`. A failure rolls back that completion; the frontend may keep the result in memory, but it must label it `Not saved` and offer a persistence retry.

### Stable fingerprint

The fingerprint is a versioned SHA-256 digest of canonical fields:

1. fingerprint schema version;
2. scanner family and rule ID;
3. normalized project-relative path;
4. normalized surrounding source context with the exact matched value replaced by a fixed marker.

Line and column numbers are deliberately excluded so inserting or deleting unrelated lines does not create a new identity. Context normalization standardizes line endings and insignificant surrounding whitespace without removing meaningful tokens.

For secret rules, the raw secret and a recoverable or brute-forceable digest of it are not fingerprint inputs. The matched span is replaced before hashing and before any log, DTO, database, policy, session, or AI boundary.

If multiple occurrences produce the same canonical fingerprint base, oxAudit assigns a deterministic occurrence suffix within that file and run. Truly indistinguishable duplicate blocks may be reported as new/resolved after reordering; the UI does not claim stronger identity than the available source context supports.

Changing fingerprint semantics increments the schema version. Runs with incompatible fingerprint versions are not diffed as though they shared identity.

### Run comparison and coverage

A completed run compares only with the latest completed run for the same project whose fingerprint version and scanner coverage are compatible.

For each current observation:

- no baseline fingerprint match means `new`;
- a baseline fingerprint match means `unchanged`.

A baseline observation becomes `resolved` only when its scanner family and path were covered successfully by the new run and its fingerprint is absent. Excluded paths, disabled scanners, unreadable files, and incomplete runs produce `not evaluated`, not `resolved`.

Resolved observations are presented from the baseline with the current run as the resolution boundary. Historical observations are immutable.

## Project Policy

The optional policy file lives at `.oxaudit/policy.json` and is designed to be reviewed and committed with the repository.

The file contains:

- a policy schema version;
- explicit finding decisions or suppression rules;
- project-relative paths or patterns;
- reason and optional expiry;
- no absolute machine paths, credentials, raw secret evidence, or private provider configuration.

Opening a project detects and validates the policy. The active policy status and validation errors are visible in Source Scan and Settings.

Local review is the default. Writing a decision into project policy requires an explicit action and clear preview of the resulting scope. Policy updates use an atomic same-directory temporary write, validation, flush, and replacement. If the write fails, oxAudit does not display the project-policy action as committed.

On the next load, the policy file is reconciled into derived review state. This makes the repository file authoritative for project-policy decisions and allows recovery if the file update succeeds but a following database refresh is interrupted.

An invalid policy is never overwritten automatically. The user can continue a scan without applying it after seeing an actionable error.

## Source Scan Workflow

### Target selection

The idle Source Scan page provides:

- recent projects with last successful scan time and open-count summary;
- path selection and drag-and-drop;
- detected `.oxaudit/policy.json` status;
- prior scan options as editable defaults;
- one clear Run scan action.

Selecting a target loads its latest completed run, local reviews, project policy, and previous options. Changing target does not erase the previous project's durable history.

### Execution pipeline

The backend pipeline is:

1. create a `running` run record;
2. collect raw scanner matches;
3. sanitize secret-bearing data at the scanner boundary;
4. calculate stable fingerprints;
5. classify every observation's scope;
6. load and apply valid policy decisions;
7. retain every observation and record coverage;
8. compare with the latest compatible completed run;
9. persist the completed run transactionally;
10. return durable run and count data to the UI.

Existing triage scope, gate, and manifest modules should be integrated through this pipeline rather than reimplemented in React.

The last completed results remain visible while a new scan runs. Cancellation and failure retain that completed baseline and clearly label the new attempt incomplete.

## Results Workflow

Results are grouped into persistent views:

- **Open:** production, infrastructure, and unknown candidates plus confirmed findings from every scope;
- **Other scopes:** visible test, fixture, generated, vendored, and documentation candidates;
- **Closed:** false positives, accepted risks, and active suppressions;
- **Resolved:** findings from the compatible baseline that were covered and absent in the current run.

Each view shows its count. Filtering never changes the underlying stored set. Result rows show severity, review state, scope, run-diff status, title, and file location.

Finding detail shows source evidence, rule metadata, scope rationale, run history, review history, and available actions. Secret findings show only a redacted preview.

### Vulnerability review

Confirming or rejecting a vulnerability uses the existing falsification gates. All required gates must be answered. The result records the deciding gate, supporting evidence, and reason rather than a conclusion alone.

### Secret review

Secret findings use a smaller evidence form that can record context and disposition without revealing or validating the live credential. oxAudit never attempts authentication with a detected value.

### Accept and suppress

Accepted-risk and suppression actions require a reason and offer an optional expiry. The user explicitly chooses whether the decision remains local or is proposed for project policy.

### AI boundary

AI can draft an explanation, gate evidence, or remediation text from sanitized context. Drafts are visibly attributed and editable. AI cannot silently change review state, write policy, or receive raw detected secrets.

## Settings Design

Settings uses a category sidebar with these sections:

1. General
2. AI provider
3. Scanning and findings
4. Data sources and tools
5. Data and privacy

Edits remain in a page-level draft until one explicit **Save changes** action. Modified categories show a dirty indicator. Navigating away with unsaved changes requires a discard confirmation.

Validation appears beside the affected field or category. Provider connection tests are explicit actions and do not save unrelated draft changes.

### Scanning and findings

This category contains global scan defaults, default finding views, review-expiry defaults, and project-policy behavior. It clearly distinguishes global local defaults from the active repository's `.oxaudit/policy.json` and never edits the repository file as a side effect of saving global settings.

### Data and privacy

This category shows the local data location and provides run-retention, export, and deletion controls.

The default retention rule is:

- delete completed run evidence older than 90 days; and
- retain no more than the newest 20 completed runs per project.

Whichever limit removes a run first applies. Review decisions and current project policy remain until explicitly removed. Deleting a run removes its stored evidence but not a review attached to the stable project finding identity.

Export and deletion clearly state whether they affect one run, one project, or all local data. Destructive deletion requires target-specific confirmation.

## Credential Storage

Provider API keys move to the operating system's protected credential store through a Rust abstraction. Settings JSON and SQLite retain only provider configuration, a credential reference, and presence metadata—not the credential value.

The UI can set, replace, test, and delete a credential but cannot read an existing value back. Logs and frontend errors never include it.

On the first compatible upgrade, migration performs these steps:

1. read the legacy plaintext settings;
2. import each credential into protected storage;
3. verify that the protected entry can be resolved through the credential abstraction;
4. atomically write sanitized settings;
5. validate the sanitized settings;
6. only then atomically sanitize the legacy settings source while retaining its non-secret recovery data.

If any step fails, legacy data remains untouched and the UI explains how to retry. Tests use an in-memory credential-store adapter; production uses the platform adapter.

## Product Identity and Data Migration

The canonical product identity becomes:

- display name: `oxAudit`;
- package and executable identity: `oxaudit`;
- Rust library identity: `oxaudit_lib`;
- bundle identifier: `com.oxaudit.desktop`;
- browser storage prefix: `oxaudit.*`.

The rename covers application chrome, package metadata, Rust crate/binary names, bundle configuration, prompts, user agent, documentation, settings paths, and remaining user-visible VulnCompanion references.

Migration runs before the new settings and database become authoritative:

1. detect the former VulnCompanion application-data location;
2. create a checkpoint and migration record;
3. copy or merge settings and sessions without overwriting newer oxAudit records;
4. migrate browser storage keys from `vc.*` to `oxaudit.*`;
5. migrate provider credentials into protected storage;
6. sanitize the new and legacy settings files after credential verification;
7. validate migrated settings, sessions, credentials, and sanitized legacy data;
8. mark the migration complete.

Each step is idempotent. A restart resumes from the last validated checkpoint. Existing oxAudit data wins on key conflicts, and the conflict is reported rather than silently overwritten.

The old application-data directory remains as a recoverable backup after successful migration, but its settings file no longer contains plaintext credentials. Settings identifies the backup and offers an explicit removal action; automatic cleanup is outside the initial migration.

Session files and the new database use owner-only permissions where supported. Migration must not print their contents or credential fields.

## Failure Handling

Persistence, policy, credential, migration, and scan failures use typed backend error codes plus safe user-facing messages. Raw internal errors may be attached to local diagnostic details only after sensitive values and source evidence are removed.

Required behavior:

- A completed in-memory scan that cannot be committed remains viewable as `Not saved` with Retry save.
- Duplicate retry uses the same run identity and cannot create two completed runs.
- An interrupted `running` run becomes `incomplete` during startup recovery.
- An invalid project policy is reported and preserved byte-for-byte.
- A failed project-policy write leaves the prior valid file and visible review state intact.
- A failed database migration rolls back its transaction and prevents commands from using a partially migrated schema.
- A failed identity or credential migration retains the legacy source and can resume safely.
- Retention failure does not invalidate the newly completed run; it produces a separate maintenance warning and can retry later.

## Frontend Boundaries

Source Scan should be decomposed around domain responsibilities rather than continuing as one monolithic page:

- target and recent-project selection;
- scan execution and progress;
- result-view toolbar and counts;
- finding list;
- finding detail and evidence;
- review form;
- run history and comparison state;
- policy status.

Durable domain state comes from typed backend commands. Zustand/local storage may retain lightweight UI preferences, but not the authoritative scan history or finding reviews.

Settings similarly separates category navigation, draft state, field validation, provider tests, credential actions, and migration/data-management status. A serialized save prevents overlapping settings writes.

## Accessibility and Interaction Requirements

- Result-view tabs, filters, scope chips, and review states expose their selected state programmatically.
- Keyboard users can move through the finding list, open detail, and complete review forms.
- Scope, severity, review state, and diff status always include text; color is supplementary.
- Progress, scan completion, persistence failure, and review completion use restrained live announcements.
- Confirmation dialogs trap and restore focus.
- Redacted secret previews cannot be revealed through hover text, accessible labels, copied debug payloads, or toast content.

## Verification Strategy

### Rust unit and integration tests

- fingerprint stability across line insertion, line-ending changes, and path normalization;
- fingerprint version incompatibility and duplicate-context behavior;
- secret redaction before DTO, persistence, logs, policy, session, and AI boundaries;
- deterministic scope classification for every supported scope;
- retention of test, fixture, generated, vendored, documentation, and unknown observations;
- policy validation, expiry, precedence, atomic replacement, and failed-write recovery;
- required falsification gates and valid review-state transitions;
- new, unchanged, resolved, and not-evaluated comparison behavior;
- coverage changes, disabled scanners, unreadable files, and incomplete-run behavior;
- SQLite creation, migration, rollback, constraints, restart recovery, and idempotent save retry;
- retention behavior and review survival after run deletion;
- credential import success, failure, redaction, replacement, and deletion through a fake adapter;
- identity, application-data, session, and browser-storage migration, including restart and conflict cases;
- owner-only permission behavior on supported platforms.

### Frontend tests

- recent-target selection and prior-option restoration;
- prior completed results remaining visible during a new scan;
- Open, Other scopes, Closed, and Resolved counts and filtering;
- visible scope and diff labels;
- vulnerability gate validation and secret review behavior;
- local versus project-policy action previews;
- unsaved, incomplete, policy-invalid, and persistence-retry states;
- categorized Settings navigation, dirty indicators, discard protection, and serialized save;
- credential presence without value disclosure;
- migration, retention, export, and deletion status surfaces.

### Native integration scenarios

1. scan -> persist -> restart -> load the same completed run;
2. edit source lines -> rescan -> reconcile unchanged/new/resolved findings;
3. change scan coverage -> verify uncovered findings are not called resolved;
4. review locally -> restart -> preserve the review;
5. write project policy -> reload -> reproduce the project-policy decision;
6. cancel or crash during scan -> restart -> preserve the previous baseline and mark the attempt incomplete;
7. fail persistence after scanning -> keep unsaved results and retry exactly once;
8. migrate a legacy VulnCompanion profile -> preserve sessions/settings, protect credentials, and keep a backup;
9. package and launch the renamed native application on the supported desktop platform.

## Quality Gates

Before feature implementation begins, repair the existing Rust fixture tests that assume a hard-coded `/tmp/vc_fixture` path so the baseline suite is trustworthy.

Each implementation slice must pass its focused tests before broader verification. Completion requires:

- frontend type checks, linting, tests, and production build;
- Rust formatting, focused tests, full tests, and clippy with project-appropriate warning settings;
- migration tests from representative legacy data;
- packaged native-app smoke testing;
- keyboard, focus, responsive desktop, and sensitive-data inspection passes.

No completion claim may rely only on the frontend showing expected data; persisted state must be verified after a real process restart.

## Acceptance Criteria

The design is successfully implemented when:

- a completed Source Scan survives application restart;
- findings reconcile across compatible rescans without depending on line numbers;
- every candidate remains accessible, including non-production scopes;
- review states, reasons, evidence, expiry, and origin remain auditable;
- resolved status is produced only from successful compatible coverage;
- `.oxaudit/policy.json` is explicit, portable, validated, and never silently overwritten;
- after successful migration, raw detected secrets and provider credentials are absent from SQLite, JSON, logs, policy, sessions, frontend payloads, AI prompts, and the retained legacy backup;
- Settings clearly separates global configuration, repository policy, credentials, and local data controls;
- the oxAudit rename preserves recoverable VulnCompanion settings and sessions through a restart-safe migration;
- error states tell the truth about durability and provide a safe retry path;
- all automated and native verification gates pass.

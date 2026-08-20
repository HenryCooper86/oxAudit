# oxAudit Settings, Credentials, and Identity Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver categorized Settings, protected provider credentials, explicit local-data controls, and a restart-safe migration from the VulnCompanion identity and data locations to oxAudit.

**Architecture:** Split public settings from runtime secrets. Sanitized JSON stores configuration and credential-presence metadata; a Rust credential abstraction stores values in native protected stores and resolves them only for the operation that needs them. A checkpointed migration service copies and validates legacy configuration/sessions, imports and verifies credentials, sanitizes the legacy backup, and reports conflicts before the package and bundle identifiers change.

**Tech Stack:** React 19, TypeScript 5.8, Zustand 5, Tauri 2.11, Rust 2021, serde/serde_json, keyring 4.1.6 default v1 native stores, zeroize 1.9, existing rusqlite foundation.

**Spec:** docs/superpowers/specs/2026-08-20-oxaudit-durable-findings-settings-design.md

**Depends on:** docs/superpowers/plans/2026-08-20-oxaudit-durable-scan-foundation.md and docs/superpowers/plans/2026-08-20-oxaudit-source-results-workflow.md

## Global Constraints

- The visible product name is oxAudit; package/executable identity is oxaudit; Rust library identity is oxaudit_lib; bundle identifier is com.oxaudit.desktop; browser keys use oxaudit.*.
- Never return an existing credential value to React. The UI may submit a replacement transiently, then must clear it.
- SQLite and settings JSON contain only provider configuration, credential references/presence, and no credential values.
- Credential migration verifies protected storage before sanitizing either new or legacy settings.
- If credential migration fails, the legacy plaintext source remains untouched and migration stays incomplete with a retry path.
- The retained legacy backup contains sessions and non-secret settings but no plaintext credentials after successful migration.
- Migration steps are checkpointed, idempotent, restart-safe, and never overwrite newer oxAudit data.
- Existing oxAudit data wins conflicts; every conflict is reported.
- Settings uses one explicit Save changes action with dirty-category indicators and discard protection.
- Provider connection tests do not save unrelated drafts.
- Default run retention is 20 completed runs per project and 90 days; reviews survive run deletion.
- Export/delete UI identifies one run, one project, or all local data and confirms the exact target.
- No release, upload, notarization, store submission, or legacy-backup deletion is authorized by this plan.
- Preserve the existing untracked artifacts/ directory and never stage it.
- Before every commit, inspect git status and the staged diff, then stage only paths named by the current task. Do not absorb unrelated user changes through directory-wide staging.
- Until Task 4 migration passes, run native/intermediate builds only with disposable config/data roots. The Task 3 save guard prevents plaintext loss, but no intermediate commit is authorized to operate on a real legacy profile.

## Dependency References

- rusqlite bundled build guidance: https://docs.rs/crate/rusqlite/latest
- keyring native-store wrapper and v1 API: https://github.com/open-source-cooperative/keyring-rs
- Tauri app_config_dir and app_data_dir identifier behavior: https://docs.rs/tauri/latest/tauri/path/struct.PathResolver.html
- Tauri native close-request interception and required unlisten lifecycle: https://v2.tauri.app/reference/javascript/api/namespacewindow/#oncloserequested

## Release-Safety Constraint

Tauri app-specific config, data, and webview locations are derived from the bundle identifier. Rust can directly migrate the old config/data directories, but browser localStorage is controlled by the webview data location. Therefore:

1. implement and test the legacy browser-cache exporter while the development build can still read vc.* keys;
2. persist that non-secret cache snapshot in the old config directory;
3. only then change the bundle identifier in source;
4. if VulnCompanion has existing distributed installations, ship the cache-exporting compatibility build before publishing a build with com.oxaudit.desktop.

Execution may build and test both stages locally. Publishing either stage requires separate user authorization.

## File Structure

### New Rust files

- src-tauri/src/credentials.rs — credential kind, trait, keyring adapter, in-memory test adapter, and zeroizing resolution.
- src-tauri/src/migration.rs — checkpointed identity, settings, session, credential, and browser-cache migration.
- src-tauri/src/data_management.rs — storage status, JSON export, scoped deletion, backup removal, and retention commands.

### Existing Rust files modified

- src-tauri/src/settings.rs — atomic sanitized settings repository and secure save orchestration.
- src-tauri/src/models.rs — public AiSettings, CredentialPresence, CredentialMutation, SaveSettingsRequest, RetentionSettings, and internal ResolvedAiSettings.
- src-tauri/src/ai/mod.rs — consume ResolvedAiSettings.
- src-tauri/src/agent/loop_engine.rs and src-tauri/src/commands.rs — resolve credentials per AI/CVE/Binary operation.
- src-tauri/src/cve.rs and src-tauri/src/binscan/scan.rs — receive short-lived NVD credentials without public settings fields.
- src-tauri/src/sessions.rs — explicit path constructor, atomic index writes, and owner-only permissions.
- src-tauri/src/lib.rs — migration before settings/database authority, credential service state, and command registration.
- src-tauri/Cargo.toml and src-tauri/Cargo.lock — keyring and zeroize.

### New frontend files

- src/features/settings/model.ts — categories, deep clone, dirty-category calculation, validation, and credential mutations.
- src/features/settings/SettingsNavigation.tsx — category sidebar and dirty indicators.
- src/features/settings/GeneralSettings.tsx — appearance controls and theme preview.
- src/features/settings/AiProviderSettings.tsx — endpoint/model plus write-only credential replacement.
- src/features/settings/ScanFindingSettings.tsx — scan defaults, finding defaults, retention, and active project-policy status.
- src/features/settings/DataSourcesSettings.tsx — NVD key and binary-tool paths/runtime.
- src/features/settings/DataPrivacySettings.tsx — data location, export, deletion, migration status, and backup removal.
- src/features/settings/useSettingsLeaveGuard.ts — app-page and window discard protection.
- src/lib/browserMigration.ts — vc.* cache export/import and oxaudit.* seeding.

### Existing frontend/configuration files modified

- src/pages/SettingsPage.tsx — category coordinator and single save.
- src/lib/types.ts and src/lib/api.ts — sanitized settings, credential, migration, and data-management DTOs.
- src/lib/settingsRequests.ts — secure save request serialization and readiness behavior.
- tests/settingsRequests.test.ts — updated secure save contract.
- src/lib/stores.ts and src/lib/theme.ts — guarded page navigation and oxaudit.* keys.
- src/App.tsx — browser-cache preflight and migration status load.
- src/components/Sidebar.tsx — guarded navigation.
- package.json and package-lock.json — oxaudit package identity.
- src-tauri/Cargo.toml, src-tauri/Cargo.lock, src-tauri/src/main.rs, src-tauri/examples/scan_tree.rs — Rust identity.
- src-tauri/tauri.conf.json — com.oxaudit.desktop.
- README.md, NOTICE, index.html, prompts, user agent, and remaining product copy — complete identity.
- src/index.css and src/components/ProgressBar.tsx — rename vc-prefixed animation identifiers and their consumers.

### New tests

- tests/settingsModel.test.ts
- tests/settingsLeaveGuard.test.ts
- tests/browserMigration.test.ts
- Rust tests colocated in credentials.rs, settings.rs, migration.rs, and data_management.rs.

---

### Task 1: Separate public settings from runtime credentials

**Files:**
- Modify: src-tauri/src/models.rs:210-327
- Modify: src/lib/types.ts:155-188
- Create: src-tauri/src/credentials.rs
- Modify: src-tauri/Cargo.toml
- Modify: src-tauri/Cargo.lock

**Interfaces:**
- Consumes: legacy AiSettings.api_key and AppSettings.nvd_api_key only during migration.
- Produces: CredentialKind, CredentialStore, KeyringCredentialStore, MemoryCredentialStore, CredentialPresence, CredentialMutation, SaveSettingsRequest, SaveSettingsResult, TestAiRequest, and ResolvedAiSettings.

- [ ] **Step 1: Add credential dependencies and write adapter tests**

Add:

~~~toml
keyring = "4.1.6"
zeroize = "1.9.0"
~~~

Test the memory adapter:

~~~rust
#[test]
fn memory_store_sets_reads_and_deletes_without_serializing_values() {
    let store = MemoryCredentialStore::default();
    store.set(CredentialKind::AiProvider, "canary-key").unwrap();
    assert_eq!(store.get(CredentialKind::AiProvider).unwrap().as_deref(), Some("canary-key"));
    store.delete(CredentialKind::AiProvider).unwrap();
    assert_eq!(store.get(CredentialKind::AiProvider).unwrap(), None);
    assert!(!format!("{store:?}").contains("canary-key"));
}
~~~

- [ ] **Step 2: Run the test and observe the missing module**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml credentials
~~~

Expected: FAIL because credentials.rs is absent.

- [ ] **Step 3: Define the protected-store interface**

~~~rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind { AiProvider, Nvd }

impl CredentialKind {
    fn account(self) -> &'static str {
        match self {
            Self::AiProvider => "ai-provider-api-key",
            Self::Nvd => "nvd-api-key",
        }
    }
}

pub trait CredentialStore: Send + Sync {
    fn get(&self, kind: CredentialKind) -> Result<Option<zeroize::Zeroizing<String>>, CommandError>;
    fn set(&self, kind: CredentialKind, value: &str) -> Result<(), CommandError>;
    fn delete(&self, kind: CredentialKind) -> Result<(), CommandError>;
}
~~~

KeyringCredentialStore uses service com.oxaudit.desktop and kind.account(). Treat keyring NoEntry as Ok(None); map all other platform errors to the foundation's reserved CredentialUnavailable code without embedding the secret or platform payload in the public message. Use the already-reserved CredentialRollbackFailed, MigrationFailed, and DataOperationFailed codes for the later services so Rust and TypeScript retain one closed error contract.

- [ ] **Step 4: Define sanitized public settings**

Use:

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPresence {
    pub ai_api_key: bool,
    pub nvd_api_key: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "action", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CredentialMutation {
    Unchanged,
    Replace { value: String },
    Delete,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SaveSettingsRequest {
    pub settings: AppSettings,
    pub ai_api_key: CredentialMutation,
    pub nvd_api_key: CredentialMutation,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SaveSettingsResult {
    pub settings: AppSettings,
    pub maintenance_warning: Option<String>,
}

#[derive(Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TestAiRequest {
    pub settings: AiSettings,
    pub ai_api_key: CredentialMutation,
}

pub struct ResolvedAiSettings {
    pub config: AiSettings,
    pub api_key: Option<zeroize::Zeroizing<String>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionSettings {
    pub max_completed_runs_per_project: u32,
    pub max_age_days: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingPreferences {
    pub default_result_view: String,
    pub default_review_expiry_days: Option<u32>,
}
~~~

Remove api_key from public AiSettings and nvd_api_key from public AppSettings. Add serde-defaulted credentials: CredentialPresence, retention: RetentionSettings, and findings: FindingPreferences so sanitized pre-feature files remain loadable. Retention defaults to 20 completed runs and 90 days; finding preferences default to open and no automatic expiry. Validate default_result_view against open, otherScopes, closed, and resolved; validate an expiry default, when present, in 1..=3650 days. ResolvedAiSettings is non-serializable and contains an optional Zeroizing<String> API key plus cloned public AI configuration. Do not add deny_unknown_fields: the later migration must still inspect legacy apiKey/nvdApiKey from the raw JSON before sanitization.

- [ ] **Step 5: Mirror the safe DTOs in TypeScript**

~~~ts
export interface CredentialPresence {
  aiApiKey: boolean;
  nvdApiKey: boolean;
}

export type CredentialMutation =
  | { action: "unchanged" }
  | { action: "replace"; value: string }
  | { action: "delete" };

export interface RetentionSettings {
  maxCompletedRunsPerProject: number;
  maxAgeDays: number;
}

export interface FindingPreferences {
  defaultResultView: "open" | "otherScopes" | "closed" | "resolved";
  defaultReviewExpiryDays: number | null;
}

export interface SaveSettingsRequest {
  settings: AppSettings;
  aiApiKey: CredentialMutation;
  nvdApiKey: CredentialMutation;
}

export interface SaveSettingsResult {
  settings: AppSettings;
  maintenanceWarning: string | null;
}

export interface TestAiRequest {
  settings: AiSettings;
  aiApiKey: CredentialMutation;
}
~~~

AiSettings no longer has apiKey. AppSettings no longer has nvdApiKey and gains credentials, retention, and findings.

- [ ] **Step 6: Verify and commit the secure contract**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml credentials
npm run check
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/credentials.rs src-tauri/src/models.rs src/lib/types.ts
git commit -m "feat(settings): separate credentials from configuration"
~~~

---

### Task 2: Resolve credentials only for the operation that needs them

**Files:**
- Modify: src-tauri/src/ai/mod.rs:1-460
- Modify: src-tauri/src/agent/loop_engine.rs
- Modify: src-tauri/src/commands.rs
- Modify: src-tauri/src/cve.rs
- Modify: src-tauri/src/binscan/scan.rs
- Modify: src-tauri/src/lib.rs

**Interfaces:**
- Consumes: Arc<dyn CredentialStore>, public AppSettings.
- Produces: resolve_ai_settings, resolve_nvd_key, and operation-scoped Zeroizing credentials.

- [ ] **Step 1: Write resolution tests**

Test configured AI with stored key, configured AI without key, explicit draft replacement for Test connection, explicit Delete for an unauthenticated endpoint, and an unavailable credential store. Assert public AppSettings JSON, typed command errors, captured tracing output, and Debug output from public state never contain the canary.

- [ ] **Step 2: Run the tests and verify the old AiSettings API fails them**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml credential_resolution
~~~

Expected: FAIL because AI and NVD clients still read public plaintext fields.

- [ ] **Step 3: Switch AI internals to ResolvedAiSettings**

Every AiClient method receives &ResolvedAiSettings. bearer_auth reads the Zeroizing key only while constructing the request. analyze_finding_messages receives public AI configuration separately when it needs only the system prompt.

Add:

~~~rust
fn resolve_ai_settings(
    public: &AiSettings,
    store: &dyn CredentialStore,
    mutation: Option<&CredentialMutation>,
) -> Result<ResolvedAiSettings, CommandError>;
~~~

Unchanged resolves stored; Replace uses a transient Zeroizing clone without persisting during Test; Delete resolves no key.

- [ ] **Step 4: Resolve NVD credentials per request**

Remove the long-lived CveState.api_key mutation from settings save. CVE and Binary commands call resolve_nvd_key immediately before an outbound request and pass Option<&str> through the existing request context. The key is dropped after the operation.

- [ ] **Step 5: Put the credential service in managed app state**

AppState contains Arc<dyn CredentialStore>. Production initialization uses KeyringCredentialStore; unit tests inject MemoryCredentialStore. No command returns the store or resolved key.

- [ ] **Step 6: Verify and commit runtime resolution**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml credential_resolution
cargo test --manifest-path src-tauri/Cargo.toml ai::
cargo check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/ai/mod.rs src-tauri/src/agent/loop_engine.rs src-tauri/src/commands.rs src-tauri/src/cve.rs src-tauri/src/binscan/scan.rs src-tauri/src/lib.rs
git commit -m "feat(settings): resolve credentials per operation"
~~~

Review staged files before commit and exclude unrelated files plus artifacts/.

---

### Task 3: Make settings writes atomic and credential-aware

**Files:**
- Modify: src-tauri/src/settings.rs:1-35
- Modify: src-tauri/src/commands.rs:1321-1373
- Modify: src-tauri/src/lib.rs:20-82
- Modify: src/lib/api.ts
- Modify: src/lib/settingsRequests.ts
- Modify: tests/settingsRequests.test.ts

**Interfaces:**
- Consumes: SaveSettingsRequest and CredentialStore.
- Produces: SettingsService::load_public, save_secure, test_ai_draft, SaveSettingsResult, and atomic_write_json.

- [ ] **Step 1: Write success, rollback, and disclosure tests**

Cover:

- Replace both credentials plus config succeeds;
- settings JSON contains presence booleans but neither canary value;
- a settings-file write failure restores both prior credentials;
- a credential set failure leaves settings byte-identical;
- a failed rollback returns CredentialRollbackFailed and a safe recovery message;
- load reconciles stale presence booleans against actual keyring entries;
- test_ai_draft never changes settings or protected credentials.
- a retention failure after a successful settings write returns the saved settings plus a sanitized maintenance warning, not a false save failure.
- a legacy settings file that still contains plaintext apiKey or nvdApiKey makes secure save return retryable MigrationFailed before any credential/file mutation.

- [ ] **Step 2: Run the tests and observe failure**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml settings::tests
~~~

Expected: FAIL because SettingsService and secure save are absent.

- [ ] **Step 3: Implement atomic sanitized JSON writes**

atomic_write_json writes a unique .settings.json.<uuid>.tmp beside settings.json with create_new, mode 0600 on Unix, pretty JSON plus newline, sync_all, deserializes the temporary file, renames over settings.json, and syncs the parent directory where supported. A failed write removes only the file created by that attempt; a stale temp from a killed process cannot block a later save.

- [ ] **Step 4: Implement credential-aware save ordering**

save_secure:

1. inspect raw settings JSON field names only; if plaintext legacy credential fields exist, return MigrationFailed and preserve the file byte-for-byte for Task 4;
2. validate all public fields and retention range 1..=500 runs and 1..=3650 days;
3. read prior credentials into Zeroizing values;
4. apply requested credential mutations;
5. verify presence through CredentialStore.get;
6. create sanitized settings with verified presence;
7. atomically write settings;
8. on write failure, restore both prior credential states;
9. update in-memory public settings only after success;
10. trigger retention as separate maintenance work and place any sanitized failure in SaveSettingsResult.maintenance_warning without rolling back the already-saved settings.

Never log SaveSettingsRequest with Debug because Replace contains values.

- [ ] **Step 5: Replace command signatures**

~~~rust
#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    request: SaveSettingsRequest,
) -> Result<SaveSettingsResult, CommandError>;

#[tauri::command]
pub async fn test_ai_with(
    state: State<'_, AppState>,
    request: TestAiRequest,
) -> Result<AiStatus, CommandError>;
~~~

Remove get_ai_settings because load_settings already returns public AI configuration and credential presence.

Update api.saveSettings to accept SaveSettingsRequest and return SaveSettingsResult. For this incremental commit, keep the existing Settings page working by having savePersistedSettingsSnapshot wrap its AppSettings argument with Unchanged mutations, publish result.settings, and return the maintenance warning to its caller. Task 7 changes that helper to accept the full categorized secure request once credential controls exist. Add a regression test proving the legacy page path sends no Replace/Delete mutation and unwraps the sanitized result.

- [ ] **Step 6: Verify and commit secure persistence**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml settings::tests
cargo check --manifest-path src-tauri/Cargo.toml
npx tsx --test tests/settingsRequests.test.ts
npm run check
git add src-tauri/src/settings.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src/lib/api.ts src/lib/settingsRequests.ts tests/settingsRequests.test.ts
git commit -m "feat(settings): save sanitized settings atomically"
~~~

---

### Task 4: Build the checkpointed legacy-data migration

**Files:**
- Create: src-tauri/src/migration.rs
- Modify: src-tauri/src/sessions.rs
- Modify: src-tauri/src/findings/repository.rs
- Modify: src-tauri/Cargo.toml
- Modify: src-tauri/Cargo.lock
- Modify: src-tauri/src/commands.rs
- Modify: src-tauri/src/lib.rs
- Modify: src/lib/types.ts
- Modify: src/lib/api.ts

**Interfaces:**
- Consumes: base config/data directories, legacy identifier com.vulncompanion.app, current identifier com.oxaudit.desktop, CredentialStore.
- Produces: MigrationService::run, MigrationReport, MigrationCheckpoint, and retry_migration command.

- [ ] **Step 1: Write a complete legacy profile fixture**

The TempDir fixture contains:

- legacy settings.json with AI and NVD canary keys;
- sessions/sessions.json plus two JSONL transcripts;
- usage.json;
- app-data/findings.sqlite3 containing one completed run and review;
- browser-cache-export-v1.json;
- a newer oxAudit settings file and one conflicting session ID for conflict tests.

Assert the fixture itself contains canaries before migration so a false-negative test cannot pass.

Define a private Deserialize-only LegacyCredentialFields/LegacyAiFields shape in migration.rs for ai.apiKey and nvdApiKey. It must not derive Serialize or Debug. Parse credential strings directly into Zeroizing<String>, then drop the raw legacy value as soon as protected-store verification completes; never attempt to recover them through the sanitized public AppSettings type.

- [ ] **Step 2: Write migration outcome tests**

Cover clean migration, restart after every checkpoint, legacy database backup, non-conflicting database merge, project-path database conflict, newer-target conflict, credential-store failure, credential verification failure, session transcript conflict, corrupt session index, sanitized backup, owner-only permissions, and second-run idempotence.

- [ ] **Step 3: Run the tests and observe the missing service**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml migration::tests
~~~

Expected: FAIL because migration.rs does not exist.

- [ ] **Step 4: Define checkpoint and report without secret fields**

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct MigrationCheckpoint {
    pub version: u16,
    pub profile_detected: bool,
    pub settings_copied: bool,
    pub sessions_merged: bool,
    pub findings_database_merged: bool,
    pub browser_cache_copied: bool,
    pub credentials_imported: bool,
    pub new_settings_validated: bool,
    pub legacy_settings_sanitized: bool,
    pub do_not_remigrate: bool,
    pub completed: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MigrationStatus {
    NotNeeded,
    InProgress,
    Blocked,
    Completed,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    pub status: MigrationStatus,
    pub conflicts: Vec<String>,
    pub legacy_backup_path: Option<String>,
    pub retryable: bool,
}
~~~

Checkpoint and conflict strings include paths/IDs only, never settings contents or credential values.

Mirror the report exactly in src/lib/types.ts:

~~~ts
export type MigrationStatus = "notNeeded" | "inProgress" | "blocked" | "completed";

export interface MigrationReport {
  status: MigrationStatus;
  conflicts: string[];
  legacyBackupPath: string | null;
  retryable: boolean;
}
~~~

Add api.getMigrationStatus() -> invoke<MigrationReport>("get_migration_status") and api.retryMigration() -> invoke<MigrationReport>("retry_migration"). Both commands re-read the checkpoint rather than trusting frontend state.

- [ ] **Step 5: Implement the exact migration order**

1. Resolve old/new config as config_dir/com.vulncompanion.app and config_dir/com.oxaudit.desktop; resolve old/new data with the same identifiers under data_dir.
2. If a validated completed checkpoint has do_not_remigrate true, return Completed without inspecting or copying the retained legacy backup. Otherwise, if no old directory exists, write a completed no-profile checkpoint.
3. Merge non-secret settings without overwriting newer new values.
4. Merge session metadata by ID; copy missing transcripts; record conflicts and keep newer target files.
5. Migrate findings.sqlite3 before the new repository opens.
6. Copy the staged browser-cache export if present.
7. Import legacy AI/NVD keys only when the protected entry is absent.
8. Read the protected values back into Zeroizing values and compare them exactly without logging either side.
9. Atomically write and validate sanitized new settings.
10. Atomically rewrite legacy settings without apiKey/nvdApiKey while preserving non-secret recovery fields.
11. apply 0700/0600 permissions where supported.
12. mark completed.

Write checkpoint after each successful step. On restart, validate a completed step before skipping it.

For database migration, enable rusqlite's backup feature:

~~~toml
rusqlite = { version = "0.40.2", features = ["bundled", "backup"] }
~~~

When the target database is absent, open the legacy database before the app service, run schema migration validation, and copy it with rusqlite::backup::Backup into a new target database. This captures committed WAL content without copying -wal/-shm files directly. When both databases exist, merge in one target transaction: copy projects whose canonical_path is absent, then their scan_runs, findings, and append-only reviews; retain target rows on every ID/path conflict and add a sanitized conflict entry. Run foreign_key_check before commit. Never open the findings service until the migrated target passes integrity_check.

- [ ] **Step 6: Make session index writes atomic**

Replace fs::write in SessionStore::save_index with the shared atomic writer. Add SessionStore::at_dir(path) for migration tests and apply owner-only permissions to session directory, index, and transcripts.

- [ ] **Step 7: Run migration before authoritative settings load**

In Tauri setup:

1. initialize CredentialStore;
2. run or resume config, findings-database, and browser-cache migration;
3. initialize SettingsService from new config;
4. initialize FindingsState from the new database only for Completed or NotNeeded; otherwise install an unavailable FindingsState carrying a safe retryable MigrationFailed error;
5. expose MigrationReport to the frontend.

If migration is blocked, non-Source tools remain launchable, Settings shows the report, and legacy data remains untouched.

- [ ] **Step 8: Verify and commit migration**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml migration::tests
cargo test --manifest-path src-tauri/Cargo.toml sessions::tests
cargo check --manifest-path src-tauri/Cargo.toml
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/migration.rs src-tauri/src/sessions.rs src-tauri/src/findings/repository.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src/lib/types.ts src/lib/api.ts
git commit -m "feat(settings): migrate legacy profile safely"
~~~

---

### Task 5: Export and import legacy browser caches

**Files:**
- Create: src/lib/browserMigration.ts
- Create: tests/browserMigration.test.ts
- Modify: src/App.tsx:40-75
- Modify: src/lib/theme.ts:1-105
- Modify: src/lib/stores.ts:37-71
- Modify: src/lib/api.ts
- Modify: src-tauri/src/commands.rs

**Interfaces:**
- Consumes: vc.themePreference, vc.recentScans, migrated settings, durable recent source projects.
- Produces: exportLegacyBrowserCache, importBrowserCache, seedAuthoritativeBrowserCache, and stage_browser_cache_migration.

- [ ] **Step 1: Write storage-adapter tests**

Use an in-memory Storage implementation. Cover:

- old key copied only when new key is absent;
- new key wins conflicts;
- malformed old JSON is reported and not copied;
- export allowlists only themePreference and recentScans;
- import never deletes old keys;
- authoritative theme and durable source history seed missing new keys;
- second execution is idempotent.

- [ ] **Step 2: Run the tests and observe the missing module**

~~~bash
npx tsx --test tests/browserMigration.test.ts
~~~

Expected: FAIL because browserMigration.ts is absent.

- [ ] **Step 3: Define the new keys and allowlisted snapshot**

~~~ts
export const THEME_CACHE_KEY = "oxaudit.themePreference";
export const RECENT_CACHE_KEY = "oxaudit.recentScans";

export interface BrowserCacheSnapshotV1 {
  version: 1;
  themePreference: "dark" | "light" | "system" | null;
  recentScans: RecentScan[];
}
~~~

Validate each RecentScan field and cap the array at 12. No arbitrary localStorage key is exported.

- [ ] **Step 4: Stage the compatibility snapshot in Rust**

stage_browser_cache_migration receives BrowserCacheSnapshotV1, validates it again, and atomically writes browser-cache-export-v1.json in the current config directory with mode 0600. It returns no file contents.

App startup calls exportLegacyBrowserCache while old keys are accessible and stages it. After migration/new identity, importBrowserCache reads the migrated snapshot through a backend command, writes only oxaudit.* keys, then seeds missing authoritative values from AppSettings.theme and listSourceProjects.

- [ ] **Step 5: Keep browser caches non-authoritative**

Theme boot caching may use oxaudit.themePreference, but settings JSON wins after load. Dashboard recent activity may use oxaudit.recentScans, but Source target/history always uses SQLite. A cache import error never blocks scanning or Settings.

- [ ] **Step 6: Verify and commit the browser bridge**

~~~bash
npx tsx --test tests/browserMigration.test.ts
npm run check
npm run build
git add src/lib/browserMigration.ts src/App.tsx src/lib/theme.ts src/lib/stores.ts src/lib/api.ts src-tauri/src/commands.rs tests/browserMigration.test.ts
git commit -m "feat(settings): bridge legacy browser caches"
~~~

---

### Task 6: Build categorized settings draft state and leave protection

**Files:**
- Create: src/features/settings/model.ts
- Create: src/features/settings/useSettingsLeaveGuard.ts
- Create: tests/settingsModel.test.ts
- Create: tests/settingsLeaveGuard.test.ts
- Modify: src/lib/stores.ts
- Modify: src/components/Sidebar.tsx

**Interfaces:**
- Consumes: persisted AppSettings and transient credential inputs.
- Produces: SettingsCategory, SettingsDraft, dirtyCategories, validateSettings, buildSaveRequest, and guarded page navigation.

- [ ] **Step 1: Write dirty-category and validation tests**

Test that:

- theme changes only General;
- endpoint/model changes only AI provider;
- scan defaults change only Scanning and findings;
- default result-view or review-expiry changes only Scanning and findings;
- retention changes only Data and privacy;
- NVD/binary changes only Data sources and tools;
- credential replacement marks its category dirty without entering AppSettings;
- reverting to initial values clears dirty;
- run count outside 1..=500, retention age outside 1..=3650, and review expiry outside 1..=3650 return field errors;
- cloneSettings does not share ignoredDirs.

- [ ] **Step 2: Write leave-guard tests**

Use fake navigation, confirmation, and close-listener adapters. Assert clean navigation never prompts, dirty navigation prompts once, Cancel retains Settings, Discard clears draft and navigates, a dirty native close calls event.preventDefault when Cancel is chosen, and unmount invokes the close listener's unlisten function exactly once.

- [ ] **Step 3: Run the tests and observe missing models**

~~~bash
npx tsx --test tests/settingsModel.test.ts tests/settingsLeaveGuard.test.ts
~~~

Expected: FAIL because the new settings feature files are absent.

- [ ] **Step 4: Define category and draft state**

~~~ts
export type SettingsCategory =
  | "general"
  | "aiProvider"
  | "scanFindings"
  | "dataSources"
  | "dataPrivacy";

export interface SecretDraft {
  action: "unchanged" | "replace" | "delete";
  value: string;
}

export interface SettingsDraft {
  initial: AppSettings;
  value: AppSettings;
  aiApiKey: SecretDraft;
  nvdApiKey: SecretDraft;
}
~~~

buildSaveRequest constructs allowlisted CredentialMutation values. It never spreads SecretDraft into settings.

- [ ] **Step 5: Add a single guarded navigation path**

Add requestPage(page) to the app store. Sidebar and every shell navigation control call requestPage instead of setPage. Settings registers a leave guard while dirty; the guard uses one confirm callback with the exact message Discard unsaved Settings changes? and clears transient credential values on discard.

The hook also registers getCurrentWindow().onCloseRequested while dirty. It uses the native dialog confirm from @tauri-apps/plugin-dialog; Cancel calls event.preventDefault(), while Discard allows the close request to continue and clears transient secret inputs. Await and retain the UnlistenFn, including the race where unmount occurs before listener registration resolves, so every installed listener is removed exactly once. A registration failure is surfaced as a non-blocking Settings warning while in-app navigation protection remains active.

- [ ] **Step 6: Preview theme without persisting it**

General theme selection applies data-theme for preview but remains a draft. On discard/unmount restore persisted theme. On successful Save, publish the returned settings and keep the selected theme. Remove immediate savePersistedThemePreference from Settings; shell-level theme changes outside Settings continue through the serialized settings service only if such controls exist.

- [ ] **Step 7: Verify and commit settings state**

~~~bash
npx tsx --test tests/settingsModel.test.ts tests/settingsLeaveGuard.test.ts tests/theme.test.ts
npm run check
git add src/features/settings/model.ts src/features/settings/useSettingsLeaveGuard.ts src/lib/stores.ts src/components/Sidebar.tsx tests/settingsModel.test.ts tests/settingsLeaveGuard.test.ts
git commit -m "feat(settings): add categorized draft state"
~~~

Review staged tests and exclude unrelated files.

---

### Task 7: Build the five Settings categories

**Files:**
- Create: src/features/settings/SettingsNavigation.tsx
- Create: src/features/settings/GeneralSettings.tsx
- Create: src/features/settings/AiProviderSettings.tsx
- Create: src/features/settings/ScanFindingSettings.tsx
- Create: src/features/settings/DataSourcesSettings.tsx
- Create: src/features/settings/DataPrivacySettings.tsx
- Modify: src/pages/SettingsPage.tsx:1-775
- Modify: src/lib/settingsRequests.ts
- Modify: tests/settingsRequests.test.ts

**Interfaces:**
- Consumes: SettingsDraft, validation, secure settings APIs, migration/data status.
- Produces: categorized Settings page with one Save changes action and category-local feedback.

- [ ] **Step 1: Create the navigation contract**

~~~tsx
export function SettingsNavigation(props: {
  value: SettingsCategory;
  dirty: Set<SettingsCategory>;
  errors: Set<SettingsCategory>;
  onChange(category: SettingsCategory): void;
}): JSX.Element;
~~~

Render a labeled navigation list, aria-current on the active category, a text Unsaved badge for dirty categories, and a text Error badge where validation fails.

- [ ] **Step 2: Move existing controls by ownership**

- General: dark/light/system appearance.
- AI provider: enable, base URL, write-only API key replacement, model, temperature, timeout, max tokens, system prompt, Test connection.
- Scanning and findings: secret/vulnerability defaults, git/symlink/file size, ignored directories, default result view, default review-expiry days, and active project-policy status plus fixed safety behavior. The page explains that policy writes and invalid-policy scan overrides always require an explicit Source Scan action; no global setting can silently weaken either guard.
- Data sources and tools: write-only NVD key replacement, cve-bin-tool runtime/path, grype path, tool readiness.
- Data and privacy: run-retention count/age, data location, usage totals, migration report, export, deletion, and legacy backup.

- [ ] **Step 3: Make credentials write-only**

Credential inputs start blank and show Stored securely when presence is true. Buttons are Replace or Remove. Use type password, autoComplete off, spellCheck false. Never populate value from AppSettings. Clear input on successful save, discard, and unmount.

- [ ] **Step 4: Update secure save serialization**

savePersistedSettingsSnapshot receives SaveSettingsRequest and publishes api.saveSettings(...).settings from SaveSettingsResult. Preserve the existing serialized write queue and latest readiness generation. A failed save publishes neither draft settings nor credential presence. A successful save with maintenanceWarning still publishes the returned settings and shows the warning beside retention controls; it is not mislabeled as an unsaved draft. Task 8 adds the explicit retry action with the data-management API.

Update tests/settingsRequests.test.ts so overlapping secure saves publish returned sanitized snapshots in native completion order, failed saves preserve the last successful presence state, and maintenance warnings do not discard a successful result.

- [ ] **Step 5: Keep provider Test independent from Save**

Test connection sends public AI draft plus CredentialMutation for the AI key only. It does not persist configuration, change dirty state, or touch the NVD mutation. Show result beside AI provider controls.

- [ ] **Step 6: Replace the monolithic page**

SettingsPage owns activeCategory, SettingsDraft, validation, saving, test status, and migration/data queries. It renders a two-column category sidebar/content layout at desktop and a labeled category select below 900 px. ToolPage action text is Save changes. Reset affects only the active category and requires confirmation when it would clear a credential action.

- [ ] **Step 7: Verify and commit the Settings UI**

~~~bash
npx tsx --test tests/settingsModel.test.ts tests/settingsRequests.test.ts tests/settingsLeaveGuard.test.ts
npm run check
npm run build
git add src/features/settings/SettingsNavigation.tsx src/features/settings/GeneralSettings.tsx src/features/settings/AiProviderSettings.tsx src/features/settings/ScanFindingSettings.tsx src/features/settings/DataSourcesSettings.tsx src/features/settings/DataPrivacySettings.tsx src/pages/SettingsPage.tsx src/lib/settingsRequests.ts tests/settingsRequests.test.ts
git commit -m "feat(settings): build categorized secure settings"
~~~

---

### Task 8: Add data export, deletion, retention, and backup controls

**Files:**
- Create: src-tauri/src/data_management.rs
- Modify: src-tauri/src/commands.rs
- Modify: src-tauri/src/lib.rs
- Modify: src-tauri/src/findings/repository.rs
- Modify: src-tauri/src/migration.rs
- Modify: src/lib/types.ts
- Modify: src/lib/api.ts
- Modify: src/lib/stores.ts
- Modify: src/App.tsx
- Modify: src/features/settings/DataPrivacySettings.tsx

**Interfaces:**
- Consumes: FindingsRepository, settings/config/session/data paths, MigrationReport.
- Produces: get_data_status, apply_retention_now, export_local_data, delete_local_data, open_data_directory, and remove_legacy_backup.

- [ ] **Step 1: Write scoped data-management tests**

Use only TempDir paths. Test manual retention success/failure; export one run, one project, and all local data; delete one run, one project, and all local data; review survival after run deletion; project deletion removes its reviews; all-local deletion clears findings, reviews, settings, sessions, usage, and protected credentials; restart after every all-local deletion checkpoint; partial credential/file failures and idempotent retry; retained-backup non-remigration; optional legacy-backup removal; path containment; backup removal refusal before completed migration; and no secret or provider-credential canary in exports.

- [ ] **Step 2: Run tests and observe the missing module**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml data_management
~~~

Expected: FAIL because data_management.rs is absent.

- [ ] **Step 3: Define explicit target types**

~~~rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DataTarget {
    Run { run_id: String },
    Project { project_id: String },
    AllLocalData { remove_legacy_backup: bool },
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DataStatus {
    pub data_directory: String,
    pub database_bytes: u64,
    pub project_count: usize,
    pub completed_run_count: usize,
    pub legacy_backup_path: Option<String>,
    pub migration_status: MigrationStatus,
    pub deletion_in_progress: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataOperationResult {
    pub reset_browser_caches: bool,
    pub reset_runtime_state: bool,
    pub settings: AppSettings,
    pub data_status: DataStatus,
}
~~~

Mirror DataTarget, DataStatus, and DataOperationResult in src/lib/types.ts. Add typed api.getDataStatus, applyRetentionNow, exportLocalData, deleteLocalData, openDataDirectory, and removeLegacyBackup calls. applyRetentionNow returns DataStatus on success and a retryable typed error on failure. deleteLocalData and removeLegacyBackup return DataOperationResult. After either response, React clears oxaudit.* browser keys only when resetBrowserCaches is true. When resetRuntimeState is true, App clears active project, active Assistant session/transcript, cached recent scans, and any mounted Source run through one app-store resetLocalRuntimeState action before publishing the returned sanitized settings/data status.

- [ ] **Step 4: Export allowlisted sanitized JSON**

The frontend save dialog supplies a destination file chosen by the user. Backend canonicalizes the destination parent and writes atomically. Run and project exports contain project/run metadata, sanitized observations, and review metadata; they exclude settings, session contents, raw internal errors, absolute project paths, and secret context. AllLocalData additionally contains sanitized settings, sessions, usage totals, migration status, and every sanitized project/run/review, but never protected credential values or unsanitized legacy settings.

- [ ] **Step 5: Implement exact deletion boundaries**

Run deletion and project deletion each use one database transaction. Run deletes one scan_runs row and its observations; reviews survive. Project deletes the project, all runs, findings, and reviews after exact project-ID confirmation.

AllLocalData is a restart-safe multi-resource deletion, not a false claim of cross-filesystem atomicity. Before changing state, atomically create data-deletion-checkpoint-v1.json with a version, remove_legacy_backup choice, and booleans for credentials_deleted, findings_cleared, sessions_deleted, usage_deleted, settings_reset, browser_reset_required, legacy_backup_handled, and completed. After each idempotent step, validate and atomically update the checkpoint. A failure returns retryable DataOperationFailed, leaves deletionInProgress true, and the UI offers Retry deletion; it never reports full success for a partial delete.

The exact order is: delete both protected credentials, clear project/run/finding/review tables in one transaction, delete sessions, delete usage, reset sanitized settings, mark browser reset required, optionally remove the validated legacy backup, write a sanitized completed migration tombstone that forbids re-import from the retained legacy backup, then complete deletion. A restart resumes the same choice and validates completed steps. After preparing the successful response, remove the completed deletion checkpoint; a completed checkpoint left by a crash is safely finalized on the next status/read or retry. Run/project operations return both reset flags false; successful AllLocalData returns both true and leaves an empty migrated schema so the running app can return to first-run state without deleting an open SQLite file. Keep only the non-secret completed migration tombstone needed to prevent deleted legacy data from being resurrected; do not treat the retained backup as a migration source again.

remove_legacy_backup accepts no arbitrary path; it uses the validated path from completed MigrationReport, verifies the directory name is com.vulncompanion.app under the platform config directory, and removes only that directory after frontend confirmation.

- [ ] **Step 6: Wire Data and privacy controls**

Each action shows its exact target and consequence. Destructive buttons open a confirmation dialog whose confirm label includes Delete run, Delete project, Delete all local data, or Remove legacy backup. All-local deletion requires typing oxAudit and separately shows whether the retained legacy backup will be removed. If DataStatus.deletionInProgress is true, disable conflicting data actions and show Retry deletion using the checkpointed choice. A retention maintenance warning shows Retry cleanup, which calls applyRetentionNow and refreshes DataStatus. Refresh DataStatus and public settings after success.

- [ ] **Step 7: Verify and commit data controls**

~~~bash
cargo test --manifest-path src-tauri/Cargo.toml data_management
npm run check
npm run build
git add src-tauri/src/data_management.rs src-tauri/src/findings/repository.rs src-tauri/src/migration.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src/lib/types.ts src/lib/api.ts src/lib/stores.ts src/App.tsx src/features/settings/DataPrivacySettings.tsx
git commit -m "feat(settings): add local data controls"
~~~

---

### Task 9: Complete the oxAudit identity rename

**Files:**
- Modify: package.json
- Modify: package-lock.json
- Modify: src-tauri/Cargo.toml
- Modify: src-tauri/Cargo.lock
- Modify: src-tauri/src/main.rs
- Modify: src-tauri/examples/scan_tree.rs
- Modify: src-tauri/tauri.conf.json
- Modify: src-tauri/src/models.rs
- Modify: src-tauri/src/commands.rs
- Modify: src-tauri/src/agent/tools.rs
- Modify: src-tauri/src/agent/loop_engine.rs
- Modify: src/index.css
- Modify: src/components/ProgressBar.tsx
- Modify: src/lib/theme.ts
- Modify: src/lib/stores.ts
- Modify: README.md
- Modify: NOTICE
- Modify: index.html

**Interfaces:**
- Consumes: completed migration and browser-cache bridge.
- Produces: canonical oxaudit/oxAudit/com.oxaudit.desktop identity with no live VulnCompanion runtime references.

- [ ] **Step 1: Add an identity contract test**

Create tests/identity.test.ts that scans runtime/configuration files and fails on:

- package name vulncompanion;
- Rust crate/library vulncompanion or vulncompanion_lib;
- com.vulncompanion.app outside migration.rs/tests;
- visible VulnCompanion outside migration copy;
- localStorage prefix vc. outside browserMigration.ts/tests;
- CSS animation prefix vc-.

Allow legacy strings only in migration implementation, migration tests, the approved historical docs, and release migration notes.

- [ ] **Step 2: Run the identity test and capture expected failures**

~~~bash
npx tsx --test tests/identity.test.ts
~~~

Expected: FAIL and list current package, Cargo, bundle, prompt, user-agent, README, browser-key, and animation references.

- [ ] **Step 3: Rename package and Rust identities**

Set package.json and package-lock root name to oxaudit. Set Cargo package name to oxaudit, description to oxAudit — local security research workbench, and lib name to oxaudit_lib. Update main.rs and scan_tree.rs imports. Regenerate Cargo.lock through cargo check; do not hand-edit dependency checksums.

- [ ] **Step 4: Change the bundle identifier only after migration tests pass**

Set:

~~~json
"productName": "oxAudit",
"identifier": "com.oxaudit.desktop"
~~~

Keep the existing window title. Confirm migration.rs still explicitly resolves com.vulncompanion.app from the platform base config/data directories.

- [ ] **Step 5: Rename runtime text and internal prefixes**

Set HTTP user agent to oxAudit/0.1 (security research). Change Rust/agent prompts to oxAudit. Replace DEFAULT_SYSTEM_PROMPT only when its persisted value exactly equals the legacy shipped default; preserve every customized prompt byte-for-byte. Keep the Rust and TypeScript new defaults identical. Rename vc-slide/vc-breathe keyframes and references to oxaudit-slide/oxaudit-breathe. Use oxaudit.themePreference and oxaudit.recentScans everywhere except the compatibility bridge.

- [ ] **Step 6: Update documentation and data-location copy**

README title becomes oxAudit — Security Research Workbench. Replace legacy config path guidance with com.oxaudit.desktop and add an Upgrade from VulnCompanion section describing automatic migration, sanitized backup, retry, and explicit backup removal. NOTICE remains oxAudit and retains third-party license statements.

- [ ] **Step 7: Verify and commit identity**

~~~bash
npx tsx --test tests/identity.test.ts
npm run check
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
git add package.json package-lock.json src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/main.rs src-tauri/examples/scan_tree.rs src-tauri/tauri.conf.json src-tauri/src/models.rs src-tauri/src/commands.rs src-tauri/src/agent/tools.rs src-tauri/src/agent/loop_engine.rs src/index.css src/components/ProgressBar.tsx src/lib/theme.ts src/lib/stores.ts README.md NOTICE index.html tests/identity.test.ts
git commit -m "refactor: complete oxAudit product identity"
~~~

Before committing, inspect git diff --cached --name-only and remove artifacts/ plus generated build directories from the index.

---

### Task 10: Verify clean install, direct migration, restart, and packaged app

**Files:**
- Create: docs/superpowers/qa/2026-08-20-oxaudit-settings-identity-migration.md
- Modify: docs/superpowers/plans/2026-08-20-oxaudit-settings-identity-migration.md (checkboxes only during execution)

**Interfaces:**
- Consumes: all settings, credential, migration, data, and identity tasks.
- Produces: final automated/native migration evidence and release readiness without publishing.

- [ ] **Step 1: Run the complete automated suite**

~~~bash
npm test
npm run check
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
~~~

Expected: every command exits 0 and no runtime identity test violation remains.

- [ ] **Step 2: Build a local compatibility-stage app**

Temporarily use a Tauri overlay config retaining com.vulncompanion.app without changing committed tauri.conf.json. Launch against a disposable legacy profile, verify browser-cache-export-v1.json is created, then close the app. Do not use or modify a real user profile.

- [ ] **Step 3: Build the renamed packaged app**

~~~bash
npm run tauri build -- --debug
~~~

Launch the generated oxAudit debug bundle with com.oxaudit.desktop.

- [ ] **Step 4: Verify clean install behavior**

With disposable empty config/data roots, launch, save each settings category, set and replace fake AI/NVD credentials, restart, and verify values are never displayed while presence remains accurate. Delete them and verify presence clears.

- [ ] **Step 5: Verify legacy migration behavior**

With the complete disposable legacy fixture and staged browser cache:

1. launch renamed oxAudit;
2. interrupt after each checkpoint in separate test runs;
3. relaunch and verify resume;
4. verify sessions, settings, theme cache, recent cache, and usage survive;
5. verify credentials work but never display;
6. verify old settings and retained backup contain no canary after success;
7. verify conflict report names conflicts without contents;
8. verify a second launch performs no duplicate migration.

- [ ] **Step 6: Verify failure recovery**

Use MemoryCredentialStore fault injection and read-only TempDir fixtures to simulate credential import, settings write, session merge, database open, and backup cleanup failures. Verify migration remains retryable, old data stays available, and non-Source tools launch.

- [ ] **Step 7: Verify Settings and data controls**

At 1440x900, 1180x760, and 900x700:

- navigate all five categories by keyboard;
- confirm dirty indicators and discard guard;
- confirm one Save changes action persists all category edits;
- confirm Test connection does not save;
- export a disposable run/project/all dataset and inspect for credential/secret canaries;
- delete run and verify review survives;
- remove the disposable legacy backup only after exact confirmation.

- [ ] **Step 8: Inspect at-rest files**

Search only the disposable test config/data roots for the AI, NVD, and scanner canaries. Expected: no match after successful migration. Verify directory/file modes on Unix and confirm findings.sqlite3, settings.json, session index/transcripts, checkpoints, and legacy backup are owner-only.

- [ ] **Step 9: Record QA evidence and commit**

Record dependency versions, app bundle path, bundle identifier, test profile roots, migration checkpoint outcomes, conflicts, canary search result, permissions, settings viewport checks, command exit codes, and confirmation that no release was published.

~~~bash
git add docs/superpowers/qa/2026-08-20-oxaudit-settings-identity-migration.md
git commit -m "docs: verify oxAudit settings migration"
~~~

## Final Completion Gate

The approved 2/3/4 scope is complete only when:

- Source Scan history, findings, and reviews survive restart;
- every candidate remains visible in a durable result view;
- credentials are protected by native secure storage and absent from JSON/SQLite/exports/logs;
- categorized Settings has truthful draft/save/test/discard behavior;
- retention, export, deletion, and backup controls respect exact targets;
- a legacy profile migrates and resumes safely from every checkpoint;
- the retained legacy backup is sanitized after success;
- runtime identity is consistently oxAudit/oxaudit/com.oxaudit.desktop;
- the packaged renamed app passes clean-install and migration smoke tests;
- no release or destructive real-profile cleanup has occurred without explicit user authorization.

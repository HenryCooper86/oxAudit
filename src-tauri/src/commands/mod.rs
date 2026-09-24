pub mod assistant;
pub mod cve;
pub mod dependencies;
pub mod history;
pub mod quality;
pub mod reporting;
pub mod schedule;
pub mod sessions;
pub mod settings;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_opener::OpenerExt;

use crate::agent::tools::TodoItem;
use crate::ai::usage::{UsageStore, UsageSummary};
use crate::ai::AiClient;
use crate::cve::CveState;
use crate::deps::osv::OsvClient;
use crate::findings::{
    domain::{
        ProjectContext, RecentProject, ReviewRecord, ReviewRequest, ReviewState, ScanRunDetail,
        ScanRunSummary,
    },
    error::CommandError,
    service::{FindingsService, FindingsState, ScanEventSink},
};
use crate::fs_utils;
use crate::models::{
    AppSettings, ChatRequest, ChatResponse, DependencyScanResult, LockfileInfo,
    SaveSettingsRequest, SaveSettingsResult, ScanOptions, ScanSettings, StreamStarted,
    TestAiRequest,
};

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleLibraryRuleStatus {
    id: String,
    title: String,
    severity: String,
    scope: Vec<String>,
    fixture_health: String,
    provenance: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleLibraryPackStatus {
    id: String,
    name: String,
    version: String,
    engine: String,
    enabled: bool,
    license: String,
    source: String,
    creation_method: String,
    content_sha256: String,
    validation: String,
    rules: Vec<RuleLibraryRuleStatus>,
    fixture_summary: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePackValidationPreview {
    id: String,
    name: String,
    version: String,
    content_sha256: String,
    rule_count: usize,
    engines: Vec<String>,
    fixture_count: usize,
    license: String,
    source: String,
    validation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityStatus {
    schema_version: u32,
    suite_id: String,
    suite_version: String,
    description: String,
    corpus_targets: usize,
    passed_targets: usize,
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
    precision: Option<f64>,
    recall: Option<f64>,
    runtime_ms: u64,
    misses: Vec<String>,
    unexpected: Vec<String>,
    limitation: String,
    previous_precision: Option<f64>,
    previous_recall: Option<f64>,
    regression: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSourceStatus {
    id: String,
    name: String,
    source_url: String,
    terms_url: String,
    license: String,
    state: String,
    supports_offline: bool,
    active_snapshot_id: Option<String>,
    fetched_at_ms: Option<u64>,
    content_sha256: Option<String>,
    record_count: Option<u64>,
    validation: String,
    limitation: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPreview {
    format: String,
    media_type: String,
    suggested_file_name: String,
    valid: bool,
    warnings: Vec<String>,
    artifacts: usize,
    components: usize,
    observations: usize,
    content: String,
    truncated: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    format: String,
    media_type: String,
    file_name: String,
    content_sha256: String,
    component_records: usize,
    finding_records: usize,
    review_records: usize,
    conflict_count: usize,
    conflicts: Vec<String>,
    unmapped_count: usize,
    unmapped_records: Vec<String>,
    warnings: Vec<String>,
    can_import_inventory: bool,
    mapped_claim_count: usize,
    mapped_claims: Vec<crate::adapters::reporting::import::ExternalClaim>,
    can_import_external_claims: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryIdentityView {
    method: String,
    value: String,
    confidence: f32,
    artifact_id: String,
    artifact_path: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryComponentView {
    id: String,
    name: String,
    version: Option<String>,
    supplier: Option<String>,
    ecosystem: Option<String>,
    purl: Option<String>,
    cpes: Vec<String>,
    aliases: Vec<String>,
    identities: Vec<InventoryIdentityView>,
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryView {
    run_id: String,
    target_label: String,
    run_kind: oxaudit_domain::RunKind,
    updated_at_ms: u64,
    provider_snapshot_count: usize,
    components: Vec<InventoryComponentView>,
}

fn report_data(
    service: &FindingsService,
    run_id: &oxaudit_domain::RunId,
) -> Result<crate::adapters::reporting::ReportData, String> {
    let run = service
        .repository()
        .canonical_load_run(run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "run was not found".to_string())?;
    let (artifacts, components, observations) = service
        .repository()
        .canonical_load_report_graph(run_id)
        .map_err(|error| error.to_string())?;
    let projection = service
        .repository()
        .canonical_load_projection(run_id)
        .map_err(|error| error.to_string())?;
    let findings = if matches!(
        run.kind,
        oxaudit_domain::RunKind::Source | oxaudit_domain::RunKind::Secrets
    ) {
        service
            .load_run(run_id.as_str())
            .map_err(|error| error.to_string())?
            .findings
    } else {
        Vec::new()
    };
    Ok(crate::adapters::reporting::ReportData {
        run,
        artifacts,
        components,
        observations,
        findings,
        projection,
    })
}

fn read_import_report(
    path: &str,
) -> Result<
    (
        PathBuf,
        Vec<u8>,
        crate::adapters::reporting::import::ImportAnalysis,
    ),
    String,
> {
    let path = Path::new(path)
        .canonicalize()
        .map_err(|error| format!("cannot resolve the report: {error}"))?;
    let metadata = path
        .metadata()
        .map_err(|error| format!("cannot inspect the report: {error}"))?;
    if !metadata.is_file() {
        return Err("the selected report is not a file".into());
    }
    if metadata.len() > crate::adapters::reporting::import::MAX_IMPORT_BYTES {
        return Err("the selected report exceeds the 16 MiB import limit".into());
    }
    let bytes = std::fs::read(&path).map_err(|error| format!("cannot read the report: {error}"))?;
    let analysis = crate::adapters::reporting::import::inspect(&bytes)?;
    Ok((path, bytes, analysis))
}

fn imported_component_conflicts(
    service: &FindingsService,
    analysis: &crate::adapters::reporting::import::ImportAnalysis,
) -> Result<Vec<String>, String> {
    let mut existing = std::collections::BTreeMap::<String, String>::new();
    for run in service
        .repository()
        .canonical_list_runs(None, 100)
        .map_err(|error| error.to_string())?
    {
        let (_, components, _) = service
            .repository()
            .canonical_load_report_graph(&run.id)
            .map_err(|error| error.to_string())?;
        for component in components {
            let key = component.purl.clone().unwrap_or_else(|| {
                format!(
                    "{}\0{}",
                    component.name.trim().to_ascii_lowercase(),
                    component
                        .version
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                )
            });
            existing.entry(key).or_insert_with(|| {
                format!(
                    "{} {} in {}",
                    component.name,
                    component.version.unwrap_or_default(),
                    run.target_label
                )
            });
        }
    }
    let mut conflicts = analysis
        .components
        .iter()
        .filter_map(|component| {
            existing.get(&component.conflict_key()).map(|matched| {
                format!(
                    "{} {} matches existing {}",
                    component.name,
                    component.version.as_deref().unwrap_or("version unknown"),
                    matched
                )
            })
        })
        .collect::<Vec<_>>();
    conflicts.sort();
    conflicts.dedup();
    Ok(conflicts)
}

struct DataSourceDefinition {
    id: &'static str,
    name: &'static str,
    source_url: &'static str,
    terms_url: &'static str,
    license: &'static str,
    supports_offline: bool,
    limitation: &'static str,
}

const DATA_SOURCES: [DataSourceDefinition; 5] = [
    DataSourceDefinition {
        id: "exploit-db",
        name: "Exploit-DB",
        source_url: crate::exploit::POC_URL,
        terms_url: "https://www.exploit-db.com/papers",
        license: "Exploit-DB records retain their source attribution",
        supports_offline: true,
        limitation: "The full index is cached locally and refreshed weekly; scans read the cached copy.",
    },
    DataSourceDefinition {
        id: "osv",
        name: "OSV",
        source_url: "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q",
        terms_url: "https://google.github.io/osv.dev/data/",
        license: "OSV records retain their source attribution",
        supports_offline: false,
        limitation: "Refresh validates and caches a representative record; dependency scans persist their exact query snapshots separately.",
    },
    DataSourceDefinition {
        id: "nvd",
        name: "NVD",
        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
        terms_url: "https://nvd.nist.gov/developers/terms-of-use",
        license: "US Government public data; NVD terms apply",
        supports_offline: false,
        limitation: "This health snapshot is not the complete NVD corpus; external binary database lifecycle remains separate.",
    },
    DataSourceDefinition {
        id: "cisa-kev",
        name: "CISA KEV",
        source_url: crate::exploit::KEV_URL,
        terms_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license: "US Government public data",
        supports_offline: true,
        limitation: "The full catalog is retained locally after a successful refresh.",
    },
    DataSourceDefinition {
        id: "epss",
        name: "FIRST EPSS",
        source_url: "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        terms_url: "https://www.first.org/epss/",
        license: "CC BY 4.0",
        supports_offline: false,
        limitation: "This health snapshot is a representative score, not the complete daily EPSS dataset.",
    },
];

fn data_source_statuses(service: &FindingsService) -> Result<Vec<DataSourceStatus>, String> {
    DATA_SOURCES
        .iter()
        .map(|definition| {
            let mut snapshot = service
                .repository()
                .provider_latest_snapshot(definition.id)
                .map_err(|error| error.to_string())?;
            if definition.id == "osv" && snapshot.is_none() {
                snapshot = service
                    .repository()
                    .provider_latest_snapshot("osv-query")
                    .map_err(|error| error.to_string())?;
            }
            let record_count = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.payload.get("recordCount"))
                .and_then(serde_json::Value::as_u64);
            Ok(DataSourceStatus {
                id: definition.id.into(),
                name: definition.name.into(),
                source_url: definition.source_url.into(),
                terms_url: definition.terms_url.into(),
                license: definition.license.into(),
                state: match &snapshot {
                    Some(_) if definition.supports_offline => "offlineReady".into(),
                    Some(_) => "onlineCached".into(),
                    None => "notRefreshed".into(),
                },
                supports_offline: definition.supports_offline,
                active_snapshot_id: snapshot.as_ref().map(|snapshot| snapshot.id.clone()),
                fetched_at_ms: snapshot.as_ref().map(|snapshot| snapshot.fetched_at_ms),
                content_sha256: snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.content_sha256.clone()),
                record_count,
                validation: if snapshot.is_some() {
                    "valid"
                } else {
                    "notRun"
                }
                .into(),
                limitation: definition.limitation.into(),
            })
        })
        .collect()
}

pub struct AppState {
    pub settings: Mutex<AppSettings>,
    pub credentials: Arc<dyn crate::credentials::CredentialStore>,
    pub http: reqwest::Client,
    pub ai: AiClient,
    /// Shared per-tool request budgets for network-backed assistant tools.
    pub tool_rate_limiter: crate::agent::rate_limit::ToolRateLimiter,
    pub osv: OsvClient,
    pub cancel_scan: AtomicBool,
    pub cancel_dependency_scan: AtomicBool,
    /// Cancellation for an in-flight cve-bin-tool run.
    pub cancel_binary_scan: Arc<AtomicBool>,
    /// run_id -> cancellation state for in-flight chat turns
    pub active_chats:
        Mutex<std::collections::HashMap<String, Arc<crate::agent::tool::RunCancellation>>>,
    /// run_id -> messages the user submitted while that turn was still running
    pub pending_steers:
        Mutex<std::collections::HashMap<String, Arc<crate::agent::tool::SteerQueue>>>,
    /// the project folder agent tools operate on
    pub active_project: Mutex<Option<PathBuf>>,
    /// pending HITL permission approvals: request_id -> answer channel
    pub pending_permissions:
        Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    /// pending `ask_user` interactions: request_id -> answers channel
    pub pending_interactions:
        Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<Value>>>,
    /// per-conversation todo lists
    pub todos: Mutex<std::collections::HashMap<String, Vec<TodoItem>>>,
}

impl AppState {
    pub fn new() -> Self {
        #[cfg(test)]
        let credentials: Arc<dyn crate::credentials::CredentialStore> =
            Arc::new(crate::credentials::MemoryCredentialStore::default());
        #[cfg(not(test))]
        let credentials: Arc<dyn crate::credentials::CredentialStore> =
            Arc::new(crate::credentials::KeyringCredentialStore);
        Self::with_credentials(credentials)
    }

    pub fn with_credentials(credentials: Arc<dyn crate::credentials::CredentialStore>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("oxAudit/0.1 (security research)")
            .gzip(true)
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            settings: Mutex::new(AppSettings::default()),
            credentials,
            http: http.clone(),
            ai: AiClient::new(http.clone()),
            tool_rate_limiter: crate::agent::rate_limit::ToolRateLimiter::oxaudit_defaults(),
            osv: OsvClient::new(http.clone()),
            cancel_scan: AtomicBool::new(false),
            cancel_dependency_scan: AtomicBool::new(false),
            cancel_binary_scan: Arc::new(AtomicBool::new(false)),
            active_chats: Mutex::new(std::collections::HashMap::new()),
            pending_steers: Mutex::new(std::collections::HashMap::new()),
            active_project: Mutex::new(None),
            pending_permissions: Mutex::new(std::collections::HashMap::new()),
            pending_interactions: Mutex::new(std::collections::HashMap::new()),
            todos: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

fn usage_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|d| d.join("usage.json"))
        .map_err(|error| format!("cannot resolve usage directory: {error}"))
}

// ---------------------------------------------------------------------------
// Source code + secret scanning
// ---------------------------------------------------------------------------

fn resolve_scan_finding_path(
    root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Result<PathBuf, String> {
    let root = root
        .as_ref()
        .canonicalize()
        .map_err(|error| format!("scan root is unavailable: {error}"))?;
    if !root.is_dir() {
        return Err("scan root is not a directory".into());
    }

    let relative_path = relative_path.as_ref();
    if relative_path.as_os_str().is_empty() {
        return Err("finding path is empty".into());
    }
    if relative_path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("finding path must be a contained relative path".into());
    }

    let candidate = root
        .join(relative_path)
        .canonicalize()
        .map_err(|error| format!("finding file is unavailable: {error}"))?;
    if !candidate.starts_with(&root) {
        return Err("finding path escapes the captured scan root".into());
    }
    if !candidate.is_file() {
        return Err("finding path does not identify a file".into());
    }
    Ok(candidate)
}

/// Open a scanner finding relative to the root captured in its scan result.
#[tauri::command]
pub fn open_scan_finding(
    app: AppHandle,
    state: State<'_, AppState>,
    root: String,
    relative_path: String,
    line: u32,
    column: u32,
) -> Result<(), String> {
    if line == 0 || column == 0 {
        return Err("Finding line and column must be positive.".into());
    }
    let root = Path::new(&root).canonicalize().map_err(|e| e.to_string())?;
    let path = resolve_scan_finding_path(&root, relative_path)?;
    let editor = state.settings.lock().unwrap().editor;
    match editor {
        crate::models::EditorPreference::System => app
            .opener()
            .open_path(path.to_string_lossy().into_owned(), None::<String>)
            .map_err(|error| format!("Finding file could not be opened: {error}")),
        crate::models::EditorPreference::Vscode => {
            crate::editor::open_vscode(&app, crate::editor::vscode_uri(&root, &path, line, column)?)
        }
    }
}

struct EffectiveScanOptions {
    include_git: bool,
    follow_symlinks: bool,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
    ignored_dirs: Vec<String>,
}

fn effective_scan_options(submitted: &ScanOptions, saved: &ScanSettings) -> EffectiveScanOptions {
    let mut ignored_dirs = saved.ignored_dirs.clone();
    ignored_dirs.extend(submitted.extra_ignored_dirs.iter().cloned());
    EffectiveScanOptions {
        include_git: submitted.include_git,
        follow_symlinks: submitted.follow_symlinks,
        max_file_size_kb: submitted.max_file_size_kb.max(1),
        scan_secrets: submitted.scan_secrets,
        scan_vulnerabilities: submitted.scan_vulnerabilities,
        ignored_dirs,
    }
}

#[cfg(test)]
fn collect_source_scan_files(
    root: &Path,
    effective: &EffectiveScanOptions,
) -> fs_utils::SourceFileCollection {
    fs_utils::collect_source_files(
        root,
        fs_utils::CollectFilesOptions {
            project_root: root,
            include_git: effective.include_git,
            follow_symlinks: effective.follow_symlinks,
            extra_ignored: &effective.ignored_dirs,
        },
    )
}

#[cfg(test)]
mod scan_option_contract_tests {
    use super::{collect_source_scan_files, effective_scan_options};
    use crate::models::{ScanOptions, ScanSettings};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn submitted_source_controls_override_every_saved_scan_default() {
        let saved = ScanSettings {
            include_git: true,
            follow_symlinks: true,
            max_file_size_kb: 4096,
            scan_secrets: true,
            scan_vulnerabilities: false,
            ignored_dirs: vec!["saved-ignore".into()],
        };
        let submitted = ScanOptions {
            path: "/project".into(),
            include_git: false,
            follow_symlinks: false,
            max_file_size_kb: 321,
            scan_secrets: false,
            scan_vulnerabilities: true,
            extra_ignored_dirs: vec!["request-ignore".into()],
            ignore_invalid_policy: false,
        };

        let effective = effective_scan_options(&submitted, &saved);

        assert!(
            !effective.include_git,
            "saved includeGit must not force the submitted control on"
        );
        assert!(
            !effective.follow_symlinks,
            "saved followSymlinks must not force the submitted control on"
        );
        assert_eq!(effective.max_file_size_kb, 321);
        assert!(!effective.scan_secrets);
        assert!(effective.scan_vulnerabilities);
        assert_eq!(effective.ignored_dirs, ["saved-ignore", "request-ignore"]);
    }

    #[test]
    fn submitted_true_controls_are_not_replaced_by_saved_false_defaults() {
        let saved = ScanSettings::default();
        let submitted = ScanOptions {
            include_git: true,
            follow_symlinks: true,
            max_file_size_kb: 0,
            scan_secrets: true,
            scan_vulnerabilities: false,
            ..ScanOptions::default()
        };

        let effective = effective_scan_options(&submitted, &saved);

        assert!(effective.include_git);
        assert!(effective.follow_symlinks);
        assert_eq!(effective.max_file_size_kb, 1);
        assert!(effective.scan_secrets);
        assert!(!effective.scan_vulnerabilities);
    }

    #[test]
    fn invalid_policy_override_defaults_false_for_existing_frontends() {
        let legacy = serde_json::json!({
            "path": "/project",
            "includeGit": false,
            "followSymlinks": false,
            "maxFileSizeKb": 1024,
            "scanSecrets": true,
            "scanVulnerabilities": true,
            "extraIgnoredDirs": []
        });
        let parsed: ScanOptions = serde_json::from_value(legacy).unwrap();
        assert!(!parsed.ignore_invalid_policy);

        let explicit: ScanOptions = serde_json::from_value(serde_json::json!({
            "path": "/project",
            "includeGit": false,
            "followSymlinks": false,
            "maxFileSizeKb": 1024,
            "scanSecrets": true,
            "scanVulnerabilities": true,
            "extraIgnoredDirs": [],
            "ignoreInvalidPolicy": true
        }))
        .unwrap();
        assert!(explicit.ignore_invalid_policy);
    }

    #[cfg(unix)]
    #[test]
    fn source_command_collection_keeps_project_relative_alias_policy() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(root.path().join("shared/exposed.js"), "eval(userInput);\n").unwrap();
        fs::write(root.path().join(".gitignore"), "alias\n").unwrap();
        symlink(root.path().join("shared"), root.path().join("alias")).unwrap();
        let submitted = ScanOptions {
            path: root.path().to_string_lossy().into_owned(),
            follow_symlinks: true,
            ..ScanOptions::default()
        };
        let effective = effective_scan_options(&submitted, &ScanSettings::default());

        let collection = collect_source_scan_files(root.path(), &effective);
        let project_relative_paths: Vec<_> = collection
            .files
            .iter()
            .map(|file| file.project_relative_path.clone())
            .collect();
        assert_eq!(
            project_relative_paths,
            [
                PathBuf::from(".gitignore"),
                PathBuf::from("shared/exposed.js")
            ],
        );
        assert_eq!(collection.skipped, 0);
    }
}

#[tauri::command]
pub async fn scan_project(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    cve: State<'_, CveState>,
    rule_packs: State<'_, crate::rulepack_store::RulePacksState>,
    options: ScanOptions,
) -> Result<ScanRunDetail, CommandError> {
    let saved_scan_settings = state.settings.lock().unwrap().scan.clone();
    let effective = effective_scan_options(&options, &saved_scan_settings);
    let mut durable_options = options;
    durable_options.include_git = effective.include_git;
    durable_options.follow_symlinks = effective.follow_symlinks;
    durable_options.max_file_size_kb = effective.max_file_size_kb;
    durable_options.scan_secrets = effective.scan_secrets;
    durable_options.scan_vulnerabilities = effective.scan_vulnerabilities;
    durable_options.extra_ignored_dirs = effective.ignored_dirs;

    struct TauriEvents(AppHandle);
    impl ScanEventSink for TauriEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }

    // Installed packs apply to every scan: the enabled state is the user's
    // selection, and a scan that quietly skipped enabled rules would be a
    // lie. A pack whose snapshot no longer validates is skipped with its
    // reason logged — the scan proceeds with the packs that hold.
    let packs = match rule_packs.store() {
        Ok(store) => {
            let resolved = store.resolve_enabled();
            for (id, reason) in &resolved.skipped {
                tracing::warn!(pack = %id, reason = %reason, "enabled rule pack skipped");
            }
            crate::scanners::rulepacks::AppliedRulePacks::from_compiled(resolved.packs)
        }
        // An unavailable store degrades to built-in rules only; the scan
        // itself must not fail over pack management.
        Err(error) => {
            tracing::warn!(reason = %error, "rule packs not applied");
            crate::scanners::rulepacks::AppliedRulePacks::empty()
        }
    };

    findings
        .service()?
        .scan_with_packs(
            durable_options,
            &cve,
            &state.cancel_scan,
            &TauriEvents(app),
            &packs,
        )
        .await
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecheckSourceResult {
    run: ScanRunDetail,
    options: ScanOptions,
}

#[tauri::command]
pub async fn recheck_source_run(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    cve: State<'_, CveState>,
    original_run_id: String,
    project_id: String,
) -> Result<RecheckSourceResult, CommandError> {
    let service = findings.service()?;
    let options = service.recheck_options(&original_run_id, &project_id)?;
    struct RecheckEvents(AppHandle);
    impl ScanEventSink for RecheckEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let run = service
        .scan(
            options.clone(),
            &cve,
            &state.cancel_scan,
            &RecheckEvents(app),
        )
        .await?;
    Ok(RecheckSourceResult { run, options })
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_scan.store(true, Ordering::Relaxed);
    Ok(())
}

trait FindingsServiceAccess {
    fn findings_service(&self) -> Result<&FindingsService, CommandError>;
}

impl FindingsServiceAccess for FindingsService {
    fn findings_service(&self) -> Result<&FindingsService, CommandError> {
        Ok(self)
    }
}

impl FindingsServiceAccess for FindingsState {
    fn findings_service(&self) -> Result<&FindingsService, CommandError> {
        self.service()
    }
}

fn inspect_source_project_inner(
    findings: &impl FindingsServiceAccess,
    path: impl AsRef<Path>,
) -> Result<ProjectContext, CommandError> {
    findings.findings_service()?.inspect_project(path)
}

fn list_source_projects_inner(
    findings: &impl FindingsServiceAccess,
    limit: u32,
) -> Result<Vec<RecentProject>, CommandError> {
    findings
        .findings_service()?
        .list_recent_projects(limit.clamp(1, 100) as usize)
}

fn list_source_runs_inner(
    findings: &impl FindingsServiceAccess,
    project_id: &str,
    limit: u32,
) -> Result<Vec<ScanRunSummary>, CommandError> {
    findings
        .findings_service()?
        .list_runs(project_id, limit.clamp(1, 100) as usize)
}

fn load_source_run_inner(
    findings: &impl FindingsServiceAccess,
    run_id: &str,
) -> Result<ScanRunDetail, CommandError> {
    findings.findings_service()?.load_run(run_id)
}

fn retry_source_run_save_inner(
    findings: &impl FindingsServiceAccess,
    retry_token: &str,
) -> Result<ScanRunDetail, CommandError> {
    findings.findings_service()?.retry_save(retry_token)
}

fn save_finding_review_inner(
    findings: &impl FindingsServiceAccess,
    request: ReviewRequest,
) -> Result<ReviewRecord, CommandError> {
    findings
        .findings_service()?
        .save_review(&request, chrono::Utc::now())
}

fn delete_finding_review_inner(
    findings: &impl FindingsServiceAccess,
    request: ReviewRequest,
) -> Result<ReviewRecord, CommandError> {
    let service = findings.findings_service()?;
    if request.state != ReviewState::Candidate {
        return Err(CommandError::review_invalid());
    }
    service.save_review(&request, chrono::Utc::now())
}

#[tauri::command]
pub fn inspect_source_project(
    state: State<'_, FindingsState>,
    path: String,
) -> Result<ProjectContext, CommandError> {
    inspect_source_project_inner(&*state, path)
}

#[tauri::command]
pub fn list_source_projects(
    state: State<'_, FindingsState>,
    limit: u32,
) -> Result<Vec<RecentProject>, CommandError> {
    list_source_projects_inner(&*state, limit)
}

#[tauri::command]
pub fn list_source_runs(
    state: State<'_, FindingsState>,
    project_id: String,
    limit: u32,
) -> Result<Vec<ScanRunSummary>, CommandError> {
    list_source_runs_inner(&*state, &project_id, limit)
}

#[tauri::command]
pub fn compare_source_runs(
    state: State<'_, FindingsState>,
    current_run_id: String,
    baseline_run_id: String,
    require_valid_policy: Option<bool>,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    if require_valid_policy.unwrap_or(false) {
        state
            .service()?
            .compare_recheck_runs(&current_run_id, &baseline_run_id)
    } else {
        state
            .service()?
            .compare_runs(&current_run_id, &baseline_run_id)
    }
}

#[tauri::command]
pub async fn inspect_source_git(
    path: String,
    base_reference: String,
) -> Result<crate::git_context::GitContext, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::git_context::inspect(std::path::Path::new(&path), &base_reference)
    })
    .await
    .map_err(|_| "Git inspection could not complete".to_owned())?
}

#[tauri::command]
pub fn load_source_run(
    state: State<'_, FindingsState>,
    run_id: String,
) -> Result<ScanRunDetail, CommandError> {
    load_source_run_inner(&*state, &run_id)
}

#[tauri::command]
pub fn retry_source_run_save(
    state: State<'_, FindingsState>,
    retry_token: String,
) -> Result<ScanRunDetail, CommandError> {
    retry_source_run_save_inner(&*state, &retry_token)
}

#[tauri::command]
pub fn save_finding_review(
    state: State<'_, FindingsState>,
    request: ReviewRequest,
) -> Result<ReviewRecord, CommandError> {
    save_finding_review_inner(&*state, request)
}

/// The most findings one bulk review may cover.
///
/// A bound rather than a preference: the request arrives from the GUI, and an
/// unbounded list would let a single call write unbounded history.
const MAX_BULK_REVIEW: usize = 1_000;

#[tauri::command]
pub fn save_finding_reviews(
    state: State<'_, FindingsState>,
    requests: Vec<ReviewRequest>,
) -> Result<crate::findings::service::BulkReviewOutcome, CommandError> {
    if requests.is_empty() {
        return Err(CommandError::review_invalid());
    }
    if requests.len() > MAX_BULK_REVIEW {
        return Err(CommandError::review_invalid());
    }
    let service = state.findings_service()?;
    Ok(service.save_reviews(&requests, chrono::Utc::now()))
}

#[tauri::command]
pub fn delete_finding_review(
    state: State<'_, FindingsState>,
    request: ReviewRequest,
) -> Result<ReviewRecord, CommandError> {
    delete_finding_review_inner(&*state, request)
}

#[cfg(test)]
mod source_finding_command_tests {
    use super::{
        delete_finding_review_inner, inspect_source_project_inner, list_source_projects_inner,
        list_source_runs_inner, load_source_run_inner, retry_source_run_save_inner,
        save_finding_review_inner,
    };
    use crate::cve::CveState;
    use crate::findings::{
        domain::{
            DiffStatus, PolicyStatus, ReviewOrigin, ReviewRequest, ReviewState, RunPersistence,
            RunStatus, ScanRunDetail,
        },
        error::{CommandError, ErrorCode},
        repository::FindingsRepository,
        service::{FindingsService, FindingsState, ScanEventSink},
    };
    use crate::models::{ScanOptions, ScanSummary};
    use crate::triage::gates::{GateNote, GateVerdict, ALL_GATES};
    use std::sync::atomic::AtomicBool;

    struct QuietEvents;

    impl ScanEventSink for QuietEvents {
        fn emit(&self, _event: &str, _payload: serde_json::Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    fn cached_cve_state() -> CveState {
        let state = CveState::new(reqwest::Client::new());
        *state.kev.lock().unwrap() = Some((std::time::Instant::now(), Default::default()));
        state
    }

    fn review_request(
        detail: &ScanRunDetail,
        state: ReviewState,
        origin: ReviewOrigin,
    ) -> ReviewRequest {
        let finding = detail
            .findings
            .iter()
            .find(|finding| finding.observation_run_id == detail.run_id)
            .unwrap();
        ReviewRequest {
            project_id: detail.project_id.clone(),
            fingerprint_version: finding.fingerprint_version,
            fingerprint: finding.fingerprint.clone(),
            category: finding.category.clone(),
            state,
            reason: if state == ReviewState::Candidate {
                String::new()
            } else {
                "Reviewed through the command boundary".into()
            },
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin,
        }
    }

    fn empty_summary(path: &std::path::Path) -> ScanSummary {
        ScanSummary {
            git_context: None,
            path: path.to_string_lossy().into_owned(),
            files_scanned: 0,
            files_skipped: 0,
            bytes_scanned: 0,
            duration_ms: 0,
            secrets_found: 0,
            vulnerabilities_found: 0,
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            rules_fired: Default::default(),
        }
    }

    fn running_detail(
        project_id: &str,
        run_id: &str,
        project: &std::path::Path,
        started_at: String,
    ) -> ScanRunDetail {
        ScanRunDetail {
            project_id: project_id.to_owned(),
            run_id: run_id.to_owned(),
            baseline_run_id: None,
            status: RunStatus::Running,
            persistence: RunPersistence::Saved,
            policy: PolicyStatus::Missing,
            started_at,
            completed_at: None,
            summary: empty_summary(project),
            findings: Vec::new(),
            maintenance_warning: None,
        }
    }

    #[test]
    fn project_inspection_is_canonical_and_visible_in_recent_projects() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let service = FindingsService::new(FindingsRepository::open_in_memory().unwrap());

        let context = inspect_source_project_inner(&service, &project).unwrap();

        assert_eq!(
            context.canonical_path,
            project
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        let recent = list_source_projects_inner(&service, 12).unwrap();
        assert_eq!(recent[0].project_id, context.project_id);
    }

    #[test]
    fn list_limits_are_clamped_and_unknown_identifiers_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let repository = FindingsRepository::open_in_memory().unwrap();
        let mut run_project = None;
        for index in 0..102 {
            let project = directory.path().join(format!("project-{index:03}"));
            std::fs::create_dir(&project).unwrap();
            let canonical = project
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let context = repository
                .upsert_project(
                    &format!("project-{index:03}"),
                    &canonical,
                    &format!("Project {index:03}"),
                    &format!("2026-01-01T00:00:00.{index:09}Z"),
                    None,
                )
                .unwrap();
            if index == 0 {
                run_project = Some((project, context));
            }
        }
        let (project, context) = run_project.unwrap();
        for index in 0..102 {
            repository
                .start_run(
                    &running_detail(
                        &context.project_id,
                        &format!("run-{index:03}"),
                        &project,
                        format!("2026-02-01T00:00:00.{index:09}Z"),
                    ),
                    "test-scanner",
                    &ScanOptions::default(),
                )
                .unwrap();
        }
        let service = FindingsService::new(repository);

        assert_eq!(list_source_projects_inner(&service, 0).unwrap().len(), 1);
        assert_eq!(
            list_source_projects_inner(&service, u32::MAX)
                .unwrap()
                .len(),
            100
        );
        assert_eq!(
            list_source_runs_inner(&service, &context.project_id, 0)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            list_source_runs_inner(&service, &context.project_id, u32::MAX)
                .unwrap()
                .len(),
            100
        );
        assert_eq!(
            list_source_runs_inner(&service, "unknown-project", 10)
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        assert_eq!(
            load_source_run_inner(&service, "run-000").unwrap().run_id,
            "run-000"
        );
        assert_eq!(
            load_source_run_inner(&service, "unknown-run")
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        assert_eq!(
            retry_source_run_save_inner(&service, "unknown-token")
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }

    #[tokio::test]
    async fn reviews_save_and_delete_as_auditable_candidate_transition() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let service = FindingsService::new(FindingsRepository::open_in_memory().unwrap());
        let detail = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: false,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &QuietEvents,
            )
            .await
            .unwrap();

        let accepted = review_request(&detail, ReviewState::AcceptedRisk, ReviewOrigin::Local);
        let stored = save_finding_review_inner(&service, accepted.clone()).unwrap();
        assert_eq!(stored.state, ReviewState::AcceptedRisk);
        assert_eq!(stored.origin, ReviewOrigin::Local);

        let deleted = delete_finding_review_inner(
            &service,
            review_request(&detail, ReviewState::Candidate, ReviewOrigin::Local),
        )
        .unwrap();
        assert_eq!(deleted.state, ReviewState::Candidate);
        assert_eq!(deleted.origin, ReviewOrigin::Local);
        let loaded = load_source_run_inner(&service, &detail.run_id).unwrap();
        let finding = loaded
            .findings
            .iter()
            .find(|finding| finding.observation_run_id == detail.run_id)
            .unwrap();
        assert!(finding.review.is_none());
        assert!(finding
            .review_history
            .iter()
            .any(|review| review.state == ReviewState::AcceptedRisk));
        assert!(finding
            .review_history
            .iter()
            .any(|review| review.state == ReviewState::Candidate));

        assert_eq!(
            delete_finding_review_inner(&service, accepted)
                .unwrap_err()
                .code,
            ErrorCode::ReviewInvalid
        );

        let mut forbidden =
            review_request(&detail, ReviewState::Confirmed, ReviewOrigin::ProjectPolicy);
        forbidden.gates = ALL_GATES
            .into_iter()
            .map(|gate| GateNote {
                gate,
                verdict: GateVerdict::Survives,
                evidence: "Reviewed sanitized source evidence".into(),
            })
            .collect();
        assert_eq!(
            save_finding_review_inner(&service, forbidden)
                .unwrap_err()
                .code,
            ErrorCode::ReviewInvalid
        );
    }

    #[tokio::test]
    async fn invalid_policy_is_visible_and_project_policy_save_preserves_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let policy_path = project.join(".oxaudit/policy.json");
        let invalid_bytes = b"{ invalid command policy bytes }";
        std::fs::write(&policy_path, invalid_bytes).unwrap();
        let service = FindingsService::new(FindingsRepository::open_in_memory().unwrap());

        let context = inspect_source_project_inner(&service, &project).unwrap();
        assert!(matches!(context.policy, PolicyStatus::Invalid { .. }));
        let detail = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: false,
                    ignore_invalid_policy: true,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &QuietEvents,
            )
            .await
            .unwrap();
        let request = review_request(
            &detail,
            ReviewState::Suppressed,
            ReviewOrigin::ProjectPolicy,
        );

        assert_eq!(
            save_finding_review_inner(&service, request)
                .unwrap_err()
                .code,
            ErrorCode::PolicyInvalid
        );
        assert_eq!(std::fs::read(policy_path).unwrap(), invalid_bytes);
    }

    #[test]
    fn unavailable_state_returns_the_same_sanitized_error_from_every_adapter() {
        let expected = CommandError::persistence_unavailable();
        let state = FindingsState::unavailable(expected.clone());
        let request = ReviewRequest {
            project_id: "project".into(),
            fingerprint_version: 1,
            fingerprint: "fingerprint".into(),
            category: "secret".into(),
            state: ReviewState::Candidate,
            reason: String::new(),
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin: ReviewOrigin::Local,
        };
        let expected = serde_json::to_value(expected).unwrap();

        let errors = [
            inspect_source_project_inner(&state, "/unused").unwrap_err(),
            list_source_projects_inner(&state, 12).unwrap_err(),
            list_source_runs_inner(&state, "project", 50).unwrap_err(),
            load_source_run_inner(&state, "run").unwrap_err(),
            retry_source_run_save_inner(&state, "token").unwrap_err(),
            save_finding_review_inner(&state, request.clone()).unwrap_err(),
            delete_finding_review_inner(&state, request).unwrap_err(),
        ];
        for error in errors {
            assert_eq!(serde_json::to_value(error).unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn file_restart_recovers_running_attempt_and_preserves_compatible_baseline() {
        let temporary = tempfile::tempdir().unwrap();
        let data_dir = temporary.path().join("private-app-data");
        let project = temporary.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let database_path = crate::findings::database_path(&data_dir);
        let service = FindingsService::new(FindingsRepository::open(&database_path).unwrap());
        let options = ScanOptions {
            path: project.to_string_lossy().into_owned(),
            scan_secrets: false,
            ..ScanOptions::default()
        };
        let baseline = service
            .scan(
                options.clone(),
                &cached_cve_state(),
                &AtomicBool::new(false),
                &QuietEvents,
            )
            .await
            .unwrap();
        drop(service);

        let repository = FindingsRepository::open(&database_path).unwrap();
        let interrupted_id = "interrupted-run";
        repository
            .start_run(
                &running_detail(
                    &baseline.project_id,
                    interrupted_id,
                    &project,
                    chrono::Utc::now().to_rfc3339(),
                ),
                "test-scanner",
                &options,
            )
            .unwrap();
        drop(repository);

        let state = crate::initialize_findings_state(&data_dir, chrono::Utc::now());
        let service = state.service().unwrap();
        assert_eq!(
            load_source_run_inner(service, interrupted_id)
                .unwrap()
                .status,
            RunStatus::Incomplete
        );
        let rescanned = service
            .scan(
                options,
                &cached_cve_state(),
                &AtomicBool::new(false),
                &QuietEvents,
            )
            .await
            .unwrap();
        assert_eq!(
            rescanned.baseline_run_id.as_deref(),
            Some(baseline.run_id.as_str())
        );
        assert!(rescanned.findings.iter().any(|finding| {
            finding.observation_run_id == rescanned.run_id
                && finding.diff_status == Some(DiffStatus::Unchanged)
        }));
    }

    #[test]
    fn startup_failure_creates_an_unavailable_sanitized_state() {
        let data_dir_file = tempfile::NamedTempFile::new().unwrap();

        let state = crate::initialize_findings_state(data_dir_file.path(), chrono::Utc::now());

        let error = match state.service() {
            Ok(_) => panic!("startup through a file path must be unavailable"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::PersistenceUnavailable);
        assert_eq!(error.detail, None);
    }
}

// ---------------------------------------------------------------------------
// Dependency scanning
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_canonical_runs(
    findings: State<'_, FindingsState>,
    kind: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<oxaudit_domain::Run>, String> {
    let kind = match kind.as_deref() {
        Some("source") => Some("source"),
        Some("secrets") => Some("secrets"),
        Some("dependencies") => Some("dependencies"),
        Some("binary") => Some("binary"),
        Some("firmware") => Some("firmware"),
        Some("import") => Some("import"),
        Some("external_evidence") => Some("external_evidence"),
        Some("verification") => Some("verification"),
        Some(_) => return Err("unknown run kind".into()),
        None => None,
    };
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .canonical_list_runs(kind, limit.unwrap_or(50))
        .map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// CVE research
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Binary / firmware scanning (cve-bin-tool)
// ---------------------------------------------------------------------------

/// Wall-clock ceiling for one scan. Generous because a first run downloads the
/// CVE database before it scans anything, which can take several minutes.
const BINARY_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45 * 60);

fn scan_context(
    state: &AppState,
    app: &AppHandle,
    use_grype: bool,
) -> Result<crate::binscan::scan::ScanContext, String> {
    let settings = state.settings.lock().unwrap().clone();
    let scratch_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("no cache directory available: {e}"))?
        .join("binscan");
    // Best-effort: a missing data dir only means the exploit index is fetched
    // fresh instead of read from cache.
    let cache_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| scratch_dir.clone());

    let trimmed = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let nvd_api_key = crate::credentials::resolve_nvd_key(state.credentials.as_ref())
        .map_err(|error| error.to_string())?;

    Ok(crate::binscan::scan::ScanContext {
        runtime: crate::binscan::runtime::Runtime::parse(
            settings.binary_scanner_runtime.as_deref(),
        ),
        cve_bin_tool_path: trimmed(settings.binary_scanner_path.clone()),
        grype_path: trimmed(settings.grype_path.clone()),
        nvd_api_key,
        scratch_dir: scratch_dir.clone(),
        cache_dir,
        use_cve_bin_tool: true,
        use_grype,
        use_native: true,
    })
}

/// Availability of every scanner and runtime, so the UI can explain itself.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryScannersStatus {
    /// oxAudit's built-in scanner. Always available — it needs nothing
    /// installed — which is why `can_scan` is always true.
    pub native: crate::binscan::detect::BinaryToolStatus,
    pub cve_bin_tool: crate::binscan::detect::BinaryToolStatus,
    pub grype: crate::binscan::detect::BinaryToolStatus,
    pub docker: crate::binscan::detect::BinaryToolStatus,
    /// The configured runtime preference, echoed back.
    pub runtime: String,
    /// Whether a scan can run at all. Always true now that the native scanner
    /// is built in; kept in the payload so the UI need not special-case it.
    pub can_scan: bool,
}

// ---------------------------------------------------------------------------
// AI assistant
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AI streaming chat
// ---------------------------------------------------------------------------

/// Upper bound on one steer message, mirroring the composer's own limit.
const MAX_STEER_CHARS: usize = 8000;

fn resolve_stream_run_id(requested: Option<String>) -> Result<String, String> {
    match requested {
        Some(run_id) if run_id.trim().is_empty() => Err("run id must not be empty".into()),
        Some(run_id) if run_id.len() > 128 => Err("run id is too long".into()),
        Some(run_id) => Ok(run_id),
        None => Ok(uuid::Uuid::new_v4().to_string()),
    }
}

fn stream_event_payload(run_id: &str, event: crate::ai::AiStreamEvent) -> Result<Value, String> {
    let mut payload = serde_json::to_value(event).map_err(|error| error.to_string())?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| "AI stream event did not serialize to an object".to_string())?;
    object.insert("runId".into(), Value::String(run_id.into()));
    Ok(payload)
}

fn capture_active_project(state: &AppState) -> Option<PathBuf> {
    state.active_project.lock().unwrap().clone()
}

#[cfg(test)]
mod stream_protocol_tests {
    use super::{capture_active_project, resolve_stream_run_id, stream_event_payload, AppState};
    use crate::ai::AiStreamEvent;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn caller_owned_run_id_is_preserved_before_stream_start() {
        assert_eq!(
            resolve_stream_run_id(Some("run-from-client".into())).unwrap(),
            "run-from-client"
        );
    }

    #[test]
    fn missing_run_id_keeps_the_legacy_generated_id_contract() {
        let generated = resolve_stream_run_id(None).unwrap();
        assert!(uuid::Uuid::parse_str(&generated).is_ok());
    }

    #[test]
    fn ordinary_stream_events_carry_their_owning_run_identity() {
        let payload = stream_event_payload(
            "run-a",
            AiStreamEvent::Delta {
                content: "hello".into(),
            },
        )
        .unwrap();

        assert_eq!(
            payload,
            json!({ "type": "delta", "runId": "run-a", "content": "hello" })
        );
    }

    #[test]
    fn tool_stream_payload_keeps_the_frontend_tag_and_field_contract() {
        let payload = stream_event_payload(
            "run-tools",
            AiStreamEvent::ToolResult {
                tool_call_id: "tool-1".into(),
                name: "read_file".into(),
                success: true,
                duration_ms: 12,
                result_preview: "ok".into(),
            },
        )
        .unwrap();

        assert_eq!(payload["type"], "tool_result");
        assert_eq!(payload["toolCallId"], "tool-1");
        assert_eq!(payload["durationMs"], 12);
        assert_eq!(payload["resultPreview"], "ok");
    }

    #[test]
    fn context_budget_payload_keeps_the_frontend_metadata_contract() {
        let payload = stream_event_payload(
            "run-context",
            AiStreamEvent::ContextBudget {
                estimated_tokens: 12_345,
                context_window: 128_000,
                reserved_output_tokens: 2_048,
            },
        )
        .unwrap();

        assert_eq!(payload["type"], "context_budget");
        assert_eq!(payload["estimatedTokens"], 12_345);
        assert_eq!(payload["contextWindow"], 128_000);
        assert_eq!(payload["reservedOutputTokens"], 2_048);
    }

    #[test]
    fn chat_run_keeps_the_project_snapshot_taken_at_start() {
        let state = AppState::new();
        *state.active_project.lock().unwrap() = Some(PathBuf::from("/first/project"));

        let captured = capture_active_project(&state);
        *state.active_project.lock().unwrap() = Some(PathBuf::from("/second/project"));

        assert_eq!(captured, Some(PathBuf::from("/first/project")));
    }
}

fn active_project_path(path: Option<String>) -> Result<Option<PathBuf>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let project = PathBuf::from(&path);
    if project.is_dir() {
        Ok(Some(project))
    } else {
        Err(format!("not a directory: {path}"))
    }
}

#[cfg(test)]
mod active_project_tests {
    use super::active_project_path;

    #[test]
    fn null_path_clears_the_runtime_project() {
        assert_eq!(active_project_path(None).unwrap(), None);
    }

    #[test]
    fn existing_directory_sets_the_runtime_project() {
        let path = std::env::temp_dir();
        assert_eq!(
            active_project_path(Some(path.to_string_lossy().into_owned())).unwrap(),
            Some(path)
        );
    }

    #[test]
    fn missing_directory_is_rejected() {
        let unique = format!(
            "oxaudit-missing-active-project-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        assert!(!path.exists());
        assert!(active_project_path(Some(path.to_string_lossy().into_owned())).is_err());
    }
}

#[cfg(test)]
mod open_scan_finding_tests {
    use super::resolve_scan_finding_path;
    use std::fs;

    #[test]
    fn safe_relative_finding_path_resolves_inside_the_captured_root() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("src");
        fs::create_dir(&nested).unwrap();
        let file = nested.join("main.rs");
        fs::write(&file, "fn main() {}\n").unwrap();

        assert_eq!(
            resolve_scan_finding_path(root.path(), "src/main.rs").unwrap(),
            file.canonicalize().unwrap()
        );
    }

    #[test]
    fn absolute_finding_path_is_rejected_even_when_it_exists() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();

        assert!(resolve_scan_finding_path(root.path(), outside.path()).is_err());
    }

    #[test]
    fn parent_traversal_cannot_escape_the_captured_scan_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("project");
        fs::create_dir(&root).unwrap();
        fs::write(parent.path().join("outside.rs"), "outside\n").unwrap();

        assert!(resolve_scan_finding_path(&root, "../outside.rs").is_err());
    }

    #[test]
    fn directories_are_not_opened_as_finding_files() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();

        assert!(resolve_scan_finding_path(root.path(), "src").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_finding_cannot_escape_the_captured_scan_root() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), root.path().join("linked.rs")).unwrap();

        assert!(resolve_scan_finding_path(root.path(), "linked.rs").is_err());
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sessions (JSONL transcripts + index)
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rayon::prelude::*;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::agent::tools::TodoItem;
use crate::ai::usage::{UsageStore, UsageSummary};
use crate::ai::AiClient;
use crate::cve::CveState;
use crate::deps::osv::OsvClient;
use crate::fs_utils;
use crate::models::{
    AiSettings, AppSettings, ChatRequest, ChatResponse, DependencyScanResult, Finding,
    LockfileInfo, ScanOptions, ScanResult, ScanSummary, StreamStarted,
};
use crate::scanners;

pub struct AppState {
    pub settings: Mutex<AppSettings>,
    pub http: reqwest::Client,
    pub ai: AiClient,
    pub osv: OsvClient,
    pub cancel_scan: AtomicBool,
    /// run_id -> cancel flag for in-flight chat turns
    pub active_chats: Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>,
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
        let http = reqwest::Client::builder()
            .user_agent("VulnCompanion/0.1 (security research)")
            .gzip(true)
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            settings: Mutex::new(AppSettings::default()),
            http: http.clone(),
            ai: AiClient::new(http.clone()),
            osv: OsvClient::new(http.clone()),
            cancel_scan: AtomicBool::new(false),
            active_chats: Mutex::new(std::collections::HashMap::new()),
            active_project: Mutex::new(None),
            pending_permissions: Mutex::new(std::collections::HashMap::new()),
            pending_interactions: Mutex::new(std::collections::HashMap::new()),
            todos: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

fn usage_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_config_dir()
        .map(|d| d.join("usage.json"))
        .unwrap_or_else(|_| PathBuf::from("usage.json"))
}

fn cancel_checked(state: &AppState) -> bool {
    state.cancel_scan.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Source code + secret scanning
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn scan_project(
    app: AppHandle,
    state: State<'_, AppState>,
    options: ScanOptions,
) -> Result<ScanResult, String> {
    state.cancel_scan.store(false, Ordering::Relaxed);
    let started = Instant::now();
    let root = Path::new(&options.path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {}", options.path));
    }

    let settings = state.settings.lock().unwrap().clone();
    let mut ignored = settings.scan.ignored_dirs.clone();
    ignored.extend(options.extra_ignored_dirs.iter().cloned());

    app.emit("scan://progress", Value::from("walking")).map_err(|e| e.to_string())?;

    let (files, skipped, total_bytes) = fs_utils::collect_files(
        root,
        settings.scan.include_git || options.include_git,
        settings.scan.follow_symlinks || options.follow_symlinks,
        &ignored,
    );

    if files.is_empty() {
        return Err("no files found to scan (check ignore rules / path)".into());
    }

    let total = files.len();
    let processed = std::sync::atomic::AtomicUsize::new(0);
    let max_file_size_kb = options.max_file_size_kb.max(1);
    let scan_secrets = options.scan_secrets;
    let scan_vulns = options.scan_vulnerabilities;

    app.emit(
        "scan://progress",
        serde_json::json!({ "total": total, "done": 0, "phase": "scanning" }),
    )
    .map_err(|e| e.to_string())?;

    let results: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|file| {
            if cancel_checked(&state) {
                return Vec::new();
            }
            let findings = scanners::scan_file(root, file, max_file_size_kb, scan_secrets, scan_vulns);
            let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 25 == 0 || done == total {
                let _ = app.emit(
                    "scan://progress",
                    serde_json::json!({ "total": total, "done": done, "phase": "scanning" }),
                );
            }
            findings
        })
        .collect();

    if cancel_checked(&state) {
        return Err("scan cancelled".into());
    }

    let mut findings: Vec<Finding> = results.into_iter().flatten().collect();
    findings.sort_by(|a, b| {
        severity_rank(&b.severity).cmp(&severity_rank(&a.severity))
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
    });

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    let mut rules_fired: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        match f.severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => info += 1,
        }
        *rules_fired.entry(f.rule_id.clone()).or_insert(0) += 1;
    }

    let secrets_found = findings.iter().filter(|f| f.category == "secret").count();
    let vulnerabilities_found = findings.iter().filter(|f| f.category == "vulnerability").count();

    let summary = ScanSummary {
        path: options.path.clone(),
        files_scanned: files.len(),
        files_skipped: skipped,
        bytes_scanned: total_bytes,
        duration_ms: started.elapsed().as_millis() as u64,
        secrets_found,
        vulnerabilities_found,
        total_findings: findings.len(),
        critical,
        high,
        medium,
        low,
        info,
        rules_fired,
    };

    app.emit("scan://done", serde_json::json!({ "findings": findings.len() }))
        .ok();

    // make this the project the agent's file tools operate on
    *state.active_project.lock().unwrap() = Some(root.to_path_buf());

    Ok(ScanResult { summary, findings })
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_scan.store(true, Ordering::Relaxed);
    Ok(())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Dependency scanning
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn scan_dependencies(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<DependencyScanResult, String> {
    let started = Instant::now();
    let root = Path::new(&path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }

    let settings = state.settings.lock().unwrap().clone();
    let lockfiles = fs_utils::collect_lockfiles(root, &settings.scan.ignored_dirs);

    let mut all_deps = Vec::new();
    let mut lockfile_infos = Vec::new();
    let mut parse_errors: Vec<String> = Vec::new();

    app.emit("deps://progress", serde_json::json!({ "phase": "parsing", "done": 0, "total": lockfiles.len() }))
        .ok();

    for (i, lf) in lockfiles.iter().enumerate() {
        let name = lf.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let kind = crate::deps::lockfiles::lockfile_kind(name);
        match crate::deps::lockfiles::parse_lockfile(lf, kind) {
            Ok(deps) => {
                lockfile_infos.push(LockfileInfo {
                    path: lf.to_string_lossy().replace('\\', "/"),
                    kind: kind.into(),
                    packages: deps.len(),
                });
                all_deps.extend(deps);
            }
            Err(e) => parse_errors.push(format!("{}: {e}", lf.display())),
        }
        let _ = app.emit(
            "deps://progress",
            serde_json::json!({ "phase": "parsing", "done": i + 1, "total": lockfiles.len(), "parseErrors": parse_errors.len() }),
        );
    }

    let deps = crate::deps::lockfiles::dedupe_dependencies(all_deps);
    let packages_queried = deps.len();

    app.emit("deps://progress", serde_json::json!({ "phase": "querying-osv", "done": 0, "total": 1 }))
        .ok();

    let vuln_map = state
        .osv
        .query_batch(&deps)
        .await
        .unwrap_or_default();

    let mut vulnerabilities = Vec::new();
    for dep in &deps {
        let key = format!("{}\u{0}{}\u{0}{}", dep.ecosystem, dep.name, dep.version);
        if let Some(vulns) = vuln_map.get(&key) {
            for mut v in vulns.clone() {
                v.lockfile = dep.lockfile.clone();
                vulnerabilities.push(v);
            }
        }
    }
    vulnerabilities.sort_by(|a, b| {
        let sa = a.cvss_score.unwrap_or(0.0);
        let sb = b.cvss_score.unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let result = DependencyScanResult {
        summary: crate::models::DepScanSummary {
            path: path.clone(),
            lockfiles_found: lockfile_infos.iter().map(|l| l.path.clone()).collect(),
            packages_found: lockfiles.iter().count(),
            packages_queried,
            vulnerabilities_found: vulnerabilities.len(),
            duration_ms: started.elapsed().as_millis() as u64,
        },
        dependencies: deps,
        vulnerabilities,
    };
    app.emit("deps://done", serde_json::json!({ "vulnerabilities": result.summary.vulnerabilities_found }))
        .ok();
    *state.active_project.lock().unwrap() = Some(root.to_path_buf());
    Ok(result)
}

#[tauri::command]
pub fn find_lockfiles(state: State<'_, AppState>, path: String) -> Result<Vec<LockfileInfo>, String> {
    let root = Path::new(&path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }
    let settings = state.settings.lock().unwrap().clone();
    let files = fs_utils::collect_lockfiles(root, &settings.scan.ignored_dirs);
    let mut out = Vec::new();
    for f in files {
        let name = f.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let kind = crate::deps::lockfiles::lockfile_kind(name);
        let count = crate::deps::lockfiles::parse_lockfile(&f, kind)
            .map(|d| d.len())
            .unwrap_or(0);
        out.push(LockfileInfo {
            path: f.to_string_lossy().replace('\\', "/"),
            kind: kind.into(),
            packages: count,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CVE research
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn search_cves(
    state: State<'_, CveState>,
    query: String,
    start_index: usize,
    per_page: usize,
    recent_days: Option<u64>,
) -> Result<crate::models::CveSearchResult, String> {
    crate::cve::search_cves(&state, &query, start_index, per_page, recent_days).await
}

#[tauri::command]
pub async fn cve_detail(
    state: State<'_, CveState>,
    id: String,
) -> Result<crate::models::CveDetail, String> {
    crate::cve::cve_detail(&state, &id).await
}

#[tauri::command]
pub async fn osv_package_vulns(
    state: State<'_, CveState>,
    ecosystem: String,
    name: String,
) -> Result<Vec<Value>, String> {
    crate::cve::osv_package_vulns(&state, &ecosystem, &name).await
}

// ---------------------------------------------------------------------------
// AI assistant
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn chat(
    state: State<'_, AppState>,
    request: ChatRequest,
) -> Result<ChatResponse, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if !settings.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    state.ai.chat(&settings, request).await
}

#[tauri::command]
pub async fn analyze_finding(
    state: State<'_, AppState>,
    finding: Finding,
) -> Result<ChatResponse, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if !settings.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let messages = crate::ai::analyze_finding_messages(&finding, &settings);
    state
        .ai
        .chat(
            &settings,
            ChatRequest { messages, temperature: None, max_tokens: None, conversation_id: None },
        )
        .await
}

#[tauri::command]
pub async fn research_cve(
    state: State<'_, AppState>,
    cve: crate::models::CveItem,
    osv: Option<Value>,
) -> Result<ChatResponse, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if !settings.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let messages = crate::ai::research_cve_messages(&cve, osv.as_ref(), &settings);
    state
        .ai
        .chat(
            &settings,
            ChatRequest { messages, temperature: None, max_tokens: None, conversation_id: None },
        )
        .await
}

// ---------------------------------------------------------------------------
// AI streaming chat
// ---------------------------------------------------------------------------

/// Start a streaming chat turn. Returns immediately with a `run_id`; the turn
/// runs on a background task that emits events:
///   `ai://started` { runId } · `ai://event` {type: delta|reasoning|usage}
///   `ai://done`    { runId, content, model, usage }
///   `ai://error`   { runId, message }
#[tauri::command]
pub async fn stream_chat(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ChatRequest,
) -> Result<StreamStarted, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if !settings.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let run_id = uuid::Uuid::new_v4().to_string();
    let run_id_response = run_id.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    state.active_chats.lock().unwrap().insert(run_id.clone(), cancel.clone());

    let client = crate::ai::AiClient::new(state.http.clone());
    let registry = crate::agent::tool::ToolRegistry::from_tools(crate::agent::tools::builtins());
    let app2 = app.clone();
    let usage_path = usage_path(&app);
    let conversation_id = request.conversation_id.clone();
    let user_messages: Vec<Value> = request
        .messages
        .into_iter()
        .map(|m| json!({ "role": m.role, "content": m.content }))
        .collect();

    tokio::spawn(async move {
        let _ = app2.emit("ai://started", json!({ "runId": run_id.clone() }));
        let app2_emit = app2.clone();
        let emitter: Arc<dyn Fn(crate::ai::AiStreamEvent) + Send + Sync> =
            Arc::new(move |ev| {
                let _ = app2_emit.emit("ai://event", ev);
            });
        let result = crate::agent::loop_engine::run_turn(
            &client,
            &settings,
            &registry,
            user_messages,
            conversation_id.clone(),
            app2.clone(),
            Some(cancel.clone()),
            emitter,
        )
        .await;
        match result {
            Ok((content, usage)) => {
                if let (Some(cid), Some(usage)) = (&conversation_id, &usage) {
                    let mut store = UsageStore::load(&usage_path).unwrap_or_default();
                    store.record(
                        cid,
                        crate::ai::usage::UsageRecord {
                            at: chrono::Utc::now().to_rfc3339(),
                            model: settings.model.clone(),
                            prompt_tokens: usage.prompt_tokens,
                            completion_tokens: usage.completion_tokens,
                            cost_usd: crate::ai::usage::estimate_cost(
                                &settings.model,
                                usage.prompt_tokens,
                                usage.completion_tokens,
                            ),
                        },
                    );
                    let _ = store.save(&usage_path);
                }
                let _ = app2.emit(
                    "ai://done",
                    json!({
                        "runId": run_id.clone(),
                        "content": content,
                        "model": settings.model,
                        "usage": usage,
                    }),
                );
            }
            Err(e) => {
                let _ = app2.emit(
                    "ai://error",
                    json!({ "runId": run_id.clone(), "message": e.user_message() }),
                );
            }
        }
        if let Some(app_state) = app2.try_state::<AppState>() {
            if let Ok(mut chats) = app_state.active_chats.lock() {
                chats.remove(&run_id);
            }
        }
    });

    Ok(StreamStarted { run_id: run_id_response })
}

/// Request cancellation of an in-flight chat stream.
#[tauri::command]
pub fn cancel_chat(state: State<'_, AppState>, run_id: String) -> Result<(), String> {
    if let Some(flag) = state.active_chats.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Resolve a pending HITL permission request.
#[tauri::command]
pub fn respond_permission(
    state: State<'_, AppState>,
    request_id: String,
    approve: bool,
) -> Result<(), String> {
    if let Some(tx) = state.pending_permissions.lock().unwrap().remove(&request_id) {
        let _ = tx.send(approve);
    }
    Ok(())
}

/// Resolve a pending `ask_user` interaction with the user's answers.
#[tauri::command]
pub fn respond_interaction(
    state: State<'_, AppState>,
    request_id: String,
    answers: Value,
) -> Result<(), String> {
    if let Some(tx) = state.pending_interactions.lock().unwrap().remove(&request_id) {
        let _ = tx.send(answers);
    }
    Ok(())
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

/// Set or explicitly clear the project folder the agent's file tools operate on.
#[tauri::command]
pub fn set_active_project(state: State<'_, AppState>, path: Option<String>) -> Result<(), String> {
    let project = active_project_path(path)?;
    *state.active_project.lock().unwrap() = project;
    Ok(())
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

#[tauri::command]
pub fn get_conversation_usage(
    app: AppHandle,
    conversation_id: String,
) -> Result<UsageSummary, String> {
    let store = UsageStore::load(&usage_path(&app)).unwrap_or_default();
    Ok(store.conversation_summary(&conversation_id))
}

#[tauri::command]
pub fn get_total_usage(app: AppHandle) -> Result<UsageSummary, String> {
    let store = UsageStore::load(&usage_path(&app)).unwrap_or_default();
    Ok(store.total())
}

#[tauri::command]
pub async fn test_ai(state: State<'_, AppState>) -> Result<crate::models::AiStatus, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if settings.base_url.trim().is_empty() {
        return Err("no AI endpoint configured".into());
    }
    state.ai.test_connection(&settings).await
}

#[tauri::command]
pub async fn test_ai_with(
    state: State<'_, AppState>,
    settings: AiSettings,
) -> Result<crate::models::AiStatus, String> {
    state.ai.test_connection(&settings).await
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn load_settings(app: AppHandle, state: State<'_, AppState>) -> Result<AppSettings, String> {
    let settings = crate::settings::load(&app);
    *state.settings.lock().unwrap() = settings.clone();
    Ok(settings)
}

#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: AppSettings,
) -> Result<(), String> {
    // keep the in-memory copy in sync and refresh NVD key
    let mut current = state.settings.lock().unwrap();
    crate::settings::save(&app, &settings)?;
    if let Some(cve) = app.try_state::<CveState>() {
        if let Ok(mut guard) = cve.api_key.lock() {
            *guard = settings.nvd_api_key.clone();
        }
    }
    *current = settings;
    Ok(())
}

#[tauri::command]
pub fn get_ai_settings(state: State<'_, AppState>) -> Result<AiSettings, String> {
    Ok(state.settings.lock().unwrap().ai.clone())
}

// ---------------------------------------------------------------------------
// Sessions (JSONL transcripts + index)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn session_list(app: AppHandle) -> Result<Vec<crate::sessions::SessionInfo>, String> {
    crate::sessions::SessionStore::new(&app)?.list()
}

#[tauri::command]
pub fn session_create(
    app: AppHandle,
    title: Option<String>,
    project_path: Option<String>,
) -> Result<crate::sessions::SessionInfo, String> {
    crate::sessions::SessionStore::new(&app)?.create(title, project_path)
}

#[tauri::command]
pub fn session_get_messages(
    app: AppHandle,
    session_id: String,
) -> Result<Vec<crate::sessions::StoredMessage>, String> {
    crate::sessions::SessionStore::new(&app)?.get_messages(&session_id)
}

#[tauri::command]
pub fn session_append(
    app: AppHandle,
    session_id: String,
    message: crate::sessions::StoredMessage,
) -> Result<crate::sessions::SessionInfo, String> {
    crate::sessions::SessionStore::new(&app)?.append(&session_id, &message)
}

#[tauri::command]
pub fn session_rename(app: AppHandle, session_id: String, title: String) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.rename(&session_id, title)
}

#[tauri::command]
pub fn session_delete(app: AppHandle, session_id: String) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.delete(&session_id)
}

#[tauri::command]
pub fn session_truncate(app: AppHandle, session_id: String, keep_count: usize) -> Result<(), String> {
    crate::sessions::SessionStore::new(&app)?.truncate(&session_id, keep_count)
}

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rayon::prelude::*;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_opener::OpenerExt;

use crate::agent::tools::TodoItem;
use crate::ai::usage::{UsageStore, UsageSummary};
use crate::ai::AiClient;
use crate::cve::CveState;
use crate::deps::osv::OsvClient;
use crate::fs_utils;
use crate::models::{
    AiSettings, AppSettings, ChatRequest, ChatResponse, DependencyScanResult, Finding,
    LockfileInfo, ScanOptions, ScanResult, ScanSettings, ScanSummary, StreamStarted,
};
use crate::scanners;

pub struct AppState {
    pub settings: Mutex<AppSettings>,
    pub http: reqwest::Client,
    pub ai: AiClient,
    pub osv: OsvClient,
    pub cancel_scan: AtomicBool,
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
    root: String,
    relative_path: String,
) -> Result<(), String> {
    let path = resolve_scan_finding_path(root, relative_path)?;
    app.opener()
        .open_path(path.to_string_lossy().into_owned(), None::<String>)
        .map_err(|error| format!("finding file could not be opened: {error}"))
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
            [PathBuf::from(".gitignore"), PathBuf::from("shared/exposed.js")],
        );
        assert_eq!(collection.skipped, 0);
    }
}

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

    let saved_scan_settings = state.settings.lock().unwrap().scan.clone();
    let effective = effective_scan_options(&options, &saved_scan_settings);

    app.emit("scan://progress", Value::from("walking")).map_err(|e| e.to_string())?;

    let collection = collect_source_scan_files(root, &effective);
    let files = collection.files;
    let skipped = collection.skipped;
    let total_bytes = collection.total_bytes;

    if files.is_empty() {
        return Err("no files found to scan (check ignore rules / path)".into());
    }

    let total = files.len();
    let processed = std::sync::atomic::AtomicUsize::new(0);
    let max_file_size_kb = effective.max_file_size_kb;
    let scan_secrets = effective.scan_secrets;
    let scan_vulns = effective.scan_vulnerabilities;

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
            let findings = scanners::scan_file_with_relative_path(
                &file.canonical_path,
                &file.collection_relative_path.to_string_lossy().replace('\\', "/"),
                max_file_size_kb,
                scan_secrets,
                scan_vulns,
            );
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
    let lockfiles =
        fs_utils::discover_lockfiles(root, root, &settings.scan.ignored_dirs);

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
    Ok(result)
}

#[tauri::command]
pub fn find_lockfiles(state: State<'_, AppState>, path: String) -> Result<Vec<LockfileInfo>, String> {
    let root = Path::new(&path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }
    let settings = state.settings.lock().unwrap().clone();
    let files = fs_utils::discover_lockfiles(root, root, &settings.scan.ignored_dirs);
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
// Binary / firmware scanning (cve-bin-tool)
// ---------------------------------------------------------------------------

/// Wall-clock ceiling for one scan. Generous because a first run downloads the
/// CVE database before it scans anything, which can take several minutes.
const BINARY_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45 * 60);

fn scan_context(state: &AppState, app: &AppHandle, use_grype: bool) -> Result<crate::binscan::scan::ScanContext, String> {
    let settings = state.settings.lock().unwrap().clone();
    let scratch_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("no cache directory available: {e}"))?
        .join("binscan");

    let trimmed = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    Ok(crate::binscan::scan::ScanContext {
        runtime: crate::binscan::runtime::Runtime::parse(
            settings.binary_scanner_runtime.as_deref(),
        ),
        cve_bin_tool_path: trimmed(settings.binary_scanner_path.clone()),
        grype_path: trimmed(settings.grype_path.clone()),
        nvd_api_key: settings.nvd_api_key.clone(),
        scratch_dir,
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

#[tauri::command]
pub async fn binary_tool_status(
    state: State<'_, AppState>,
) -> Result<BinaryScannersStatus, String> {
    let settings = state.settings.lock().unwrap().clone();
    let trimmed = |value: Option<String>| {
        value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    };
    let cve_path = trimmed(settings.binary_scanner_path.clone());
    let grype_path = trimmed(settings.grype_path.clone());
    let runtime = crate::binscan::runtime::Runtime::parse(
        settings.binary_scanner_runtime.as_deref(),
    );

    // Each probe spawns a process, so keep them off the UI thread.
    let (cve_bin_tool, grype, docker) = tokio::task::spawn_blocking(move || {
        (
            crate::binscan::detect::detect(cve_path.as_deref()),
            crate::binscan::detect::detect_grype(grype_path.as_deref()),
            crate::binscan::detect::detect_docker(),
        )
    })
    .await
    .map_err(|e| format!("tool detection failed: {e}"))?;

    // cve-bin-tool is reachable if its chosen runtime is; grype needs no runtime.
    let cve_bin_tool_usable = match runtime {
        crate::binscan::runtime::Runtime::Native => cve_bin_tool.available,
        crate::binscan::runtime::Runtime::Docker => docker.available,
        crate::binscan::runtime::Runtime::Auto => cve_bin_tool.available || docker.available,
    };

    // The native scanner is not probed: it is part of the binary and cannot be
    // absent. `_usable` still feeds the per-tool display of the others.
    let _ = cve_bin_tool_usable;
    let native = crate::binscan::detect::BinaryToolStatus::builtin(
        env!("CARGO_PKG_VERSION"),
        "Built in — no installation required. Reads component versions from strings, ELF package notes and byte patterns.",
    );

    Ok(BinaryScannersStatus {
        can_scan: true,
        native,
        cve_bin_tool,
        grype,
        docker,
        runtime: match runtime {
            crate::binscan::runtime::Runtime::Native => "native",
            crate::binscan::runtime::Runtime::Docker => "docker",
            crate::binscan::runtime::Runtime::Auto => "auto",
        }
        .to_string(),
    })
}

/// Scan a file or folder for vulnerable bundled components.
///
/// Runs every enabled scanner and merges the results. Emits
/// `binscan://progress` with each tool's own output; on a first cve-bin-tool
/// run that is the only sign of life while the CVE database downloads.
#[tauri::command]
pub async fn scan_binaries(
    app: AppHandle,
    state: State<'_, AppState>,
    request: crate::binscan::run::BinaryScanRequest,
    use_grype: Option<bool>,
) -> Result<crate::binscan::report::BinaryScanResult, String> {
    let context = scan_context(&state, &app, use_grype.unwrap_or(false))?;
    let cancel = state.cancel_binary_scan.clone();
    cancel.store(false, Ordering::Relaxed);

    let progress_app = app.clone();
    let on_progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("binscan://progress", Value::from(line));
    });

    let outcome = crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel,
        BINARY_SCAN_TIMEOUT,
        on_progress,
        app.try_state::<CveState>().as_deref(),
    )
    .await?;

    // A scanner that failed while another succeeded is reported, not hidden:
    // the two see different things, so a partial result is easy to misread as
    // a complete one.
    for failure in &outcome.failures {
        let _ = app.emit(
            "binscan://scanner-failed",
            json!({ "scanner": failure.scanner, "message": failure.message }),
        );
    }

    // Notes are not failures, but they change how the result should be read —
    // a capped or rate-limited lookup means "fewer CVEs than exist", which is
    // indistinguishable from "clean" unless we say so.
    for note in &outcome.notes {
        let _ = app.emit("binscan://note", Value::from(note.clone()));
    }

    Ok(outcome.result)
}

/// Force a full CVE database refresh.
///
/// cve-bin-tool's default `daily` policy treats a half-downloaded cache as
/// current, so a failed first bootstrap leaves it permanently stuck. `--update
/// now` is the only way out, and the user has no other way to reach it.
#[tauri::command]
pub async fn refresh_binary_database(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut context = scan_context(&state, &app, false)?;
    context.use_grype = false;
    // This refreshes cve-bin-tool's database. The native scanner has no
    // database, so running it here would only scan an empty probe directory.
    context.use_native = false;
    let cancel = state.cancel_binary_scan.clone();
    cancel.store(false, Ordering::Relaxed);

    // cve-bin-tool always needs a target, so refresh against an empty directory:
    // the point is the `--update now` side effect, not the (empty) findings.
    let probe = context.scratch_dir.join("refresh-probe");
    std::fs::create_dir_all(&probe)
        .map_err(|e| format!("cannot prepare a refresh directory: {e}"))?;

    let progress_app = app.clone();
    let on_progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("binscan://progress", Value::from(line));
    });

    let request = crate::binscan::run::BinaryScanRequest {
        path: probe.to_string_lossy().into_owned(),
        severity: None,
        offline: false,
        update: Some("now".into()),
    };

    crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel,
        BINARY_SCAN_TIMEOUT,
        on_progress,
        None,
    )
    .await
    .map(|_| ())
}

/// Ask an in-flight binary scan to stop; the child process is killed.
#[tauri::command]
pub fn cancel_binary_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_binary_scan.store(true, Ordering::Relaxed);
    Ok(())
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

/// Start a streaming chat turn. Returns immediately with a `run_id`; the turn
/// runs on a background task that emits events:
///   `ai://started` { runId } · `ai://event` { runId, type, ... }
///   `ai://done`    { runId, content, model, usage }
///   `ai://error`   { runId, message }
#[tauri::command]
pub async fn stream_chat(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ChatRequest,
    run_id: Option<String>,
) -> Result<StreamStarted, String> {
    let settings = state.settings.lock().unwrap().ai.clone();
    if !settings.enabled {
        return Err("AI is disabled — enable it in Settings and configure an endpoint.".into());
    }
    let run_id = resolve_stream_run_id(run_id)?;
    let run_id_response = run_id.clone();
    let cancel = Arc::new(crate::agent::tool::RunCancellation::new());
    let steer = Arc::new(crate::agent::tool::SteerQueue::new());
    let project_root = capture_active_project(&state);
    {
        let mut active_chats = state.active_chats.lock().unwrap();
        if active_chats.contains_key(&run_id) {
            return Err("a chat stream with that run id is already active".into());
        }
        active_chats.insert(run_id.clone(), cancel.clone());
        state
            .pending_steers
            .lock()
            .unwrap()
            .insert(run_id.clone(), steer.clone());
    }

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
        let event_run_id = run_id.clone();
        let emitter: Arc<dyn Fn(crate::ai::AiStreamEvent) + Send + Sync> = Arc::new(move |ev| {
            if let Ok(payload) = stream_event_payload(&event_run_id, ev) {
                let _ = app2_emit.emit("ai://event", payload);
            }
        });
        let result = crate::agent::loop_engine::run_turn(
            &client,
            &settings,
            &registry,
            user_messages,
            conversation_id.clone(),
            project_root,
            app2.clone(),
            Some(cancel.clone()),
            Some(steer.clone()),
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
            if let Ok(mut steers) = app_state.pending_steers.lock() {
                steers.remove(&run_id);
            }
        }
    });

    Ok(StreamStarted { run_id: run_id_response })
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
    fn chat_run_keeps_the_project_snapshot_taken_at_start() {
        let state = AppState::new();
        *state.active_project.lock().unwrap() = Some(PathBuf::from("/first/project"));

        let captured = capture_active_project(&state);
        *state.active_project.lock().unwrap() = Some(PathBuf::from("/second/project"));

        assert_eq!(captured, Some(PathBuf::from("/first/project")));
    }
}

/// Request cancellation of an in-flight chat stream.
#[tauri::command]
pub fn cancel_chat(state: State<'_, AppState>, run_id: String) -> Result<(), String> {
    if let Some(cancellation) = state.active_chats.lock().unwrap().get(&run_id) {
        cancellation.cancel();
    }
    Ok(())
}

/// The agent's todo list for one conversation.
///
/// The live list arrives on the event stream while a turn runs; this is how the
/// UI recovers it when switching back to a session between turns.
#[tauri::command]
pub fn todo_list(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<crate::agent::tools::TodoItem>, String> {
    Ok(state
        .todos
        .lock()
        .unwrap()
        .get(&conversation_id)
        .cloned()
        .unwrap_or_default())
}

/// Queue a message for a turn that is already running.
///
/// Returns `false` when the run is no longer active, which is the signal for the
/// caller to send the text as an ordinary new turn instead. This races by
/// nature: the turn can finish between the user pressing Enter and this landing.
#[tauri::command]
pub fn steer_chat(
    state: State<'_, AppState>,
    run_id: String,
    message: String,
) -> Result<bool, String> {
    let message = message.trim().to_string();
    if message.is_empty() {
        return Err("steer message must not be empty".into());
    }
    if message.len() > MAX_STEER_CHARS {
        return Err(format!(
            "steer message is too long (limit {MAX_STEER_CHARS} characters)"
        ));
    }

    // The queue itself is the authority on whether the run can still take a
    // message: it is removed when the run tears down, and closed atomically
    // while empty just before the run finishes. No separate liveness check can
    // be as precise, because the run could finish between the two lookups.
    match state.pending_steers.lock().unwrap().get(&run_id) {
        Some(queue) => Ok(queue.push(message)),
        None => Ok(false),
    }
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

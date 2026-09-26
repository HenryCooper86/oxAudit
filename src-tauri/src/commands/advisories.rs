//! Desktop commands over the local advisory database — the GUI face of
//! `oxaudit-cli advisory-db update/status`.

use super::*;

/// What the Advisory Database page shows for one database file.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryDbStatus {
    pub path: String,
    pub schema_version: u64,
    pub ecosystems: Vec<String>,
    pub advisories: usize,
    pub packages: usize,
    pub built_at_ms: Option<u64>,
    pub updated_at_ms: Option<u64>,
    pub size_bytes: u64,
}

fn open_db(path: &str) -> Result<crate::advisories::store::AdvisoryDb, String> {
    let path = std::path::Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::private_storage::ensure_private_dir(parent)?;
        }
    }
    crate::advisories::store::AdvisoryDb::open(path)
}

/// The advisory database file the app manages by default, so pages that use
/// one can prefill the path instead of asking the user to invent one. The CLI
/// has no equivalent default — it always takes an explicit `--db`.
#[tauri::command]
pub fn default_advisory_db_path(app: AppHandle) -> Result<String, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("cannot resolve the app data directory: {error}"))?;
    Ok(dir
        .join("advisories.sqlite3")
        .to_string_lossy()
        .replace('\\', "/"))
}

#[tauri::command]
pub fn advisory_db_status(path: String) -> Result<AdvisoryDbStatus, String> {
    let db = open_db(&path)?;
    let (advisories, packages) = db.counts()?;
    let size_bytes = std::fs::metadata(std::path::Path::new(&path))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    Ok(AdvisoryDbStatus {
        path,
        schema_version: crate::advisories::store::SCHEMA_VERSION,
        ecosystems: db.ecosystems()?,
        advisories,
        packages,
        built_at_ms: db.built_at_ms(),
        updated_at_ms: db.updated_at_ms(),
        size_bytes,
    })
}

#[tauri::command]
pub async fn advisory_db_update(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    ecosystems: Vec<String>,
    source: Option<String>,
) -> Result<serde_json::Value, String> {
    struct TauriEvents(AppHandle);
    impl crate::findings::service::ScanEventSink for TauriEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let mut store = open_db(&path)?;
    advisory_db_update_engine(
        &state.http,
        &mut store,
        ecosystems,
        source,
        &TauriEvents(app),
    )
    .await
}

/// The advisory database refresh minus its Tauri wiring; the headless server
/// emits the same `advisorydb://progress` and `advisorydb://done` events over
/// its own hub.
pub(crate) async fn advisory_db_update_engine(
    http: &reqwest::Client,
    store: &mut crate::advisories::store::AdvisoryDb,
    ecosystems: Vec<String>,
    source: Option<String>,
    events: &dyn crate::findings::service::ScanEventSink,
) -> Result<serde_json::Value, String> {
    let mut fetcher = match &source {
        Some(base) => crate::advisories::ingest::HttpDumpFetcher::with_base(http.clone(), base),
        None => crate::advisories::ingest::HttpDumpFetcher::new(http.clone()),
    };
    let mut selected: Vec<String> = crate::advisories::ingest::DEFAULT_ECOSYSTEMS
        .iter()
        .map(|ecosystem| ecosystem.to_string())
        .collect();
    for ecosystem in &ecosystems {
        if !selected.iter().any(|existing| existing == ecosystem) {
            selected.push(ecosystem.clone());
        }
    }
    let report = crate::advisories::ingest::update(store, &selected, &mut fetcher, |line| {
        let _ = events.emit("advisorydb://progress", serde_json::Value::from(line));
    })
    .await
    .map_err(|error| format!("cannot update the advisory database: {error}"))?;
    let _ = events.emit(
        "advisorydb://done",
        serde_json::json!({ "advisories": report.total_advisories }),
    );
    Ok(serde_json::json!({
        "ecosystems": report.ecosystems.iter().map(|ecosystem| serde_json::json!({
            "ecosystem": ecosystem.ecosystem,
            "records": ecosystem.records,
        })).collect::<Vec<_>>(),
        "totalAdvisories": report.total_advisories,
        "totalPackages": report.total_packages,
        "builtAtMs": report.built_at_ms,
    }))
}

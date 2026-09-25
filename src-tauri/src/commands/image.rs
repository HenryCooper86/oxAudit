//! Desktop image-scanning command — the GUI face of `oxaudit-cli image`,
//! including registry references and offline advisory matching.

use super::*;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageScanRequest {
    /// Registry reference (`registry/ns/repo:tag`) or a local path.
    pub target: String,
    pub advisory_db_path: Option<String>,
    pub offline: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageScanOutcome {
    pub result: crate::binscan::report::BinaryScanResult,
    pub notes: Vec<String>,
}

#[tauri::command]
pub async fn scan_image(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ImageScanRequest,
) -> Result<ImageScanOutcome, String> {
    state.cancel_binary_scan.store(false, Ordering::SeqCst);
    let cancel = state.cancel_binary_scan.clone();

    let progress_app = app.clone();
    let progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("image://progress", serde_json::Value::from(line));
    });

    let advisory_db = match &request.advisory_db_path {
        Some(path) => Some(
            crate::advisories::store::AdvisoryDb::open(std::path::Path::new(path))
                .map_err(|error| format!("cannot open {path}: {error}"))?,
        ),
        None => None,
    };

    // Resolve the target: registry reference or local path. The heavy scan
    // runs on the blocking pool; downloads stay on the async runtime.
    let scanned = if let Some(reference) = crate::binscan::registry::parse_ref(&request.target) {
        let http = state.http.clone();
        let progress_sink = progress.clone();
        let image = crate::binscan::registry::fetch_image_layers(&http, &reference, move |line| {
            progress_sink(line)
        })
        .await
        .map_err(|error| {
            format!(
                "cannot pull {request_target}: {error}",
                request_target = request.target
            )
        })?;
        let display = image.display.clone();
        let layers = image.layers;
        let cancel_scan = cancel.clone();
        let progress_scan = progress.clone();
        tauri::async_runtime::spawn_blocking(move || {
            crate::binscan::native::scan::scan_image_layers(
                &display,
                &layers,
                &cancel_scan,
                progress_scan,
            )
        })
        .await
        .map_err(|error| format!("the image scan task failed: {error}"))??
    } else {
        let target = std::path::PathBuf::from(&request.target);
        if !target.exists() {
            return Err(format!(
                "{} does not exist, and it is not a registry reference",
                request.target
            ));
        }
        let target = target.canonicalize().map_err(|error| error.to_string())?;
        let cancel_scan = cancel.clone();
        let progress_scan = progress.clone();
        tauri::async_runtime::spawn_blocking(move || {
            crate::binscan::native::scan::scan(&target, cancel_scan, progress_scan)
        })
        .await
        .map_err(|error| format!("the image scan task failed: {error}"))??
    };

    let mut result = scanned.result;
    let mut notes = scanned.notes;

    if let Some(db) = &advisory_db {
        let local = crate::binscan::native::enrich::enrich_local(db, &scanned.queries);
        crate::binscan::native::enrich::apply(&mut result, local.found);
        notes.extend(local.notes);
    }

    if !request.offline {
        if !scanned.queries.is_empty() {
            if let Some(cve) = app.try_state::<crate::cve::CveState>() {
                let cache_dir = app
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::env::temp_dir());
                let nvd_api_key = crate::credentials::resolve_nvd_key(state.credentials.as_ref())
                    .map_err(|error| error.to_string())?;
                let enriched = crate::binscan::native::enrich::enrich(
                    &cve,
                    &cache_dir,
                    nvd_api_key.as_deref().map(|key| key.as_str()),
                    &scanned.queries,
                    cancel.clone(),
                    progress.clone(),
                )
                .await;
                crate::binscan::native::enrich::apply(&mut result, enriched.found);
                notes.extend(enriched.notes);
            } else {
                notes.push("CVE lookup was skipped because no CVE client is available.".into());
            }
        }
    } else {
        let cpe_askable = scanned
            .queries
            .iter()
            .filter(|query| {
                crate::binscan::native::enrich::cpe_match_string(
                    &query.vendor,
                    &query.product,
                    &query.version,
                )
                .is_some()
            })
            .count();
        if cpe_askable > 0 {
            notes.push(format!(
                "{cpe_askable} CPE-keyed component(s) can only be answered by NVD, which needs the network; they are listed without vulnerabilities in this offline scan"
            ));
        }
    }

    let _ = app.emit(
        "image://done",
        serde_json::json!({ "components": result.summary.components }),
    );
    Ok(ImageScanOutcome { result, notes })
}

#[tauri::command]
pub fn cancel_image_scan(state: State<'_, AppState>) {
    state.cancel_binary_scan.store(true, Ordering::SeqCst);
}

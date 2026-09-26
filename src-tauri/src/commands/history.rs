//! Git history secret scanning command.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;
use crate::models::Finding;

/// The result of a history scan, as the workbench consumes it.
///
/// Findings are not persisted as a canonical run: they describe objects in
/// git history, not the working tree a stored run's projection is indexed
/// against. The response is the whole run — small by construction, because
/// one credential in one file is one finding.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryScanResponse {
    pub findings: Vec<Finding>,
    pub blobs_scanned: usize,
    pub blobs_skipped: usize,
    pub truncated: bool,
    pub limit_note: Option<String>,
    /// Present only when the caller opted into live validation, mirroring
    /// the CLI's `--validate-secrets` summary.
    pub validation: Option<crate::secrets_validation::ValidationSummary>,
}

#[tauri::command]
pub async fn scan_history_secrets(
    state: State<'_, AppState>,
    path: String,
    validate_secrets: Option<bool>,
) -> Result<HistoryScanResponse, String> {
    scan_history_secrets_engine(&state.http, path, validate_secrets).await
}

/// The history scan minus its Tauri wiring; the server passes its own HTTP
/// client for live credential validation.
pub(crate) async fn scan_history_secrets_engine(
    http: &reqwest::Client,
    path: String,
    validate_secrets: Option<bool>,
) -> Result<HistoryScanResponse, String> {
    let target = PathBuf::from(path.trim());
    if target.as_os_str().is_empty() {
        return Err("choose a repository folder first".into());
    }
    if !target.is_dir() {
        return Err(format!("{} is not a directory", target.display()));
    }
    let validating = validate_secrets.unwrap_or(false);
    // The engine's own budgets (blobs, bytes, wall clock) bound this work;
    // spawn_blocking keeps it off the async runtime's threads regardless.
    let mut outcome = tauri::async_runtime::spawn_blocking(move || {
        crate::history::scan_history_secrets_with_options(&target, validating)
    })
    .await
    .map_err(|_| "history scan task failed".to_string())??;
    let validation = if validating {
        let raw = std::mem::take(&mut outcome.raw_secrets);
        Some(
            crate::secrets_validation::validate_raw_secrets(&mut outcome.findings, raw, http).await,
        )
    } else {
        None
    };
    Ok(HistoryScanResponse {
        findings: outcome.findings,
        blobs_scanned: outcome.blobs_scanned,
        blobs_skipped: outcome.blobs_skipped,
        truncated: outcome.truncated,
        limit_note: outcome.limit_note,
        validation,
    })
}

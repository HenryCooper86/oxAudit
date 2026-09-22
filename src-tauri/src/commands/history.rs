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
}

#[tauri::command]
pub async fn scan_history_secrets(path: String) -> Result<HistoryScanResponse, String> {
    let target = PathBuf::from(path.trim());
    if target.as_os_str().is_empty() {
        return Err("choose a repository folder first".into());
    }
    if !target.is_dir() {
        return Err(format!("{} is not a directory", target.display()));
    }
    // The engine's own budgets (blobs, bytes, wall clock) bound this work;
    // spawn_blocking keeps it off the async runtime's threads regardless.
    tauri::async_runtime::spawn_blocking(move || crate::history::scan_history_secrets(&target))
        .await
        .map_err(|_| "history scan task failed".to_string())
        .map(|result| {
            result.map(|outcome| HistoryScanResponse {
                findings: outcome.findings,
                blobs_scanned: outcome.blobs_scanned,
                blobs_skipped: outcome.blobs_skipped,
                truncated: outcome.truncated,
                limit_note: outcome.limit_note,
            })
        })?
}

//! CVE and advisory research commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

#[tauri::command]
pub async fn search_cves(
    state: State<'_, CveState>,
    app_state: State<'_, AppState>,
    query: String,
    start_index: usize,
    per_page: usize,
    recent_days: Option<u64>,
) -> Result<crate::models::CveSearchResult, String> {
    let key = crate::credentials::resolve_nvd_key(app_state.credentials.as_ref())
        .map_err(|error| error.to_string())?;
    crate::cve::search_cves(
        &state,
        key.as_ref().map(|key| key.as_str()),
        &query,
        start_index,
        per_page,
        recent_days,
    )
    .await
}

#[tauri::command]
pub async fn cve_detail(
    state: State<'_, CveState>,
    app_state: State<'_, AppState>,
    id: String,
) -> Result<crate::models::CveDetail, String> {
    let key = crate::credentials::resolve_nvd_key(app_state.credentials.as_ref())
        .map_err(|error| error.to_string())?;
    crate::cve::cve_detail(&state, key.as_ref().map(|key| key.as_str()), &id).await
}

#[tauri::command]
pub async fn osv_package_vulns(
    state: State<'_, CveState>,
    ecosystem: String,
    name: String,
) -> Result<Vec<Value>, String> {
    crate::cve::osv_package_vulns(&state, &ecosystem, &name).await
}

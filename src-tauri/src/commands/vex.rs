//! Desktop commands over trusted VEX claims — the GUI face of
//! `oxaudit-cli vex claims/trust/revoke/suggest` (ADR 0003: trusted claims
//! inform, humans decide).

use super::*;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VexClaimSet {
    pub run_id: String,
    pub content_sha256: String,
    pub format: String,
    pub claims: usize,
    pub trusted: bool,
    pub granted_by: Option<String>,
    pub granted_at_ms: Option<u64>,
}

#[tauri::command]
pub fn vex_claim_sets(findings: State<'_, FindingsState>) -> Result<Vec<VexClaimSet>, String> {
    vex_claim_sets_inner(&findings)
}

pub(crate) fn vex_claim_sets_inner(findings: &FindingsState) -> Result<Vec<VexClaimSet>, String> {
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    let sets = crate::vex_trust::claim_sets(repository)?;
    let grants = crate::vex_trust::trust_grants(repository)?;
    Ok(sets
        .into_iter()
        .map(|set| {
            let grant = grants
                .iter()
                .find(|grant| grant.content_sha256 == set.content_sha256);
            VexClaimSet {
                run_id: set.run_id,
                content_sha256: set.content_sha256,
                format: set.format,
                claims: set.claims.len(),
                trusted: grant.is_some(),
                granted_by: grant.map(|grant| grant.granted_by.clone()),
                granted_at_ms: grant.map(|grant| grant.granted_at_ms),
            }
        })
        .collect())
}

#[tauri::command]
pub fn vex_grant_trust(
    findings: State<'_, FindingsState>,
    content_sha256: String,
    granted_by: String,
    note: Option<String>,
) -> Result<(), String> {
    vex_grant_trust_inner(&findings, content_sha256, granted_by, note)
}

pub(crate) fn vex_grant_trust_inner(
    findings: &FindingsState,
    content_sha256: String,
    granted_by: String,
    note: Option<String>,
) -> Result<(), String> {
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    crate::vex_trust::grant_trust(
        repository,
        &content_sha256,
        &granted_by,
        note.as_deref().unwrap_or(""),
    )?;
    Ok(())
}

#[tauri::command]
pub fn vex_revoke_trust(
    findings: State<'_, FindingsState>,
    content_sha256: String,
) -> Result<(), String> {
    vex_revoke_trust_inner(&findings, content_sha256)
}

pub(crate) fn vex_revoke_trust_inner(
    findings: &FindingsState,
    content_sha256: String,
) -> Result<(), String> {
    let repository = findings
        .service()
        .map_err(|error| error.to_string())?
        .repository();
    crate::vex_trust::revoke_trust(repository, &content_sha256)?;
    Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VexSuggestions {
    #[serde(flatten)]
    pub report: crate::vex_trust::SuggestionReport,
    /// The dependency run's label, for display.
    pub run_target: String,
}

#[tauri::command]
pub fn vex_suggest(
    findings: State<'_, FindingsState>,
    run_id: String,
) -> Result<VexSuggestions, String> {
    vex_suggest_inner(&findings, run_id)
}

pub(crate) fn vex_suggest_inner(
    findings: &FindingsState,
    run_id: String,
) -> Result<VexSuggestions, String> {
    let service = findings.service().map_err(|error| error.to_string())?;
    let repository = service.repository();
    let identity = oxaudit_domain::RunId::parse(run_id.clone())
        .map_err(|_| format!("'{run_id}' is not a run identity"))?;
    let projection = repository
        .canonical_load_projection(&identity)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("run {run_id} has no stored projection"))?;
    let scan: crate::models::DependencyScanResult = serde_json::from_value(projection)
        .map_err(|error| format!("run {run_id} is not a dependency scan: {error}"))?;
    let run_target = scan.summary.path.clone();
    let sets = crate::vex_trust::claim_sets(repository)?;
    let grants = crate::vex_trust::trust_grants(repository)?;
    let report = crate::vex_trust::suggest(&sets, &grants, &scan.vulnerabilities);
    Ok(VexSuggestions { report, run_target })
}

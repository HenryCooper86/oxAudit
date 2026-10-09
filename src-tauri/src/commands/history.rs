//! Shared durable Git-history scan for desktop, server and CLI.
use super::*;
use crate::models::Finding;
use oxaudit_domain::{Run, RunKind, RunState};
use std::collections::BTreeMap;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryScanResponse {
    pub run_id: String,
    pub state: RunState,
    pub target: String,
    pub findings: Vec<Finding>,
    pub blobs_scanned: usize,
    pub blobs_skipped: usize,
    pub truncated: bool,
    pub limit_note: Option<String>,
    pub duration_ms: u64,
    pub validation_enabled: bool,
    pub validation: Option<crate::secrets_validation::ValidationSummary>,
    pub git_context: Option<crate::history::HistoryGitContext>,
    pub blobs: Vec<crate::history::HistoryBlobEvidence>,
    pub finding_blob_ids: BTreeMap<String, String>,
}

#[tauri::command]
pub async fn scan_history_secrets(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    path: String,
    validate_secrets: Option<bool>,
    operation_id: Option<String>,
) -> Result<HistoryScanResponse, String> {
    struct Events(AppHandle);
    impl ScanEventSink for Events {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    scan_history_secrets_engine(
        &state,
        &findings,
        &Events(app),
        path,
        validate_secrets,
        operation_id,
    )
    .await
}

pub(crate) async fn scan_history_secrets_engine(
    state: &AppState,
    findings: &FindingsState,
    events: &dyn ScanEventSink,
    path: String,
    validate_secrets: Option<bool>,
    operation_id: Option<String>,
) -> Result<HistoryScanResponse, String> {
    let mut work = state.scan_work.begin(
        crate::scan_work::WorkKind::History,
        &path,
        operation_id.as_deref(),
        events,
    )?;
    let cancel = work.cancellation();
    let result = scan_history_workflow(
        findings
            .service()
            .map_err(|error| error.to_string())?
            .repository(),
        &state.http,
        path,
        validate_secrets.unwrap_or(false),
        &cancel,
        &work,
    )
    .await;
    if let Ok(outcome) = &result {
        work.finish(
            match outcome.state {
                RunState::Completed => "completed",
                RunState::Incomplete => "incomplete",
                RunState::Cancelled => "cancelled",
                _ => "failed",
            },
            Some(&outcome.run_id),
        );
    }
    result
}

fn save_projection(
    repository: &crate::findings::repository::FindingsRepository,
    identity: &oxaudit_domain::RunId,
    outcome: &HistoryScanResponse,
) -> Result<(), String> {
    let mut payload = serde_json::to_value(outcome).map_err(|error| error.to_string())?;
    // The immutable projection carries observations; canonical lifecycle state
    // is supplied on loading, including a later completion-save failure.
    payload
        .as_object_mut()
        .expect("history response is an object")
        .remove("state");
    payload.as_object_mut().expect("history response is an object").insert("coverage".into(), json!({
        "scope":"unique reachable blobs; no dangling objects; first enumerated path per blob",
        "maxBlobBytes":1048576, "maxTotalTextBytes":268435456, "maxBlobs":100000,
        "maxFindings":10000, "filteredOversizedBlobCount":null,
        "notes":"Oversized blobs are filtered by Git; their exact count is unknown. Non-UTF-8 and quoted paths are not scanned."
    }));
    repository
        .canonical_save_projection(identity, "history", 1, &payload)
        .map_err(|error| error.to_string())
}

pub(crate) async fn scan_history_workflow(
    repository: &crate::findings::repository::FindingsRepository,
    http: &reqwest::Client,
    path: String,
    validate_secrets: bool,
    cancel: &Arc<AtomicBool>,
    events: &dyn ScanEventSink,
) -> Result<HistoryScanResponse, String> {
    let started = std::time::Instant::now();
    let target = PathBuf::from(path);
    let label = target
        .canonicalize()
        .unwrap_or_else(|_| target.clone())
        .to_string_lossy()
        .into_owned();
    let adapter = crate::adapters::persistence::CanonicalSqliteRepository::new(repository);
    let run_events = crate::presentation::CanonicalRunEvents::new(events);
    let coordinator = oxaudit_application::RunCoordinator::new(&adapter, &run_events);
    let mut queued = Run::queued(RunKind::History, &label, epoch_millis());
    queued.engine_ids.push("oxaudit.native.git-history".into());
    let mut managed = Some(
        coordinator
            .begin(queued)
            .map_err(|error| error.to_string())?,
    );
    let identity = managed
        .as_ref()
        .expect("history run exists")
        .run()
        .id
        .clone();
    let result: Result<HistoryScanResponse, String> = async {
        if cancel.load(Ordering::SeqCst) { return Err("history scan cancelled".into()); }
        if target.as_os_str().is_empty() || !target.is_dir() { return Err("Choose an existing Git repository directory".into()); }
        managed.as_mut().expect("history run exists").transition(RunState::Discovering, epoch_millis()).map_err(|error| error.to_string())?;
        managed.as_mut().expect("history run exists").transition(RunState::Detecting, epoch_millis()).map_err(|error| error.to_string())?;
        let cancellation = cancel.clone();
        // Await the blocking task: cancellation stops Git and the bounded
        // producer queue rather than merely dropping this await.
        let mut outcome = tokio::task::spawn_blocking(move || crate::history::scan_history_secrets_cancellable(&target, validate_secrets, &cancellation))
            .await.map_err(|error| format!("history scan task failed: {error}"))??;
        outcome.cancelled |= cancel.load(Ordering::SeqCst);
        managed.as_mut().expect("history run exists").transition(RunState::Normalizing, epoch_millis()).map_err(|error| error.to_string())?;
        let validation = if validate_secrets && !outcome.cancelled {
            managed.as_mut().expect("history run exists").transition(RunState::Enriching, epoch_millis()).map_err(|error| error.to_string())?;
            let raw = std::mem::take(&mut outcome.raw_secrets);
            let future = crate::secrets_validation::validate_raw_secrets(&mut outcome.findings, raw, http);
            tokio::select! {
                biased;
                _ = async { while !cancel.load(Ordering::SeqCst) { tokio::time::sleep(std::time::Duration::from_millis(25)).await; } } => { outcome.cancelled = true; None },
                validation = future => Some(validation),
            }
        } else { outcome.raw_secrets.clear(); None };
        outcome.cancelled |= cancel.load(Ordering::SeqCst);
        let mut artifacts = BTreeMap::new();
        use sha2::Digest;
        for blob in &outcome.blobs {
            let artifact = oxaudit_domain::Artifact {
                id: oxaudit_domain::ArtifactId::parse(format!("artifact_{:x}", sha2::Sha256::digest(format!("{identity}\0{}", blob.oid)))).map_err(|error| error.to_string())?,
                kind: oxaudit_domain::ArtifactKind::SourceFile,
                location: oxaudit_domain::ArtifactLocation { normalized_path: format!("git:{}!{}", blob.oid, blob.path), canonical_path: None, parent_id: None },
                size_bytes: blob.size_bytes, media_type: Some("text/plain".into()), content_sha256: Some(blob.content_sha256.clone()),
            };
            managed.as_mut().expect("history run exists").append_artifact(&artifact).map_err(|error| error.to_string())?;
            artifacts.insert(blob.oid.clone(), artifact);
        }
        let mut observations = Vec::new();
        for finding in &mut outcome.findings {
            finding.observation_run_id = identity.to_string();
            let oid = outcome.finding_blob_ids.get(&finding.id).ok_or("History finding has no Git object identity")?;
            let artifact = artifacts.get(oid).ok_or("History Git artifact missing")?;
            let mut observation = crate::adapters::scanners::source_observation(&identity, artifact, finding)?;
            observation.observation.detector_id = "oxaudit.native.git-history".into();
            observations.push(observation);
        }
        managed.as_mut().expect("history run exists").append_observations(observations).map_err(|error| error.to_string())?;
        managed.as_mut().expect("history run exists").warning("history_scope", "Historical Git object locations do not identify current working-tree content. Oversized filtered blobs have an unknown count; dangling objects are not covered.");
        if let Some(note) = &outcome.limit_note { managed.as_mut().expect("history run exists").warning("history_coverage", note.clone()); }
        managed.as_mut().expect("history run exists").transition(RunState::Assessing, epoch_millis()).map_err(|error| error.to_string())?;
        managed.as_mut().expect("history run exists").transition(RunState::Persisting, epoch_millis()).map_err(|error| error.to_string())?;
        let state = if outcome.cancelled || cancel.load(Ordering::SeqCst) { RunState::Cancelled } else if outcome.truncated { RunState::Incomplete } else { RunState::Completed };
        let response = HistoryScanResponse { run_id: identity.to_string(), state, target: label.clone(), findings: outcome.findings, blobs_scanned: outcome.blobs_scanned, blobs_skipped: outcome.blobs_skipped,
            truncated: outcome.truncated || state != RunState::Completed, limit_note: outcome.limit_note, duration_ms: started.elapsed().as_millis() as u64,
            validation_enabled: validate_secrets, validation, git_context: outcome.git_context, blobs: outcome.blobs, finding_blob_ids: outcome.finding_blob_ids };
        save_projection(repository, &identity, &response)?;
        if state == RunState::Completed {
            if cancel.load(Ordering::SeqCst) { return Err("history scan cancelled".into()); }
            managed.as_mut().expect("history run exists").complete_in_place(epoch_millis()).map_err(|error| error.to_string())?;
            managed.take();
        } else { managed.take().expect("history run exists").terminate(state, epoch_millis()).map_err(|error| error.to_string())?; }
        let _ = events.emit("history://done", json!({"runId":response.run_id,"state":response.state,"blobsScanned":response.blobs_scanned}));
        Ok(response)
    }.await;
    if let Err(error) = &result {
        if let Some(mut run) = managed.take() {
            let state = if cancel.load(Ordering::SeqCst) || error.contains("cancelled") {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            let fallback = HistoryScanResponse {
                run_id: identity.to_string(),
                state,
                target: label,
                findings: Vec::new(),
                blobs_scanned: 0,
                blobs_skipped: 0,
                truncated: true,
                limit_note: Some(error.clone()),
                duration_ms: started.elapsed().as_millis() as u64,
                validation_enabled: validate_secrets,
                validation: None,
                git_context: None,
                blobs: Vec::new(),
                finding_blob_ids: BTreeMap::new(),
            };
            if repository
                .canonical_load_projection(&identity)
                .map_err(|persist| persist.to_string())?
                .is_none()
            {
                if let Err(persist) = save_projection(repository, &identity, &fallback) {
                    run.warning("history_projection_unavailable", persist);
                }
            }
            run.warning("history_failed", error.clone());
            run.terminate(state, epoch_millis()).map_err(|persist| {
                format!("{error}; could not persist terminal history state: {persist}")
            })?;
        }
    }
    result
}

#[tauri::command]
pub fn cancel_history_scan(state: State<'_, AppState>) {
    let _ = state
        .scan_work
        .cancel(None, &[crate::scan_work::WorkKind::History]);
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;

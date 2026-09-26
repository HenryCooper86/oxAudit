//! Portfolio re-scan scheduling commands and the shared scheduled-scan runner.

use super::*;

/// One project's schedule with its next fire time, as the Portfolio shows it.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanScheduleStatus {
    #[serde(flatten)]
    pub record: crate::schedule_store::ScheduleRecord,
    pub next_due_at: Option<String>,
}

#[tauri::command]
pub fn list_scan_schedules(
    schedules: State<'_, crate::schedule_store::ScheduleState>,
) -> Result<Vec<ScanScheduleStatus>, String> {
    Ok(schedules
        .store()?
        .list()
        .into_iter()
        .map(|record| ScanScheduleStatus {
            next_due_at: crate::schedule_store::next_due(&record).map(|when| when.to_rfc3339()),
            record,
        })
        .collect())
}

#[tauri::command]
pub fn set_scan_schedule(
    schedules: State<'_, crate::schedule_store::ScheduleState>,
    project_id: String,
    canonical_path: String,
    display_name: String,
    interval_hours: u32,
    enabled: bool,
) -> Result<crate::schedule_store::ScheduleRecord, String> {
    schedules.store()?.upsert(
        &project_id,
        &canonical_path,
        &display_name,
        interval_hours,
        enabled,
    )
}

#[tauri::command]
pub fn remove_scan_schedule(
    schedules: State<'_, crate::schedule_store::ScheduleState>,
    project_id: String,
) -> Result<(), String> {
    schedules.store()?.remove(&project_id)
}

/// Run one project's scan now, through the same runner the background
/// scheduler uses, and wait for the result so the Portfolio can show it.
#[tauri::command]
pub async fn run_scan_now(
    app: AppHandle,
    project_id: String,
    canonical_path: String,
) -> Result<ScanRunDetail, CommandError> {
    run_scheduled_scan(&app, &project_id, &canonical_path).await
}

/// The one scan path both the scheduler and "scan now" use. Applies saved
/// scan settings and enabled rule packs, marks the schedule as started only
/// when the scan actually launches, and emits a completion event either way
/// — a scheduled scan that fails is a fact the Portfolio must show, not a
/// silent gap in the cadence.
pub async fn run_scheduled_scan(
    app: &AppHandle,
    project_id: &str,
    canonical_path: &str,
) -> Result<ScanRunDetail, CommandError> {
    let state = app
        .try_state::<AppState>()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let findings = app
        .try_state::<FindingsState>()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let cve = app
        .try_state::<CveState>()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let rule_packs = app.try_state::<crate::rulepack_store::RulePacksState>();
    struct ScheduledEvents(AppHandle);
    impl ScanEventSink for ScheduledEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let events = ScheduledEvents(app.clone());
    let emit_schedule_completed = |result: &Result<ScanRunDetail, CommandError>| {
        let _ = app.emit(
            "schedule://completed",
            serde_json::json!({
                "projectId": project_id,
                "canonicalPath": canonical_path,
                "ok": result.is_ok(),
                "runId": result.as_ref().map(|detail| detail.run_id.clone()),
                "findings": result.as_ref().map(|detail| detail.summary.total_findings),
                "error": result.as_ref().err().map(|error| error.to_string()),
            }),
        );
    };
    run_scheduled_scan_engine(
        &state,
        &findings,
        &cve,
        rule_packs.as_deref(),
        &events,
        &emit_schedule_completed,
        canonical_path,
    )
    .await
}

/// The scheduled re-scan minus its Tauri wiring. The headless server runs
/// the same function from its own ticker, passing its own event sink and a
/// completion callback that publishes `schedule://completed` to the hub.
pub(crate) async fn run_scheduled_scan_engine(
    state: &AppState,
    findings: &FindingsState,
    cve: &CveState,
    rule_packs: Option<&crate::rulepack_store::RulePacksState>,
    events: &dyn ScanEventSink,
    publish_completed: &(dyn Fn(&Result<ScanRunDetail, CommandError>) + Send + Sync),
    canonical_path: &str,
) -> Result<ScanRunDetail, CommandError> {
    let saved = state.settings.lock().unwrap().scan.clone();
    let options = ScanOptions {
        path: canonical_path.to_owned(),
        include_git: saved.include_git,
        follow_symlinks: saved.follow_symlinks,
        max_file_size_kb: saved.max_file_size_kb.max(1),
        scan_secrets: saved.scan_secrets,
        scan_vulnerabilities: saved.scan_vulnerabilities,
        extra_ignored_dirs: Vec::new(),
        // A broken policy must surface through the scheduled scan, not be
        // quietly bypassed by an unattended run.
        ignore_invalid_policy: false,
        extra_rule_pack_files: Vec::new(),
    };

    let packs = match rule_packs {
        Some(rule_packs) => match rule_packs.store() {
            Ok(store) => {
                let resolved = store.resolve_enabled();
                for (id, reason) in &resolved.skipped {
                    tracing::warn!(pack = %id, reason = %reason, "enabled rule pack skipped");
                }
                crate::scanners::rulepacks::AppliedRulePacks::from_compiled(resolved.packs)
            }
            Err(error) => {
                tracing::warn!(reason = %error, "rule packs not applied");
                crate::scanners::rulepacks::AppliedRulePacks::empty()
            }
        },
        None => crate::scanners::rulepacks::AppliedRulePacks::empty(),
    };

    let cancel = std::sync::Arc::new(AtomicBool::new(false));

    let result = findings
        .service()?
        .scan_with_packs(options, cve, &cancel, events, &packs)
        .await;
    publish_completed(&result);
    result
}

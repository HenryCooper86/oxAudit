//! Portfolio re-scan scheduling commands and the shared scheduled-scan runner.

use super::*;

pub(crate) struct ScheduledScanTarget<'a> {
    pub canonical_path: &'a str,
    pub project_id: &'a str,
    pub schedules: Option<&'a crate::schedule_store::ScheduleStore>,
}

pub(crate) fn completion_payload(
    project_id: &str,
    canonical_path: &str,
    result: &Result<ScanRunDetail, CommandError>,
) -> Value {
    let error = match result {
        Err(error) => Some(error.to_string()),
        Ok(detail) if detail.status != crate::findings::domain::RunStatus::Completed => {
            Some("The scan did not complete.".to_owned())
        }
        Ok(detail) if detail.persistence != crate::findings::domain::RunPersistence::Saved => {
            Some("The scan completed, but results were not saved.".to_owned())
        }
        _ => None,
    };
    serde_json::json!({
        "projectId": project_id,
        "canonicalPath": canonical_path,
        "ok": error.is_none(),
        "runId": result.as_ref().ok().map(|detail| detail.run_id.clone()),
        "findings": result.as_ref().ok().map(|detail| detail.summary.total_findings),
        "error": error,
    })
}

/// Record a launch only after the scan acquired its project and started a run.
/// A rejected target, policy, or colliding scan cannot advance the cadence.
struct ScheduledEvents<'a> {
    events: &'a dyn ScanEventSink,
    target: ScheduledScanTarget<'a>,
    started: AtomicBool,
}

impl ScanEventSink for ScheduledEvents<'_> {
    fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
        if event == "scan://progress" && !self.started.swap(true, Ordering::SeqCst) {
            if let Some(store) = self.target.schedules {
                // Scan now is also available to projects without a schedule.
                let _ =
                    store.mark_started(self.target.project_id, &chrono::Utc::now().to_rfc3339());
            }
        }
        self.events.emit(event, payload)
    }
}

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
            completion_payload(project_id, canonical_path, result),
        );
    };
    let schedules = app.try_state::<crate::schedule_store::ScheduleState>();
    run_scheduled_scan_engine(
        &state,
        &findings,
        &cve,
        rule_packs.as_deref(),
        &events,
        &emit_schedule_completed,
        ScheduledScanTarget {
            canonical_path,
            project_id,
            schedules: schedules.as_ref().and_then(|state| state.store().ok()),
        },
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
    target: ScheduledScanTarget<'_>,
) -> Result<ScanRunDetail, CommandError> {
    let saved = state.settings.lock().unwrap().scan.clone();
    let options = ScanOptions {
        path: target.canonical_path.to_owned(),
        include_git: saved.include_git,
        follow_symlinks: saved.follow_symlinks,
        max_file_size_kb: saved.max_file_size_kb.max(1),
        scan_secrets: saved.scan_secrets,
        scan_vulnerabilities: saved.scan_vulnerabilities,
        extra_ignored_dirs: saved.ignored_dirs,
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
    let events = ScheduledEvents {
        events,
        target,
        started: AtomicBool::new(false),
    };

    let result = if !options.scan_secrets && !options.scan_vulnerabilities {
        Err(CommandError::data_operation_failed(
            "Enable a source scan category in Settings before running a scheduled scan.",
        ))
    } else {
        match findings.service() {
            Ok(service) => {
                service
                    .scan_with_packs(options, cve, &cancel, &events, &packs)
                    .await
            }
            Err(error) => Err(error),
        }
    };
    publish_completed(&result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoEvents;
    impl ScanEventSink for NoEvents {
        fn emit(&self, _event: &str, _payload: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn scheduled_scans_honor_saved_ignored_directories() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir_all(project.join("excluded")).unwrap();
        std::fs::write(project.join("app.js"), "const safe = 1;\n").unwrap();
        std::fs::write(project.join("excluded/app.js"), "eval(input);\n").unwrap();
        let app = AppState::new();
        {
            let mut settings = app.settings.lock().unwrap();
            settings.scan.ignored_dirs = vec!["excluded".into()];
            settings.scan.scan_secrets = false;
        }
        let findings =
            crate::initialize_findings_state(&directory.path().join("data"), chrono::Utc::now());
        let cve = CveState::new(app.http.clone());
        *cve.kev.lock().unwrap() = Some((std::time::Instant::now(), Default::default()));
        let store =
            crate::schedule_store::ScheduleStore::open(&directory.path().join("schedules.sqlite3"))
                .unwrap();
        store
            .upsert("p1", project.to_str().unwrap(), "project", 24, true)
            .unwrap();
        let completed = Mutex::new(Value::Null);
        let result = run_scheduled_scan_engine(
            &app,
            &findings,
            &cve,
            None,
            &NoEvents,
            &|result| {
                *completed.lock().unwrap() =
                    completion_payload("p1", project.to_str().unwrap(), result)
            },
            ScheduledScanTarget {
                canonical_path: project.to_str().unwrap(),
                project_id: "p1",
                schedules: Some(&store),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.summary.files_scanned, 1);
        assert!(result.findings.is_empty());
        let payload = completed.lock().unwrap();
        assert_eq!(payload["findings"], 0);
        assert_eq!(payload["runId"], result.run_id);
        assert!(
            store.list()[0].last_started_at.is_some(),
            "real launches must advance the schedule, including Scan now"
        );
        let mut unsaved = result.clone();
        unsaved.persistence = crate::findings::domain::RunPersistence::NotSaved {
            retry_token: "retry".into(),
        };
        let payload = completion_payload("p1", project.to_str().unwrap(), &Ok(unsaved));
        assert_eq!(payload["ok"], false);
        assert!(payload["error"].as_str().unwrap().contains("not saved"));
    }

    #[tokio::test]
    async fn unavailable_findings_storage_still_publishes_schedule_failure() {
        let app = AppState::new();
        let findings = FindingsState::unavailable(CommandError::persistence_unavailable());
        let cve = CveState::new(app.http.clone());
        let completed = Mutex::new(Vec::new());
        let result = run_scheduled_scan_engine(
            &app,
            &findings,
            &cve,
            None,
            &NoEvents,
            &|result| completed.lock().unwrap().push(result.is_ok()),
            ScheduledScanTarget {
                canonical_path: "/unused",
                project_id: "p1",
                schedules: None,
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*completed.lock().unwrap(), [false]);
    }

    #[test]
    fn failed_schedule_events_have_null_run_and_finding_fields() {
        let payload = completion_payload("p1", "/project", &Err(CommandError::invalid_target()));
        assert_eq!(payload["ok"], false);
        assert!(payload["runId"].is_null());
        assert!(payload["findings"].is_null());
        assert!(payload["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn a_refused_schedule_launch_keeps_its_previous_start_time() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            crate::schedule_store::ScheduleStore::open(&directory.path().join("schedules.sqlite3"))
                .unwrap();
        store.upsert("p1", "/missing", "project", 24, true).unwrap();
        store.mark_started("p1", "2026-10-01T00:00:00Z").unwrap();
        let app = AppState::new();
        let findings =
            crate::initialize_findings_state(&directory.path().join("data"), chrono::Utc::now());
        let cve = CveState::new(app.http.clone());
        assert!(run_scheduled_scan_engine(
            &app,
            &findings,
            &cve,
            None,
            &NoEvents,
            &|_| {},
            ScheduledScanTarget {
                canonical_path: directory.path().join("missing").to_str().unwrap(),
                project_id: "p1",
                schedules: Some(&store)
            }
        )
        .await
        .is_err());
        assert_eq!(
            store.list()[0].last_started_at.as_deref(),
            Some("2026-10-01T00:00:00Z")
        );
    }

    #[tokio::test]
    async fn disabled_scan_categories_cannot_produce_a_clean_scheduled_run() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let app = AppState::new();
        {
            let mut settings = app.settings.lock().unwrap();
            settings.scan.scan_secrets = false;
            settings.scan.scan_vulnerabilities = false;
        }
        let findings =
            crate::initialize_findings_state(&directory.path().join("data"), chrono::Utc::now());
        let cve = CveState::new(app.http.clone());
        let completed = Mutex::new(Vec::new());
        let result = run_scheduled_scan_engine(
            &app,
            &findings,
            &cve,
            None,
            &NoEvents,
            &|result| completed.lock().unwrap().push(result.is_ok()),
            ScheduledScanTarget {
                canonical_path: project.to_str().unwrap(),
                project_id: "p1",
                schedules: None,
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*completed.lock().unwrap(), [false]);
    }
}

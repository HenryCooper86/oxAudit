//! Dependency and binary scanning commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

#[tauri::command]
pub async fn scan_dependencies(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    path: String,
    offline: bool,
    advisory_db_path: Option<String>,
    operation_id: Option<String>,
) -> Result<DependencyScanResult, String> {
    struct Events(AppHandle);
    impl crate::findings::service::ScanEventSink for Events {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let cache_path = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    scan_dependencies_engine(
        &state,
        &findings,
        &cache_path,
        &Events(app),
        path,
        offline,
        advisory_db_path,
        operation_id,
    )
    .await
}

/// The dependency check minus its Tauri wiring — the headless server runs
/// this same function over its own event sink and cache directory.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_dependencies_engine(
    state: &AppState,
    findings: &FindingsState,
    cache_path: &Path,
    events: &dyn crate::findings::service::ScanEventSink,
    path: String,
    offline: bool,
    advisory_db_path: Option<String>,
    operation_id: Option<String>,
) -> Result<DependencyScanResult, String> {
    let mut work = state.scan_work.begin(
        crate::scan_work::WorkKind::Dependencies,
        &path,
        operation_id.as_deref(),
        events,
    )?;
    let cancel = work.cancellation();
    let root = Path::new(&path)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    // Held across awaits on purpose: the connection sits in a Mutex, so the
    // reference is Send even though rusqlite's connection alone is not.
    let advisory_db = match &advisory_db_path {
        Some(path) => Some(
            crate::advisories::store::AdvisoryDb::open(std::path::Path::new(path))
                .map_err(|error| format!("cannot open {path}: {error}"))?,
        ),
        None => None,
    };
    let service = findings.service().map_err(|error| error.to_string())?;
    let settings = state.settings.lock().unwrap().clone();
    let providers = crate::deps::service::NetworkProviders {
        osv: &state.osv,
        http: &state.http,
    };
    let result = crate::deps::service::scan(crate::deps::service::ScanRequest {
        project_root: &root,
        root: &root,
        ignored_dirs: &settings.scan.ignored_dirs,
        offline,
        advisory_db: advisory_db.as_ref(),
        repository: service.repository(),
        providers: &providers,
        cancel: &cancel,
        events: &work,
        cache_path,
    })
    .await;
    if let Ok(result) = &result {
        work.finish("completed", result.summary.run_id.as_deref());
    }
    result
}

#[tauri::command]
pub fn cancel_dependency_scan(state: State<'_, AppState>) {
    let _ = state
        .scan_work
        .cancel(None, &[crate::scan_work::WorkKind::Dependencies]);
}

#[tauri::command]
pub fn find_lockfiles(
    state: State<'_, AppState>,
    path: String,
) -> Result<Vec<LockfileInfo>, String> {
    find_lockfiles_inner(&state, path)
}

pub(crate) fn find_lockfiles_inner(
    state: &AppState,
    path: String,
) -> Result<Vec<LockfileInfo>, String> {
    let root = Path::new(&path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }
    let settings = state.settings.lock().unwrap().clone();
    let files = fs_utils::discover_lockfiles_bounded(
        root,
        root,
        &settings.scan.ignored_dirs,
        crate::deps::lockfiles::MAX_LOCKFILES,
        None,
    )
    .map_err(|error| error.to_string())?;
    let mut out = Vec::new();
    for f in files {
        let name = f.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let kind = crate::deps::lockfiles::lockfile_kind(name);
        let (count, parse_error) = match crate::deps::lockfiles::parse_lockfile(&f, kind) {
            Ok(dependencies) => (Some(dependencies.len()), None),
            Err(error) if crate::deps::lockfiles::is_resource_limit_error(&error) => {
                return Err(format!("{}: {error}", f.display()));
            }
            Err(error) => (None, Some(error)),
        };
        out.push(LockfileInfo {
            path: f.to_string_lossy().replace('\\', "/"),
            kind: kind.into(),
            packages: count,
            parse_error,
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn binary_tool_status(
    state: State<'_, AppState>,
) -> Result<BinaryScannersStatus, String> {
    binary_tool_status_engine(&state).await
}

pub(crate) async fn binary_tool_status_engine(
    state: &AppState,
) -> Result<BinaryScannersStatus, String> {
    let settings = state.settings.lock().unwrap().clone();
    let trimmed = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let cve_path = trimmed(settings.binary_scanner_path.clone());
    let grype_path = trimmed(settings.grype_path.clone());
    let runtime =
        crate::binscan::runtime::Runtime::parse(settings.binary_scanner_runtime.as_deref());

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
    findings: State<'_, FindingsState>,
    cve: State<'_, CveState>,
    request: crate::binscan::run::BinaryScanRequest,
    use_grype: Option<bool>,
    operation_id: Option<String>,
) -> Result<crate::binscan::report::BinaryScanResult, String> {
    struct TauriEvents(AppHandle);
    impl crate::findings::service::ScanEventSink for TauriEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let progress_app = app.clone();
    let progress: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |payload| {
        let _ = progress_app.emit("binscan://progress", payload);
    });
    let scratch_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("no cache directory available: {e}"))?
        .join("binscan");
    let cache_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| scratch_dir.clone());
    let run_events = crate::presentation::TauriRunEvents::new(app.clone());
    scan_binaries_engine(
        &state,
        &findings,
        Some(&cve),
        &scratch_dir,
        &cache_dir,
        &run_events,
        &TauriEvents(app),
        progress,
        request,
        use_grype,
        operation_id,
    )
    .await
}

/// The binary/firmware scan minus its Tauri wiring: the headless server
/// drives this same function with its own run-event and progress sinks.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_binaries_engine(
    state: &AppState,
    findings: &FindingsState,
    cve: Option<&CveState>,
    scratch_dir: &Path,
    cache_dir: &Path,
    run_events: &dyn oxaudit_application::RunEventSink,
    events: &dyn crate::findings::service::ScanEventSink,
    progress: Arc<dyn Fn(Value) + Send + Sync>,
    request: crate::binscan::run::BinaryScanRequest,
    use_grype: Option<bool>,
    operation_id: Option<String>,
) -> Result<crate::binscan::report::BinaryScanResult, String> {
    let mut work = state.scan_work.begin(
        crate::scan_work::WorkKind::Binary,
        &request.path,
        operation_id.as_deref(),
        events,
    )?;
    let active_operation_id = work.id().to_owned();
    let progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |message| {
        progress(json!({"operationId": active_operation_id, "message": message}))
    });
    let target = Path::new(&request.path)
        .canonicalize()
        .map_err(|error| format!("cannot resolve the binary scan target: {error}"))?;
    let context = scan_context_dirs(state, scratch_dir, cache_dir, use_grype.unwrap_or(false))?;
    let service = findings.service().map_err(|error| error.to_string())?;
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(service.repository());
    let canonical_events = run_events;
    let coordinator =
        oxaudit_application::RunCoordinator::new(&canonical_repository, canonical_events);
    let mut managed = Some(
        coordinator
            .begin(oxaudit_domain::Run::queued(
                oxaudit_domain::RunKind::Binary,
                target.to_string_lossy(),
                epoch_millis(),
            ))
            .map_err(|error| error.to_string())?,
    );
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Discovering, epoch_millis())
        .map_err(|error| error.to_string())?;
    let cancel = work.cancellation();
    work.bind_run(
        managed
            .as_ref()
            .expect("managed binary run exists")
            .run()
            .id
            .as_str(),
    );
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
        .map_err(|error| error.to_string())?;

    let outcome = crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel.clone(),
        BINARY_SCAN_TIMEOUT,
        progress.clone(),
        cve,
    )
    .await;
    let mut outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(managed) = managed.take() {
                let terminal = if cancel.load(Ordering::Relaxed) || error.contains("cancelled") {
                    oxaudit_domain::RunState::Cancelled
                } else {
                    oxaudit_domain::RunState::Failed
                };
                let _ = managed.terminate(terminal, epoch_millis());
            }
            return Err(error);
        }
    };
    if cancel.load(Ordering::SeqCst) {
        managed
            .take()
            .expect("managed binary run exists")
            .terminate(oxaudit_domain::RunState::Cancelled, epoch_millis())
            .map_err(|error| error.to_string())?;
        return Err("binary scan cancelled".into());
    }
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Normalizing, epoch_millis())
        .map_err(|error| error.to_string())?;

    let run_id = managed
        .as_ref()
        .expect("managed binary run exists")
        .run()
        .id
        .clone();
    let advisory_sources = outcome
        .result
        .components
        .iter()
        .flat_map(|component| component.vulnerabilities.iter())
        .map(|vulnerability| vulnerability.source.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for source in advisory_sources {
        let snapshot_id = crate::adapters::scanners::binary_provider_snapshot_id(&run_id, &source)?;
        let record_count = outcome
            .result
            .components
            .iter()
            .flat_map(|component| component.vulnerabilities.iter())
            .filter(|vulnerability| vulnerability.source == source)
            .count();
        let payload = serde_json::json!({
            "schemaVersion": 1,
            "provider": source,
            "recordCount": record_count,
            "databaseLastUpdated": outcome.result.database_last_updated,
            "scanners": outcome.result.scanners,
            "kind": "bounded-query-receipt"
        });
        let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
        let content_sha256 = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(bytes))
        };
        service
            .repository()
            .provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
                id: snapshot_id.to_string(),
                provider_id: source,
                fetched_at_ms: epoch_millis(),
                content_sha256,
                payload,
            })
            .map_err(|error| error.to_string())?;
        managed
            .as_mut()
            .expect("managed binary run exists")
            .record_provider_snapshot(snapshot_id)
            .map_err(|error| error.to_string())?;
    }
    let (artifacts, components, mut observations) =
        crate::adapters::scanners::binary_graph(&run_id, &outcome.result)?;
    if request.deep_analysis {
        if target.is_file() {
            const SEMANTIC_MAX_BYTES: u64 = 16 * 1024 * 1024;
            let semantic_result = std::fs::metadata(&target)
                .map_err(|error| error.to_string())
                .and_then(|metadata| {
                    if metadata.len() > SEMANTIC_MAX_BYTES {
                        return Err("target exceeds the 16 MiB deep-analysis budget".into());
                    }
                    std::fs::read(&target).map_err(|error| error.to_string())
                })
                .and_then(|bytes| {
                    if bytes.len() as u64 > SEMANTIC_MAX_BYTES {
                        return Err("target exceeded the deep-analysis budget while reading".into());
                    }
                    use oxaudit_scanners::SemanticAnalyzer;
                    let artifact_id = artifacts
                        .first()
                        .ok_or_else(|| "binary artifact was not projected".to_string())?
                        .id
                        .to_string();
                    oxaudit_scanners::BoundedObjectAnalyzer.analyze(
                        oxaudit_scanners::SemanticInput {
                            artifact_id,
                            architecture: String::new(),
                            bytes,
                            limits: oxaudit_scanners::SemanticAnalysisLimits {
                                max_input_bytes: SEMANTIC_MAX_BYTES,
                                max_functions: 25_000,
                                max_basic_blocks: 100_000,
                                max_seconds: 20,
                            },
                        },
                    )
                });
            match semantic_result {
                Ok(report) => {
                    use oxaudit_scanners::SemanticAnalyzer;
                    let descriptor = oxaudit_scanners::BoundedObjectAnalyzer.descriptor();
                    let artifact_id = artifacts
                        .first()
                        .expect("binary graph always produces an artifact")
                        .id
                        .clone();
                    for finding in &report.findings {
                        let evidence = finding
                            .evidence
                            .iter()
                            .cloned()
                            .map(|evidence| oxaudit_domain::EvidenceRecord {
                                id: oxaudit_domain::EvidenceId::new(),
                                evidence,
                            })
                            .collect::<Vec<_>>();
                        observations.push(oxaudit_application::ObservationRecord {
                            observation: oxaudit_domain::Observation {
                                id: oxaudit_domain::ObservationId::new(),
                                run_id: run_id.clone(),
                                artifact_id: artifact_id.clone(),
                                kind: oxaudit_domain::ObservationKind::SemanticDataFlow,
                                detector_id: descriptor.id.clone(),
                                detector_version: descriptor.version.clone(),
                                rule_id: Some(finding.rule_id.clone()),
                                title: format!(
                                    "Call to security-sensitive sink at 0x{:x}",
                                    finding.function_address
                                ),
                                summary: finding.limitations.join(" "),
                                evidence_ids: evidence
                                    .iter()
                                    .map(|record| record.id.clone())
                                    .collect(),
                            },
                            evidence,
                        });
                    }
                    outcome.result.semantic_analysis = Some(report);
                }
                Err(error) => outcome
                    .notes
                    .push(format!("Deep binary analysis was not completed: {error}")),
            }
        } else {
            outcome.notes.push(
                "Deep binary analysis currently accepts one object file at a time; the directory scan still completed normally.".into(),
            );
        }
    }
    let component_observations = observations
        .iter()
        .filter(|record| {
            record.observation.kind == oxaudit_domain::ObservationKind::BinaryComponent
        })
        .count();
    let advisory_observations = observations
        .iter()
        .filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch)
        .count();
    let expected_advisories: usize = outcome
        .result
        .components
        .iter()
        .map(|component| component.vulnerabilities.len())
        .sum();
    if component_observations != outcome.result.components.len()
        || advisory_observations != expected_advisories
    {
        if let Some(managed) = managed.take() {
            let _ = managed.terminate(oxaudit_domain::RunState::Incomplete, epoch_millis());
        }
        return Err(
            "binary result manifest could not account for every component and advisory".into(),
        );
    }
    for artifact in &artifacts {
        managed
            .as_mut()
            .expect("managed binary run exists")
            .append_artifact(artifact)
            .map_err(|error| error.to_string())?;
    }
    managed
        .as_mut()
        .expect("managed binary run exists")
        .append_components(&components)
        .map_err(|error| error.to_string())?;
    managed
        .as_mut()
        .expect("managed binary run exists")
        .append_observations(observations)
        .map_err(|error| error.to_string())?;
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Enriching, epoch_millis())
        .map_err(|error| error.to_string())?;

    // A scanner that failed while another succeeded is reported, not hidden:
    // the two see different things, so a partial result is easy to misread as
    // a complete one.
    for failure in &outcome.failures {
        managed
            .as_mut()
            .expect("managed binary run exists")
            .warning(
                "scanner_failed",
                format!("{}: {}", failure.scanner, failure.message),
            );
        let _ = events.emit(
            "binscan://scanner-failed",
            json!({ "operationId": work.id(), "scanner": failure.scanner, "message": failure.message }),
        );
    }

    // Notes are not failures, but they change how the result should be read —
    // a capped or rate-limited lookup means "fewer CVEs than exist", which is
    // indistinguishable from "clean" unless we say so.
    for note in &outcome.notes {
        managed
            .as_mut()
            .expect("managed binary run exists")
            .warning("enrichment_note", note.clone());
        let _ = events.emit(
            "binscan://note",
            json!({"operationId": work.id(), "message": note}),
        );
    }
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Assessing, epoch_millis())
        .map_err(|error| error.to_string())?;
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Persisting, epoch_millis())
        .map_err(|error| error.to_string())?;
    service
        .repository()
        .canonical_save_projection(&run_id, "binary", 1, &outcome.result)
        .map_err(|error| error.to_string())?;
    if cancel.load(Ordering::SeqCst) {
        managed
            .take()
            .expect("managed binary run exists")
            .terminate(oxaudit_domain::RunState::Cancelled, epoch_millis())
            .map_err(|error| error.to_string())?;
        return Err("binary scan cancelled".into());
    }
    managed
        .as_mut()
        .expect("managed binary run exists")
        .complete_in_place(epoch_millis())
        .map_err(|error| error.to_string())?;

    work.finish("completed", Some(run_id.as_str()));
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
    operation_id: Option<String>,
) -> Result<(), String> {
    struct RefreshEvents(AppHandle);
    impl ScanEventSink for RefreshEvents {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    let progress_app = app.clone();
    let progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("binscan://progress", Value::from(line));
    });
    let scratch_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("no cache directory available: {e}"))?
        .join("binscan");
    let cache_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| scratch_dir.clone());
    refresh_binary_database_engine(
        &state,
        &scratch_dir,
        &cache_dir,
        progress,
        &RefreshEvents(app),
        operation_id,
    )
    .await
}

pub(crate) async fn refresh_binary_database_engine(
    state: &AppState,
    scratch_dir: &Path,
    cache_dir: &Path,
    progress: Arc<dyn Fn(String) + Send + Sync>,
    events: &dyn ScanEventSink,
    operation_id: Option<String>,
) -> Result<(), String> {
    let mut context = scan_context_dirs(state, scratch_dir, cache_dir, false)?;
    context.use_grype = false;
    // This refreshes cve-bin-tool's database. The native scanner has no
    // database, so running it here would only scan an empty probe directory.
    context.use_native = false;
    let mut work = state.scan_work.begin(
        crate::scan_work::WorkKind::Binary,
        "advisory database refresh",
        operation_id.as_deref(),
        events,
    )?;
    let cancel = work.cancellation();

    // cve-bin-tool always needs a target, so refresh against an empty directory:
    // the point is the `--update now` side effect, not the (empty) findings.
    let probe = context.scratch_dir.join("refresh-probe");
    std::fs::create_dir_all(&probe)
        .map_err(|e| format!("cannot prepare a refresh directory: {e}"))?;

    let request = crate::binscan::run::BinaryScanRequest {
        path: probe.to_string_lossy().into_owned(),
        severity: None,
        offline: false,
        update: Some("now".into()),
        deep_analysis: false,
    };

    let result = crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel,
        BINARY_SCAN_TIMEOUT,
        progress,
        None,
    )
    .await
    .map(|_| ());
    if result.is_ok() {
        work.finish("completed", None);
    }
    result
}

/// Ask an in-flight binary scan to stop; the child process is killed.
#[tauri::command]
pub fn cancel_binary_scan(state: State<'_, AppState>) -> Result<(), String> {
    state
        .scan_work
        .cancel(None, &[crate::scan_work::WorkKind::Binary])?;
    Ok(())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn malformed_inventory_has_unknown_count_while_valid_empty_inventory_has_zero() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("package-lock.json");
        std::fs::write(&path, "{broken json").unwrap();
        let state = AppState::new();
        let failed =
            find_lockfiles_inner(&state, directory.path().to_string_lossy().into_owned()).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].packages, None);
        assert!(failed[0]
            .parse_error
            .as_ref()
            .is_some_and(|error| !error.is_empty()));
        std::fs::write(
            path,
            r#"{"name":"fixture","lockfileVersion":3,"packages":{}}"#,
        )
        .unwrap();
        let empty =
            find_lockfiles_inner(&state, directory.path().to_string_lossy().into_owned()).unwrap();
        assert_eq!(empty[0].packages, Some(0));
        assert_eq!(empty[0].parse_error, None);
    }
}

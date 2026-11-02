//! Shared durable image workflow for desktop, server and CLI.
use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageScanRequest {
    pub target: String,
    pub advisory_db_path: Option<String>,
    pub offline: bool,
    #[serde(default)]
    pub operation_id: Option<String>,
    /// An advisory policy file to dismiss advisories by. Images have no
    /// project root, so nothing is read unless a file is named.
    #[serde(default)]
    pub advisory_policy_path: Option<String>,
    /// Report an invalid advisory policy as a note instead of failing.
    #[serde(default)]
    pub ignore_invalid_policy: bool,
}

/// Set the image vulnerabilities' reviews from the policy in force now, and
/// only from it (any earlier review is cleared). Images carry no ecosystem
/// per component, so entries match on the CVE id, the component name and
/// its version. Returns how many were dismissed and how many matched only
/// expired entries.
pub(crate) fn apply_advisory_policy(
    result: &mut crate::binscan::report::BinaryScanResult,
    policy: Option<&crate::findings::advisory_policy::AdvisoryPolicy>,
    now: chrono::DateTime<chrono::Utc>,
) -> (usize, usize) {
    use crate::findings::advisory_policy::{AdvisorySubject, Decision};
    let (mut dismissed, mut expired) = (0, 0);
    for component in &mut result.components {
        for vulnerability in &mut component.vulnerabilities {
            vulnerability.review = None;
            let Some(policy) = policy else { continue };
            let subject = AdvisorySubject {
                ids: vec![vulnerability.cve_id.as_str()],
                ecosystem: None,
                package: &component.product,
                version: &component.version,
            };
            match policy.decide(&subject, now) {
                Decision::Dismissed(review) => {
                    vulnerability.review = Some(review);
                    dismissed += 1;
                }
                Decision::Expired => expired += 1,
                Decision::None => {}
            }
        }
    }
    (dismissed, expired)
}

/// Load the policy an image scan names, before any work starts.
fn image_advisory_policy(
    request: &ImageScanRequest,
) -> Result<
    (
        Option<crate::findings::advisory_policy::AdvisoryPolicy>,
        Vec<String>,
    ),
    String,
> {
    use crate::findings::advisory_policy::{load_advisory_policy_file, AdvisoryPolicyStatus};
    let Some(path) = &request.advisory_policy_path else {
        return Ok((None, Vec::new()));
    };
    match load_advisory_policy_file(Path::new(path)) {
        AdvisoryPolicyStatus::Loaded(policy) => Ok((Some(policy), Vec::new())),
        AdvisoryPolicyStatus::Missing => Ok((None, Vec::new())),
        AdvisoryPolicyStatus::Invalid(reason) if request.ignore_invalid_policy => Ok((
            None,
            vec![format!(
                "invalid {path} was ignored ({reason}); no advisory is dismissed"
            )],
        )),
        AdvisoryPolicyStatus::Invalid(reason) => Err(format!(
            "invalid {path}: {reason}; fix or remove it (the CLI's --ignore-invalid-policy scans anyway)"
        )),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageScanOutcome {
    pub run_id: String,
    pub state: oxaudit_domain::RunState,
    pub result: crate::binscan::report::BinaryScanResult,
    pub notes: Vec<String>,
    pub image_digest: Option<String>,
    pub layers: Vec<crate::binscan::registry::LayerReceipt>,
    pub offline: bool,
    pub advisory_db_path: Option<String>,
    pub local_evidence: Option<Value>,
}

#[tauri::command]
pub async fn scan_image(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    request: ImageScanRequest,
) -> Result<ImageScanOutcome, String> {
    let progress_app = app.clone();
    let progress: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |payload| {
        let _ = progress_app.emit("image://progress", payload);
    });
    let cache_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    struct Events(AppHandle);
    impl ScanEventSink for Events {
        fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
            let _ = self.0.emit(event, payload);
            Ok(())
        }
    }
    scan_image_engine(
        &state,
        &findings,
        app.try_state::<CveState>().as_deref(),
        &cache_dir,
        progress,
        &Events(app.clone()),
        request,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_image_engine(
    state: &AppState,
    findings: &FindingsState,
    cve: Option<&CveState>,
    cache_dir: &Path,
    progress: Arc<dyn Fn(Value) + Send + Sync>,
    events: &dyn ScanEventSink,
    request: ImageScanRequest,
) -> Result<ImageScanOutcome, String> {
    let mut work = state.scan_work.begin(
        crate::scan_work::WorkKind::Image,
        &request.target,
        request.operation_id.as_deref(),
        events,
    )?;
    let cancel = work.cancellation();
    let operation_id = work.id().to_owned();
    let progress: Arc<dyn Fn(String) + Send + Sync> =
        Arc::new(move |message| progress(json!({"operationId": operation_id, "message": message})));
    let nvd_key = if request.offline {
        None
    } else {
        crate::credentials::resolve_nvd_key(state.credentials.as_ref())
            .map_err(|error| error.to_string())?
    };
    let result = scan_image_workflow(
        findings
            .service()
            .map_err(|error| error.to_string())?
            .repository(),
        &state.http,
        cve,
        nvd_key.as_ref().map(|key| key.as_str()),
        cache_dir,
        progress,
        &work,
        &cancel,
        request,
    )
    .await;
    if let Ok(outcome) = &result {
        work.finish("completed", Some(&outcome.run_id));
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_image_workflow(
    repository: &crate::findings::repository::FindingsRepository,
    http: &reqwest::Client,
    cve: Option<&CveState>,
    nvd_key: Option<&str>,
    cache_dir: &Path,
    progress: Arc<dyn Fn(String) + Send + Sync>,
    events: &dyn ScanEventSink,
    cancel: &Arc<AtomicBool>,
    request: ImageScanRequest,
) -> Result<ImageScanOutcome, String> {
    use oxaudit_domain::{Run, RunKind, RunState};
    // Read before any pull or scan, so a broken policy fails first.
    let (advisory_policy, policy_notes) = image_advisory_policy(&request)?;
    let adapter = crate::adapters::persistence::CanonicalSqliteRepository::new(repository);
    let run_events = crate::presentation::CanonicalRunEvents::new(events);
    let coordinator = oxaudit_application::RunCoordinator::new(&adapter, &run_events);
    let mut run = Run::queued(RunKind::Image, &request.target, epoch_millis());
    run.engine_ids
        .push(crate::binscan::native::scan::NATIVE.into());
    let mut managed = Some(coordinator.begin(run).map_err(|error| error.to_string())?);
    let run_id = managed.as_ref().expect("image run exists").run().id.clone();
    let started = std::time::Instant::now();
    let mut attempt = ImageScanOutcome {
        run_id: run_id.to_string(),
        state: RunState::Queued,
        result: crate::binscan::report::BinaryScanResult {
            target: request.target.clone(),
            components: Vec::new(),
            summary: Default::default(),
            database_last_updated: None,
            duration_ms: 0,
            scanners: vec![crate::binscan::native::scan::NATIVE.into()],
            semantic_analysis: None,
        },
        notes: Vec::new(),
        image_digest: None,
        layers: Vec::new(),
        offline: request.offline,
        advisory_db_path: request.advisory_db_path.clone(),
        local_evidence: None,
    };
    let result: Result<ImageScanOutcome, String> = async {
        if cancel.load(Ordering::SeqCst) { return Err("image scan cancelled".into()); }
        managed.as_mut().expect("image run exists").transition(RunState::Discovering, epoch_millis()).map_err(|error| error.to_string())?;
        let advisory_db = request.advisory_db_path.as_ref().map(|path| crate::advisories::store::AdvisoryDb::open(Path::new(path))).transpose()?;
        let mut image_digest = None;
        let mut layer_receipts = Vec::new();
        let mut local_notes = Vec::new();
        managed.as_mut().expect("image run exists").transition(RunState::Detecting, epoch_millis()).map_err(|error| error.to_string())?;
        let scanned = if let Some(reference) = crate::binscan::registry::parse_ref(&request.target) {
            let progress_pull = progress.clone();
            let image = crate::binscan::registry::fetch_image_layer_files(http, &reference, cancel, move |line| progress_pull(line)).await?;
            image_digest = Some(image.digest.clone());
            layer_receipts = image.receipts.clone();
            attempt.image_digest = image_digest.clone();
            attempt.layers = layer_receipts.clone();
            let cancel_scan = cancel.clone();
            let progress_scan = progress.clone();
            // The task owns the private spool until every layer is scanned.
            tokio::task::spawn_blocking(move || {
                let image = image;
                crate::binscan::native::scan::scan_image_layer_files(
                    &image.display, &image.layers, &cancel_scan, progress_scan)
            })
                .await.map_err(|error| format!("image scan task failed: {error}"))??
        } else {
            let target = Path::new(&request.target).canonicalize().map_err(|error| format!("cannot resolve image target: {error}"))?;
            let identity_target = target.clone();
            let identity_cancel = cancel.clone();
            let identity = tokio::task::spawn_blocking(move || crate::binscan::image_identity::inspect_local_identity(&identity_target, &identity_cancel))
                .await.map_err(|error| format!("image identity task failed: {error}"))??;
            local_notes = identity.notes.clone();
            attempt.notes.extend(local_notes.clone());
            attempt.local_evidence = Some(serde_json::to_value(identity).map_err(|error| error.to_string())?);
            let cancel_scan = cancel.clone();
            let progress_scan = progress.clone();
            tokio::task::spawn_blocking(move || crate::binscan::native::scan::scan(&target, cancel_scan, progress_scan))
                .await.map_err(|error| format!("image scan task failed: {error}"))??
        };
        if cancel.load(Ordering::SeqCst) { return Err("image scan cancelled".into()); }
        managed.as_mut().expect("image run exists").transition(RunState::Normalizing, epoch_millis()).map_err(|error| error.to_string())?;
        let mut result = scanned.result;
        let mut notes = scanned.notes;
        notes.extend(local_notes);
        attempt.result = result.clone();
        attempt.notes = notes.clone();
        managed.as_mut().expect("image run exists").transition(RunState::Enriching, epoch_millis()).map_err(|error| error.to_string())?;
        if let Some(db) = &advisory_db {
            let local = crate::binscan::native::enrich::enrich_local(db, &scanned.queries);
            crate::binscan::native::enrich::apply(&mut result, local.found);
            notes.extend(local.notes);
            attempt.result = result.clone();
            attempt.notes = notes.clone();
        }
        if !request.offline && !scanned.queries.is_empty() {
            if let Some(cve) = cve {
                let enriched = cancellable_image(cancel, crate::binscan::native::enrich::enrich(
                    cve, cache_dir, nvd_key, &scanned.queries, cancel.clone(), progress.clone())).await?;
                crate::binscan::native::enrich::apply(&mut result, enriched.found);
                notes.extend(enriched.notes);
            } else { notes.push("Online advisory lookup unavailable; components remain inventory evidence.".into()); }
        } else if request.offline && !scanned.queries.is_empty() {
            if advisory_db.is_none() { notes.push("Offline image scan without a local advisory database: components are listed without refreshed vulnerability evidence.".into()); }
            let cpe_askable = scanned.queries.iter().filter(|query| crate::binscan::native::enrich::cpe_match_string(&query.vendor, &query.product, &query.version).is_some()).count();
            if cpe_askable > 0 { notes.push(format!("{cpe_askable} CPE-keyed component(s) require online NVD evidence; offline absence does not establish a clean result.")); }
        }
        notes.extend(policy_notes);
        let (_, expired) = apply_advisory_policy(&mut result, advisory_policy.as_ref(), chrono::Utc::now());
        let shown_as = request.advisory_policy_path.as_deref().unwrap_or_default();
        notes.extend(crate::deps::service::advisory_policy_notes(shown_as, expired));
        attempt.result = result.clone();
        attempt.notes = notes.clone();
        if cancel.load(Ordering::SeqCst) { return Err("image scan cancelled".into()); }
        for note in &notes { managed.as_mut().expect("image run exists").warning("image_coverage", note.clone()); }
        let (artifacts, components, observations) = crate::adapters::scanners::binary_graph(&run_id, &result)?;
        for artifact in &artifacts { managed.as_mut().expect("image run exists").append_artifact(artifact).map_err(|error| error.to_string())?; }
        managed.as_mut().expect("image run exists").append_components(&components).map_err(|error| error.to_string())?;
        managed.as_mut().expect("image run exists").append_observations(observations).map_err(|error| error.to_string())?;
        // Returned evidence with query context, not a complete provider dump.
        let provider_payload = json!({"schemaVersion":1, "kind":"image-query-receipt",
            "offline": request.offline, "advisoryDb": request.advisory_db_path,
            "queryKeys": scanned.queries.iter().map(|query| json!({"vendor": query.vendor,
                "product": query.product, "version": query.version, "rawVersion": query.raw_version,
                "ecosystem": query.ecosystem, "osvName": query.osv_name})).collect::<Vec<_>>(), "components": result.components,
            "imageDigest": image_digest, "layers": layer_receipts, "localEvidence": attempt.local_evidence});
        use sha2::Digest;
        let bytes = serde_json::to_vec(&provider_payload).map_err(|error| error.to_string())?;
        let snapshot_id = oxaudit_domain::ProviderSnapshotId::new();
        repository.provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
            id: snapshot_id.to_string(), provider_id: "oxaudit.image.evidence".into(),
            fetched_at_ms: epoch_millis(), content_sha256: format!("{:x}", sha2::Sha256::digest(bytes)), payload: provider_payload,
        }).map_err(|error| error.to_string())?;
        managed.as_mut().expect("image run exists").record_provider_snapshot(snapshot_id).map_err(|error| error.to_string())?;
        managed.as_mut().expect("image run exists").transition(RunState::Assessing, epoch_millis()).map_err(|error| error.to_string())?;
        let outcome = ImageScanOutcome { run_id: run_id.to_string(), state: RunState::Completed, result, notes, image_digest,
            layers: layer_receipts, offline: request.offline, advisory_db_path: request.advisory_db_path,
            local_evidence: attempt.local_evidence.clone() };
        managed.as_mut().expect("image run exists").transition(RunState::Persisting, epoch_millis()).map_err(|error| error.to_string())?;
        if cancel.load(Ordering::SeqCst) { return Err("image scan cancelled".into()); }
        repository.canonical_save_projection(&run_id, "image", 1, &outcome).map_err(|error| error.to_string())?;
        managed.as_mut().expect("image run exists").complete_in_place(epoch_millis()).map_err(|error| error.to_string())?;
        managed.take();
        let _ = events.emit("image://done", json!({"runId": outcome.run_id, "components": outcome.result.summary.components}));
        Ok(outcome)
    }.await;
    if let Err(error) = &result {
        if let Some(mut run) = managed.take() {
            run.warning("image_failed", error.clone());
            let terminal = if cancel.load(Ordering::SeqCst) || error.contains("cancelled") {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            attempt.state = terminal;
            attempt.result.duration_ms = started.elapsed().as_millis() as u64;
            attempt.notes.push(format!(
                "Image scan {}: {error}. Inventory and advisory coverage are incomplete.",
                if terminal == RunState::Cancelled {
                    "cancelled"
                } else {
                    "failed"
                }
            ));
            if repository
                .canonical_load_projection(&run_id)
                .map_err(|persist| persist.to_string())?
                .is_none()
            {
                if let Err(persist) =
                    repository.canonical_save_projection(&run_id, "image", 1, &attempt)
                {
                    run.warning("image_projection_unavailable", persist.to_string());
                }
            }
            run.terminate(terminal, epoch_millis()).map_err(|persist| {
                format!("{error}; could not save terminal image state: {persist}")
            })?;
        }
    }
    result
}

pub(crate) async fn cancellable_image<F: std::future::Future>(
    cancel: &AtomicBool,
    future: F,
) -> Result<F::Output, String> {
    tokio::select! {
        biased;
        _ = async { while !cancel.load(Ordering::SeqCst) { tokio::time::sleep(std::time::Duration::from_millis(25)).await; } } => Err("scan cancelled".into()),
        output = future => if cancel.load(Ordering::SeqCst) { Err("scan cancelled".into()) } else { Ok(output) },
    }
}

#[tauri::command]
pub fn cancel_image_scan(state: State<'_, AppState>) -> Result<(), String> {
    state
        .scan_work
        .cancel(None, &[crate::scan_work::WorkKind::Image])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Quiet;
    impl ScanEventSink for Quiet {
        fn emit(&self, _: &str, _: Value) -> Result<(), CommandError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn image_receipt_survives_reopen_and_exports_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("busybox.bin");
        std::fs::write(&target, b"\0BusyBox v1.36.1 (fixture)\0").unwrap();
        let db = directory.path().join("private/evidence.sqlite");
        let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
        let outcome = scan_image_workflow(
            &repository,
            &reqwest::Client::new(),
            None,
            None,
            directory.path(),
            Arc::new(|_| {}),
            &Quiet,
            &Arc::new(AtomicBool::new(false)),
            ImageScanRequest {
                target: target.to_string_lossy().into_owned(),
                advisory_db_path: None,
                offline: true,
                advisory_policy_path: None,
                ignore_invalid_policy: false,
                operation_id: None,
            },
        )
        .await
        .unwrap();
        assert!(outcome
            .result
            .components
            .iter()
            .any(|component| component.product == "busybox"));
        let id = oxaudit_domain::RunId::parse(outcome.run_id).unwrap();
        drop(repository);
        std::fs::remove_file(target).unwrap();
        let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
        let run = repository.canonical_load_run(&id).unwrap().unwrap();
        assert_eq!(run.kind, oxaudit_domain::RunKind::Image);
        assert_eq!(run.state, oxaudit_domain::RunState::Completed);
        assert_eq!(run.provider_snapshot_ids.len(), 1);
        let projection = repository.canonical_load_projection(&id).unwrap().unwrap();
        assert_eq!(projection["state"], "completed");
        assert_eq!(projection["offline"], true);
        use sha2::Digest;
        assert_eq!(
            projection["localEvidence"]["file"]["sha256"],
            format!(
                "{:x}",
                sha2::Sha256::digest(b"\0BusyBox v1.36.1 (fixture)\0")
            )
        );
        assert_eq!(projection["localEvidence"]["complete"], true);
        let (artifacts, components, observations) =
            repository.canonical_load_report_graph(&id).unwrap();
        let report = crate::adapters::reporting::generate(
            &crate::adapters::reporting::ReportData {
                run,
                artifacts,
                components,
                observations,
                findings: Vec::new(),
                projection: Some(projection),
            },
            crate::adapters::reporting::ReportFormat::CycloneDx,
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&report.bytes).unwrap();
        assert!(report["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component["name"] == "busybox"));
    }

    #[tokio::test]
    async fn image_failed_and_cancelled_attempts_are_durable() {
        for cancelled in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let db = directory.path().join("private/attempt.sqlite");
            let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
            let cancel = Arc::new(AtomicBool::new(cancelled));
            let error = scan_image_workflow(
                &repository,
                &reqwest::Client::new(),
                None,
                None,
                directory.path(),
                Arc::new(|_| {}),
                &Quiet,
                &cancel,
                ImageScanRequest {
                    target: directory
                        .path()
                        .join("missing")
                        .to_string_lossy()
                        .into_owned(),
                    advisory_db_path: None,
                    offline: true,
                    advisory_policy_path: None,
                    ignore_invalid_policy: false,
                    operation_id: None,
                },
            )
            .await
            .unwrap_err();
            assert!(!error.is_empty());
            drop(repository);
            let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
            let runs = repository.canonical_list_runs(Some("image"), 10).unwrap();
            assert_eq!(runs.len(), 1);
            assert_eq!(
                runs[0].state,
                if cancelled {
                    oxaudit_domain::RunState::Cancelled
                } else {
                    oxaudit_domain::RunState::Failed
                }
            );
            let projection = repository
                .canonical_load_projection(&runs[0].id)
                .unwrap()
                .unwrap();
            assert_ne!(projection["state"], "completed");
            assert_eq!(projection["offline"], true);
            assert!(projection["notes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|note| note.as_str().unwrap().contains("incomplete")));
        }
    }

    #[tokio::test]
    async fn image_completion_write_failure_reloads_partial_receipt_as_failed() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("busybox.bin");
        std::fs::write(&target, b"\0BusyBox v1.36.1 (fixture)\0").unwrap();
        let db = directory.path().join("private/fault.sqlite");
        let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
        rusqlite::Connection::open(&db).unwrap().execute_batch("CREATE TRIGGER reject_image_completion BEFORE UPDATE OF state ON canonical_runs WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT,'completion rejected'); END;").unwrap();
        assert!(scan_image_workflow(
            &repository,
            &reqwest::Client::new(),
            None,
            None,
            directory.path(),
            Arc::new(|_| {}),
            &Quiet,
            &Arc::new(AtomicBool::new(false)),
            ImageScanRequest {
                target: target.to_string_lossy().into_owned(),
                advisory_db_path: None,
                offline: true,
                advisory_policy_path: None,
                ignore_invalid_policy: false,
                operation_id: None
            }
        )
        .await
        .is_err());
        drop(repository);
        let repository = crate::findings::repository::FindingsRepository::open(&db).unwrap();
        let runs = repository.canonical_list_runs(Some("image"), 10).unwrap();
        assert_eq!(runs[0].state, oxaudit_domain::RunState::Failed);
        let projection = repository
            .canonical_load_projection(&runs[0].id)
            .unwrap()
            .unwrap();
        assert_eq!(projection["state"], "failed");
        assert_eq!(projection["result"]["summary"]["components"], 1);
    }
}

#[cfg(test)]
mod advisory_policy_tests {
    use crate::binscan::report::{
        BinaryComponent, BinaryScanResult, BinaryScanSummary, BinaryVulnerability,
    };
    use crate::findings::advisory_policy::{load_advisory_policy_file, AdvisoryPolicyStatus};
    use crate::findings::domain::ReviewState;

    fn vulnerability(cve: &str) -> BinaryVulnerability {
        BinaryVulnerability {
            cve_id: cve.into(),
            severity: "critical".into(),
            score: Some(9.8),
            cvss_version: None,
            cvss_vector: None,
            source: "OSV".into(),
            remarks: None,
            epss_probability: None,
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
            public_exploit: false,
            fixed_in: None,
            review: None,
        }
    }

    fn component(product: &str, version: &str) -> BinaryComponent {
        BinaryComponent {
            vendor: String::new(),
            product: product.into(),
            version: version.into(),
            paths: vec![format!("image.tar!/{product}")],
            vulnerabilities: vec![vulnerability("CVE-2099-2222")],
            detected_by: vec!["oxaudit".into()],
        }
    }

    #[test]
    fn image_advisory_policy_dismisses_by_cve_and_component() {
        let mut result = BinaryScanResult {
            target: "image.tar".into(),
            components: vec![component("libc6", "2.36-9"), component("curl", "7.88.1")],
            summary: BinaryScanSummary::default(),
            database_last_updated: None,
            duration_ms: 0,
            scanners: Vec::new(),
            semantic_analysis: None,
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{"version": 1, "entries": [{"advisory": "CVE-2099-2222", "package": "libc6",
                "state": "acceptedRisk", "reason": "Not reachable in this image"}]}"#,
        )
        .unwrap();
        let AdvisoryPolicyStatus::Loaded(policy) = load_advisory_policy_file(&path) else {
            panic!("policy loads");
        };
        let counts = super::apply_advisory_policy(&mut result, Some(&policy), chrono::Utc::now());
        assert_eq!(counts, (1, 0));
        let review = result.components[0].vulnerabilities[0]
            .review
            .as_ref()
            .expect("libc6 dismissed");
        assert_eq!(review.state, ReviewState::AcceptedRisk);
        assert!(
            result.components[1].vulnerabilities[0].review.is_none(),
            "curl untouched"
        );
    }
}

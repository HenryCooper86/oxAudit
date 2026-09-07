//! Dependency and binary scanning commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;

const COMPLETE_OSV_RECEIPT_SCHEMA_VERSION: u64 = 2;
const COMPLETE_OSV_RECEIPT_COVERAGE: &str = "complete";

/// A cached provider response is usable offline only when it was written after
/// every candidate advisory had been resolved to a full OSV record. Earlier
/// batch-only snapshots remain historical data, but cannot prove a complete
/// advisory result for a new scan.
fn complete_osv_receipt_payload(
    query_keys: Vec<String>,
    results: &std::collections::HashMap<String, Vec<crate::models::Vulnerability>>,
) -> Result<serde_json::Value, String> {
    let record_count = results.values().map(Vec::len).sum::<usize>();
    let payload = serde_json::json!({
        "schemaVersion": COMPLETE_OSV_RECEIPT_SCHEMA_VERSION,
        "advisoryCoverage": COMPLETE_OSV_RECEIPT_COVERAGE,
        "queryKeys": query_keys,
        "results": results,
        "recordCount": record_count,
    });
    // Keep serialization fallible here so a cache write never invents a
    // receipt after a malformed result cannot be represented.
    serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    Ok(payload)
}

fn load_complete_osv_receipt(
    payload: &serde_json::Value,
    expected_query_keys: &[String],
) -> Result<std::collections::HashMap<String, Vec<crate::models::Vulnerability>>, String> {
    if payload
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(COMPLETE_OSV_RECEIPT_SCHEMA_VERSION)
        || payload
            .get("advisoryCoverage")
            .and_then(serde_json::Value::as_str)
            != Some(COMPLETE_OSV_RECEIPT_COVERAGE)
    {
        return Err("incomplete advisory coverage: the cached OSV snapshot is not a validated complete receipt; refresh online before scanning offline".into());
    }

    let cached_keys = payload
        .get("queryKeys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cached OSV receipt is invalid: queryKeys must be an array".to_string())?
        .iter()
        .map(|key| {
            key.as_str().ok_or_else(|| {
                "cached OSV receipt is invalid: queryKeys must contain strings".to_string()
            })
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if !expected_query_keys
        .iter()
        .all(|key| cached_keys.contains(key.as_str()))
    {
        return Err("incomplete advisory coverage: the latest OSV query snapshot does not cover every selected package".into());
    }

    let results_value = payload
        .get("results")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| "cached OSV receipt is invalid: results must be an object".to_string())?;
    let results = serde_json::from_value::<
        std::collections::HashMap<String, Vec<crate::models::Vulnerability>>,
    >(results_value)
    .map_err(|error| format!("cached OSV receipt is invalid: {error}"))?;
    let record_count = payload
        .get("recordCount")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            "cached OSV receipt is invalid: recordCount must be an integer".to_string()
        })?;
    if record_count != results.values().map(Vec::len).sum::<usize>() as u64 {
        return Err("cached OSV receipt is invalid: recordCount does not match results".into());
    }
    Ok(results)
}

#[tauri::command]
pub async fn scan_dependencies(
    app: AppHandle,
    state: State<'_, AppState>,
    findings: State<'_, FindingsState>,
    path: String,
    offline: bool,
) -> Result<DependencyScanResult, String> {
    let started = Instant::now();
    let root = Path::new(&path);
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }

    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    state.cancel_dependency_scan.store(false, Ordering::SeqCst);
    let service = findings.service().map_err(|error| error.to_string())?;
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(service.repository());
    let canonical_events = crate::presentation::TauriRunEvents::new(app.clone());
    let coordinator =
        oxaudit_application::RunCoordinator::new(&canonical_repository, &canonical_events);
    let mut managed = Some(
        coordinator
            .begin(oxaudit_domain::Run::queued(
                oxaudit_domain::RunKind::Dependencies,
                canonical_root.to_string_lossy(),
                epoch_millis(),
            ))
            .map_err(|error| error.to_string())?,
    );

    let scan_result: Result<DependencyScanResult, String> = async {
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Discovering, epoch_millis())
            .map_err(|error| error.to_string())?;
        let settings = state.settings.lock().unwrap().clone();
        let lockfiles = fs_utils::discover_lockfiles_bounded(
            root,
            root,
            &settings.scan.ignored_dirs,
            crate::deps::lockfiles::MAX_LOCKFILES,
            Some(&state.cancel_dependency_scan),
        )
        .map_err(|error| error.to_string())?;
        let run_id = managed
            .as_ref()
            .expect("managed dependency run exists")
            .run()
            .id
            .clone();
        let mut canonical_artifacts = std::collections::BTreeMap::new();
        for lockfile in &lockfiles {
            let artifact = crate::adapters::scanners::lockfile_artifact(&run_id, lockfile)?;
            managed
                .as_mut()
                .expect("managed dependency run exists")
                .append_artifact(&artifact)
                .map_err(|error| error.to_string())?;
            canonical_artifacts.insert(artifact.location.normalized_path.clone(), artifact);
        }
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
            .map_err(|error| error.to_string())?;

        let mut all_deps = Vec::new();
        let mut lockfile_infos = Vec::new();
        let mut parse_errors: Vec<String> = Vec::new();

        app.emit(
            "deps://progress",
            serde_json::json!({ "phase": "parsing", "done": 0, "total": lockfiles.len() }),
        )
        .ok();

        for (i, lf) in lockfiles.iter().enumerate() {
        if state.cancel_dependency_scan.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }
        let name = lf.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let kind = crate::deps::lockfiles::lockfile_kind(name);
        match crate::deps::lockfiles::parse_lockfile(lf, kind) {
            Ok(deps) => {
                lockfile_infos.push(LockfileInfo {
                    path: lf.to_string_lossy().replace('\\', "/"),
                    kind: kind.into(),
                    packages: deps.len(),
                });
                crate::deps::lockfiles::extend_dependencies_bounded(
                    &mut all_deps,
                    deps,
                    crate::deps::lockfiles::MAX_DEPENDENCIES,
                )?;
            }
            Err(error) if crate::deps::lockfiles::is_resource_limit_error(&error) => {
                return Err(format!("{}: {error}", lf.display()));
            }
            Err(e) => parse_errors.push(format!("{}: {e}", lf.display())),
        }
        let _ = app.emit(
            "deps://progress",
            serde_json::json!({ "phase": "parsing", "done": i + 1, "total": lockfiles.len(), "parseErrors": parse_errors.len() }),
        );
        }

        let packages_found = all_deps.len();
        if state.cancel_dependency_scan.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }
        crate::deps::ensure_complete_lockfile_coverage(&parse_errors)?;
        let deps = crate::deps::lockfiles::dedupe_dependencies(all_deps);
        let packages_queried = crate::deps::osv::queryable_dependencies(&deps).count();
        // Direct-usage reachability: one index over the project's own source,
        // asked about every vulnerable package later. Purely local, so it runs
        // regardless of the offline flag.
        let usage_index = crate::reachability::UsageIndex::for_project(root, &settings.scan.ignored_dirs);
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Normalizing, epoch_millis())
            .map_err(|error| error.to_string())?;
        let (components, declarations) = crate::adapters::scanners::dependency_graph(
            &run_id,
            &deps,
            &[],
            &canonical_artifacts,
            None,
        )?;
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .append_components(&components)
            .map_err(|error| error.to_string())?;
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .append_observations(declarations)
            .map_err(|error| error.to_string())?;
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Enriching, epoch_millis())
            .map_err(|error| error.to_string())?;

        app.emit(
        "deps://progress",
        serde_json::json!({ "phase": "querying-osv", "done": 0, "total": 1 }),
    )
        .ok();

        let query_keys = crate::deps::osv::query_keys(&deps);
        let (vuln_map, osv_snapshot_id) = if query_keys.is_empty() {
            // There is no provider claim to cache or satisfy: a complete empty
            // inventory must work offline without borrowing an unrelated
            // snapshot from another project.
            (std::collections::HashMap::new(), None)
        } else if offline {
            match service
                .repository()
                .provider_latest_snapshot("osv-query")
                .map_err(|error| error.to_string())?
            {
                Some(snapshot) => {
                    let results = load_complete_osv_receipt(&snapshot.payload, &query_keys)?;
                    (results, Some(snapshot.id))
                }
                None => return Err("incomplete advisory coverage: no cached OSV query snapshot is available".into()),
            }
        } else {
            let candidates = state
                .osv
                .query_batch(&deps)
                .await
                .map_err(|error| format!("incomplete advisory coverage: OSV query failed: {error}"))?;
            let results = state
                .osv
                .resolve_full(&candidates, &deps)
                .await
                .map_err(|error| format!("incomplete advisory coverage: {error}"))?;
            let payload = complete_osv_receipt_payload(query_keys, &results)?;
            let payload_bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
            let content_sha256 = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&payload_bytes))
            };
            let snapshot_id = format!("provider_{}", uuid::Uuid::new_v4());
            service
                .repository()
                .provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
                    id: snapshot_id.clone(),
                    provider_id: "osv-query".into(),
                    fetched_at_ms: epoch_millis(),
                    content_sha256,
                    payload,
                })
                .map_err(|error| error.to_string())?;
            (results, Some(snapshot_id))
        };
        let osv_snapshot_id = osv_snapshot_id
            .map(oxaudit_domain::ProviderSnapshotId::parse)
            .transpose()
            .map_err(|error| error.to_string())?;
        if let Some(snapshot_id) = &osv_snapshot_id {
            managed
                .as_mut()
                .expect("managed dependency run exists")
                .record_provider_snapshot(snapshot_id.clone())
                .map_err(|error| error.to_string())?;
        }
        if state.cancel_dependency_scan.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }

        let mut vulnerabilities = Vec::new();
        for dep in &deps {
        let key = crate::deps::osv::dependency_query_key(dep);
        if let Some(vulns) = vuln_map.get(&key) {
            for mut v in vulns.clone() {
                v.lockfile = dep.lockfile.clone();
                vulnerabilities.push(v);
            }
        }
        }
        // Direct usage is local evidence: attach it whether or not the
        // network sources answered.
        for vulnerability in &mut vulnerabilities {
            vulnerability.direct_usage =
                usage_index.lookup(&vulnerability.ecosystem, &vulnerability.package_name);
        }
    // Exploitation signal: rank these CVEs by CISA KEV and EPSS, the same way
    // the binary scanner does. A dependency vuln's CVE is in its id or aliases.
        let cve_ids: Vec<String> = vulnerabilities
        .iter()
        .filter_map(|v| {
            crate::exploit::cve_among(
                std::iter::once(v.id.as_str()).chain(v.aliases.iter().map(String::as_str)),
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
        if !cve_ids.is_empty() && !offline {
        let _ = app.emit(
            "deps://progress",
            serde_json::json!({ "phase": "exploitation-signal", "done": 0, "total": 1 }),
        );
        let (kev, epss, _notes) = crate::exploit::fetch(&state.http, &cve_ids).await;
        let (poc, _poc_notes) = {
            let cache_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir());
            crate::exploit::fetch_poc_set(&state.http, &cache_dir).await
        };
        for vulnerability in &mut vulnerabilities {
            // A finding's CVE is whichever of its id/aliases is a CVE.
            let cve = crate::exploit::cve_among(
                std::iter::once(vulnerability.id.as_str())
                    .chain(vulnerability.aliases.iter().map(String::as_str)),
            );
            if let Some(cve) = cve {
                let signal = crate::exploit::combine(&kev, &epss, &cve);
                vulnerability.known_exploited = signal.known_exploited;
                vulnerability.ransomware = signal.ransomware;
                vulnerability.epss = signal.epss;
                vulnerability.epss_percentile = signal.epss_percentile;
                vulnerability.public_exploit = poc.has(&cve);
            }
        }
        }

    // Exploited-first, then public exploit, then EPSS, then direct usage, then
    // CVSS — the actionable order.
        vulnerabilities.sort_by(|a, b| {
        b.known_exploited
            .cmp(&a.known_exploited)
            .then(b.public_exploit.cmp(&a.public_exploit))
            .then(
                b.epss
                    .unwrap_or(0.0)
                    .partial_cmp(&a.epss.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(
                b.direct_usage
                    .referenced
                    .unwrap_or(false)
                    .cmp(&a.direct_usage.referenced.unwrap_or(false)),
            )
            .then(
                b.cvss_score
                    .unwrap_or(0.0)
                    .partial_cmp(&a.cvss_score.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });

        let (_, advisory_records) = crate::adapters::scanners::dependency_graph(
            &run_id,
            &deps,
            &vulnerabilities,
            &canonical_artifacts,
            osv_snapshot_id.as_ref(),
        )?;
        let advisory_records = advisory_records
            .into_iter()
            .filter(|record| {
                record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch
            })
            .collect();
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .append_observations(advisory_records)
            .map_err(|error| error.to_string())?;
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Assessing, epoch_millis())
            .map_err(|error| error.to_string())?;

        let result = DependencyScanResult {
        summary: crate::models::DepScanSummary {
            path: path.clone(),
            lockfiles_found: lockfile_infos.iter().map(|l| l.path.clone()).collect(),
            packages_found,
            packages_queried,
            advisory_coverage: crate::models::AdvisoryCoverage::Complete,
            vulnerabilities_found: vulnerabilities.len(),
            duration_ms: started.elapsed().as_millis() as u64,
        },
        dependencies: deps,
        vulnerabilities,
        };
        managed
            .as_mut()
            .expect("managed dependency run exists")
            .transition(oxaudit_domain::RunState::Persisting, epoch_millis())
            .map_err(|error| error.to_string())?;
        service
            .repository()
            .canonical_save_projection(&run_id, "dependencies", 1, &result)
            .map_err(|error| error.to_string())?;
        app.emit(
        "deps://done",
        serde_json::json!({ "vulnerabilities": result.summary.vulnerabilities_found }),
    )
        .ok();
        Ok(result)
    }
    .await;

    match scan_result {
        Ok(result) => {
            managed
                .take()
                .expect("managed dependency run exists")
                .complete(epoch_millis())
                .map_err(|error| error.to_string())?;
            Ok(result)
        }
        Err(error) => {
            if let Some(managed) = managed.take() {
                let terminal = if error.contains("cancelled") {
                    oxaudit_domain::RunState::Cancelled
                } else {
                    oxaudit_domain::RunState::Failed
                };
                let _ = managed.terminate(terminal, epoch_millis());
            }
            Err(error)
        }
    }
}

#[tauri::command]
pub fn cancel_dependency_scan(state: State<'_, AppState>) {
    state.cancel_dependency_scan.store(true, Ordering::SeqCst);
}

#[tauri::command]
pub fn find_lockfiles(
    state: State<'_, AppState>,
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
        let count = match crate::deps::lockfiles::parse_lockfile(&f, kind) {
            Ok(dependencies) => dependencies.len(),
            Err(error) if crate::deps::lockfiles::is_resource_limit_error(&error) => {
                return Err(format!("{}: {error}", f.display()));
            }
            Err(_) => 0,
        };
        out.push(LockfileInfo {
            path: f.to_string_lossy().replace('\\', "/"),
            kind: kind.into(),
            packages: count,
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn binary_tool_status(
    state: State<'_, AppState>,
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
    request: crate::binscan::run::BinaryScanRequest,
    use_grype: Option<bool>,
) -> Result<crate::binscan::report::BinaryScanResult, String> {
    let target = Path::new(&request.path)
        .canonicalize()
        .map_err(|error| format!("cannot resolve the binary scan target: {error}"))?;
    let context = scan_context(&state, &app, use_grype.unwrap_or(false))?;
    let service = findings.service().map_err(|error| error.to_string())?;
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(service.repository());
    let canonical_events = crate::presentation::TauriRunEvents::new(app.clone());
    let coordinator =
        oxaudit_application::RunCoordinator::new(&canonical_repository, &canonical_events);
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
    let cancel = state.cancel_binary_scan.clone();
    cancel.store(false, Ordering::Relaxed);
    managed
        .as_mut()
        .expect("managed binary run exists")
        .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
        .map_err(|error| error.to_string())?;

    let progress_app = app.clone();
    let on_progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("binscan://progress", Value::from(line));
    });

    let outcome = crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel.clone(),
        BINARY_SCAN_TIMEOUT,
        on_progress,
        app.try_state::<CveState>().as_deref(),
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
        let _ = app.emit(
            "binscan://scanner-failed",
            json!({ "scanner": failure.scanner, "message": failure.message }),
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
        let _ = app.emit("binscan://note", Value::from(note.clone()));
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
    managed
        .take()
        .expect("managed binary run exists")
        .complete(epoch_millis())
        .map_err(|error| error.to_string())?;

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
) -> Result<(), String> {
    let mut context = scan_context(&state, &app, false)?;
    context.use_grype = false;
    // This refreshes cve-bin-tool's database. The native scanner has no
    // database, so running it here would only scan an empty probe directory.
    context.use_native = false;
    let cancel = state.cancel_binary_scan.clone();
    cancel.store(false, Ordering::Relaxed);

    // cve-bin-tool always needs a target, so refresh against an empty directory:
    // the point is the `--update now` side effect, not the (empty) findings.
    let probe = context.scratch_dir.join("refresh-probe");
    std::fs::create_dir_all(&probe)
        .map_err(|e| format!("cannot prepare a refresh directory: {e}"))?;

    let progress_app = app.clone();
    let on_progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        let _ = progress_app.emit("binscan://progress", Value::from(line));
    });

    let request = crate::binscan::run::BinaryScanRequest {
        path: probe.to_string_lossy().into_owned(),
        severity: None,
        offline: false,
        update: Some("now".into()),
        deep_analysis: false,
    };

    crate::binscan::scan::run_scan(
        &context,
        &request,
        cancel,
        BINARY_SCAN_TIMEOUT,
        on_progress,
        None,
    )
    .await
    .map(|_| ())
}

/// Ask an in-flight binary scan to stop; the child process is killed.
#[tauri::command]
pub fn cancel_binary_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_binary_scan.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{complete_osv_receipt_payload, load_complete_osv_receipt};

    fn full_vulnerability() -> crate::models::Vulnerability {
        crate::models::Vulnerability {
            id: "GHSA-full-detail".into(),
            aliases: vec!["CVE-2026-0001".into()],
            summary: "full advisory".into(),
            details: "resolved OSV detail".into(),
            severity: Some("high".into()),
            cvss_score: Some(8.1),
            epss: None,
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
            public_exploit: false,
            direct_usage: Default::default(),
            ecosystem: "npm".into(),
            package_name: "example".into(),
            installed_version: "1.0.0".into(),
            fixed_versions: vec!["1.0.1".into()],
            affected_range: Some("< 1.0.1".into()),
            references: vec![],
            published: None,
            modified: None,
            lockfile: "package-lock.json".into(),
        }
    }

    #[test]
    fn legacy_batch_snapshot_cannot_be_promoted_to_complete_offline_coverage() {
        let key = "npm\u{0}example\u{0}1.0.0".to_string();
        // Schema 1 wrote batch skeletons before detail resolution. Its empty
        // map can represent a previously truncated response, so it cannot
        // become a clean result merely because the query key is present.
        let legacy = serde_json::json!({
            "schemaVersion": 1,
            "queryKeys": [key],
            "results": {},
            "recordCount": 0,
        });

        let error = load_complete_osv_receipt(&legacy, &[key])
            .expect_err("legacy cache must require an online refresh");

        assert!(
            error.contains("not a validated complete receipt"),
            "{error}"
        );
    }

    #[test]
    fn incomplete_batch_only_receipt_cannot_succeed_on_an_offline_retry() {
        let key = "npm\u{0}example\u{0}1.0.0".to_string();
        // This is what existed after a batch found an advisory but the detail
        // request failed. New code never writes it; old cache must fail too.
        let batch_only = serde_json::json!({
            "schemaVersion": 1,
            "queryKeys": [key],
            "results": { key.clone(): [{ "id": "GHSA-skeleton" }] },
            "recordCount": 1,
        });

        assert!(load_complete_osv_receipt(&batch_only, &[key]).is_err());
    }

    #[test]
    fn complete_receipt_round_trip_preserves_full_advisory_details() {
        let key = "npm\u{0}example\u{0}1.0.0".to_string();
        let results = std::collections::HashMap::from([(key.clone(), vec![full_vulnerability()])]);
        let receipt = complete_osv_receipt_payload(vec![key.clone()], &results)
            .expect("resolved advisory data is cacheable");

        let restored = load_complete_osv_receipt(&receipt, std::slice::from_ref(&key))
            .expect("validated full receipt is reusable offline");
        let vulnerability = &restored[&key][0];
        assert_eq!(vulnerability.severity.as_deref(), Some("high"));
        assert_eq!(vulnerability.fixed_versions, vec!["1.0.1"]);
        assert_eq!(vulnerability.aliases, vec!["CVE-2026-0001"]);
    }

    #[test]
    fn complete_receipt_requires_an_explicit_results_object() {
        let key = "npm\u{0}example\u{0}1.0.0".to_string();
        let missing_results = serde_json::json!({
            "schemaVersion": 2,
            "advisoryCoverage": "complete",
            "queryKeys": [key],
            "recordCount": 0,
        });

        let error = load_complete_osv_receipt(&missing_results, &[key])
            .expect_err("missing results must not look clean");
        assert!(error.contains("results must be an object"), "{error}");
    }
}

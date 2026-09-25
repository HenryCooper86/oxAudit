//! Shared dependency workflow. Adapters supply transport, storage and cancellation;
//! all inventory, receipt and canonical-run decisions live here.
use crate::findings::{repository::FindingsRepository, service::ScanEventSink};
use crate::fs_utils;
use crate::models::{
    Dependency, DependencyScanResult, EnrichmentStatus, LockfileInfo, Vulnerability,
};
use oxaudit_application::PortFuture;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub type AdvisoryResults = std::collections::HashMap<String, Vec<Vulnerability>>;

/// Full-detail lookup is mandatory; enrichment is optional and reports its uncertainty.
pub trait DependencyProviders: Send + Sync {
    fn query_full<'a>(
        &'a self,
        dependencies: &'a [Dependency],
    ) -> PortFuture<'a, Result<AdvisoryResults, String>>;
    fn enrich<'a>(
        &'a self,
        vulnerabilities: &'a mut [Vulnerability],
        cves: &'a [String],
        cache_path: &'a Path,
    ) -> PortFuture<'a, EnrichmentStatus>;
    /// Fill declared licenses from package registries, online-only. The
    /// default does nothing — a provider without network access cannot
    /// invent licenses, and none are guessed.
    fn licenses<'a>(
        &'a self,
        _dependencies: &'a mut [Dependency],
    ) -> PortFuture<'a, crate::licenses::LicenseFetchSummary> {
        Box::pin(async { crate::licenses::LicenseFetchSummary::default() })
    }
}

pub struct NetworkProviders<'a> {
    pub osv: &'a crate::deps::osv::OsvClient,
    pub http: &'a reqwest::Client,
}
impl DependencyProviders for NetworkProviders<'_> {
    fn query_full<'a>(
        &'a self,
        dependencies: &'a [Dependency],
    ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
        Box::pin(self.osv.query_batch_full(dependencies))
    }
    fn licenses<'a>(
        &'a self,
        dependencies: &'a mut [Dependency],
    ) -> PortFuture<'a, crate::licenses::LicenseFetchSummary> {
        Box::pin(crate::licenses::fetch_missing(dependencies, self.http))
    }
    fn enrich<'a>(
        &'a self,
        vulnerabilities: &'a mut [Vulnerability],
        cves: &'a [String],
        cache_path: &'a Path,
    ) -> PortFuture<'a, EnrichmentStatus> {
        Box::pin(async move {
            let (kev, epss, mut warnings) = crate::exploit::fetch(self.http, cves).await;
            let (poc, notes) = crate::exploit::fetch_poc_set(self.http, cache_path).await;
            warnings.extend(notes);
            for vulnerability in vulnerabilities {
                if let Some(cve) = crate::exploit::cve_among(
                    std::iter::once(vulnerability.id.as_str())
                        .chain(vulnerability.aliases.iter().map(String::as_str)),
                ) {
                    let signal = crate::exploit::combine(&kev, &epss, &cve);
                    vulnerability.known_exploited = signal.known_exploited;
                    vulnerability.ransomware = signal.ransomware;
                    vulnerability.epss = signal.epss;
                    vulnerability.epss_percentile = signal.epss_percentile;
                    vulnerability.public_exploit = poc.has(&cve);
                }
            }
            let poc_cache_updated_at_ms =
                std::fs::metadata(crate::exploit::poc_cache_path(cache_path))
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64);
            EnrichmentStatus {
                status: if warnings.is_empty() {
                    "available"
                } else {
                    "partial"
                }
                .into(),
                checked_at_ms: Some(epoch_millis()),
                poc_cache_updated_at_ms,
                warnings,
            }
        })
    }
}

pub struct ScanRequest<'a> {
    pub root: &'a Path,
    pub ignored_dirs: &'a [String],
    pub offline: bool,
    /// Answer advisories from this local database instead of the network,
    /// whether or not `offline` is set. Coverage discipline is the same: an
    /// ecosystem whose dump the database does not carry fails the scan.
    pub advisory_db: Option<&'a crate::advisories::store::AdvisoryDb>,
    pub repository: &'a FindingsRepository,
    pub providers: &'a dyn DependencyProviders,
    pub cancel: &'a AtomicBool,
    pub events: &'a dyn ScanEventSink,
    pub cache_path: &'a Path,
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn validate_snapshot_hash(
    snapshot: &crate::findings::repository::ProviderSnapshotRecord,
) -> Result<(), String> {
    use sha2::Digest;
    let bytes = serde_json::to_vec(&snapshot.payload).map_err(|e| e.to_string())?;
    if format!("{:x}", sha2::Sha256::digest(bytes)) != snapshot.content_sha256 {
        return Err("cached OSV receipt integrity check failed".into());
    }
    Ok(())
}

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
    for (key, vulnerabilities) in &results {
        if !cached_keys.contains(key.as_str()) {
            return Err("cached OSV receipt is invalid: result is outside query membership".into());
        }
        for vulnerability in vulnerabilities {
            let identity = format!(
                "{}\0{}\0{}",
                vulnerability.ecosystem,
                vulnerability.package_name,
                vulnerability.installed_version
            );
            if &identity != key || vulnerability.id.trim().is_empty() {
                return Err(
                    "cached OSV receipt is invalid: advisory package identity mismatch".into(),
                );
            }
        }
    }
    let selected = expected_query_keys
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    Ok(results
        .into_iter()
        .filter(|(key, _)| selected.contains(key))
        .collect())
}

pub async fn scan(request: ScanRequest<'_>) -> Result<DependencyScanResult, String> {
    let started = Instant::now();
    let path = request.root.to_string_lossy().into_owned();
    let root = request.root;
    if !root.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }

    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(request.repository);
    let canonical_events = crate::presentation::CanonicalRunEvents::new(request.events);
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
        let lockfiles = fs_utils::discover_lockfiles_bounded(
            root,
            root,
            request.ignored_dirs,
            crate::deps::lockfiles::MAX_LOCKFILES,
            Some(request.cancel),
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

        request.events.emit(
            "deps://progress",
            serde_json::json!({ "phase": "parsing", "done": 0, "total": lockfiles.len() }),
        )
        .ok();

        for (i, lf) in lockfiles.iter().enumerate() {
        if request.cancel.load(Ordering::SeqCst) {
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
        let _ = request.events.emit(
            "deps://progress",
            serde_json::json!({ "phase": "parsing", "done": i + 1, "total": lockfiles.len(), "parseErrors": parse_errors.len() }),
        );
        }

        let packages_found = all_deps.len();
        if request.cancel.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }
        crate::deps::ensure_complete_lockfile_coverage(&parse_errors)?;
        let mut deps = all_deps;
        let query_deps = crate::deps::lockfiles::dedupe_dependencies(deps.clone());
        let packages_queried = crate::deps::osv::queryable_dependencies(&query_deps).count();
        // License enrichment: online-only, best-effort, bounded. A
        // lockfile-declared license (npm) is already present and is never
        // overwritten. Notes join the enrichment warnings — they are
        // optional-source honesty, not advisory coverage.
        let mut license_notes = Vec::new();
        if !request.offline {
            let license_summary = request.providers.licenses(&mut deps).await;
            license_notes = license_summary.notes;
        }

        // Direct-usage reachability: one index over the project's own source,
        // asked about every vulnerable package later. Purely local, so it runs
        // regardless of the offline flag.
        let usage_index = crate::reachability::UsageIndex::for_project(root, request.ignored_dirs);
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

        let query_keys = crate::deps::osv::query_keys(&query_deps);
        let mut advisory_fetched_at_ms = None;
        let mut advisory_notes = Vec::new();
        let mut advisory_source = "online";
        let (vuln_map, osv_snapshot_id) = if query_keys.is_empty() {
            // There is no provider claim to cache or satisfy: a complete empty
            // inventory must work offline without borrowing an unrelated
            // snapshot from another project.
            advisory_source = "notApplicable";
            (std::collections::HashMap::new(), None)
        } else if let Some(db) = request.advisory_db {
            let _ = request.events.emit("deps://progress", serde_json::json!({ "phase": "matching-local", "done": 0, "total": 1 }));
            // The database's build time is the honest as-of stamp: the answer
            // is exactly as fresh as the dump it was built from.
            advisory_fetched_at_ms = db.built_at_ms();
            advisory_source = "local-db";
            let outcome = crate::advisories::matching::query_local(db, &query_deps)
                .map_err(|error| format!("incomplete advisory coverage: {error}"))?;
            advisory_notes = outcome.notes.warnings();
            // Advisory evidence binds to an immutable snapshot of what the
            // source answered; a database answer gets the same treatment as a
            // network answer, under its own provider identity.
            let mut payload = complete_osv_receipt_payload(query_keys.clone(), &outcome.results)?;
            payload["advisorySource"] = serde_json::json!("local-db");
            payload["sourceUrl"] = serde_json::json!(db.source_url()?);
            payload["builtAtMs"] = serde_json::json!(advisory_fetched_at_ms);
            let validated = load_complete_osv_receipt(&payload, &query_keys)?;
            let payload_bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
            let content_sha256 = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&payload_bytes))
            };
            let fetched_at = advisory_fetched_at_ms.unwrap_or_else(epoch_millis);
            let snapshot_id = format!("provider_{}", uuid::Uuid::new_v4());
            request
                .repository
                .provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
                    id: snapshot_id.clone(),
                    provider_id: "local-advisory-db".into(),
                    fetched_at_ms: fetched_at,
                    content_sha256,
                    payload,
                })
                .map_err(|error| error.to_string())?;
            (validated, Some(snapshot_id))
        } else if request.offline {
            advisory_source = "cache";
            let _ = request.events.emit("deps://progress", serde_json::json!({ "phase": "loading-cache", "done": 0, "total": 1 }));
            match request.repository
                .provider_latest_snapshot("osv-query")
                .map_err(|error| error.to_string())?
            {
                Some(snapshot) => {
                    validate_snapshot_hash(&snapshot)?;
                    advisory_fetched_at_ms = Some(snapshot.fetched_at_ms);
                    let results = load_complete_osv_receipt(&snapshot.payload, &query_keys)?;
                    (results, Some(snapshot.id))
                }
                None => return Err("incomplete advisory coverage: no cached OSV query snapshot is available".into()),
            }
        } else {
            let _ = request.events.emit("deps://progress", serde_json::json!({ "phase": "querying-osv", "done": 0, "total": 1 }));
            let results = request.providers.query_full(&query_deps).await
                .map_err(|error| format!("incomplete advisory coverage: {error}"))?;
            if request.cancel.load(Ordering::SeqCst) {
                return Err("dependency scan cancelled".into());
            }
            let payload = complete_osv_receipt_payload(query_keys.clone(), &results)?;
            let results = load_complete_osv_receipt(&payload, &query_keys)?;
            advisory_fetched_at_ms = Some(epoch_millis());
            let payload_bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
            let content_sha256 = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&payload_bytes))
            };
            let snapshot_id = format!("provider_{}", uuid::Uuid::new_v4());
            request.repository
                .provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
                    id: snapshot_id.clone(),
                    provider_id: "osv-query".into(),
                    fetched_at_ms: advisory_fetched_at_ms.unwrap(),
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
        if request.cancel.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }

        let mut vulnerabilities = Vec::new();
        for dep in &deps {
        let key = crate::deps::osv::dependency_query_key(dep);
        if let Some(vulns) = vuln_map.get(&key) {
            for mut v in vulns.clone() {
                v.lockfile = dep.lockfile.clone();
                v.occurrence = dep.occurrence.clone();
                vulnerabilities.push(v);
            }
        }
        }
        // Direct usage is local evidence: attach it whether or not the
        // network sources answered. Advisories that name affected functions
        // (RustSec) additionally learn which of them this project
        // references — literal path match, docs/reachability-scoping.md.
        for vulnerability in &mut vulnerabilities {
            vulnerability.direct_usage =
                usage_index.lookup(&vulnerability.ecosystem, &vulnerability.package_name);
            if !vulnerability.affected_functions.is_empty() {
                vulnerability.referenced_functions = usage_index
                    .referenced_functions(&vulnerability.affected_functions);
            }
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
        let mut enrichment = if cve_ids.is_empty() {
            EnrichmentStatus { status: "notApplicable".into(), ..Default::default() }
        } else if request.offline {
            EnrichmentStatus { status: "unavailable".into(), warnings: vec!["Optional exploitation sources were not refreshed in offline mode; absent signals are unknown.".into()], ..Default::default() }
        } else {
            let _ = request.events.emit("deps://progress", serde_json::json!({"phase":"exploitation-signal","done":0,"total":1}));
            request.providers.enrich(&mut vulnerabilities, &cve_ids, request.cache_path).await
        };
        if request.cancel.load(Ordering::SeqCst) {
            return Err("dependency scan cancelled".into());
        }
        enrichment.warnings.extend(license_notes);

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
            .then(b.referenced_functions.len().cmp(&a.referenced_functions.len()))
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
            run_id: Some(run_id.to_string()),
            advisory_fetched_at_ms,
            advisory_source: advisory_source.into(),
            enrichment,
            lockfiles_found: lockfile_infos.iter().map(|l| l.path.clone()).collect(),
            packages_found,
            packages_queried,
            advisory_coverage: crate::models::AdvisoryCoverage::Complete,
            advisory_notes,
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
        request.repository
            .canonical_save_projection(&run_id, "dependencies", 1, &result)
            .map_err(|error| error.to_string())?;
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
            let _ = request.events.emit(
                "deps://done",
                serde_json::json!({ "vulnerabilities": result.summary.vulnerabilities_found }),
            );
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

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

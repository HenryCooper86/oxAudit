use super::*;

fn full_vulnerability() -> crate::models::Vulnerability {
    crate::models::Vulnerability {
        occurrence: Default::default(),
        affected_evidence: None,
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

struct Events(std::sync::Mutex<Vec<String>>);
impl ScanEventSink for Events {
    fn emit(
        &self,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<(), crate::findings::error::CommandError> {
        let mut events = self.0.lock().unwrap();
        events.push(event.into());
        if let Some(phase) = payload.get("phase").and_then(serde_json::Value::as_str) {
            events.push(format!("{event}:{phase}"));
        }
        Ok(())
    }
}
struct Provider<'a> {
    calls: std::sync::atomic::AtomicUsize,
    failure: bool,
    expected_queries: usize,
    cancel_after_query: Option<&'a AtomicBool>,
}
impl DependencyProviders for Provider<'_> {
    fn query_full<'a>(
        &'a self,
        dependencies: &'a [Dependency],
    ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.failure {
                return Err("deterministic advisory detail unavailable".into());
            }
            assert_eq!(
                dependencies.len(),
                self.expected_queries,
                "only distinct provider queries"
            );
            let dependency = &dependencies[0];
            let mut vulnerability = full_vulnerability();
            vulnerability.ecosystem = dependency.ecosystem.clone();
            vulnerability.package_name = dependency.name.clone();
            vulnerability.installed_version = dependency.version.clone();
            if let Some(cancel) = self.cancel_after_query {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(AdvisoryResults::from([(
                crate::deps::osv::dependency_query_key(dependency),
                vec![vulnerability],
            )]))
        })
    }
    fn enrich<'a>(
        &'a self,
        _: &'a mut [Vulnerability],
        _: &'a [String],
        _: &'a Path,
    ) -> PortFuture<'a, EnrichmentStatus> {
        Box::pin(async {
            EnrichmentStatus {
                status: "partial".into(),
                checked_at_ms: Some(42),
                warnings: vec!["deterministic optional feed unavailable".into()],
                ..Default::default()
            }
        })
    }
}
fn provider() -> Provider<'static> {
    Provider {
        calls: Default::default(),
        failure: false,
        expected_queries: 1,
        cancel_after_query: None,
    }
}
fn events() -> Events {
    Events(Default::default())
}
fn project(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
}
async fn execute(
    root: &Path,
    repo: &FindingsRepository,
    provider: &dyn DependencyProviders,
    offline: bool,
    cancel: &AtomicBool,
    events: &Events,
) -> Result<DependencyScanResult, String> {
    scan(ScanRequest {
        root,
        repository: repo,
        providers: provider,
        offline,
        advisory_db: None,
        cancel,
        events,
        cache_path: root,
        ignored_dirs: &[],
    })
    .await
}
#[tokio::test]
async fn durable_online_offline_retains_occurrences_details_and_canonical_provenance() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("project");
    project(&root);
    project(&root.join("workspace"));
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let provider = provider();
    let cancel = AtomicBool::new(false);
    let events = events();
    let online = execute(&root, &repository, &provider, false, &cancel, &events)
        .await
        .unwrap();
    assert_eq!(online.summary.packages_found, 2);
    assert_eq!(online.summary.packages_queried, 1);
    assert_eq!(online.dependencies.len(), 2);
    assert_eq!(online.vulnerabilities.len(), 2);
    assert_ne!(
        online.vulnerabilities[0].lockfile,
        online.vulnerabilities[1].lockfile
    );
    assert_eq!(
        online.summary.enrichment.warnings,
        ["deterministic optional feed unavailable"]
    );
    let run_id = oxaudit_domain::RunId::parse(online.summary.run_id.clone().unwrap()).unwrap();
    let run = repository.canonical_load_run(&run_id).unwrap().unwrap();
    assert_eq!(run.state, oxaudit_domain::RunState::Completed);
    let (artifacts, components, observations) =
        repository.canonical_load_report_graph(&run_id).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(components.len(), 1);
    assert_eq!(components[0].identities.len(), 2);
    assert_eq!(observations.len(), 4);
    events.0.lock().unwrap().clear();
    let offline = execute(&root, &repository, &provider, true, &cancel, &events)
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(offline.vulnerabilities.len(), 2);
    assert_eq!(offline.vulnerabilities[0].details, "resolved OSV detail");
    assert_eq!(offline.vulnerabilities[0].fixed_versions, ["1.0.1"]);
    assert_eq!(
        online.summary.advisory_fetched_at_ms,
        offline.summary.advisory_fetched_at_ms
    );
    assert_eq!(offline.summary.enrichment.status, "unavailable");
    let phases = events.0.lock().unwrap();
    assert!(phases
        .iter()
        .any(|event| event == "deps://progress:loading-cache"));
    assert!(!phases
        .iter()
        .any(|event| event == "deps://progress:querying-osv"));
    assert_eq!(
        repository
            .canonical_list_runs(Some("dependencies"), 10)
            .unwrap()
            .len(),
        2
    );
}
#[tokio::test]
async fn empty_inventory_never_calls_any_provider_online_or_offline() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("package-lock.json"),
        r#"{"packages":{}}"#,
    )
    .unwrap();
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let provider = provider();
    let observed = events();
    for offline in [false, true] {
        let result = execute(
            directory.path(),
            &repository,
            &provider,
            offline,
            &AtomicBool::new(false),
            &observed,
        )
        .await
        .unwrap();
        assert_eq!(result.summary.packages_queried, 0);
        assert_eq!(result.summary.enrichment.status, "notApplicable");
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert!(!observed
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|event| event == "deps://progress:querying-osv"));
    assert!(repository
        .provider_latest_snapshot("osv-query")
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn parse_failure_is_a_failed_durable_run_before_provider_lookup() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    std::fs::write(directory.path().join("Cargo.lock"), "invalid [").unwrap();
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let provider = provider();
    let events = events();
    let error = execute(
        directory.path(),
        &repository,
        &provider,
        false,
        &AtomicBool::new(false),
        &events,
    )
    .await
    .unwrap_err();
    assert!(error.contains("incomplete dependency coverage"));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        repository.canonical_list_runs(None, 1).unwrap()[0].state,
        oxaudit_domain::RunState::Failed
    );
    assert!(!events.0.lock().unwrap().iter().any(|e| e == "deps://done"));
}
#[tokio::test]
async fn missing_receipt_and_advisory_failure_cannot_complete_or_write_receipts() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let provider = Provider {
        failure: true,
        ..provider()
    };
    for offline in [true, false] {
        let error = execute(
            directory.path(),
            &repository,
            &provider,
            offline,
            &AtomicBool::new(false),
            &events(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("incomplete advisory coverage"), "{error}");
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert!(repository
        .provider_latest_snapshot("osv-query")
        .unwrap()
        .is_none());
    assert!(repository
        .canonical_list_runs(None, 10)
        .unwrap()
        .iter()
        .all(|r| r.state == oxaudit_domain::RunState::Failed));
}
#[tokio::test]
async fn malformed_osv_batch_cannot_complete_or_persist_a_receipt() {
    struct BatchProvider(serde_json::Value);
    impl DependencyProviders for BatchProvider {
        fn query_full<'a>(
            &'a self,
            dependencies: &'a [Dependency],
        ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
            Box::pin(async move {
                crate::deps::osv::decode_batch_results(&self.0, dependencies.len())?;
                Ok(AdvisoryResults::new())
            })
        }
        fn enrich<'a>(
            &'a self,
            _: &'a mut [Vulnerability],
            _: &'a [String],
            _: &'a Path,
        ) -> PortFuture<'a, EnrichmentStatus> {
            Box::pin(async { EnrichmentStatus::default() })
        }
    }
    for response in [
        serde_json::json!({"results":[null]}),
        serde_json::json!({"results":[{"vulns":{}}]}),
    ] {
        let directory = tempfile::tempdir().unwrap();
        project(directory.path());
        let repository =
            FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
        let events = events();
        let error = execute(
            directory.path(),
            &repository,
            &BatchProvider(response),
            false,
            &AtomicBool::new(false),
            &events,
        )
        .await
        .unwrap_err();
        assert!(error.contains("incomplete advisory coverage"), "{error}");
        assert!(repository
            .provider_latest_snapshot("osv-query")
            .unwrap()
            .is_none());
        assert_eq!(
            repository.canonical_list_runs(None, 10).unwrap()[0].state,
            oxaudit_domain::RunState::Failed
        );
        assert!(!events
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "deps://done"));
    }
}

#[tokio::test]
async fn cancellation_before_discovery_and_after_provider_never_completes() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    for initial in [true, false] {
        let cancel = AtomicBool::new(initial);
        let provider = Provider {
            cancel_after_query: Some(&cancel),
            ..provider()
        };
        let events = events();
        assert!(execute(
            directory.path(),
            &repository,
            &provider,
            false,
            &cancel,
            &events
        )
        .await
        .unwrap_err()
        .contains("cancelled"));
        assert!(!events.0.lock().unwrap().iter().any(|e| e == "deps://done"));
    }
    assert!(repository
        .canonical_list_runs(None, 10)
        .unwrap()
        .iter()
        .all(|r| r.state == oxaudit_domain::RunState::Cancelled));
    assert!(
        repository
            .provider_latest_snapshot("osv-query")
            .unwrap()
            .is_none(),
        "cancelled provider work must stop before writing a receipt"
    );
}
#[tokio::test]
async fn projection_persistence_failure_is_not_reported_as_saved_or_done() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let db = directory.path().join("data/runs.sqlite");
    let repository = FindingsRepository::open(&db).unwrap();
    rusqlite::Connection::open(db).unwrap().execute_batch("CREATE TRIGGER fail_projection BEFORE INSERT ON canonical_projections BEGIN SELECT RAISE(FAIL, 'test persistence failure'); END;").unwrap();
    let events = events();
    assert!(execute(
        directory.path(),
        &repository,
        &provider(),
        false,
        &AtomicBool::new(false),
        &events
    )
    .await
    .is_err());
    assert_eq!(
        repository.canonical_list_runs(None, 1).unwrap()[0].state,
        oxaudit_domain::RunState::Failed
    );
    assert!(!events.0.lock().unwrap().iter().any(|e| e == "deps://done"));
}
#[test]
fn receipt_validates_membership_identity_and_filters_to_selected_queries() {
    let key = "npm\0example\u{0}1.0.0".to_owned();
    let other = "npm\0unrelated\u{0}1.0.0".to_owned();
    let mut vulnerability = full_vulnerability();
    vulnerability.package_name = "unrelated".into();
    let results = AdvisoryResults::from([
        (key.clone(), vec![full_vulnerability()]),
        (other.clone(), vec![vulnerability]),
    ]);
    let mut payload =
        complete_osv_receipt_payload(vec![key.clone(), other.clone()], &results).unwrap();
    let selected = load_complete_osv_receipt(&payload, std::slice::from_ref(&key)).unwrap();
    assert_eq!(selected.len(), 1);
    assert!(load_complete_osv_receipt(&payload, &["npm\0new\u{0}2.0.0".into()]).is_err());
    payload["queryKeys"] = serde_json::json!([key]);
    assert!(
        load_complete_osv_receipt(&payload, std::slice::from_ref(&key))
            .unwrap_err()
            .contains("membership")
    );
    payload["queryKeys"] = serde_json::json!([key, other]);
    payload["results"][&key][0]["packageName"] = "wrong-package".into();
    assert!(load_complete_osv_receipt(&payload, &[key])
        .unwrap_err()
        .contains("identity mismatch"));
}
#[tokio::test]
async fn offline_detects_tampered_receipt_hash() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let payload = complete_osv_receipt_payload(
        vec!["npm\0example\u{0}1.0.0".into()],
        &AdvisoryResults::new(),
    )
    .unwrap();
    repository
        .provider_save_snapshot(&crate::findings::repository::ProviderSnapshotRecord {
            id: "provider_tampered".into(),
            provider_id: "osv-query".into(),
            fetched_at_ms: 1,
            content_sha256: "wrong".into(),
            payload,
        })
        .unwrap();
    assert!(execute(
        directory.path(),
        &repository,
        &provider(),
        true,
        &AtomicBool::new(false),
        &events()
    )
    .await
    .unwrap_err()
    .contains("integrity"));
}
#[tokio::test]
async fn dependency_standards_link_advisory_only_to_affected_component_and_lockfile() {
    use crate::adapters::reporting::{generate, ReportData, ReportFormat};
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let result = execute(
        directory.path(),
        &repository,
        &provider(),
        false,
        &AtomicBool::new(false),
        &events(),
    )
    .await
    .unwrap();
    let id = oxaudit_domain::RunId::parse(result.summary.run_id.clone().unwrap()).unwrap();
    let (artifacts, mut components, observations) =
        repository.canonical_load_report_graph(&id).unwrap();
    let mut unrelated = components[0].clone();
    unrelated.id = oxaudit_domain::ComponentId::new();
    unrelated.name = "unrelated".into();
    unrelated.purl = Some("pkg/npm/unrelated@1.0.0".into());
    components.push(unrelated);
    let affected_id = components[0].id.to_string();
    let data = ReportData {
        run: repository.canonical_load_run(&id).unwrap().unwrap(),
        artifacts,
        components,
        observations,
        findings: vec![],
        projection: repository.canonical_load_projection(&id).unwrap(),
    };
    let openvex: serde_json::Value =
        serde_json::from_slice(&generate(&data, ReportFormat::OpenVex).unwrap().bytes).unwrap();
    assert_eq!(
        openvex["statements"][0]["products"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "only evidence-linked affected package belongs in a statement"
    );
    assert!(!openvex.to_string().contains("unrelated"));
    let cd: serde_json::Value =
        serde_json::from_slice(&generate(&data, ReportFormat::CycloneDxVex).unwrap().bytes)
            .unwrap();
    assert_eq!(cd["vulnerabilities"][0]["affects"][0]["ref"], affected_id);
    let sarif: serde_json::Value =
        serde_json::from_slice(&generate(&data, ReportFormat::Sarif).unwrap().bytes).unwrap();
    let finding = &sarif["runs"][0]["results"][0];
    assert_eq!(finding["ruleId"], "GHSA-full-detail");
    assert_eq!(finding["level"], "error");
    assert_eq!(finding["properties"]["packageName"], "example");
    assert!(
        finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .ends_with("package-lock.json")
    );
    assert!(
        finding["locations"][0]["physicalLocation"]
            .get("region")
            .is_none(),
        "lockfile evidence does not invent a source line"
    );
    for format in [ReportFormat::CycloneDx, ReportFormat::Spdx] {
        let exported = generate(&data, format).unwrap();
        let imported = crate::adapters::reporting::import::inspect(&exported.bytes).unwrap();
        assert_eq!(imported.components.len(), 2);
        assert!(imported
            .components
            .iter()
            .any(|c| c.name == "example" && c.version.as_deref() == Some("1.0.0")));
    }
    for format in [
        ReportFormat::Sarif,
        ReportFormat::OpenVex,
        ReportFormat::CycloneDxVex,
    ] {
        let exported = generate(&data, format).unwrap();
        let imported = crate::adapters::reporting::import::inspect(&exported.bytes).unwrap();
        assert_eq!(imported.external_claims.len(), 1, "{format:?}");
        assert_eq!(imported.external_claims[0].trust, "external-unverified");
    }
}

#[tokio::test]
async fn repeated_install_paths_survive_projection_and_canonical_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("project");
    project(&root);
    project(&root.join("workspace"));
    std::fs::write(
        root.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{
      "":{"dependencies":{"example":"1.0.0","parent":"1.0.0"}},
      "node_modules/example":{"version":"1.0.0"},
      "node_modules/parent":{"version":"1.0.0","dependencies":{"example":"1.0.0"}},
      "node_modules/parent/node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
    let repository = FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
    let provider = Provider {
        expected_queries: 2,
        ..provider()
    };
    let result = execute(
        &root,
        &repository,
        &provider,
        false,
        &AtomicBool::new(false),
        &events(),
    )
    .await
    .unwrap();
    assert_eq!(result.dependencies.len(), 4);
    assert_eq!(result.vulnerabilities.len(), 3);
    let paths = result
        .vulnerabilities
        .iter()
        .map(|v| (v.lockfile.clone(), v.occurrence.install_path.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(paths.len(), 3);
    let run = oxaudit_domain::RunId::parse(result.summary.run_id.unwrap()).unwrap();
    let (artifacts, components, observations) =
        repository.canonical_load_report_graph(&run).unwrap();
    assert_eq!(components.len(), 2);
    assert_eq!(observations.len(), 7);
    let records = serde_json::to_value(
        observations
            .iter()
            .flat_map(|o| &o.evidence)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(records
        .to_string()
        .contains("node_modules/parent/node_modules/example"));
    use crate::adapters::reporting::{generate, ReportData, ReportFormat};
    let mut projection = repository.canonical_load_projection(&run).unwrap().unwrap();
    for vulnerability in projection["vulnerabilities"].as_array_mut().unwrap() {
        vulnerability["severity"] = serde_json::json!(if vulnerability["lockfile"]
            .as_str()
            .unwrap()
            .contains("workspace")
        {
            "info"
        } else if vulnerability["occurrence"]["installPath"]
            == "node_modules/parent/node_modules/example"
        {
            "medium"
        } else {
            "high"
        });
    }
    let data = ReportData {
        run: repository.canonical_load_run(&run).unwrap().unwrap(),
        artifacts,
        components,
        observations,
        findings: vec![],
        projection: Some(projection),
    };
    let sarif: serde_json::Value =
        serde_json::from_slice(&generate(&data, ReportFormat::Sarif).unwrap().bytes).unwrap();
    let rows = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let mut levels = rows
        .iter()
        .map(|row| row["level"].as_str().unwrap())
        .collect::<Vec<_>>();
    levels.sort();
    assert_eq!(
        levels,
        ["error", "note", "warning"],
        "detail joins must retain installation and lockfile provenance"
    );
    for format in [ReportFormat::OpenVex, ReportFormat::CycloneDxVex] {
        let output: serde_json::Value =
            serde_json::from_slice(&generate(&data, format).unwrap().bytes).unwrap();
        let (collection, affected) = if format == ReportFormat::OpenVex {
            ("statements", "products")
        } else {
            ("vulnerabilities", "affects")
        };
        let rows = output[collection].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row[affected].as_array().unwrap().len() == 1));
    }
}

#[tokio::test]
async fn unnamed_workspace_v2_v3_queries_and_persists_actual_package_name() {
    struct WorkspaceProvider;
    impl DependencyProviders for WorkspaceProvider {
        fn query_full<'a>(
            &'a self,
            dependencies: &'a [Dependency],
        ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
            Box::pin(async move {
                assert_eq!(dependencies.len(), 1);
                assert_eq!(
                    dependencies[0].name, "a",
                    "provider must query package identity, not local directory"
                );
                let mut vulnerability = full_vulnerability();
                vulnerability.package_name = "a".into();
                Ok(AdvisoryResults::from([(
                    "npm\u{0}a\u{0}1.0.0".into(),
                    vec![vulnerability],
                )]))
            })
        }
        fn enrich<'a>(
            &'a self,
            _: &'a mut [Vulnerability],
            _: &'a [String],
            _: &'a Path,
        ) -> PortFuture<'a, EnrichmentStatus> {
            Box::pin(async { EnrichmentStatus::default() })
        }
    }
    for version in [2, 3] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("package-lock.json"),serde_json::to_vec(&serde_json::json!({"lockfileVersion":version,"packages":{
            "":{"workspaces":["packages/*"]},"node_modules/a":{"link":true,"resolved":"packages/a"},"packages/a":{"version":"1.0.0"}
        }})).unwrap()).unwrap();
        let repository =
            FindingsRepository::open(directory.path().join("data/runs.sqlite")).unwrap();
        let result = execute(
            directory.path(),
            &repository,
            &WorkspaceProvider,
            false,
            &AtomicBool::new(false),
            &events(),
        )
        .await
        .unwrap();
        assert_eq!(result.dependencies[0].name, "a");
        assert_eq!(result.vulnerabilities[0].package_name, "a");
        assert_eq!(result.summary.packages_queried, 1);
        let run = oxaudit_domain::RunId::parse(result.summary.run_id.unwrap()).unwrap();
        let (_, components, observations) = repository.canonical_load_report_graph(&run).unwrap();
        assert_eq!(components[0].name, "a");
        assert_eq!(components[0].purl.as_deref(), Some("pkg/npm/a@1.0.0"));
        assert!(observations.iter().flat_map(|o| &o.evidence).any(|e| matches!(&e.evidence,oxaudit_domain::Evidence::PackageDeclaration(d) if d.package_name=="a" && d.install_path.as_deref()==Some("packages/a"))));
    }
}

fn advisory_db_with(records: Vec<(String, String)>) -> crate::advisories::store::AdvisoryDb {
    // (id, package) advisory records affecting the package at <2.0.0
    let mut db = crate::advisories::store::AdvisoryDb::open_in_memory().unwrap();
    for (id, package) in records {
        let record = serde_json::json!({
            "id": id,
            "summary": "fixture advisory",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "affected": [{
                "package": { "ecosystem": "npm", "name": package },
                "ranges": [{ "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]
            }]
        });
        let packages = vec![("npm".to_string(), package)];
        db.insert_record(&id, None, &record, &packages).unwrap();
    }
    db.finish_update(&["npm".to_string()], 12345, 12345)
        .unwrap();
    db
}

#[tokio::test]
async fn local_advisory_db_answers_offline_with_the_same_finding_shape() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    project(root);
    let repo = FindingsRepository::open_in_memory().unwrap();
    let db = advisory_db_with(vec![("GHSA-fixture".to_string(), "example".to_string())]);
    let provider = provider();
    let result = scan(ScanRequest {
        root,
        repository: &repo,
        providers: &provider,
        offline: true,
        advisory_db: Some(&db),
        cancel: &AtomicBool::new(false),
        events: &events(),
        cache_path: root,
        ignored_dirs: &[],
    })
    .await
    .unwrap();

    assert_eq!(result.summary.advisory_source, "local-db");
    assert_eq!(result.summary.advisory_fetched_at_ms, Some(12345));
    assert_eq!(result.vulnerabilities.len(), 1);
    let vulnerability = &result.vulnerabilities[0];
    assert_eq!(vulnerability.id, "GHSA-fixture");
    assert_eq!(vulnerability.package_name, "example");
    assert_eq!(vulnerability.fixed_versions, vec!["2.0.0"]);
    // The shared parser filled severity and evidence exactly as the
    // network path would.
    assert!(vulnerability.cvss_score.is_some());
    assert!(vulnerability.affected_evidence.is_some());
}

#[tokio::test]
async fn local_advisory_db_requires_full_ecosystem_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    project(root);
    let repo = FindingsRepository::open_in_memory().unwrap();
    // A database built for PyPI cannot answer an npm query.
    let db = crate::advisories::store::AdvisoryDb::open_in_memory().unwrap();
    db.finish_update(&["PyPI".to_string()], 1, 1).unwrap();
    let error = scan(ScanRequest {
        root,
        repository: &repo,
        providers: &provider(),
        offline: true,
        advisory_db: Some(&db),
        cancel: &AtomicBool::new(false),
        events: &events(),
        cache_path: root,
        ignored_dirs: &[],
    })
    .await
    .unwrap_err();
    assert!(error.contains("incomplete advisory coverage"), "{error}");
    assert!(error.contains("npm"), "{error}");
}

#[tokio::test]
async fn local_advisory_db_surfaces_undetermined_notes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    project(root);
    let repo = FindingsRepository::open_in_memory().unwrap();
    let mut db = crate::advisories::store::AdvisoryDb::open_in_memory().unwrap();
    let record = serde_json::json!({
        "id": "GHSA-undecidable",
        "affected": [{
            "package": { "ecosystem": "npm", "name": "example" },
            "ranges": [{ "type": "SEMVER",
                "events": [{"introduced": "not-a-version"}] }]
        }]
    });
    let packages = vec![("npm".to_string(), "example".to_string())];
    db.insert_record("GHSA-undecidable", None, &record, &packages)
        .unwrap();
    db.finish_update(&["npm".to_string()], 1, 1).unwrap();

    let result = scan(ScanRequest {
        root,
        repository: &repo,
        providers: &provider(),
        offline: true,
        advisory_db: Some(&db),
        cancel: &AtomicBool::new(false),
        events: &events(),
        cache_path: root,
        ignored_dirs: &[],
    })
    .await
    .unwrap();

    // Undetermined keeps the advisory and says so in the summary.
    assert_eq!(result.vulnerabilities.len(), 1);
    assert_eq!(result.summary.advisory_notes.len(), 1);
    assert!(result.summary.advisory_notes[0].contains("undetermined"));
}

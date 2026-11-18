use super::*;
use crate::deps::service::{
    scan, AdvisoryPolicySource, AdvisoryResults, DependencyProviders, ScanRequest,
};
use crate::findings::service::ScanEventSink;
use crate::models::{EnrichmentStatus, Vulnerability};
use oxaudit_application::PortFuture;
use oxaudit_sca::Action;
use std::sync::atomic::AtomicBool;

struct Quiet;
impl ScanEventSink for Quiet {
    fn emit(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> Result<(), crate::findings::error::CommandError> {
        Ok(())
    }
}

/// Reports one high advisory against every package named `vulnerable`.
struct Provider;
impl DependencyProviders for Provider {
    fn query_full<'a>(
        &'a self,
        dependencies: &'a [Dependency],
    ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
        Box::pin(async move {
            Ok(dependencies
                .iter()
                .filter(|dependency| dependency.name == "vulnerable")
                .map(|dependency| {
                    (
                        crate::deps::osv::dependency_query_key(dependency),
                        vec![Vulnerability {
                            affected_functions: Vec::new(),
                            referenced_functions: Vec::new(),
                            occurrence: Default::default(),
                            affected_evidence: None,
                            id: "GHSA-test-0001".into(),
                            aliases: Vec::new(),
                            summary: "fixture".into(),
                            details: String::new(),
                            severity: Some("high".into()),
                            cvss_score: None,
                            epss: None,
                            epss_percentile: None,
                            known_exploited: false,
                            ransomware: false,
                            public_exploit: false,
                            direct_usage: Default::default(),
                            ecosystem: dependency.ecosystem.clone(),
                            package_name: dependency.name.clone(),
                            installed_version: dependency.version.clone(),
                            fixed_versions: Vec::new(),
                            affected_range: None,
                            references: Vec::new(),
                            published: None,
                            modified: None,
                            lockfile: String::new(),
                            review: None,
                        }],
                    )
                })
                .collect())
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

const LOCK: &str = r#"{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0",
         "dependencies": {"vulnerable": "^1.0.0", "copyleft": "^2.0.0"}},
    "node_modules/vulnerable": {"version": "1.0.0", "license": "MIT",
         "dependencies": {"deep": "^3.0.0"}},
    "node_modules/copyleft": {"version": "2.0.0", "license": "GPL-3.0-only"},
    "node_modules/deep": {"version": "3.0.0"}
  }
}"#;

fn project(root: &Path, policy: Option<&str>) {
    std::fs::create_dir_all(root.join(".oxaudit")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"vulnerable":"^1.0.0","copyleft":"^2.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(root.join("package-lock.json"), LOCK).unwrap();
    if let Some(policy) = policy {
        std::fs::write(root.join(COMPONENT_POLICY_PATH), policy).unwrap();
    }
}

async fn scanned(root: &Path, repository: &FindingsRepository) -> DependencyScanResult {
    scan(ScanRequest {
        project_root: root,
        root,
        repository,
        providers: &Provider,
        offline: false,
        advisory_db: None,
        cancel: &AtomicBool::new(false),
        events: &Quiet,
        cache_path: root,
        ignored_dirs: &[],
        advisory_policy: AdvisoryPolicySource::Project,
        ignore_invalid_policy: false,
    })
    .await
    .expect("fixture scan completes")
}

fn now() -> chrono::DateTime<chrono::Utc> {
    "2026-11-16T00:00:00Z".parse().unwrap()
}

const POLICY: &str = r#"{
  "version": 1,
  "licenses": {"deny": ["category:strong-copyleft"], "unknown": "warn"},
  "operational": {"deprecated": "deny"},
  "vulnerabilities": {"warn": "high"}
}"#;

#[test]
fn a_project_without_a_policy_gets_the_empty_one_and_an_invalid_one_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let loaded = load_policy(PolicySource::Project(root), false).unwrap();
    assert!(loaded.source.is_none() && !loaded.policy.has_rules());

    project(root, Some(POLICY));
    let loaded = load_policy(PolicySource::Project(root), false).unwrap();
    assert_eq!(loaded.source.as_deref(), Some(COMPONENT_POLICY_PATH));
    assert!(loaded.policy.has_rules());

    for broken in [
        r#"{"version": 1, "licenses": {"deny": ["GPL-9"]}}"#,
        r#"{"version": 1, "version": 1}"#,
        r#"{"version": 1, "components": [{"ecosystem": "npm", "package": "x",
            "decision": "approved", "reason": "see /Users/me/notes.txt"}]}"#,
        "not json",
    ] {
        std::fs::write(root.join(COMPONENT_POLICY_PATH), broken).unwrap();
        let error = load_policy(PolicySource::Project(root), false).unwrap_err();
        assert!(
            error.starts_with("invalid .oxaudit/component-policy.json: "),
            "{error}"
        );
        let ignored = load_policy(PolicySource::Project(root), true).unwrap();
        assert!(ignored.source.is_none() && !ignored.policy.has_rules());
        assert!(
            ignored.notes[0].contains("was ignored"),
            "{:?}",
            ignored.notes
        );
    }

    // A named file that does not exist is an error, not "no policy".
    assert!(load_policy(PolicySource::File(&root.join("nope.json")), false).is_err());
}

#[cfg(unix)]
#[test]
fn a_symlinked_project_policy_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    project(root, None);
    let real = root.join("real.json");
    std::fs::write(&real, POLICY).unwrap();
    std::os::unix::fs::symlink(&real, root.join(COMPONENT_POLICY_PATH)).unwrap();
    assert!(load_policy(PolicySource::Project(root), false).is_err());
    assert!(load_policy(PolicySource::File(&root.join(COMPONENT_POLICY_PATH)), false).is_ok());
}

#[tokio::test]
async fn a_scan_becomes_a_report_with_relationships_licenses_and_policy_verdicts() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    project(&root, Some(POLICY));
    let repository = FindingsRepository::open_in_memory().unwrap();
    let result = scanned(&root, &repository).await;
    let loaded = load_policy(PolicySource::Project(&root), false).unwrap();
    let facts = collect_releases(&repository, &result, ReleaseMode::Skip).await;
    let report = build_report(&result, &facts, &loaded, now());

    assert_eq!(report.summary.run_id, result.summary.run_id);
    assert_eq!(report.summary.components, 3);
    assert_eq!(report.summary.direct_components, 2);
    assert_eq!(report.summary.unclassified_relationship, 0);
    let by_name = |name: &str| {
        report
            .components
            .iter()
            .find(|component| component.name == name)
            .unwrap()
    };
    assert_eq!(by_name("copyleft").verdict, Action::Deny);
    assert_eq!(by_name("copyleft").direct, Some(true));
    assert_eq!(by_name("copyleft").lockfiles, vec!["package-lock.json"]);
    assert_eq!(by_name("deep").direct, Some(false));
    // No declared license: flagged by `unknown`, never assumed permissive.
    assert_eq!(by_name("deep").verdict, Action::Warn);
    assert_eq!(by_name("vulnerable").advisories, vec!["GHSA-test-0001"]);
    assert_eq!(by_name("vulnerable").verdict, Action::Warn);
    assert!(report.fails());
    assert_eq!(
        report.summary.policy.source.as_deref(),
        Some(COMPONENT_POLICY_PATH)
    );
    // Operational rules exist but no facts were collected: said, not passed.
    assert_eq!(report.summary.releases.status, "notCollected");
    assert!(
        report
            .summary
            .notes
            .iter()
            .any(|note| note.contains("were not evaluated")),
        "{:?}",
        report.summary.notes
    );
}

#[tokio::test]
async fn release_facts_are_stored_once_and_reused_offline_with_an_integrity_check() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    project(&root, Some(POLICY));
    let repository = FindingsRepository::open_in_memory().unwrap();
    let result = scanned(&root, &repository).await;

    // Nothing stored yet: offline says so instead of reporting a pass.
    let missing = collect_releases(&repository, &result, ReleaseMode::Cached).await;
    assert_eq!(missing.status, "notCollected");
    assert!(
        missing.notes[0].contains("no stored release facts"),
        "{:?}",
        missing.notes
    );

    // An index that is unreachable still leaves a receipt of what was asked.
    let http = reqwest::Client::new();
    let fetched = collect_releases(
        &repository,
        &result,
        ReleaseMode::Fetch {
            http: &http,
            base: "http://127.0.0.1:1",
        },
    )
    .await;
    assert_eq!(fetched.status, "partial");
    assert!(fetched.releases.is_empty());

    // Store a receipt with one deprecated component and read it back.
    let keys = crate::deps::osv::query_keys(&result.dependencies);
    let payload = serde_json::json!({
        "schemaVersion": 1,
        "queryKeys": keys,
        "releases": [
            {"ecosystem": "npm", "name": "vulnerable", "version": "1.0.0", "deprecated": true},
            {"ecosystem": "npm", "name": "elsewhere", "version": "9.9.9", "deprecated": true}
        ],
    });
    let mut record = ProviderSnapshotRecord {
        id: "provider_fixture".into(),
        provider_id: RELEASE_PROVIDER_ID.into(),
        fetched_at_ms: epoch_millis() + 60_000,
        content_sha256: receipt_hash(&payload).unwrap(),
        payload,
    };
    repository.provider_save_snapshot(&record).unwrap();
    let cached = collect_releases(&repository, &result, ReleaseMode::Cached).await;
    assert_eq!(cached.status, "cached");
    // Facts about packages outside this inventory are not carried along.
    assert_eq!(cached.releases.len(), 1);
    let loaded = load_policy(PolicySource::Project(&root), false).unwrap();
    let report = build_report(&result, &cached, &loaded, now());
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.rule == "operational.deprecated" && violation.gates()));
    assert_eq!(report.summary.releases.deprecated, 1);

    // A receipt whose content no longer matches its hash is not trusted.
    record.id = "provider_tampered".into();
    record.fetched_at_ms += 60_000;
    record.payload["releases"][0]["deprecated"] = serde_json::json!(false);
    repository.provider_save_snapshot(&record).unwrap();
    let tampered = collect_releases(&repository, &result, ReleaseMode::Cached).await;
    assert_eq!(tampered.status, "notCollected");
    assert!(
        tampered.notes[0].contains("integrity"),
        "{:?}",
        tampered.notes
    );
}

#[tokio::test]
async fn the_portfolio_rebuilds_reports_from_stored_runs_without_touching_them() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let (api, web) = (base.join("api"), base.join("web"));
    project(&api, Some(POLICY));
    project(&web, None);
    let repository = FindingsRepository::open_in_memory().unwrap();
    scanned(&api, &repository).await;
    scanned(&web, &repository).await;
    let runs = crate::monitor::select_runs(&repository, &[]).unwrap();
    assert_eq!(runs.len(), 2);

    let own = portfolio_entries(&repository, &runs, PortfolioPolicy::PerProject, now()).unwrap();
    let fails: Vec<(String, bool)> = own
        .iter()
        .map(|entry| (entry.target.clone(), entry.report.fails()))
        .collect();
    assert_eq!(
        fails,
        vec![
            (api.to_string_lossy().into_owned(), true),
            (web.to_string_lossy().into_owned(), false),
        ]
    );

    // One policy for the whole portfolio applies to both.
    let shared = load_policy(PolicySource::Project(&api), false).unwrap();
    let all =
        portfolio_entries(&repository, &runs, PortfolioPolicy::Shared(&shared), now()).unwrap();
    assert!(all.iter().all(|entry| entry.report.fails()));
    let summary = oxaudit_sca::portfolio::summarize(&all);
    assert_eq!(summary.totals.failing_projects, 2);
    assert_eq!(summary.totals.distinct_components, 3);
    let used = oxaudit_sca::portfolio::where_used(&all, Some("npm"), "copyleft", None);
    assert_eq!(used.len(), 2);

    // A project directory that is gone gets no policy, and says so.
    std::fs::remove_dir_all(&api).unwrap();
    let gone = portfolio_entries(&repository, &runs, PortfolioPolicy::PerProject, now()).unwrap();
    assert!(!gone[0].report.fails());
    assert!(gone[0].report.summary.notes[0].contains("not on this machine"));
}

/// `yara-x` turns on serde_json's `preserve_order` workspace-wide, which makes a
/// `Value` serialize in insertion order. Stored receipts were hashed over
/// key-sorted bytes, so the digest must stay the sorted-bytes digest.
#[test]
fn receipt_digest_is_over_key_sorted_bytes_whatever_the_insertion_order() {
    use sha2::Digest;
    let mut payload = serde_json::json!({});
    payload["zeta"] = serde_json::json!({"y": 1, "b": [{"d": 1, "c": 2}]});
    payload["alpha"] = serde_json::json!(true);
    let expected = hex::encode(sha2::Sha256::digest(
        br#"{"alpha":true,"zeta":{"b":[{"c":2,"d":1}],"y":1}}"#,
    ));
    assert_eq!(super::receipt_hash(&payload).unwrap(), expected);
}

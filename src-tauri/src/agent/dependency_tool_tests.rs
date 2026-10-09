use super::{scan_agent_dependencies, DependencyToolEvents};
use crate::deps::service::{AdvisoryResults, DependencyProviders, ScanRequest};
use crate::findings::repository::FindingsRepository;
use crate::models::{Dependency, EnrichmentStatus, Vulnerability};
use oxaudit_application::PortFuture;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

struct Provider<'a> {
    mode: &'static str,
    cancel: &'a AtomicBool,
}
impl DependencyProviders for Provider<'_> {
    fn query_full<'a>(
        &'a self,
        deps: &'a [Dependency],
    ) -> PortFuture<'a, Result<AdvisoryResults, String>> {
        Box::pin(async move {
            if self.mode == "missing" {
                return Err("OSV advisory detail record is unavailable for GHSA-tool".into());
            }
            if self.mode == "pending" {
                self.cancel.store(true, Ordering::SeqCst);
                return std::future::pending().await;
            }
            let d = &deps[0];
            let full = serde_json::json!({"id":"GHSA-tool", "summary":"Resolved advisory", "details":"Full detail",
                "aliases":["CVE-2026-1234"],"database_specific":{"severity":"HIGH"},
                "affected":[{"database_specific":{"severity":"HIGH"},"package":{"ecosystem":"npm","name":"example"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]});
            let vulnerabilities =
                crate::deps::osv::parse_vulns(vec![full], &d.ecosystem, &d.name, &d.version);
            Ok(AdvisoryResults::from([(
                crate::deps::osv::dependency_query_key(d),
                vulnerabilities,
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
fn project(root: &Path) {
    std::fs::write(
        root.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
}
async fn scan(
    root: &Path,
    repo: &FindingsRepository,
    provider: &Provider<'_>,
) -> Result<serde_json::Value, String> {
    scan_agent_dependencies(ScanRequest {
        project_root: root,
        root,
        ignored_dirs: &[],
        offline: false,
        advisory_db: None,
        repository: repo,
        providers: provider,
        cancel: provider.cancel,
        events: &DependencyToolEvents,
        cache_path: root,
    })
    .await
}

#[tokio::test]
async fn dependency_tool_uses_full_details_and_returns_a_durable_run() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repo = FindingsRepository::open_in_memory().unwrap();
    let cancel = AtomicBool::new(false);
    let result = scan(
        directory.path(),
        &repo,
        &Provider {
            mode: "full",
            cancel: &cancel,
        },
    )
    .await
    .unwrap();
    assert_eq!(result["top_vulnerabilities"][0]["severity"], "high");
    assert_eq!(
        result["top_vulnerabilities"][0]["fixed"],
        serde_json::json!(["1.0.1"])
    );
    assert_eq!(
        result["top_vulnerabilities"][0]["summary"],
        "Resolved advisory"
    );
    let run_id =
        oxaudit_domain::RunId::parse(result["run_id"].as_str().expect("durable run id")).unwrap();
    assert_eq!(
        repo.canonical_load_run(&run_id).unwrap().unwrap().state,
        oxaudit_domain::RunState::Completed
    );
    assert!(repo.canonical_load_projection(&run_id).unwrap().is_some());
    assert_eq!(result["advisory_coverage"], "complete");
}

#[tokio::test]
async fn dependency_tool_refuses_mixed_malformed_inventories() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    std::fs::write(directory.path().join("bun.lock"), "invalid").unwrap();
    let repo = FindingsRepository::open_in_memory().unwrap();
    let cancel = AtomicBool::new(false);
    let error = scan(
        directory.path(),
        &repo,
        &Provider {
            mode: "full",
            cancel: &cancel,
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("incomplete dependency coverage"), "{error}");
    assert_eq!(
        repo.canonical_list_runs(Some("dependencies"), 10).unwrap()[0].state,
        oxaudit_domain::RunState::Failed
    );
}

#[tokio::test]
async fn dependency_tool_records_failed_detail_resolution() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repo = FindingsRepository::open_in_memory().unwrap();
    let cancel = AtomicBool::new(false);
    let error = scan(
        directory.path(),
        &repo,
        &Provider {
            mode: "missing",
            cancel: &cancel,
        },
    )
    .await
    .unwrap_err();
    assert!(
        error.contains("advisory detail record is unavailable"),
        "{error}"
    );
    assert_eq!(
        repo.canonical_list_runs(Some("dependencies"), 10).unwrap()[0].state,
        oxaudit_domain::RunState::Failed
    );
    assert!(repo
        .provider_latest_snapshot("osv-query")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn dependency_tool_cancels_pending_provider_work() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path());
    let repo = FindingsRepository::open_in_memory().unwrap();
    let cancel = AtomicBool::new(false);
    let provider = Provider {
        mode: "pending",
        cancel: &cancel,
    };
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        scan(directory.path(), &repo, &provider),
    )
    .await
    .expect("tool must interrupt pending provider work")
    .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    assert_eq!(
        repo.canonical_list_runs(Some("dependencies"), 10).unwrap()[0].state,
        oxaudit_domain::RunState::Cancelled
    );
}

#[tokio::test]
async fn dependency_tool_preserves_authorized_and_ignored_subdirectory_scope() {
    let directory = tempfile::tempdir().unwrap();
    let ignored = directory.path().join("generated");
    std::fs::create_dir(&ignored).unwrap();
    project(&ignored);
    let repo = FindingsRepository::open_in_memory().unwrap();
    let cancel = AtomicBool::new(false);
    let provider = Provider {
        mode: "full",
        cancel: &cancel,
    };
    let ignored_dirs = vec!["generated".into()];
    let result = scan_agent_dependencies(ScanRequest {
        project_root: directory.path(),
        root: &ignored,
        ignored_dirs: &ignored_dirs,
        offline: false,
        advisory_db: None,
        repository: &repo,
        providers: &provider,
        cancel: &cancel,
        events: &DependencyToolEvents,
        cache_path: directory.path(),
    })
    .await
    .unwrap();
    assert_eq!(result["packages_queried"], 0);
    let outside = tempfile::tempdir().unwrap();
    project(outside.path());
    let error = scan_agent_dependencies(ScanRequest {
        project_root: directory.path(),
        root: outside.path(),
        ignored_dirs: &[],
        offline: false,
        advisory_db: None,
        repository: &repo,
        providers: &provider,
        cancel: &cancel,
        events: &DependencyToolEvents,
        cache_path: directory.path(),
    })
    .await
    .unwrap_err();
    assert!(error.contains("outside the authorized project"), "{error}");
}

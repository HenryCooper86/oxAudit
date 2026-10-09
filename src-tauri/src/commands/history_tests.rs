use super::*;
use oxaudit_domain::{RunId, RunState};
use std::fs;

const LEAK: &str = "AKIAZ9X8W7U6T5S4R3Q2";
struct Quiet;
impl ScanEventSink for Quiet {
    fn emit(&self, _: &str, _: Value) -> Result<(), CommandError> {
        Ok(())
    }
}
fn repository_with_deleted_leak() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| crate::git_context::tests::git(temp.path(), args);
    git(&["init", "-b", "main"]);
    git(&["config", "user.email", "history-test@example.invalid"]);
    git(&["config", "user.name", "History test"]);
    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src/deploy.sh"),
        format!("export AWS_ACCESS_KEY_ID={LEAK}\n"),
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-m", "inert historical fixture"]);
    fs::remove_file(temp.path().join("src/deploy.sh")).unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-m", "delete historical fixture"]);
    temp
}
fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
#[cfg(unix)]
async fn history_workflow_preserves_whitespace_in_the_existing_repository_directory() {
    let source = repository_with_deleted_leak();
    let owned = tempfile::tempdir().unwrap();
    let target = owned.path().join("repository ");
    fs::rename(source.path(), &target).unwrap();
    let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
    let outcome = scan_history_workflow(
        &repository,
        &http(),
        target.to_string_lossy().into_owned(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &Quiet,
    )
    .await
    .expect("the existing Git directory's whitespace belongs to its path");
    assert_eq!(outcome.state, RunState::Completed);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        outcome.target,
        target.canonicalize().unwrap().to_string_lossy()
    );
    let id = RunId::parse(outcome.run_id).unwrap();
    assert_eq!(
        repository
            .canonical_load_run(&id)
            .unwrap()
            .unwrap()
            .target_label,
        outcome.target
    );
}

#[tokio::test]
async fn durable_history_reloads_and_exports_redacted_immutable_blob_locations() {
    let root = repository_with_deleted_leak();
    let db = tempfile::tempdir().unwrap();
    let db_path = db.path().join("private/history.sqlite");
    let repository = crate::findings::repository::FindingsRepository::open(&db_path).unwrap();
    let outcome = scan_history_workflow(
        &repository,
        &http(),
        root.path().to_string_lossy().into_owned(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &Quiet,
    )
    .await
    .unwrap();
    assert_eq!(outcome.state, RunState::Completed);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        outcome.git_context.as_ref().unwrap().context_changed,
        Some(false)
    );
    let oid = outcome.finding_blob_ids[&outcome.findings[0].id].clone();
    assert!(oid.len() == 40 || oid.len() == 64);
    let identity = RunId::parse(outcome.run_id.clone()).unwrap();
    drop(repository);
    fs::write(root.path().join("src/deploy.sh"), "current clean content\n").unwrap();
    let repository = crate::findings::repository::FindingsRepository::open(&db_path).unwrap();
    let run = repository.canonical_load_run(&identity).unwrap().unwrap();
    assert_eq!(run.kind, oxaudit_domain::RunKind::History);
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(run.engine_ids, vec!["oxaudit.native.git-history"]);
    let projection = repository
        .canonical_load_projection(&identity)
        .unwrap()
        .unwrap();
    assert_eq!(projection["runId"], outcome.run_id);
    let (artifacts, components, observations) =
        repository.canonical_load_report_graph(&identity).unwrap();
    assert!(artifacts
        .iter()
        .all(|artifact| artifact.location.canonical_path.is_none()));
    assert!(artifacts
        .iter()
        .any(
            |artifact| artifact.location.normalized_path == format!("git:{oid}!src/deploy.sh")
                && artifact.content_sha256.is_some()
        ));
    let report = crate::adapters::reporting::generate(
        &crate::adapters::reporting::ReportData {
            run,
            artifacts,
            components,
            observations,
            findings: outcome.findings,
            projection: Some(projection),
        },
        crate::adapters::reporting::ReportFormat::Sarif,
    )
    .unwrap();
    let content = String::from_utf8(report.bytes).unwrap();
    assert!(content.contains(&format!("git:{oid}!src/deploy.sh")));
    assert!(!content.contains(LEAK));
    for entry in fs::read_dir(db_path.parent().unwrap()).unwrap().flatten() {
        if entry.path().is_file() {
            assert!(!String::from_utf8_lossy(&fs::read(entry.path()).unwrap()).contains(LEAK));
        }
    }
}

#[tokio::test]
async fn failed_and_pre_cancelled_history_attempts_are_durable_not_completed_empty() {
    for cancelled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
        let error = scan_history_workflow(
            &repository,
            &http(),
            root.path().to_string_lossy().into_owned(),
            false,
            &Arc::new(AtomicBool::new(cancelled)),
            &Quiet,
        )
        .await
        .unwrap_err();
        let runs = repository.canonical_list_runs(Some("history"), 10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(
            runs[0].state,
            if cancelled {
                RunState::Cancelled
            } else {
                RunState::Failed
            }
        );
        let projection = repository
            .canonical_load_projection(&runs[0].id)
            .unwrap()
            .unwrap();
        assert_ne!(projection["state"], "completed");
        assert_eq!(projection["findings"].as_array().unwrap().len(), 0);
        if cancelled {
            assert!(error.contains("cancelled"));
        }
    }
}

#[tokio::test]
async fn history_projection_save_failure_preserves_failed_attempt_and_prior_graph() {
    let root = repository_with_deleted_leak();
    let db = tempfile::tempdir().unwrap();
    let db_path = db.path().join("private/history.sqlite");
    let repository = crate::findings::repository::FindingsRepository::open(&db_path).unwrap();
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_history_projection BEFORE INSERT ON canonical_projections BEGIN SELECT RAISE(ABORT,'history save rejected'); END;").unwrap();
    assert!(scan_history_workflow(
        &repository,
        &http(),
        root.path().to_string_lossy().into_owned(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &Quiet
    )
    .await
    .is_err());
    let runs = repository.canonical_list_runs(Some("history"), 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].state, RunState::Failed);
    let (_, _, observations) = repository.canonical_load_report_graph(&runs[0].id).unwrap();
    assert_eq!(observations.len(), 1);
}

#[tokio::test]
async fn terminal_history_save_failure_keeps_saved_evidence_but_never_claims_completion() {
    let root = repository_with_deleted_leak();
    let db = tempfile::tempdir().unwrap();
    let db_path = db.path().join("private/history.sqlite");
    let repository = crate::findings::repository::FindingsRepository::open(&db_path).unwrap();
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_history_completion BEFORE UPDATE ON canonical_runs WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'terminal save rejected'); END;").unwrap();
    assert!(scan_history_workflow(
        &repository,
        &http(),
        root.path().to_string_lossy().into_owned(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &Quiet
    )
    .await
    .is_err());
    let runs = repository.canonical_list_runs(Some("history"), 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].state, RunState::Failed);
    let projection = repository
        .canonical_load_projection(&runs[0].id)
        .unwrap()
        .unwrap();
    assert_eq!(projection["state"], "failed");
    assert_eq!(projection["findings"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn history_adapter_cannot_bypass_another_categorys_work_owner() {
    let root = repository_with_deleted_leak();
    let state = AppState::new();
    let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
    let findings =
        FindingsState::available(crate::findings::service::FindingsService::new(repository));
    let work = state
        .scan_work
        .begin(
            crate::scan_work::WorkKind::Source,
            "active source",
            None,
            &Quiet,
        )
        .unwrap();
    let error = scan_history_secrets_engine(
        &state,
        &findings,
        &Quiet,
        root.path().to_string_lossy().into_owned(),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(error.contains("already running"));
    assert_eq!(
        state
            .scan_work
            .snapshot()
            .unwrap()
            .active
            .unwrap()
            .operation_id,
        work.id()
    );
    assert!(findings
        .service()
        .unwrap()
        .repository()
        .canonical_list_runs(Some("history"), 10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn history_adapter_binds_its_canonical_run_while_active_and_preserves_terminal_identity() {
    struct Observe<'a> {
        registry: &'a crate::scan_work::ScanWorkRegistry,
        ids: std::sync::Mutex<Vec<String>>,
    }
    impl ScanEventSink for Observe<'_> {
        fn emit(&self, event: &str, _: Value) -> Result<(), CommandError> {
            if event == "run://event" {
                if let Some(id) = self
                    .registry
                    .snapshot()
                    .unwrap()
                    .active
                    .and_then(|work| work.run_id)
                {
                    self.ids.lock().unwrap().push(id);
                }
            }
            Ok(())
        }
    }
    let root = repository_with_deleted_leak();
    let state = AppState::new();
    let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
    let findings =
        FindingsState::available(crate::findings::service::FindingsService::new(repository));
    let events = Observe {
        registry: &state.scan_work,
        ids: std::sync::Mutex::new(Vec::new()),
    };
    let outcome = scan_history_secrets_engine(
        &state,
        &findings,
        &events,
        root.path().to_string_lossy().into_owned(),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(!events.ids.lock().unwrap().is_empty());
    assert!(events
        .ids
        .lock()
        .unwrap()
        .iter()
        .all(|id| id == &outcome.run_id));
    let snapshot = state.scan_work.snapshot().unwrap();
    assert!(snapshot.active.is_none());
    assert_eq!(
        snapshot.recent[0].run_id.as_deref(),
        Some(outcome.run_id.as_str())
    );
    assert_eq!(snapshot.recent[0].status, "completed");
}

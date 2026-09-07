//! Tests for [`super`].
//!
//! Kept a child module rather than moved to `tests/`: these reach private
//! items through `use super::*`, and widening their visibility to run them
//! from outside would be a worse design than a long file. This is purely a
//! split for readability — service.rs was 3776 lines.

use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Arc, Barrier, Mutex},
};

use crate::{
    cve::CveState,
    findings::domain::{DiffStatus, RunPersistence, RunStatus},
    models::ScanOptions,
};

use super::{FindingsService, ScanEventSink, POLICY_REFRESH_WARNING, RETENTION_WARNING};

#[derive(Default)]
struct RecordingEvents(Mutex<Vec<String>>);

impl ScanEventSink for RecordingEvents {
    fn emit(
        &self,
        event: &str,
        _payload: serde_json::Value,
    ) -> Result<(), crate::findings::error::CommandError> {
        self.0.lock().unwrap().push(event.to_owned());
        Ok(())
    }
}

struct FailingEvents;

impl ScanEventSink for FailingEvents {
    fn emit(
        &self,
        _event: &str,
        _payload: serde_json::Value,
    ) -> Result<(), crate::findings::error::CommandError> {
        Err(crate::findings::error::CommandError::persistence_unavailable())
    }
}

fn cached_cve_state() -> CveState {
    let state = CveState::new(reqwest::Client::new());
    *state.kev.lock().unwrap() = Some((std::time::Instant::now(), Default::default()));
    state
}

fn write_valid_policy(project: &std::path::Path, reason: &str) {
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(
            project.join(".oxaudit/policy.json"),
            format!(
                r#"{{"version":1,"entries":[{{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"{reason}"}}]}}"#
            ),
        )
        .unwrap();
}

fn remove_policy(project: &std::path::Path) {
    let path = project.join(".oxaudit/policy.json");
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
}

fn seed_aged_baseline(
    service: &FindingsService,
    project: &std::path::Path,
) -> crate::findings::domain::ScanRunDetail {
    let context = service.inspect_project(project).unwrap();
    let mut outcome = crate::scanners::scan_file_with_relative_path(
        &project.join("app.js"),
        "app.js",
        1024,
        false,
        true,
    );
    crate::findings::fingerprint::assign_fingerprints(&mut outcome.findings);
    let run_id = format!("aged-baseline-{}", uuid::Uuid::new_v4());
    for finding in &mut outcome.findings {
        let decision = crate::triage::scope::classify(&finding.file_path);
        finding.scope = Some(decision.scope);
        finding.scope_reason = Some(decision.reason);
        finding.observation_run_id = run_id.clone();
    }
    let coverage = crate::findings::coverage::CoverageManifest::from_entries(vec![(
        "app.js".to_owned(),
        outcome.covered_families,
    )]);
    let started_at = "2025-01-01T00:00:00.000000000Z".to_owned();
    let running = crate::findings::domain::ScanRunDetail {
        project_id: context.project_id.clone(),
        run_id: run_id.clone(),
        baseline_run_id: None,
        status: RunStatus::Running,
        persistence: RunPersistence::Saved,
        policy: crate::findings::domain::PolicyStatus::Missing,
        started_at: started_at.clone(),
        completed_at: None,
        summary: super::summarize(
            project.to_string_lossy().into_owned(),
            1,
            0,
            16,
            1,
            &outcome.findings,
        ),
        findings: Vec::new(),
        maintenance_warning: None,
    };
    service
        .repository
        .start_run(&running, "test-scanner", &ScanOptions::default())
        .unwrap();
    let mut completed = running;
    completed.status = RunStatus::Completed;
    completed.completed_at = Some("2025-01-01T00:00:01.000000000Z".to_owned());
    completed.findings = outcome.findings;
    service
        .repository
        .complete_run(&completed, &coverage)
        .unwrap()
}

#[test]
fn service_can_be_constructed_over_a_repository() {
    let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
    let _service = FindingsService::new(repository);
}

#[test]
fn service_exposes_the_bounded_run_list_contract() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let context = service.inspect_project(&project).unwrap();
    assert!(service
        .list_runs(&context.project_id, 10)
        .unwrap()
        .is_empty());
    assert_eq!(
        service.list_runs("unknown-project", 10).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[test]
fn inspect_project_returns_the_policy_loaded_under_current_authority() {
    for transition in [
        ("valid-valid", "valid", "valid"),
        ("valid-missing", "valid", "missing"),
        ("missing-valid", "missing", "valid"),
        ("invalid-valid", "invalid", "valid"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join(transition.0);
        std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
        match transition.1 {
            "valid" => write_valid_policy(&project, "initial authority"),
            "invalid" => {
                std::fs::write(project.join(".oxaudit/policy.json"), b"{ invalid initial }")
                    .unwrap()
            }
            "missing" => remove_policy(&project),
            _ => unreachable!(),
        }
        let service = Arc::new(FindingsService::new(
            crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
        ));
        let canonical = project
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        service.pause_policy_projection_after_read_for_test(
            canonical,
            entered.clone(),
            release.clone(),
        );
        let operation = {
            let service = service.clone();
            let project = project.clone();
            std::thread::spawn(move || service.inspect_project(project))
        };
        entered.wait();
        match transition.2 {
            "valid" => write_valid_policy(&project, "current authority"),
            "missing" => remove_policy(&project),
            _ => unreachable!(),
        }
        release.wait();
        let context = operation.join().unwrap().unwrap();
        let current = crate::findings::policy::load_policy(&project).unwrap();
        assert_eq!(
            context.policy,
            current.status().clone(),
            "{} must return current policy authority",
            transition.0
        );
    }
}

#[tokio::test]
async fn load_run_returns_one_current_policy_and_review_projection() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let saved = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();

    for transition in [
        ("valid-valid", "valid", "valid"),
        ("valid-missing", "valid", "missing"),
        ("missing-valid", "missing", "valid"),
        ("invalid-valid", "invalid", "valid"),
    ] {
        match transition.1 {
            "valid" => write_valid_policy(&project, "initial authority"),
            "invalid" => {
                std::fs::write(project.join(".oxaudit/policy.json"), b"{ invalid initial }")
                    .unwrap()
            }
            "missing" => remove_policy(&project),
            _ => unreachable!(),
        }
        service.load_run(&saved.run_id).unwrap();
        let canonical = project
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        service.pause_policy_projection_after_read_for_test(
            canonical,
            entered.clone(),
            release.clone(),
        );
        let operation = {
            let service = service.clone();
            let run_id = saved.run_id.clone();
            std::thread::spawn(move || service.load_run(&run_id))
        };
        entered.wait();
        match transition.2 {
            "valid" => write_valid_policy(&project, "current authority"),
            "missing" => remove_policy(&project),
            _ => unreachable!(),
        }
        release.wait();
        let loaded = operation.join().unwrap().unwrap();
        let current = crate::findings::policy::load_policy(&project).unwrap();
        assert_eq!(loaded.policy, current.status().clone(), "{}", transition.0);
        let mut saw_project_policy = false;
        for finding in &loaded.findings {
            if let Some(review) = finding.review.as_ref().filter(|review| {
                review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
            }) {
                saw_project_policy = true;
                let crate::findings::domain::PolicyStatus::Valid { hash } = current.status() else {
                    panic!("{} exposed a stale project-policy closure", transition.0)
                };
                assert_eq!(review.policy_hash.as_deref(), Some(hash.as_str()));
            }
        }
        assert_eq!(
            saw_project_policy,
            matches!(
                current.status(),
                crate::findings::domain::PolicyStatus::Valid { .. }
            ),
            "{} must reconcile the active closure with the returned authority",
            transition.0
        );
    }
}

#[tokio::test]
async fn file_database_scan_survives_restart_and_line_insertion_is_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("app.js"),
        "beforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
    )
    .unwrap();
    let database = directory.path().join("data/findings.sqlite3");
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let events = RecordingEvents::default();
    let cancel = AtomicBool::new(false);
    let cve = cached_cve_state();

    let first = {
        let service = FindingsService::new(
            crate::findings::repository::FindingsRepository::open(&database).unwrap(),
        );
        service
            .scan(options.clone(), &cve, &cancel, &events)
            .await
            .unwrap()
    };
    assert_eq!(first.status, RunStatus::Completed);
    assert_eq!(first.persistence, RunPersistence::Saved);
    assert_eq!(first.findings.len(), 1);

    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open(&database).unwrap(),
    );
    let restarted = service.load_run(&first.run_id).unwrap();
    assert_eq!(restarted.run_id, first.run_id);
    std::fs::write(
            project.join("app.js"),
            "inserted();\ninsertedAgain();\nbeforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
        )
        .unwrap();
    let second = service.scan(options, &cve, &cancel, &events).await.unwrap();
    assert_eq!(
        second.baseline_run_id.as_deref(),
        Some(first.run_id.as_str())
    );
    assert_eq!(second.findings[0].diff_status, Some(DiffStatus::Unchanged));
    let names = events.0.lock().unwrap();
    assert!(names.iter().any(|name| name == "scan://progress"));
    assert!(names.iter().any(|name| name == "scan://done"));
}

#[tokio::test]
async fn file_database_survives_restart_and_contains_no_secret_canary() {
    let directory = tempfile::tempdir().unwrap();
    let app_data = directory.path().join("app-data");
    std::fs::create_dir(&app_data).unwrap();
    let database = crate::findings::database_path(&app_data);
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();

    let raw_canary = format!("ghp_OxAuditRestartCanary{}", "7".repeat(16));
    assert_eq!(raw_canary.len(), 40);
    std::fs::write(
        project.join("credentials.js"),
        format!("const token = '{raw_canary}';\n"),
    )
    .unwrap();

    let saved = {
        let service = FindingsService::new(
            crate::findings::repository::FindingsRepository::open(&database).unwrap(),
        );
        service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: true,
                    scan_vulnerabilities: false,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap()
    };
    let sanitized = saved
        .findings
        .iter()
        .find(|finding| finding.rule_id == "github-token")
        .expect("scan must retain the sanitized canary finding");
    assert!(!sanitized.fingerprint.is_empty());
    assert!(sanitized
        .match_text
        .contains(crate::findings::redaction::REDACTED));
    assert!(!serde_json::to_string(&saved).unwrap().contains(&raw_canary));
    let fingerprint = sanitized.fingerprint.clone();

    let restarted = {
        let service = FindingsService::new(
            crate::findings::repository::FindingsRepository::open(&database).unwrap(),
        );
        service.load_run(&saved.run_id).unwrap()
    };
    let restarted_finding = restarted
        .findings
        .iter()
        .find(|finding| finding.rule_id == "github-token")
        .expect("restart must load the sanitized canary finding");
    assert_eq!(restarted_finding.fingerprint, fingerprint);
    assert!(restarted_finding
        .match_text
        .contains(crate::findings::redaction::REDACTED));
    assert!(!serde_json::to_string(&restarted)
        .unwrap()
        .contains(&raw_canary));

    let connection = rusqlite::Connection::open(&database).unwrap();
    let schema_tables = {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap()
    };
    let required_tables = [
        "schema_migrations",
        "projects",
        "scan_runs",
        "findings",
        "reviews",
    ];
    for table in required_tables {
        assert!(
            schema_tables.contains(table),
            "missing logical table {table}"
        );
    }

    let mut searched_columns = 0usize;
    for table in required_tables {
        let columns = {
            let pragma = format!("PRAGMA table_info(\"{table}\")");
            let mut statement = connection.prepare(&pragma).unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        for column in columns {
            assert!(column
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let query = format!(
                    "SELECT COUNT(*) FROM \"{table}\" WHERE CAST(\"{column}\" AS TEXT) LIKE '%' || ?1 || '%'"
                );
            let leaked: i64 = connection
                .query_row(&query, [raw_canary.as_str()], |row| row.get(0))
                .unwrap();
            assert_eq!(
                leaked, 0,
                "raw canary reached durable column {table}.{column}"
            );
            searched_columns += 1;
        }
    }
    assert!(
        searched_columns > 0,
        "schema inspection must search columns"
    );
}

#[tokio::test]
async fn normal_scan_returns_post_retention_projection_that_matches_restart() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let database = directory.path().join("data/findings.sqlite3");
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let saved = {
        let service = FindingsService::new(
            crate::findings::repository::FindingsRepository::open(&database).unwrap(),
        );
        let baseline = seed_aged_baseline(&service, &project);
        let saved = service
            .scan(
                options.clone(),
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .repository
                .load_run(&baseline.run_id)
                .unwrap_err()
                .code,
            crate::findings::error::ErrorCode::NotFound
        );
        assert_eq!(saved.baseline_run_id, None);
        assert_eq!(saved.findings.len(), 1);
        assert_eq!(saved.findings[0].diff_status, Some(DiffStatus::New));
        saved
    };
    let restarted = FindingsService::new(
        crate::findings::repository::FindingsRepository::open(&database).unwrap(),
    );
    assert_eq!(
        serde_json::to_value(&saved).unwrap(),
        serde_json::to_value(restarted.load_run(&saved.run_id).unwrap()).unwrap()
    );
}

#[tokio::test]
async fn retry_returns_post_retention_projection_that_matches_restart() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let database = directory.path().join("data/findings.sqlite3");
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let saved = {
        let service = FindingsService::new(
            crate::findings::repository::FindingsRepository::open(&database).unwrap(),
        );
        let baseline = seed_aged_baseline(&service, &project);
        service.fail_next_completions_for_test(1);
        let pending = service
            .scan(
                options,
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        let RunPersistence::NotSaved { retry_token } = pending.persistence else {
            panic!("injected failure must retain a retry token")
        };
        assert_eq!(
            pending.baseline_run_id.as_deref(),
            Some(baseline.run_id.as_str())
        );
        let saved = service.retry_save(&retry_token).unwrap();
        assert_eq!(
            service
                .repository
                .load_run(&baseline.run_id)
                .unwrap_err()
                .code,
            crate::findings::error::ErrorCode::NotFound
        );
        assert_eq!(saved.baseline_run_id, None);
        assert_eq!(saved.findings.len(), 1);
        assert_eq!(saved.findings[0].diff_status, Some(DiffStatus::New));
        saved
    };
    let restarted = FindingsService::new(
        crate::findings::repository::FindingsRepository::open(&database).unwrap(),
    );
    assert_eq!(
        serde_json::to_value(&saved).unwrap(),
        serde_json::to_value(restarted.load_run(&saved.run_id).unwrap()).unwrap()
    );
}

#[tokio::test]
async fn failed_completion_is_bounded_and_retry_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("data/findings.sqlite3");
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open(&database).unwrap(),
    );
    service.fail_next_completions_for_test(4);
    let cve = cached_cve_state();
    let cancel = AtomicBool::new(false);
    let events = RecordingEvents::default();
    let mut tokens = Vec::new();
    let mut run_ids = Vec::new();
    let mut newest_run = String::new();
    for index in 0..4 {
        let project = directory.path().join(format!("project-{index}"));
        std::fs::create_dir(&project).unwrap();
        let source = if index == 3 {
            "const token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';\n"
        } else {
            "eval(input);\n"
        };
        std::fs::write(project.join("app.js"), source).unwrap();
        let detail = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: index == 3,
                    scan_vulnerabilities: index != 3,
                    ..ScanOptions::default()
                },
                &cve,
                &cancel,
                &events,
            )
            .await
            .unwrap();
        newest_run = detail.run_id.clone();
        run_ids.push(detail.run_id.clone());
        let RunPersistence::NotSaved { ref retry_token } = detail.persistence else {
            panic!("completion failure must remain retryable")
        };
        let serialized = serde_json::to_string(&detail).unwrap();
        assert!(!serialized.contains("oxaudit-secret-canary-7D4zP9q2"));
        tokens.push(retry_token.clone());
    }
    let pending_json = service
        .pending_saves
        .lock()
        .unwrap()
        .iter()
        .map(|pending| serde_json::to_string(&pending.result).unwrap())
        .collect::<String>();
    assert!(!pending_json.contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));

    assert_eq!(
        service.retry_save(&tokens[0]).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
    assert_eq!(
        service.repository.load_run(&run_ids[0]).unwrap().status,
        RunStatus::Incomplete
    );
    let stored = service.retry_save(tokens.last().unwrap()).unwrap();
    assert_eq!(stored.run_id, newest_run);
    assert_eq!(stored.persistence, RunPersistence::Saved);
    assert_eq!(
        service.retry_save(tokens.last().unwrap()).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
    assert_eq!(
        service.repository.load_run(&newest_run).unwrap().run_id,
        newest_run
    );
}

#[tokio::test]
async fn failed_eviction_terminalization_keeps_old_token_and_declines_new_pending() {
    let directory = tempfile::tempdir().unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.fail_next_completions_for_test(3);
    let mut tokens = Vec::new();
    let mut run_ids = Vec::new();
    for index in 0..3 {
        let project = directory.path().join(format!("project-{index}"));
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let pending = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: false,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        run_ids.push(pending.run_id.clone());
        let RunPersistence::NotSaved { retry_token } = pending.persistence else {
            panic!("fixture completion must be pending")
        };
        tokens.push(retry_token);
    }

    service.fail_next_mark_incomplete_for_test();
    service.fail_next_completions_for_test(1);
    let fourth_project = directory.path().join("project-3");
    std::fs::create_dir(&fourth_project).unwrap();
    std::fs::write(fourth_project.join("app.js"), "eval(input);\n").unwrap();
    let error = service
        .scan(
            ScanOptions {
                path: fourth_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .expect_err("a new token cannot be offered when eviction did not terminalize");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let queued_tokens = service
        .pending_saves
        .lock()
        .unwrap()
        .iter()
        .map(|pending| pending.retry_token.clone())
        .collect::<Vec<_>>();
    assert_eq!(queued_tokens, tokens);
    assert_eq!(
        service.repository.load_run(&run_ids[0]).unwrap().status,
        RunStatus::Running
    );
    let declined_run = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        service.repository.load_run(&declined_run).unwrap().status,
        RunStatus::Incomplete
    );

    let recovered = service.retry_save(&tokens[0]).unwrap();
    assert_eq!(recovered.run_id, run_ids[0]);
    assert_eq!(recovered.persistence, RunPersistence::Saved);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_eviction_candidate_cannot_be_retried_before_token_transition() {
    let directory = tempfile::tempdir().unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    service.fail_next_completions_for_test(3);
    let mut tokens = Vec::new();
    let mut run_ids = Vec::new();
    for index in 0..3 {
        let project = directory.path().join(format!("project-{index}"));
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let pending = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: false,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        run_ids.push(pending.run_id.clone());
        let RunPersistence::NotSaved { retry_token } = pending.persistence else {
            panic!("fixture completion must be pending")
        };
        tokens.push(retry_token);
    }

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_pending_eviction_after_reservation_for_test(
        tokens[0].clone(),
        entered.clone(),
        release.clone(),
    );
    service.fail_next_completions_for_test(1);
    let fourth_project = directory.path().join("project-3");
    std::fs::create_dir(&fourth_project).unwrap();
    std::fs::write(fourth_project.join("app.js"), "eval(input);\n").unwrap();
    let scan = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .scan(
                    ScanOptions {
                        path: fourth_project.to_string_lossy().into_owned(),
                        scan_secrets: false,
                        ..ScanOptions::default()
                    },
                    &cached_cve_state(),
                    &AtomicBool::new(false),
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();

    assert_eq!(
        service.retry_save(&tokens[0]).unwrap_err().code,
        crate::findings::error::ErrorCode::ScanAlreadyRunning
    );
    assert_eq!(
        service.repository.load_run(&run_ids[0]).unwrap().status,
        RunStatus::Running
    );
    release.wait();

    let fourth = scan.await.unwrap().unwrap();
    let RunPersistence::NotSaved { retry_token } = fourth.persistence else {
        panic!("successful terminal transition must transfer retry ownership")
    };
    assert_eq!(
        service.repository.load_run(&run_ids[0]).unwrap().status,
        RunStatus::Incomplete
    );
    assert!(service
        .pending_saves
        .lock()
        .unwrap()
        .iter()
        .any(|pending| pending.retry_token == retry_token && pending.run_id == fourth.run_id));
    assert_eq!(
        service.retry_save(&retry_token).unwrap().run_id,
        fourth.run_id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_retry_is_reserved_from_fourth_pending_eviction() {
    let directory = tempfile::tempdir().unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    service.fail_next_completions_for_test(3);
    let mut tokens = Vec::new();
    let mut run_ids = Vec::new();
    for index in 0..3 {
        let project = directory.path().join(format!("project-{index}"));
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let pending = service
            .scan(
                ScanOptions {
                    path: project.to_string_lossy().into_owned(),
                    scan_secrets: false,
                    ..ScanOptions::default()
                },
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        run_ids.push(pending.run_id.clone());
        let RunPersistence::NotSaved { retry_token } = pending.persistence else {
            panic!("fixture completion must be pending")
        };
        tokens.push(retry_token);
    }

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_reserved_retry_for_test(tokens[0].clone(), entered.clone(), release.clone());
    let retry = {
        let service = service.clone();
        let token = tokens[0].clone();
        std::thread::spawn(move || service.retry_save(&token))
    };
    entered.wait();

    service.fail_next_completions_for_test(1);
    let fourth_project = directory.path().join("project-3");
    std::fs::create_dir(&fourth_project).unwrap();
    std::fs::write(fourth_project.join("app.js"), "eval(input);\n").unwrap();
    let fourth = service
        .scan(
            ScanOptions {
                path: fourth_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fourth.persistence,
        RunPersistence::NotSaved { .. }
    ));
    {
        let queue = service.pending_saves.lock().unwrap();
        assert_eq!(queue.len(), 3);
        assert!(queue.iter().any(|pending| pending.retry_token == tokens[0]));
        assert!(!queue.iter().any(|pending| pending.retry_token == tokens[1]));
    }
    assert_eq!(
        service.repository.load_run(&run_ids[1]).unwrap().status,
        RunStatus::Incomplete
    );

    release.wait();
    let saved = retry.join().unwrap().unwrap();
    assert_eq!(saved.run_id, run_ids[0]);
    assert_eq!(saved.persistence, RunPersistence::Saved);
    assert_eq!(
        service.retry_save(&tokens[0]).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_guard_rejects_only_duplicates_and_clears_on_every_terminal_path() {
    let directory = tempfile::tempdir().unwrap();
    let first_project = directory.path().join("first");
    let other_project = directory.path().join("other");
    for project in [&first_project, &other_project] {
        std::fs::create_dir(project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    }
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let cve = Arc::new(cached_cve_state());
    let events = Arc::new(RecordingEvents::default());
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let first_path = first_project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    service.pause_next_scan_for_test(first_path.clone(), entered.clone(), release.clone());
    let first_options = ScanOptions {
        path: first_path.clone(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let first_task = {
        let service = service.clone();
        let cve = cve.clone();
        let events = events.clone();
        let options = first_options.clone();
        tokio::spawn(async move {
            service
                .scan(options, &cve, &AtomicBool::new(false), &*events)
                .await
        })
    };
    entered.wait();
    let duplicate = service
        .scan(
            first_options.clone(),
            &cve,
            &AtomicBool::new(false),
            &*events,
        )
        .await
        .unwrap_err();
    assert_eq!(
        duplicate.code,
        crate::findings::error::ErrorCode::ScanAlreadyRunning
    );
    let unrelated = service
        .scan(
            ScanOptions {
                path: other_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cve,
            &AtomicBool::new(false),
            &*events,
        )
        .await
        .unwrap();
    assert_eq!(unrelated.status, RunStatus::Completed);
    release.wait();
    first_task.await.unwrap().unwrap();
    service
        .scan(
            first_options.clone(),
            &cve,
            &AtomicBool::new(false),
            &*events,
        )
        .await
        .unwrap();

    service.fail_next_scanner_for_test(first_path);
    let failure = service
        .scan(
            first_options.clone(),
            &cve,
            &AtomicBool::new(false),
            &*events,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.code, crate::findings::error::ErrorCode::ScanFailed);
    let failed_run_id = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        service.repository.load_run(&failed_run_id).unwrap().status,
        RunStatus::Incomplete
    );
    service
        .scan(first_options, &cve, &AtomicBool::new(false), &*events)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_marks_incomplete_and_event_delivery_is_best_effort() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("app.js"),
        "beforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
    )
    .unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let cve = Arc::new(cached_cve_state());
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let options = ScanOptions {
        path: canonical.clone(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_next_scan_for_test(canonical, entered.clone(), release.clone());
    let cancel = Arc::new(AtomicBool::new(false));
    let task = {
        let service = service.clone();
        let cve = cve.clone();
        let cancel = cancel.clone();
        let options = options.clone();
        tokio::spawn(async move {
            service
                .scan(options, &cve, &cancel, &RecordingEvents::default())
                .await
        })
    };
    entered.wait();
    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    release.wait();
    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::ScanCancelled);
    let run_id = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        service.repository.load_run(&run_id).unwrap().status,
        RunStatus::Incomplete
    );

    let completed = service
        .scan(options, &cve, &AtomicBool::new(false), &FailingEvents)
        .await
        .unwrap();
    assert_eq!(completed.status, RunStatus::Completed);
}

#[tokio::test]
async fn post_start_policy_failure_marks_exact_run_incomplete_without_masking_primary() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let mut scanned = crate::scanners::scan_file_with_relative_path(
        &project.join("app.js"),
        "app.js",
        1024,
        false,
        true,
    )
    .findings;
    crate::findings::fingerprint::assign_fingerprints(&mut scanned);
    let fingerprint = scanned[0].fingerprint.clone();
    std::fs::write(
        project.join(".oxaudit/policy.json"),
        serde_json::json!({
            "version": 1,
            "entries": [{
                "kind": "finding",
                "fingerprintVersion": crate::findings::domain::FINGERPRINT_VERSION,
                "fingerprint": &fingerprint,
                "category": "secret",
                "state": "suppressed",
                "reason": "valid entry with the wrong authoritative category"
            }]
        })
        .to_string(),
    )
    .unwrap();

    let error = service
        .scan(
            options.clone(),
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
    let failed_run = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        service.repository.load_run(&failed_run).unwrap().status,
        RunStatus::Incomplete
    );

    service.fail_next_mark_incomplete_for_test();
    let error = service
        .scan(
            options,
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::PolicyInvalid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_immediately_before_completion_never_commits_observations() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_before_completion_for_test(canonical.clone(), entered.clone(), release.clone());
    let cancel = Arc::new(AtomicBool::new(false));
    let task = {
        let service = service.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            service
                .scan(
                    ScanOptions {
                        path: canonical,
                        scan_secrets: false,
                        ..ScanOptions::default()
                    },
                    &cached_cve_state(),
                    &cancel,
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();
    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    release.wait();

    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error.code, crate::findings::error::ErrorCode::ScanCancelled);
    let run_id = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let stored = service.repository.load_run(&run_id).unwrap();
    assert_eq!(stored.status, RunStatus::Incomplete);
    assert!(stored.findings.is_empty());
}

#[tokio::test]
async fn unsaved_projection_has_advisory_baseline_and_authoritative_policy_review() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(
        project.join("app.js"),
        "beforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
    )
    .unwrap();
    std::fs::write(
            project.join(".oxaudit/policy.json"),
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let cve = cached_cve_state();
    let events = RecordingEvents::default();
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let first = service
        .scan(options.clone(), &cve, &AtomicBool::new(false), &events)
        .await
        .unwrap();
    assert_eq!(
        first.findings[0].review.as_ref().map(|review| review.state),
        Some(crate::findings::domain::ReviewState::Suppressed)
    );
    assert!(first.findings[0]
        .review_history
        .iter()
        .any(|review| { review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy }));

    std::fs::write(
            project.join("app.js"),
            "inserted();\ninsertedAgain();\nbeforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
        )
        .unwrap();
    service.fail_next_completions_for_test(1);
    let pending = service
        .scan(options, &cve, &AtomicBool::new(false), &events)
        .await
        .unwrap();
    assert!(matches!(
        pending.persistence,
        RunPersistence::NotSaved { .. }
    ));
    assert_eq!(
        pending.baseline_run_id.as_deref(),
        Some(first.run_id.as_str())
    );
    assert_eq!(pending.findings[0].diff_status, Some(DiffStatus::Unchanged));
    assert_eq!(
        pending.findings[0]
            .review
            .as_ref()
            .map(|review| review.state),
        Some(crate::findings::domain::ReviewState::Suppressed)
    );
}

#[tokio::test]
async fn invalid_policy_blocks_or_is_ignored_without_overwrite_or_stale_closure() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy_path = project.join(".oxaudit/policy.json");
    std::fs::write(
            &policy_path,
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let cve = cached_cve_state();
    let events = RecordingEvents::default();
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let first = service
        .scan(options.clone(), &cve, &AtomicBool::new(false), &events)
        .await
        .unwrap();
    let finding = first
        .findings
        .iter()
        .find(|finding| finding.observation_run_id == first.run_id)
        .unwrap();
    service
        .save_review(
            &crate::findings::domain::ReviewRequest {
                project_id: first.project_id.clone(),
                fingerprint_version: finding.fingerprint_version,
                fingerprint: finding.fingerprint.clone(),
                category: "vulnerability".into(),
                state: crate::findings::domain::ReviewState::AcceptedRisk,
                reason: "accepted until the parser is replaced".into(),
                evidence: None,
                entry_point: None,
                data_flow: None,
                gates: Vec::new(),
                deciding_gate: None,
                expires_at: None,
                origin: crate::findings::domain::ReviewOrigin::Local,
            },
            chrono::Utc::now(),
        )
        .unwrap();

    let invalid_bytes = b"{ this policy is invalid and must survive }";
    std::fs::write(&policy_path, invalid_bytes).unwrap();
    let blocked = service
        .scan(options.clone(), &cve, &AtomicBool::new(false), &events)
        .await
        .unwrap_err();
    assert_eq!(
        blocked.code,
        crate::findings::error::ErrorCode::PolicyInvalid
    );
    assert_eq!(std::fs::read(&policy_path).unwrap(), invalid_bytes);

    let mut override_options = options;
    override_options.ignore_invalid_policy = true;
    let overridden = service
        .scan(override_options, &cve, &AtomicBool::new(false), &events)
        .await
        .unwrap();
    let current = overridden
        .findings
        .iter()
        .find(|finding| finding.observation_run_id == overridden.run_id)
        .unwrap();
    assert_eq!(
        current.review.as_ref().map(|review| review.origin),
        Some(crate::findings::domain::ReviewOrigin::Local)
    );
    assert!(current
        .review_history
        .iter()
        .any(|review| review.origin == crate::findings::domain::ReviewOrigin::Local));
    assert!(current
        .review_history
        .iter()
        .any(|review| { review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy }));
    assert_eq!(std::fs::read(&policy_path).unwrap(), invalid_bytes);
    assert!(matches!(
        overridden.policy,
        crate::findings::domain::PolicyStatus::Invalid { .. }
    ));
}

#[tokio::test]
async fn retry_recovers_when_completion_committed_before_the_error_was_observed() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.fail_after_next_committed_completion_for_test();
    let pending = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let RunPersistence::NotSaved { retry_token } = pending.persistence else {
        panic!("lost acknowledgement must be retryable")
    };
    assert_eq!(
        service.repository.load_run(&pending.run_id).unwrap().status,
        RunStatus::Completed
    );
    let retried = service.retry_save(&retry_token).unwrap();
    assert_eq!(retried.run_id, pending.run_id);
    assert_eq!(
        service.retry_save(&retry_token).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[tokio::test]
async fn missing_attempt_at_completion_is_terminal_and_never_offers_retry() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.delete_next_attempt_before_completion_for_test();

    let error = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, crate::findings::error::ErrorCode::NotFound);
    assert!(service.pending_saves.lock().unwrap().is_empty());
    let run_id = service
        .started_run_ids
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        service.repository.load_run(&run_id).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[tokio::test]
async fn post_maintenance_reload_failure_is_pending_and_retry_keeps_token() {
    let directory = tempfile::tempdir().unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let normal_project = directory.path().join("normal");
    std::fs::create_dir(&normal_project).unwrap();
    std::fs::write(normal_project.join("app.js"), "eval(input);\n").unwrap();
    service.fail_next_post_maintenance_reload_for_test();
    let pending = service
        .scan(
            ScanOptions {
                path: normal_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let RunPersistence::NotSaved { retry_token } = pending.persistence else {
        panic!("lost post-maintenance reload acknowledgement must be retryable")
    };
    assert_eq!(
        service.repository.load_run(&pending.run_id).unwrap().status,
        RunStatus::Completed
    );
    assert_eq!(
        service.retry_save(&retry_token).unwrap().run_id,
        pending.run_id
    );

    let retry_project = directory.path().join("retry");
    std::fs::create_dir(&retry_project).unwrap();
    std::fs::write(retry_project.join("app.js"), "eval(input);\n").unwrap();
    service.fail_next_completions_for_test(1);
    let pending = service
        .scan(
            ScanOptions {
                path: retry_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let RunPersistence::NotSaved { retry_token } = pending.persistence else {
        panic!("injected completion failure must be retryable")
    };
    service.fail_next_post_maintenance_reload_for_test();
    let error = service.retry_save(&retry_token).unwrap_err();
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(
        service.repository.load_run(&pending.run_id).unwrap().status,
        RunStatus::Completed
    );
    assert_eq!(
        service.retry_save(&retry_token).unwrap().run_id,
        pending.run_id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_is_reset_only_when_the_service_was_idle() {
    let directory = tempfile::tempdir().unwrap();
    let first_project = directory.path().join("first");
    let second_project = directory.path().join("second");
    for project in [&first_project, &second_project] {
        std::fs::create_dir(project).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    }
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let cve = Arc::new(cached_cve_state());
    let events = Arc::new(RecordingEvents::default());
    let cancel = Arc::new(AtomicBool::new(true));
    service
        .scan(
            ScanOptions {
                path: first_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cve,
            &cancel,
            &*events,
        )
        .await
        .unwrap();

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let first_path = first_project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    service.pause_next_scan_for_test(first_path.clone(), entered.clone(), release.clone());
    let active = {
        let service = service.clone();
        let cve = cve.clone();
        let events = events.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            service
                .scan(
                    ScanOptions {
                        path: first_path,
                        scan_secrets: false,
                        ..ScanOptions::default()
                    },
                    &cve,
                    &cancel,
                    &*events,
                )
                .await
        })
    };
    entered.wait();
    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    let later = service
        .scan(
            ScanOptions {
                path: second_project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cve,
            &cancel,
            &*events,
        )
        .await
        .unwrap_err();
    assert_eq!(later.code, crate::findings::error::ErrorCode::ScanCancelled);
    assert!(cancel.load(std::sync::atomic::Ordering::SeqCst));
    release.wait();
    assert_eq!(
        active.await.unwrap().unwrap_err().code,
        crate::findings::error::ErrorCode::ScanCancelled
    );
}

#[tokio::test]
async fn post_completion_policy_refresh_failure_still_returns_saved_and_load_heals() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    std::fs::write(
            project.join(".oxaudit/policy.json"),
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.fail_next_post_completion_policy_refresh_for_test();
    let saved = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    assert_eq!(saved.persistence, RunPersistence::Saved);
    assert!(saved.maintenance_warning.is_some());
    assert!(saved
        .findings
        .iter()
        .all(|finding| finding.review.is_none()));

    let healed = service.load_run(&saved.run_id).unwrap();
    assert_eq!(
        healed.findings[0]
            .review
            .as_ref()
            .map(|review| review.state),
        Some(crate::findings::domain::ReviewState::Suppressed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_scan_reports_policy_removed_during_completion() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy_path = project.join(".oxaudit/policy.json");
    std::fs::write(
            &policy_path,
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_before_completion_for_test(canonical.clone(), entered.clone(), release.clone());
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .scan(
                    ScanOptions {
                        path: canonical,
                        scan_secrets: false,
                        ..ScanOptions::default()
                    },
                    &cached_cve_state(),
                    &AtomicBool::new(false),
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();
    std::fs::remove_file(&policy_path).unwrap();
    release.wait();
    let saved = task.await.unwrap().unwrap();
    assert_eq!(saved.policy, crate::findings::domain::PolicyStatus::Missing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_scan_reports_invalid_current_policy_and_keeps_audit_history_inactive() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy_path = project.join(".oxaudit/policy.json");
    std::fs::write(
            &policy_path,
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    service
        .scan(
            options.clone(),
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_before_completion_for_test(canonical, entered.clone(), release.clone());
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .scan(
                    options,
                    &cached_cve_state(),
                    &AtomicBool::new(false),
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();
    let invalid_bytes = b"{ invalid policy bytes must remain exact }";
    std::fs::write(&policy_path, invalid_bytes).unwrap();
    release.wait();
    let saved = task.await.unwrap().unwrap();
    assert!(matches!(
        saved.policy,
        crate::findings::domain::PolicyStatus::Invalid { .. }
    ));
    assert_eq!(std::fs::read(&policy_path).unwrap(), invalid_bytes);
    let current = saved
        .findings
        .iter()
        .find(|finding| finding.observation_run_id == saved.run_id)
        .unwrap();
    assert_ne!(
        current.review.as_ref().map(|review| review.origin),
        Some(crate::findings::domain::ReviewOrigin::ProjectPolicy)
    );
    assert!(current
        .review_history
        .iter()
        .any(|review| { review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_mutation_during_refresh_returns_current_status_conservatively() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy_path = project.join(".oxaudit/policy.json");
    std::fs::write(
            &policy_path,
            r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
        )
        .unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let options = ScanOptions {
        path: project.to_string_lossy().into_owned(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    service
        .scan(
            options.clone(),
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_policy_refresh_after_load_for_test(canonical, entered.clone(), release.clone());
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .scan(
                    options,
                    &cached_cve_state(),
                    &AtomicBool::new(false),
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();
    std::fs::write(&policy_path, b"{ invalid concurrent policy }").unwrap();
    release.wait();
    let saved = task.await.unwrap().unwrap();
    assert!(matches!(
        saved.policy,
        crate::findings::domain::PolicyStatus::Invalid { .. }
    ));
    assert_eq!(
        saved.maintenance_warning.as_deref(),
        Some(POLICY_REFRESH_WARNING)
    );
    let current = saved
        .findings
        .iter()
        .find(|finding| finding.observation_run_id == saved.run_id)
        .unwrap();
    assert_ne!(
        current.review.as_ref().map(|review| review.origin),
        Some(crate::findings::domain::ReviewOrigin::ProjectPolicy)
    );
    assert!(current
        .review_history
        .iter()
        .any(|review| { review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_to_valid_mutation_during_saved_refresh_is_current_and_conservative() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy_path = project.join(".oxaudit/policy.json");
    std::fs::write(&policy_path, b"{ invalid initial policy }").unwrap();
    let service = Arc::new(FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    ));
    let canonical = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    service.pause_policy_refresh_after_load_for_test(
        canonical.clone(),
        entered.clone(),
        release.clone(),
    );
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .scan(
                    ScanOptions {
                        path: canonical,
                        scan_secrets: false,
                        ignore_invalid_policy: true,
                        ..ScanOptions::default()
                    },
                    &cached_cve_state(),
                    &AtomicBool::new(false),
                    &RecordingEvents::default(),
                )
                .await
        })
    };
    entered.wait();
    write_valid_policy(&project, "current valid authority");
    release.wait();

    let saved = task.await.unwrap().unwrap();
    let current = crate::findings::policy::load_policy(&project).unwrap();
    assert_eq!(saved.persistence, RunPersistence::Saved);
    assert_eq!(saved.policy, current.status().clone());
    assert_eq!(
        saved.maintenance_warning.as_deref(),
        Some(POLICY_REFRESH_WARNING)
    );
    assert!(saved.findings.iter().all(|finding| {
        finding.review.as_ref().is_none_or(|review| {
            review.origin != crate::findings::domain::ReviewOrigin::ProjectPolicy
        })
    }));

    let healed = service.load_run(&saved.run_id).unwrap();
    let crate::findings::domain::PolicyStatus::Valid { hash } = current.status() else {
        panic!("fixture must now be valid")
    };
    assert!(healed.findings.iter().any(|finding| {
        finding.review.as_ref().is_some_and(|review| {
            review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
                && review.policy_hash.as_deref() == Some(hash.as_str())
        })
    }));
}

#[tokio::test]
async fn retry_reports_current_missing_or_invalid_policy_without_losing_history() {
    let directory = tempfile::tempdir().unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    for transition in ["missing", "invalid"] {
        let project = directory.path().join(transition);
        std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
        std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
        let policy_path = project.join(".oxaudit/policy.json");
        std::fs::write(
                &policy_path,
                r#"{"version":1,"entries":[{"kind":"suppression","ruleId":"js-eval","pathPattern":"app.js","state":"suppressed","reason":"approved local fixture"}]}"#,
            )
            .unwrap();
        let options = ScanOptions {
            path: project.to_string_lossy().into_owned(),
            scan_secrets: false,
            ..ScanOptions::default()
        };
        service
            .scan(
                options.clone(),
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        service.fail_next_completions_for_test(1);
        let pending = service
            .scan(
                options,
                &cached_cve_state(),
                &AtomicBool::new(false),
                &RecordingEvents::default(),
            )
            .await
            .unwrap();
        let RunPersistence::NotSaved { retry_token } = pending.persistence else {
            panic!("injected failure must retain a retry token")
        };
        if transition == "missing" {
            std::fs::remove_file(&policy_path).unwrap();
        } else {
            std::fs::write(&policy_path, b"{ invalid current policy }").unwrap();
        }
        let saved = service.retry_save(&retry_token).unwrap();
        if transition == "missing" {
            assert_eq!(saved.policy, crate::findings::domain::PolicyStatus::Missing);
        } else {
            assert!(matches!(
                saved.policy,
                crate::findings::domain::PolicyStatus::Invalid { .. }
            ));
            let current = saved
                .findings
                .iter()
                .find(|finding| finding.observation_run_id == saved.run_id)
                .unwrap();
            assert_ne!(
                current.review.as_ref().map(|review| review.origin),
                Some(crate::findings::domain::ReviewOrigin::ProjectPolicy)
            );
            assert!(current.review_history.iter().any(|review| {
                review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
            }));
        }
    }
}

#[tokio::test]
async fn committed_retry_keeps_token_until_policy_refresh_heals() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.fail_next_completions_for_test(1);
    let pending = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let RunPersistence::NotSaved { retry_token } = pending.persistence else {
        panic!("injected failure must retain a retry token")
    };
    service.fail_next_post_completion_policy_refresh_for_test();
    let error = service.retry_save(&retry_token).unwrap_err();
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PolicyWriteFailed
    );
    assert_eq!(
        service.repository.load_run(&pending.run_id).unwrap().status,
        RunStatus::Completed
    );
    let healed = service.retry_save(&retry_token).unwrap();
    assert_eq!(healed.run_id, pending.run_id);
    assert_eq!(
        service.retry_save(&retry_token).unwrap_err().code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[tokio::test]
async fn retention_and_policy_refresh_warnings_merge_in_fixed_order() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    service.fail_next_retention_maintenance_for_test();
    service.fail_next_post_completion_policy_refresh_for_test();
    let saved = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let expected = format!("{RETENTION_WARNING}\n{POLICY_REFRESH_WARNING}");
    assert_eq!(
        saved.maintenance_warning.as_deref(),
        Some(expected.as_str())
    );
}

/// A scanned project with several findings, for the bulk-review tests.
async fn scanned_project_with_findings() -> (
    tempfile::TempDir,
    FindingsService,
    crate::findings::domain::ScanRunDetail,
) {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path();
    std::fs::write(project.join("a.js"), "const a = eval(x);\n").unwrap();
    std::fs::write(project.join("b.js"), "const b = eval(y);\n").unwrap();
    std::fs::write(project.join("c.js"), "document.write(z);\n").unwrap();

    let service = FindingsService::new(
        crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
    );
    let detail = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into_owned(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    (directory, service, detail)
}

fn dismissal(
    project_id: &str,
    finding: &crate::models::Finding,
) -> crate::findings::domain::ReviewRequest {
    crate::findings::domain::ReviewRequest {
        project_id: project_id.to_owned(),
        fingerprint_version: finding.fingerprint_version,
        fingerprint: finding.fingerprint.clone(),
        category: finding.category.clone(),
        state: crate::findings::domain::ReviewState::AcceptedRisk,
        reason: "Reviewed as a class during triage; tracked in SEC-441.".into(),
        evidence: None,
        entry_point: None,
        data_flow: None,
        gates: Vec::new(),
        deciding_gate: None,
        expires_at: None,
        origin: crate::findings::domain::ReviewOrigin::Local,
    }
}

#[tokio::test]
async fn a_bulk_review_records_every_decision() {
    let (_directory, service, detail) = scanned_project_with_findings().await;
    assert!(
        detail.findings.len() >= 3,
        "fixture should produce findings"
    );

    let requests: Vec<_> = detail
        .findings
        .iter()
        .map(|finding| dismissal(&detail.project_id, finding))
        .collect();

    let outcome = service.save_reviews(&requests, chrono::Utc::now());
    assert_eq!(outcome.recorded.len(), requests.len());
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);

    // The decisions have to survive as history, not just be reported back.
    let reloaded = service.load_run(&detail.run_id).unwrap();
    for finding in &reloaded.findings {
        assert_eq!(
            finding.review.as_ref().map(|review| review.state),
            Some(crate::findings::domain::ReviewState::AcceptedRisk),
            "{} was not recorded",
            finding.file_path
        );
    }
}

#[tokio::test]
async fn a_bulk_review_reports_each_failure_instead_of_swallowing_it() {
    let (_directory, service, detail) = scanned_project_with_findings().await;

    let mut requests: Vec<_> = detail
        .findings
        .iter()
        .take(2)
        .map(|finding| dismissal(&detail.project_id, finding))
        .collect();
    // A fingerprint that belongs to no finding in this project.
    let mut orphan = requests[0].clone();
    orphan.fingerprint = "not-a-real-fingerprint".into();
    requests.push(orphan);

    let outcome = service.save_reviews(&requests, chrono::Utc::now());

    // Partial results are kept and reported. A reviewer who acted on forty
    // findings would rather keep the ones that landed than lose them all
    // because one was stale — but they must be told which did not.
    assert_eq!(outcome.recorded.len(), 2);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].fingerprint, "not-a-real-fingerprint");
    assert!(!outcome.failures[0].message.is_empty());
}

#[tokio::test]
async fn a_bulk_review_appends_rather_than_replacing_history() {
    let (_directory, service, detail) = scanned_project_with_findings().await;
    let finding = &detail.findings[0];

    // Two gate-free states: confirming a vulnerability additionally
    // requires the falsification gates, which is a separate invariant.
    let mut first = dismissal(&detail.project_id, finding);
    first.state = crate::findings::domain::ReviewState::Suppressed;
    first.reason = "Suppressed during the first triage pass.".into();
    service.save_review(&first, chrono::Utc::now()).unwrap();

    let second = dismissal(&detail.project_id, finding);
    let outcome = service.save_reviews(std::slice::from_ref(&second), chrono::Utc::now());
    assert_eq!(outcome.recorded.len(), 1);

    let reloaded = service.load_run(&detail.run_id).unwrap();
    let reviewed = reloaded
        .findings
        .iter()
        .find(|candidate| candidate.fingerprint == finding.fingerprint)
        .unwrap();

    // The latest decision stands, and the earlier one is still on record —
    // a bulk action must not quietly erase a considered judgement.
    assert_eq!(
        reviewed.review.as_ref().map(|review| review.state),
        Some(crate::findings::domain::ReviewState::AcceptedRisk)
    );
    assert!(
        reviewed.review_history.len() >= 2,
        "history was {:?}",
        reviewed.review_history.len()
    );
}

#[tokio::test]
async fn an_empty_bulk_review_does_nothing_rather_than_erroring() {
    let (_directory, service, _detail) = scanned_project_with_findings().await;
    let outcome = service.save_reviews(&[], chrono::Utc::now());
    assert!(outcome.recorded.is_empty());
    assert!(outcome.failures.is_empty());
}

#[tokio::test]
async fn explicit_comparison_is_read_only_and_reports_unscanned_absence() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(super::FindingsRepository::open_in_memory().unwrap());
    let baseline = service
        .scan(
            ScanOptions {
                path: temp.path().to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    std::fs::remove_file(temp.path().join("app.js")).unwrap();
    std::fs::write(temp.path().join("safe.js"), "const safe = true;\n").unwrap();
    let current = service
        .scan(
            ScanOptions {
                path: temp.path().to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let before =
        serde_json::to_value(service.repository.load_run(&current.run_id).unwrap()).unwrap();
    let projection = service
        .compare_runs(&current.run_id, &baseline.run_id)
        .unwrap();
    assert!(
        projection
            .iter()
            .any(|f| f.diff_status == Some(DiffStatus::NotEvaluated)
                && f.resolved_by_run_id.is_none())
    );
    assert_eq!(
        before,
        serde_json::to_value(service.repository.load_run(&current.run_id).unwrap()).unwrap()
    );
    assert!(service
        .compare_runs(&baseline.run_id, &current.run_id)
        .is_err());
    assert!(service
        .compare_runs(&current.run_id, &current.run_id)
        .is_err());
}

#[tokio::test]
async fn source_summary_persists_revision_and_defaults_legacy_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        crate::git_context::tests::git(temp.path(), args);
    };
    git(&["init", "-b", "main"]);
    std::fs::write(temp.path().join("app.js"), "const safe = true;\n").unwrap();
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "initial",
    ]);
    let service = FindingsService::new(super::FindingsRepository::open_in_memory().unwrap());
    let run = service
        .scan(
            ScanOptions {
                path: temp.path().to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let summary =
        serde_json::to_value(&service.repository.load_run(&run.run_id).unwrap().summary).unwrap();
    assert_eq!(summary["gitContext"]["contextChanged"], false);
    assert_eq!(summary["gitContext"]["before"]["branch"], "main");
    let mut legacy = summary;
    legacy.as_object_mut().unwrap().remove("gitContext");
    assert!(serde_json::from_value::<crate::models::ScanSummary>(legacy).is_ok());
}

#[tokio::test]
async fn index_change_during_scan_is_disclosed_in_saved_evidence() {
    struct StageDuringScan {
        root: std::path::PathBuf,
        staged: AtomicBool,
    }
    impl ScanEventSink for StageDuringScan {
        fn emit(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<(), crate::findings::error::CommandError> {
            if !self.staged.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::fs::write(self.root.join("app.js"), "const changed = true;\n").unwrap();
                crate::git_context::tests::git(&self.root, &["add", "app.js"]);
            }
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        crate::git_context::tests::git(temp.path(), args);
    };
    git(&["init", "-b", "main"]);
    std::fs::write(temp.path().join("app.js"), "const safe = true;\n").unwrap();
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "initial",
    ]);
    let service = FindingsService::new(super::FindingsRepository::open_in_memory().unwrap());
    let events = StageDuringScan {
        root: temp.path().to_owned(),
        staged: AtomicBool::new(false),
    };
    let run = service
        .scan(
            ScanOptions {
                path: temp.path().to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &events,
        )
        .await
        .unwrap();
    let evidence = service
        .repository
        .load_run(&run.run_id)
        .unwrap()
        .summary
        .git_context
        .unwrap();
    assert_eq!(evidence.context_changed, Some(true));
    assert_ne!(
        evidence.before.unwrap().index_digest,
        evidence.after.unwrap().index_digest
    );
}

#[tokio::test]
async fn explicit_comparison_uses_current_policy_without_writing_review_events() {
    use crate::findings::domain::{ReviewOrigin, ReviewState};
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    for path in ["app.js", "removed.js"] {
        std::fs::write(project.join(path), "eval(input);\n").unwrap();
    }
    let policy = project.join(".oxaudit/policy.json");
    let write_policy = |state: &str, reason: &str| {
        std::fs::write(&policy, format!(r#"{{"version":1,"entries":[{{"kind":"suppression","ruleId":"js-eval","pathPattern":"*.js","state":"{state}","reason":"{reason}"}}]}}"#)).unwrap()
    };
    write_policy("suppressed", "Initial project policy");
    let database = temp.path().join("data/findings.db");
    let service = FindingsService::new(super::FindingsRepository::open(&database).unwrap());
    let options = ScanOptions {
        path: project.to_string_lossy().into(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    let baseline = service
        .scan(
            options.clone(),
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    std::fs::remove_file(project.join("removed.js")).unwrap();
    let current = service
        .scan(
            options,
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    assert_eq!(current.findings.len(), 2);
    assert!(current
        .findings
        .iter()
        .all(|f| f.review.as_ref().is_some_and(
            |r| r.origin == ReviewOrigin::ProjectPolicy && r.state == ReviewState::Suppressed
        )));
    let observer = rusqlite::Connection::open(&database).unwrap();
    let version = || {
        observer
            .query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    let stored_baseline =
        serde_json::to_value(service.repository.load_run(&baseline.run_id).unwrap()).unwrap();
    let stored_current =
        serde_json::to_value(service.repository.load_run(&current.run_id).unwrap()).unwrap();
    std::fs::write(&policy, "{ invalid policy").unwrap();
    let ordinary = service.load_run(&current.run_id).unwrap();
    assert!(ordinary.findings.iter().all(|f| f.review.is_none()));
    let before = version();
    let compared = service
        .compare_runs(&current.run_id, &baseline.run_id)
        .unwrap();
    assert_eq!(
        version(),
        before,
        "read-only comparison must not write any database row"
    );
    assert!(
        compared.iter().all(|f| f.review.is_none()),
        "invalid persisted policy must not reactivate in explicit comparison"
    );
    assert!(compared
        .iter()
        .any(|f| f.diff_status == Some(DiffStatus::NotEvaluated)));
    write_policy("suppressed", "Updated current policy");
    let before = version();
    let compared = service
        .compare_runs(&current.run_id, &baseline.run_id)
        .unwrap();
    assert_eq!(version(), before);
    assert!(compared
        .iter()
        .all(|f| f.review.as_ref().is_some_and(
            |r| r.state == ReviewState::Suppressed && r.reason == "Updated current policy"
        )));
    std::fs::remove_file(&policy).unwrap();
    let before = version();
    let compared = service
        .compare_runs(&current.run_id, &baseline.run_id)
        .unwrap();
    assert_eq!(version(), before);
    assert!(compared.iter().all(|f| f.review.is_none()));
    assert_eq!(
        stored_baseline,
        serde_json::to_value(service.repository.load_run(&baseline.run_id).unwrap()).unwrap()
    );
    assert_eq!(
        stored_current,
        serde_json::to_value(service.repository.load_run(&current.run_id).unwrap()).unwrap()
    );
    let app = current
        .findings
        .iter()
        .find(|f| f.file_path == "app.js")
        .unwrap();
    service
        .save_review(&dismissal(&current.project_id, app), chrono::Utc::now())
        .unwrap();
    write_policy("suppressed", "Readded project policy");
    let before = version();
    let compared = service
        .compare_runs(&current.run_id, &baseline.run_id)
        .unwrap();
    assert_eq!(version(), before);
    assert!(compared
        .iter()
        .find(|f| f.file_path == "app.js")
        .unwrap()
        .review
        .as_ref()
        .is_some_and(|r| r.origin == ReviewOrigin::Local && r.state == ReviewState::AcceptedRisk));
    assert!(compared
        .iter()
        .find(|f| f.file_path == "removed.js")
        .unwrap()
        .review
        .as_ref()
        .is_some_and(
            |r| r.origin == ReviewOrigin::ProjectPolicy && r.reason == "Readded project policy"
        ));
}

#[tokio::test]
async fn recent_counts_follow_current_policy_read_only_and_keep_missing_roots() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(project.join(".oxaudit")).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let policy = project.join(".oxaudit/policy.json");
    let write_policy = |pattern: &str| {
        std::fs::write(&policy, format!(r#"{{"version":1,"entries":[{{"kind":"suppression","ruleId":"js-eval","pathPattern":"{pattern}","state":"suppressed","reason":"Reviewed project exception"}}]}}"#)).unwrap();
    };
    write_policy("*.js");
    let database = temp.path().join("data/findings.db");
    let service = FindingsService::new(super::FindingsRepository::open(&database).unwrap());
    let run = service
        .scan(
            ScanOptions {
                path: project.to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    let observer = rusqlite::Connection::open(&database).unwrap();
    let version = || {
        observer
            .query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    let stored = serde_json::to_value(service.repository.load_run(&run.run_id).unwrap()).unwrap();
    let assert_counts = |expected: usize| {
        let before = version();
        let recent = service.list_recent_projects(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].open_findings, expected);
        assert_eq!(recent[0].high, expected);
        assert_eq!(
            recent[0].last_completed_run_id.as_deref(),
            Some(run.run_id.as_str())
        );
        assert_eq!(
            serde_json::to_value(&recent[0]).unwrap()["countsAvailable"],
            true
        );
        assert_eq!(version(), before, "history count projection must not write");
        assert_eq!(
            stored,
            serde_json::to_value(service.repository.load_run(&run.run_id).unwrap()).unwrap()
        );
    };
    // No ordinary load/reconciliation first: persisted suppression is still active.
    std::fs::write(&policy, "{ invalid").unwrap();
    assert_counts(1);
    write_policy("*.js");
    assert_counts(0);
    write_policy("other.js");
    assert_counts(1);
    std::fs::remove_file(&policy).unwrap();
    assert_counts(1);
    write_policy("*.js");
    let other = temp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("app.js"), "eval(input);\n").unwrap();
    service
        .scan(
            ScanOptions {
                path: other.to_string_lossy().into(),
                scan_secrets: false,
                ..ScanOptions::default()
            },
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    std::fs::remove_dir_all(&project).unwrap();
    let before = version();
    let recent = service.list_recent_projects(10).unwrap();
    assert_eq!(recent.len(), 2);
    let available = recent
        .iter()
        .find(|row| row.project_id != run.project_id)
        .unwrap();
    assert_eq!(available.counts_available, Some(true));
    assert_eq!(available.open_findings, 1);
    let missing = recent
        .iter()
        .find(|row| row.project_id == run.project_id)
        .unwrap();
    assert_eq!(
        missing.last_completed_run_id.as_deref(),
        Some(run.run_id.as_str())
    );
    assert_eq!(
        serde_json::to_value(missing).unwrap()["countsAvailable"],
        false
    );
    assert_eq!(version(), before);
}

#[tokio::test]
async fn recent_counts_only_include_last_completed_observations() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("app.js"), "eval(input);\n").unwrap();
    let service = FindingsService::new(
        super::FindingsRepository::open(temp.path().join("data/findings.db")).unwrap(),
    );
    let options = ScanOptions {
        path: project.to_string_lossy().into(),
        scan_secrets: false,
        ..ScanOptions::default()
    };
    service
        .scan(
            options.clone(),
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    std::fs::remove_file(project.join("app.js")).unwrap();
    std::fs::write(project.join("safe.js"), "const a = 1;\n").unwrap();
    let current = service
        .scan(
            options,
            &cached_cve_state(),
            &AtomicBool::new(false),
            &RecordingEvents::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        current.findings.len(),
        1,
        "baseline-only unscanned finding remains visible for comparison"
    );
    let recent = service.list_recent_projects(10).unwrap();
    assert_eq!(
        recent[0].last_completed_run_id.as_deref(),
        Some(current.run_id.as_str())
    );
    assert_eq!(
        recent[0].open_findings, 0,
        "baseline-only evidence is not part of completed observation counts"
    );
    assert_eq!(recent[0].counts_available, Some(true));
}

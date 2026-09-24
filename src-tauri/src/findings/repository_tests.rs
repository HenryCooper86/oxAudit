//! Tests for [`super`].
//!
//! Kept a child module rather than moved to `tests/`: these reach private
//! items through `use super::*`, and widening their visibility to run them
//! from outside would be a worse design than a long file. This is purely a
//! split for readability — repository.rs was 6870 lines.

use std::collections::BTreeMap;
use std::path::Path;

use crate::findings::coverage::CoverageManifest;
use crate::findings::domain::{
    DiffStatus, FindingScope, PolicyStatus, RetentionPolicy, ReviewOrigin, ReviewRecord,
    ReviewState, RunPersistence, RunStatus, ScanRunDetail, SeverityCounts, FINGERPRINT_VERSION,
};
use crate::models::{Finding, ScanOptions, ScanSummary};

use super::*;

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::symlink_metadata(path)
        .expect("read metadata")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::symlink_metadata(path)
        .expect("read metadata")
        .permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).expect("set permissions");
}

fn summary(total_findings: usize) -> ScanSummary {
    ScanSummary {
        git_context: None,
        path: "/project".into(),
        files_scanned: 1,
        files_skipped: 0,
        bytes_scanned: 42,
        duration_ms: 7,
        secrets_found: total_findings,
        vulnerabilities_found: 0,
        total_findings,
        critical: 0,
        high: total_findings,
        medium: 0,
        low: 0,
        info: 0,
        rules_fired: BTreeMap::from([("generic-api-key".into(), total_findings)]),
    }
}

fn run_detail(run_id: &str, status: RunStatus, findings: Vec<Finding>) -> ScanRunDetail {
    ScanRunDetail {
        project_id: "project-1".into(),
        run_id: run_id.into(),
        baseline_run_id: None,
        status,
        persistence: RunPersistence::Saved,
        policy: PolicyStatus::Valid {
            hash: "policy-hash".into(),
        },
        started_at: "2026-08-20T10:00:00Z".into(),
        completed_at: (status == RunStatus::Completed).then(|| "2026-08-20T10:00:07Z".into()),
        summary: summary(findings.len()),
        findings,
        maintenance_warning: None,
    }
}

fn finding(id: &str, fingerprint: &str) -> Finding {
    Finding {
        id: id.into(),
        category: "secret".into(),
        rule_id: "generic-api-key".into(),
        rule_name: "Generic API Key".into(),
        severity: "high".into(),
        title: "Credential in source".into(),
        description: "A sanitized credential match was observed.".into(),
        file_path: "src/config.rs".into(),
        line: 9,
        column: 17,
        match_text: "token = [REDACTED]".into(),
        context: "let token = \"[REDACTED]\";".into(),
        language: "rust".into(),
        cwe: Some("CWE-798".into()),
        cwe_exploited: false,
        cwe_exploited_count: 0,
        recommendation: "Move the credential to protected storage.".into(),
        entropy: Some(4.25),
        verified: None,
        // Rows written before the tier existed read back as Text: a stored
        // finding must not claim a verification that never ran.
        analysis: crate::models::AnalysisTier::default(),
        analysis_gates: Vec::new(),
        observation_run_id: "dynamic-run-id-must-not-be-persisted-in-payload".into(),
        resolved_by_run_id: Some("dynamic-resolution-must-not-be-persisted".into()),
        fingerprint_version: FINGERPRINT_VERSION,
        fingerprint: fingerprint.into(),
        in_test_region: false,
        scope: Some(FindingScope::Production),
        scope_reason: Some("source directory".into()),
        review: Some(review("embedded-review-must-not-be-persisted")),
        review_history: vec![review("embedded-history-must-not-be-persisted")],
        diff_status: Some(DiffStatus::Resolved),
    }
}

fn review(id: &str) -> ReviewRecord {
    ReviewRecord {
        id: id.into(),
        project_id: "project-1".into(),
        fingerprint_version: FINGERPRINT_VERSION,
        fingerprint: "fingerprint-1".into(),
        state: ReviewState::Confirmed,
        reason: "Manually verified".into(),
        evidence: Some("Sanitized evidence".into()),
        entry_point: None,
        data_flow: None,
        gates: Vec::new(),
        deciding_gate: None,
        expires_at: None,
        origin: ReviewOrigin::Local,
        policy_hash: None,
        updated_at: "2026-08-20T10:01:00Z".into(),
        superseded_at: None,
    }
}

fn prepare_run(repository: &FindingsRepository, run_id: &str) {
    prepare_project_run(repository, "project-1", "/project", run_id);
}

fn prepare_project_run(
    repository: &FindingsRepository,
    project_id: &str,
    project_path: &str,
    run_id: &str,
) {
    prepare_project_run_at(
        repository,
        project_id,
        project_path,
        run_id,
        "2026-08-20T10:00:00Z",
    );
}

fn prepare_project_run_at(
    repository: &FindingsRepository,
    project_id: &str,
    project_path: &str,
    run_id: &str,
    started_at: &str,
) {
    let options = ScanOptions::default();
    repository
        .upsert_project(
            project_id,
            project_path,
            "Project",
            "2026-08-20T09:59:00Z",
            Some(&options),
        )
        .expect("upsert project");
    let mut running = run_detail(run_id, RunStatus::Running, Vec::new());
    running.project_id = project_id.into();
    running.started_at = started_at.into();
    repository
        .start_run(&running, "scanner-1.0", &options)
        .expect("start run");
}

fn complete_project_run(
    repository: &FindingsRepository,
    project_id: &str,
    project_path: &str,
    run_id: &str,
    completed_at: &str,
    findings: Vec<Finding>,
    coverage: &CoverageManifest,
) {
    let completed_instant = DateTime::parse_from_rfc3339(completed_at)
        .expect("valid completed fixture time")
        .with_timezone(&Utc);
    let started_at = completed_instant
        .checked_sub_signed(ChronoDuration::seconds(1))
        .expect("valid started fixture time")
        .to_rfc3339();
    prepare_project_run_at(repository, project_id, project_path, run_id, &started_at);
    let mut completed = run_detail(run_id, RunStatus::Completed, findings);
    completed.project_id = project_id.into();
    completed.started_at = started_at;
    completed.completed_at = Some(completed_at.into());
    repository
        .complete_run(&completed, coverage)
        .expect("complete project run");
}

fn finding_at(
    id: &str,
    fingerprint: &str,
    category: &str,
    path: &str,
    scope: FindingScope,
) -> Finding {
    let mut item = finding(id, fingerprint);
    item.category = category.into();
    item.file_path = path.into();
    item.scope = Some(scope);
    item
}

#[test]
fn reopening_canonical_path_with_fresh_id_returns_stored_project_identity() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let initial_options = ScanOptions {
        path: "/project".into(),
        ..ScanOptions::default()
    };

    let created = repository
        .upsert_project(
            "stored-project-id",
            "/project",
            "Initial name",
            "2026-08-20T09:00:00Z",
            Some(&initial_options),
        )
        .expect("create project");
    let reopened = repository
        .upsert_project(
            "fresh-caller-id",
            "/project",
            "Updated name",
            "2026-08-20T10:00:00Z",
            None,
        )
        .expect("reopen project");

    assert_eq!(created.project_id, "stored-project-id");
    assert_eq!(reopened.project_id, "stored-project-id");
    assert_eq!(reopened.canonical_path, "/project");
    assert_eq!(reopened.display_name, "Updated name");
    assert_eq!(reopened.last_options, Some(initial_options));
    assert_eq!(reopened.policy, PolicyStatus::Missing);
    let connection = repository.connection.lock().expect("lock connection");
    let projects: i64 = connection
        .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
        .expect("count projects");
    assert_eq!(projects, 1);
}

#[test]
fn existing_project_id_cannot_be_rebound_to_another_path() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    repository
        .upsert_project(
            "project-id",
            "/first",
            "First",
            "2026-08-20T09:00:00Z",
            Some(&ScanOptions::default()),
        )
        .expect("create project");

    let error = repository
        .upsert_project(
            "project-id",
            "/second",
            "Rebound",
            "2026-08-20T10:00:00Z",
            None,
        )
        .expect_err("must reject project ID rebinding");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let connection = repository.connection.lock().expect("lock connection");
    let stored: (String, String, String) = connection
        .query_row(
            "SELECT canonical_path, display_name, last_opened_at FROM projects WHERE id = ?1",
            ["project-id"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load original project");
    assert_eq!(
        stored,
        (
            "/first".into(),
            "First".into(),
            "2026-08-20T09:00:00Z".into()
        )
    );
}

#[test]
fn reopening_without_options_preserves_last_successful_options() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let options = ScanOptions {
        path: "/project".into(),
        include_git: true,
        extra_ignored_dirs: vec!["private-cache".into()],
        ..ScanOptions::default()
    };
    repository
        .upsert_project(
            "project-id",
            "/project",
            "Project",
            "2026-08-20T09:00:00Z",
            Some(&options),
        )
        .expect("create project");

    let reopened = repository
        .upsert_project(
            "new-id",
            "/project",
            "Project",
            "2026-08-20T10:00:00Z",
            None,
        )
        .expect("reopen without options");

    assert_eq!(reopened.last_options, Some(options));
}

#[test]
fn creates_current_schema() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let connection = repository.connection.lock().expect("lock connection");
    let tables = [
        "schema_migrations",
        "projects",
        "scan_runs",
        "findings",
        "reviews",
        "canonical_runs",
        "canonical_artifacts",
        "canonical_components",
        "canonical_observations",
        "canonical_findings",
        "canonical_projections",
        "provider_snapshots",
        "verification_records",
        "benchmark_results",
        "compliance_assessments",
        "compliance_control_reviews",
        "compliance_reports",
    ];

    for table in tables {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .expect("query schema");
        assert!(exists, "missing table {table}");
    }

    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("query foreign key pragma");
    assert_eq!(foreign_keys, 1);

    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("query migration version");
    assert_eq!(version, 5);
}

#[test]
fn compliance_assessments_reviews_and_report_receipts_are_durable_and_append_only() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let profile = oxaudit_compliance::builtin_profile("gdpr").expect("profile");
    let assessment = oxaudit_compliance::assess(
        &profile,
        &oxaudit_compliance::EvidenceSnapshot {
            root_label: "/project".into(),
            files: vec![],
            completed_runs: vec![],
            collection_limits: vec!["bounded".into()],
        },
        oxaudit_compliance::AssessmentMetadata {
            title: "Readiness".into(),
            organization: "Example".into(),
            assessor: "Reviewer".into(),
            scope: "Product".into(),
        },
        "assessment-test".into(),
        100,
    )
    .expect("assessment");
    repository
        .compliance_save_assessment(&assessment)
        .expect("save assessment");

    for (id, status, reviewed_at_ms) in [
        (
            "review-1",
            oxaudit_compliance::ReadinessStatus::Partial,
            101,
        ),
        (
            "review-2",
            oxaudit_compliance::ReadinessStatus::Supported,
            102,
        ),
    ] {
        repository
            .compliance_save_review(&crate::compliance::ComplianceReview {
                id: id.into(),
                assessment_id: assessment.id.clone(),
                control_id: assessment.controls[0].control_id.clone(),
                status,
                note: "Qualified decision with linked evidence.".into(),
                author: "Reviewer".into(),
                reviewed_at_ms,
            })
            .expect("append review");
    }

    let reviews = repository
        .compliance_list_reviews(&assessment.id)
        .expect("load reviews");
    assert_eq!(reviews.len(), 2);
    assert_eq!(reviews[0].id, "review-2");
    assert_eq!(
        repository
            .compliance_list_assessments(10)
            .expect("list assessments"),
        vec![assessment.clone()]
    );
    assert_eq!(
        repository
            .compliance_load_assessment(&assessment.id)
            .expect("load assessment"),
        assessment
    );

    repository
        .compliance_save_report(&crate::compliance::ComplianceReportReceipt {
            id: "report-1".into(),
            assessment_id: "assessment-test".into(),
            format: crate::compliance::ComplianceReportFormat::Pdf,
            output_path: "/reports/readiness.pdf".into(),
            content_sha256: "abc123".into(),
            created_at_ms: 103,
            metadata: crate::compliance::ComplianceReportMetadata {
                title: "Readiness report".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                classification: "Confidential".into(),
                executive_summary: "Evidence readiness summary.".into(),
                include_evidence: true,
                include_reviews: true,
                include_references: true,
            },
        })
        .expect("save report receipt");
}

#[test]
fn provider_snapshot_identity_is_immutable_and_idempotent() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let snapshot = ProviderSnapshotRecord {
        id: "provider_fixture".into(),
        provider_id: "osv-query".into(),
        fetched_at_ms: 42,
        content_sha256: "a".repeat(64),
        payload: serde_json::json!({"schemaVersion": 1, "results": {}}),
    };

    repository
        .provider_save_snapshot(&snapshot)
        .expect("save provider snapshot");
    repository
        .provider_save_snapshot(&snapshot)
        .expect("same immutable snapshot is idempotent");

    let mut collision = snapshot.clone();
    collision.payload = serde_json::json!({"schemaVersion": 1, "results": {"changed": []}});
    assert!(repository.provider_save_snapshot(&collision).is_err());
    assert_eq!(
        repository
            .provider_latest_snapshot("osv-query")
            .expect("load latest snapshot")
            .expect("snapshot exists")
            .payload,
        snapshot.payload
    );
}

#[test]
fn failed_migration_does_not_record_version_one() {
    let mut connection = Connection::open_in_memory().expect("open sqlite");
    initialize_connection(&connection, false).expect("initialize sqlite");

    let error = migrate(
        &mut connection,
        "CREATE TABLE durable_test(id INTEGER); THIS IS NOT SQL;",
    )
    .expect_err("migration must fail");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let migration_ledger: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'schema_migrations')",
            [],
            |row| row.get(0),
        )
        .expect("query migration ledger");
    assert!(!migration_ledger);
    let partial_table: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'durable_test')",
            [],
            |row| row.get(0),
        )
        .expect("query partial schema");
    assert!(!partial_table);
}

#[test]
fn completion_is_atomic_allowlisted_and_idempotent() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "run-1");
    let stored_review = review("review-1");
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason, evidence,
                         entry_point, data_flow, gates_json, deciding_gate, expires_at, origin,
                         policy_hash, updated_at, superseded_at
                       ) VALUES (?1, ?2, ?3, ?4, 'confirmed', ?5, ?6, NULL, NULL, '[]', NULL,
                                 NULL, 'local', NULL, ?7, NULL)"#,
                rusqlite::params![
                    stored_review.id,
                    stored_review.project_id,
                    stored_review.fingerprint_version,
                    stored_review.fingerprint,
                    stored_review.reason,
                    stored_review.evidence,
                    stored_review.updated_at,
                ],
            )
            .expect("insert review fixture");
    }

    let completed = run_detail(
        "run-1",
        RunStatus::Completed,
        vec![finding("observation-1", "fingerprint-1")],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let first = repository
        .complete_run(&completed, &coverage)
        .expect("complete run");
    let retried = repository
        .complete_run(&completed, &coverage)
        .expect("retry completed run");

    assert_eq!(first.status, RunStatus::Completed);
    assert_eq!(retried.status, RunStatus::Completed);
    assert_eq!(retried.findings.len(), 1);
    assert_eq!(first.findings[0].diff_status, Some(DiffStatus::New));
    assert_eq!(retried.findings[0].diff_status, Some(DiffStatus::New));
    let loaded = repository.load_run("run-1").expect("load completed run");
    assert_eq!(loaded.findings.len(), 1);
    let loaded_finding = &loaded.findings[0];
    assert_eq!(loaded_finding.observation_run_id, "run-1");
    assert_eq!(loaded_finding.resolved_by_run_id, None);
    assert_eq!(loaded_finding.diff_status, Some(DiffStatus::New));
    assert_eq!(
        loaded_finding.review.as_ref().map(|item| &item.id),
        Some(&"review-1".into())
    );
    assert_eq!(loaded_finding.review_history, vec![stored_review]);

    let connection = repository.connection.lock().expect("lock connection");
    let raw = load_run_from_connection(&connection, "run-1")
        .expect("load raw run")
        .expect("raw run exists");
    assert_eq!(raw.findings[0].observation_run_id, "run-1");
    assert_eq!(raw.findings[0].resolved_by_run_id, None);
    assert_eq!(raw.findings[0].diff_status, None);
    let observation_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE run_id = 'run-1'",
            [],
            |row| row.get(0),
        )
        .expect("count observations");
    assert_eq!(observation_count, 1);
    let (payload, stored_coverage): (String, String) = connection
        .query_row(
            r#"SELECT f.payload_json, r.coverage_json
                   FROM findings f JOIN scan_runs r ON r.id = f.run_id
                   WHERE f.id = 'observation-1'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query stored JSON");
    let payload: serde_json::Value = serde_json::from_str(&payload).expect("parse payload");
    for forbidden in [
        "id",
        "observationRunId",
        "resolvedByRunId",
        "fingerprintVersion",
        "fingerprint",
        "scope",
        "scopeReason",
        "review",
        "reviewHistory",
        "diffStatus",
    ] {
        assert!(
            payload.get(forbidden).is_none(),
            "payload contains {forbidden}"
        );
    }
    assert_eq!(
        serde_json::from_str::<CoverageManifest>(&stored_coverage).expect("parse coverage"),
        coverage
    );
}

#[test]
fn failed_completion_rolls_back_observations_and_leaves_run_running() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "run-rollback");
    let mut invalid = finding("observation-invalid", "fingerprint-invalid");
    invalid.scope = None;
    let completed = run_detail("run-rollback", RunStatus::Completed, vec![invalid]);
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let error = repository
        .complete_run(&completed, &coverage)
        .expect_err("missing scope must fail completion");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let connection = repository.connection.lock().expect("lock connection");
    let (status, observations): (String, i64) = connection
        .query_row(
            r#"SELECT r.status, COUNT(f.id)
                   FROM scan_runs r LEFT JOIN findings f ON f.run_id = r.id
                   WHERE r.id = 'run-rollback' GROUP BY r.id"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query rollback state");
    assert_eq!(status, "running");
    assert_eq!(observations, 0);
}

#[test]
fn coverage_fingerprint_version_mismatch_rolls_back_completion() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "coverage-version-mismatch");
    let completed = run_detail(
        "coverage-version-mismatch",
        RunStatus::Completed,
        vec![finding(
            "coverage-version-observation",
            "coverage-version-fingerprint",
        )],
    );
    let mut coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    coverage.fingerprint_version = FINGERPRINT_VERSION + 1;

    let error = repository
        .complete_run(&completed, &coverage)
        .expect_err("coverage version mismatch must fail");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_running_without_findings(&repository, "coverage-version-mismatch");
}

#[test]
fn finding_fingerprint_version_mismatch_rolls_back_completion() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "finding-version-mismatch");
    let mut mismatched = finding("finding-version-observation", "finding-version-fingerprint");
    mismatched.fingerprint_version = FINGERPRINT_VERSION + 1;
    let completed = run_detail(
        "finding-version-mismatch",
        RunStatus::Completed,
        vec![mismatched],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let error = repository
        .complete_run(&completed, &coverage)
        .expect_err("finding version mismatch must fail");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_running_without_findings(&repository, "finding-version-mismatch");
}

fn assert_running_without_findings(repository: &FindingsRepository, run_id: &str) {
    let connection = repository.connection.lock().expect("lock connection");
    let (status, findings): (String, i64) = connection
        .query_row(
            r#"SELECT r.status, COUNT(f.id)
                   FROM scan_runs r LEFT JOIN findings f ON f.run_id = r.id
                   WHERE r.id = ?1 GROUP BY r.id"#,
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query run integrity");
    assert_eq!(status, "running");
    assert_eq!(findings, 0);
}

#[test]
fn interrupted_recovery_preserves_completed_baseline_and_latest_selection() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "baseline-run");
    let mut baseline = run_detail(
        "baseline-run",
        RunStatus::Completed,
        vec![finding("baseline-observation", "baseline-fingerprint")],
    );
    baseline.completed_at = Some("2026-08-20T10:00:07Z".into());
    repository
        .complete_run(
            &baseline,
            &CoverageManifest::from_entries([("src/config.rs", ["secret"])]),
        )
        .expect("complete baseline");

    prepare_run(&repository, "interrupted-run");
    let recovered = repository
        .recover_interrupted_runs(
            chrono::DateTime::parse_from_rfc3339("2026-08-20T11:00:00Z")
                .expect("parse recovery time")
                .with_timezone(&chrono::Utc),
        )
        .expect("recover interrupted runs");

    assert_eq!(recovered, 1);
    let interrupted = repository
        .load_run("interrupted-run")
        .expect("load interrupted run");
    assert_eq!(interrupted.status, RunStatus::Incomplete);
    assert_eq!(
        interrupted.completed_at.as_deref(),
        Some("2026-08-20T11:00:00+00:00")
    );
    let latest = repository
        .latest_completed_run("project-1")
        .expect("query latest completed")
        .expect("completed baseline");
    assert_eq!(latest.run_id, "baseline-run");

    let connection = repository.connection.lock().expect("lock connection");
    let baseline_error: Option<String> = connection
        .query_row(
            "SELECT error_code FROM scan_runs WHERE id = 'baseline-run'",
            [],
            |row| row.get(0),
        )
        .expect("query completed baseline");
    let interrupted_error: String = connection
        .query_row(
            "SELECT error_code FROM scan_runs WHERE id = 'interrupted-run'",
            [],
            |row| row.get(0),
        )
        .expect("query interrupted run");
    assert_eq!(baseline_error, None);
    assert_eq!(interrupted_error, "process_interrupted");
}

#[test]
fn mark_incomplete_does_not_overwrite_a_completed_run() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "completed-run");
    repository
        .complete_run(
            &run_detail("completed-run", RunStatus::Completed, Vec::new()),
            &CoverageManifest::from_entries([("src/lib.rs", ["vulnerability"])]),
        )
        .expect("complete run");

    repository
        .mark_incomplete("completed-run", "2026-08-20T12:00:00Z", "scanner_failed")
        .expect("completed run is left alone");

    assert_eq!(
        repository
            .load_run("completed-run")
            .expect("load completed run")
            .status,
        RunStatus::Completed
    );
}

#[test]
fn start_run_rejects_completed_id_collision_without_changing_original() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "completed-collision");
    repository
        .complete_run(
            &run_detail("completed-collision", RunStatus::Completed, Vec::new()),
            &CoverageManifest::from_entries([("src/lib.rs", ["vulnerability"])]),
        )
        .expect("complete original run");
    let before = stored_run_identity(&repository, "completed-collision");

    let error = repository
        .start_run(
            &run_detail("completed-collision", RunStatus::Running, Vec::new()),
            "scanner-1.0",
            &ScanOptions::default(),
        )
        .expect_err("completed run ID must not restart");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(
        stored_run_identity(&repository, "completed-collision"),
        before
    );
}

#[test]
fn start_run_rejects_incomplete_id_collision_without_changing_original() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "incomplete-collision");
    repository
        .mark_incomplete(
            "incomplete-collision",
            "2026-08-20T10:30:00Z",
            "scanner_failed",
        )
        .expect("mark original incomplete");
    let before = stored_run_identity(&repository, "incomplete-collision");

    let error = repository
        .start_run(
            &run_detail("incomplete-collision", RunStatus::Running, Vec::new()),
            "scanner-1.0",
            &ScanOptions::default(),
        )
        .expect_err("incomplete run ID must not restart");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(
        stored_run_identity(&repository, "incomplete-collision"),
        before
    );
}

#[test]
fn start_run_rejects_mismatched_running_collision_without_changing_original() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "running-collision");
    let before = stored_run_identity(&repository, "running-collision");

    let error = repository
        .start_run(
            &run_detail("running-collision", RunStatus::Running, Vec::new()),
            "different-scanner-version",
            &ScanOptions::default(),
        )
        .expect_err("mismatched running collision must fail");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(
        stored_run_identity(&repository, "running-collision"),
        before
    );
}

#[test]
fn start_run_ignores_advisory_baseline_hints_without_stale_locking_retry() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    repository
        .upsert_project(
            "project-1",
            "/project",
            "Project",
            "2026-08-20T09:59:00Z",
            Some(&ScanOptions::default()),
        )
        .expect("upsert project");
    let mut running = run_detail("advisory-start-run", RunStatus::Running, Vec::new());
    running.baseline_run_id = Some("nonexistent-advisory-baseline".into());
    repository
        .start_run(&running, "scanner-1.0", &ScanOptions::default())
        .expect("advisory hint must not control the stored boundary");

    running.baseline_run_id = Some("different-retry-hint".into());
    repository
        .start_run(&running, "scanner-1.0", &ScanOptions::default())
        .expect("changed advisory hint must not stale-lock retry");

    let connection = repository.connection.lock().expect("lock connection");
    let stored_baseline: Option<String> = connection
        .query_row(
            "SELECT baseline_run_id FROM scan_runs WHERE id = 'advisory-start-run'",
            [],
            |row| row.get(0),
        )
        .expect("load stored boundary");
    assert_eq!(stored_baseline, None);
}

fn stored_run_identity(
    repository: &FindingsRepository,
    run_id: &str,
) -> (
    String,
    String,
    Option<String>,
    String,
    u16,
    String,
    String,
    Option<String>,
    String,
) {
    repository
        .connection
        .lock()
        .expect("lock connection")
        .query_row(
            r#"SELECT status, project_id, baseline_run_id, scanner_version,
                          fingerprint_version, options_json, policy_status_json, policy_hash,
                          started_at
                   FROM scan_runs WHERE id = ?1"#,
            [run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("load stored run identity")
}

#[test]
fn recent_projects_report_latest_completed_open_counts() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "recent-completed");
    repository
        .complete_run(
            &run_detail(
                "recent-completed",
                RunStatus::Completed,
                vec![finding("recent-observation", "recent-fingerprint")],
            ),
            &CoverageManifest::from_entries([("src/config.rs", ["secret"])]),
        )
        .expect("complete recent run");
    prepare_run(&repository, "newer-running");

    let recent = repository
        .list_recent_projects(10)
        .expect("list recent projects");

    assert_eq!(recent.len(), 1);
    assert_eq!(
        recent[0].last_completed_run_id.as_deref(),
        Some("recent-completed")
    );
    assert_eq!(
        recent[0].last_completed_at.as_deref(),
        Some("2026-08-20T10:00:07Z")
    );
    assert_eq!(recent[0].open_findings, 1);
    assert_eq!(recent[0].critical, 0);
    assert_eq!(recent[0].high, 1);
}

#[test]
fn recent_open_counts_exclude_nonproduction_candidates_but_include_confirmed() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "scope-count-run");
    let mut test_candidate = finding("test-candidate", "test-candidate-fingerprint");
    test_candidate.scope = Some(FindingScope::Test);
    let mut documentation_confirmed = finding("docs-confirmed", "docs-confirmed-fingerprint");
    documentation_confirmed.scope = Some(FindingScope::Documentation);
    documentation_confirmed.severity = "critical".into();
    repository
        .complete_run(
            &run_detail(
                "scope-count-run",
                RunStatus::Completed,
                vec![test_candidate, documentation_confirmed],
            ),
            &CoverageManifest::from_entries([
                ("src/config.rs", ["secret"]),
                ("docs/example.md", ["secret"]),
            ]),
        )
        .expect("complete scoped run");
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason,
                         gates_json, origin, updated_at
                       ) VALUES ('docs-confirmation', 'project-1', ?1,
                                 'docs-confirmed-fingerprint', 'confirmed', 'verified', '[]',
                                 'local', '2026-08-20T11:00:00Z')"#,
                [FINGERPRINT_VERSION],
            )
            .expect("insert confirmation");
    }

    let recent = repository.list_recent_projects(1).expect("list project");

    assert_eq!(recent[0].open_findings, 1);
    assert_eq!(recent[0].critical, 1);
    assert_eq!(recent[0].high, 0);
}

#[test]
fn expired_review_remains_history_but_does_not_close_a_finding() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "expired-review-run");
    repository
        .complete_run(
            &run_detail(
                "expired-review-run",
                RunStatus::Completed,
                vec![finding("expired-observation", "expired-fingerprint")],
            ),
            &CoverageManifest::from_entries([("src/config.rs", ["secret"])]),
        )
        .expect("complete run");
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason,
                         gates_json, expires_at, origin, updated_at
                       ) VALUES ('expired-review', 'project-1', ?1, 'expired-fingerprint',
                                 'falsePositive', 'expired decision', '[]',
                                 '2000-01-01T00:00:00Z', 'local', '2000-01-01T00:00:00Z')"#,
                [FINGERPRINT_VERSION],
            )
            .expect("insert expired review");
    }

    let loaded = repository
        .load_run("expired-review-run")
        .expect("load reviewed run");
    let recent = repository.list_recent_projects(1).expect("list project");

    assert_eq!(loaded.findings[0].review, None);
    assert_eq!(loaded.findings[0].review_history.len(), 1);
    assert_eq!(recent[0].open_findings, 1);
}

#[test]
fn run_comparison_classifies_every_current_and_baseline_only_observation() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let baseline_coverage = CoverageManifest::from_entries([
        ("src/a.rs", ["vulnerability"]),
        ("src/b.rs", ["vulnerability"]),
        ("config/c.env", ["secret"]),
    ]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "baseline-run",
        "2026-08-20T10:00:00Z",
        vec![
            finding_at(
                "baseline-a",
                "fingerprint-a",
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            ),
            finding_at(
                "baseline-b",
                "fingerprint-b",
                "vulnerability",
                "src/b.rs",
                FindingScope::Test,
            ),
            finding_at(
                "baseline-c",
                "fingerprint-c",
                "secret",
                "config/c.env",
                FindingScope::Documentation,
            ),
        ],
        &baseline_coverage,
    );
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason,
                         gates_json, origin, updated_at
                       ) VALUES ('baseline-review', 'project-1', ?1, 'fingerprint-b',
                                 'confirmed', 'review survives projection', '[]', 'local',
                                 '2026-08-20T10:01:00Z')"#,
                [FINGERPRINT_VERSION],
            )
            .expect("insert baseline review");
    }
    let current_coverage = CoverageManifest::from_entries([
        ("src/a.rs", ["vulnerability"]),
        ("src/b.rs", ["vulnerability"]),
        ("src/d.rs", ["vulnerability"]),
    ]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "current-run",
        "2026-08-20T11:00:00Z",
        vec![
            finding_at(
                "current-a",
                "fingerprint-a",
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            ),
            finding_at(
                "current-d",
                "fingerprint-d",
                "vulnerability",
                "src/d.rs",
                FindingScope::Fixture,
            ),
        ],
        &current_coverage,
    );

    let comparison = repository
        .compare_runs("current-run", "baseline-run")
        .expect("compare completed compatible runs");

    assert_eq!(comparison.len(), 4);
    let by_fingerprint = comparison
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let unchanged = by_fingerprint["fingerprint-a"];
    assert_eq!(unchanged.id, "current-a");
    assert_eq!(unchanged.observation_run_id, "current-run");
    assert_eq!(unchanged.resolved_by_run_id, None);
    assert_eq!(unchanged.diff_status, Some(DiffStatus::Unchanged));

    let new = by_fingerprint["fingerprint-d"];
    assert_eq!(new.id, "current-d");
    assert_eq!(new.observation_run_id, "current-run");
    assert_eq!(new.resolved_by_run_id, None);
    assert_eq!(new.diff_status, Some(DiffStatus::New));
    assert_eq!(new.scope, Some(FindingScope::Fixture));

    let resolved = by_fingerprint["fingerprint-b"];
    assert_eq!(resolved.id, "baseline-b");
    assert_eq!(resolved.observation_run_id, "baseline-run");
    assert_eq!(resolved.resolved_by_run_id.as_deref(), Some("current-run"));
    assert_eq!(resolved.diff_status, Some(DiffStatus::Resolved));
    assert_eq!(resolved.scope, Some(FindingScope::Test));
    assert_eq!(
        resolved.review.as_ref().map(|review| review.id.as_str()),
        Some("baseline-review")
    );
    assert_eq!(resolved.review_history.len(), 1);

    let not_evaluated = by_fingerprint["fingerprint-c"];
    assert_eq!(not_evaluated.id, "baseline-c");
    assert_eq!(not_evaluated.observation_run_id, "baseline-run");
    assert_eq!(not_evaluated.resolved_by_run_id, None);
    assert_eq!(not_evaluated.diff_status, Some(DiffStatus::NotEvaluated));
    assert_eq!(not_evaluated.scope, Some(FindingScope::Documentation));

    let connection = repository.connection.lock().expect("lock connection");
    for run_id in ["baseline-run", "current-run"] {
        let stored = load_run_from_connection(&connection, run_id)
            .expect("load immutable stored run")
            .expect("stored run exists");
        assert!(stored.findings.iter().all(|finding| {
            finding.diff_status.is_none() && finding.resolved_by_run_id.is_none()
        }));
    }
}

#[test]
fn list_runs_is_bounded_instant_ordered_and_counts_comparisons_without_payload_loads() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "first-run",
        "2026-08-20T08:00:00Z",
        vec![
            finding("first-shared", "shared"),
            finding("first-old", "old"),
        ],
        &coverage,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "compared-run",
        "2026-08-20T09:00:00Z",
        vec![
            finding("current-shared", "shared"),
            finding("current-new", "new"),
        ],
        &coverage,
    );
    for (run_id, completed_at) in [
        ("offset-newer", "2026-08-20T12:00:00.100000000+02:00"),
        ("nano-older", "2026-08-20T10:00:00.090000000Z"),
        ("tie-a", "2026-08-20T09:30:00.000000001Z"),
        ("tie-z", "2026-08-20T09:30:00.000000001Z"),
    ] {
        prepare_project_run_at(
            &repository,
            "project-1",
            "/project",
            run_id,
            "2026-08-20T07:00:00Z",
        );
        repository
            .mark_incomplete(run_id, completed_at, "fixture_incomplete")
            .expect("mark fixture incomplete");
    }

    let runs = repository.list_runs("project-1", 20).expect("list runs");
    assert_eq!(
        runs.iter()
            .map(|run| run.run_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "offset-newer",
            "nano-older",
            "tie-z",
            "tie-a",
            "compared-run",
            "first-run"
        ]
    );
    let first = runs.iter().find(|run| run.run_id == "first-run").unwrap();
    assert_eq!(
        (
            first.total_findings,
            first.new_findings,
            first.resolved_findings
        ),
        (2, 2, 0)
    );
    let compared = runs
        .iter()
        .find(|run| run.run_id == "compared-run")
        .unwrap();
    assert_eq!(
        (
            compared.total_findings,
            compared.new_findings,
            compared.resolved_findings
        ),
        (2, 1, 1)
    );
    let incomplete = runs
        .iter()
        .find(|run| run.run_id == "offset-newer")
        .unwrap();
    assert_eq!(incomplete.status, RunStatus::Incomplete);
    assert_eq!(
        (
            incomplete.total_findings,
            incomplete.new_findings,
            incomplete.resolved_findings
        ),
        (0, 0, 0)
    );
    assert_eq!(
        repository
            .list_runs("project-1", 2)
            .unwrap()
            .iter()
            .map(|run| run.run_id.as_str())
            .collect::<Vec<_>>(),
        vec!["offset-newer", "nano-older"]
    );
    assert!(repository.list_runs("project-1", 0).unwrap().is_empty());
    assert_eq!(
        repository
            .list_runs("unknown-project", 10)
            .unwrap_err()
            .code,
        crate::findings::error::ErrorCode::NotFound
    );
}

#[test]
fn list_runs_reports_each_runs_severity_mix_and_zeroes_unfinished_runs() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    let mut critical = finding("f-critical", "fp-critical");
    critical.severity = "critical".into();
    let mut info = finding("f-info", "fp-info");
    info.severity = "info".into();
    let high = finding("f-high", "fp-high");
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "mixed-run",
        "2026-08-20T08:00:00Z",
        vec![critical, high, info],
        &coverage,
    );
    prepare_project_run_at(
        &repository,
        "project-1",
        "/project",
        "unfinished-run",
        "2026-08-20T09:00:00Z",
    );

    let runs = repository.list_runs("project-1", 20).expect("list runs");
    let mixed = runs.iter().find(|run| run.run_id == "mixed-run").unwrap();
    assert_eq!(
        (
            mixed.severity_counts.critical,
            mixed.severity_counts.high,
            mixed.severity_counts.medium,
            mixed.severity_counts.low,
            mixed.severity_counts.info
        ),
        (1, 1, 0, 0, 1)
    );
    assert_eq!(
        mixed.severity_counts.total(),
        mixed.total_findings,
        "the severity mix accounts for every finding"
    );
    let unfinished = runs
        .iter()
        .find(|run| run.run_id == "unfinished-run")
        .unwrap();
    assert_ne!(unfinished.status, RunStatus::Completed);
    assert_eq!(unfinished.severity_counts, SeverityCounts::default());
}

#[test]
fn run_comparison_unreadable_or_missing_prior_path_is_not_evaluated() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "baseline-unreadable",
        "2026-08-20T10:00:00Z",
        vec![finding_at(
            "prior-unreadable",
            "prior-unreadable-fingerprint",
            "vulnerability",
            "src/unreadable.rs",
            FindingScope::Production,
        )],
        &CoverageManifest::from_entries([("src/unreadable.rs", ["vulnerability"])]),
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "current-skipped",
        "2026-08-20T11:00:00Z",
        Vec::new(),
        &CoverageManifest::from_entries([("src/readable.rs", ["vulnerability"])]),
    );

    let comparison = repository
        .compare_runs("current-skipped", "baseline-unreadable")
        .expect("compare covered family with skipped prior path");

    assert_eq!(comparison.len(), 1);
    assert_eq!(comparison[0].diff_status, Some(DiffStatus::NotEvaluated));
    assert_eq!(comparison[0].resolved_by_run_id, None);
}

#[test]
fn run_comparison_rejects_incomplete_current_and_incompatible_versions() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "baseline-version",
        "2026-08-20T10:00:00Z",
        vec![finding_at(
            "baseline-version-observation",
            "baseline-version-fingerprint",
            "vulnerability",
            "src/a.rs",
            FindingScope::Production,
        )],
        &coverage,
    );
    prepare_run(&repository, "incomplete-current");
    repository
        .mark_incomplete(
            "incomplete-current",
            "2026-08-20T10:30:00Z",
            "scanner_failed",
        )
        .expect("mark current incomplete");

    let incomplete_error = repository
        .compare_runs("incomplete-current", "baseline-version")
        .expect_err("incomplete current must never compare");
    assert_eq!(
        incomplete_error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );

    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "current-version",
        "2026-08-20T11:00:00Z",
        Vec::new(),
        &coverage,
    );
    {
        let mut mismatched = coverage.clone();
        mismatched.fingerprint_version = FINGERPRINT_VERSION + 1;
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                "UPDATE scan_runs SET fingerprint_version = ?2, coverage_json = ?3 WHERE id = ?1",
                params![
                    "baseline-version",
                    FINGERPRINT_VERSION + 1,
                    serde_json::to_string(&mismatched).expect("serialize coverage")
                ],
            )
            .expect("create incompatible persisted baseline fixture");
        connection
            .execute(
                "UPDATE findings SET fingerprint_version = ?2 WHERE run_id = ?1",
                params!["baseline-version", FINGERPRINT_VERSION + 1],
            )
            .expect("update fixture observation version");
    }

    let mismatch_error = repository
        .compare_runs("current-version", "baseline-version")
        .expect_err("version mismatch must never compare");
    assert_eq!(
        mismatch_error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert!(repository
        .load_run("baseline-version")
        .expect("baseline remains loadable")
        .findings
        .iter()
        .all(|finding| finding.resolved_by_run_id.is_none()));
}

#[test]
fn run_comparison_latest_compatible_baseline_is_prior_completed_and_deterministic() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let vulnerability = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    let secret = CoverageManifest::from_entries([("config.env", ["secret"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "older-compatible",
        "2026-08-20T09:00:00Z",
        Vec::new(),
        &vulnerability,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "tie-a-compatible",
        "2026-08-20T10:00:00Z",
        Vec::new(),
        &vulnerability,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "tie-z-compatible",
        "2026-08-20T10:00:00Z",
        Vec::new(),
        &vulnerability,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "offset-newest-compatible",
        "2026-08-20T18:15:00+08:00",
        Vec::new(),
        &vulnerability,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "after-cutoff-compatible",
        "2026-08-20T12:00:00Z",
        Vec::new(),
        &vulnerability,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "newer-incompatible",
        "2026-08-20T10:30:00Z",
        Vec::new(),
        &secret,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "newer-version-incompatible",
        "2026-08-20T10:45:00Z",
        Vec::new(),
        &vulnerability,
    );
    {
        let mut different_version = vulnerability.clone();
        different_version.fingerprint_version = FINGERPRINT_VERSION + 1;
        repository
            .connection
            .lock()
            .expect("lock connection")
            .execute(
                "UPDATE scan_runs SET fingerprint_version = ?2, coverage_json = ?3 WHERE id = ?1",
                params![
                    "newer-version-incompatible",
                    FINGERPRINT_VERSION + 1,
                    serde_json::to_string(&different_version).expect("serialize coverage")
                ],
            )
            .expect("create incompatible version fixture");
    }
    prepare_run(&repository, "running-never-baseline");
    prepare_run(&repository, "incomplete-never-baseline");
    repository
        .mark_incomplete(
            "incomplete-never-baseline",
            "2026-08-20T10:45:00Z",
            "scanner_failed",
        )
        .expect("mark incomplete fixture");
    complete_project_run(
        &repository,
        "project-2",
        "/other-project",
        "other-project-newest",
        "2026-08-20T10:50:00Z",
        Vec::new(),
        &vulnerability,
    );
    let selected = repository
        .latest_compatible_baseline(
            "project-1",
            FINGERPRINT_VERSION,
            &vulnerability,
            DateTime::parse_from_rfc3339("2026-08-20T11:00:00Z")
                .expect("parse cutoff")
                .with_timezone(&Utc),
        )
        .expect("select compatible baseline")
        .expect("compatible baseline exists");

    assert_eq!(selected.run_id, "offset-newest-compatible");
    assert_eq!(selected.status, RunStatus::Completed);
}

#[test]
fn completion_persists_the_selected_compatible_baseline_in_its_transaction() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "persisted-baseline",
        "2026-08-20T09:00:00Z",
        Vec::new(),
        &coverage,
    );
    prepare_run(&repository, "current-with-baseline");
    let baseline = repository
        .latest_compatible_baseline(
            "project-1",
            FINGERPRINT_VERSION,
            &coverage,
            DateTime::parse_from_rfc3339("2026-08-20T10:00:00Z")
                .expect("parse cutoff")
                .with_timezone(&Utc),
        )
        .expect("select baseline")
        .expect("baseline exists");
    let mut completed = run_detail("current-with-baseline", RunStatus::Completed, Vec::new());
    completed.completed_at = Some("2026-08-20T11:00:00Z".into());
    completed.baseline_run_id = Some(baseline.run_id);

    let stored = repository
        .complete_run(&completed, &coverage)
        .expect("complete with selected baseline");

    assert_eq!(
        stored.baseline_run_id.as_deref(),
        Some("persisted-baseline")
    );
    assert_eq!(
        repository
            .load_run("current-with-baseline")
            .expect("reload completed run")
            .baseline_run_id
            .as_deref(),
        Some("persisted-baseline")
    );
}

#[test]
fn completion_derives_an_eligible_baseline_when_caller_hint_is_none() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "derived-baseline",
        "2026-08-20T09:00:00Z",
        Vec::new(),
        &coverage,
    );
    prepare_project_run_at(
        &repository,
        "project-1",
        "/project",
        "derived-current",
        "2026-08-20T10:00:00Z",
    );
    let mut completed = run_detail("derived-current", RunStatus::Completed, Vec::new());
    completed.started_at = "2026-08-20T10:00:00Z".into();
    completed.completed_at = Some("2026-08-20T10:05:00Z".into());
    completed.baseline_run_id = None;

    let stored = repository
        .complete_run(&completed, &coverage)
        .expect("repository derives baseline");

    assert_eq!(stored.baseline_run_id.as_deref(), Some("derived-baseline"));
}

#[test]
fn completion_ignores_a_stale_non_newest_baseline_hint() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    for (run_id, completed_at) in [
        ("stale-baseline", "2026-08-20T08:00:00Z"),
        ("newest-baseline", "2026-08-20T09:00:00Z"),
    ] {
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            run_id,
            completed_at,
            Vec::new(),
            &coverage,
        );
    }
    prepare_project_run_at(
        &repository,
        "project-1",
        "/project",
        "stale-hint-current",
        "2026-08-20T10:00:00Z",
    );
    let mut completed = run_detail("stale-hint-current", RunStatus::Completed, Vec::new());
    completed.started_at = "2026-08-20T10:00:00Z".into();
    completed.completed_at = Some("2026-08-20T10:05:00Z".into());
    completed.baseline_run_id = Some("stale-baseline".into());

    let stored = repository
        .complete_run(&completed, &coverage)
        .expect("caller hint is advisory");

    assert_eq!(stored.baseline_run_id.as_deref(), Some("newest-baseline"));
}

#[test]
fn completion_excludes_runs_finishing_after_scan_start_and_retry_keeps_boundary() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "pre-start-baseline",
        "2026-08-20T09:00:00Z",
        Vec::new(),
        &coverage,
    );
    prepare_project_run_at(
        &repository,
        "project-1",
        "/project",
        "race-current",
        "2026-08-20T10:00:00Z",
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "equal-start-completion",
        "2026-08-20T10:00:00Z",
        Vec::new(),
        &coverage,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "post-start-completion",
        "2026-08-20T10:30:00Z",
        Vec::new(),
        &coverage,
    );
    let mut completed = run_detail("race-current", RunStatus::Completed, Vec::new());
    completed.started_at = "2026-08-20T10:00:00Z".into();
    completed.completed_at = Some("2026-08-20T11:00:00Z".into());
    completed.baseline_run_id = Some("post-start-completion".into());

    let first = repository
        .complete_run(&completed, &coverage)
        .expect("complete with authoritative cutoff");
    completed.baseline_run_id = None;
    let retried = repository
        .complete_run(&completed, &coverage)
        .expect("retry returns durable boundary");

    assert_eq!(first.baseline_run_id.as_deref(), Some("pre-start-baseline"));
    assert_eq!(retried.baseline_run_id, first.baseline_run_id);
}

#[test]
fn completion_rejects_invalid_or_reversed_current_timestamps_before_writes() {
    for (run_id, started_at, completed_at) in [
        (
            "invalid-current-start",
            "not-rfc3339",
            Some("2026-08-20T11:00:00Z"),
        ),
        (
            "invalid-current-complete",
            "2026-08-20T10:00:00Z",
            Some("not-rfc3339"),
        ),
        (
            "reversed-current-time",
            "2026-08-20T10:00:00Z",
            Some("2026-08-20T09:59:59Z"),
        ),
        ("missing-current-complete", "2026-08-20T10:00:00Z", None),
    ] {
        let repository = FindingsRepository::open_in_memory().expect("open repository");
        let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
        prepare_project_run_at(&repository, "project-1", "/project", run_id, started_at);
        let mut completed = run_detail(
            run_id,
            RunStatus::Completed,
            vec![finding_at(
                &format!("{run_id}-observation"),
                &format!("{run_id}-fingerprint"),
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            )],
        );
        completed.started_at = started_at.into();
        completed.completed_at = completed_at.map(Into::into);

        let error = repository
            .complete_run(&completed, &coverage)
            .expect_err("invalid current timestamps must fail");

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_running_without_findings(&repository, run_id);
    }
}

#[test]
fn completion_rejects_invalid_or_missing_candidate_timestamp_before_writes() {
    for (current_run, corrupt_timestamp) in [
        ("invalid-candidate-current", Some("not-rfc3339")),
        ("missing-candidate-current", None),
    ] {
        let repository = FindingsRepository::open_in_memory().expect("open repository");
        let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            "corrupt-candidate",
            "2026-08-20T09:00:00Z",
            Vec::new(),
            &coverage,
        );
        repository
            .connection
            .lock()
            .expect("lock connection")
            .execute(
                "UPDATE scan_runs SET completed_at = ?2 WHERE id = ?1",
                params!["corrupt-candidate", corrupt_timestamp],
            )
            .expect("corrupt candidate timestamp");
        prepare_project_run_at(
            &repository,
            "project-1",
            "/project",
            current_run,
            "2026-08-20T10:00:00Z",
        );
        let mut completed = run_detail(
            current_run,
            RunStatus::Completed,
            vec![finding_at(
                &format!("{current_run}-observation"),
                &format!("{current_run}-fingerprint"),
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            )],
        );
        completed.started_at = "2026-08-20T10:00:00Z".into();
        completed.completed_at = Some("2026-08-20T11:00:00Z".into());

        let error = repository
            .complete_run(&completed, &coverage)
            .expect_err("corrupt candidate timestamp must fail safe");

        assert_eq!(
            error.code,
            crate::findings::error::ErrorCode::PersistenceUnavailable
        );
        assert_running_without_findings(&repository, current_run);
    }
}

#[test]
fn latest_compatible_baseline_orders_and_cuts_off_exact_nanoseconds() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    for (run_id, completed_at) in [
        ("z-older-nanosecond", "2026-08-20T09:00:00.000000001Z"),
        ("a-newer-nanosecond", "2026-08-20T09:00:00.000000002Z"),
        ("after-nanosecond-cutoff", "2026-08-20T09:00:00.000000004Z"),
    ] {
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            run_id,
            completed_at,
            Vec::new(),
            &coverage,
        );
    }

    let selected = repository
        .latest_compatible_baseline(
            "project-1",
            FINGERPRINT_VERSION,
            &coverage,
            DateTime::parse_from_rfc3339("2026-08-20T09:00:00.000000003Z")
                .expect("parse nanosecond cutoff")
                .with_timezone(&Utc),
        )
        .expect("select exact baseline")
        .expect("baseline exists");

    assert_eq!(selected.run_id, "a-newer-nanosecond");
}

#[test]
fn completed_run_and_restart_load_reconstruct_the_persisted_comparison_boundary() {
    let temporary = tempfile::tempdir().expect("temporary repository root");
    let database = temporary.path().join("private/findings.sqlite3");
    let repository = FindingsRepository::open(&database).expect("open repository");
    let baseline_coverage = CoverageManifest::from_entries([
        ("src/a.rs", ["vulnerability"]),
        ("src/b.rs", ["vulnerability"]),
        ("config/c.env", ["secret"]),
    ]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "restart-baseline",
        "2026-08-20T09:00:00Z",
        vec![
            finding_at(
                "restart-baseline-a",
                "restart-fingerprint-a",
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            ),
            finding_at(
                "restart-baseline-b",
                "restart-fingerprint-b",
                "vulnerability",
                "src/b.rs",
                FindingScope::Test,
            ),
            finding_at(
                "restart-baseline-c",
                "restart-fingerprint-c",
                "secret",
                "config/c.env",
                FindingScope::Documentation,
            ),
        ],
        &baseline_coverage,
    );
    let current_coverage = CoverageManifest::from_entries([
        ("src/a.rs", ["vulnerability"]),
        ("src/b.rs", ["vulnerability"]),
        ("src/d.rs", ["vulnerability"]),
    ]);
    prepare_run(&repository, "restart-current");
    let baseline = repository
        .latest_compatible_baseline(
            "project-1",
            FINGERPRINT_VERSION,
            &current_coverage,
            DateTime::parse_from_rfc3339("2026-08-20T10:00:00Z")
                .expect("parse cutoff")
                .with_timezone(&Utc),
        )
        .expect("select baseline")
        .expect("baseline exists");
    let mut completed = run_detail(
        "restart-current",
        RunStatus::Completed,
        vec![
            finding_at(
                "restart-current-a",
                "restart-fingerprint-a",
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            ),
            finding_at(
                "restart-current-d",
                "restart-fingerprint-d",
                "vulnerability",
                "src/d.rs",
                FindingScope::Fixture,
            ),
        ],
    );
    completed.completed_at = Some("2026-08-20T11:00:00Z".into());
    completed.baseline_run_id = Some(baseline.run_id);

    let committed = repository
        .complete_run(&completed, &current_coverage)
        .expect("commit current run");
    assert_comparison_statuses(&committed);
    drop(repository);

    let reopened = FindingsRepository::open(&database).expect("reopen repository");
    let loaded = reopened
        .load_run("restart-current")
        .expect("load comparison after restart");
    assert_comparison_statuses(&loaded);
    assert_eq!(loaded.baseline_run_id.as_deref(), Some("restart-baseline"));
    let connection = reopened.connection.lock().expect("lock connection");
    let current_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE run_id = 'restart-current'",
            [],
            |row| row.get(0),
        )
        .expect("count immutable current observations");
    let baseline_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE run_id = 'restart-baseline'",
            [],
            |row| row.get(0),
        )
        .expect("count immutable baseline observations");
    assert_eq!(current_rows, 2);
    assert_eq!(baseline_rows, 3);
}

#[test]
fn latest_project_observation_projection_is_one_bounded_raw_pass() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let identities = 24usize;
    let runs = 9usize;
    for run in 0..runs {
        let completed_at = if run == runs - 1 {
            "2026-08-20T09:08:00.000000008-01:00".to_owned()
        } else {
            format!("2026-08-20T10:{run:02}:00.00000000{run}Z")
        };
        let findings = (0..identities)
            .map(|identity| {
                finding_at(
                    &format!("observation-{run}-{identity}"),
                    &format!("fingerprint-{identity}"),
                    "vulnerability",
                    &format!("src/{identity}.rs"),
                    FindingScope::Production,
                )
            })
            .collect::<Vec<_>>();
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            &format!("projection-run-{run:02}"),
            &completed_at,
            findings,
            &CoverageManifest::from_entries([("src", ["vulnerability"])]),
        );
    }

    let (observations, work) = repository
        .latest_project_observations_with_work("project-1")
        .expect("project observations");

    assert_eq!(work.queries, 1);
    assert_eq!(work.rows_visited, identities * runs);
    assert_eq!(work.payloads_deserialized, identities);
    assert_eq!(observations.len(), identities);
    assert!(observations
        .iter()
        .all(|finding| finding.observation_run_id == "projection-run-08"));

    {
        let connection = repository.connection.lock().unwrap();
        connection
            .execute(
                "UPDATE scan_runs SET completed_at = 'not-rfc3339' WHERE id = 'projection-run-00'",
                [],
            )
            .unwrap();
    }
    assert_eq!(
        repository
            .latest_project_observations("project-1")
            .unwrap_err()
            .code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
}

fn assert_comparison_statuses(run: &ScanRunDetail) {
    let statuses = run
        .findings
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding.diff_status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(run.findings.len(), 4);
    assert_eq!(
        statuses["restart-fingerprint-a"],
        Some(DiffStatus::Unchanged)
    );
    assert_eq!(statuses["restart-fingerprint-d"], Some(DiffStatus::New));
    assert_eq!(
        statuses["restart-fingerprint-b"],
        Some(DiffStatus::Resolved)
    );
    assert_eq!(
        statuses["restart-fingerprint-c"],
        Some(DiffStatus::NotEvaluated)
    );
}

#[test]
fn retention_policy_defaults_to_twenty_runs_and_ninety_days() {
    assert_eq!(
        RetentionPolicy::default(),
        RetentionPolicy {
            max_completed_runs_per_project: 20,
            max_age_days: 90,
        }
    );
}

#[test]
fn retention_zero_removes_all_completed_runs_per_project_but_never_other_records() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    for (project_id, path, run_id, observation_id, fingerprint) in [
        (
            "project-1",
            "/project",
            "p1-completed",
            "p1-observation",
            "p1-fingerprint",
        ),
        (
            "project-2",
            "/other",
            "p2-completed",
            "p2-observation",
            "p2-fingerprint",
        ),
    ] {
        complete_project_run(
            &repository,
            project_id,
            path,
            run_id,
            "2026-08-20T10:00:00Z",
            vec![finding_at(
                observation_id,
                fingerprint,
                "vulnerability",
                "src/a.rs",
                FindingScope::Production,
            )],
            &coverage,
        );
    }
    prepare_project_run(&repository, "project-1", "/project", "p1-running");
    prepare_project_run(&repository, "project-2", "/other", "p2-incomplete");
    repository
        .mark_incomplete("p2-incomplete", "2026-08-20T10:30:00Z", "cancelled")
        .expect("mark incomplete fixture");
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason,
                         gates_json, origin, updated_at
                       ) VALUES ('retained-zero-review', 'project-1', ?1, 'p1-fingerprint',
                                 'falsePositive', 'review survives', '[]', 'local',
                                 '2026-08-20T10:05:00Z')"#,
                [FINGERPRINT_VERSION],
            )
            .expect("insert retained review");
    }

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-20T12:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 0,
                max_age_days: 90,
            },
        )
        .expect("apply zero retention");

    assert_eq!(deleted, 2);
    let connection = repository.connection.lock().expect("lock connection");
    let retained_runs = {
        let mut statement = connection
            .prepare("SELECT id FROM scan_runs ORDER BY id")
            .expect("prepare retained runs");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query retained runs")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect retained runs")
    };
    assert_eq!(retained_runs, vec!["p1-running", "p2-incomplete"]);
    let projects: i64 = connection
        .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
        .expect("count projects");
    let reviews: i64 = connection
        .query_row("SELECT COUNT(*) FROM reviews", [], |row| row.get(0))
        .expect("count reviews");
    let findings: i64 = connection
        .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
        .expect("count findings");
    assert_eq!(projects, 2);
    assert_eq!(reviews, 1);
    assert_eq!(findings, 0);
}

#[test]
fn retention_uses_strict_age_cutoff_and_stable_count_ties_per_project() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    for (run_id, completed_at) in [
        ("expired", "2026-05-22T11:59:59Z"),
        ("at-cutoff", "2026-05-22T12:00:00Z"),
        ("tie-a", "2026-08-20T10:00:00Z"),
        ("tie-z", "2026-08-20T10:00:00Z"),
    ] {
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            run_id,
            completed_at,
            Vec::new(),
            &coverage,
        );
    }
    complete_project_run(
        &repository,
        "project-2",
        "/other",
        "other-retained",
        "2026-08-20T09:00:00Z",
        Vec::new(),
        &coverage,
    );

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-20T12:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 1,
                max_age_days: 90,
            },
        )
        .expect("apply bounded retention");

    assert_eq!(deleted, 3);
    let connection = repository.connection.lock().expect("lock connection");
    let retained = {
        let mut statement = connection
            .prepare("SELECT id FROM scan_runs ORDER BY id")
            .expect("prepare retained query");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query retained runs")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect retained runs")
    };
    assert_eq!(retained, vec!["other-retained", "tie-z"]);
}

#[test]
fn retention_age_cutoff_compares_rfc3339_instants_not_timestamp_text() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "offset-expired",
        "2026-05-22T19:59:59+08:00",
        Vec::new(),
        &coverage,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "offset-at-cutoff",
        "2026-05-22T20:00:00+08:00",
        Vec::new(),
        &coverage,
    );

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-20T12:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 20,
                max_age_days: 90,
            },
        )
        .expect("apply age retention");

    assert_eq!(deleted, 1);
    assert!(repository.load_run("offset-expired").is_err());
    assert_eq!(
        repository
            .load_run("offset-at-cutoff")
            .expect("exact cutoff is retained")
            .status,
        RunStatus::Completed
    );
}

#[test]
fn retention_age_cutoff_preserves_exact_nanoseconds() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "nano-expired",
        "2026-08-20T10:00:00.000000001Z",
        Vec::new(),
        &coverage,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "nano-at-cutoff",
        "2026-08-20T10:00:00.000000002Z",
        Vec::new(),
        &coverage,
    );

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-20T10:00:00.000000002Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 20,
                max_age_days: 0,
            },
        )
        .expect("apply nanosecond age retention");

    assert_eq!(deleted, 1);
    assert!(repository.load_run("nano-expired").is_err());
    assert_eq!(
        repository
            .load_run("nano-at-cutoff")
            .expect("exact nanosecond cutoff is retained")
            .status,
        RunStatus::Completed
    );
}

#[test]
fn retention_count_order_uses_exact_nanoseconds_before_run_id() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "z-older-count",
        "2026-08-20T10:00:00.000000001Z",
        Vec::new(),
        &coverage,
    );
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "a-newer-count",
        "2026-08-20T10:00:00.000000002Z",
        Vec::new(),
        &coverage,
    );

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-21T10:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 1,
                max_age_days: 90,
            },
        )
        .expect("apply nanosecond count retention");

    assert_eq!(deleted, 1);
    assert!(repository.load_run("z-older-count").is_err());
    assert_eq!(
        repository
            .load_run("a-newer-count")
            .expect("newer nanosecond is retained")
            .status,
        RunStatus::Completed
    );
}

#[test]
fn retention_invalid_completed_timestamp_rolls_back_without_deletion() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    for (run_id, completed_at) in [
        ("valid-retention-run", "2026-08-20T10:00:00Z"),
        ("corrupt-retention-run", "2026-08-20T10:00:01Z"),
    ] {
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            run_id,
            completed_at,
            Vec::new(),
            &coverage,
        );
    }
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
                .execute(
                    "UPDATE scan_runs SET completed_at = 'not-rfc3339' WHERE id = 'corrupt-retention-run'",
                    [],
                )
                .expect("corrupt stored timestamp");
    }

    let error = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-21T10:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 0,
                max_age_days: 90,
            },
        )
        .expect_err("invalid completed timestamp must abort retention");
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let connection = repository.connection.lock().expect("lock connection");
    let retained: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE status = 'completed'",
            [],
            |row| row.get(0),
        )
        .expect("count retained completed runs");
    assert_eq!(retained, 2);
}

#[test]
fn maintenance_failure_after_completion_returns_safe_warning_and_keeps_saved_run() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "maintenance-failure-run");
    let completed = run_detail(
        "maintenance-failure-run",
        RunStatus::Completed,
        vec![finding(
            "maintenance-failure-observation",
            "maintenance-failure-fingerprint",
        )],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let returned = repository
        .complete_run_with_maintenance_hook(&completed, &coverage, || {
            let committed = repository
                .load_run("maintenance-failure-run")
                .expect("completion must commit before maintenance starts");
            assert_eq!(committed.status, RunStatus::Completed);
            assert_eq!(committed.persistence, RunPersistence::Saved);
            Err(CommandError {
                code: crate::findings::error::ErrorCode::PersistenceUnavailable,
                message: "sensitive sqlite failure text".into(),
                detail: Some("raw database error".into()),
                retryable: true,
            })
        })
        .expect("maintenance failure must not fail completed persistence");

    assert_eq!(returned.status, RunStatus::Completed);
    assert_eq!(returned.persistence, RunPersistence::Saved);
    let warning = returned
        .maintenance_warning
        .as_deref()
        .expect("separate maintenance warning");
    assert_eq!(
        warning,
        "Run saved, but old scan history could not be cleaned up."
    );
    assert!(!warning.contains("sqlite"));
    assert!(!warning.contains("database"));
    let loaded = repository
        .load_run("maintenance-failure-run")
        .expect("completed run remains loadable");
    assert_eq!(loaded.status, RunStatus::Completed);
    assert_eq!(loaded.persistence, RunPersistence::Saved);
    assert_eq!(loaded.maintenance_warning, None);
}

#[test]
fn successful_maintenance_reload_failure_propagates_without_hiding_durable_run() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "maintenance-reload-failure-run");
    let completed = run_detail(
        "maintenance-reload-failure-run",
        RunStatus::Completed,
        vec![finding(
            "maintenance-reload-failure-observation",
            "maintenance-reload-failure-fingerprint",
        )],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    repository.fail_next_post_maintenance_reload_for_test();

    let error = repository
        .complete_run_with_maintenance(
            &completed,
            &coverage,
            RetentionPolicy::default(),
            DateTime::parse_from_rfc3339("2026-08-20T10:00:08Z")
                .expect("parse maintenance time")
                .with_timezone(&Utc),
        )
        .expect_err("post-maintenance reload failure must propagate");

    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    let durable = repository
        .load_run("maintenance-reload-failure-run")
        .expect("current run remains durable");
    assert_eq!(durable.status, RunStatus::Completed);
    assert_eq!(durable.findings.len(), 1);
}

#[test]
fn maintenance_zero_count_is_a_safe_failure_and_keeps_the_completed_run() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "maintenance-zero-count");
    let completed = run_detail(
        "maintenance-zero-count",
        RunStatus::Completed,
        vec![finding("zero-count-observation", "zero-count-fingerprint")],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let returned = repository
        .complete_run_with_maintenance(
            &completed,
            &coverage,
            RetentionPolicy {
                max_completed_runs_per_project: 0,
                max_age_days: 90,
            },
            DateTime::parse_from_rfc3339("2026-08-20T10:00:08Z")
                .expect("parse maintenance time")
                .with_timezone(&Utc),
        )
        .expect("zero count maintenance is isolated from completion");

    assert_eq!(returned.persistence, RunPersistence::Saved);
    assert_eq!(
        returned.maintenance_warning.as_deref(),
        Some(RETENTION_MAINTENANCE_WARNING)
    );
    let loaded = repository
        .load_run("maintenance-zero-count")
        .expect("completed run remains loadable");
    assert_eq!(loaded.persistence, RunPersistence::Saved);
    assert_eq!(loaded.findings.len(), 1);
}

#[test]
fn maintenance_zero_age_is_a_safe_failure_and_keeps_the_completed_run() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    prepare_run(&repository, "maintenance-zero-age");
    let completed = run_detail(
        "maintenance-zero-age",
        RunStatus::Completed,
        vec![finding("zero-age-observation", "zero-age-fingerprint")],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);

    let returned = repository
        .complete_run_with_maintenance(
            &completed,
            &coverage,
            RetentionPolicy {
                max_completed_runs_per_project: 20,
                max_age_days: 0,
            },
            DateTime::parse_from_rfc3339("2026-08-20T10:00:07Z")
                .expect("parse maintenance time")
                .with_timezone(&Utc),
        )
        .expect("zero age maintenance is isolated from completion");

    assert_eq!(returned.persistence, RunPersistence::Saved);
    assert_eq!(
        returned.maintenance_warning.as_deref(),
        Some(RETENTION_MAINTENANCE_WARNING)
    );
    let loaded = repository
        .load_run("maintenance-zero-age")
        .expect("completed run remains loadable");
    assert_eq!(loaded.persistence, RunPersistence::Saved);
    assert_eq!(loaded.findings.len(), 1);
}

#[test]
fn successful_maintenance_returns_the_post_retention_projection_and_protects_current() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    let coverage = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "maintenance-baseline",
        "2026-08-20T09:00:00Z",
        vec![finding_at(
            "maintenance-baseline-observation",
            "maintenance-baseline-fingerprint",
            "vulnerability",
            "src/a.rs",
            FindingScope::Production,
        )],
        &coverage,
    );
    prepare_project_run_at(
        &repository,
        "project-1",
        "/project",
        "maintenance-current",
        "2026-08-20T10:00:00Z",
    );
    let mut completed = run_detail(
        "maintenance-current",
        RunStatus::Completed,
        vec![finding_at(
            "maintenance-current-observation",
            "maintenance-current-fingerprint",
            "vulnerability",
            "src/a.rs",
            FindingScope::Production,
        )],
    );
    completed.completed_at = Some("2026-08-20T10:00:07Z".into());

    let returned = repository
        .complete_run_with_maintenance(
            &completed,
            &coverage,
            RetentionPolicy {
                max_completed_runs_per_project: 1,
                max_age_days: 1,
            },
            DateTime::parse_from_rfc3339("2026-08-22T10:00:07Z")
                .expect("parse maintenance time")
                .with_timezone(&Utc),
        )
        .expect("complete and retain current run");
    let reloaded = repository
        .load_run("maintenance-current")
        .expect("reload current after maintenance");

    assert_eq!(returned.baseline_run_id, None);
    assert_eq!(returned.findings.len(), 1);
    assert_eq!(returned.findings[0].diff_status, Some(DiffStatus::New));
    assert_eq!(
        serde_json::to_value(&returned).expect("serialize immediate result"),
        serde_json::to_value(&reloaded).expect("serialize restart result")
    );
    assert!(repository.load_run("maintenance-baseline").is_err());
    let connection = repository.connection.lock().expect("lock connection");
    let stored_boundary: Option<String> = connection
        .query_row(
            "SELECT baseline_run_id FROM scan_runs WHERE id = 'maintenance-current'",
            [],
            |row| row.get(0),
        )
        .expect("load cleared baseline boundary");
    assert_eq!(stored_boundary, None);
}

#[test]
fn retention_deletes_only_completed_run_evidence() {
    let repository = FindingsRepository::open_in_memory().expect("open repository");
    for (run_id, observation_id, fingerprint, completed_at) in [
        (
            "old-run",
            "old-observation",
            "old-fingerprint",
            "2026-01-01T00:00:00Z",
        ),
        (
            "middle-run",
            "middle-observation",
            "middle-fingerprint",
            "2026-08-18T00:00:00Z",
        ),
        (
            "new-run",
            "new-observation",
            "new-fingerprint",
            "2026-08-19T00:00:00Z",
        ),
    ] {
        complete_project_run(
            &repository,
            "project-1",
            "/project",
            run_id,
            completed_at,
            vec![finding(observation_id, fingerprint)],
            &CoverageManifest::from_entries([("src/config.rs", ["secret"])]),
        );
    }
    prepare_run(&repository, "running-run");
    {
        let connection = repository.connection.lock().expect("lock connection");
        connection
            .execute(
                r#"INSERT INTO reviews(
                         id, project_id, fingerprint_version, fingerprint, state, reason,
                         gates_json, origin, updated_at
                       ) VALUES ('retained-review', 'project-1', ?1, 'old-fingerprint',
                                 'falsePositive', 'review survives', '[]', 'local',
                                 '2026-08-20T00:00:00Z')"#,
                [FINGERPRINT_VERSION],
            )
            .expect("insert retained review");
    }

    let deleted = repository
        .apply_retention(
            DateTime::parse_from_rfc3339("2026-08-20T00:00:00Z")
                .expect("parse retention time")
                .with_timezone(&Utc),
            RetentionPolicy {
                max_completed_runs_per_project: 1,
                max_age_days: 19,
            },
        )
        .expect("apply retention");

    assert_eq!(deleted, 2);
    let connection = repository.connection.lock().expect("lock connection");
    let run_ids = {
        let mut statement = connection
            .prepare("SELECT id FROM scan_runs ORDER BY id")
            .expect("prepare retained runs query");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query retained runs")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect retained runs")
    };
    assert_eq!(run_ids, vec!["new-run", "running-run"]);
    let findings: i64 = connection
        .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
        .expect("count retained findings");
    let projects: i64 = connection
        .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
        .expect("count retained projects");
    let reviews: i64 = connection
        .query_row("SELECT COUNT(*) FROM reviews", [], |row| row.get(0))
        .expect("count retained reviews");
    assert_eq!(findings, 1);
    assert_eq!(projects, 1);
    assert_eq!(reviews, 1);
}

#[cfg(unix)]
#[test]
fn missing_database_parent_is_created_owner_only() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("private");
    let database = parent.join("findings.sqlite3");

    let repository = FindingsRepository::open(&database).expect("open file repository");
    let connection = repository.connection.lock().expect("lock connection");
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("query journal mode");

    assert_eq!(journal_mode, "wal");
    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&database), 0o600);
}

#[cfg(unix)]
#[test]
fn existing_insecure_parent_is_rejected_without_changing_its_mode() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("shared");
    std::fs::create_dir(&parent).expect("create shared parent");
    set_mode(&parent, 0o755);
    let database = parent.join("findings.sqlite3");

    let result = FindingsRepository::open(&database);

    assert!(result.is_err());
    assert_eq!(mode(&parent), 0o755);
    assert!(!database.exists());
}

#[cfg(unix)]
#[test]
fn symlink_database_parent_is_rejected() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary root");
    let real_parent = temporary.path().join("real-parent");
    std::fs::create_dir(&real_parent).expect("create real parent");
    set_mode(&real_parent, 0o700);
    let linked_parent = temporary.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).expect("create parent symlink");

    let result = FindingsRepository::open(linked_parent.join("findings.sqlite3"));

    assert!(result.is_err());
    assert!(!real_parent.join("findings.sqlite3").exists());
    assert_eq!(mode(&real_parent), 0o700);
}

#[cfg(unix)]
#[test]
fn symlink_database_file_is_rejected() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("private");
    std::fs::create_dir(&parent).expect("create private parent");
    set_mode(&parent, 0o700);
    let real_database = parent.join("real.sqlite3");
    std::fs::write(&real_database, []).expect("create target file");
    set_mode(&real_database, 0o600);
    let linked_database = parent.join("linked.sqlite3");
    symlink(&real_database, &linked_database).expect("create database symlink");

    let result = FindingsRepository::open(&linked_database);

    assert!(result.is_err());
    assert_eq!(mode(&real_database), 0o600);
    assert_eq!(
        std::fs::metadata(&real_database)
            .expect("target metadata")
            .len(),
        0
    );
}

#[cfg(unix)]
#[test]
fn existing_private_parent_accepts_a_new_database() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("private");
    std::fs::create_dir(&parent).expect("create private parent");
    set_mode(&parent, 0o700);
    let database = parent.join("findings.sqlite3");

    FindingsRepository::open(&database).expect("open database in private parent");

    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&database), 0o600);
}

#[cfg(unix)]
#[test]
fn parent_symlink_swap_is_rejected_without_writing_attacker_target() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("database-parent");
    let parked_parent = temporary.path().join("parked-parent");
    let attacker_parent = temporary.path().join("attacker-parent");
    std::fs::create_dir(&parent).expect("create original parent");
    std::fs::create_dir(&attacker_parent).expect("create attacker parent");
    set_mode(&parent, 0o700);
    set_mode(&attacker_parent, 0o700);
    std::fs::write(parent.join("marker"), "original").expect("write original marker");
    std::fs::write(attacker_parent.join("marker"), "attacker").expect("write attacker marker");
    let database = parent.join("findings.sqlite3");

    let result = FindingsRepository::open_with_test_parent_hook(&database, || {
        std::fs::rename(&parent, &parked_parent).expect("park original parent");
        symlink(&attacker_parent, &parent).expect("swap parent for symlink");
    });

    let error = match result {
        Err(error) => error,
        Ok(_) => panic!(
            "parent identity swap must fail (attacker_db_exists={})",
            attacker_parent.join("findings.sqlite3").exists()
        ),
    };
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(error.message, "Scan results could not be saved.");
    assert_eq!(error.detail, None);
    assert!(!parked_parent.join("findings.sqlite3").exists());
    assert!(!attacker_parent.join("findings.sqlite3").exists());
    assert_eq!(mode(&parked_parent), 0o700);
    assert_eq!(mode(&attacker_parent), 0o700);
    assert_eq!(
        std::fs::read_to_string(parked_parent.join("marker")).expect("original marker"),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(attacker_parent.join("marker")).expect("attacker marker"),
        "attacker"
    );
}

#[cfg(unix)]
#[test]
fn parent_regular_directory_swap_is_rejected_without_writing_replacement() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let parent = temporary.path().join("database-parent");
    let parked_parent = temporary.path().join("parked-parent");
    std::fs::create_dir(&parent).expect("create original parent");
    set_mode(&parent, 0o700);
    std::fs::write(parent.join("marker"), "original").expect("write original marker");
    let database = parent.join("findings.sqlite3");

    let result = FindingsRepository::open_with_test_parent_hook(&database, || {
        std::fs::rename(&parent, &parked_parent).expect("park original parent");
        std::fs::create_dir(&parent).expect("create replacement parent");
        set_mode(&parent, 0o700);
        std::fs::write(parent.join("marker"), "replacement").expect("write replacement marker");
    });

    let error = match result {
        Err(error) => error,
        Ok(_) => panic!(
            "parent identity replacement must fail (replacement_db_exists={})",
            database.exists()
        ),
    };
    assert_eq!(
        error.code,
        crate::findings::error::ErrorCode::PersistenceUnavailable
    );
    assert_eq!(error.message, "Scan results could not be saved.");
    assert_eq!(error.detail, None);
    assert!(!parked_parent.join("findings.sqlite3").exists());
    assert!(!parent.join("findings.sqlite3").exists());
    assert_eq!(mode(&parked_parent), 0o700);
    assert_eq!(mode(&parent), 0o700);
    assert_eq!(
        std::fs::read_to_string(parked_parent.join("marker")).expect("original marker"),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(parent.join("marker")).expect("replacement marker"),
        "replacement"
    );
}

#[test]
fn legacy_stored_summary_defaults_git_context_to_unavailable() {
    let mut stored = serde_json::to_value(StoredScanSummary::from(&summary(0))).unwrap();
    stored.as_object_mut().unwrap().remove("gitContext");
    let legacy: StoredScanSummary = serde_json::from_value(stored).unwrap();
    let projection: ScanSummary = legacy.into();
    assert!(projection.git_context.is_none());
}

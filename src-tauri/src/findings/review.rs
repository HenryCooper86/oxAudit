use std::{collections::HashSet, path::Path};

use chrono::{DateTime, SecondsFormat, Utc};

use super::{
    domain::{ReviewOrigin, ReviewRecord, ReviewRequest, ReviewState},
    error::CommandError,
    policy::{
        apply_policy, contains_credential_material, load_policy, update_policy_decision,
        validate_portable_review_fields,
    },
    repository::FindingsRepository,
};
use crate::triage::gates::{Disposition, GateVerdict, Triage, ALL_GATES};

pub fn validate_review(
    request: &ReviewRequest,
    authoritative_category: &str,
) -> Result<(), CommandError> {
    validate_review_at(request, authoritative_category, Utc::now())
}

fn validate_review_at(
    request: &ReviewRequest,
    authoritative_category: &str,
    now: DateTime<Utc>,
) -> Result<(), CommandError> {
    if request.category != authoritative_category
        || !matches!(authoritative_category, "secret" | "vulnerability")
    {
        return Err(CommandError::review_invalid());
    }
    if request.state == ReviewState::Candidate {
        if request.reason.trim().is_empty()
            && request.evidence.is_none()
            && request.entry_point.is_none()
            && request.data_flow.is_none()
            && request.gates.is_empty()
            && request.deciding_gate.is_none()
            && request.expires_at.is_none()
        {
            return Ok(());
        }
        return Err(CommandError::review_invalid());
    }
    if request.reason.trim().is_empty()
        || [
            request.evidence.as_deref(),
            request.entry_point.as_deref(),
            request.data_flow.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.trim().is_empty())
        || request.expires_at.as_deref().is_some_and(|expires_at| {
            DateTime::parse_from_rfc3339(expires_at)
                .map(|expires_at| expires_at.with_timezone(&Utc) <= now)
                .unwrap_or(true)
        })
    {
        return Err(CommandError::review_invalid());
    }
    if std::iter::once(request.reason.as_str())
        .chain(request.evidence.as_deref())
        .chain(request.entry_point.as_deref())
        .chain(request.data_flow.as_deref())
        .chain(request.gates.iter().map(|note| note.evidence.as_str()))
        .any(contains_credential_material)
    {
        return Err(CommandError::review_invalid());
    }
    if request.origin == ReviewOrigin::ProjectPolicy
        && (request.state == ReviewState::Confirmed
            || !validate_portable_review_fields(request, &now))
    {
        return Err(CommandError::review_invalid());
    }

    match (authoritative_category, request.state) {
        ("vulnerability", ReviewState::Confirmed) => {
            if request.gates.len() != ALL_GATES.len()
                || request.deciding_gate.is_some()
                || request
                    .gates
                    .iter()
                    .any(|note| note.verdict != GateVerdict::Survives)
            {
                return Err(CommandError::review_invalid());
            }
            Triage::new(
                &request.fingerprint,
                Disposition::Confirmed,
                request.gates.clone(),
                timestamp(now),
            )
            .map_err(|_| CommandError::review_invalid())?;
        }
        ("vulnerability", ReviewState::FalsePositive) => {
            let deciding_gate = request
                .deciding_gate
                .ok_or_else(CommandError::review_invalid)?;
            let mut seen = HashSet::new();
            let mut eliminating = 0usize;
            for note in &request.gates {
                if !seen.insert(note.gate)
                    || note.evidence.trim().is_empty()
                    || note.verdict == GateVerdict::Unknown
                {
                    return Err(CommandError::review_invalid());
                }
                if note.verdict == GateVerdict::Eliminates {
                    eliminating += 1;
                    if note.gate != deciding_gate {
                        return Err(CommandError::review_invalid());
                    }
                }
            }
            if eliminating != 1 {
                return Err(CommandError::review_invalid());
            }
            Triage::new(
                &request.fingerprint,
                Disposition::Eliminated {
                    gate: deciding_gate,
                },
                request.gates.clone(),
                timestamp(now),
            )
            .map_err(|_| CommandError::review_invalid())?;
        }
        ("secret", ReviewState::Confirmed | ReviewState::FalsePositive)
        | (_, ReviewState::AcceptedRisk | ReviewState::Suppressed) => {
            if request.evidence.is_some()
                || request.entry_point.is_some()
                || request.data_flow.is_some()
                || !request.gates.is_empty()
                || request.deciding_gate.is_some()
            {
                return Err(CommandError::review_invalid());
            }
        }
        _ => return Err(CommandError::review_invalid()),
    }
    Ok(())
}

pub fn save_local_review(
    repository: &FindingsRepository,
    request: &ReviewRequest,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    let observation = repository.latest_observation(
        &request.project_id,
        request.fingerprint_version,
        &request.fingerprint,
    )?;
    if request.origin != ReviewOrigin::Local {
        return Err(CommandError::review_invalid());
    }
    validate_review_at(request, &observation.category, now)?;
    repository.save_review_event(&record_from_request(request, None, now))
}

pub fn save_project_policy_review(
    repository: &FindingsRepository,
    project_root: impl AsRef<Path>,
    request: &ReviewRequest,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    save_project_policy_review_with_reconcile(
        repository,
        project_root.as_ref(),
        request,
        now,
        |repository, review| {
            let (stored, inserted) = repository.reconcile_project_policy_event(review)?;
            if !inserted && review.state == ReviewState::Candidate && stored.id == review.id {
                repository.save_review_event(review)
            } else {
                Ok(stored)
            }
        },
    )
}

fn save_project_policy_review_with_reconcile<F>(
    repository: &FindingsRepository,
    project_root: &Path,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    reconcile: F,
) -> Result<ReviewRecord, CommandError>
where
    F: FnOnce(&FindingsRepository, &ReviewRecord) -> Result<ReviewRecord, CommandError>,
{
    let observation = repository.latest_observation(
        &request.project_id,
        request.fingerprint_version,
        &request.fingerprint,
    )?;
    if request.origin != ReviewOrigin::ProjectPolicy {
        return Err(CommandError::review_invalid());
    }
    validate_review_at(request, &observation.category, now)?;

    update_policy_decision(project_root, &observation, request, now)?;
    let loaded = load_policy(project_root)?;
    let authoritative = apply_policy(
        &loaded,
        &request.project_id,
        observation.fingerprint_version,
        &observation.fingerprint,
        &observation.category,
        &observation.rule_id,
        &observation.file_path,
        None,
        now,
    )?;
    reconcile(repository, &authoritative).map_err(|_| CommandError::policy_write_failed())
}

pub fn reconcile_project_policy_reviews(
    repository: &FindingsRepository,
    project_root: impl AsRef<Path>,
    project_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, CommandError> {
    let loaded = load_policy(project_root)?;
    if matches!(loaded.status(), super::domain::PolicyStatus::Invalid { .. }) {
        return Err(CommandError::policy_invalid());
    }
    let reviews = repository
        .latest_project_observations(project_id)?
        .into_iter()
        .map(|observation| {
            apply_policy(
                &loaded,
                project_id,
                observation.fingerprint_version,
                &observation.fingerprint,
                &observation.category,
                &observation.rule_id,
                &observation.file_path,
                None,
                now,
            )
        })
        .collect::<Result<Vec<_>, CommandError>>()?;
    repository.reconcile_project_policy_events(&reviews)
}

fn record_from_request(
    request: &ReviewRequest,
    policy_hash: Option<String>,
    now: DateTime<Utc>,
) -> ReviewRecord {
    ReviewRecord {
        id: String::new(),
        project_id: request.project_id.clone(),
        fingerprint_version: request.fingerprint_version,
        fingerprint: request.fingerprint.clone(),
        state: request.state,
        reason: request.reason.clone(),
        evidence: request.evidence.clone(),
        entry_point: request.entry_point.clone(),
        data_flow: request.data_flow.clone(),
        gates: request.gates.clone(),
        deciding_gate: request.deciding_gate,
        expires_at: request.expires_at.clone(),
        origin: request.origin,
        policy_hash,
        updated_at: timestamp(now),
        superseded_at: None,
    }
}

fn timestamp(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use crate::{
        findings::{
            coverage::CoverageManifest,
            domain::{
                FindingScope, PolicyStatus, ReviewOrigin, ReviewRequest, ReviewState,
                RunPersistence, RunStatus, ScanRunDetail, FINGERPRINT_VERSION,
            },
            error::ErrorCode,
            repository::FindingsRepository,
        },
        models::{Finding, ScanOptions, ScanSummary},
        triage::gates::{Gate, GateNote, GateVerdict, ALL_GATES},
    };

    use super::*;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
            .single()
            .unwrap()
    }

    fn note(gate: Gate, verdict: GateVerdict) -> GateNote {
        GateNote {
            gate,
            verdict,
            evidence: format!("Reviewed {} in the production manifest", gate.slug()),
        }
    }

    fn request(state: ReviewState, category: &str, origin: ReviewOrigin) -> ReviewRequest {
        ReviewRequest {
            project_id: "project-1".into(),
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: "abcdef0123456789".into(),
            category: category.into(),
            state,
            reason: if state == ReviewState::Candidate {
                String::new()
            } else {
                "Reviewed by the application security team".into()
            },
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin,
        }
    }

    fn valid_confirmation() -> ReviewRequest {
        let mut request = request(ReviewState::Confirmed, "vulnerability", ReviewOrigin::Local);
        request.gates = ALL_GATES
            .iter()
            .copied()
            .map(|gate| note(gate, GateVerdict::Survives))
            .collect();
        request.entry_point = Some("src/router.rs:18".into());
        request.data_flow = Some("router -> validated handler".into());
        request
    }

    fn valid_false_positive(origin: ReviewOrigin) -> ReviewRequest {
        let mut request = request(ReviewState::FalsePositive, "vulnerability", origin);
        request.gates = vec![
            note(Gate::Intended, GateVerdict::Survives),
            note(Gate::Reachable, GateVerdict::Eliminates),
        ];
        request.deciding_gate = Some(Gate::Reachable);
        request.evidence = Some("The production manifest excludes the development route".into());
        request.entry_point = Some("src/router.rs:18".into());
        request.data_flow = Some("router -> development handler".into());
        request
    }

    #[test]
    fn review_state_matrix_requires_exact_category_evidence() {
        validate_review_at(&valid_confirmation(), "vulnerability", now()).expect("confirmation");
        validate_review_at(
            &valid_false_positive(ReviewOrigin::Local),
            "vulnerability",
            now(),
        )
        .expect("false positive");
        for state in [ReviewState::Confirmed, ReviewState::FalsePositive] {
            validate_review_at(
                &request(state, "secret", ReviewOrigin::Local),
                "secret",
                now(),
            )
            .expect("secret reason-only decision");
        }
        for state in [ReviewState::AcceptedRisk, ReviewState::Suppressed] {
            for category in ["secret", "vulnerability"] {
                validate_review_at(
                    &request(state, category, ReviewOrigin::Local),
                    category,
                    now(),
                )
                .expect("reason-only closure");
            }
        }

        let mut invalid = Vec::new();
        let mut missing_reason = request(
            ReviewState::AcceptedRisk,
            "vulnerability",
            ReviewOrigin::Local,
        );
        missing_reason.reason = "   ".into();
        invalid.push(missing_reason);
        let mut duplicate = valid_confirmation();
        duplicate
            .gates
            .push(note(Gate::Reachable, GateVerdict::Survives));
        invalid.push(duplicate);
        let mut unknown = valid_confirmation();
        unknown.gates[1].verdict = GateVerdict::Unknown;
        invalid.push(unknown);
        let mut eliminates = valid_confirmation();
        eliminates.gates[2].verdict = GateVerdict::Eliminates;
        invalid.push(eliminates);
        let mut blank = valid_confirmation();
        blank.gates[3].evidence = "  ".into();
        invalid.push(blank);
        let mut duplicate_fp = valid_false_positive(ReviewOrigin::Local);
        duplicate_fp
            .gates
            .push(note(Gate::Reachable, GateVerdict::Survives));
        invalid.push(duplicate_fp);
        let mut unknown_fp = valid_false_positive(ReviewOrigin::Local);
        unknown_fp.gates[0].verdict = GateVerdict::Unknown;
        invalid.push(unknown_fp);
        let mut second_eliminates = valid_false_positive(ReviewOrigin::Local);
        second_eliminates.gates[0].verdict = GateVerdict::Eliminates;
        invalid.push(second_eliminates);
        let mut secret_gates = request(ReviewState::FalsePositive, "secret", ReviewOrigin::Local);
        secret_gates.gates = vec![note(Gate::Reachable, GateVerdict::Eliminates)];
        secret_gates.deciding_gate = Some(Gate::Reachable);
        invalid.push(secret_gates);
        let mut reason_only_gates = request(
            ReviewState::Suppressed,
            "vulnerability",
            ReviewOrigin::Local,
        );
        reason_only_gates.gates = vec![note(Gate::Reachable, GateVerdict::Survives)];
        invalid.push(reason_only_gates);
        let mut blank_optional_evidence = valid_false_positive(ReviewOrigin::Local);
        blank_optional_evidence.evidence = Some("   ".into());
        invalid.push(blank_optional_evidence);

        for invalid in invalid {
            let error = validate_review_at(&invalid, &invalid.category, now())
                .expect_err("invalid review matrix must be rejected");
            assert_eq!(error.code, ErrorCode::ReviewInvalid);
            assert_eq!(error.detail, None);
        }
    }

    #[test]
    fn candidate_expiry_and_project_policy_boundaries_are_strict() {
        let candidate = request(ReviewState::Candidate, "secret", ReviewOrigin::Local);
        validate_review_at(&candidate, "secret", now()).expect("empty candidate clears");

        let mut dirty_candidate = candidate.clone();
        dirty_candidate.reason = "clear it".into();
        assert!(validate_review_at(&dirty_candidate, "secret", now()).is_err());

        for expiry in ["not-rfc3339", "2026-08-21T12:00:00Z"] {
            let mut expiring = request(
                ReviewState::AcceptedRisk,
                "vulnerability",
                ReviewOrigin::Local,
            );
            expiring.expires_at = Some(expiry.into());
            assert!(validate_review_at(&expiring, "vulnerability", now()).is_err());
        }
        let mut future = request(
            ReviewState::AcceptedRisk,
            "vulnerability",
            ReviewOrigin::Local,
        );
        future.expires_at = Some("2026-08-21T12:00:00.000000001Z".into());
        validate_review_at(&future, "vulnerability", now()).expect("future expiry");

        let mut project_confirmation = valid_confirmation();
        project_confirmation.origin = ReviewOrigin::ProjectPolicy;
        assert!(validate_review_at(&project_confirmation, "vulnerability", now()).is_err());

        let mut raw_context = valid_false_positive(ReviewOrigin::ProjectPolicy);
        raw_context.evidence = Some("source at /Users/alice/private/router.rs:18".into());
        assert!(validate_review_at(&raw_context, "vulnerability", now()).is_err());
        validate_review_at(
            &valid_false_positive(ReviewOrigin::ProjectPolicy),
            "vulnerability",
            now(),
        )
        .expect("sanitized portable project evidence");
    }

    fn finding(category: &str) -> Finding {
        Finding {
            id: format!("observation-{category}"),
            category: category.into(),
            rule_id: "rule-1".into(),
            rule_name: "Rule".into(),
            severity: "high".into(),
            title: "Finding".into(),
            description: "Sanitized observation".into(),
            file_path: "src/router.rs".into(),
            line: 18,
            column: 4,
            match_text: "sanitized match".into(),
            context: "sanitized context".into(),
            language: "rust".into(),
            cwe: Some("CWE-20".into()),
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: "Validate input".into(),
            entropy: None,
            verified: None,
            observation_run_id: "run-1".into(),
            resolved_by_run_id: None,
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: "abcdef0123456789".into(),
            scope: Some(FindingScope::Production),
            scope_reason: Some("source directory".into()),
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    fn prepare_repository(repository: &FindingsRepository, category: &str) {
        repository
            .upsert_project(
                "project-1",
                "/project",
                "Project",
                "2026-08-21T11:00:00Z",
                Some(&ScanOptions::default()),
            )
            .unwrap();
        let summary = ScanSummary {
            path: "/project".into(),
            files_scanned: 1,
            files_skipped: 0,
            bytes_scanned: 10,
            duration_ms: 1,
            secrets_found: usize::from(category == "secret"),
            vulnerabilities_found: usize::from(category == "vulnerability"),
            total_findings: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
            rules_fired: BTreeMap::from([("rule-1".into(), 1)]),
        };
        let running = ScanRunDetail {
            project_id: "project-1".into(),
            run_id: "run-1".into(),
            baseline_run_id: None,
            status: RunStatus::Running,
            persistence: RunPersistence::Saved,
            policy: PolicyStatus::Missing,
            started_at: "2026-08-21T11:00:00Z".into(),
            completed_at: None,
            summary: summary.clone(),
            findings: Vec::new(),
            maintenance_warning: None,
        };
        repository
            .start_run(&running, "scanner-1", &ScanOptions::default())
            .unwrap();
        let completed = ScanRunDetail {
            status: RunStatus::Completed,
            completed_at: Some("2026-08-21T11:01:00Z".into()),
            findings: vec![finding(category)],
            ..running
        };
        repository
            .complete_run(
                &completed,
                &CoverageManifest::from_entries([("src/router.rs", [category])]),
            )
            .unwrap();
    }

    #[test]
    fn save_rejects_unknown_or_category_mismatched_observations_before_write() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");

        let mut unknown = valid_confirmation();
        unknown.fingerprint = "deadbeef01234567".into();
        let not_found = save_local_review(&repository, &unknown, now()).unwrap_err();
        assert_eq!(not_found.code, ErrorCode::NotFound);

        let mismatch = request(ReviewState::FalsePositive, "secret", ReviewOrigin::Local);
        let invalid = save_local_review(&repository, &mismatch, now()).unwrap_err();
        assert_eq!(invalid.code, ErrorCode::ReviewInvalid);

        let loaded = repository.load_run("run-1").unwrap();
        assert!(loaded.findings[0].review_history.is_empty());
    }

    #[test]
    fn local_review_events_are_append_only_and_origin_precedence_survives_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("private/findings.sqlite3");
        let repository = FindingsRepository::open(&database).unwrap();
        prepare_repository(&repository, "vulnerability");

        let first = save_local_review(&repository, &valid_confirmation(), now()).unwrap();
        let mut replacement = request(
            ReviewState::AcceptedRisk,
            "vulnerability",
            ReviewOrigin::Local,
        );
        replacement.reason = "Accepted until the next architecture review".into();
        replacement.expires_at = Some("2027-01-01T00:00:00Z".into());
        let second = save_local_review(
            &repository,
            &replacement,
            now() + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_ne!(first.id, second.id);
        let cleared = save_local_review(
            &repository,
            &request(ReviewState::Candidate, "vulnerability", ReviewOrigin::Local),
            now() + chrono::Duration::seconds(2),
        )
        .unwrap();
        assert_eq!(cleared.state, ReviewState::Candidate);
        drop(repository);

        let reopened = FindingsRepository::open(&database).unwrap();
        let loaded = reopened.load_run("run-1").unwrap();
        assert_eq!(loaded.findings[0].review, None);
        assert_eq!(loaded.findings[0].review_history.len(), 3);
        assert_eq!(loaded.findings[0].review_history[0].id, cleared.id);
        assert_eq!(loaded.findings[0].review_history[1].id, second.id);
        assert_eq!(loaded.findings[0].review_history[2].id, first.id);
        assert!(loaded.findings[0].review_history[1].superseded_at.is_some());
    }

    #[test]
    fn project_policy_is_file_first_idempotent_and_reconciliation_heals_database() {
        let root = tempfile::tempdir().unwrap();
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");
        let policy_request = valid_false_positive(ReviewOrigin::ProjectPolicy);

        let failed = save_project_policy_review_with_reconcile(
            &repository,
            root.path(),
            &policy_request,
            now(),
            |_, _| Err(crate::findings::error::CommandError::persistence_unavailable()),
        )
        .unwrap_err();
        assert_eq!(failed.code, ErrorCode::PolicyWriteFailed);
        assert!(failed.retryable);
        assert!(matches!(
            crate::findings::policy::load_policy(root.path())
                .unwrap()
                .status(),
            PolicyStatus::Valid { .. }
        ));
        assert!(repository.load_run("run-1").unwrap().findings[0]
            .review_history
            .is_empty());

        let inserted =
            reconcile_project_policy_reviews(&repository, root.path(), "project-1", now()).unwrap();
        assert_eq!(inserted, 1);
        let first = repository.load_run("run-1").unwrap();
        assert_eq!(
            first.findings[0].review.as_ref().unwrap().state,
            ReviewState::FalsePositive
        );
        assert_eq!(
            first.findings[0].review.as_ref().unwrap().origin,
            ReviewOrigin::ProjectPolicy
        );
        assert_eq!(
            reconcile_project_policy_reviews(&repository, root.path(), "project-1", now()).unwrap(),
            0
        );
        assert_eq!(
            repository.load_run("run-1").unwrap().findings[0]
                .review_history
                .len(),
            1
        );

        let local = save_local_review(
            &repository,
            &request(
                ReviewState::AcceptedRisk,
                "vulnerability",
                ReviewOrigin::Local,
            ),
            now() + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_eq!(
            repository.load_run("run-1").unwrap().findings[0]
                .review
                .as_ref()
                .unwrap()
                .id,
            local.id
        );

        let clear = request(
            ReviewState::Candidate,
            "vulnerability",
            ReviewOrigin::ProjectPolicy,
        );
        save_project_policy_review(
            &repository,
            root.path(),
            &clear,
            now() + chrono::Duration::seconds(2),
        )
        .unwrap();
        let loaded = repository.load_run("run-1").unwrap();
        let history = &loaded.findings[0].review_history;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].state, ReviewState::Candidate);
        assert_eq!(history[0].origin, ReviewOrigin::ProjectPolicy);
    }

    #[test]
    fn reconciliation_batch_rolls_back_every_event_when_one_insert_fails() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");
        let request = valid_false_positive(ReviewOrigin::ProjectPolicy);
        let mut valid = record_from_request(&request, Some("policy-hash".into()), now());
        valid.state = ReviewState::FalsePositive;
        let mut invalid_project = valid.clone();
        invalid_project.project_id = "missing-project".into();
        invalid_project.fingerprint = "fedcba9876543210".into();

        let error = repository
            .reconcile_project_policy_events(&[valid, invalid_project])
            .expect_err("one invalid event must roll back the complete policy projection");
        assert_eq!(error.code, ErrorCode::PersistenceUnavailable);
        assert!(repository.load_run("run-1").unwrap().findings[0]
            .review_history
            .is_empty());
    }

    #[test]
    fn file_write_failure_and_credential_shaped_local_text_leave_database_unchanged() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".oxaudit")).unwrap();
        let invalid_bytes = br#"{"version":999,"entries":[],"private":"preserve"}"#;
        std::fs::write(root.path().join(".oxaudit/policy.json"), invalid_bytes).unwrap();
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");

        let error = save_project_policy_review(
            &repository,
            root.path(),
            &valid_false_positive(ReviewOrigin::ProjectPolicy),
            now(),
        )
        .expect_err("invalid policy is never overwritten");
        assert_eq!(error.code, ErrorCode::PolicyInvalid);
        assert_eq!(
            std::fs::read(root.path().join(".oxaudit/policy.json")).unwrap(),
            invalid_bytes
        );

        let mut credential = valid_confirmation();
        credential.reason = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz".into();
        let error = save_local_review(&repository, &credential, now())
            .expect_err("credential-shaped text never reaches SQLite");
        assert_eq!(error.code, ErrorCode::ReviewInvalid);
        assert!(repository.load_run("run-1").unwrap().findings[0]
            .review_history
            .is_empty());
    }

    #[test]
    fn newest_observation_uses_parsed_instant_before_category_validation() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");
        let summary = ScanSummary {
            path: "/project".into(),
            files_scanned: 1,
            files_skipped: 0,
            bytes_scanned: 10,
            duration_ms: 1,
            secrets_found: 1,
            vulnerabilities_found: 0,
            total_findings: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
            rules_fired: BTreeMap::from([("rule-1".into(), 1)]),
        };
        let running = ScanRunDetail {
            project_id: "project-1".into(),
            run_id: "run-offset-newer".into(),
            baseline_run_id: None,
            status: RunStatus::Running,
            persistence: RunPersistence::Saved,
            policy: PolicyStatus::Missing,
            // 11:30Z, later than run-1, despite sorting before its `11:` text.
            started_at: "2026-08-21T10:30:00-01:00".into(),
            completed_at: None,
            summary: summary.clone(),
            findings: Vec::new(),
            maintenance_warning: None,
        };
        repository
            .start_run(&running, "scanner-1", &ScanOptions::default())
            .unwrap();
        let mut newer = finding("secret");
        newer.id = "observation-offset-newer".into();
        newer.observation_run_id = "run-offset-newer".into();
        let completed = ScanRunDetail {
            status: RunStatus::Completed,
            completed_at: Some("2026-08-21T10:31:00-01:00".into()),
            findings: vec![newer],
            ..running
        };
        repository
            .complete_run(
                &completed,
                &CoverageManifest::from_entries([("src/router.rs", ["secret"])]),
            )
            .unwrap();

        let error = save_local_review(&repository, &valid_confirmation(), now())
            .expect_err("newest secret observation must reject vulnerability validation");
        assert_eq!(error.code, ErrorCode::ReviewInvalid);
        assert!(repository.load_run("run-offset-newer").unwrap().findings[0]
            .review_history
            .is_empty());
    }

    #[test]
    fn expired_local_event_exposes_current_project_policy_event() {
        let root = tempfile::tempdir().unwrap();
        let repository = FindingsRepository::open_in_memory().unwrap();
        prepare_repository(&repository, "vulnerability");
        let policy = save_project_policy_review(
            &repository,
            root.path(),
            &valid_false_positive(ReviewOrigin::ProjectPolicy),
            now(),
        )
        .unwrap();
        let mut expired = request(
            ReviewState::AcceptedRisk,
            "vulnerability",
            ReviewOrigin::Local,
        );
        expired.expires_at = Some("2000-01-01T00:00:00Z".into());
        let expired = repository
            .save_review_event(&record_from_request(
                &expired,
                None,
                now() + chrono::Duration::seconds(1),
            ))
            .unwrap();

        let loaded = repository.load_run("run-1").unwrap();
        assert_eq!(loaded.findings[0].review.as_ref().unwrap().id, policy.id);
        assert_eq!(loaded.findings[0].review_history.len(), 2);
        assert_eq!(loaded.findings[0].review_history[0].id, expired.id);
    }
}

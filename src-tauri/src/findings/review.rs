use std::{collections::HashSet, path::Path};

use chrono::{DateTime, SecondsFormat, Utc};

use super::{
    domain::{ReviewOrigin, ReviewRecord, ReviewRequest, ReviewState},
    error::CommandError,
    policy::{
        apply_policy, contains_credential_material, load_policy_under_authority,
        policy_authority_still_matches, reproject_or_clear_orphaned_policy_review,
        update_policy_decision_under_authority, validate_portable_review_fields,
        with_policy_authority, PolicyAuthority,
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
    save_local_review_core(repository, request, now, || {})
}

fn save_local_review_core<F>(
    repository: &FindingsRepository,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    after_observation: F,
) -> Result<ReviewRecord, CommandError>
where
    F: FnOnce(),
{
    if request.origin != ReviewOrigin::Local {
        return Err(CommandError::review_invalid());
    }
    repository.save_local_review_for_latest_observation(
        &request.project_id,
        request.fingerprint_version,
        &request.fingerprint,
        |observation| {
            after_observation();
            validate_review_at(request, &observation.category, now)?;
            Ok(record_from_request(request, None, now))
        },
    )
}

#[cfg(test)]
fn save_local_review_with_hook(
    repository: &FindingsRepository,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    after_observation: impl FnOnce(),
) -> Result<ReviewRecord, CommandError> {
    save_local_review_core(repository, request, now, after_observation)
}

pub fn save_project_policy_review(
    repository: &FindingsRepository,
    request: &ReviewRequest,
    now: DateTime<Utc>,
) -> Result<ReviewRecord, CommandError> {
    with_policy_authority(|authority| {
        let project = repository.project_context(&request.project_id)?;
        save_project_policy_review_under_authority(
            authority,
            repository,
            Path::new(&project.canonical_path),
            request,
            now,
            || {},
            |authority, repository, projection| {
                repository
                    .reconcile_project_policy_projection(
                        authority,
                        &projection.reviews,
                        Some((
                            projection.selected_fingerprint_version,
                            &projection.selected_fingerprint,
                        )),
                    )
                    .map(|(stored, _)| stored)
            },
        )
    })
}

struct ProjectPolicyProjection {
    reviews: Vec<ReviewRecord>,
    selected_fingerprint_version: u16,
    selected_fingerprint: String,
}

#[cfg(test)]
fn save_project_policy_review_with_reconcile<F>(
    repository: &FindingsRepository,
    project_root: &Path,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    reconcile: F,
) -> Result<ReviewRecord, CommandError>
where
    F: FnOnce(
        &PolicyAuthority<'_>,
        &FindingsRepository,
        &ProjectPolicyProjection,
    ) -> Result<Vec<ReviewRecord>, CommandError>,
{
    with_policy_authority(|authority| {
        save_project_policy_review_under_authority(
            authority,
            repository,
            project_root,
            request,
            now,
            || {},
            reconcile,
        )
    })
}

#[cfg(test)]
fn save_project_policy_review_with_prewrite_hook<F>(
    repository: &FindingsRepository,
    project_root: &Path,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    before_root_revalidation: F,
) -> Result<ReviewRecord, CommandError>
where
    F: FnOnce(),
{
    with_policy_authority(|authority| {
        save_project_policy_review_under_authority(
            authority,
            repository,
            project_root,
            request,
            now,
            before_root_revalidation,
            |authority, repository, projection| {
                repository
                    .reconcile_project_policy_projection(
                        authority,
                        &projection.reviews,
                        Some((
                            projection.selected_fingerprint_version,
                            &projection.selected_fingerprint,
                        )),
                    )
                    .map(|(stored, _)| stored)
            },
        )
    })
}

fn save_project_policy_review_under_authority<F, G>(
    authority: &PolicyAuthority<'_>,
    repository: &FindingsRepository,
    project_root: &Path,
    request: &ReviewRequest,
    now: DateTime<Utc>,
    before_root_revalidation: G,
    reconcile: F,
) -> Result<ReviewRecord, CommandError>
where
    F: FnOnce(
        &PolicyAuthority<'_>,
        &FindingsRepository,
        &ProjectPolicyProjection,
    ) -> Result<Vec<ReviewRecord>, CommandError>,
    G: FnOnce(),
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
    before_root_revalidation();
    revalidate_project_root(repository, &request.project_id, project_root)?;

    let loaded = update_policy_decision_under_authority(
        authority,
        project_root,
        &observation,
        request,
        now,
    )?;
    let projection = ProjectPolicyProjection {
        reviews: build_project_policy_projection(repository, &loaded, &request.project_id, now)
            .map_err(|_| CommandError::policy_write_failed())?,
        selected_fingerprint_version: observation.fingerprint_version,
        selected_fingerprint: observation.fingerprint,
    };
    if !policy_authority_still_matches(authority, project_root, &loaded)? {
        return Err(CommandError::policy_write_failed());
    }
    let stored = reconcile(authority, repository, &projection)
        .map_err(|_| CommandError::policy_write_failed())?;
    if !policy_authority_still_matches(authority, project_root, &loaded)? {
        return Err(CommandError::policy_write_failed());
    }
    stored
        .into_iter()
        .find(|review| {
            review.fingerprint_version == projection.selected_fingerprint_version
                && review.fingerprint == projection.selected_fingerprint
        })
        .ok_or_else(CommandError::policy_write_failed)
}

pub fn reconcile_project_policy_reviews(
    repository: &FindingsRepository,
    project_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, CommandError> {
    reconcile_project_policy_reviews_core(
        repository,
        project_id,
        now,
        |authority, repository, reviews| {
            repository.reconcile_project_policy_events(authority, reviews)
        },
    )
}

/// Project current policy authority onto a comparison without reconciling or
/// appending review events. Historical policy events remain historical evidence;
/// only local decisions and the policy currently on disk determine active state.
pub(in crate::findings) fn read_only_project_policy_comparison(
    repository: &FindingsRepository,
    current_run_id: &str,
    baseline_run_id: &str,
    now: DateTime<Utc>,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    read_only_comparison_with_policy_requirement(
        repository,
        current_run_id,
        baseline_run_id,
        now,
        false,
    )
}

pub(in crate::findings) fn read_only_recheck_comparison(
    repository: &FindingsRepository,
    current_run_id: &str,
    baseline_run_id: &str,
    now: DateTime<Utc>,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    read_only_comparison_with_policy_requirement(
        repository,
        current_run_id,
        baseline_run_id,
        now,
        true,
    )
}

fn read_only_comparison_with_policy_requirement(
    repository: &FindingsRepository,
    current_run_id: &str,
    baseline_run_id: &str,
    now: DateTime<Utc>,
    require_valid_policy: bool,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    let current = repository
        .load_run(current_run_id)
        .map_err(|_| CommandError::baseline_incompatible())?;
    let findings = repository
        .compare_runs(current_run_id, baseline_run_id)
        .map_err(|_| CommandError::baseline_incompatible())?;
    read_only_findings_with_policy_requirement(
        repository,
        &current.project_id,
        findings,
        now,
        require_valid_policy,
    )
}

pub(in crate::findings) fn read_only_project_policy_findings(
    repository: &FindingsRepository,
    project_id: &str,
    findings: Vec<crate::models::Finding>,
    now: DateTime<Utc>,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    read_only_findings_with_policy_requirement(repository, project_id, findings, now, false)
}

fn read_only_findings_with_policy_requirement(
    repository: &FindingsRepository,
    project_id: &str,
    mut findings: Vec<crate::models::Finding>,
    now: DateTime<Utc>,
    require_valid_policy: bool,
) -> Result<Vec<crate::models::Finding>, CommandError> {
    with_policy_authority(|authority| {
        let project = repository.project_context(project_id)?;
        let root = Path::new(&project.canonical_path);
        let loaded = load_policy_under_authority(authority, root)?;
        if require_valid_policy
            && matches!(loaded.status(), super::domain::PolicyStatus::Invalid { .. })
        {
            return Err(CommandError::policy_invalid());
        }
        // Only SELECT history; persisted policy events are not active authority.
        repository.enrich_findings_with_reviews(project_id, &mut findings, false, now)?;
        if !matches!(loaded.status(), super::domain::PolicyStatus::Invalid { .. }) {
            for finding in &mut findings {
                let projected = apply_policy(
                    &loaded,
                    project_id,
                    finding.fingerprint_version,
                    &finding.fingerprint,
                    &finding.category,
                    &finding.rule_id,
                    &finding.file_path,
                    finding.review.as_ref(),
                    now,
                )?;
                finding.review = (projected.state != ReviewState::Candidate).then_some(projected);
            }
        }
        revalidate_project_root(repository, project_id, root)?;
        if !policy_authority_still_matches(authority, root, &loaded)? {
            return Err(CommandError::policy_write_failed());
        }
        Ok(findings)
    })
}

pub(in crate::findings) fn authoritative_project_policy_projection<T, H, P>(
    repository: &FindingsRepository,
    project_id: &str,
    now: DateTime<Utc>,
    after_policy_load: H,
    projection: P,
) -> Result<(super::domain::PolicyStatus, T), CommandError>
where
    H: FnOnce() -> Result<(), CommandError>,
    P: FnOnce(&FindingsRepository) -> Result<T, CommandError>,
{
    let (status, _, projection) = authoritative_project_policy_projection_core(
        repository,
        project_id,
        now,
        after_policy_load,
        |authority, repository, reviews| {
            repository.reconcile_project_policy_events(authority, reviews)
        },
        projection,
    )?;
    Ok((status, projection))
}

#[cfg(test)]
fn reconcile_project_policy_reviews_with_reconcile<F>(
    repository: &FindingsRepository,
    project_id: &str,
    now: DateTime<Utc>,
    reconcile: F,
) -> Result<usize, CommandError>
where
    F: FnOnce(
        &PolicyAuthority<'_>,
        &FindingsRepository,
        &[ReviewRecord],
    ) -> Result<usize, CommandError>,
{
    reconcile_project_policy_reviews_core(repository, project_id, now, reconcile)
}

fn reconcile_project_policy_reviews_core<F>(
    repository: &FindingsRepository,
    project_id: &str,
    now: DateTime<Utc>,
    reconcile: F,
) -> Result<usize, CommandError>
where
    F: FnOnce(
        &PolicyAuthority<'_>,
        &FindingsRepository,
        &[ReviewRecord],
    ) -> Result<usize, CommandError>,
{
    let (status, inserted, ()) = authoritative_project_policy_projection_core(
        repository,
        project_id,
        now,
        || Ok(()),
        reconcile,
        |_| Ok(()),
    )?;
    if matches!(status, super::domain::PolicyStatus::Invalid { .. }) {
        Err(CommandError::policy_invalid())
    } else {
        Ok(inserted)
    }
}

fn authoritative_project_policy_projection_core<T, H, R, P>(
    repository: &FindingsRepository,
    project_id: &str,
    now: DateTime<Utc>,
    after_policy_load: H,
    reconcile: R,
    projection: P,
) -> Result<(super::domain::PolicyStatus, usize, T), CommandError>
where
    H: FnOnce() -> Result<(), CommandError>,
    R: FnOnce(
        &PolicyAuthority<'_>,
        &FindingsRepository,
        &[ReviewRecord],
    ) -> Result<usize, CommandError>,
    P: FnOnce(&FindingsRepository) -> Result<T, CommandError>,
{
    with_policy_authority(|authority| {
        let project = repository.project_context(project_id)?;
        let project_root = Path::new(&project.canonical_path);
        let loaded = load_policy_under_authority(authority, project_root)?;
        after_policy_load()?;
        let inserted = if matches!(loaded.status(), super::domain::PolicyStatus::Invalid { .. }) {
            0
        } else {
            let reviews = build_project_policy_projection(repository, &loaded, project_id, now)?;
            revalidate_project_root(repository, project_id, project_root)?;
            if !policy_authority_still_matches(authority, project_root, &loaded)? {
                return Err(CommandError::policy_write_failed());
            }
            let inserted = reconcile(authority, repository, &reviews)?;
            if !policy_authority_still_matches(authority, project_root, &loaded)? {
                return Err(CommandError::policy_write_failed());
            }
            inserted
        };
        revalidate_project_root(repository, project_id, project_root)?;
        if !policy_authority_still_matches(authority, project_root, &loaded)? {
            return Err(CommandError::policy_write_failed());
        }
        let projection = projection(repository)?;
        revalidate_project_root(repository, project_id, project_root)?;
        if !policy_authority_still_matches(authority, project_root, &loaded)? {
            return Err(CommandError::policy_write_failed());
        }
        Ok((loaded.status().clone(), inserted, projection))
    })
}

fn revalidate_project_root(
    repository: &FindingsRepository,
    project_id: &str,
    expected_root: &Path,
) -> Result<(), CommandError> {
    let current = repository.project_context(project_id)?;
    if Path::new(&current.canonical_path) != expected_root {
        return Err(CommandError::persistence_unavailable());
    }
    Ok(())
}

fn build_project_policy_projection(
    repository: &FindingsRepository,
    loaded: &super::policy::LoadedPolicy,
    project_id: &str,
    now: DateTime<Utc>,
) -> Result<Vec<ReviewRecord>, CommandError> {
    let observations = repository.latest_project_observations(project_id)?;
    let observed_identities = observations
        .iter()
        .map(|observation| {
            (
                observation.fingerprint_version,
                observation.fingerprint.clone(),
            )
        })
        .collect::<HashSet<_>>();
    let mut reviews = observations
        .into_iter()
        .map(|observation| {
            apply_policy(
                loaded,
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
    for current in repository.current_project_policy_reviews(project_id)? {
        if !observed_identities
            .contains(&(current.fingerprint_version, current.fingerprint.clone()))
        {
            reviews.push(reproject_or_clear_orphaned_policy_review(
                loaded, &current, now,
            )?);
        }
    }
    Ok(reviews)
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
#[path = "review_tests.rs"]
mod tests;

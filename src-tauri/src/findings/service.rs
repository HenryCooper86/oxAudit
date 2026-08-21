use std::{
    collections::{HashSet, VecDeque},
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Mutex,
    time::Instant,
};

use chrono::{DateTime, SecondsFormat, Utc};
use rayon::prelude::*;
use serde_json::Value;
use uuid::Uuid;

use super::{
    coverage::CoverageManifest,
    domain::{
        DiffStatus, PolicyStatus, ProjectContext, RecentProject, RetentionPolicy, ReviewOrigin,
        ReviewRecord, ReviewRequest, ReviewState, RunPersistence, RunStatus, ScanRunDetail,
        ScanRunSummary,
    },
    error::CommandError,
    fingerprint::assign_fingerprints,
    policy::{apply_policy, load_policy},
    repository::FindingsRepository,
    review::{
        authoritative_project_policy_projection, reconcile_project_policy_reviews,
        save_local_review, save_project_policy_review,
    },
};
use crate::{
    cve::CveState,
    fs_utils::{self, CollectFilesOptions},
    models::{Finding, ScanOptions, ScanResult, ScanSummary},
    scanners,
    triage::scope,
};

const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");
const RETENTION_WARNING: &str = "Run saved, but old scan history could not be cleaned up.";
const POLICY_REFRESH_WARNING: &str = "Run saved, but project policy state could not be refreshed.";

pub trait ScanEventSink: Send + Sync {
    fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError>;
}

#[cfg(test)]
type ScanPause = (
    String,
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
);

pub struct FindingsService {
    repository: FindingsRepository,
    active_projects: Mutex<HashSet<String>>,
    pending_saves: Mutex<VecDeque<PendingSave>>,
    #[cfg(test)]
    completion_failures: AtomicUsize,
    #[cfg(test)]
    fail_after_committed_completion: AtomicBool,
    #[cfg(test)]
    fail_post_completion_policy_refresh: AtomicBool,
    #[cfg(test)]
    scan_pause: Mutex<Option<ScanPause>>,
    #[cfg(test)]
    before_completion_pause: Mutex<Option<ScanPause>>,
    #[cfg(test)]
    policy_refresh_pause: Mutex<Option<ScanPause>>,
    #[cfg(test)]
    policy_projection_pause: Mutex<Option<ScanPause>>,
    #[cfg(test)]
    retry_reservation_pause: Mutex<Option<ScanPause>>,
    #[cfg(test)]
    scanner_failures: Mutex<HashSet<String>>,
    #[cfg(test)]
    mark_incomplete_failures: AtomicUsize,
    #[cfg(test)]
    retention_maintenance_failures: AtomicUsize,
    #[cfg(test)]
    delete_attempt_before_completion: AtomicBool,
    #[cfg(test)]
    started_run_ids: Mutex<Vec<String>>,
}

pub struct FindingsState {
    service: Option<FindingsService>,
    initialization_error: Option<CommandError>,
}

impl FindingsState {
    pub fn available(service: FindingsService) -> Self {
        Self {
            service: Some(service),
            initialization_error: None,
        }
    }

    pub fn unavailable(error: CommandError) -> Self {
        Self {
            service: None,
            initialization_error: Some(error),
        }
    }

    pub fn service(&self) -> Result<&FindingsService, CommandError> {
        self.service.as_ref().ok_or_else(|| {
            self.initialization_error
                .clone()
                .unwrap_or_else(CommandError::persistence_unavailable)
        })
    }
}

#[derive(Clone)]
pub struct PendingSave {
    pub run_id: String,
    pub project_id: String,
    pub result: ScanResult,
    pub coverage: CoverageManifest,
    pub policy: PolicyStatus,
    pub baseline_run_id: Option<String>,
    started_at: String,
    completed_at: String,
    retry_token: String,
    in_flight: bool,
}

struct ProjectScanGuard<'a> {
    project_id: String,
    active_projects: &'a Mutex<HashSet<String>>,
}

struct RunAttemptGuard<'a> {
    service: &'a FindingsService,
    run_id: String,
    armed: bool,
}

struct PendingSaveReservation<'a> {
    pending_saves: &'a Mutex<VecDeque<PendingSave>>,
    retry_token: String,
    finished: bool,
}

impl PendingSaveReservation<'_> {
    fn remove(mut self) -> Result<(), CommandError> {
        let mut pending_saves = self
            .pending_saves
            .lock()
            .map_err(|_| CommandError::persistence_unavailable())?;
        let index = pending_saves
            .iter()
            .position(|pending| pending.retry_token == self.retry_token)
            .ok_or_else(CommandError::not_found)?;
        pending_saves.remove(index);
        self.finished = true;
        Ok(())
    }
}

impl Drop for PendingSaveReservation<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut pending_saves) = self.pending_saves.lock() {
            if let Some(pending) = pending_saves
                .iter_mut()
                .find(|pending| pending.retry_token == self.retry_token)
            {
                pending.in_flight = false;
            }
        }
    }
}

impl RunAttemptGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn fail(&mut self, error: &CommandError) {
        self.armed = false;
        self.service
            .mark_incomplete_best_effort(&self.run_id, terminal_error_code(error));
    }
}

impl Drop for RunAttemptGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.service
                .mark_incomplete_best_effort(&self.run_id, "scan_failed");
        }
    }
}

impl Drop for ProjectScanGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_projects.lock() {
            active.remove(&self.project_id);
        }
    }
}

impl FindingsService {
    pub fn new(repository: FindingsRepository) -> Self {
        Self {
            repository,
            active_projects: Mutex::new(HashSet::new()),
            pending_saves: Mutex::new(VecDeque::new()),
            #[cfg(test)]
            completion_failures: AtomicUsize::new(0),
            #[cfg(test)]
            fail_after_committed_completion: AtomicBool::new(false),
            #[cfg(test)]
            fail_post_completion_policy_refresh: AtomicBool::new(false),
            #[cfg(test)]
            scan_pause: Mutex::new(None),
            #[cfg(test)]
            before_completion_pause: Mutex::new(None),
            #[cfg(test)]
            policy_refresh_pause: Mutex::new(None),
            #[cfg(test)]
            policy_projection_pause: Mutex::new(None),
            #[cfg(test)]
            retry_reservation_pause: Mutex::new(None),
            #[cfg(test)]
            scanner_failures: Mutex::new(HashSet::new()),
            #[cfg(test)]
            mark_incomplete_failures: AtomicUsize::new(0),
            #[cfg(test)]
            retention_maintenance_failures: AtomicUsize::new(0),
            #[cfg(test)]
            delete_attempt_before_completion: AtomicBool::new(false),
            #[cfg(test)]
            started_run_ids: Mutex::new(Vec::new()),
        }
    }

    pub fn inspect_project(&self, path: impl AsRef<Path>) -> Result<ProjectContext, CommandError> {
        let canonical = path
            .as_ref()
            .canonicalize()
            .map_err(|_| CommandError::invalid_target())?;
        if !canonical.is_dir() {
            return Err(CommandError::invalid_target());
        }
        let canonical_path = canonical.to_string_lossy().into_owned();
        let display_name = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or(&canonical_path)
            .to_owned();
        let now = timestamp(Utc::now());
        let context = self.repository.upsert_project(
            &Uuid::new_v4().to_string(),
            &canonical_path,
            &display_name,
            &now,
            None,
        )?;
        self.run_test_policy_projection_seam(&canonical_path);
        let (policy, mut context) = authoritative_project_policy_projection(
            &self.repository,
            &context.project_id,
            Utc::now(),
            || Ok(()),
            |repository| repository.project_context(&context.project_id),
        )?;
        context.policy = policy;
        Ok(context)
    }

    pub fn load_run(&self, run_id: &str) -> Result<ScanRunDetail, CommandError> {
        let initial = self.repository.load_run(run_id)?;
        let project = self.repository.project_context(&initial.project_id)?;
        self.run_test_policy_projection_seam(&project.canonical_path);
        let (policy, mut loaded) = authoritative_project_policy_projection(
            &self.repository,
            &initial.project_id,
            Utc::now(),
            || Ok(()),
            |repository| repository.load_run(run_id),
        )?;
        loaded.policy = policy.clone();
        if matches!(policy, PolicyStatus::Invalid { .. }) {
            strip_project_policy_reviews(&mut loaded.findings, Utc::now());
        }
        Ok(loaded)
    }

    pub fn list_recent_projects(&self, limit: usize) -> Result<Vec<RecentProject>, CommandError> {
        self.repository.list_recent_projects(limit)
    }

    pub fn list_runs(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<ScanRunSummary>, CommandError> {
        self.repository.list_runs(project_id, limit)
    }

    pub fn save_review(
        &self,
        request: &ReviewRequest,
        now: DateTime<Utc>,
    ) -> Result<ReviewRecord, CommandError> {
        match request.origin {
            ReviewOrigin::Local => save_local_review(&self.repository, request, now),
            ReviewOrigin::ProjectPolicy => {
                save_project_policy_review(&self.repository, request, now)
            }
        }
    }

    pub async fn scan<E: ScanEventSink + ?Sized>(
        &self,
        options: ScanOptions,
        cve: &CveState,
        cancel: &AtomicBool,
        events: &E,
    ) -> Result<ScanRunDetail, CommandError> {
        let started_instant = Instant::now();
        let canonical = Path::new(&options.path)
            .canonicalize()
            .map_err(|_| CommandError::invalid_target())?;
        if !canonical.is_dir() {
            return Err(CommandError::invalid_target());
        }
        let canonical_path = canonical.to_string_lossy().into_owned();
        let display_name = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or(&canonical_path)
            .to_owned();
        let started_at = timestamp(Utc::now());
        let project = self.repository.upsert_project(
            &Uuid::new_v4().to_string(),
            &canonical_path,
            &display_name,
            &started_at,
            Some(&options),
        )?;
        let _guard = self.acquire_project(&project.project_id, cancel)?;
        let loaded_policy = load_policy(&canonical)?;
        if matches!(loaded_policy.status(), PolicyStatus::Invalid { .. })
            && !options.ignore_invalid_policy
        {
            return Err(CommandError::policy_invalid());
        }
        if !matches!(loaded_policy.status(), PolicyStatus::Invalid { .. }) {
            reconcile_project_policy_reviews(&self.repository, &project.project_id, Utc::now())?;
        }

        let run_id = Uuid::new_v4().to_string();
        let running = ScanRunDetail {
            project_id: project.project_id.clone(),
            run_id: run_id.clone(),
            baseline_run_id: None,
            status: RunStatus::Running,
            persistence: RunPersistence::Saved,
            policy: loaded_policy.status().clone(),
            started_at: started_at.clone(),
            completed_at: None,
            summary: empty_summary(canonical_path.clone()),
            findings: Vec::new(),
            maintenance_warning: None,
        };
        self.repository
            .start_run(&running, SCANNER_VERSION, &options)?;
        #[cfg(test)]
        self.started_run_ids.lock().unwrap().push(run_id.clone());
        let mut run_attempt = RunAttemptGuard {
            service: self,
            run_id: run_id.clone(),
            armed: true,
        };
        let result = async {
            self.run_test_scan_seam(&canonical_path)?;

            let _ = events.emit("scan://progress", Value::from("walking"));
            let collection = fs_utils::collect_source_files(
                &canonical,
                CollectFilesOptions {
                    project_root: &canonical,
                    include_git: options.include_git,
                    follow_symlinks: options.follow_symlinks,
                    extra_ignored: &options.extra_ignored_dirs,
                },
            );
            if collection.files.is_empty() {
                return Err(CommandError::scan_failed());
            }
            let total = collection.files.len();
            let _ = events.emit(
                "scan://progress",
                serde_json::json!({"total": total, "done": 0, "phase": "scanning"}),
            );
            let processed = AtomicUsize::new(0);
            let outcomes = collection
                .files
                .par_iter()
                .map(|file| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    let relative = file
                        .project_relative_path
                        .to_string_lossy()
                        .replace('\\', "/");
                    let outcome = scanners::scan_file_with_relative_path(
                        &file.canonical_path,
                        &relative,
                        options.max_file_size_kb.max(1),
                        options.scan_secrets,
                        options.scan_vulnerabilities,
                    );
                    let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    if done.is_multiple_of(25) || done == total {
                        let _ = events.emit(
                            "scan://progress",
                            serde_json::json!({"total": total, "done": done, "phase": "scanning"}),
                        );
                    }
                    Some((relative, outcome))
                })
                .collect::<Vec<_>>();
            if cancel.load(Ordering::Relaxed) || outcomes.iter().any(Option::is_none) {
                return Err(CommandError::scan_cancelled());
            }

            let mut findings = Vec::new();
            let mut coverage_entries = Vec::new();
            for (relative, outcome) in outcomes.into_iter().flatten() {
                coverage_entries.push((relative, outcome.covered_families));
                findings.extend(outcome.findings);
            }
            if findings.iter().any(|finding| finding.cwe.is_some()) {
                let _ = events.emit("scan://progress", Value::from("exploitation-signal"));
                let kev = cve.kev_set().await;
                for finding in &mut findings {
                    if let Some(cwe) = finding.cwe.as_deref() {
                        let count = kev.cwe_exploited_count(cwe);
                        finding.cwe_exploited = count > 0;
                        finding.cwe_exploited_count = count;
                    }
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(CommandError::scan_cancelled());
            }
            assign_fingerprints(&mut findings);
            for finding in &mut findings {
                let decision = scope::classify(&finding.file_path);
                finding.scope = Some(decision.scope);
                finding.scope_reason = Some(decision.reason);
                finding.observation_run_id = run_id.clone();
            }
            let include_project_policy =
                !matches!(loaded_policy.status(), PolicyStatus::Invalid { .. });
            self.repository.enrich_findings_with_reviews(
                &project.project_id,
                &mut findings,
                include_project_policy,
                Utc::now(),
            )?;
            if include_project_policy {
                let review_now = Utc::now();
                for finding in &mut findings {
                    let local = finding
                        .review
                        .as_ref()
                        .filter(|review| review.origin == ReviewOrigin::Local);
                    let projected = apply_policy(
                        &loaded_policy,
                        &project.project_id,
                        finding.fingerprint_version,
                        &finding.fingerprint,
                        &finding.category,
                        &finding.rule_id,
                        &finding.file_path,
                        local,
                        review_now,
                    )?;
                    if projected.state == ReviewState::Candidate {
                        finding.review = None;
                    } else {
                        if !finding.review_history.iter().any(|review| {
                            review.origin == projected.origin
                                && review.state == projected.state
                                && review.policy_hash == projected.policy_hash
                                && review.superseded_at.is_none()
                        }) {
                            finding.review_history.insert(0, projected.clone());
                        }
                        finding.review = Some(projected);
                    }
                }
            }
            sort_findings(&mut findings);
            let summary = summarize(
                canonical_path.clone(),
                collection.files.len(),
                collection.skipped,
                collection.total_bytes,
                started_instant.elapsed().as_millis() as u64,
                &findings,
            );
            let coverage = CoverageManifest::from_entries(coverage_entries);
            let started_cutoff = DateTime::parse_from_rfc3339(&started_at)
                .map_err(|_| CommandError::persistence_unavailable())?
                .with_timezone(&Utc);
            let advisory_baseline = self.repository.latest_compatible_baseline(
                &project.project_id,
                super::domain::FINGERPRINT_VERSION,
                &coverage,
                started_cutoff,
            )?;
            let completed_at = timestamp(Utc::now());
            let completed = ScanRunDetail {
                project_id: project.project_id.clone(),
                run_id: run_id.clone(),
                baseline_run_id: advisory_baseline
                    .as_ref()
                    .map(|baseline| baseline.run_id.clone()),
                status: RunStatus::Completed,
                persistence: RunPersistence::Saved,
                policy: loaded_policy.status().clone(),
                started_at,
                completed_at: Some(completed_at.clone()),
                summary: summary.clone(),
                findings: findings.clone(),
                maintenance_warning: None,
            };

            self.run_test_before_completion_seam(&canonical_path);
            if cancel.load(Ordering::SeqCst) {
                return Err(CommandError::scan_cancelled());
            }
            self.run_test_completion_seam(&run_id)?;
            let completion = if self.should_fail_completion() {
                Err(CommandError::persistence_unavailable())
            } else {
                let result = self.repository.complete_run_with_maintenance(
                    &completed,
                    &coverage,
                    self.retention_policy_for_attempt(),
                    Utc::now(),
                );
                if result.is_ok() && self.should_fail_after_committed_completion() {
                    Err(CommandError::persistence_unavailable())
                } else {
                    result
                }
            };
            let stored = match completion {
                Ok(stored) => stored,
                Err(error) if is_retryable_completion_failure(&error) => {
                    return self.retain_pending(completed, coverage, advisory_baseline.as_ref())
                }
                Err(error) => return Err(error),
            };
            let stored = match self.refresh_saved_policy(stored, &project.project_id) {
                Ok(stored) => stored,
                Err((stored, _)) => {
                    let mut stored = *stored;
                    merge_maintenance_warning(&mut stored, POLICY_REFRESH_WARNING);
                    stored
                }
            };
            let _ = events.emit(
                "scan://done",
                serde_json::json!({"findings": stored.findings.len()}),
            );
            Ok(stored)
        }
        .await;
        match result {
            Ok(detail) => {
                run_attempt.disarm();
                Ok(detail)
            }
            Err(error) => {
                run_attempt.fail(&error);
                Err(error)
            }
        }
    }

    pub fn retry_save(&self, retry_token: &str) -> Result<ScanRunDetail, CommandError> {
        let (pending, reservation) = self.reserve_pending(retry_token)?;
        self.run_test_reserved_retry_seam(retry_token);
        let detail = pending.detail();
        let stored = self.repository.complete_run_with_maintenance(
            &detail,
            &pending.coverage,
            self.retention_policy_for_attempt(),
            Utc::now(),
        )?;
        let stored = match self.refresh_saved_policy(stored, &pending.project_id) {
            Ok(stored) => stored,
            Err((_, error)) => return Err(error),
        };
        reservation.remove()?;
        Ok(stored)
    }

    fn reserve_pending(
        &self,
        retry_token: &str,
    ) -> Result<(PendingSave, PendingSaveReservation<'_>), CommandError> {
        let pending = {
            let mut pending_saves = self
                .pending_saves
                .lock()
                .map_err(|_| CommandError::persistence_unavailable())?;
            let pending = pending_saves
                .iter_mut()
                .find(|pending| pending.retry_token == retry_token)
                .ok_or_else(CommandError::not_found)?;
            if pending.in_flight {
                return Err(CommandError::scan_already_running());
            }
            pending.in_flight = true;
            pending.clone()
        };
        Ok((
            pending,
            PendingSaveReservation {
                pending_saves: &self.pending_saves,
                retry_token: retry_token.to_owned(),
                finished: false,
            },
        ))
    }

    fn refresh_saved_policy(
        &self,
        mut stored: ScanRunDetail,
        project_id: &str,
    ) -> Result<ScanRunDetail, (Box<ScanRunDetail>, CommandError)> {
        let project = match self.repository.project_context(project_id) {
            Ok(project) => project,
            Err(error) => {
                strip_project_policy_reviews(&mut stored.findings, Utc::now());
                return Err((Box::new(stored), error));
            }
        };
        let maintenance_warning = stored.maintenance_warning.clone();
        let projection = authoritative_project_policy_projection(
            &self.repository,
            project_id,
            Utc::now(),
            || {
                self.run_test_policy_refresh_seam(&project.canonical_path);
                if self.should_fail_post_completion_policy_refresh() {
                    Err(CommandError::policy_write_failed())
                } else {
                    Ok(())
                }
            },
            |repository| repository.load_run(&stored.run_id),
        );
        let (policy, mut reloaded) = match projection {
            Ok(projection) => projection,
            Err(error) => {
                return self.failed_policy_refresh(stored, &project.canonical_path, error);
            }
        };
        reloaded.policy = policy.clone();
        if matches!(policy, PolicyStatus::Invalid { .. }) {
            strip_project_policy_reviews(&mut reloaded.findings, Utc::now());
        }
        if let Some(warning) = maintenance_warning {
            merge_maintenance_warning(&mut reloaded, &warning);
        }
        Ok(reloaded)
    }

    fn failed_policy_refresh(
        &self,
        mut stored: ScanRunDetail,
        canonical_path: &str,
        error: CommandError,
    ) -> Result<ScanRunDetail, (Box<ScanRunDetail>, CommandError)> {
        if let Ok(current) = load_policy(canonical_path) {
            stored.policy = current.status().clone();
        }
        strip_project_policy_reviews(&mut stored.findings, Utc::now());
        Err((Box::new(stored), error))
    }

    fn acquire_project(
        &self,
        project_id: &str,
        cancel: &AtomicBool,
    ) -> Result<ProjectScanGuard<'_>, CommandError> {
        let mut active = self
            .active_projects
            .lock()
            .map_err(|_| CommandError::persistence_unavailable())?;
        if active.contains(project_id) {
            return Err(CommandError::scan_already_running());
        }
        if active.is_empty() {
            cancel.store(false, Ordering::SeqCst);
        }
        active.insert(project_id.to_owned());
        Ok(ProjectScanGuard {
            project_id: project_id.to_owned(),
            active_projects: &self.active_projects,
        })
    }

    fn mark_incomplete_best_effort(&self, run_id: &str, error_code: &str) {
        if self.should_fail_mark_incomplete() {
            return;
        }
        let _ = self
            .repository
            .mark_incomplete(run_id, &timestamp(Utc::now()), error_code);
    }

    fn retain_pending(
        &self,
        mut detail: ScanRunDetail,
        coverage: CoverageManifest,
        baseline: Option<&ScanRunDetail>,
    ) -> Result<ScanRunDetail, CommandError> {
        let retry_token = Uuid::new_v4().to_string();
        let completed_at = detail.completed_at.clone().unwrap_or_default();
        let pending = PendingSave {
            run_id: detail.run_id.clone(),
            project_id: detail.project_id.clone(),
            result: ScanResult {
                summary: detail.summary.clone(),
                findings: detail.findings.clone(),
            },
            coverage,
            policy: detail.policy.clone(),
            baseline_run_id: detail.baseline_run_id.clone(),
            started_at: detail.started_at.clone(),
            completed_at,
            retry_token: retry_token.clone(),
            in_flight: false,
        };
        detail.persistence = RunPersistence::NotSaved { retry_token };
        apply_advisory_comparison(&mut detail, baseline, &pending.coverage);
        let mut evicted = Vec::new();
        {
            let mut queue = self
                .pending_saves
                .lock()
                .map_err(|_| CommandError::persistence_unavailable())?;
            while queue.len() >= 3 {
                if let Some(index) = queue.iter().position(|pending| !pending.in_flight) {
                    let pending = queue
                        .remove(index)
                        .expect("selected pending save must still exist");
                    evicted.push(pending.run_id);
                } else {
                    return Err(CommandError::persistence_unavailable());
                }
            }
            queue.push_back(pending);
        }
        for run_id in evicted {
            let _ = self.repository.mark_incomplete(
                &run_id,
                &timestamp(Utc::now()),
                "pending_save_evicted",
            );
        }
        Ok(detail)
    }

    #[cfg(test)]
    fn fail_next_completions_for_test(&self, count: usize) {
        self.completion_failures.store(count, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_after_next_committed_completion_for_test(&self) {
        self.fail_after_committed_completion
            .store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_post_completion_policy_refresh_for_test(&self) {
        self.fail_post_completion_policy_refresh
            .store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn should_fail_post_completion_policy_refresh(&self) -> bool {
        self.fail_post_completion_policy_refresh
            .swap(false, Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn should_fail_post_completion_policy_refresh(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn should_fail_after_committed_completion(&self) -> bool {
        self.fail_after_committed_completion
            .swap(false, Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn should_fail_after_committed_completion(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn should_fail_completion(&self) -> bool {
        self.completion_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    #[cfg(not(test))]
    fn should_fail_completion(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn pause_next_scan_for_test(
        &self,
        canonical_path: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.scan_pause.lock().unwrap() = Some((canonical_path, entered, release));
    }

    #[cfg(test)]
    fn pause_before_completion_for_test(
        &self,
        canonical_path: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.before_completion_pause.lock().unwrap() = Some((canonical_path, entered, release));
    }

    #[cfg(test)]
    fn pause_policy_refresh_after_load_for_test(
        &self,
        canonical_path: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.policy_refresh_pause.lock().unwrap() = Some((canonical_path, entered, release));
    }

    #[cfg(test)]
    fn pause_policy_projection_after_read_for_test(
        &self,
        canonical_path: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.policy_projection_pause.lock().unwrap() = Some((canonical_path, entered, release));
    }

    #[cfg(test)]
    fn pause_reserved_retry_for_test(
        &self,
        retry_token: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.retry_reservation_pause.lock().unwrap() = Some((retry_token, entered, release));
    }

    #[cfg(test)]
    fn fail_next_mark_incomplete_for_test(&self) {
        self.mark_incomplete_failures.store(1, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn should_fail_mark_incomplete(&self) -> bool {
        self.mark_incomplete_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    #[cfg(not(test))]
    fn should_fail_mark_incomplete(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn fail_next_retention_maintenance_for_test(&self) {
        self.retention_maintenance_failures
            .store(1, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_post_maintenance_reload_for_test(&self) {
        self.repository.fail_next_post_maintenance_reload_for_test();
    }

    #[cfg(test)]
    fn delete_next_attempt_before_completion_for_test(&self) {
        self.delete_attempt_before_completion
            .store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn retention_policy_for_attempt(&self) -> RetentionPolicy {
        if self
            .retention_maintenance_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            RetentionPolicy {
                max_completed_runs_per_project: 0,
                max_age_days: 0,
            }
        } else {
            RetentionPolicy::default()
        }
    }

    #[cfg(not(test))]
    fn retention_policy_for_attempt(&self) -> RetentionPolicy {
        RetentionPolicy::default()
    }

    #[cfg(test)]
    fn fail_next_scanner_for_test(&self, canonical_path: String) {
        self.scanner_failures.lock().unwrap().insert(canonical_path);
    }

    #[cfg(test)]
    fn run_test_scan_seam(&self, canonical_path: &str) -> Result<(), CommandError> {
        let pause = {
            let mut pause = self.scan_pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|(path, _, _)| path == canonical_path)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.wait();
            release.wait();
        }
        if self.scanner_failures.lock().unwrap().remove(canonical_path) {
            return Err(CommandError::scan_failed());
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn run_test_scan_seam(&self, _canonical_path: &str) -> Result<(), CommandError> {
        Ok(())
    }

    #[cfg(test)]
    fn run_test_before_completion_seam(&self, canonical_path: &str) {
        let pause = {
            let mut pause = self.before_completion_pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|(path, _, _)| path == canonical_path)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn run_test_before_completion_seam(&self, _canonical_path: &str) {}

    #[cfg(test)]
    fn run_test_policy_refresh_seam(&self, canonical_path: &str) {
        let pause = {
            let mut pause = self.policy_refresh_pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|(path, _, _)| path == canonical_path)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn run_test_policy_refresh_seam(&self, _canonical_path: &str) {}

    #[cfg(test)]
    fn run_test_policy_projection_seam(&self, canonical_path: &str) {
        let pause = {
            let mut pause = self.policy_projection_pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|(path, _, _)| path == canonical_path)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn run_test_policy_projection_seam(&self, _canonical_path: &str) {}

    #[cfg(test)]
    fn run_test_reserved_retry_seam(&self, retry_token: &str) {
        let pause = {
            let mut pause = self.retry_reservation_pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|(token, _, _)| token == retry_token)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn run_test_reserved_retry_seam(&self, _retry_token: &str) {}

    #[cfg(test)]
    fn run_test_completion_seam(&self, run_id: &str) -> Result<(), CommandError> {
        if self
            .delete_attempt_before_completion
            .swap(false, Ordering::SeqCst)
        {
            self.repository.delete_run_for_test(run_id)?;
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn run_test_completion_seam(&self, _run_id: &str) -> Result<(), CommandError> {
        Ok(())
    }
}

impl PendingSave {
    fn detail(&self) -> ScanRunDetail {
        ScanRunDetail {
            project_id: self.project_id.clone(),
            run_id: self.run_id.clone(),
            baseline_run_id: self.baseline_run_id.clone(),
            status: RunStatus::Completed,
            persistence: RunPersistence::Saved,
            policy: self.policy.clone(),
            started_at: self.started_at.clone(),
            completed_at: Some(self.completed_at.clone()),
            summary: self.result.summary.clone(),
            findings: self.result.findings.clone(),
            maintenance_warning: None,
        }
    }
}

fn timestamp(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn terminal_error_code(error: &CommandError) -> &'static str {
    match error.code {
        super::error::ErrorCode::ScanCancelled => "scan_cancelled",
        super::error::ErrorCode::PolicyInvalid => "policy_invalid",
        super::error::ErrorCode::ReviewInvalid => "review_invalid",
        super::error::ErrorCode::ScanFailed => "scan_failed",
        _ => "scan_failed",
    }
}

fn is_retryable_completion_failure(error: &CommandError) -> bool {
    error.code == super::error::ErrorCode::PersistenceUnavailable && error.retryable
}

fn merge_maintenance_warning(detail: &mut ScanRunDetail, warning: &str) {
    match detail.maintenance_warning.as_mut() {
        Some(current)
            if warning == RETENTION_WARNING && current.as_str() == POLICY_REFRESH_WARNING =>
        {
            *current = format!("{RETENTION_WARNING}\n{POLICY_REFRESH_WARNING}");
        }
        Some(current) if current != warning && !current.split("\n").any(|part| part == warning) => {
            current.push('\n');
            current.push_str(warning);
        }
        Some(_) => {}
        None => detail.maintenance_warning = Some(warning.to_owned()),
    }
}

fn empty_summary(path: String) -> ScanSummary {
    summarize(path, 0, 0, 0, 0, &[])
}

fn summarize(
    path: String,
    files_scanned: usize,
    files_skipped: usize,
    bytes_scanned: u64,
    duration_ms: u64,
    findings: &[Finding],
) -> ScanSummary {
    let mut rules_fired = std::collections::BTreeMap::new();
    for finding in findings {
        *rules_fired.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }
    let count = |severity: &str| {
        findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };
    ScanSummary {
        path,
        files_scanned,
        files_skipped,
        bytes_scanned,
        duration_ms,
        secrets_found: findings
            .iter()
            .filter(|finding| finding.category == "secret")
            .count(),
        vulnerabilities_found: findings
            .iter()
            .filter(|finding| finding.category == "vulnerability")
            .count(),
        total_findings: findings.len(),
        critical: count("critical"),
        high: count("high"),
        medium: count("medium"),
        low: count("low"),
        info: findings.len() - count("critical") - count("high") - count("medium") - count("low"),
        rules_fired,
    }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        right
            .cwe_exploited
            .cmp(&left.cwe_exploited)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.line.cmp(&right.line))
    });
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn strip_project_policy_reviews(findings: &mut [Finding], now: DateTime<Utc>) {
    for finding in findings {
        finding.review = finding
            .review_history
            .iter()
            .find(|review| {
                review.origin == ReviewOrigin::Local
                    && review.superseded_at.is_none()
                    && review.state != super::domain::ReviewState::Candidate
                    && review.expires_at.as_deref().is_none_or(|expires_at| {
                        DateTime::parse_from_rfc3339(expires_at)
                            .is_ok_and(|expires_at| expires_at.with_timezone(&Utc) > now)
                    })
            })
            .cloned();
    }
}

fn apply_advisory_comparison(
    detail: &mut ScanRunDetail,
    baseline: Option<&ScanRunDetail>,
    coverage: &CoverageManifest,
) {
    let current_identities = detail
        .findings
        .iter()
        .map(|finding| (finding.fingerprint_version, finding.fingerprint.clone()))
        .collect::<HashSet<_>>();
    let Some(baseline) = baseline else {
        for finding in &mut detail.findings {
            finding.diff_status = Some(DiffStatus::New);
        }
        return;
    };
    let baseline_observations = baseline
        .findings
        .iter()
        .filter(|finding| finding.observation_run_id == baseline.run_id)
        .collect::<Vec<_>>();
    let baseline_identities = baseline_observations
        .iter()
        .map(|finding| (finding.fingerprint_version, finding.fingerprint.clone()))
        .collect::<HashSet<_>>();
    for finding in &mut detail.findings {
        finding.diff_status = Some(
            if baseline_identities
                .contains(&(finding.fingerprint_version, finding.fingerprint.clone()))
            {
                DiffStatus::Unchanged
            } else {
                DiffStatus::New
            },
        );
    }
    for finding in baseline_observations {
        if current_identities.contains(&(finding.fingerprint_version, finding.fingerprint.clone()))
        {
            continue;
        }
        let mut projected = finding.clone();
        if coverage.is_covered(&projected.file_path, &projected.category) {
            projected.diff_status = Some(DiffStatus::Resolved);
            projected.resolved_by_run_id = Some(detail.run_id.clone());
        } else {
            projected.diff_status = Some(DiffStatus::NotEvaluated);
            projected.resolved_by_run_id = None;
        }
        detail.findings.push(projected);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{atomic::AtomicBool, Arc, Barrier, Mutex};

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
                    let crate::findings::domain::PolicyStatus::Valid { hash } = current.status()
                    else {
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
        service.pause_before_completion_for_test(
            canonical.clone(),
            entered.clone(),
            release.clone(),
        );
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
        assert!(first.findings[0].review_history.iter().any(|review| {
            review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
        }));

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
        assert!(current.review_history.iter().any(|review| {
            review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
        }));
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
        service.pause_before_completion_for_test(
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
        assert!(current.review_history.iter().any(|review| {
            review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
        }));
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
        service.pause_policy_refresh_after_load_for_test(
            canonical,
            entered.clone(),
            release.clone(),
        );
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
        assert!(current.review_history.iter().any(|review| {
            review.origin == crate::findings::domain::ReviewOrigin::ProjectPolicy
        }));
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
}

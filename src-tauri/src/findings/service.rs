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
    },
    error::CommandError,
    fingerprint::assign_fingerprints,
    policy::{apply_policy, load_policy},
    repository::FindingsRepository,
    review::{reconcile_project_policy_reviews, save_local_review, save_project_policy_review},
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
    scanner_failures: Mutex<HashSet<String>>,
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
}

struct ProjectScanGuard<'a> {
    project_id: String,
    active_projects: &'a Mutex<HashSet<String>>,
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
            scanner_failures: Mutex::new(HashSet::new()),
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
        let mut context = self.repository.upsert_project(
            &Uuid::new_v4().to_string(),
            &canonical_path,
            &display_name,
            &now,
            None,
        )?;
        let loaded = load_policy(&canonical)?;
        context.policy = loaded.status().clone();
        if !matches!(context.policy, PolicyStatus::Invalid { .. }) {
            reconcile_project_policy_reviews(&self.repository, &context.project_id, Utc::now())?;
        }
        Ok(context)
    }

    pub fn load_run(&self, run_id: &str) -> Result<ScanRunDetail, CommandError> {
        let initial = self.repository.load_run(run_id)?;
        let project = self.repository.project_context(&initial.project_id)?;
        let policy = load_policy(&project.canonical_path)?;
        if !matches!(policy.status(), PolicyStatus::Invalid { .. }) {
            reconcile_project_policy_reviews(&self.repository, &initial.project_id, Utc::now())?;
        }
        let mut loaded = self.repository.load_run(run_id)?;
        loaded.policy = policy.status().clone();
        if matches!(policy.status(), PolicyStatus::Invalid { .. }) {
            strip_project_policy_reviews(&mut loaded.findings, Utc::now());
        }
        Ok(loaded)
    }

    pub fn list_recent_projects(&self, limit: usize) -> Result<Vec<RecentProject>, CommandError> {
        self.repository.list_recent_projects(limit)
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
        self.run_test_scan_seam(&canonical_path, &run_id)?;

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
            return self.fail_started_run(&run_id, "scan_failed", CommandError::scan_failed());
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
            return self.fail_started_run(
                &run_id,
                "scan_cancelled",
                CommandError::scan_cancelled(),
            );
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
            return self.fail_started_run(
                &run_id,
                "scan_cancelled",
                CommandError::scan_cancelled(),
            );
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
            canonical_path,
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

        let completion = if self.should_fail_completion() {
            Err(CommandError::persistence_unavailable())
        } else {
            let result = self.repository.complete_run(&completed, &coverage);
            if result.is_ok() && self.should_fail_after_committed_completion() {
                Err(CommandError::persistence_unavailable())
            } else {
                result
            }
        };
        let mut stored = match completion {
            Ok(stored) => stored,
            Err(_) => {
                return Ok(self.retain_pending(completed, coverage, advisory_baseline.as_ref()))
            }
        };
        if !matches!(loaded_policy.status(), PolicyStatus::Invalid { .. }) {
            let refreshed = if self.should_fail_post_completion_policy_refresh() {
                Err(CommandError::policy_write_failed())
            } else {
                reconcile_project_policy_reviews(&self.repository, &project.project_id, Utc::now())
                    .and_then(|_| self.repository.load_run(&run_id))
            };
            match refreshed {
                Ok(reloaded) => stored = reloaded,
                Err(_) => {
                    strip_project_policy_reviews(&mut stored.findings, Utc::now());
                    stored.maintenance_warning = Some(POLICY_REFRESH_WARNING.into());
                }
            }
        } else {
            strip_project_policy_reviews(&mut stored.findings, Utc::now());
        }
        if self
            .repository
            .apply_retention(Utc::now(), RetentionPolicy::default())
            .is_err()
            && stored.maintenance_warning.is_none()
        {
            stored.maintenance_warning = Some(RETENTION_WARNING.into());
        }
        let _ = events.emit(
            "scan://done",
            serde_json::json!({"findings": stored.findings.len()}),
        );
        Ok(stored)
    }

    pub fn retry_save(&self, retry_token: &str) -> Result<ScanRunDetail, CommandError> {
        let pending = self
            .pending_saves
            .lock()
            .map_err(|_| CommandError::persistence_unavailable())?
            .iter()
            .find(|pending| pending.retry_token == retry_token)
            .cloned()
            .ok_or_else(CommandError::not_found)?;
        let detail = pending.detail();
        let stored = self.repository.complete_run(&detail, &pending.coverage)?;
        let project = self.repository.project_context(&pending.project_id)?;
        let loaded = load_policy(&project.canonical_path)?;
        let mut stored = if matches!(loaded.status(), PolicyStatus::Invalid { .. }) {
            let mut stored = stored;
            strip_project_policy_reviews(&mut stored.findings, Utc::now());
            stored
        } else {
            reconcile_project_policy_reviews(&self.repository, &pending.project_id, Utc::now())?;
            self.repository.load_run(&pending.run_id)?
        };
        if self
            .repository
            .apply_retention(Utc::now(), RetentionPolicy::default())
            .is_err()
        {
            stored.maintenance_warning = Some(RETENTION_WARNING.into());
        }
        let mut pending_saves = self
            .pending_saves
            .lock()
            .map_err(|_| CommandError::persistence_unavailable())?;
        if let Some(index) = pending_saves
            .iter()
            .position(|pending| pending.retry_token == retry_token)
        {
            pending_saves.remove(index);
        }
        Ok(stored)
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

    fn fail_started_run<T>(
        &self,
        run_id: &str,
        error_code: &str,
        error: CommandError,
    ) -> Result<T, CommandError> {
        let _ = self
            .repository
            .mark_incomplete(run_id, &timestamp(Utc::now()), error_code);
        Err(error)
    }

    fn retain_pending(
        &self,
        mut detail: ScanRunDetail,
        coverage: CoverageManifest,
        baseline: Option<&ScanRunDetail>,
    ) -> ScanRunDetail {
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
        };
        detail.persistence = RunPersistence::NotSaved { retry_token };
        apply_advisory_comparison(&mut detail, baseline, &pending.coverage);
        let mut evicted = Vec::new();
        if let Ok(mut queue) = self.pending_saves.lock() {
            while queue.len() >= 3 {
                if let Some(pending) = queue.pop_front() {
                    evicted.push(pending.run_id);
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
        detail
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
    fn fail_next_scanner_for_test(&self, canonical_path: String) {
        self.scanner_failures.lock().unwrap().insert(canonical_path);
    }

    #[cfg(test)]
    fn run_test_scan_seam(&self, canonical_path: &str, run_id: &str) -> Result<(), CommandError> {
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
            return self.fail_started_run(run_id, "scan_failed", CommandError::scan_failed());
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn run_test_scan_seam(&self, _canonical_path: &str, _run_id: &str) -> Result<(), CommandError> {
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

    use super::{FindingsService, ScanEventSink};

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

    #[test]
    fn service_can_be_constructed_over_a_repository() {
        let repository = crate::findings::repository::FindingsRepository::open_in_memory().unwrap();
        let _service = FindingsService::new(repository);
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
}

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
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
    adapters::{
        persistence::CanonicalSqliteRepository,
        scanners::{source_artifact, source_observation},
    },
    cve::CveState,
    fs_utils::{self, CollectFilesOptions},
    models::{Finding, ScanOptions, ScanResult, ScanSummary},
    presentation::CanonicalRunEvents,
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

/// One finding a bulk review could not be recorded against.
#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BulkReviewFailure {
    pub fingerprint: String,
    pub message: String,
}

/// What a bulk review actually did.
///
/// Both halves are reported. A caller that only learns "it worked" cannot tell
/// a reviewer that three of their forty decisions did not land.
#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BulkReviewOutcome {
    pub recorded: Vec<ReviewRecord>,
    pub failures: Vec<BulkReviewFailure>,
}

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
    pending_eviction_pause: Mutex<Option<ScanPause>>,
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

    fn replace(mut self, pending: PendingSave) -> Result<(), CommandError> {
        let mut pending_saves = self
            .pending_saves
            .lock()
            .map_err(|_| CommandError::persistence_unavailable())?;
        let index = pending_saves
            .iter()
            .position(|candidate| candidate.retry_token == self.retry_token)
            .ok_or_else(CommandError::not_found)?;
        pending_saves.remove(index);
        pending_saves.push_back(pending);
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
    pub(crate) fn repository(&self) -> &FindingsRepository {
        &self.repository
    }

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
            pending_eviction_pause: Mutex::new(None),
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

    pub fn recheck_options(
        &self,
        run_id: &str,
        project_id: &str,
    ) -> Result<ScanOptions, CommandError> {
        let original = self.repository.load_run(run_id)?;
        if original.project_id != project_id || original.status != RunStatus::Completed {
            return Err(CommandError::baseline_incompatible());
        }
        let stored_project = self.repository.project_context(project_id)?;
        let project = self.inspect_project(&stored_project.canonical_path)?;
        if matches!(project.policy, PolicyStatus::Invalid { .. }) {
            return Err(CommandError::policy_invalid());
        }
        let mut options = self.repository.run_options(run_id)?;
        let scope = Path::new(&options.path)
            .canonicalize()
            .map_err(|_| CommandError::invalid_target())?;
        if !scope.is_dir() || !scope.starts_with(Path::new(&project.canonical_path)) {
            return Err(CommandError::invalid_target());
        }
        options.path = scope.to_string_lossy().into_owned();
        // The scan service revalidates current policy. A historic override must
        // never authorize ignoring a newly invalid policy during recheck.
        options.ignore_invalid_policy = false;
        Ok(options)
    }

    pub fn compare_recheck_runs(
        &self,
        current_run_id: &str,
        baseline_run_id: &str,
    ) -> Result<Vec<Finding>, CommandError> {
        super::review::read_only_recheck_comparison(
            &self.repository,
            current_run_id,
            baseline_run_id,
            Utc::now(),
        )
    }

    pub fn compare_runs(
        &self,
        current_run_id: &str,
        baseline_run_id: &str,
    ) -> Result<Vec<Finding>, CommandError> {
        // Preserve repository comparison/coverage authority and apply current
        // policy in memory. This route must never reconcile stored review events.
        super::review::read_only_project_policy_comparison(
            &self.repository,
            current_run_id,
            baseline_run_id,
            Utc::now(),
        )
    }

    pub fn list_recent_projects(&self, limit: usize) -> Result<Vec<RecentProject>, CommandError> {
        let mut projects = self.repository.list_recent_projects(limit)?;
        let now = Utc::now();
        for project in &mut projects {
            // A missing project is distinct from an accessible project with no policy.
            // Retain its saved history, but do not present stale totals as current.
            let root = std::path::Path::new(&project.canonical_path);
            let accessible = || {
                root.canonicalize().is_ok_and(|canonical| canonical == root)
                    && std::fs::read_dir(root).is_ok()
            };
            let projected = project.last_completed_run_id.as_deref().and_then(|run_id| {
                if !accessible() {
                    return None;
                }
                let mut run = self.repository.load_run(run_id).ok()?;
                // Comparison can append baseline-only findings; history totals
                // describe observations actually saved in the completed run.
                run.findings
                    .retain(|finding| finding.observation_run_id == run_id);
                let findings = super::review::read_only_project_policy_findings(
                    &self.repository,
                    &project.project_id,
                    run.findings,
                    now,
                )
                .ok()?;
                accessible().then_some(findings)
            });
            project.counts_available = Some(projected.is_some());
            if let Some(findings) = projected {
                let open = findings
                    .iter()
                    .filter(|finding| super::repository::is_open_finding(finding))
                    .collect::<Vec<_>>();
                project.open_findings = open.len();
                project.critical = open
                    .iter()
                    .filter(|finding| finding.severity == "critical")
                    .count();
                project.high = open
                    .iter()
                    .filter(|finding| finding.severity == "high")
                    .count();
            }
        }
        Ok(projects)
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

    /// Record the same decision against many findings.
    ///
    /// A first scan of a real project produces hundreds of findings, and
    /// dismissing them one at a time is where a scanner gets abandoned. This
    /// exists so a reviewer can act on a whole class at once.
    ///
    /// Deliberately *not* atomic. Reviews are an append-only history, so a
    /// partial run cannot be rolled back into "nothing happened" without
    /// writing more history to undo history — and a reviewer who marked 40
    /// findings would rather keep the 37 that succeeded than lose them because
    /// three were stale. Every outcome is reported per finding instead, so a
    /// partial result is visible rather than silent.
    pub fn save_reviews(
        &self,
        requests: &[ReviewRequest],
        now: DateTime<Utc>,
    ) -> BulkReviewOutcome {
        let mut recorded = Vec::new();
        let mut failures = Vec::new();
        for request in requests {
            match self.save_review(request, now) {
                Ok(record) => recorded.push(record),
                Err(error) => failures.push(BulkReviewFailure {
                    fingerprint: request.fingerprint.clone(),
                    message: error.message.clone(),
                }),
            }
        }
        BulkReviewOutcome { recorded, failures }
    }

    pub async fn scan<E: ScanEventSink + ?Sized>(
        &self,
        options: ScanOptions,
        cve: &CveState,
        cancel: &AtomicBool,
        events: &E,
    ) -> Result<ScanRunDetail, CommandError> {
        self.scan_with_packs(
            options,
            cve,
            cancel,
            events,
            &crate::scanners::rulepacks::AppliedRulePacks::empty(),
        )
        .await
    }

    /// The same scan with installed rule packs applied: every enabled
    /// pack's text-engine rules run beside the built-ins, and the run
    /// records which pack identities were in force.
    #[allow(clippy::too_many_arguments)]
    pub async fn scan_with_packs<E: ScanEventSink + ?Sized>(
        &self,
        options: ScanOptions,
        cve: &CveState,
        cancel: &AtomicBool,
        events: &E,
        packs: &crate::scanners::rulepacks::AppliedRulePacks,
    ) -> Result<ScanRunDetail, CommandError> {
        let project_root = std::path::PathBuf::from(&options.path);
        self.scan_scoped_with_packs(options, &project_root, cve, cancel, events, packs, &[])
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn scan_scoped_with_packs<E: ScanEventSink + ?Sized>(
        &self,
        options: ScanOptions,
        project_root: &Path,
        cve: &CveState,
        cancel: &AtomicBool,
        events: &E,
        packs: &crate::scanners::rulepacks::AppliedRulePacks,
        coverage_warnings: &[String],
    ) -> Result<ScanRunDetail, CommandError> {
        let started_instant = Instant::now();
        let scan_target = Path::new(&options.path)
            .canonicalize()
            .map_err(|_| CommandError::invalid_target())?;
        let canonical = project_root
            .canonicalize()
            .map_err(|_| CommandError::invalid_target())?;
        // The span covers the whole run, so every event underneath it carries
        // the run's identity — which is what makes a log from a user's machine
        // readable at all.
        tracing::info!(
            target_path = %canonical.display(),
            scan_secrets = options.scan_secrets,
            scan_vulnerabilities = options.scan_vulnerabilities,
            max_file_size_kb = options.max_file_size_kb,
            "scan starting"
        );
        if !canonical.is_dir() || !scan_target.is_dir() || !scan_target.starts_with(&canonical) {
            return Err(CommandError::invalid_target());
        }
        let canonical_path = canonical.to_string_lossy().into_owned();
        let display_name = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or(&canonical_path)
            .to_owned();
        let git_before = crate::git_context::snapshot(&canonical).ok();
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
        let canonical_repository = CanonicalSqliteRepository::new(&self.repository);
        let canonical_events = CanonicalRunEvents::new(events);
        let coordinator =
            oxaudit_application::RunCoordinator::new(&canonical_repository, &canonical_events);
        let mut canonical_run = oxaudit_domain::Run::queued(
            oxaudit_domain::RunKind::Source,
            display_name,
            epoch_millis(),
        );
        canonical_run.id = oxaudit_domain::RunId::parse(run_id.clone())
            .map_err(|_| CommandError::persistence_unavailable())?;
        canonical_run.rule_pack_ids = packs
            .ids()
            .into_iter()
            .filter_map(|id| oxaudit_domain::RulePackId::parse(id).ok())
            .collect();
        canonical_run
            .warnings
            .extend(
                coverage_warnings
                    .iter()
                    .map(|message| oxaudit_domain::RunWarning {
                        code: "source_rule_coverage".into(),
                        message: message.clone(),
                    }),
            );
        let mut managed_run = Some(
            coordinator
                .begin(canonical_run)
                .map_err(|_| CommandError::persistence_unavailable())?,
        );
        #[cfg(test)]
        self.started_run_ids.lock().unwrap().push(run_id.clone());
        let mut run_attempt = RunAttemptGuard {
            service: self,
            run_id: run_id.clone(),
            armed: true,
        };
        let result = async {
            self.run_test_scan_seam(&canonical_path)?;

            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Discovering, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;

            let _ = events.emit("scan://progress", Value::from("walking"));
            let collection = fs_utils::collect_source_files_bounded(
                &scan_target,
                CollectFilesOptions {
                    project_root: &canonical,
                    include_git: options.include_git,
                    follow_symlinks: options.follow_symlinks,
                    extra_ignored: &options.extra_ignored_dirs,
                },
                fs_utils::CollectionBudget::default(),
                Some(cancel),
            )
            .map_err(|error| match error {
                fs_utils::CollectionError::Cancelled => CommandError::scan_cancelled(),
                error => CommandError::scan_resource_limit(error.to_string()),
            })?;
            if collection.files.is_empty() {
                // Not a failure: nothing broke. The target, the ignore list,
                // and the size limit between them selected no files, and
                // saying so beats a generic error the user cannot act on.
                return Err(CommandError::nothing_to_scan());
            }
            let canonical_run_id = managed_run
                .as_ref()
                .expect("managed run exists until terminal handling")
                .run()
                .id
                .clone();
            let mut canonical_artifacts = BTreeMap::new();
            for file in &collection.files {
                let artifact = source_artifact(&canonical_run_id, file)
                    .map_err(|_| CommandError::scan_failed())?;
                managed_run
                    .as_mut()
                    .expect("managed run exists until terminal handling")
                    .append_artifact(&artifact)
                    .map_err(|_| CommandError::persistence_unavailable())?;
                canonical_artifacts.insert(artifact.location.normalized_path.clone(), artifact);
            }
            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;
            let total = collection.files.len();
            let _ = events.emit(
                "scan://progress",
                serde_json::json!({"total": total, "done": 0, "phase": "scanning"}),
            );
            let processed = AtomicUsize::new(0);
            // Read once, before the parallel walk, so every file is assessed
            // against the same view of what the project configures.
            let config_collection = if scan_target != canonical {
                Some(
                    fs_utils::collect_source_files_bounded(
                        &canonical,
                        CollectFilesOptions {
                            project_root: &canonical,
                            include_git: options.include_git,
                            follow_symlinks: options.follow_symlinks,
                            extra_ignored: &options.extra_ignored_dirs,
                        },
                        fs_utils::CollectionBudget::default(),
                        Some(cancel),
                    )
                    .map_err(|error| match error {
                        fs_utils::CollectionError::Cancelled => CommandError::scan_cancelled(),
                        other => CommandError::scan_resource_limit(other.to_string()),
                    })?,
                )
            } else {
                None
            };
            let config_files = config_collection.as_ref().unwrap_or(&collection);
            let project_config = scanners::config_values::ProjectConfig::from_paths(
                config_files
                    .files
                    .iter()
                    .map(|file| file.canonical_path.as_path()),
            );
            // Workers only retain one bounded outcome each. The shared collector
            // enforces the run limit as findings are produced, before later files run.
            let aggregate = std::sync::Mutex::new((Vec::new(), Vec::new(), None));
            let stopped = AtomicBool::new(false);
            collection.files.par_iter().for_each(|file| {
                if stopped.load(Ordering::Relaxed) {
                    return;
                }
                if cancel.load(Ordering::Relaxed) {
                    stopped.store(true, Ordering::Relaxed);
                    return;
                }
                let relative = file
                    .project_relative_path
                    .to_string_lossy()
                    .replace('\\', "/");
                let outcome = scanners::scan_file_in_project_with_packs(
                    &file.canonical_path,
                    &relative,
                    options.max_file_size_kb.max(1),
                    options.scan_secrets,
                    options.scan_vulnerabilities,
                    &project_config,
                    packs,
                );
                let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 25 == 0 || done == total {
                    let _ = events.emit(
                        "scan://progress",
                        serde_json::json!({"total": total, "done": done, "phase": "scanning"}),
                    );
                }
                let mut aggregate = aggregate.lock().expect("source collector not poisoned");
                if aggregate.2.is_some() {
                    return;
                }
                let limit = outcome
                    .limit_error
                    .map(|error| CommandError::scan_resource_limit(error.to_string()))
                    .or_else(|| {
                        scanners::ensure_run_finding_budget(
                            aggregate.0.len(),
                            outcome.findings.len(),
                            scanners::MAX_FINDINGS_PER_RUN,
                        )
                        .err()
                        .map(|error| CommandError::scan_resource_limit(error.to_string()))
                    });
                if let Some(error) = limit {
                    aggregate.2 = Some(error);
                    stopped.store(true, Ordering::Relaxed);
                    return;
                }
                aggregate.1.push((relative, outcome.covered_families));
                aggregate.0.extend(outcome.findings);
            });
            if cancel.load(Ordering::Relaxed) {
                return Err(CommandError::scan_cancelled());
            }
            let (mut findings, mut coverage_entries, limit_error) = aggregate
                .into_inner()
                .expect("source collector not poisoned");
            if let Some(error) = limit_error {
                return Err(error);
            }
            coverage_entries.sort_by(|a, b| a.0.cmp(&b.0));
            if cancel.load(Ordering::Relaxed) {
                return Err(CommandError::scan_cancelled());
            }
            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Normalizing, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;
            assign_fingerprints(&mut findings);
            for finding in &mut findings {
                let decision = scope::classify_at(&finding.file_path, finding.in_test_region);
                finding.scope = Some(decision.scope);
                finding.scope_reason = Some(decision.reason);
                finding.observation_run_id = run_id.clone();
            }
            let mut observation_manifest = oxaudit_application::StageManifest::new(
                "source_observations",
                findings.iter().map(|finding| finding.id.clone()),
            )
            .map_err(|_| CommandError::scan_failed())?;
            let mut canonical_observations = Vec::with_capacity(findings.len());
            for finding in &findings {
                let artifact = canonical_artifacts
                    .get(&finding.file_path)
                    .ok_or_else(CommandError::scan_failed)?;
                let observation = source_observation(&canonical_run_id, artifact, finding)
                    .map_err(|_| CommandError::scan_failed())?;
                observation_manifest.record(observation.observation.id.to_string());
                canonical_observations.push(observation);
            }
            observation_manifest
                .reconcile()
                .map_err(|_| CommandError::scan_failed())?;
            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .append_observations(canonical_observations)
                .map_err(|_| CommandError::persistence_unavailable())?;
            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Enriching, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;
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
            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Assessing, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;
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
            let mut summary = summarize(
                canonical_path.clone(),
                coverage_entries
                    .iter()
                    .filter(|(_, families)| !families.is_empty())
                    .count(),
                collection.skipped
                    + coverage_entries
                        .iter()
                        .filter(|(_, families)| families.is_empty())
                        .count(),
                collection.total_bytes,
                started_instant.elapsed().as_millis() as u64,
                &findings,
            );
            summary.coverage_warnings = coverage_warnings.to_vec();
            let git_after = crate::git_context::snapshot(&canonical).ok();
            if git_before.is_some() || git_after.is_some() {
                summary.git_context = Some(crate::git_context::GitEvidence {
                    context_changed: git_before
                        .as_ref()
                        .zip(git_after.as_ref())
                        .map(|(before, after)| before != after),
                    before: git_before.clone(),
                    after: git_after,
                });
            }
            let mut coverage = CoverageManifest::from_entries(coverage_entries);
            coverage.rule_pack_hashes = packs.snapshot_hashes();
            coverage.installed_rule_pack_ids = Some(packs.installed_ids().clone());
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

            tracing::info!(
                run_id = %run_id,
                files_scanned = summary.files_scanned,
                files_skipped = summary.files_skipped,
                findings = summary.total_findings,
                duration_ms = summary.duration_ms,
                "scan completed"
            );

            managed_run
                .as_mut()
                .expect("managed run exists until terminal handling")
                .transition(oxaudit_domain::RunState::Persisting, epoch_millis())
                .map_err(|_| CommandError::persistence_unavailable())?;

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
            Ok(mut detail) => {
                if let Some(mut canonical) = managed_run.take() {
                    let canonical_result = match &detail.persistence {
                        RunPersistence::Saved => canonical.complete(epoch_millis()),
                        RunPersistence::NotSaved { .. } => {
                            canonical.warning(
                                "legacy_persistence_pending",
                                "The canonical run is waiting for the existing durable-save retry.",
                            );
                            canonical.checkpoint()
                        }
                    };
                    if canonical_result.is_err() {
                        merge_maintenance_warning(
                            &mut detail,
                            "Run saved, but its canonical evidence graph could not be finalized.",
                        );
                    }
                }
                run_attempt.disarm();
                Ok(detail)
            }
            Err(error) => {
                if let Some(canonical) = managed_run.take() {
                    let terminal = if error.code == super::error::ErrorCode::ScanCancelled {
                        oxaudit_domain::RunState::Cancelled
                    } else {
                        oxaudit_domain::RunState::Incomplete
                    };
                    let _ = canonical.terminate(terminal, epoch_millis());
                }
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
        if let Ok(run_id) = oxaudit_domain::RunId::parse(pending.run_id.clone()) {
            if let Some(mut run) = self.repository.canonical_load_run(&run_id)? {
                if run.state == oxaudit_domain::RunState::Persisting {
                    run.transition(oxaudit_domain::RunState::Completed, epoch_millis())
                        .map_err(|_| CommandError::persistence_unavailable())?;
                    self.repository.canonical_save_run(&run)?;
                }
            }
        }
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
        let _ = cancel;
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
        apply_advisory_comparison(&mut detail, baseline, &pending.coverage);
        let eviction = {
            let mut queue = self
                .pending_saves
                .lock()
                .map_err(|_| CommandError::persistence_unavailable())?;
            if queue.len() < 3 {
                queue.push_back(pending.clone());
                None
            } else {
                let candidate = queue
                    .iter_mut()
                    .find(|candidate| !candidate.in_flight)
                    .ok_or_else(CommandError::persistence_unavailable)?;
                candidate.in_flight = true;
                Some((candidate.run_id.clone(), candidate.retry_token.clone()))
            }
        };
        if let Some((run_id, candidate_token)) = eviction {
            let reservation = PendingSaveReservation {
                pending_saves: &self.pending_saves,
                retry_token: candidate_token.clone(),
                finished: false,
            };
            self.run_test_pending_eviction_seam(&candidate_token);
            self.mark_pending_evicted(&run_id)?;
            reservation.replace(pending)?;
        }
        detail.persistence = RunPersistence::NotSaved { retry_token };
        Ok(detail)
    }

    fn mark_pending_evicted(&self, run_id: &str) -> Result<(), CommandError> {
        if self.should_fail_mark_incomplete() {
            return Err(CommandError::persistence_unavailable());
        }
        self.repository
            .mark_incomplete(run_id, &timestamp(Utc::now()), "pending_save_evicted")
    }

    #[cfg(test)]
    pub(crate) fn fail_next_completions_for_test(&self, count: usize) {
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
    fn pause_pending_eviction_after_reservation_for_test(
        &self,
        retry_token: String,
        entered: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) {
        *self.pending_eviction_pause.lock().unwrap() = Some((retry_token, entered, release));
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
    fn run_test_pending_eviction_seam(&self, retry_token: &str) {
        let pause = {
            let mut pause = self.pending_eviction_pause.lock().unwrap();
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
    fn run_test_pending_eviction_seam(&self, _retry_token: &str) {}

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

fn epoch_millis() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default()
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
        coverage_warnings: Vec::new(),
        git_context: None,
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
                    && review.expires_at.as_deref().map_or(true, |expires_at| {
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
        // An unsaved projection has no authoritative baseline pack snapshot.
        // Keep custom detector absence unknown until durable comparison.
        if !projected.rule_id.contains('/')
            && coverage.is_covered(&projected.file_path, &projected.category)
        {
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
#[path = "service_tests.rs"]
mod tests;

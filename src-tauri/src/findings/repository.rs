use std::{path::Path, sync::Mutex, time::Duration};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::{
    coverage::CoverageManifest,
    domain::{
        FindingScope, PolicyStatus, RecentProject, ReviewOrigin, ReviewRecord, ReviewState,
        RunPersistence, RunStatus, ScanRunDetail,
    },
    error::CommandError,
};
use crate::{
    models::{Finding, ScanOptions, ScanSummary},
    triage::{
        gates::{Gate, GateNote},
        manifest::Manifest,
    },
};

const MIGRATION_V1: &str = r#"
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  canonical_path TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_opened_at TEXT NOT NULL,
  last_options_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE scan_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_run_id TEXT REFERENCES scan_runs(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK(status IN ('running','completed','incomplete')),
  scanner_version TEXT NOT NULL,
  fingerprint_version INTEGER NOT NULL,
  options_json TEXT NOT NULL,
  policy_status_json TEXT NOT NULL,
  policy_hash TEXT,
  coverage_json TEXT,
  summary_json TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  error_code TEXT
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  fingerprint_version INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  scope TEXT NOT NULL,
  scope_reason TEXT NOT NULL,
  UNIQUE(run_id, fingerprint_version, fingerprint)
);

CREATE INDEX findings_run_idx ON findings(run_id);
CREATE INDEX findings_fingerprint_idx ON findings(fingerprint_version, fingerprint);
CREATE INDEX runs_project_completed_idx ON scan_runs(project_id, status, completed_at DESC);

CREATE TABLE reviews (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint_version INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence TEXT,
  entry_point TEXT,
  data_flow TEXT,
  gates_json TEXT NOT NULL DEFAULT '[]',
  deciding_gate TEXT,
  expires_at TEXT,
  origin TEXT NOT NULL,
  policy_hash TEXT,
  updated_at TEXT NOT NULL,
  superseded_at TEXT
);

CREATE INDEX reviews_history_idx
  ON reviews(project_id, fingerprint_version, fingerprint, updated_at DESC);
CREATE UNIQUE INDEX reviews_active_origin_idx
  ON reviews(project_id, fingerprint_version, fingerprint, origin)
  WHERE superseded_at IS NULL;
"#;

pub struct FindingsRepository {
    connection: Mutex<Connection>,
}

impl FindingsRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CommandError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(persistence_error)?;
            #[cfg(unix)]
            protect(parent, 0o700)?;
        }

        let mut connection = Connection::open(path).map_err(persistence_error)?;
        #[cfg(unix)]
        protect(path, 0o600)?;
        initialize_connection(&connection, true)?;
        migrate(&mut connection, MIGRATION_V1)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open_in_memory() -> Result<Self, CommandError> {
        let mut connection = Connection::open_in_memory().map_err(persistence_error)?;
        initialize_connection(&connection, false)?;
        migrate(&mut connection, MIGRATION_V1)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn upsert_project(
        &self,
        project_id: &str,
        canonical_path: &str,
        display_name: &str,
        opened_at: &str,
        last_options: &ScanOptions,
    ) -> Result<(), CommandError> {
        let options_json = to_json(last_options)?;
        self.connection
            .lock()
            .map_err(persistence_error)?
            .execute(
                r#"INSERT INTO projects(
                     id, canonical_path, display_name, created_at, last_opened_at, last_options_json
                   ) VALUES (?1, ?2, ?3, ?4, ?4, ?5)
                   ON CONFLICT(id) DO UPDATE SET
                     canonical_path = excluded.canonical_path,
                     display_name = excluded.display_name,
                     last_opened_at = excluded.last_opened_at,
                     last_options_json = excluded.last_options_json"#,
                params![
                    project_id,
                    canonical_path,
                    display_name,
                    opened_at,
                    options_json
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub fn start_run(
        &self,
        detail: &ScanRunDetail,
        scanner_version: &str,
        options: &ScanOptions,
    ) -> Result<(), CommandError> {
        if detail.status != RunStatus::Running {
            return Err(CommandError::persistence_unavailable());
        }
        let options_json = to_json(options)?;
        let policy_status_json = to_json(&detail.policy)?;
        let policy_hash = match &detail.policy {
            PolicyStatus::Valid { hash } => Some(hash.as_str()),
            PolicyStatus::Missing | PolicyStatus::Invalid { .. } => None,
        };
        self.connection
            .lock()
            .map_err(persistence_error)?
            .execute(
                r#"INSERT INTO scan_runs(
                     id, project_id, baseline_run_id, status, scanner_version, fingerprint_version,
                     options_json, policy_status_json, policy_hash, started_at
                   ) VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, ?8, ?9)
                   ON CONFLICT(id) DO UPDATE SET
                     project_id = excluded.project_id,
                     baseline_run_id = excluded.baseline_run_id,
                     scanner_version = excluded.scanner_version,
                     fingerprint_version = excluded.fingerprint_version,
                     options_json = excluded.options_json,
                     policy_status_json = excluded.policy_status_json,
                     policy_hash = excluded.policy_hash,
                     started_at = excluded.started_at
                   WHERE scan_runs.status = 'running'"#,
                params![
                    detail.run_id,
                    detail.project_id,
                    detail.baseline_run_id,
                    scanner_version,
                    super::domain::FINGERPRINT_VERSION,
                    options_json,
                    policy_status_json,
                    policy_hash,
                    detail.started_at,
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub fn complete_run(
        &self,
        detail: &ScanRunDetail,
        coverage: &CoverageManifest,
    ) -> Result<ScanRunDetail, CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;

        let (project_id, status): (String, String) = transaction
            .query_row(
                "SELECT project_id, status FROM scan_runs WHERE id = ?1",
                [&detail.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::not_found)?;
        if status == "completed" {
            let stored = load_run_from_connection(&transaction, &detail.run_id)?
                .ok_or_else(CommandError::not_found)?;
            transaction.commit().map_err(persistence_error)?;
            return Ok(stored);
        }
        if status != "running"
            || detail.status != RunStatus::Completed
            || detail.project_id != project_id
        {
            return Err(CommandError::persistence_unavailable());
        }

        let manifest = Manifest::new(
            detail
                .findings
                .iter()
                .map(|finding| finding.fingerprint.clone()),
        )
        .map_err(persistence_error)?;

        for finding in &detail.findings {
            let scope = finding
                .scope
                .map(scope_name)
                .ok_or_else(CommandError::persistence_unavailable)?;
            let scope_reason = finding
                .scope_reason
                .as_deref()
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(CommandError::persistence_unavailable)?;
            let payload = to_json(&StoredFindingPayload::from(finding))?;
            transaction
                .execute(
                    r#"INSERT INTO findings(
                         id, run_id, fingerprint_version, fingerprint, category, rule_id,
                         payload_json, scope, scope_reason
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                       ON CONFLICT(id) DO UPDATE SET
                         fingerprint_version = excluded.fingerprint_version,
                         fingerprint = excluded.fingerprint,
                         category = excluded.category,
                         rule_id = excluded.rule_id,
                         payload_json = excluded.payload_json,
                         scope = excluded.scope,
                         scope_reason = excluded.scope_reason
                       WHERE findings.run_id = excluded.run_id"#,
                    params![
                        finding.id,
                        detail.run_id,
                        finding.fingerprint_version,
                        finding.fingerprint,
                        finding.category,
                        finding.rule_id,
                        payload,
                        scope,
                        scope_reason,
                    ],
                )
                .map_err(persistence_error)?;
        }

        let inserted_fingerprints = {
            let mut statement = transaction
                .prepare("SELECT fingerprint FROM findings WHERE run_id = ?1 ORDER BY rowid")
                .map_err(persistence_error)?;
            let rows = statement
                .query_map([&detail.run_id], |row| row.get::<_, String>(0))
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            rows
        };
        manifest
            .reconcile_ids(inserted_fingerprints)
            .map_err(persistence_error)?;

        let coverage_json = to_json(coverage)?;
        let summary_json = to_json(&StoredScanSummary::from(&detail.summary))?;
        transaction
            .execute(
                "UPDATE scan_runs SET coverage_json = ?2, summary_json = ?3 WHERE id = ?1",
                params![detail.run_id, coverage_json, summary_json],
            )
            .map_err(persistence_error)?;
        let completed_at = detail
            .completed_at
            .as_deref()
            .ok_or_else(CommandError::persistence_unavailable)?;
        let changed = transaction
            .execute(
                r#"UPDATE scan_runs
                   SET status = 'completed', completed_at = ?2, error_code = NULL
                   WHERE id = ?1 AND status = 'running'"#,
                params![detail.run_id, completed_at],
            )
            .map_err(persistence_error)?;
        if changed != 1 {
            return Err(CommandError::persistence_unavailable());
        }
        transaction.commit().map_err(persistence_error)?;

        load_run_from_connection(&connection, &detail.run_id)?.ok_or_else(CommandError::not_found)
    }

    pub fn load_run(&self, run_id: &str) -> Result<ScanRunDetail, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        load_run_from_connection(&connection, run_id)?.ok_or_else(CommandError::not_found)
    }

    pub fn mark_incomplete(
        &self,
        run_id: &str,
        completed_at: &str,
        error_code: &str,
    ) -> Result<(), CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let changed = connection
            .execute(
                r#"UPDATE scan_runs
                   SET status = 'incomplete', completed_at = ?2, error_code = ?3
                   WHERE id = ?1 AND status = 'running'"#,
                params![run_id, completed_at, error_code],
            )
            .map_err(persistence_error)?;
        if changed == 0 {
            let exists = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM scan_runs WHERE id = ?1)",
                    [run_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(persistence_error)?;
            if !exists {
                return Err(CommandError::not_found());
            }
        }
        Ok(())
    }

    pub fn recover_interrupted_runs(
        &self,
        completed_at: DateTime<Utc>,
    ) -> Result<usize, CommandError> {
        self.connection
            .lock()
            .map_err(persistence_error)?
            .execute(
                r#"UPDATE scan_runs
                   SET status = 'incomplete', completed_at = ?1,
                       error_code = 'process_interrupted'
                   WHERE status = 'running'"#,
                [completed_at.to_rfc3339()],
            )
            .map_err(persistence_error)
    }

    pub fn latest_completed_run(
        &self,
        project_id: &str,
    ) -> Result<Option<ScanRunDetail>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        latest_completed_run_from_connection(&connection, project_id)
    }

    pub fn list_recent_projects(&self, limit: usize) -> Result<Vec<RecentProject>, CommandError> {
        struct StoredProject {
            id: String,
            canonical_path: String,
            display_name: String,
            last_opened_at: String,
        }

        let connection = self.connection.lock().map_err(persistence_error)?;
        let projects = {
            let mut statement = connection
                .prepare(
                    r#"SELECT id, canonical_path, display_name, last_opened_at
                       FROM projects ORDER BY last_opened_at DESC, id LIMIT ?1"#,
                )
                .map_err(persistence_error)?;
            let rows = statement
                .query_map([limit as i64], |row| {
                    Ok(StoredProject {
                        id: row.get(0)?,
                        canonical_path: row.get(1)?,
                        display_name: row.get(2)?,
                        last_opened_at: row.get(3)?,
                    })
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            rows
        };

        projects
            .into_iter()
            .map(|project| {
                let latest = latest_completed_run_from_connection(&connection, &project.id)?;
                let open = latest
                    .as_ref()
                    .map(|run| {
                        run.findings
                            .iter()
                            .filter(|finding| {
                                finding.review.as_ref().map_or(true, |review| {
                                    matches!(
                                        review.state,
                                        ReviewState::Candidate | ReviewState::Confirmed
                                    )
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Ok(RecentProject {
                    project_id: project.id,
                    canonical_path: project.canonical_path,
                    display_name: project.display_name,
                    last_opened_at: project.last_opened_at,
                    last_completed_run_id: latest.as_ref().map(|run| run.run_id.clone()),
                    last_completed_at: latest.as_ref().and_then(|run| run.completed_at.clone()),
                    open_findings: open.len(),
                    critical: open
                        .iter()
                        .filter(|finding| finding.severity == "critical")
                        .count(),
                    high: open
                        .iter()
                        .filter(|finding| finding.severity == "high")
                        .count(),
                })
            })
            .collect()
    }

    pub fn apply_retention(
        &self,
        completed_before: &str,
        max_completed_runs_per_project: u32,
    ) -> Result<usize, CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let expired = transaction
            .execute(
                r#"DELETE FROM scan_runs
                   WHERE status = 'completed' AND completed_at < ?1"#,
                [completed_before],
            )
            .map_err(persistence_error)?;
        let over_limit = transaction
            .execute(
                r#"DELETE FROM scan_runs
                   WHERE id IN (
                     SELECT id FROM (
                       SELECT id,
                              ROW_NUMBER() OVER (
                                PARTITION BY project_id
                                ORDER BY completed_at DESC, id DESC
                              ) AS ordinal
                       FROM scan_runs
                       WHERE status = 'completed'
                     ) ranked
                     WHERE ordinal > ?1
                   )"#,
                [i64::from(max_completed_runs_per_project)],
            )
            .map_err(persistence_error)?;
        transaction.commit().map_err(persistence_error)?;
        Ok(expired + over_limit)
    }
}

fn latest_completed_run_from_connection(
    connection: &Connection,
    project_id: &str,
) -> Result<Option<ScanRunDetail>, CommandError> {
    let run_id = connection
        .query_row(
            r#"SELECT id FROM scan_runs
               WHERE project_id = ?1 AND status = 'completed'
               ORDER BY completed_at DESC, id DESC LIMIT 1"#,
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(persistence_error)?;
    run_id
        .as_deref()
        .map(|run_id| load_run_from_connection(connection, run_id))
        .transpose()
        .map(Option::flatten)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFindingPayload {
    rule_name: String,
    severity: String,
    title: String,
    description: String,
    file_path: String,
    line: usize,
    column: usize,
    match_text: String,
    context: String,
    language: String,
    cwe: Option<String>,
    cwe_exploited: bool,
    cwe_exploited_count: usize,
    recommendation: String,
    entropy: Option<f32>,
    verified: Option<bool>,
}

impl From<&Finding> for StoredFindingPayload {
    fn from(finding: &Finding) -> Self {
        Self {
            rule_name: finding.rule_name.clone(),
            severity: finding.severity.clone(),
            title: finding.title.clone(),
            description: finding.description.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            column: finding.column,
            match_text: finding.match_text.clone(),
            context: finding.context.clone(),
            language: finding.language.clone(),
            cwe: finding.cwe.clone(),
            cwe_exploited: finding.cwe_exploited,
            cwe_exploited_count: finding.cwe_exploited_count,
            recommendation: finding.recommendation.clone(),
            entropy: finding.entropy,
            verified: finding.verified,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredScanSummary {
    path: String,
    files_scanned: usize,
    files_skipped: usize,
    bytes_scanned: u64,
    duration_ms: u64,
    secrets_found: usize,
    vulnerabilities_found: usize,
    total_findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    rules_fired: std::collections::BTreeMap<String, usize>,
}

impl From<&ScanSummary> for StoredScanSummary {
    fn from(summary: &ScanSummary) -> Self {
        Self {
            path: summary.path.clone(),
            files_scanned: summary.files_scanned,
            files_skipped: summary.files_skipped,
            bytes_scanned: summary.bytes_scanned,
            duration_ms: summary.duration_ms,
            secrets_found: summary.secrets_found,
            vulnerabilities_found: summary.vulnerabilities_found,
            total_findings: summary.total_findings,
            critical: summary.critical,
            high: summary.high,
            medium: summary.medium,
            low: summary.low,
            info: summary.info,
            rules_fired: summary.rules_fired.clone(),
        }
    }
}

impl From<StoredScanSummary> for ScanSummary {
    fn from(summary: StoredScanSummary) -> Self {
        Self {
            path: summary.path,
            files_scanned: summary.files_scanned,
            files_skipped: summary.files_skipped,
            bytes_scanned: summary.bytes_scanned,
            duration_ms: summary.duration_ms,
            secrets_found: summary.secrets_found,
            vulnerabilities_found: summary.vulnerabilities_found,
            total_findings: summary.total_findings,
            critical: summary.critical,
            high: summary.high,
            medium: summary.medium,
            low: summary.low,
            info: summary.info,
            rules_fired: summary.rules_fired,
        }
    }
}

fn load_run_from_connection(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<ScanRunDetail>, CommandError> {
    struct StoredRun {
        project_id: String,
        run_id: String,
        baseline_run_id: Option<String>,
        status: String,
        policy_json: String,
        started_at: String,
        completed_at: Option<String>,
        summary_json: Option<String>,
    }

    let stored = connection
        .query_row(
            r#"SELECT project_id, id, baseline_run_id, status, policy_status_json, started_at,
                      completed_at, summary_json
               FROM scan_runs WHERE id = ?1"#,
            [run_id],
            |row| {
                Ok(StoredRun {
                    project_id: row.get(0)?,
                    run_id: row.get(1)?,
                    baseline_run_id: row.get(2)?,
                    status: row.get(3)?,
                    policy_json: row.get(4)?,
                    started_at: row.get(5)?,
                    completed_at: row.get(6)?,
                    summary_json: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(persistence_error)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let findings = load_findings(connection, &stored.run_id, &stored.project_id)?;
    let summary = match stored.summary_json {
        Some(json) => from_json::<StoredScanSummary>(&json)?.into(),
        None => empty_summary(),
    };
    Ok(Some(ScanRunDetail {
        project_id: stored.project_id,
        run_id: stored.run_id,
        baseline_run_id: stored.baseline_run_id,
        status: parse_run_status(&stored.status)?,
        persistence: RunPersistence::Saved,
        policy: from_json(&stored.policy_json)?,
        started_at: stored.started_at,
        completed_at: stored.completed_at,
        summary,
        findings,
        maintenance_warning: None,
    }))
}

fn load_findings(
    connection: &Connection,
    run_id: &str,
    project_id: &str,
) -> Result<Vec<Finding>, CommandError> {
    struct StoredObservation {
        id: String,
        fingerprint_version: u16,
        fingerprint: String,
        category: String,
        rule_id: String,
        payload: String,
        scope: String,
        scope_reason: String,
    }

    let observations = {
        let mut statement = connection
            .prepare(
                r#"SELECT id, fingerprint_version, fingerprint, category, rule_id, payload_json,
                          scope, scope_reason
                   FROM findings WHERE run_id = ?1 ORDER BY rowid"#,
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok(StoredObservation {
                    id: row.get(0)?,
                    fingerprint_version: row.get(1)?,
                    fingerprint: row.get(2)?,
                    category: row.get(3)?,
                    rule_id: row.get(4)?,
                    payload: row.get(5)?,
                    scope: row.get(6)?,
                    scope_reason: row.get(7)?,
                })
            })
            .map_err(persistence_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(persistence_error)?;
        rows
    };

    observations
        .into_iter()
        .map(|observation| {
            let payload: StoredFindingPayload = from_json(&observation.payload)?;
            let review_history = load_reviews(
                connection,
                project_id,
                observation.fingerprint_version,
                &observation.fingerprint,
            )?;
            let review = review_history
                .iter()
                .find(|review| review_is_active(review))
                .cloned();
            Ok(Finding {
                id: observation.id,
                category: observation.category,
                rule_id: observation.rule_id,
                rule_name: payload.rule_name,
                severity: payload.severity,
                title: payload.title,
                description: payload.description,
                file_path: payload.file_path,
                line: payload.line,
                column: payload.column,
                match_text: payload.match_text,
                context: payload.context,
                language: payload.language,
                cwe: payload.cwe,
                cwe_exploited: payload.cwe_exploited,
                cwe_exploited_count: payload.cwe_exploited_count,
                recommendation: payload.recommendation,
                entropy: payload.entropy,
                verified: payload.verified,
                observation_run_id: run_id.to_owned(),
                resolved_by_run_id: None,
                fingerprint_version: observation.fingerprint_version,
                fingerprint: observation.fingerprint,
                scope: Some(parse_scope(&observation.scope)?),
                scope_reason: Some(observation.scope_reason),
                review,
                review_history,
                diff_status: None,
            })
        })
        .collect()
}

fn review_is_active(review: &ReviewRecord) -> bool {
    if review.superseded_at.is_some() {
        return false;
    }
    match review.expires_at.as_deref() {
        None => true,
        Some(expires_at) => {
            DateTime::parse_from_rfc3339(expires_at).is_ok_and(|expires_at| expires_at > Utc::now())
        }
    }
}

fn load_reviews(
    connection: &Connection,
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
) -> Result<Vec<ReviewRecord>, CommandError> {
    let mut statement = connection
        .prepare(
            r#"SELECT id, state, reason, evidence, entry_point, data_flow, gates_json, deciding_gate,
                      expires_at, origin, policy_hash, updated_at, superseded_at
               FROM reviews
               WHERE project_id = ?1 AND fingerprint_version = ?2 AND fingerprint = ?3
               ORDER BY updated_at DESC, id DESC"#,
        )
        .map_err(persistence_error)?;
    let rows = statement
        .query_map(
            params![project_id, fingerprint_version, fingerprint],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        )
        .map_err(persistence_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(persistence_error)?;
    rows.into_iter()
        .map(|row| {
            let (
                id,
                state,
                reason,
                evidence,
                entry_point,
                data_flow,
                gates_json,
                deciding_gate,
                expires_at,
                origin,
                policy_hash,
                updated_at,
                superseded_at,
            ) = row;
            Ok(ReviewRecord {
                id,
                project_id: project_id.to_owned(),
                fingerprint_version,
                fingerprint: fingerprint.to_owned(),
                state: parse_json_enum::<ReviewState>(&state)?,
                reason,
                evidence,
                entry_point,
                data_flow,
                gates: from_json::<Vec<GateNote>>(&gates_json)?,
                deciding_gate: deciding_gate
                    .as_deref()
                    .map(parse_json_enum::<Gate>)
                    .transpose()?,
                expires_at,
                origin: parse_json_enum::<ReviewOrigin>(&origin)?,
                policy_hash,
                updated_at,
                superseded_at,
            })
        })
        .collect()
}

fn to_json(value: &impl Serialize) -> Result<String, CommandError> {
    serde_json::to_string(value).map_err(persistence_error)
}

fn from_json<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, CommandError> {
    serde_json::from_str(value).map_err(persistence_error)
}

fn parse_json_enum<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, CommandError> {
    from_json(&format!("\"{value}\""))
}

fn scope_name(scope: FindingScope) -> &'static str {
    match scope {
        FindingScope::Production => "production",
        FindingScope::Infrastructure => "infrastructure",
        FindingScope::Test => "test",
        FindingScope::Fixture => "fixture",
        FindingScope::Generated => "generated",
        FindingScope::Vendored => "vendored",
        FindingScope::Documentation => "documentation",
        FindingScope::Unknown => "unknown",
    }
}

fn parse_scope(value: &str) -> Result<FindingScope, CommandError> {
    parse_json_enum(value)
}

fn parse_run_status(value: &str) -> Result<RunStatus, CommandError> {
    parse_json_enum(value)
}

fn empty_summary() -> ScanSummary {
    ScanSummary {
        path: String::new(),
        files_scanned: 0,
        files_skipped: 0,
        bytes_scanned: 0,
        duration_ms: 0,
        secrets_found: 0,
        vulnerabilities_found: 0,
        total_findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        rules_fired: std::collections::BTreeMap::new(),
    }
}

#[cfg(unix)]
fn protect(path: &Path, mode: u32) -> Result<(), CommandError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(persistence_error)?
        .permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(persistence_error)
}

fn persistence_error<T>(_: T) -> CommandError {
    CommandError::persistence_unavailable()
}

fn initialize_connection(connection: &Connection, file_database: bool) -> Result<(), CommandError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(persistence_error)?;
    if file_database {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(persistence_error)?;
    }
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .map_err(persistence_error)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(persistence_error)
}

fn migrate(connection: &mut Connection, migration_v1: &str) -> Result<(), CommandError> {
    let migration_ledger_exists = connection
        .query_row(
            r#"SELECT EXISTS(SELECT 1 FROM sqlite_master
               WHERE type = 'table' AND name = 'schema_migrations')"#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    let applied = migration_ledger_exists
        && connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 1)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(persistence_error)?;
    if applied {
        return Ok(());
    }

    let transaction = connection.transaction().map_err(persistence_error)?;
    transaction
        .execute_batch(
            r#"CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
               );"#,
        )
        .map_err(persistence_error)?;
    transaction
        .execute_batch(migration_v1)
        .map_err(persistence_error)?;
    transaction
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
            [Utc::now().to_rfc3339()],
        )
        .map_err(persistence_error)?;
    transaction.commit().map_err(persistence_error)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use crate::findings::coverage::CoverageManifest;
    use crate::findings::domain::{
        DiffStatus, FindingScope, PolicyStatus, ReviewOrigin, ReviewRecord, ReviewState,
        RunPersistence, RunStatus, ScanRunDetail, FINGERPRINT_VERSION,
    };
    use crate::models::{Finding, ScanOptions, ScanSummary};

    use super::*;

    fn summary(total_findings: usize) -> ScanSummary {
        ScanSummary {
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
            observation_run_id: "dynamic-run-id-must-not-be-persisted-in-payload".into(),
            resolved_by_run_id: Some("dynamic-resolution-must-not-be-persisted".into()),
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint: fingerprint.into(),
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
        let options = ScanOptions::default();
        repository
            .upsert_project(
                "project-1",
                "/project",
                "Project",
                "2026-08-20T09:59:00Z",
                &options,
            )
            .expect("upsert project");
        repository
            .start_run(
                &run_detail(run_id, RunStatus::Running, Vec::new()),
                "scanner-1.0",
                &options,
            )
            .expect("start run");
    }

    #[test]
    fn creates_version_one_schema() {
        let repository = FindingsRepository::open_in_memory().expect("open repository");
        let connection = repository.connection.lock().expect("lock connection");
        let tables = [
            "schema_migrations",
            "projects",
            "scan_runs",
            "findings",
            "reviews",
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
            .query_row("SELECT version FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("query migration version");
        assert_eq!(version, 1);
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
        let loaded = repository.load_run("run-1").expect("load completed run");
        assert_eq!(loaded.findings.len(), 1);
        let loaded_finding = &loaded.findings[0];
        assert_eq!(loaded_finding.observation_run_id, "run-1");
        assert_eq!(loaded_finding.resolved_by_run_id, None);
        assert_eq!(loaded_finding.diff_status, None);
        assert_eq!(
            loaded_finding.review.as_ref().map(|item| &item.id),
            Some(&"review-1".into())
        );
        assert_eq!(loaded_finding.review_history, vec![stored_review]);

        let connection = repository.connection.lock().expect("lock connection");
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
            prepare_run(&repository, run_id);
            let mut completed = run_detail(
                run_id,
                RunStatus::Completed,
                vec![finding(observation_id, fingerprint)],
            );
            completed.completed_at = Some(completed_at.into());
            repository
                .complete_run(
                    &completed,
                    &CoverageManifest::from_entries([("src/config.rs", ["secret"])]),
                )
                .expect("complete retained run");
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
            .apply_retention("2026-08-01T00:00:00Z", 1)
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
    fn file_database_uses_wal_and_owner_only_modes() {
        use std::os::unix::fs::PermissionsExt;

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

        fn mode(path: &Path) -> u32 {
            std::fs::metadata(path)
                .expect("read metadata")
                .permissions()
                .mode()
                & 0o777
        }
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Mutex,
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    coverage::CoverageManifest,
    domain::{
        DiffStatus, FindingScope, PolicyStatus, ProjectContext, RecentProject, RetentionPolicy,
        ReviewOrigin, ReviewRecord, ReviewState, RunPersistence, RunStatus, ScanRunDetail,
        ScanRunSummary,
    },
    error::CommandError,
    policy::PolicyAuthority,
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

const MIGRATION_V2: &str = r#"
CREATE TABLE canonical_runs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  target_label TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE canonical_artifacts (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  UNIQUE(run_id, id)
);

CREATE TABLE canonical_components (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  UNIQUE(run_id, id)
);

CREATE TABLE canonical_observations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  UNIQUE(run_id, id)
);

CREATE TABLE canonical_projections (
  run_id TEXT PRIMARY KEY REFERENCES canonical_runs(id) ON DELETE CASCADE,
  projection_kind TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE INDEX canonical_runs_state_idx ON canonical_runs(state, updated_at_ms DESC);
CREATE INDEX canonical_artifacts_run_idx ON canonical_artifacts(run_id);
CREATE INDEX canonical_components_run_idx ON canonical_components(run_id);
CREATE INDEX canonical_observations_run_idx ON canonical_observations(run_id);

CREATE TABLE provider_snapshots (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  fetched_at_ms INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE verification_records (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  verified_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
"#;

const MIGRATION_V3: &str = r#"
CREATE TABLE canonical_findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  UNIQUE(run_id, id)
);
CREATE INDEX canonical_findings_run_idx ON canonical_findings(run_id);
CREATE INDEX verification_records_finding_idx
  ON verification_records(finding_id, verified_at_ms DESC);
"#;

const MIGRATION_V4: &str = r#"
CREATE TABLE benchmark_results (
  id TEXT PRIMARY KEY,
  suite_id TEXT NOT NULL,
  suite_version TEXT NOT NULL,
  recorded_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX benchmark_results_suite_idx
  ON benchmark_results(suite_id, recorded_at_ms DESC);
"#;

const MIGRATION_V5: &str = r#"
CREATE TABLE compliance_assessments (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX compliance_assessments_created_idx
  ON compliance_assessments(created_at_ms DESC, id DESC);
CREATE INDEX compliance_assessments_profile_idx
  ON compliance_assessments(profile_id, created_at_ms DESC);

CREATE TABLE compliance_control_reviews (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
  control_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('supported','partial','gap','manualReview','notApplicable')),
  note TEXT NOT NULL,
  author TEXT NOT NULL,
  reviewed_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX compliance_reviews_assessment_idx
  ON compliance_control_reviews(assessment_id, reviewed_at_ms DESC, id DESC);

CREATE TABLE compliance_reports (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  output_path TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  metadata_json TEXT NOT NULL
);
CREATE INDEX compliance_reports_assessment_idx
  ON compliance_reports(assessment_id, created_at_ms DESC, id DESC);
"#;

const RETENTION_MAINTENANCE_WARNING: &str =
    "Run saved, but old scan history could not be cleaned up.";

pub struct FindingsRepository {
    connection: Mutex<Connection>,
    #[cfg(test)]
    fail_post_maintenance_reload: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Clone)]
pub(crate) struct ProviderSnapshotRecord {
    pub id: String,
    pub provider_id: String,
    pub fetched_at_ms: u64,
    pub content_sha256: String,
    pub payload: serde_json::Value,
}

impl FindingsRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CommandError> {
        Self::open_with_parent_hook(path, || {})
    }

    #[cfg(test)]
    fn open_with_test_parent_hook(
        path: impl AsRef<Path>,
        hook: impl FnOnce(),
    ) -> Result<Self, CommandError> {
        Self::open_with_parent_hook(path, hook)
    }

    fn open_with_parent_hook(
        path: impl AsRef<Path>,
        hook: impl FnOnce(),
    ) -> Result<Self, CommandError> {
        let path = path.as_ref();

        #[cfg(unix)]
        {
            open_file_database_unix(path, hook)
        }

        #[cfg(not(unix))]
        {
            open_file_database_portable(path, hook)
        }
    }

    pub fn open_in_memory() -> Result<Self, CommandError> {
        let mut connection = Connection::open_in_memory().map_err(persistence_error)?;
        initialize_connection(&connection, false)?;
        migrate(&mut connection, MIGRATION_V1)?;
        Ok(Self {
            connection: Mutex::new(connection),
            #[cfg(test)]
            fail_post_maintenance_reload: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn canonical_create_run(
        &self,
        run: &oxaudit_domain::Run,
    ) -> Result<(), CommandError> {
        let payload = to_json(run)?;
        let kind = enum_name(&run.kind)?;
        let state = enum_name(&run.state)?;
        let updated_at_ms = i64::try_from(run.updated_at_ms).map_err(persistence_error)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let existing = connection
            .query_row(
                "SELECT payload_json FROM canonical_runs WHERE id = ?1",
                [run.id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        if let Some(existing) = existing {
            return if existing == payload {
                Ok(())
            } else {
                Err(CommandError::persistence_unavailable())
            };
        }
        connection
            .execute(
                r#"INSERT INTO canonical_runs(
                     id, kind, state, target_label, payload_json, updated_at_ms
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
                params![
                    run.id.as_str(),
                    kind,
                    state,
                    run.target_label,
                    payload,
                    updated_at_ms
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn canonical_save_run(&self, run: &oxaudit_domain::Run) -> Result<(), CommandError> {
        let payload = to_json(run)?;
        let state = enum_name(&run.state)?;
        let updated_at_ms = i64::try_from(run.updated_at_ms).map_err(persistence_error)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let changed = connection
            .execute(
                r#"UPDATE canonical_runs
                   SET state = ?2, target_label = ?3, payload_json = ?4, updated_at_ms = ?5
                   WHERE id = ?1"#,
                params![
                    run.id.as_str(),
                    state,
                    run.target_label,
                    payload,
                    updated_at_ms
                ],
            )
            .map_err(persistence_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(CommandError::persistence_unavailable())
        }
    }

    pub(crate) fn canonical_append_artifact(
        &self,
        run_id: &oxaudit_domain::RunId,
        artifact: &oxaudit_domain::Artifact,
    ) -> Result<(), CommandError> {
        let payload = to_json(artifact)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let existing = connection
            .query_row(
                "SELECT run_id, payload_json FROM canonical_artifacts WHERE id = ?1",
                [artifact.id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(persistence_error)?;
        if let Some((stored_run_id, stored_payload)) = existing {
            return if stored_run_id == run_id.as_str() && stored_payload == payload {
                Ok(())
            } else {
                Err(CommandError::persistence_unavailable())
            };
        }
        connection
            .execute(
                "INSERT INTO canonical_artifacts(id, run_id, payload_json) VALUES (?1, ?2, ?3)",
                params![artifact.id.as_str(), run_id.as_str(), payload],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn canonical_append_observations(
        &self,
        run_id: &oxaudit_domain::RunId,
        observations: &[oxaudit_application::ObservationRecord],
    ) -> Result<(), CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        for record in observations {
            let payload = to_json(&record.observation)?;
            let evidence = to_json(&record.evidence)?;
            let existing = transaction
                .query_row(
                    "SELECT run_id, payload_json, evidence_json FROM canonical_observations WHERE id = ?1",
                    [record.observation.id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(persistence_error)?;
            if let Some((stored_run_id, stored_payload, stored_evidence)) = existing {
                if stored_run_id != run_id.as_str()
                    || stored_payload != payload
                    || stored_evidence != evidence
                {
                    return Err(CommandError::persistence_unavailable());
                }
                continue;
            }
            transaction
                .execute(
                    r#"INSERT INTO canonical_observations(
                         id, run_id, payload_json, evidence_json
                       ) VALUES (?1, ?2, ?3, ?4)"#,
                    params![
                        record.observation.id.as_str(),
                        run_id.as_str(),
                        payload,
                        evidence
                    ],
                )
                .map_err(persistence_error)?;
            if matches!(
                record.observation.kind,
                oxaudit_domain::ObservationKind::SourceWeakness
                    | oxaudit_domain::ObservationKind::SecretCandidate
                    | oxaudit_domain::ObservationKind::AdvisoryMatch
                    | oxaudit_domain::ObservationKind::PolicyConcern
                    | oxaudit_domain::ObservationKind::SemanticDataFlow
            ) {
                let finding_id =
                    record
                        .observation
                        .id
                        .as_str()
                        .replacen("observation_", "finding_", 1);
                let finding = oxaudit_domain::Finding {
                    id: oxaudit_domain::FindingId::parse(finding_id).map_err(persistence_error)?,
                    run_id: run_id.clone(),
                    fingerprint: record.observation.id.as_str().to_owned(),
                    fingerprint_version: 1,
                    title: record.observation.title.clone(),
                    severity: oxaudit_domain::Severity::Info,
                    state: oxaudit_domain::FindingState::Candidate,
                    classifications: Vec::new(),
                    observation_ids: vec![record.observation.id.clone()],
                    evidence_ids: record.observation.evidence_ids.clone(),
                };
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO canonical_findings(id, run_id, payload_json) VALUES (?1, ?2, ?3)",
                        params![finding.id.as_str(), run_id.as_str(), to_json(&finding)?],
                    )
                    .map_err(persistence_error)?;
            }
        }
        transaction.commit().map_err(persistence_error)
    }

    pub(crate) fn canonical_append_components(
        &self,
        run_id: &oxaudit_domain::RunId,
        components: &[oxaudit_domain::Component],
    ) -> Result<(), CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        for component in components {
            let payload = to_json(component)?;
            let existing = transaction
                .query_row(
                    "SELECT run_id, payload_json FROM canonical_components WHERE id = ?1",
                    [component.id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(persistence_error)?;
            if let Some((stored_run_id, stored_payload)) = existing {
                if stored_run_id != run_id.as_str() || stored_payload != payload {
                    return Err(CommandError::persistence_unavailable());
                }
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO canonical_components(id, run_id, payload_json) VALUES (?1, ?2, ?3)",
                    params![component.id.as_str(), run_id.as_str(), payload],
                )
                .map_err(persistence_error)?;
        }
        transaction.commit().map_err(persistence_error)
    }

    pub(crate) fn canonical_load_run(
        &self,
        run_id: &oxaudit_domain::RunId,
    ) -> Result<Option<oxaudit_domain::Run>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM canonical_runs WHERE id = ?1",
                [run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .transpose()
    }

    pub(crate) fn canonical_load_report_graph(
        &self,
        run_id: &oxaudit_domain::RunId,
    ) -> Result<crate::adapters::scanners::ScanGraph, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let load_payloads = |table: &str| -> Result<Vec<String>, CommandError> {
            let sql = format!("SELECT payload_json FROM {table} WHERE run_id = ?1 ORDER BY id");
            let mut statement = connection.prepare(&sql).map_err(persistence_error)?;
            let rows = statement
                .query_map([run_id.as_str()], |row| row.get::<_, String>(0))
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)
        };
        let artifacts = load_payloads("canonical_artifacts")?
            .into_iter()
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .collect::<Result<Vec<_>, _>>()?;
        let components = load_payloads("canonical_components")?
            .into_iter()
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .collect::<Result<Vec<_>, _>>()?;
        let mut statement = connection
            .prepare(
                "SELECT payload_json, evidence_json FROM canonical_observations WHERE run_id = ?1 ORDER BY id",
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([run_id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(persistence_error)?;
        let observations = rows
            .map(|row| {
                let (observation, evidence) = row.map_err(persistence_error)?;
                Ok(oxaudit_application::ObservationRecord {
                    observation: serde_json::from_str(&observation).map_err(persistence_error)?,
                    evidence: serde_json::from_str(&evidence).map_err(persistence_error)?,
                })
            })
            .collect::<Result<Vec<_>, CommandError>>()?;
        Ok((artifacts, components, observations))
    }

    pub(crate) fn canonical_list_findings(
        &self,
        run_id: Option<&oxaudit_domain::RunId>,
    ) -> Result<Vec<oxaudit_domain::Finding>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut payloads = Vec::new();
        match run_id {
            Some(run_id) => {
                let mut statement = connection
                    .prepare(
                        "SELECT payload_json FROM canonical_findings WHERE run_id = ?1 ORDER BY id",
                    )
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map([run_id.as_str()], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
            None => {
                let mut statement = connection
                    .prepare(
                        "SELECT payload_json FROM canonical_findings ORDER BY rowid DESC LIMIT 500",
                    )
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
        }
        payloads
            .into_iter()
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .collect()
    }

    pub(crate) fn canonical_load_finding(
        &self,
        finding_id: &oxaudit_domain::FindingId,
    ) -> Result<Option<oxaudit_domain::Finding>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM canonical_findings WHERE id = ?1",
                [finding_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .transpose()
    }

    pub(crate) fn verification_save(
        &self,
        verification: &oxaudit_domain::Verification,
    ) -> Result<(), CommandError> {
        verification
            .validate_independence()
            .map_err(persistence_error)?;
        let verified_at_ms =
            i64::try_from(verification.verified_at_ms).map_err(persistence_error)?;
        let payload = to_json(verification)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                r#"INSERT INTO verification_records(id, finding_id, verified_at_ms, payload_json)
                   VALUES (?1, ?2, ?3, ?4)"#,
                params![
                    verification.id.as_str(),
                    verification.finding_id.as_str(),
                    verified_at_ms,
                    payload
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn verification_list(
        &self,
        finding_id: Option<&oxaudit_domain::FindingId>,
    ) -> Result<Vec<oxaudit_domain::Verification>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut payloads = Vec::new();
        match finding_id {
            Some(finding_id) => {
                let mut statement = connection
                    .prepare("SELECT payload_json FROM verification_records WHERE finding_id = ?1 ORDER BY verified_at_ms DESC")
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map([finding_id.as_str()], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
            None => {
                let mut statement = connection
                    .prepare("SELECT payload_json FROM verification_records ORDER BY verified_at_ms DESC LIMIT 500")
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
        }
        payloads
            .into_iter()
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .collect()
    }

    pub(crate) fn benchmark_latest(
        &self,
        suite_id: &str,
    ) -> Result<Option<serde_json::Value>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM benchmark_results WHERE suite_id = ?1 ORDER BY recorded_at_ms DESC, id DESC LIMIT 1",
                [suite_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .transpose()
    }

    pub(crate) fn benchmark_save(
        &self,
        id: &str,
        suite_id: &str,
        suite_version: &str,
        recorded_at_ms: u64,
        payload: &impl Serialize,
    ) -> Result<(), CommandError> {
        let recorded_at_ms = i64::try_from(recorded_at_ms).map_err(persistence_error)?;
        let payload = to_json(payload)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                "INSERT INTO benchmark_results(id, suite_id, suite_version, recorded_at_ms, payload_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, suite_id, suite_version, recorded_at_ms, payload],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn compliance_save_assessment(
        &self,
        assessment: &oxaudit_compliance::ComplianceAssessment,
    ) -> Result<(), CommandError> {
        let created_at_ms = i64::try_from(assessment.created_at_ms).map_err(persistence_error)?;
        let payload = to_json(assessment)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                "INSERT INTO compliance_assessments(id, profile_id, created_at_ms, payload_json) VALUES (?1, ?2, ?3, ?4)",
                params![assessment.id, assessment.profile_id, created_at_ms, payload],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn compliance_list_assessments(
        &self,
        limit: usize,
    ) -> Result<Vec<oxaudit_compliance::ComplianceAssessment>, CommandError> {
        let limit = i64::try_from(limit.clamp(1, 100)).map_err(persistence_error)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut statement = connection
            .prepare("SELECT payload_json FROM compliance_assessments ORDER BY created_at_ms DESC, id DESC LIMIT ?1")
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([limit], |row| row.get::<_, String>(0))
            .map_err(persistence_error)?;
        rows.map(|row| {
            let payload = row.map_err(persistence_error)?;
            serde_json::from_str(&payload).map_err(persistence_error)
        })
        .collect()
    }

    pub(crate) fn compliance_load_assessment(
        &self,
        assessment_id: &str,
    ) -> Result<oxaudit_compliance::ComplianceAssessment, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM compliance_assessments WHERE id = ?1",
                [assessment_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::not_found)?;
        serde_json::from_str(&payload).map_err(persistence_error)
    }

    pub(crate) fn compliance_save_review(
        &self,
        review: &crate::compliance::ComplianceReview,
    ) -> Result<(), CommandError> {
        let reviewed_at_ms = i64::try_from(review.reviewed_at_ms).map_err(persistence_error)?;
        let status = enum_name(&review.status)?;
        let payload = to_json(review)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                r#"INSERT INTO compliance_control_reviews(
                     id, assessment_id, control_id, status, note, author, reviewed_at_ms, payload_json
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![review.id, review.assessment_id, review.control_id, status, review.note, review.author, reviewed_at_ms, payload],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn compliance_list_reviews(
        &self,
        assessment_id: &str,
    ) -> Result<Vec<crate::compliance::ComplianceReview>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut statement = connection
            .prepare("SELECT payload_json FROM compliance_control_reviews WHERE assessment_id = ?1 ORDER BY reviewed_at_ms DESC, id DESC")
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([assessment_id], |row| row.get::<_, String>(0))
            .map_err(persistence_error)?;
        rows.map(|row| {
            let payload = row.map_err(persistence_error)?;
            serde_json::from_str(&payload).map_err(persistence_error)
        })
        .collect()
    }

    pub(crate) fn compliance_save_report(
        &self,
        receipt: &crate::compliance::ComplianceReportReceipt,
    ) -> Result<(), CommandError> {
        let created_at_ms = i64::try_from(receipt.created_at_ms).map_err(persistence_error)?;
        let format = enum_name(&receipt.format)?;
        let metadata = to_json(&receipt.metadata)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                r#"INSERT INTO compliance_reports(
                     id, assessment_id, format, output_path, content_sha256, created_at_ms, metadata_json
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                params![receipt.id, receipt.assessment_id, format, receipt.output_path, receipt.content_sha256, created_at_ms, metadata],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn canonical_recover_interrupted_runs(
        &self,
        recovered_at_ms: u64,
    ) -> Result<usize, CommandError> {
        let payloads = {
            let connection = self.connection.lock().map_err(persistence_error)?;
            let mut statement = connection
                .prepare(
                    r#"SELECT payload_json FROM canonical_runs
                       WHERE state NOT IN ('completed', 'cancelled', 'incomplete', 'failed')"#,
                )
                .map_err(persistence_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?
        };
        for payload in &payloads {
            let mut run: oxaudit_domain::Run =
                serde_json::from_str(payload).map_err(persistence_error)?;
            let terminal = if run.state == oxaudit_domain::RunState::Cancelling {
                oxaudit_domain::RunState::Cancelled
            } else {
                oxaudit_domain::RunState::Incomplete
            };
            run.transition(terminal, recovered_at_ms)
                .map_err(persistence_error)?;
            run.warnings.push(oxaudit_domain::RunWarning {
                code: "interrupted_by_restart".into(),
                message: "The application restarted before this run reached a terminal state."
                    .into(),
            });
            self.canonical_save_run(&run)?;
        }
        Ok(payloads.len())
    }

    pub(crate) fn canonical_save_projection(
        &self,
        run_id: &oxaudit_domain::RunId,
        projection_kind: &str,
        schema_version: u32,
        payload: &impl Serialize,
    ) -> Result<(), CommandError> {
        if projection_kind.trim().is_empty() || schema_version == 0 {
            return Err(CommandError::persistence_unavailable());
        }
        let schema_version_i64 = i64::from(schema_version);
        let payload = to_json(payload)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let existing = connection
            .query_row(
                r#"SELECT projection_kind, schema_version, payload_json
                   FROM canonical_projections WHERE run_id = ?1"#,
                [run_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(persistence_error)?;
        if let Some(existing) = existing {
            return if existing == (projection_kind.to_owned(), schema_version_i64, payload) {
                Ok(())
            } else {
                Err(CommandError::persistence_unavailable())
            };
        }
        connection
            .execute(
                r#"INSERT INTO canonical_projections(
                     run_id, projection_kind, schema_version, payload_json
                   ) VALUES (?1, ?2, ?3, ?4)"#,
                params![
                    run_id.as_str(),
                    projection_kind,
                    schema_version_i64,
                    payload
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn canonical_load_projection(
        &self,
        run_id: &oxaudit_domain::RunId,
    ) -> Result<Option<serde_json::Value>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM canonical_projections WHERE run_id = ?1",
                [run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .transpose()
    }

    pub(crate) fn canonical_list_runs(
        &self,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<oxaudit_domain::Run>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let limit = i64::try_from(limit.clamp(1, 100)).map_err(persistence_error)?;
        let mut payloads = Vec::new();
        match kind {
            Some(kind) => {
                let mut statement = connection
                    .prepare(
                        r#"SELECT payload_json FROM canonical_runs
                           WHERE kind = ?1 ORDER BY updated_at_ms DESC, id DESC LIMIT ?2"#,
                    )
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map(params![kind, limit], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
            None => {
                let mut statement = connection
                    .prepare(
                        r#"SELECT payload_json FROM canonical_runs
                           ORDER BY updated_at_ms DESC, id DESC LIMIT ?1"#,
                    )
                    .map_err(persistence_error)?;
                let rows = statement
                    .query_map([limit], |row| row.get::<_, String>(0))
                    .map_err(persistence_error)?;
                for row in rows {
                    payloads.push(row.map_err(persistence_error)?);
                }
            }
        }
        payloads
            .into_iter()
            .map(|payload| serde_json::from_str(&payload).map_err(persistence_error))
            .collect()
    }

    pub(crate) fn provider_save_snapshot(
        &self,
        snapshot: &ProviderSnapshotRecord,
    ) -> Result<(), CommandError> {
        let fetched_at_ms = i64::try_from(snapshot.fetched_at_ms).map_err(persistence_error)?;
        let payload = to_json(&snapshot.payload)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let existing = connection
            .query_row(
                "SELECT provider_id, fetched_at_ms, content_sha256, payload_json FROM provider_snapshots WHERE id = ?1",
                [snapshot.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(persistence_error)?;
        if let Some(existing) = existing {
            return if existing
                == (
                    snapshot.provider_id.clone(),
                    fetched_at_ms,
                    snapshot.content_sha256.clone(),
                    payload,
                ) {
                Ok(())
            } else {
                Err(CommandError::persistence_unavailable())
            };
        }
        connection
            .execute(
                r#"INSERT INTO provider_snapshots(
                     id, provider_id, fetched_at_ms, content_sha256, payload_json
                   ) VALUES (?1, ?2, ?3, ?4, ?5)
                   "#,
                params![
                    snapshot.id,
                    snapshot.provider_id,
                    fetched_at_ms,
                    snapshot.content_sha256,
                    payload
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn provider_latest_snapshot(
        &self,
        provider_id: &str,
    ) -> Result<Option<ProviderSnapshotRecord>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let row = connection
            .query_row(
                r#"SELECT id, provider_id, fetched_at_ms, content_sha256, payload_json
                   FROM provider_snapshots WHERE provider_id = ?1
                   ORDER BY fetched_at_ms DESC, id DESC LIMIT 1"#,
                [provider_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(persistence_error)?;
        row.map(
            |(id, provider_id, fetched_at_ms, content_sha256, payload)| {
                Ok(ProviderSnapshotRecord {
                    id,
                    provider_id,
                    fetched_at_ms: u64::try_from(fetched_at_ms).map_err(persistence_error)?,
                    content_sha256,
                    payload: serde_json::from_str(&payload).map_err(persistence_error)?,
                })
            },
        )
        .transpose()
    }

    pub fn upsert_project(
        &self,
        project_id: &str,
        canonical_path: &str,
        display_name: &str,
        opened_at: &str,
        last_options: Option<&ScanOptions>,
    ) -> Result<ProjectContext, CommandError> {
        let options_json = last_options.map(to_json).transpose()?;
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;

        let caller_path = transaction
            .query_row(
                "SELECT canonical_path FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        if caller_path
            .as_deref()
            .is_some_and(|stored_path| stored_path != canonical_path)
        {
            return Err(CommandError::persistence_unavailable());
        }

        let stored_id = transaction
            .query_row(
                "SELECT id FROM projects WHERE canonical_path = ?1",
                [canonical_path],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        let persisted_id = match stored_id {
            Some(stored_id) => {
                match options_json.as_deref() {
                    Some(options_json) => transaction.execute(
                        r#"UPDATE projects
                           SET display_name = ?2, last_opened_at = ?3, last_options_json = ?4
                           WHERE id = ?1"#,
                        params![stored_id, display_name, opened_at, options_json],
                    ),
                    None => transaction.execute(
                        r#"UPDATE projects
                           SET display_name = ?2, last_opened_at = ?3
                           WHERE id = ?1"#,
                        params![stored_id, display_name, opened_at],
                    ),
                }
                .map_err(persistence_error)?;
                stored_id
            }
            None => {
                transaction
                    .execute(
                        r#"INSERT INTO projects(
                             id, canonical_path, display_name, created_at, last_opened_at,
                             last_options_json
                           ) VALUES (?1, ?2, ?3, ?4, ?4, COALESCE(?5, '{}'))"#,
                        params![
                            project_id,
                            canonical_path,
                            display_name,
                            opened_at,
                            options_json
                        ],
                    )
                    .map_err(persistence_error)?;
                project_id.to_owned()
            }
        };

        let (stored_path, stored_name, stored_options): (String, String, String) = transaction
            .query_row(
                "SELECT canonical_path, display_name, last_options_json FROM projects WHERE id = ?1",
                [&persisted_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(persistence_error)?;
        let last_completed_run_id = transaction
            .query_row(
                r#"SELECT id FROM scan_runs
                   WHERE project_id = ?1 AND status = 'completed'
                   ORDER BY completed_at DESC, id DESC LIMIT 1"#,
                [&persisted_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        let context = ProjectContext {
            project_id: persisted_id,
            canonical_path: stored_path,
            display_name: stored_name,
            policy: PolicyStatus::Missing,
            last_completed_run_id,
            last_options: parse_last_options(&stored_options)?,
        };
        transaction.commit().map_err(persistence_error)?;
        Ok(context)
    }

    /// Loads exactly one persisted project identity for service operations that
    /// must bind filesystem access to the repository-owned canonical root.
    pub fn project_context(&self, project_id: &str) -> Result<ProjectContext, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let stored = connection
            .query_row(
                r#"SELECT canonical_path, display_name, last_options_json
                   FROM projects WHERE id = ?1"#,
                [project_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::not_found)?;
        let last_completed_run_id = connection
            .query_row(
                r#"SELECT id FROM scan_runs
                   WHERE project_id = ?1 AND status = 'completed'
                   ORDER BY completed_at DESC, id DESC LIMIT 1"#,
                [project_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?;
        Ok(ProjectContext {
            project_id: project_id.to_owned(),
            canonical_path: stored.0,
            display_name: stored.1,
            policy: PolicyStatus::Missing,
            last_completed_run_id,
            last_options: parse_last_options(&stored.2)?,
        })
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
        struct StoredRunIdentity {
            status: String,
            project_id: String,
            scanner_version: String,
            fingerprint_version: u16,
            options_json: String,
            policy_status_json: String,
            policy_hash: Option<String>,
            started_at: String,
        }

        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let existing = transaction
            .query_row(
                r#"SELECT status, project_id, scanner_version,
                          fingerprint_version, options_json, policy_status_json, policy_hash,
                          started_at
                   FROM scan_runs WHERE id = ?1"#,
                [&detail.run_id],
                |row| {
                    Ok(StoredRunIdentity {
                        status: row.get(0)?,
                        project_id: row.get(1)?,
                        scanner_version: row.get(2)?,
                        fingerprint_version: row.get(3)?,
                        options_json: row.get(4)?,
                        policy_status_json: row.get(5)?,
                        policy_hash: row.get(6)?,
                        started_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(persistence_error)?;
        if let Some(existing) = existing {
            let identical = existing.status == "running"
                && existing.project_id == detail.project_id
                && existing.scanner_version == scanner_version
                && existing.fingerprint_version == super::domain::FINGERPRINT_VERSION
                && existing.options_json == options_json
                && existing.policy_status_json == policy_status_json
                && existing.policy_hash.as_deref() == policy_hash
                && existing.started_at == detail.started_at;
            if !identical {
                return Err(CommandError::persistence_unavailable());
            }
            transaction.commit().map_err(persistence_error)?;
            return Ok(());
        }

        transaction
            .execute(
                // `baseline_run_id` is advisory output. Completion derives and
                // persists the authoritative boundary from repository state.
                r#"INSERT INTO scan_runs(
                     id, project_id, baseline_run_id, status, scanner_version, fingerprint_version,
                     options_json, policy_status_json, policy_hash, started_at
                   ) VALUES (?1, ?2, NULL, 'running', ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![
                    detail.run_id,
                    detail.project_id,
                    scanner_version,
                    super::domain::FINGERPRINT_VERSION,
                    options_json,
                    policy_status_json,
                    policy_hash,
                    detail.started_at,
                ],
            )
            .map_err(persistence_error)?;
        transaction.commit().map_err(persistence_error)
    }

    pub fn complete_run(
        &self,
        detail: &ScanRunDetail,
        coverage: &CoverageManifest,
    ) -> Result<ScanRunDetail, CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;

        let (project_id, status, fingerprint_version, stored_started_at): (
            String,
            String,
            u16,
            String,
        ) = transaction
            .query_row(
                r#"SELECT project_id, status, fingerprint_version, started_at
                   FROM scan_runs WHERE id = ?1"#,
                [&detail.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::not_found)?;
        if status == "completed" {
            let stored = load_run_with_comparison_from_connection(&transaction, &detail.run_id)?
                .ok_or_else(CommandError::not_found)?;
            transaction.commit().map_err(persistence_error)?;
            return Ok(stored);
        }
        if status != "running"
            || detail.status != RunStatus::Completed
            || detail.project_id != project_id
            || detail.started_at != stored_started_at
            || coverage.fingerprint_version != fingerprint_version
            || detail
                .findings
                .iter()
                .any(|finding| finding.fingerprint_version != fingerprint_version)
        {
            return Err(CommandError::persistence_unavailable());
        }
        let started_at = parse_utc_timestamp(&stored_started_at)?;
        let completed_at = detail
            .completed_at
            .as_deref()
            .ok_or_else(CommandError::persistence_unavailable)
            .and_then(parse_utc_timestamp)?;
        if completed_at < started_at {
            return Err(CommandError::persistence_unavailable());
        }
        let baseline_run_id = latest_compatible_baseline_id_from_connection(
            &transaction,
            &project_id,
            fingerprint_version,
            coverage,
            started_at,
        )?;

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
                r#"UPDATE scan_runs
                   SET baseline_run_id = ?2, coverage_json = ?3, summary_json = ?4
                   WHERE id = ?1"#,
                params![detail.run_id, baseline_run_id, coverage_json, summary_json],
            )
            .map_err(persistence_error)?;
        let changed = transaction
            .execute(
                r#"UPDATE scan_runs
                   SET status = 'completed', completed_at = ?2, error_code = NULL
                   WHERE id = ?1 AND status = 'running'"#,
                params![detail.run_id, detail.completed_at],
            )
            .map_err(persistence_error)?;
        if changed != 1 {
            return Err(CommandError::persistence_unavailable());
        }
        transaction.commit().map_err(persistence_error)?;

        load_run_with_comparison_from_connection(&connection, &detail.run_id)?
            .ok_or_else(CommandError::not_found)
    }

    /// Commits a completed run first, then performs retention as independent
    /// maintenance. A maintenance failure is reported only on the returned
    /// projection and never changes the run's durable `Saved` state.
    pub fn complete_run_with_maintenance(
        &self,
        detail: &ScanRunDetail,
        coverage: &CoverageManifest,
        policy: RetentionPolicy,
        now: DateTime<Utc>,
    ) -> Result<ScanRunDetail, CommandError> {
        self.complete_run_with_maintenance_hook(detail, coverage, || {
            if policy.max_completed_runs_per_project == 0 || policy.max_age_days == 0 {
                return Err(CommandError::persistence_unavailable());
            }
            self.apply_retention_protecting(now, policy, Some(&detail.run_id))
                .map(|_| ())
        })
    }

    fn complete_run_with_maintenance_hook<F>(
        &self,
        detail: &ScanRunDetail,
        coverage: &CoverageManifest,
        maintenance: F,
    ) -> Result<ScanRunDetail, CommandError>
    where
        F: FnOnce() -> Result<(), CommandError>,
    {
        let mut stored = self.complete_run(detail, coverage)?;
        if maintenance().is_err() {
            stored.maintenance_warning = Some(RETENTION_MAINTENANCE_WARNING.into());
            return Ok(stored);
        }
        if self.should_fail_post_maintenance_reload_for_test() {
            Err(CommandError::persistence_unavailable())
        } else {
            self.load_run(&stored.run_id)
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_post_maintenance_reload_for_test(&self) {
        self.fail_post_maintenance_reload
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn should_fail_post_maintenance_reload_for_test(&self) -> bool {
        self.fail_post_maintenance_reload
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn should_fail_post_maintenance_reload_for_test(&self) -> bool {
        false
    }

    pub fn load_run(&self, run_id: &str) -> Result<ScanRunDetail, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        load_run_with_comparison_from_connection(&connection, run_id)?
            .ok_or_else(CommandError::not_found)
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

    #[cfg(test)]
    pub(crate) fn delete_run_for_test(&self, run_id: &str) -> Result<(), CommandError> {
        self.connection
            .lock()
            .map_err(persistence_error)?
            .execute("DELETE FROM scan_runs WHERE id = ?1", [run_id])
            .map(|_| ())
            .map_err(persistence_error)
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

    /// Selects the newest completed run for a project whose fingerprint version
    /// and scanner-family coverage are compatible with the supplied current
    /// coverage and whose completion instant is strictly before the cutoff.
    /// This is advisory for pre-completion display only: `complete_run` ignores
    /// caller hints and derives the authoritative boundary in its transaction.
    pub fn latest_compatible_baseline(
        &self,
        project_id: &str,
        fingerprint_version: u16,
        current_coverage: &CoverageManifest,
        strictly_before: DateTime<Utc>,
    ) -> Result<Option<ScanRunDetail>, CommandError> {
        if current_coverage.fingerprint_version != fingerprint_version {
            return Err(CommandError::persistence_unavailable());
        }
        let connection = self.connection.lock().map_err(persistence_error)?;
        latest_compatible_baseline_id_from_connection(
            &connection,
            project_id,
            fingerprint_version,
            current_coverage,
            strictly_before,
        )?
        .as_deref()
        .map(|run_id| load_run_from_connection(&connection, run_id))
        .transpose()
        .map(Option::flatten)
    }

    /// Returns an immutable comparison projection: current observations first,
    /// followed by every baseline-only observation. Stored rows are not updated.
    pub fn compare_runs(
        &self,
        current_run_id: &str,
        baseline_run_id: &str,
    ) -> Result<Vec<Finding>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        compare_runs_from_connection(&connection, current_run_id, baseline_run_id)
    }

    /// Returns the authoritative newest completed observation for an exact
    /// project finding identity. Stored RFC3339 values are parsed as instants;
    /// their textual representation never controls recency.
    pub fn latest_observation(
        &self,
        project_id: &str,
        fingerprint_version: u16,
        fingerprint: &str,
    ) -> Result<Finding, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        latest_observation_from_connection(
            &connection,
            project_id,
            fingerprint_version,
            fingerprint,
        )?
        .ok_or_else(CommandError::not_found)
    }

    /// Returns one authoritative newest completed observation per stable
    /// identity for policy reconciliation on project load.
    pub fn latest_project_observations(
        &self,
        project_id: &str,
    ) -> Result<Vec<Finding>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        latest_project_observations_from_connection(&connection, project_id)
            .map(|(observations, _)| observations)
    }

    /// Enriches a bounded finding slice from one project-level review query.
    /// This is the service boundary for unsaved observations, which do not yet
    /// have durable rows from which `load_run` could build their projection.
    pub fn enrich_findings_with_reviews(
        &self,
        project_id: &str,
        findings: &mut [Finding],
        include_project_policy: bool,
        now: DateTime<Utc>,
    ) -> Result<(), CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let identities = findings
            .iter()
            .map(|finding| (finding.fingerprint_version, finding.fingerprint.clone()))
            .collect::<BTreeSet<_>>();
        let mut histories =
            load_project_reviews_for_identities(&connection, project_id, &identities)?;
        for finding in findings {
            let history = histories
                .remove(&(finding.fingerprint_version, finding.fingerprint.clone()))
                .unwrap_or_default();
            finding.review = if include_project_policy {
                select_active_review(&history, now)
            } else {
                select_active_local_review(&history, now)
            };
            finding.review_history = history;
        }
        Ok(())
    }

    pub(crate) fn current_project_policy_reviews(
        &self,
        project_id: &str,
    ) -> Result<Vec<ReviewRecord>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        current_project_policy_reviews_from_connection(&connection, project_id)
    }

    #[cfg(test)]
    fn latest_project_observations_with_work(
        &self,
        project_id: &str,
    ) -> Result<(Vec<Finding>, ProjectObservationWork), CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        latest_project_observations_from_connection(&connection, project_id)
    }

    /// Test-only Local event injection for projection/history fixtures. Policy
    /// events must always enter through the authority-bound review service.
    #[cfg(test)]
    pub(in crate::findings) fn inject_local_review_event_for_test(
        &self,
        review: &ReviewRecord,
    ) -> Result<ReviewRecord, CommandError> {
        if review.origin != ReviewOrigin::Local {
            return Err(CommandError::review_invalid());
        }
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let stored = append_review_event(&transaction, review, None)?;
        transaction.commit().map_err(persistence_error)?;
        Ok(stored)
    }

    /// Resolves the authoritative observation and appends a Local event inside
    /// one repository lock and SQLite transaction. The builder performs the
    /// category-specific validation while the observation cannot change.
    pub(crate) fn save_local_review_for_latest_observation<F>(
        &self,
        project_id: &str,
        fingerprint_version: u16,
        fingerprint: &str,
        build: F,
    ) -> Result<ReviewRecord, CommandError>
    where
        F: FnOnce(&Finding) -> Result<ReviewRecord, CommandError>,
    {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let observation = latest_observation_from_connection(
            &transaction,
            project_id,
            fingerprint_version,
            fingerprint,
        )?
        .ok_or_else(CommandError::not_found)?;
        let review = build(&observation)?;
        if review.origin != ReviewOrigin::Local
            || review.project_id != project_id
            || review.fingerprint_version != fingerprint_version
            || review.fingerprint != fingerprint
        {
            return Err(CommandError::review_invalid());
        }
        let stored = append_review_event(&transaction, &review, None)?;
        transaction.commit().map_err(persistence_error)?;
        Ok(stored)
    }

    #[cfg(test)]
    pub(crate) fn test_connection_is_available(&self) -> bool {
        self.connection.try_lock().is_ok()
    }

    /// Reconciles a complete project-policy projection atomically. Either all
    /// changed identities are appended or none are.
    pub(in crate::findings) fn reconcile_project_policy_events(
        &self,
        authority: &PolicyAuthority<'_>,
        reviews: &[ReviewRecord],
    ) -> Result<usize, CommandError> {
        self.reconcile_project_policy_projection(authority, reviews, None)
            .map(|(_, inserted)| inserted)
    }

    pub(in crate::findings) fn reconcile_project_policy_projection(
        &self,
        authority: &PolicyAuthority<'_>,
        reviews: &[ReviewRecord],
        explicit_identity: Option<(u16, &str)>,
    ) -> Result<(Vec<ReviewRecord>, usize), CommandError> {
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let mut inserted = 0usize;
        let mut stored = Vec::with_capacity(reviews.len());
        for review in reviews {
            let force_initial_candidate = explicit_identity.is_some_and(|identity| {
                identity == (review.fingerprint_version, review.fingerprint.as_str())
            });
            let (event, was_inserted) = reconcile_project_policy_event_in_transaction(
                &transaction,
                authority,
                review,
                force_initial_candidate,
            )?;
            inserted += usize::from(was_inserted);
            stored.push(event);
        }
        transaction.commit().map_err(persistence_error)?;
        Ok((stored, inserted))
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
                            .filter(|finding| is_open_finding(finding))
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

    pub fn list_runs(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<ScanRunSummary>, CommandError> {
        struct StoredRunSummary {
            run_id: String,
            project_id: String,
            baseline_run_id: Option<String>,
            status: RunStatus,
            started_at: String,
            completed_at: Option<String>,
            coverage: Option<CoverageManifest>,
            effective_at: DateTime<Utc>,
        }

        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct ObservationIdentity {
            fingerprint_version: u16,
            fingerprint: String,
            category: String,
            file_path: String,
        }

        let connection = self.connection.lock().map_err(persistence_error)?;
        let exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
                [project_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(persistence_error)?;
        if !exists {
            return Err(CommandError::not_found());
        }
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut runs = {
            let mut statement = connection
                .prepare(
                    r#"SELECT id, project_id, baseline_run_id, status, started_at,
                              completed_at, coverage_json
                       FROM scan_runs WHERE project_id = ?1"#,
                )
                .map_err(persistence_error)?;
            let rows = statement
                .query_map([project_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            rows.into_iter()
                .map(
                    |(
                        run_id,
                        project_id,
                        baseline_run_id,
                        status,
                        started_at,
                        completed_at,
                        coverage_json,
                    )| {
                        let effective_at = parse_utc_timestamp(
                            completed_at.as_deref().unwrap_or(started_at.as_str()),
                        )?;
                        Ok(StoredRunSummary {
                            run_id,
                            project_id,
                            baseline_run_id,
                            status: parse_run_status(&status)?,
                            started_at,
                            completed_at,
                            coverage: coverage_json.as_deref().map(from_json).transpose()?,
                            effective_at,
                        })
                    },
                )
                .collect::<Result<Vec<_>, CommandError>>()?
        };
        runs.sort_by(|left, right| {
            right
                .effective_at
                .cmp(&left.effective_at)
                .then_with(|| right.run_id.cmp(&left.run_id))
        });
        runs.truncate(limit);

        let relevant_run_ids = runs
            .iter()
            .flat_map(|run| std::iter::once(run.run_id.clone()).chain(run.baseline_run_id.clone()))
            .collect::<BTreeSet<_>>();
        let mut observations = BTreeMap::<String, Vec<ObservationIdentity>>::new();
        if !relevant_run_ids.is_empty() {
            let placeholders = std::iter::repeat("?")
                .take(relevant_run_ids.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                r#"SELECT run_id, fingerprint_version, fingerprint, category,
                          json_extract(payload_json, '$.filePath')
                   FROM findings WHERE run_id IN ({placeholders}) ORDER BY run_id, rowid"#
            );
            let mut statement = connection.prepare(&sql).map_err(persistence_error)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(relevant_run_ids.iter()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        ObservationIdentity {
                            fingerprint_version: row.get(1)?,
                            fingerprint: row.get(2)?,
                            category: row.get(3)?,
                            file_path: row.get(4)?,
                        },
                    ))
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            for (run_id, identity) in rows {
                observations.entry(run_id).or_default().push(identity);
            }
        }

        runs.into_iter()
            .map(|run| {
                let current = observations.get(&run.run_id).cloned().unwrap_or_default();
                let (total_findings, new_findings, resolved_findings) = if run.status
                    != RunStatus::Completed
                {
                    (0, 0, 0)
                } else if let Some(baseline_run_id) = run.baseline_run_id.as_deref() {
                    let baseline = observations
                        .get(baseline_run_id)
                        .cloned()
                        .unwrap_or_default();
                    let current_keys = current
                        .iter()
                        .map(|observation| {
                            (
                                observation.fingerprint_version,
                                observation.fingerprint.as_str(),
                            )
                        })
                        .collect::<BTreeSet<_>>();
                    let baseline_keys = baseline
                        .iter()
                        .map(|observation| {
                            (
                                observation.fingerprint_version,
                                observation.fingerprint.as_str(),
                            )
                        })
                        .collect::<BTreeSet<_>>();
                    let coverage = run
                        .coverage
                        .as_ref()
                        .ok_or_else(CommandError::persistence_unavailable)?;
                    let new_findings = current_keys.difference(&baseline_keys).count();
                    let resolved_findings = baseline
                        .iter()
                        .filter(|observation| {
                            !current_keys.contains(&(
                                observation.fingerprint_version,
                                observation.fingerprint.as_str(),
                            )) && coverage.is_covered(&observation.file_path, &observation.category)
                        })
                        .count();
                    (current.len(), new_findings, resolved_findings)
                } else {
                    (current.len(), current.len(), 0)
                };
                Ok(ScanRunSummary {
                    run_id: run.run_id,
                    project_id: run.project_id,
                    status: run.status,
                    started_at: run.started_at,
                    completed_at: run.completed_at,
                    total_findings,
                    new_findings,
                    resolved_findings,
                })
            })
            .collect()
    }

    pub fn apply_retention(
        &self,
        now: DateTime<Utc>,
        policy: RetentionPolicy,
    ) -> Result<usize, CommandError> {
        self.apply_retention_protecting(now, policy, None)
    }

    fn apply_retention_protecting(
        &self,
        now: DateTime<Utc>,
        policy: RetentionPolicy,
        protected_run_id: Option<&str>,
    ) -> Result<usize, CommandError> {
        struct CompletedRun {
            id: String,
            project_id: String,
            completed_at: DateTime<Utc>,
        }

        let completed_before = now
            .checked_sub_signed(ChronoDuration::days(i64::from(policy.max_age_days)))
            .ok_or_else(CommandError::persistence_unavailable)?;
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let completed_runs = {
            let mut statement = transaction
                .prepare(
                    r#"SELECT id, project_id, completed_at
                       FROM scan_runs
                       WHERE status = 'completed'"#,
                )
                .map_err(persistence_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            rows.into_iter()
                .map(|(id, project_id, completed_at)| {
                    let completed_at = completed_at
                        .as_deref()
                        .ok_or_else(CommandError::persistence_unavailable)
                        .and_then(parse_utc_timestamp)?;
                    Ok(CompletedRun {
                        id,
                        project_id,
                        completed_at,
                    })
                })
                .collect::<Result<Vec<_>, CommandError>>()?
        };

        let mut delete_ids = completed_runs
            .iter()
            .filter(|run| {
                run.completed_at < completed_before && protected_run_id != Some(run.id.as_str())
            })
            .map(|run| run.id.clone())
            .collect::<BTreeSet<_>>();
        let mut by_project = BTreeMap::<String, Vec<&CompletedRun>>::new();
        for run in &completed_runs {
            if !delete_ids.contains(&run.id) {
                by_project
                    .entry(run.project_id.clone())
                    .or_default()
                    .push(run);
            }
        }
        for runs in by_project.values_mut() {
            runs.sort_by(|left, right| {
                right
                    .completed_at
                    .cmp(&left.completed_at)
                    .then_with(|| right.id.cmp(&left.id))
            });
            let protected_is_present = protected_run_id
                .is_some_and(|protected| runs.iter().any(|run| run.id == protected));
            let mut remaining_slots = policy.max_completed_runs_per_project as usize;
            if protected_is_present {
                remaining_slots = remaining_slots.saturating_sub(1);
            }
            for run in runs
                .iter()
                .filter(|run| protected_run_id != Some(run.id.as_str()))
            {
                if remaining_slots > 0 {
                    remaining_slots -= 1;
                } else {
                    delete_ids.insert(run.id.clone());
                }
            }
        }

        let mut deleted = 0;
        for run_id in delete_ids {
            let changed = transaction
                .execute(
                    "DELETE FROM scan_runs WHERE id = ?1 AND status = 'completed'",
                    [run_id],
                )
                .map_err(persistence_error)?;
            if changed != 1 {
                return Err(CommandError::persistence_unavailable());
            }
            deleted += changed;
        }
        transaction.commit().map_err(persistence_error)?;
        Ok(deleted)
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
struct PinnedDirectory {
    file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(unix)]
fn open_file_database_unix(
    path: &Path,
    hook: impl FnOnce(),
) -> Result<FindingsRepository, CommandError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(CommandError::persistence_unavailable)?;
    let file_name = path
        .file_name()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let pinned_parent = pin_database_parent(parent)?;

    hook();

    let canonical_parent = canonicalize_pinned_parent(parent, &pinned_parent)?;
    let open_path = canonical_parent.join(file_name);
    let pinned_database = open_database_at(&pinned_parent.file, file_name)?;

    revalidate_parent_identity(parent, &canonical_parent, &pinned_parent)?;
    revalidate_database_identity(path, &open_path, pinned_database.identity)?;

    // The file is already present relative to the pinned directory, so CREATE is
    // deliberately omitted: a later path replacement cannot make SQLite create
    // a database in an attacker-controlled directory.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection =
        Connection::open_with_flags(&open_path, flags).map_err(persistence_error)?;

    // SQLite accepts a pathname rather than our fd. Re-check both pinned
    // identities after it opens and before any PRAGMA or migration can write.
    revalidate_parent_identity(parent, &canonical_parent, &pinned_parent)?;
    revalidate_database_identity(path, &open_path, pinned_database.identity)?;

    initialize_connection(&connection, true)?;
    migrate(&mut connection, MIGRATION_V1)?;
    Ok(FindingsRepository {
        connection: Mutex::new(connection),
        #[cfg(test)]
        fail_post_maintenance_reload: std::sync::atomic::AtomicBool::new(false),
    })
}

#[cfg(unix)]
fn pin_database_parent(parent: &Path) -> Result<PinnedDirectory, CommandError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    let created = match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            validate_directory_metadata(&metadata)?;
            require_owner_only(&metadata)?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent).map_err(persistence_error)?;
            true
        }
        Err(error) => return Err(persistence_error(error)),
    };

    let path_metadata = std::fs::symlink_metadata(parent).map_err(persistence_error)?;
    validate_directory_metadata(&path_metadata)?;

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(persistence_error)?;
    let mut handle_metadata = directory.metadata().map_err(persistence_error)?;
    validate_directory_metadata(&handle_metadata)?;
    if file_identity(&path_metadata) != file_identity(&handle_metadata) {
        return Err(CommandError::persistence_unavailable());
    }

    if created {
        let mut permissions = handle_metadata.permissions();
        permissions.set_mode(0o700);
        directory
            .set_permissions(permissions)
            .map_err(persistence_error)?;
        handle_metadata = directory.metadata().map_err(persistence_error)?;
    }
    require_owner_only(&handle_metadata)?;

    Ok(PinnedDirectory {
        identity: file_identity(&handle_metadata),
        file: directory,
    })
}

#[cfg(unix)]
fn canonicalize_pinned_parent(
    parent: &Path,
    pinned: &PinnedDirectory,
) -> Result<std::path::PathBuf, CommandError> {
    validate_directory_path_identity(parent, pinned.identity)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(persistence_error)?;
    validate_directory_path_identity(&canonical_parent, pinned.identity)?;
    Ok(canonical_parent)
}

#[cfg(unix)]
fn revalidate_parent_identity(
    parent: &Path,
    canonical_parent: &Path,
    pinned: &PinnedDirectory,
) -> Result<(), CommandError> {
    let handle_metadata = pinned.file.metadata().map_err(persistence_error)?;
    validate_directory_metadata(&handle_metadata)?;
    if file_identity(&handle_metadata) != pinned.identity {
        return Err(CommandError::persistence_unavailable());
    }
    validate_directory_path_identity(parent, pinned.identity)?;
    validate_directory_path_identity(canonical_parent, pinned.identity)
}

#[cfg(unix)]
fn validate_directory_path_identity(
    path: &Path,
    expected: FileIdentity,
) -> Result<(), CommandError> {
    let metadata = std::fs::symlink_metadata(path).map_err(persistence_error)?;
    validate_directory_metadata(&metadata)?;
    if file_identity(&metadata) == expected {
        Ok(())
    } else {
        Err(CommandError::persistence_unavailable())
    }
}

#[cfg(unix)]
fn validate_directory_metadata(metadata: &std::fs::Metadata) -> Result<(), CommandError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        Err(CommandError::persistence_unavailable())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
struct PinnedDatabase {
    _file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(unix)]
fn open_database_at(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
) -> Result<PinnedDatabase, CommandError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    let file_name = std::ffi::CString::new(file_name.as_bytes()).map_err(persistence_error)?;
    let base_flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let (file, created) = match openat_file(
        parent.as_raw_fd(),
        &file_name,
        base_flags | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            openat_file(parent.as_raw_fd(), &file_name, base_flags, 0)
                .map_err(persistence_error)?,
            false,
        ),
        Err(error) => return Err(persistence_error(error)),
    };

    let mut metadata = file.metadata().map_err(persistence_error)?;
    if !metadata.is_file() {
        return Err(CommandError::persistence_unavailable());
    }
    if created {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .map_err(persistence_error)?;
        metadata = file.metadata().map_err(persistence_error)?;
    }
    require_owner_only(&metadata)?;

    Ok(PinnedDatabase {
        identity: file_identity(&metadata),
        _file: file,
    })
}

#[cfg(unix)]
fn openat_file(
    parent_fd: std::os::unix::io::RawFd,
    file_name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;

    // SAFETY: `parent_fd` remains owned by the caller, `file_name` is a valid
    // NUL-terminated string, and a successful returned fd is transferred into
    // exactly one `File` for closing.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            file_name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new owned descriptor on success.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn revalidate_database_identity(
    requested_path: &Path,
    canonical_path: &Path,
    expected: FileIdentity,
) -> Result<(), CommandError> {
    validate_database_path_identity(requested_path, expected)?;
    validate_database_path_identity(canonical_path, expected)
}

#[cfg(unix)]
fn validate_database_path_identity(
    path: &Path,
    expected: FileIdentity,
) -> Result<(), CommandError> {
    let metadata = std::fs::symlink_metadata(path).map_err(persistence_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || file_identity(&metadata) != expected
    {
        Err(CommandError::persistence_unavailable())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn open_file_database_portable(
    path: &Path,
    hook: impl FnOnce(),
) -> Result<FindingsRepository, CommandError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(CommandError::persistence_unavailable)?;
    prepare_database_parent(parent)?;
    validate_database_path(path)?;
    hook();
    let canonical_parent = std::fs::canonicalize(parent).map_err(persistence_error)?;
    let file_name = path
        .file_name()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let open_path = canonical_parent.join(file_name);

    let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection =
        Connection::open_with_flags(open_path, flags).map_err(persistence_error)?;
    validate_database_path(path)?;
    initialize_connection(&connection, true)?;
    migrate(&mut connection, MIGRATION_V1)?;
    Ok(FindingsRepository {
        connection: Mutex::new(connection),
        #[cfg(test)]
        fail_post_maintenance_reload: std::sync::atomic::AtomicBool::new(false),
    })
}

#[cfg(not(unix))]
fn prepare_database_parent(parent: &Path) -> Result<(), CommandError> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CommandError::persistence_unavailable());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent).map_err(persistence_error)?;
            let metadata = std::fs::symlink_metadata(parent).map_err(persistence_error)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CommandError::persistence_unavailable());
            }
        }
        Err(error) => return Err(persistence_error(error)),
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_database_path(path: &Path) -> Result<bool, CommandError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CommandError::persistence_unavailable());
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(persistence_error(error)),
    }
}

#[cfg(unix)]
fn require_owner_only(metadata: &std::fs::Metadata) -> Result<(), CommandError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(CommandError::persistence_unavailable())
    }
}

fn is_open_finding(finding: &Finding) -> bool {
    match finding.review.as_ref().map(|review| review.state) {
        Some(ReviewState::Confirmed) => true,
        None | Some(ReviewState::Candidate) => matches!(
            finding.scope,
            Some(FindingScope::Production | FindingScope::Infrastructure | FindingScope::Unknown)
        ),
        Some(ReviewState::FalsePositive | ReviewState::AcceptedRisk | ReviewState::Suppressed) => {
            false
        }
    }
}

struct StoredComparisonRun {
    project_id: String,
    status: RunStatus,
    fingerprint_version: u16,
    coverage: Option<CoverageManifest>,
    started_at: String,
    completed_at: Option<String>,
}

fn load_comparison_run(
    connection: &Connection,
    run_id: &str,
) -> Result<StoredComparisonRun, CommandError> {
    let stored = connection
        .query_row(
            r#"SELECT project_id, status, fingerprint_version, coverage_json, started_at,
                      completed_at
               FROM scan_runs WHERE id = ?1"#,
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u16>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(persistence_error)?
        .ok_or_else(CommandError::not_found)?;
    Ok(StoredComparisonRun {
        project_id: stored.0,
        status: parse_run_status(&stored.1)?,
        fingerprint_version: stored.2,
        coverage: stored.3.as_deref().map(from_json).transpose()?,
        started_at: stored.4,
        completed_at: stored.5,
    })
}

fn require_completed_comparison_run(run: &StoredComparisonRun) -> Result<(), CommandError> {
    let compatible_version = run
        .coverage
        .as_ref()
        .is_some_and(|coverage| coverage.fingerprint_version == run.fingerprint_version);
    if run.status == RunStatus::Completed && run.completed_at.is_some() && compatible_version {
        Ok(())
    } else {
        Err(CommandError::persistence_unavailable())
    }
}

fn compare_runs_from_connection(
    connection: &Connection,
    current_run_id: &str,
    baseline_run_id: &str,
) -> Result<Vec<Finding>, CommandError> {
    let current = load_comparison_run(connection, current_run_id)?;
    let baseline = load_comparison_run(connection, baseline_run_id)?;
    require_completed_comparison_run(&current)?;
    require_completed_comparison_run(&baseline)?;
    let current_started_at = parse_utc_timestamp(&current.started_at)?;
    let baseline_completed_at = baseline
        .completed_at
        .as_deref()
        .ok_or_else(CommandError::persistence_unavailable)
        .and_then(parse_utc_timestamp)?;
    let baseline_is_prior = baseline_completed_at < current_started_at;
    let current_coverage = current
        .coverage
        .as_ref()
        .ok_or_else(CommandError::persistence_unavailable)?;
    let baseline_coverage = baseline
        .coverage
        .as_ref()
        .ok_or_else(CommandError::persistence_unavailable)?;
    if current.project_id != baseline.project_id
        || current.fingerprint_version != baseline.fingerprint_version
        || !baseline_is_prior
        || !current_coverage.is_compatible_with(baseline_coverage)
    {
        return Err(CommandError::persistence_unavailable());
    }

    let current_detail = load_run_from_connection(connection, current_run_id)?
        .ok_or_else(CommandError::not_found)?;
    let baseline_detail = load_run_from_connection(connection, baseline_run_id)?
        .ok_or_else(CommandError::not_found)?;
    let baseline_fingerprints = baseline_detail
        .findings
        .iter()
        .map(|finding| (finding.fingerprint_version, finding.fingerprint.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let current_fingerprints = current_detail
        .findings
        .iter()
        .map(|finding| (finding.fingerprint_version, finding.fingerprint.clone()))
        .collect::<std::collections::BTreeSet<_>>();

    let mut projection = Vec::with_capacity(
        current_detail
            .findings
            .len()
            .saturating_add(baseline_detail.findings.len()),
    );
    for mut finding in current_detail.findings {
        finding.observation_run_id = current_run_id.into();
        finding.resolved_by_run_id = None;
        finding.diff_status = Some(
            if baseline_fingerprints
                .contains(&(finding.fingerprint_version, finding.fingerprint.clone()))
            {
                DiffStatus::Unchanged
            } else {
                DiffStatus::New
            },
        );
        projection.push(finding);
    }
    for mut finding in baseline_detail.findings {
        if current_fingerprints
            .contains(&(finding.fingerprint_version, finding.fingerprint.clone()))
        {
            continue;
        }
        finding.observation_run_id = baseline_run_id.into();
        if current_coverage.is_covered(&finding.file_path, &finding.category) {
            finding.resolved_by_run_id = Some(current_run_id.into());
            finding.diff_status = Some(DiffStatus::Resolved);
        } else {
            finding.resolved_by_run_id = None;
            finding.diff_status = Some(DiffStatus::NotEvaluated);
        }
        projection.push(finding);
    }
    Ok(projection)
}

fn latest_compatible_baseline_id_from_connection(
    connection: &Connection,
    project_id: &str,
    fingerprint_version: u16,
    current_coverage: &CoverageManifest,
    strictly_before: DateTime<Utc>,
) -> Result<Option<String>, CommandError> {
    struct Candidate {
        run_id: String,
        completed_at: DateTime<Utc>,
    }

    let candidates = {
        let mut statement = connection
            .prepare(
                r#"SELECT id, completed_at, coverage_json FROM scan_runs
                   WHERE project_id = ?1
                     AND status = 'completed'
                     AND fingerprint_version = ?2"#,
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map(params![project_id, fingerprint_version], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(persistence_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(persistence_error)?;
        rows
    };

    let mut compatible = Vec::new();
    for (run_id, completed_at, coverage_json) in candidates {
        let completed_at = completed_at
            .as_deref()
            .ok_or_else(CommandError::persistence_unavailable)
            .and_then(parse_utc_timestamp)?;
        let coverage: CoverageManifest = coverage_json
            .as_deref()
            .ok_or_else(CommandError::persistence_unavailable)
            .and_then(from_json)?;
        if coverage.fingerprint_version != fingerprint_version {
            return Err(CommandError::persistence_unavailable());
        }
        if completed_at < strictly_before && current_coverage.is_compatible_with(&coverage) {
            compatible.push(Candidate {
                run_id,
                completed_at,
            });
        }
    }
    compatible.sort_by(|left, right| {
        right
            .completed_at
            .cmp(&left.completed_at)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    Ok(compatible
        .into_iter()
        .next()
        .map(|candidate| candidate.run_id))
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

fn latest_observation_from_connection(
    connection: &Connection,
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
) -> Result<Option<Finding>, CommandError> {
    let candidates = {
        let mut statement = connection
            .prepare(
                r#"SELECT f.run_id, r.completed_at
                   FROM findings f
                   JOIN scan_runs r ON r.id = f.run_id
                   WHERE r.project_id = ?1
                     AND r.status = 'completed'
                     AND f.fingerprint_version = ?2
                     AND f.fingerprint = ?3"#,
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map(
                params![project_id, fingerprint_version, fingerprint],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .map_err(persistence_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(persistence_error)?;
        rows
    };
    let mut newest = None::<(DateTime<Utc>, String)>;
    for (run_id, completed_at) in candidates {
        let completed_at = completed_at
            .as_deref()
            .ok_or_else(CommandError::persistence_unavailable)
            .and_then(parse_utc_timestamp)?;
        let replace = newest.as_ref().map_or(true, |(newest_at, newest_run)| {
            completed_at > *newest_at || (completed_at == *newest_at && run_id > *newest_run)
        });
        if replace {
            newest = Some((completed_at, run_id));
        }
    }
    let Some((_, run_id)) = newest else {
        return Ok(None);
    };
    let observation = load_findings(connection, &run_id, project_id)?
        .into_iter()
        .find(|finding| {
            finding.fingerprint_version == fingerprint_version && finding.fingerprint == fingerprint
        })
        .ok_or_else(CommandError::persistence_unavailable)?;
    Ok(Some(observation))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProjectObservationWork {
    queries: usize,
    rows_visited: usize,
    payloads_deserialized: usize,
}

struct RawProjectObservation {
    id: String,
    run_id: String,
    completed_at: DateTime<Utc>,
    fingerprint_version: u16,
    fingerprint: String,
    category: String,
    rule_id: String,
    payload: String,
    scope: String,
    scope_reason: String,
}

fn latest_project_observations_from_connection(
    connection: &Connection,
    project_id: &str,
) -> Result<(Vec<Finding>, ProjectObservationWork), CommandError> {
    let mut work = ProjectObservationWork {
        queries: 1,
        ..ProjectObservationWork::default()
    };
    let mut winners = BTreeMap::<(u16, String), RawProjectObservation>::new();
    {
        let mut statement = connection
            .prepare(
                r#"SELECT f.id, f.run_id, r.completed_at, f.fingerprint_version, f.fingerprint,
                          f.category, f.rule_id, f.payload_json, f.scope, f.scope_reason
                   FROM findings f
                   JOIN scan_runs r ON r.id = f.run_id
                   WHERE r.project_id = ?1 AND r.status = 'completed'"#,
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, u16>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(persistence_error)?;
        for candidate in rows {
            work.rows_visited += 1;
            let (
                id,
                run_id,
                completed_at,
                fingerprint_version,
                fingerprint,
                category,
                rule_id,
                payload,
                scope,
                scope_reason,
            ) = candidate.map_err(persistence_error)?;
            let completed_at = completed_at
                .as_deref()
                .ok_or_else(CommandError::persistence_unavailable)
                .and_then(parse_utc_timestamp)?;
            let identity = (fingerprint_version, fingerprint.clone());
            let replace = winners.get(&identity).map_or(true, |current| {
                completed_at > current.completed_at
                    || (completed_at == current.completed_at && run_id > current.run_id)
            });
            if replace {
                winners.insert(
                    identity,
                    RawProjectObservation {
                        id,
                        run_id,
                        completed_at,
                        fingerprint_version,
                        fingerprint,
                        category,
                        rule_id,
                        payload,
                        scope,
                        scope_reason,
                    },
                );
            }
        }
    };

    let observations = winners
        .into_values()
        .map(|observation| {
            work.payloads_deserialized += 1;
            finding_from_raw_project_observation(observation)
        })
        .collect::<Result<Vec<_>, CommandError>>()?;
    Ok((observations, work))
}

fn finding_from_raw_project_observation(
    observation: RawProjectObservation,
) -> Result<Finding, CommandError> {
    let payload: StoredFindingPayload = from_json(&observation.payload)?;
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
        observation_run_id: observation.run_id,
        resolved_by_run_id: None,
        fingerprint_version: observation.fingerprint_version,
        fingerprint: observation.fingerprint,
        scope: Some(parse_scope(&observation.scope)?),
        scope_reason: Some(observation.scope_reason),
        review: None,
        review_history: Vec::new(),
        diff_status: None,
    })
}

fn current_project_policy_reviews_from_connection(
    connection: &Connection,
    project_id: &str,
) -> Result<Vec<ReviewRecord>, CommandError> {
    let mut statement = connection
        .prepare(
            r#"SELECT id, fingerprint_version, fingerprint, state, reason, evidence,
                      entry_point, data_flow, gates_json, deciding_gate, expires_at,
                      origin, policy_hash, updated_at, superseded_at
               FROM reviews
               WHERE project_id = ?1 AND origin = 'projectPolicy' AND superseded_at IS NULL
               ORDER BY fingerprint_version, fingerprint"#,
        )
        .map_err(persistence_error)?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u16>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, Option<String>>(14)?,
            ))
        })
        .map_err(persistence_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(persistence_error)?;
    rows.into_iter()
        .map(|row| {
            let (
                id,
                fingerprint_version,
                fingerprint,
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
            parse_utc_timestamp(&updated_at)?;
            Ok(ReviewRecord {
                id,
                project_id: project_id.to_owned(),
                fingerprint_version,
                fingerprint,
                state: parse_json_enum(&state)?,
                reason,
                evidence,
                entry_point,
                data_flow,
                gates: from_json(&gates_json)?,
                deciding_gate: deciding_gate.as_deref().map(parse_json_enum).transpose()?,
                expires_at,
                origin: parse_json_enum(&origin)?,
                policy_hash,
                updated_at,
                superseded_at,
            })
        })
        .collect()
}

fn append_review_event(
    transaction: &rusqlite::Transaction<'_>,
    review: &ReviewRecord,
    policy_authority: Option<&PolicyAuthority<'_>>,
) -> Result<ReviewRecord, CommandError> {
    match (review.origin, policy_authority.is_some()) {
        (ReviewOrigin::Local, false) | (ReviewOrigin::ProjectPolicy, true) => {}
        _ => return Err(CommandError::review_invalid()),
    }
    let current = load_reviews(
        transaction,
        &review.project_id,
        review.fingerprint_version,
        &review.fingerprint,
    )?
    .into_iter()
    .find(|stored| stored.origin == review.origin && stored.superseded_at.is_none());
    if let Some(current) = current {
        let changed = transaction
            .execute(
                "UPDATE reviews SET superseded_at = ?2 WHERE id = ?1 AND superseded_at IS NULL",
                params![current.id, review.updated_at],
            )
            .map_err(persistence_error)?;
        if changed != 1 {
            return Err(CommandError::persistence_unavailable());
        }
    }

    let mut stored = review.clone();
    stored.id = Uuid::new_v4().to_string();
    stored.superseded_at = None;
    transaction
        .execute(
            r#"INSERT INTO reviews(
                 id, project_id, fingerprint_version, fingerprint, state, reason, evidence,
                 entry_point, data_flow, gates_json, deciding_gate, expires_at, origin,
                 policy_hash, updated_at, superseded_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL)"#,
            params![
                stored.id,
                stored.project_id,
                stored.fingerprint_version,
                stored.fingerprint,
                json_enum_name(stored.state)?,
                stored.reason,
                stored.evidence,
                stored.entry_point,
                stored.data_flow,
                to_json(&stored.gates)?,
                stored.deciding_gate.map(json_enum_name).transpose()?,
                stored.expires_at,
                json_enum_name(stored.origin)?,
                stored.policy_hash,
                stored.updated_at,
            ],
        )
        .map_err(persistence_error)?;
    Ok(stored)
}

fn reconcile_project_policy_event_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    authority: &PolicyAuthority<'_>,
    review: &ReviewRecord,
    force_initial_candidate: bool,
) -> Result<(ReviewRecord, bool), CommandError> {
    if review.origin != ReviewOrigin::ProjectPolicy {
        return Err(CommandError::persistence_unavailable());
    }
    let current = load_reviews(
        transaction,
        &review.project_id,
        review.fingerprint_version,
        &review.fingerprint,
    )?
    .into_iter()
    .find(|stored| stored.origin == ReviewOrigin::ProjectPolicy && stored.superseded_at.is_none());

    if let Some(current) = current.as_ref() {
        if same_reconciled_policy_state(current, review) {
            return Ok((current.clone(), false));
        }
    } else if review.state == ReviewState::Candidate && !force_initial_candidate {
        return Ok((review.clone(), false));
    }

    append_review_event(transaction, review, Some(authority)).map(|stored| (stored, true))
}

fn same_reconciled_policy_state(left: &ReviewRecord, right: &ReviewRecord) -> bool {
    left.project_id == right.project_id
        && left.fingerprint_version == right.fingerprint_version
        && left.fingerprint == right.fingerprint
        && left.state == right.state
        && left.reason == right.reason
        && left.evidence == right.evidence
        && left.entry_point == right.entry_point
        && left.data_flow == right.data_flow
        && left.gates == right.gates
        && left.deciding_gate == right.deciding_gate
        && left.expires_at == right.expires_at
        && left.origin == right.origin
        && left.policy_hash == right.policy_hash
}

fn json_enum_name(value: impl Serialize) -> Result<String, CommandError> {
    let encoded = to_json(&value)?;
    encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(CommandError::persistence_unavailable)
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

fn load_run_with_comparison_from_connection(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<ScanRunDetail>, CommandError> {
    let Some(mut run) = load_run_from_connection(connection, run_id)? else {
        return Ok(None);
    };
    if run.status == RunStatus::Completed {
        if let Some(baseline_run_id) = run.baseline_run_id.as_deref() {
            run.findings = compare_runs_from_connection(connection, run_id, baseline_run_id)?;
        } else {
            for finding in &mut run.findings {
                finding.observation_run_id = run_id.into();
                finding.resolved_by_run_id = None;
                finding.diff_status = Some(DiffStatus::New);
            }
        }
    }
    Ok(Some(run))
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

    let identities = observations
        .iter()
        .map(|observation| {
            (
                observation.fingerprint_version,
                observation.fingerprint.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut histories = load_project_reviews_for_identities(connection, project_id, &identities)?;

    observations
        .into_iter()
        .map(|observation| {
            let payload: StoredFindingPayload = from_json(&observation.payload)?;
            let review_history = histories
                .remove(&(
                    observation.fingerprint_version,
                    observation.fingerprint.clone(),
                ))
                .unwrap_or_default();
            let review = select_active_review(&review_history, Utc::now());
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

fn select_active_review(history: &[ReviewRecord], now: DateTime<Utc>) -> Option<ReviewRecord> {
    [ReviewOrigin::Local, ReviewOrigin::ProjectPolicy]
        .into_iter()
        .filter_map(|origin| {
            history
                .iter()
                .find(|review| review.origin == origin && review.superseded_at.is_none())
        })
        .find(|review| {
            review.state != ReviewState::Candidate
                && review.expires_at.as_deref().map_or(true, |expires_at| {
                    DateTime::parse_from_rfc3339(expires_at)
                        .is_ok_and(|expires_at| expires_at.with_timezone(&Utc) > now)
                })
        })
        .cloned()
}

fn select_active_local_review(
    history: &[ReviewRecord],
    now: DateTime<Utc>,
) -> Option<ReviewRecord> {
    history
        .iter()
        .find(|review| {
            review.origin == ReviewOrigin::Local
                && review.superseded_at.is_none()
                && review.state != ReviewState::Candidate
                && review.expires_at.as_deref().map_or(true, |expires_at| {
                    DateTime::parse_from_rfc3339(expires_at)
                        .is_ok_and(|expires_at| expires_at.with_timezone(&Utc) > now)
                })
        })
        .cloned()
}

fn load_reviews(
    connection: &Connection,
    project_id: &str,
    fingerprint_version: u16,
    fingerprint: &str,
) -> Result<Vec<ReviewRecord>, CommandError> {
    let mut statement = connection
        .prepare(
            r#"SELECT rowid, id, state, reason, evidence, entry_point, data_flow, gates_json, deciding_gate,
                      expires_at, origin, policy_hash, updated_at, superseded_at
               FROM reviews
               WHERE project_id = ?1 AND fingerprint_version = ?2 AND fingerprint = ?3
               "#,
        )
        .map_err(persistence_error)?;
    let rows = statement
        .query_map(
            params![project_id, fingerprint_version, fingerprint],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .map_err(persistence_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(persistence_error)?;
    let mut parsed = rows
        .into_iter()
        .map(|row| {
            let (
                rowid,
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
            let updated_instant = parse_utc_timestamp(&updated_at)?;
            Ok((
                rowid,
                updated_instant,
                ReviewRecord {
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
                },
            ))
        })
        .collect::<Result<Vec<_>, CommandError>>()?;
    parsed.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0)));
    Ok(parsed.into_iter().map(|(_, _, review)| review).collect())
}

fn load_project_reviews_for_identities(
    connection: &Connection,
    project_id: &str,
    identities: &BTreeSet<(u16, String)>,
) -> Result<BTreeMap<(u16, String), Vec<ReviewRecord>>, CommandError> {
    if identities.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut statement = connection
        .prepare(
            r#"SELECT rowid, id, fingerprint_version, fingerprint, state, reason, evidence,
                      entry_point, data_flow, gates_json, deciding_gate, expires_at, origin,
                      policy_hash, updated_at, superseded_at
               FROM reviews WHERE project_id = ?1"#,
        )
        .map_err(persistence_error)?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, Option<String>>(15)?,
            ))
        })
        .map_err(persistence_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(persistence_error)?;
    let mut grouped = BTreeMap::<(u16, String), Vec<(i64, DateTime<Utc>, ReviewRecord)>>::new();
    for row in rows {
        let (
            rowid,
            id,
            fingerprint_version,
            fingerprint,
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
        let identity = (fingerprint_version, fingerprint.clone());
        if !identities.contains(&identity) {
            continue;
        }
        let origin = parse_json_enum::<ReviewOrigin>(&origin)?;
        let updated_instant = parse_utc_timestamp(&updated_at)?;
        grouped.entry(identity).or_default().push((
            rowid,
            updated_instant,
            ReviewRecord {
                id,
                project_id: project_id.to_owned(),
                fingerprint_version,
                fingerprint,
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
                origin,
                policy_hash,
                updated_at,
                superseded_at,
            },
        ));
    }
    Ok(grouped
        .into_iter()
        .map(|(identity, mut reviews)| {
            reviews.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0)));
            (
                identity,
                reviews.into_iter().map(|(_, _, review)| review).collect(),
            )
        })
        .collect())
}

fn to_json(value: &impl Serialize) -> Result<String, CommandError> {
    serde_json::to_string(value).map_err(persistence_error)
}

fn enum_name(value: &impl Serialize) -> Result<String, CommandError> {
    serde_json::to_value(value)
        .map_err(persistence_error)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(CommandError::persistence_unavailable)
}

fn from_json<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, CommandError> {
    serde_json::from_str(value).map_err(persistence_error)
}

fn parse_utc_timestamp(value: &str) -> Result<DateTime<Utc>, CommandError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(persistence_error)
}

fn parse_last_options(value: &str) -> Result<Option<ScanOptions>, CommandError> {
    if matches!(value.trim(), "{}" | "null") {
        Ok(None)
    } else {
        from_json(value).map(Some)
    }
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
    if !applied {
        apply_migration(connection, 1, migration_v1)?;
    }
    let version_two_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 2)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_two_applied {
        apply_migration(connection, 2, MIGRATION_V2)?;
    }
    let version_three_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 3)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_three_applied {
        apply_migration(connection, 3, MIGRATION_V3)?;
    }
    backfill_canonical_findings(connection)?;
    let version_four_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 4)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_four_applied {
        apply_migration(connection, 4, MIGRATION_V4)?;
    }
    let version_five_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 5)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_five_applied {
        apply_migration(connection, 5, MIGRATION_V5)?;
    }
    Ok(())
}

fn backfill_canonical_findings(connection: &mut Connection) -> Result<(), CommandError> {
    let payloads = {
        let mut statement = connection
            .prepare("SELECT payload_json FROM canonical_observations ORDER BY id")
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(persistence_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(persistence_error)?
    };
    let transaction = connection.transaction().map_err(persistence_error)?;
    for payload in payloads {
        let observation: oxaudit_domain::Observation =
            serde_json::from_str(&payload).map_err(persistence_error)?;
        if !matches!(
            observation.kind,
            oxaudit_domain::ObservationKind::SourceWeakness
                | oxaudit_domain::ObservationKind::SecretCandidate
                | oxaudit_domain::ObservationKind::AdvisoryMatch
                | oxaudit_domain::ObservationKind::PolicyConcern
                | oxaudit_domain::ObservationKind::SemanticDataFlow
        ) {
            continue;
        }
        let finding = oxaudit_domain::Finding {
            id: oxaudit_domain::FindingId::parse(observation.id.as_str().replacen(
                "observation_",
                "finding_",
                1,
            ))
            .map_err(persistence_error)?,
            run_id: observation.run_id.clone(),
            fingerprint: observation.id.as_str().to_owned(),
            fingerprint_version: 1,
            title: observation.title.clone(),
            severity: oxaudit_domain::Severity::Info,
            state: oxaudit_domain::FindingState::Candidate,
            classifications: Vec::new(),
            observation_ids: vec![observation.id.clone()],
            evidence_ids: observation.evidence_ids.clone(),
        };
        transaction
            .execute(
                "INSERT OR IGNORE INTO canonical_findings(id, run_id, payload_json) VALUES (?1, ?2, ?3)",
                params![
                    finding.id.as_str(),
                    finding.run_id.as_str(),
                    to_json(&finding)?
                ],
            )
            .map_err(persistence_error)?;
    }
    transaction.commit().map_err(persistence_error)
}

fn apply_migration(
    connection: &mut Connection,
    version: u32,
    sql: &str,
) -> Result<(), CommandError> {
    let transaction = connection.transaction().map_err(persistence_error)?;
    transaction
        .execute_batch(
            r#"CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
               );"#,
        )
        .map_err(persistence_error)?;
    transaction.execute_batch(sql).map_err(persistence_error)?;
    transaction
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![version, Utc::now().to_rfc3339()],
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
        DiffStatus, FindingScope, PolicyStatus, RetentionPolicy, ReviewOrigin, ReviewRecord,
        ReviewState, RunPersistence, RunStatus, ScanRunDetail, FINGERPRINT_VERSION,
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
}

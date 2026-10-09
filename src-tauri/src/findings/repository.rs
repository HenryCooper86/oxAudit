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
        ScanRunSummary, SeverityCounts,
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

const MIGRATION_V6: &str = r#"
CREATE TABLE IF NOT EXISTS trust_grants (
  content_sha256 TEXT PRIMARY KEY,
  granted_at_ms INTEGER NOT NULL,
  granted_by TEXT NOT NULL,
  note TEXT NOT NULL
);
"#;

const MIGRATION_V7: &str = r#"
CREATE INDEX provider_snapshots_freshness_idx
ON provider_snapshots(provider_id, fetched_at_ms DESC, id DESC);
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

    /// Record (or refresh) a trust grant for an imported claim document.
    pub(crate) fn save_trust_grant(
        &self,
        grant: &crate::vex_trust::TrustGrant,
    ) -> Result<(), CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                "INSERT INTO trust_grants (content_sha256, granted_at_ms, granted_by, note)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(content_sha256) DO UPDATE SET
                     granted_at_ms = excluded.granted_at_ms,
                     granted_by = excluded.granted_by,
                     note = excluded.note",
                params![
                    grant.content_sha256,
                    grant.granted_at_ms as i64,
                    grant.granted_by,
                    grant.note
                ],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn delete_trust_grant(&self, content_sha256: &str) -> Result<(), CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        connection
            .execute(
                "DELETE FROM trust_grants WHERE content_sha256 = ?1",
                params![content_sha256],
            )
            .map_err(persistence_error)?;
        Ok(())
    }

    pub(crate) fn trust_grants(&self) -> Result<Vec<crate::vex_trust::TrustGrant>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut statement = connection
            .prepare(
                "SELECT content_sha256, granted_at_ms, granted_by, note
                 FROM trust_grants ORDER BY granted_at_ms DESC",
            )
            .map_err(persistence_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(crate::vex_trust::TrustGrant {
                    content_sha256: row.get(0)?,
                    granted_at_ms: row.get::<_, i64>(1)? as u64,
                    granted_by: row.get(2)?,
                    note: row.get(3)?,
                })
            })
            .map_err(persistence_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(persistence_error)
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

    /// Return one covering candidate at a time. Unrelated histories are filtered
    /// in SQLite, so they cannot consume the validation budget or fill memory.
    /// Membership is only a selection hint: callers must validate the hash and
    /// complete receipt contract before treating a candidate as evidence.
    pub(crate) fn provider_covering_snapshot(
        &self,
        provider_id: &str,
        query_keys: &[String],
        before: Option<(u64, &str)>,
    ) -> Result<Option<ProviderSnapshotRecord>, CommandError> {
        let keys = to_json(&query_keys)?;
        let before_time = before
            .map(|(time, _)| i64::try_from(time))
            .transpose()
            .map_err(persistence_error)?;
        let before_id = before.map(|(_, id)| id);
        let connection = self.connection.lock().map_err(persistence_error)?;
        let row = connection
            .query_row(
                r#"SELECT id, provider_id, fetched_at_ms, content_sha256, payload_json
               FROM provider_snapshots
               WHERE provider_id = ?1
                 AND (?3 IS NULL OR fetched_at_ms < ?3 OR (fetched_at_ms = ?3 AND id < ?4))
                 AND NOT EXISTS (
                   SELECT value FROM json_each(?2)
                   EXCEPT
                   SELECT value FROM json_each(
                     CASE WHEN json_valid(payload_json) THEN
                       CASE WHEN json_type(payload_json, '$.queryKeys') = 'array'
                         THEN json_extract(payload_json, '$.queryKeys') ELSE '[]' END
                       ELSE '[]' END
                   ) WHERE type = 'text'
                 )
               ORDER BY fetched_at_ms DESC, id DESC LIMIT 1"#,
                params![provider_id, keys, before_time, before_id],
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

    /// Effective options captured when this saved run started; never project defaults.
    pub fn run_options(&self, run_id: &str) -> Result<ScanOptions, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let json: String = connection
            .query_row(
                "SELECT options_json FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::not_found)?;
        from_json(&json)
    }

    pub(crate) fn run_coverage(
        &self,
        run_id: &str,
    ) -> Result<Option<CoverageManifest>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        Ok(load_comparison_run(&connection, run_id)?.coverage)
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
                    counts_available: None,
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
            rule_id: String,
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
        // Severity rides along for the per-run counts; it deliberately stays
        // out of ObservationIdentity so a severity relabel between runs is
        // not miscounted as a new or resolved finding.
        let mut observations = BTreeMap::<String, Vec<(ObservationIdentity, String)>>::new();
        if !relevant_run_ids.is_empty() {
            let placeholders = std::iter::repeat("?")
                .take(relevant_run_ids.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                r#"SELECT run_id, fingerprint_version, fingerprint, category,
                          json_extract(payload_json, '$.filePath'),
                          json_extract(payload_json, '$.severity'),
                          rule_id
                   FROM findings WHERE run_id IN ({placeholders}) ORDER BY run_id, rowid"#
            );
            let mut statement = connection.prepare(&sql).map_err(persistence_error)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(relevant_run_ids.iter()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        (
                            ObservationIdentity {
                                fingerprint_version: row.get(1)?,
                                fingerprint: row.get(2)?,
                                category: row.get(3)?,
                                file_path: row.get(4)?,
                                rule_id: row.get(6)?,
                            },
                            row.get::<_, String>(5)?,
                        ),
                    ))
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?;
            for (run_id, (identity, severity)) in rows {
                observations
                    .entry(run_id)
                    .or_default()
                    .push((identity, severity));
            }
        }

        runs.into_iter()
            .map(|run| {
                let current = observations.get(&run.run_id).cloned().unwrap_or_default();
                let (total_findings, new_findings, resolved_findings) =
                    if run.status != RunStatus::Completed {
                        (0, 0, 0)
                    } else if let Some(baseline_run_id) = run.baseline_run_id.as_deref() {
                        let baseline = observations
                            .get(baseline_run_id)
                            .cloned()
                            .unwrap_or_default();
                        let current_keys = current
                            .iter()
                            .map(|(observation, _)| {
                                (
                                    observation.fingerprint_version,
                                    observation.fingerprint.as_str(),
                                )
                            })
                            .collect::<BTreeSet<_>>();
                        let baseline_keys = baseline
                            .iter()
                            .map(|(observation, _)| {
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
                        let baseline_coverage = load_comparison_run(&connection, baseline_run_id)?
                            .coverage
                            .unwrap_or_default();
                        let new_findings = current_keys.difference(&baseline_keys).count();
                        let resolved_findings = baseline
                            .iter()
                            .filter(|(observation, _)| {
                                !current_keys.contains(&(
                                    observation.fingerprint_version,
                                    observation.fingerprint.as_str(),
                                )) && coverage.is_finding_covered(
                                    &observation.file_path,
                                    &observation.category,
                                    &observation.rule_id,
                                    &baseline_coverage,
                                )
                            })
                            .count();
                        (current.len(), new_findings, resolved_findings)
                    } else {
                        (current.len(), current.len(), 0)
                    };
                let severity_counts = if run.status != RunStatus::Completed {
                    SeverityCounts::default()
                } else {
                    let mut counts = SeverityCounts::default();
                    for (_, severity) in &current {
                        counts.record(severity);
                    }
                    counts
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
                    severity_counts,
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

pub(in crate::findings) fn is_open_finding(finding: &Finding) -> bool {
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
        if current_coverage.is_finding_covered(
            &finding.file_path,
            &finding.category,
            &finding.rule_id,
            baseline_coverage,
        ) {
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
        analysis: payload.analysis,
        analysis_gates: payload.analysis_gates.clone(),
        observation_run_id: observation.run_id,
        resolved_by_run_id: None,
        fingerprint_version: observation.fingerprint_version,
        fingerprint: observation.fingerprint,
        // Scanner-time signal; the stored row already carries the scope it
        // produced, so nothing is lost by not persisting it.
        in_test_region: false,
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
    /// Absent in rows written before the tier existed; those default to `Text`
    /// so a stored finding never claims a verification that did not run.
    #[serde(default)]
    analysis: crate::models::AnalysisTier,
    #[serde(default)]
    analysis_gates: Vec<crate::triage::gates::GateNote>,
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
            analysis: finding.analysis,
            analysis_gates: finding.analysis_gates.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredScanSummary {
    #[serde(default)]
    git_context: Option<crate::git_context::GitEvidence>,
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
            git_context: summary.git_context.clone(),
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
            git_context: summary.git_context,
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
                analysis: payload.analysis,
                analysis_gates: payload.analysis_gates.clone(),
                observation_run_id: run_id.to_owned(),
                resolved_by_run_id: None,
                fingerprint_version: observation.fingerprint_version,
                fingerprint: observation.fingerprint,
                // Scanner-time signal; the stored row already carries the scope it
                // produced, so nothing is lost by not persisting it.
                in_test_region: false,
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
        git_context: None,
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
    let version_six_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 6)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_six_applied {
        apply_migration(connection, 6, MIGRATION_V6)?;
    }
    let version_seven_applied = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 7)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(persistence_error)?;
    if !version_seven_applied {
        apply_migration(connection, 7, MIGRATION_V7)?;
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
#[path = "repository_tests.rs"]
mod tests;

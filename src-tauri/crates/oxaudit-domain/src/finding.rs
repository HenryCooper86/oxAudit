use serde::{Deserialize, Serialize};

use crate::{EvidenceId, FindingId, ObservationId, RunId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Candidate,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Suppressed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: FindingId,
    pub run_id: RunId,
    pub fingerprint: String,
    pub fingerprint_version: u32,
    pub title: String,
    pub severity: Severity,
    pub state: FindingState,
    pub classifications: Vec<String>,
    pub observation_ids: Vec<ObservationId>,
    pub evidence_ids: Vec<EvidenceId>,
}

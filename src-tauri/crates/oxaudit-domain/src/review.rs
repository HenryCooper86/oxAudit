use serde::{Deserialize, Serialize};

use crate::{EvidenceId, FindingId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Candidate,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewOrigin {
    Human,
    ImportedVex,
    Policy,
    AiDraftAcceptedByHuman,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub finding_id: FindingId,
    pub disposition: ReviewDisposition,
    pub author: String,
    pub origin: ReviewOrigin,
    pub reason: String,
    pub deciding_gate: Option<String>,
    pub evidence_ids: Vec<EvidenceId>,
    pub expires_at_ms: Option<u64>,
    pub reviewed_at_ms: u64,
}

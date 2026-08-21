use serde::{Deserialize, Serialize};

use crate::{ArtifactId, EvidenceId, ObservationId, RunId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    SourceWeakness,
    SecretCandidate,
    DependencyDeclaration,
    BinaryComponent,
    AdvisoryMatch,
    PolicyConcern,
    SemanticDataFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub id: ObservationId,
    pub run_id: RunId,
    pub artifact_id: ArtifactId,
    pub kind: ObservationKind,
    pub detector_id: String,
    pub detector_version: String,
    pub rule_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub evidence_ids: Vec<EvidenceId>,
}

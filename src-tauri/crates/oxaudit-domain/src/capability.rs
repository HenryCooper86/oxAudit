use serde::{Deserialize, Serialize};

use crate::Provenance;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Detector,
    AdvisoryProvider,
    RulePack,
    ReportWriter,
    Verifier,
    SemanticAnalyzer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum CapabilityAvailability {
    Available,
    Degraded(String),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescriptor {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: CapabilityKind,
    pub provenance: Provenance,
    pub supports_offline: bool,
    pub availability: CapabilityAvailability,
    pub limitations: Vec<String>,
}

use serde::{Deserialize, Serialize};

use crate::{ArtifactId, ComponentId, DomainError, EvidenceId, ProviderSnapshotId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileLocationEvidence {
    pub artifact_id: ArtifactId,
    pub normalized_path: String,
    pub start_line: Option<u32>,
    pub start_column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub context_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedValue {
    display: String,
    redaction_reason: String,
    correlation_hash: String,
}

impl RedactedValue {
    pub fn secret(
        redaction_reason: impl Into<String>,
        keyed_correlation_sha256: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let hash = keyed_correlation_sha256.into();
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidSecretCorrelation);
        }
        Ok(Self {
            display: "[REDACTED]".to_string(),
            redaction_reason: redaction_reason.into(),
            correlation_hash: hash.to_ascii_lowercase(),
        })
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub fn redaction_reason(&self) -> &str {
        &self.redaction_reason
    }

    pub fn correlation_hash(&self) -> &str {
        &self.correlation_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedSecretEvidence {
    pub artifact_id: ArtifactId,
    pub rule_id: String,
    pub location: FileLocationEvidence,
    pub value: RedactedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryMatchEvidence {
    pub artifact_id: ArtifactId,
    pub offset: Option<u64>,
    pub section: Option<String>,
    pub matcher_id: String,
    pub encoding: String,
    pub captured_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageDeclarationEvidence {
    pub artifact_id: ArtifactId,
    pub ecosystem: String,
    pub package_name: String,
    pub declared_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryMatchEvidence {
    pub component_id: ComponentId,
    pub provider_snapshot_id: ProviderSnapshotId,
    pub advisory_id: String,
    pub affected: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDecisionEvidence {
    pub gate: String,
    pub verdict: String,
    pub rationale: String,
    pub supporting_evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolReceiptEvidence {
    pub engine_id: String,
    pub engine_version: String,
    pub invocation_sha256: String,
    pub bounded_metadata: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowNode {
    pub address: u64,
    pub label: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowEdge {
    pub from_address: u64,
    pub to_address: Option<u64>,
    pub relationship: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowEvidence {
    pub artifact_id: ArtifactId,
    pub entry_point: u64,
    pub sink: String,
    pub nodes: Vec<DataFlowNode>,
    pub edges: Vec<DataFlowEdge>,
    pub unresolved_edges: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details", rename_all = "snake_case")]
pub enum Evidence {
    FileLocation(FileLocationEvidence),
    RedactedSecret(RedactedSecretEvidence),
    BinaryMatch(BinaryMatchEvidence),
    PackageDeclaration(PackageDeclarationEvidence),
    AdvisoryMatch(AdvisoryMatchEvidence),
    GateDecision(GateDecisionEvidence),
    ToolReceipt(ToolReceiptEvidence),
    DataFlow(DataFlowEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub evidence: Evidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_evidence_serializes_only_a_redaction() {
        let redacted = RedactedValue::secret("credential", "a".repeat(64)).unwrap();
        let json = serde_json::to_value(redacted).unwrap();
        assert_eq!(json["display"], "[REDACTED]");
        assert_eq!(json["correlationHash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn reversible_or_missing_secret_correlation_is_rejected() {
        assert_eq!(
            RedactedValue::secret("credential", "hunter2"),
            Err(DomainError::InvalidSecretCorrelation)
        );
    }
}

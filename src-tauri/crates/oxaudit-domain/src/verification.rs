use serde::{Deserialize, Serialize};

use crate::{DomainError, EvidenceId, FindingId, VerificationId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierIdentity {
    pub kind: String,
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    Supported,
    Refuted,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: VerificationId,
    pub finding_id: FindingId,
    pub producer_id: String,
    pub verifier: VerifierIdentity,
    pub input_snapshot_sha256: String,
    pub result: VerificationResult,
    pub evidence_delta: Vec<EvidenceId>,
    pub limitations: Vec<String>,
    pub verified_at_ms: u64,
}

impl Verification {
    pub fn validate_independence(&self) -> Result<(), DomainError> {
        if self.producer_id == self.verifier.id {
            Err(DomainError::SelfVerification)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_cannot_self_verify() {
        let verification = Verification {
            id: VerificationId::new(),
            finding_id: FindingId::new(),
            producer_id: "native-source".into(),
            verifier: VerifierIdentity {
                kind: "detector".into(),
                id: "native-source".into(),
                version: "1".into(),
            },
            input_snapshot_sha256: "a".repeat(64),
            result: VerificationResult::Supported,
            evidence_delta: Vec::new(),
            limitations: Vec::new(),
            verified_at_ms: 1,
        };
        assert_eq!(
            verification.validate_independence(),
            Err(DomainError::SelfVerification)
        );
    }
}

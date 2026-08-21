use oxaudit_domain::DomainError;
use thiserror::Error;

use crate::ManifestError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApplicationError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("repository operation failed: {0}")]
    Repository(String),
    #[error("detector {detector_id} failed: {message}")]
    Detector {
        detector_id: String,
        message: String,
    },
    #[error("no detector supports artifact {0}")]
    UnsupportedArtifact(String),
    #[error("run was cancelled")]
    Cancelled,
    #[error("report writer failed: {0}")]
    Report(String),
    #[error("verification failed: {0}")]
    Verification(String),
}

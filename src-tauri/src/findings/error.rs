use serde::Serialize;

#[derive(Serialize, Clone, Debug, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{message}")]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidTarget,
    ScanCancelled,
    ScanFailed,
    ScanAlreadyRunning,
    PersistenceUnavailable,
    PolicyInvalid,
    PolicyWriteFailed,
    ReviewInvalid,
    NotFound,
    CredentialUnavailable,
    CredentialRollbackFailed,
    MigrationFailed,
    DataOperationFailed,
}

impl CommandError {
    pub fn invalid_target() -> Self {
        Self::new(
            ErrorCode::InvalidTarget,
            "The selected target cannot be scanned.",
            false,
        )
    }

    pub fn scan_cancelled() -> Self {
        Self::new(ErrorCode::ScanCancelled, "The scan was cancelled.", false)
    }

    pub fn scan_failed() -> Self {
        Self::new(
            ErrorCode::ScanFailed,
            "The scan could not be completed.",
            true,
        )
    }

    pub fn scan_already_running() -> Self {
        Self::new(
            ErrorCode::ScanAlreadyRunning,
            "A scan is already running for this project.",
            false,
        )
    }

    pub fn persistence_unavailable() -> Self {
        Self::new(
            ErrorCode::PersistenceUnavailable,
            "Scan results could not be saved.",
            true,
        )
    }

    pub fn policy_invalid() -> Self {
        Self::new(
            ErrorCode::PolicyInvalid,
            "The project policy is invalid.",
            false,
        )
    }

    pub fn policy_write_failed() -> Self {
        Self::new(
            ErrorCode::PolicyWriteFailed,
            "The project policy could not be saved.",
            true,
        )
    }

    pub fn review_invalid() -> Self {
        Self::new(
            ErrorCode::ReviewInvalid,
            "The review request is invalid.",
            false,
        )
    }

    pub fn not_found() -> Self {
        Self::new(
            ErrorCode::NotFound,
            "The requested item was not found.",
            false,
        )
    }

    pub fn credential_unavailable() -> Self {
        Self::new(
            ErrorCode::CredentialUnavailable,
            "Protected credential storage is unavailable. Unlock the system credential store and try again.",
            true,
        )
    }

    pub fn credential_rollback_failed() -> Self {
        Self::new(
            ErrorCode::CredentialRollbackFailed,
            "Credential storage could not be restored after a failed settings save. Review both credentials before retrying.",
            false,
        )
    }

    pub fn migration_failed() -> Self {
        Self::new(
            ErrorCode::MigrationFailed,
            "Existing oxAudit data could not be migrated safely. The original data was preserved.",
            true,
        )
    }

    fn new(code: ErrorCode, message: &str, retryable: bool) -> Self {
        Self {
            code,
            message: message.to_owned(),
            detail: None,
            retryable,
        }
    }
}

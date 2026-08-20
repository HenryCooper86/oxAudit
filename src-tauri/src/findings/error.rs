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

    pub fn scan_failed_with_detail(sanitized_detail: String) -> Self {
        Self::scan_failed().with_sanitized_detail(sanitized_detail)
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

    pub fn persistence_unavailable_with_detail(sanitized_detail: String) -> Self {
        Self::persistence_unavailable().with_sanitized_detail(sanitized_detail)
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

    pub fn policy_write_failed_with_detail(sanitized_detail: String) -> Self {
        Self::policy_write_failed().with_sanitized_detail(sanitized_detail)
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

    fn new(code: ErrorCode, message: &str, retryable: bool) -> Self {
        Self {
            code,
            message: message.to_owned(),
            detail: None,
            retryable,
        }
    }

    fn with_sanitized_detail(mut self, sanitized_detail: String) -> Self {
        self.detail = Some(sanitized_detail);
        self
    }
}

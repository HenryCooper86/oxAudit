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
    BaselineIncompatible,
    NothingToScan,
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
    pub fn baseline_incompatible() -> Self {
        Self::new(ErrorCode::BaselineIncompatible,
            "This baseline cannot be compared. Choose an earlier completed saved run from the same project with compatible scanner coverage and finding identities.", false)
    }

    pub fn invalid_target() -> Self {
        Self::new(
            ErrorCode::InvalidTarget,
            "The selected target cannot be scanned.",
            false,
        )
    }

    /// The target exists but contains nothing this scan would read.
    ///
    /// Distinct from `scan_failed` on purpose. Nothing broke — the target, the
    /// ignore list, and the size limit between them selected no files, and the
    /// only useful response names all three. Reporting it as a generic failure
    /// tells the user nothing; reporting it as a clean scan would be worse,
    /// because "no files were examined" and "no problems were found" are very
    /// different statements for a security tool to make.
    pub fn nothing_to_scan() -> Self {
        Self::new(
            ErrorCode::NothingToScan,
            "No files were eligible for this scan. Check the target path, the ignored \
             directories, and the maximum file size.",
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

    pub fn scan_resource_limit(detail: impl Into<String>) -> Self {
        let mut error = Self::new(
            ErrorCode::ScanFailed,
            "The scan exceeded a safety limit and was stopped.",
            false,
        );
        error.detail = Some(detail.into());
        error
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

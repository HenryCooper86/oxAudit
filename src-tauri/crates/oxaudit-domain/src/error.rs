use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("{kind} identity cannot be empty")]
    EmptyId { kind: &'static str },
    #[error("{kind} identity exceeds 200 characters")]
    IdTooLong { kind: &'static str },
    #[error("illegal run transition from {from} to {to}")]
    IllegalRunTransition { from: String, to: String },
    #[error("terminal runs are immutable")]
    TerminalRunImmutable,
    #[error("a redacted secret requires a non-reversible correlation hash")]
    InvalidSecretCorrelation,
    #[error("provenance field {field} cannot be empty")]
    MissingProvenance { field: &'static str },
    #[error("a verifier cannot independently verify its own producer output")]
    SelfVerification,
}

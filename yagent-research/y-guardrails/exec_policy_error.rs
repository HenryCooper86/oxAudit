//! Errors from the exec policy engine.

use std::path::PathBuf;

use thiserror::Error;

/// Errors from parsing or evaluating an exec policy.
#[derive(Debug, Error)]
pub enum ExecPolicyError {
    /// Policy file syntax error.
    #[error("{policy}: line {line}: {message}")]
    Syntax {
        /// Policy identifier (usually the file path).
        policy: String,
        /// 1-based line number.
        line: usize,
        /// Human-readable description.
        message: String,
    },

    /// Invalid decision string.
    #[error("invalid decision: {0}")]
    InvalidDecision(String),

    /// Invalid rule definition.
    #[error("invalid rule: {0}")]
    InvalidRule(String),

    /// Invalid pattern.
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    /// A `match` example did not match any rule.
    #[error("match example {example:?} did not match any rule")]
    MatchExampleFailed { example: Vec<String> },

    /// A `not_match` example matched a rule.
    #[error("not_match example {example:?} matched a rule")]
    NotMatchExampleFailed { example: Vec<String> },

    /// I/O error reading or writing a policy file.
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// File lock error.
    #[error("lock error on {path}: {source}")]
    Lock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Policy file has no parent directory.
    #[error("policy path has no parent: {0}")]
    MissingParent(PathBuf),
}

/// Result alias for exec policy operations.
pub type ExecPolicyResult<T> = Result<T, ExecPolicyError>;

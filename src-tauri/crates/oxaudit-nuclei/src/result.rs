//! Result types shared by every protocol.

use oxaudit_domain::Severity;
use serde::{Deserialize, Serialize};

use crate::model::Protocol;

/// A location inside a file for word/regex matches. Lines and columns are
/// 1-based; columns count bytes. Offsets are 0-based bytes into the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileLine {
    pub line: usize,
    pub start_column: usize,
    pub end_column: usize,
    pub start_offset: usize,
    pub end_offset: usize,
    /// The matched line, lossily decoded and truncated.
    pub text: String,
    /// Name of the matcher that matched, when it has one.
    pub matcher: Option<String>,
}

/// One result of a template against one target (or file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateMatch {
    pub template_id: String,
    pub name: String,
    pub severity: Severity,
    pub matcher_names: Vec<String>,
    /// Extractor name (empty when unnamed) and its values.
    pub extracted: Vec<(String, Vec<String>)>,
    pub protocol: Protocol,
    /// Index of the request block inside the template's protocol list.
    pub request_index: usize,
    /// URL, `host:port`, DNS name or file path.
    pub matched_at: String,
    /// File matches only.
    pub lines: Vec<FileLine>,
    /// What the word/regex matchers matched (truncated).
    pub matched_values: Vec<String>,
    /// Evaluation problems seen while producing this result.
    pub warnings: Vec<String>,
}

/// Why a planned request was not produced. Skips are reported, never silent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SkipReason {
    #[error("unresolved variable(s): {}", .0.join(", "))]
    UnresolvedVariable(Vec<String>),
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("expression error: {0}")]
    Expression(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

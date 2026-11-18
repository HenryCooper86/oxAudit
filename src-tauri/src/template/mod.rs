//! The Template scan: request and result shapes, template selection, the
//! local-path (Nuclei `file` protocol) executor, and the canonical graph.
//! `commands/template.rs` wires it to a run lifecycle; nothing here touches
//! Tauri or the findings database.
//!
//! The types are always compiled so the command surface is identical in
//! every build. The engine needs the `templates` feature; without it the
//! `scan_templates` command fails with an explicit error and never returns an
//! empty result.
//!
//! Everything except producing matches is shared between a local-path scan
//! and a live-target scan: validation, selection and filtering, projection,
//! graph, events, and terminal states. An executor returns an [`Execution`];
//! `files::scan_path` is the local one and `live::run_live_targets` the
//! live one.

#![cfg_attr(not(feature = "templates"), allow(dead_code))]

#[cfg(feature = "templates")]
pub(crate) mod exec;
#[cfg(feature = "templates")]
pub(crate) mod files;
#[cfg(feature = "templates")]
pub(crate) mod graph;
#[cfg(feature = "templates")]
pub(crate) mod live;
#[cfg(feature = "templates")]
pub(crate) mod select;

use serde::{Deserialize, Serialize};

#[cfg(feature = "templates")]
pub use crate::filewalk::MAX_FILES;

/// Largest `maxFileSizeMb` accepted.
pub const MAX_FILE_SIZE_MB_LIMIT: u32 = 1024;
pub const DEFAULT_MAX_FILE_SIZE_MB: u32 = 64;
/// Stored match rows; the remainder is counted and the run is Incomplete.
pub const MAX_MATCH_ROWS: usize = 100_000;
/// Stored not-evaluated rows; the remainder is counted.
pub const MAX_NOT_EVALUATED_ROWS: usize = 100_000;
/// Pack id used for one-off template paths that are not installed.
pub const ADHOC_PACK_ID: &str = "adhoc";
/// Lines kept per match row and characters kept per line.
pub const MAX_LINES_PER_ROW: usize = 50;
pub const MAX_LINE_CHARS: usize = 300;
/// Extracted values kept per extractor and characters kept per value.
pub const MAX_EXTRACTED_VALUES: usize = 20;
pub const MAX_EXTRACTED_CHARS: usize = 500;
/// Longest authorization statement kept.
pub const MAX_STATEMENT_CHARS: usize = 500;

/// Tags that mark a template as reporting credentials or other secrets. For
/// these, extracted values and matched text are masked before they reach the
/// projection, an event, or any output.
pub const SECRET_TAGS: &[&str] = &[
    "token",
    "keys",
    "secret",
    "secrets",
    "credentials",
    "creds",
    "password",
    "api-key",
    "apikey",
    "private-key",
];

/// The user's statement that they may test the targets they named.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateAuthorization {
    #[serde(default)]
    pub acknowledged: bool,
    #[serde(default)]
    pub statement: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateScanRequest {
    /// File or folder to scan with `file` templates. Exactly one of `path`
    /// and `targets` must be given.
    #[serde(default)]
    pub path: Option<String>,
    /// Live targets (URL, host, host:port, IP, CIDR).
    #[serde(default)]
    pub targets: Vec<String>,
    /// Required with `targets`; never remembered between runs.
    #[serde(default)]
    pub authorization: Option<TemplateAuthorization>,
    /// Installed Nuclei packs to apply. `None` means every enabled pack.
    #[serde(default)]
    pub pack_ids: Option<Vec<String>>,
    /// One-off template files or folders that are not installed.
    #[serde(default)]
    pub extra_template_paths: Vec<String>,
    /// Run only templates with any of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Never run templates with any of these tags.
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    /// Run only templates of these severities.
    #[serde(default)]
    pub severities: Vec<String>,
    /// Run only templates with these ids.
    #[serde(default)]
    pub template_ids: Vec<String>,
    /// Allow templates tagged `intrusive` or `fuzz`. `dos` never runs.
    #[serde(default)]
    pub include_intrusive: bool,
    /// Live scans: requests per second overall. `None` uses the setting.
    #[serde(default)]
    pub rate_limit: Option<u32>,
    /// Files larger than this are listed as skipped. Default 64.
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub operation_id: Option<String>,
}

/// What a request scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Path,
    Targets,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Targets => "targets",
        }
    }
}

/// A request that fails its own bounds before any work starts.
pub fn validate_request(request: &TemplateScanRequest) -> Result<ScanMode, String> {
    let has_path = request
        .path
        .as_deref()
        .is_some_and(|path| !path.trim().is_empty());
    let has_targets = request.targets.iter().any(|t| !t.trim().is_empty());
    let mode = match (has_path, has_targets) {
        (true, false) => ScanMode::Path,
        (false, true) => ScanMode::Targets,
        (true, true) => {
            return Err(
                "give either a local path or live targets, not both; they are separate scans"
                    .into(),
            )
        }
        (false, false) => {
            return Err("give a local path or at least one live target to scan".into())
        }
    };
    let mb = request.max_file_size_mb.unwrap_or(DEFAULT_MAX_FILE_SIZE_MB);
    if mb == 0 || mb > MAX_FILE_SIZE_MB_LIMIT {
        return Err(format!(
            "maxFileSizeMb must be between 1 and {MAX_FILE_SIZE_MB_LIMIT} (MiB): each file is read into memory whole, so larger files are listed as skipped instead"
        ));
    }
    for severity in &request.severities {
        let lower = severity.trim().to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "info" | "low" | "medium" | "high" | "critical"
        ) {
            return Err(format!(
                "unknown severity {severity:?}; expected info, low, medium, high or critical"
            ));
        }
    }
    if mode == ScanMode::Targets {
        let authorization = request.authorization.as_ref();
        if !authorization.is_some_and(|a| a.acknowledged) {
            return Err(
                "live-target scanning sends network traffic to the targets you name and requires an explicit authorization: confirm that you are authorized to test them (authorization.acknowledged)"
                    .into(),
            );
        }
        if authorization.is_some_and(|a| a.statement.chars().count() > MAX_STATEMENT_CHARS) {
            return Err(format!(
                "the authorization statement is over {MAX_STATEMENT_CHARS} characters"
            ));
        }
    }
    Ok(mode)
}

/// The scan's file size cap in bytes (request already validated).
pub fn max_file_bytes(request: &TemplateScanRequest) -> u64 {
    u64::from(request.max_file_size_mb.unwrap_or(DEFAULT_MAX_FILE_SIZE_MB)) * 1024 * 1024
}

pub use crate::filewalk::SkippedFile as TemplateSkippedFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplatePackInfo {
    pub id: String,
    pub name: String,
    pub license: String,
    pub content_sha256: String,
    /// Supported templates the pack holds.
    pub template_count: usize,
}

/// A template that was not run, or not run against something, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotEvaluatedRow {
    pub template_id: String,
    pub pack: String,
    /// The template file's path inside its pack.
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Live scans: the target this applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateLineRow {
    pub line: u32,
    pub start_column: u32,
    pub end_column: u32,
    /// The matched line, capped; masked for credential templates.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateClassification {
    pub cve_id: Vec<String>,
    pub cwe_id: Vec<String>,
    pub cvss_score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateMatchRow {
    /// Unique within the run; the paged-results key.
    pub id: String,
    pub template_id: String,
    /// `<pack>/<templateId>`, also the observation's rule id.
    pub rule_id: String,
    pub name: String,
    /// `info`, `low`, `medium`, `high` or `critical`.
    pub severity: String,
    pub tags: Vec<String>,
    pub pack: String,
    /// `file` for local scans; `http`, `dns`, `tcp` or `ssl` for live ones.
    pub protocol: String,
    /// The file path or live endpoint that matched.
    pub matched_at: String,
    /// File matches: path relative to the scan target, forward slashes; the
    /// key the paged index sorts and filters by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub lines: Vec<TemplateLineRow>,
    pub matcher_names: Vec<String>,
    /// Extractor name (empty when unnamed) and its values.
    pub extracted: Vec<(String, Vec<String>)>,
    pub classification: TemplateClassification,
    pub description: String,
    pub reference: Vec<String>,
    pub remediation: String,
    /// Live matches: the bounded, redacted request and response excerpts.
    /// Always `null` for file matches.
    pub exchange: Option<TemplateExchange>,
}

/// What was sent to a live target and an excerpt of what came back. Values
/// of credential-bearing headers are `[REDACTED]`; for templates that report
/// credentials the response body is withheld and matched values are masked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateExchange {
    /// `http`, `dns`, `tcp` or `ssl`.
    pub protocol: String,
    /// The target as the user typed it.
    pub target: String,
    pub request: String,
    pub response_excerpt: String,
    pub response_truncated: bool,
}

/// The authorization a live scan was started with. Recorded per run; never
/// remembered between runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAuthorization {
    pub acknowledged: bool,
    pub statement: String,
    pub acknowledged_at_ms: u64,
}

/// A host name resolved once for a live run and the addresses every
/// connection to it used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedHost {
    pub host: String,
    pub addresses: Vec<String>,
}

/// A live target that could not be resolved or did not answer; its
/// templates were not evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreachableTarget {
    pub target: String,
    pub reason: String,
}

/// The stored and returned result of a Template scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateScanResult {
    pub run_id: String,
    /// `path` or `targets`.
    pub mode: String,
    /// The canonical scanned path, or the targets joined by `, `.
    pub target: String,
    /// `completed` or `incomplete`. A scan that was cancelled or failed
    /// returns an error instead of a result.
    pub state: String,
    pub matches: Vec<TemplateMatchRow>,
    /// Match rows beyond the stored cap; counted, not kept.
    pub matches_dropped: u64,
    pub not_evaluated: Vec<NotEvaluatedRow>,
    pub not_evaluated_dropped: u64,
    pub packs: Vec<TemplatePackInfo>,
    /// Distinct templates loaded from the packs and one-off paths.
    pub templates_loaded: usize,
    /// Templates that were applicable and evaluated.
    pub templates_run: usize,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped: Vec<TemplateSkippedFile>,
    pub requests_sent: u64,
    pub requests_refused: u64,
    /// Live scans: distinct hosts (never full URLs) that a template, redirect
    /// or DNS question tried to reach outside the scope; nothing was sent to
    /// them.
    #[serde(default)]
    pub refused_hosts: Vec<String>,
    /// Live scans: each host name and the addresses pinned for the run.
    #[serde(default)]
    pub resolved: Vec<ResolvedHost>,
    /// Live scans: targets that could not be resolved or reached.
    #[serde(default)]
    pub unreachable_targets: Vec<UnreachableTarget>,
    /// Live scans: the recorded authorization. `null` for local scans.
    pub authorization: Option<RecordedAuthorization>,
    /// Why the run is incomplete, how many templates were not evaluated, and
    /// other limits worth knowing.
    pub notes: Vec<String>,
    /// The subset of `notes` that is why the run is `incomplete`; empty for
    /// a completed run. The rest of `notes` is informational.
    #[serde(default)]
    pub incomplete_reasons: Vec<String>,
    pub duration_ms: u64,
}

/// True when `tags` marks credential-bearing output.
pub fn has_secret_tag(tags: &[String]) -> bool {
    tags.iter().any(|tag| SECRET_TAGS.contains(&tag.as_str()))
}

/// Mask a value that may be a credential: the first four characters (only
/// when the value is long enough that they reveal little) and the length.
/// `AKIAIOSFODNN7EXAMPLE` becomes `AKIA... (20 chars)`.
pub fn mask_value(value: &str) -> String {
    let count = value.chars().count();
    if count > 8 {
        let prefix: String = value.chars().take(4).collect();
        format!("{prefix}\u{2026} ({count} chars)")
    } else {
        format!("\u{2026} ({count} chars)")
    }
}

pub fn severity_label(severity: oxaudit_domain::Severity) -> &'static str {
    use oxaudit_domain::Severity::*;
    match severity {
        Info => "info",
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_keeps_a_short_prefix_only_for_long_values() {
        assert_eq!(
            mask_value("AKIAIOSFODNN7EXAMPLE"),
            "AKIA\u{2026} (20 chars)"
        );
        assert_eq!(mask_value("hunter2"), "\u{2026} (7 chars)");
        assert_eq!(mask_value(""), "\u{2026} (0 chars)");
    }

    #[test]
    fn credential_tags_withhold_output_but_the_common_exposure_tag_does_not() {
        let tags = |list: &[&str]| list.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        for tag in [
            "token",
            "keys",
            "secret",
            "secrets",
            "credentials",
            "creds",
            "password",
            "api-key",
            "apikey",
            "private-key",
        ] {
            assert!(has_secret_tag(&tags(&["misc", tag])), "{tag}");
        }
        assert!(!has_secret_tag(&tags(&["exposure", "config", "panel"])));
        assert!(!has_secret_tag(&[]));
    }

    #[test]
    fn exactly_one_of_path_and_targets_is_required() {
        let mut request = TemplateScanRequest::default();
        assert!(validate_request(&request)
            .unwrap_err()
            .contains("local path"));
        request.path = Some("/tmp/x".into());
        assert_eq!(validate_request(&request).unwrap(), ScanMode::Path);
        request.targets = vec!["https://example.test".into()];
        assert!(validate_request(&request).unwrap_err().contains("not both"));
        request.path = None;
        assert!(validate_request(&request)
            .unwrap_err()
            .contains("requires an explicit authorization"));
        request.authorization = Some(TemplateAuthorization {
            acknowledged: true,
            statement: "my own lab".into(),
        });
        assert_eq!(validate_request(&request).unwrap(), ScanMode::Targets);
        request.max_file_size_mb = Some(0);
        assert!(validate_request(&request)
            .unwrap_err()
            .contains("maxFileSizeMb"));
        request.max_file_size_mb = None;
        request.severities = vec!["urgent".into()];
        assert!(validate_request(&request).unwrap_err().contains("severity"));
    }
}

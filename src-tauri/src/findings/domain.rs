use serde::{Deserialize, Serialize};

pub const FINGERPRINT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FindingScope {
    Production,
    Infrastructure,
    Test,
    Fixture,
    Generated,
    Vendored,
    Documentation,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReviewState {
    Candidate,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Suppressed,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DiffStatus {
    New,
    Unchanged,
    Resolved,
    NotEvaluated,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RunStatus {
    Running,
    Completed,
    Incomplete,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReviewOrigin {
    Local,
    ProjectPolicy,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecord {
    pub id: String,
    pub project_id: String,
    pub fingerprint_version: u16,
    pub fingerprint: String,
    pub state: ReviewState,
    pub reason: String,
    pub evidence: Option<String>,
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gates: Vec<crate::triage::gates::GateNote>,
    pub deciding_gate: Option<crate::triage::gates::Gate>,
    pub expires_at: Option<String>,
    pub origin: ReviewOrigin,
    pub policy_hash: Option<String>,
    pub updated_at: String,
    pub superseded_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PolicyStatus {
    Missing,
    Valid { hash: String },
    Invalid { message: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RunPersistence {
    Saved,
    NotSaved { retry_token: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_completed_runs_per_project: u32,
    pub max_age_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_completed_runs_per_project: 20,
            max_age_days: 90,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunDetail {
    pub project_id: String,
    pub run_id: String,
    pub baseline_run_id: Option<String>,
    pub status: RunStatus,
    pub persistence: RunPersistence,
    pub policy: PolicyStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub summary: crate::models::ScanSummary,
    pub findings: Vec<crate::models::Finding>,
    pub maintenance_warning: Option<String>,
}

/// Saved run context without a findings collection. Never a partial full report.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SourceRunMetadata {
    pub project_id: String,
    pub run_id: String,
    pub baseline_run_id: Option<String>,
    pub status: RunStatus,
    pub persistence: RunPersistence,
    pub policy: PolicyStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub summary: crate::models::ScanSummary,
    pub maintenance_warning: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
pub struct ResultPageQuery {
    pub offset: u32,
    pub limit: u32,
    pub search: String,
    pub severity: Option<String>,
    pub minimum_severity: Option<String>,
    pub sort: String,
}

impl Default for ResultPageQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
            search: String::new(),
            severity: None,
            minimum_severity: None,
            sort: "original".into(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResultPage<T> {
    pub items: Vec<T>,
    pub offset: u32,
    pub limit: u32,
    pub filtered_total: usize,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
pub struct SourceFindingsQuery {
    #[serde(flatten, deserialize_with = "deserialize_source_page")]
    pub page: ResultPageQuery,
    pub view: String,
    pub new_only: bool,
    pub category: String,
    pub scope: String,
    pub language: String,
    pub baseline_run_id: Option<String>,
    pub file_paths: Option<Vec<String>>,
    pub require_valid_policy: bool,
}

fn deserialize_source_page<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ResultPageQuery, D::Error> {
    let mut fields = serde_json::Value::deserialize(deserializer)?;
    if let Some(object) = fields.as_object_mut() {
        object
            .entry("sort")
            .or_insert_with(|| serde_json::Value::String("severity".into()));
    }
    serde_json::from_value(fields).map_err(serde::de::Error::custom)
}

impl Default for SourceFindingsQuery {
    fn default() -> Self {
        Self {
            page: ResultPageQuery {
                sort: "severity".into(),
                ..Default::default()
            },
            view: "all".into(),
            new_only: false,
            category: "all".into(),
            scope: "all".into(),
            language: "all".into(),
            baseline_run_id: None,
            file_paths: None,
            require_valid_policy: false,
        }
    }
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingViewCounts {
    pub open: usize,
    pub other_scopes: usize,
    pub closed: usize,
    pub resolved: usize,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingDiffCounts {
    pub new: usize,
    pub unchanged: usize,
    pub resolved: usize,
    pub not_evaluated: usize,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SourceFindingsPage {
    #[serde(flatten)]
    pub page: ResultPage<crate::models::Finding>,
    pub view_counts: FindingViewCounts,
    pub diff_counts: FindingDiffCounts,
    pub languages: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalProjectionMetadata {
    pub kind: &'static str,
    pub projection_kind: String,
    pub projection: serde_json::Value,
    pub sections: std::collections::BTreeMap<String, usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectContext {
    pub project_id: String,
    pub canonical_path: String,
    pub display_name: String,
    pub policy: PolicyStatus,
    pub last_completed_run_id: Option<String>,
    pub last_options: Option<crate::models::ScanOptions>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecentProject {
    pub project_id: String,
    pub canonical_path: String,
    pub display_name: String,
    pub last_opened_at: String,
    pub last_completed_run_id: Option<String>,
    pub last_completed_at: Option<String>,
    /// None is legacy metadata; false means numeric totals are not authoritative.
    #[serde(default)]
    pub counts_available: Option<bool>,
    pub open_findings: usize,
    pub critical: usize,
    pub high: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunSummary {
    pub run_id: String,
    pub project_id: String,
    pub status: RunStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_findings: usize,
    pub new_findings: usize,
    pub resolved_findings: usize,
    /// The run's findings by severity, so a caller can draw the trend over
    /// time without loading payloads. Zeroed for runs that never completed.
    #[serde(default)]
    pub severity_counts: SeverityCounts,
}

/// One run's findings split across the five severity levels. Unknown
/// severity strings are ignored rather than guessed into a bucket.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    pub fn record(&mut self, severity: &str) {
        match severity {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRequest {
    pub project_id: String,
    pub fingerprint_version: u16,
    pub fingerprint: String,
    pub category: String,
    pub state: ReviewState,
    pub reason: String,
    pub evidence: Option<String>,
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gates: Vec<crate::triage::gates::GateNote>,
    pub deciding_gate: Option<crate::triage::gates::Gate>,
    pub expires_at: Option<String>,
    pub origin: ReviewOrigin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_enums_use_stable_camel_case_values() {
        assert_eq!(
            serde_json::to_string(&FindingScope::Infrastructure).unwrap(),
            "\"infrastructure\""
        );
        assert_eq!(
            serde_json::to_string(&ReviewState::FalsePositive).unwrap(),
            "\"falsePositive\""
        );
        assert_eq!(
            serde_json::to_string(&DiffStatus::NotEvaluated).unwrap(),
            "\"notEvaluated\""
        );
        assert_eq!(
            serde_json::to_string(&RunStatus::Incomplete).unwrap(),
            "\"incomplete\""
        );
        assert_eq!(
            serde_json::to_value(RunPersistence::NotSaved {
                retry_token: "retry-1".into()
            })
            .unwrap(),
            serde_json::json!({"status": "notSaved", "retryToken": "retry-1"}),
        );
    }

    #[test]
    fn paged_queries_keep_source_and_canonical_default_sort_contracts() {
        let canonical: ResultPageQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(canonical.sort, "original");
        let source: SourceFindingsQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(source.page.sort, "severity");
        let source: SourceFindingsQuery =
            serde_json::from_value(serde_json::json!({"sort":"original","limit":20})).unwrap();
        assert_eq!(source.page.sort, "original");
        assert_eq!(source.page.limit, 20);
        assert_eq!(source.view, "all");
    }
}

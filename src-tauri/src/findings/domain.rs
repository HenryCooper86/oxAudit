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
}

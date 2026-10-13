//! Inventory read models shared by storage and transport adapters.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryIdentityView {
    pub method: String,
    pub value: String,
    pub confidence: f32,
    pub artifact_id: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryComponentView {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub supplier: Option<String>,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
    pub cpes: Vec<String>,
    pub aliases: Vec<String>,
    pub identities: Vec<InventoryIdentityView>,
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryView {
    pub run_id: String,
    pub target_label: String,
    pub run_kind: oxaudit_domain::RunKind,
    pub updated_at_ms: u64,
    pub provider_snapshot_count: usize,
    pub components: Vec<InventoryComponentView>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryPage {
    #[serde(flatten)]
    pub page: super::domain::ResultPage<InventoryComponentView>,
    pub run_id: String,
    pub target_label: String,
    pub run_kind: oxaudit_domain::RunKind,
    pub updated_at_ms: u64,
    pub provider_snapshot_count: usize,
}

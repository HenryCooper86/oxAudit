use std::future::Future;
use std::pin::Pin;

use oxaudit_domain::{
    Artifact, CapabilityDescriptor, Component, EvidenceRecord, Finding, Observation, Provenance,
    ProviderSnapshotId, RulePackId, Run, RunId, Verification,
};
use serde::{Deserialize, Serialize};

use crate::{EventEnvelope, ManifestSnapshot};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct DetectionInput {
    pub run_id: RunId,
    pub artifact: Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionSummary {
    pub artifact_id: String,
    pub detector_id: String,
    pub candidate_manifest: Option<ManifestSnapshot>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservationRecord {
    pub observation: Observation,
    pub evidence: Vec<EvidenceRecord>,
}

pub trait ObservationSink {
    fn emit(&mut self, record: ObservationRecord) -> Result<(), String>;
}

pub trait Detector: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn supports(&self, artifact: &Artifact) -> bool;
    fn detect(
        &self,
        input: DetectionInput,
        sink: &mut dyn ObservationSink,
    ) -> Result<DetectionSummary, String>;
}

pub trait RunRepository: Send + Sync {
    fn create_run(&self, run: &Run) -> Result<(), String>;
    fn save_run(&self, run: &Run) -> Result<(), String>;
    fn append_artifact(&self, run_id: &RunId, artifact: &Artifact) -> Result<(), String>;
    fn append_components(&self, run_id: &RunId, components: &[Component]) -> Result<(), String>;
    fn append_observations(
        &self,
        run_id: &RunId,
        observations: &[ObservationRecord],
    ) -> Result<(), String>;
    fn load_run(&self, run_id: &RunId) -> Result<Option<Run>, String>;
}

pub trait RunEventSink: Send + Sync {
    fn publish(&self, event: &EventEnvelope) -> Result<(), String>;
}

pub trait Cancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

pub struct NoCancellation;

impl Cancellation for NoCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRequest {
    pub offline: bool,
    pub maximum_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSnapshot {
    pub id: ProviderSnapshotId,
    pub provider_id: String,
    pub provider_version: String,
    pub fetched_at_ms: u64,
    pub content_sha256: String,
    pub provenance: Provenance,
    pub offline_usable: bool,
    pub record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryMatch {
    pub advisory_id: String,
    pub component_id: String,
    pub affected: bool,
    pub rationale: String,
}

pub trait AdvisoryProvider: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn snapshot<'a>(
        &'a self,
        request: SnapshotRequest,
    ) -> PortFuture<'a, Result<ProviderSnapshot, String>>;
    fn query<'a>(
        &'a self,
        snapshot: &'a ProviderSnapshot,
        component: &'a Component,
    ) -> PortFuture<'a, Result<Vec<AdvisoryMatch>, String>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePackRecord {
    pub id: RulePackId,
    pub version: String,
    pub name: String,
    pub engine_compatibility: Vec<String>,
    pub enabled: bool,
    pub content_sha256: String,
    pub provenance: Provenance,
    pub fixture_passes: u64,
    pub fixture_failures: u64,
}

pub trait RulePackStore: Send + Sync {
    fn list(&self) -> Result<Vec<RulePackRecord>, String>;
    fn enabled_snapshot(&self) -> Result<Vec<RulePackRecord>, String>;
    fn set_enabled(&self, id: &RulePackId, enabled: bool) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct ReportInput {
    pub run: Run,
    pub findings: Vec<Finding>,
    pub components: Vec<Component>,
    pub observations: Vec<ObservationRecord>,
}

pub trait ReportWriter: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn media_type(&self) -> &'static str;
    fn file_extension(&self) -> &'static str;
    fn write(&self, input: &ReportInput) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone)]
pub struct VerificationInput {
    pub finding: Finding,
    pub producer_id: String,
    pub immutable_input_sha256: String,
    pub evidence: Vec<EvidenceRecord>,
}

pub trait Verifier: Send + Sync {
    fn descriptor(&self) -> CapabilityDescriptor;
    fn verify<'a>(
        &'a self,
        input: VerificationInput,
    ) -> PortFuture<'a, Result<Verification, String>>;
}

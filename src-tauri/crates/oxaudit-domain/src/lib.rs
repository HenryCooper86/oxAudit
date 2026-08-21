//! Canonical, presentation-independent security audit records.
//!
//! This crate intentionally has no filesystem, database, network, desktop, or
//! scanner dependencies. Adapters may depend on the domain; the domain never
//! depends on adapters.

mod artifact;
mod capability;
mod component;
mod error;
mod evidence;
mod finding;
mod id;
mod observation;
mod provenance;
mod review;
mod run;
mod verification;

pub use artifact::{Artifact, ArtifactKind, ArtifactLocation};
pub use capability::{CapabilityAvailability, CapabilityDescriptor, CapabilityKind};
pub use component::{Component, ComponentIdentity, IdentityMethod};
pub use error::DomainError;
pub use evidence::{
    AdvisoryMatchEvidence, BinaryMatchEvidence, DataFlowEdge, DataFlowEvidence, DataFlowNode,
    Evidence, EvidenceRecord, FileLocationEvidence, GateDecisionEvidence,
    PackageDeclarationEvidence, RedactedSecretEvidence, RedactedValue, ToolReceiptEvidence,
};
pub use finding::{Finding, FindingState, Severity};
pub use id::{
    ArtifactId, ComponentId, EvidenceId, FindingId, ObservationId, ProviderSnapshotId, RulePackId,
    RunId, VerificationId,
};
pub use observation::{Observation, ObservationKind};
pub use provenance::{CreationMethod, Provenance};
pub use review::{Review, ReviewDisposition, ReviewOrigin};
pub use run::{Run, RunKind, RunState, RunWarning};
pub use verification::{Verification, VerificationResult, VerifierIdentity};

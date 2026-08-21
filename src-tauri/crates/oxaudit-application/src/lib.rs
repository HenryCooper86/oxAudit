//! GUI-neutral application use cases and inward-facing ports.

mod coordinator;
mod error;
mod events;
mod lifecycle;
mod manifest;
mod ports;

pub use coordinator::{RunCoordinator, RunOutcome, RunRequest};
pub use error::ApplicationError;
pub use events::{EventEnvelope, EventKind, EventSequencer, RunEvent};
pub use lifecycle::ManagedRun;
pub use manifest::{ManifestError, ManifestReport, ManifestSnapshot, StageManifest};
pub use ports::{
    AdvisoryMatch, AdvisoryProvider, Cancellation, DetectionInput, DetectionSummary, Detector,
    NoCancellation, ObservationRecord, ObservationSink, PortFuture, ProviderSnapshot, ReportInput,
    ReportWriter, RulePackRecord, RulePackStore, RunEventSink, RunRepository, SnapshotRequest,
    VerificationInput, Verifier,
};

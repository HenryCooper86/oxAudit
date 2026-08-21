mod binary;
mod dependency;
mod source;

pub type ScanGraph = (
    Vec<oxaudit_domain::Artifact>,
    Vec<oxaudit_domain::Component>,
    Vec<oxaudit_application::ObservationRecord>,
);

pub use binary::{binary_graph, binary_provider_snapshot_id};
pub use dependency::{dependency_graph, lockfile_artifact};
pub use source::{source_artifact, source_observation};

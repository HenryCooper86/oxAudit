use oxaudit_application::{ObservationRecord, RunRepository};
use oxaudit_domain::{Artifact, Component, Run, RunId};

use crate::findings::repository::FindingsRepository;

/// Canonical graph persistence backed by the same protected SQLite database as
/// the established Source Results repository. Keeping this as an adapter lets
/// the legacy DTO tables coexist during migration without leaking rusqlite into
/// the application crate.
pub struct CanonicalSqliteRepository<'a> {
    repository: &'a FindingsRepository,
}

impl<'a> CanonicalSqliteRepository<'a> {
    pub fn new(repository: &'a FindingsRepository) -> Self {
        Self { repository }
    }
}

impl RunRepository for CanonicalSqliteRepository<'_> {
    fn create_run(&self, run: &Run) -> Result<(), String> {
        self.repository
            .canonical_create_run(run)
            .map_err(|error| error.to_string())
    }

    fn save_run(&self, run: &Run) -> Result<(), String> {
        self.repository
            .canonical_save_run(run)
            .map_err(|error| error.to_string())
    }

    fn append_artifact(&self, run_id: &RunId, artifact: &Artifact) -> Result<(), String> {
        self.repository
            .canonical_append_artifact(run_id, artifact)
            .map_err(|error| error.to_string())
    }

    fn append_components(&self, run_id: &RunId, components: &[Component]) -> Result<(), String> {
        self.repository
            .canonical_append_components(run_id, components)
            .map_err(|error| error.to_string())
    }

    fn append_observations(
        &self,
        run_id: &RunId,
        observations: &[ObservationRecord],
    ) -> Result<(), String> {
        self.repository
            .canonical_append_observations(run_id, observations)
            .map_err(|error| error.to_string())
    }

    fn load_run(&self, run_id: &RunId) -> Result<Option<Run>, String> {
        self.repository
            .canonical_load_run(run_id)
            .map_err(|error| error.to_string())
    }
}

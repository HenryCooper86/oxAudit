use oxaudit_domain::{Artifact, Component, ProviderSnapshotId, Run, RunState, RunWarning};

use crate::{
    ApplicationError, EventSequencer, ObservationRecord, RunEvent, RunEventSink, RunOutcome,
    RunRepository,
};

/// A durable lifecycle handle for adapters that already own bounded work
/// scheduling (for example the established parallel source scanner). It keeps
/// orchestration and persistence in the application layer while allowing a
/// staged migration into [`crate::RunCoordinator::execute`].
pub struct ManagedRun<'a> {
    repository: &'a dyn RunRepository,
    events: &'a dyn RunEventSink,
    run: Run,
    sequencer: EventSequencer,
    persistence_attempts: usize,
    event_delivery_failures: usize,
    observations: Vec<ObservationRecord>,
}

impl<'a> ManagedRun<'a> {
    pub(crate) fn begin(
        repository: &'a dyn RunRepository,
        events: &'a dyn RunEventSink,
        run: Run,
        persistence_attempts: usize,
    ) -> Result<Self, ApplicationError> {
        persist(persistence_attempts, || repository.create_run(&run))?;
        let mut managed = Self {
            repository,
            events,
            sequencer: EventSequencer::new(run.id.clone()),
            run,
            persistence_attempts,
            event_delivery_failures: 0,
            observations: Vec::new(),
        };
        managed.publish(RunEvent::RunStarted);
        Ok(managed)
    }

    pub fn run(&self) -> &Run {
        &self.run
    }

    pub fn transition(&mut self, state: RunState, now_ms: u64) -> Result<(), ApplicationError> {
        self.run.transition(state, now_ms)?;
        self.persist_run()?;
        let event = if state.is_terminal() {
            RunEvent::RunTerminal { state }
        } else {
            RunEvent::StageChanged { state }
        };
        self.publish(event);
        Ok(())
    }

    pub fn append_artifact(&mut self, artifact: &Artifact) -> Result<(), ApplicationError> {
        persist(self.persistence_attempts, || {
            self.repository.append_artifact(&self.run.id, artifact)
        })?;
        self.publish(RunEvent::ArtifactDiscovered {
            artifact_id: artifact.id.clone(),
        });
        Ok(())
    }

    pub fn append_observations(
        &mut self,
        observations: Vec<ObservationRecord>,
    ) -> Result<(), ApplicationError> {
        persist(self.persistence_attempts, || {
            self.repository
                .append_observations(&self.run.id, &observations)
        })?;
        for observation in &observations {
            self.publish(RunEvent::ObservationEmitted {
                observation_id: observation.observation.id.clone(),
            });
        }
        self.observations.extend(observations);
        Ok(())
    }

    pub fn append_components(&mut self, components: &[Component]) -> Result<(), ApplicationError> {
        persist(self.persistence_attempts, || {
            self.repository.append_components(&self.run.id, components)
        })
    }

    pub fn record_provider_snapshot(
        &mut self,
        snapshot_id: ProviderSnapshotId,
    ) -> Result<(), ApplicationError> {
        if !self.run.provider_snapshot_ids.contains(&snapshot_id) {
            self.run.provider_snapshot_ids.push(snapshot_id);
            self.persist_run()?;
        }
        Ok(())
    }

    pub fn warning(&mut self, code: impl Into<String>, message: impl Into<String>) {
        let warning = RunWarning {
            code: code.into(),
            message: message.into(),
        };
        self.publish(RunEvent::Warning {
            code: warning.code.clone(),
            message: warning.message.clone(),
        });
        self.run.warnings.push(warning);
    }

    pub fn complete(mut self, now_ms: u64) -> Result<RunOutcome, ApplicationError> {
        self.transition(RunState::Completed, now_ms)?;
        self.persist_run()?;
        Ok(self.outcome())
    }

    pub fn terminate(
        mut self,
        state: RunState,
        now_ms: u64,
    ) -> Result<RunOutcome, ApplicationError> {
        if state == RunState::Cancelled && self.run.state != RunState::Cancelling {
            self.transition(RunState::Cancelling, now_ms)?;
        }
        self.transition(state, now_ms)?;
        self.persist_run()?;
        Ok(self.outcome())
    }

    /// Persist current non-terminal state for an existing retry/recovery path.
    pub fn checkpoint(self) -> Result<RunOutcome, ApplicationError> {
        self.persist_run()?;
        Ok(self.outcome())
    }

    fn persist_run(&self) -> Result<(), ApplicationError> {
        persist(self.persistence_attempts, || {
            self.repository.save_run(&self.run)
        })
    }

    fn publish(&mut self, event: RunEvent) {
        let envelope = self.sequencer.envelope(self.run.updated_at_ms, event);
        if let Err(message) = self.events.publish(&envelope) {
            self.event_delivery_failures += 1;
            self.run.warnings.push(RunWarning {
                code: "event_delivery_failed".into(),
                message,
            });
        }
    }

    fn outcome(self) -> RunOutcome {
        RunOutcome {
            run: self.run,
            observations: self.observations,
            event_delivery_failures: self.event_delivery_failures,
        }
    }
}

impl<'a> crate::RunCoordinator<'a> {
    pub fn begin(&self, run: Run) -> Result<ManagedRun<'a>, ApplicationError> {
        ManagedRun::begin(
            self.repository(),
            self.event_sink(),
            run,
            self.persistence_attempts(),
        )
    }
}

fn persist<F>(attempts: usize, operation: F) -> Result<(), ApplicationError>
where
    F: Fn() -> Result<(), String>,
{
    let mut last_error = None;
    for _ in 0..attempts.max(1) {
        match operation() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(ApplicationError::Repository(
        last_error.unwrap_or_else(|| "unknown persistence failure".into()),
    ))
}

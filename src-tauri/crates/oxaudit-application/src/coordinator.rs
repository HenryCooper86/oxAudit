use std::time::{SystemTime, UNIX_EPOCH};

use oxaudit_domain::{Artifact, Run, RunState, RunWarning};

use crate::{
    ApplicationError, Cancellation, DetectionInput, Detector, EventSequencer, ObservationRecord,
    ObservationSink, RunEvent, RunEventSink, RunRepository, StageManifest,
};

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub run: Run,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub run: Run,
    pub observations: Vec<ObservationRecord>,
    pub event_delivery_failures: usize,
}

pub struct RunCoordinator<'a> {
    repository: &'a dyn RunRepository,
    events: &'a dyn RunEventSink,
    persistence_attempts: usize,
}

impl<'a> RunCoordinator<'a> {
    pub fn new(repository: &'a dyn RunRepository, events: &'a dyn RunEventSink) -> Self {
        Self {
            repository,
            events,
            persistence_attempts: 2,
        }
    }

    pub fn with_persistence_attempts(mut self, attempts: usize) -> Self {
        self.persistence_attempts = attempts.max(1);
        self
    }

    pub(crate) fn repository(&self) -> &'a dyn RunRepository {
        self.repository
    }

    pub(crate) fn event_sink(&self) -> &'a dyn RunEventSink {
        self.events
    }

    pub(crate) fn persistence_attempts(&self) -> usize {
        self.persistence_attempts
    }

    pub fn execute(
        &self,
        request: RunRequest,
        detectors: &[&dyn Detector],
        cancellation: &dyn Cancellation,
    ) -> Result<RunOutcome, ApplicationError> {
        let mut run = request.run;
        self.persist(|| self.repository.create_run(&run))?;
        let mut sequencer = EventSequencer::new(run.id.clone());
        let mut event_failures = 0usize;
        self.publish(
            &mut run,
            &mut sequencer,
            RunEvent::RunStarted,
            &mut event_failures,
        );

        self.transition(
            &mut run,
            RunState::Discovering,
            &mut sequencer,
            &mut event_failures,
        )?;
        for artifact in &request.artifacts {
            if cancellation.is_cancelled() {
                return self.cancel(run, sequencer, event_failures);
            }
            self.persist(|| self.repository.append_artifact(&run.id, artifact))?;
            self.publish(
                &mut run,
                &mut sequencer,
                RunEvent::ArtifactDiscovered {
                    artifact_id: artifact.id.clone(),
                },
                &mut event_failures,
            );
        }

        self.transition(
            &mut run,
            RunState::Detecting,
            &mut sequencer,
            &mut event_failures,
        )?;

        let expected: Vec<String> = request
            .artifacts
            .iter()
            .flat_map(|artifact| {
                detectors
                    .iter()
                    .filter(move |detector| detector.supports(artifact))
                    .map(move |detector| format!("{}\0{}", artifact.id, detector.descriptor().id))
            })
            .collect();
        if expected.is_empty() && !request.artifacts.is_empty() {
            self.fail_run(
                &mut run,
                RunState::Incomplete,
                &mut sequencer,
                &mut event_failures,
            )?;
            return Err(ApplicationError::UnsupportedArtifact(
                request.artifacts[0].id.to_string(),
            ));
        }
        let mut accounting = StageManifest::new("detect", expected)?;
        let mut sink = VecObservationSink::default();

        for artifact in request.artifacts {
            for detector in detectors {
                if !detector.supports(&artifact) {
                    continue;
                }
                if cancellation.is_cancelled() {
                    return self.cancel(run, sequencer, event_failures);
                }
                let descriptor = detector.descriptor();
                if !run.engine_ids.contains(&descriptor.id) {
                    run.engine_ids.push(descriptor.id.clone());
                }
                let summary = match detector.detect(
                    DetectionInput {
                        run_id: run.id.clone(),
                        artifact: artifact.clone(),
                    },
                    &mut sink,
                ) {
                    Ok(summary) => summary,
                    Err(message) => {
                        self.fail_run(
                            &mut run,
                            RunState::Failed,
                            &mut sequencer,
                            &mut event_failures,
                        )?;
                        return Err(ApplicationError::Detector {
                            detector_id: descriptor.id,
                            message,
                        });
                    }
                };
                if let Some(candidate_manifest) = summary.candidate_manifest {
                    if let Err(error) = candidate_manifest.validate() {
                        self.fail_run(
                            &mut run,
                            RunState::Incomplete,
                            &mut sequencer,
                            &mut event_failures,
                        )?;
                        return Err(error.into());
                    }
                }
                accounting.record(format!("{}\0{}", summary.artifact_id, summary.detector_id));
                for warning in summary.warnings {
                    run.warnings.push(RunWarning {
                        code: "detector_warning".into(),
                        message: warning,
                    });
                }
            }
        }
        if let Err(error) = accounting.reconcile() {
            self.fail_run(
                &mut run,
                RunState::Incomplete,
                &mut sequencer,
                &mut event_failures,
            )?;
            return Err(error.into());
        }

        self.transition(
            &mut run,
            RunState::Normalizing,
            &mut sequencer,
            &mut event_failures,
        )?;
        self.transition(
            &mut run,
            RunState::Assessing,
            &mut sequencer,
            &mut event_failures,
        )?;
        self.transition(
            &mut run,
            RunState::Persisting,
            &mut sequencer,
            &mut event_failures,
        )?;
        self.persist(|| self.repository.append_observations(&run.id, &sink.records))?;
        for record in &sink.records {
            self.publish(
                &mut run,
                &mut sequencer,
                RunEvent::ObservationEmitted {
                    observation_id: record.observation.id.clone(),
                },
                &mut event_failures,
            );
        }
        self.transition(
            &mut run,
            RunState::Completed,
            &mut sequencer,
            &mut event_failures,
        )?;
        self.persist(|| self.repository.save_run(&run))?;

        Ok(RunOutcome {
            run,
            observations: sink.records,
            event_delivery_failures: event_failures,
        })
    }

    fn transition(
        &self,
        run: &mut Run,
        state: RunState,
        sequencer: &mut EventSequencer,
        event_failures: &mut usize,
    ) -> Result<(), ApplicationError> {
        run.transition(state, now_ms())?;
        self.persist(|| self.repository.save_run(run))?;
        let event = if state.is_terminal() {
            RunEvent::RunTerminal { state }
        } else {
            RunEvent::StageChanged { state }
        };
        self.publish(run, sequencer, event, event_failures);
        Ok(())
    }

    fn fail_run(
        &self,
        run: &mut Run,
        state: RunState,
        sequencer: &mut EventSequencer,
        event_failures: &mut usize,
    ) -> Result<(), ApplicationError> {
        run.transition(state, now_ms())?;
        self.persist(|| self.repository.save_run(run))?;
        self.publish(
            run,
            sequencer,
            RunEvent::RunTerminal { state },
            event_failures,
        );
        Ok(())
    }

    fn cancel(
        &self,
        mut run: Run,
        mut sequencer: EventSequencer,
        mut event_failures: usize,
    ) -> Result<RunOutcome, ApplicationError> {
        self.transition(
            &mut run,
            RunState::Cancelling,
            &mut sequencer,
            &mut event_failures,
        )?;
        self.transition(
            &mut run,
            RunState::Cancelled,
            &mut sequencer,
            &mut event_failures,
        )?;
        Ok(RunOutcome {
            run,
            observations: Vec::new(),
            event_delivery_failures: event_failures,
        })
    }

    fn publish(
        &self,
        run: &mut Run,
        sequencer: &mut EventSequencer,
        event: RunEvent,
        event_failures: &mut usize,
    ) {
        let envelope = sequencer.envelope(now_ms(), event);
        if let Err(message) = self.events.publish(&envelope) {
            *event_failures += 1;
            run.warnings.push(RunWarning {
                code: "event_delivery_failed".into(),
                message,
            });
        }
    }

    fn persist<F>(&self, operation: F) -> Result<(), ApplicationError>
    where
        F: Fn() -> Result<(), String>,
    {
        let mut last_error = None;
        for _ in 0..self.persistence_attempts {
            match operation() {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(ApplicationError::Repository(
            last_error.unwrap_or_else(|| "unknown persistence failure".into()),
        ))
    }
}

#[derive(Default)]
struct VecObservationSink {
    records: Vec<ObservationRecord>,
}

impl ObservationSink for VecObservationSink {
    fn emit(&mut self, record: ObservationRecord) -> Result<(), String> {
        self.records.push(record);
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

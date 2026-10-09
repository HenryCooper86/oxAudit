use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use oxaudit_application::{
    ApplicationError, Cancellation, DetectionInput, DetectionSummary, Detector, EventEnvelope,
    NoCancellation, ObservationRecord, ObservationSink, RunCoordinator, RunEventSink,
    RunRepository, RunRequest,
};
use oxaudit_domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactLocation, CapabilityAvailability,
    CapabilityDescriptor, CapabilityKind, CreationMethod, Observation, ObservationId,
    ObservationKind, Provenance, Run, RunId, RunKind, RunState,
};

#[derive(Default)]
struct MemoryRepository {
    run: Mutex<Option<Run>>,
    artifacts: Mutex<Vec<Artifact>>,
    observations: Mutex<Vec<ObservationRecord>>,
    save_failures_remaining: AtomicUsize,
    commit_then_error: AtomicBool,
}

impl RunRepository for MemoryRepository {
    fn create_run(&self, run: &Run) -> Result<(), String> {
        *self.run.lock().unwrap() = Some(run.clone());
        Ok(())
    }

    fn save_run(&self, run: &Run) -> Result<(), String> {
        if self.commit_then_error.load(Ordering::SeqCst) {
            *self.run.lock().unwrap() = Some(run.clone());
            return Err("write committed before response failure".into());
        }
        if self
            .save_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            })
            .is_ok()
        {
            return Err("transient write failure".into());
        }
        *self.run.lock().unwrap() = Some(run.clone());
        Ok(())
    }

    fn append_artifact(&self, _run_id: &RunId, artifact: &Artifact) -> Result<(), String> {
        self.artifacts.lock().unwrap().push(artifact.clone());
        Ok(())
    }

    fn append_components(
        &self,
        _run_id: &RunId,
        _components: &[oxaudit_domain::Component],
    ) -> Result<(), String> {
        Ok(())
    }

    fn append_observations(
        &self,
        _run_id: &RunId,
        observations: &[ObservationRecord],
    ) -> Result<(), String> {
        self.observations
            .lock()
            .unwrap()
            .extend_from_slice(observations);
        Ok(())
    }

    fn load_run(&self, _run_id: &RunId) -> Result<Option<Run>, String> {
        Ok(self.run.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct MemoryEvents {
    events: Mutex<Vec<EventEnvelope>>,
    fail: AtomicBool,
}

#[test]
fn managed_transition_failure_keeps_the_last_durable_state_recoverable() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let coordinator = RunCoordinator::new(&repository, &events);
    let mut run = coordinator
        .begin(Run::queued(RunKind::Image, "fixture", 1))
        .unwrap();
    repository
        .save_failures_remaining
        .store(2, Ordering::SeqCst);
    assert!(run.transition(RunState::Discovering, 2).is_err());
    assert_eq!(run.run().state, RunState::Queued);
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Queued
    );
    assert!(!events.events.lock().unwrap().iter().any(|event| matches!(
        event.event,
        oxaudit_application::RunEvent::StageChanged {
            state: RunState::Discovering
        }
    )));
    let failed = run.terminate(RunState::Failed, 3).unwrap();
    assert_eq!(failed.run.state, RunState::Failed);
}

#[test]
fn failed_completion_retains_the_handle_and_never_emits_success() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let coordinator = RunCoordinator::new(&repository, &events);
    let mut run = coordinator
        .begin(Run::queued(RunKind::Image, "fixture", 1))
        .unwrap();
    for state in [
        RunState::Discovering,
        RunState::Detecting,
        RunState::Normalizing,
        RunState::Assessing,
        RunState::Persisting,
    ] {
        run.transition(state, 2).unwrap();
    }
    repository
        .save_failures_remaining
        .store(2, Ordering::SeqCst);
    assert!(run.complete_in_place(3).is_err());
    assert_eq!(run.run().state, RunState::Persisting);
    assert!(!events.events.lock().unwrap().iter().any(|event| matches!(
        event.event,
        oxaudit_application::RunEvent::RunTerminal {
            state: RunState::Completed
        }
    )));
    run.terminate(RunState::Failed, 4).unwrap();
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Failed
    );
}

#[test]
fn abandoned_managed_run_records_failure_but_checkpoint_preserves_recovery() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    {
        let coordinator = RunCoordinator::new(&repository, &events);
        let mut run = coordinator
            .begin(Run::queued(RunKind::Image, "abandoned", 1))
            .unwrap();
        run.transition(RunState::Discovering, 2).unwrap();
    }
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Failed
    );
    let coordinator = RunCoordinator::new(&repository, &events);
    let run = coordinator
        .begin(Run::queued(RunKind::Source, "retry", 3))
        .unwrap();
    run.checkpoint().unwrap();
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Queued
    );
}

#[test]
fn managed_transition_uses_committed_state_after_an_adapter_response_error() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let coordinator = RunCoordinator::new(&repository, &events);
    let mut run = coordinator
        .begin(Run::queued(RunKind::Image, "fixture", 1))
        .unwrap();
    repository.commit_then_error.store(true, Ordering::SeqCst);
    run.transition(RunState::Discovering, 2).unwrap();
    assert_eq!(run.run().state, RunState::Discovering);
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Discovering
    );
    assert_eq!(
        events
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(
                event.event,
                oxaudit_application::RunEvent::StageChanged {
                    state: RunState::Discovering
                }
            ))
            .count(),
        1
    );
}

#[test]
fn failed_checkpoint_keeps_a_nonterminal_receipt_available_for_retry() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let coordinator = RunCoordinator::new(&repository, &events);
    let mut run = coordinator
        .begin(Run::queued(RunKind::Source, "retry", 1))
        .unwrap();
    for state in [
        RunState::Discovering,
        RunState::Detecting,
        RunState::Normalizing,
        RunState::Assessing,
        RunState::Persisting,
    ] {
        run.transition(state, 2).unwrap();
    }
    repository
        .save_failures_remaining
        .store(2, Ordering::SeqCst);
    assert!(run.checkpoint().is_err());
    let stored = repository.run.lock().unwrap().clone().unwrap();
    assert_eq!(stored.state, RunState::Persisting);
    let mut completed = stored;
    completed.transition(RunState::Completed, 3).unwrap();
    repository.save_run(&completed).unwrap();
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Completed
    );
}

impl RunEventSink for MemoryEvents {
    fn publish(&self, event: &EventEnvelope) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            Err("GUI event channel closed".into())
        } else {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }
}

struct TestDetector {
    fail: bool,
    reported_artifact_id: Option<String>,
}

impl TestDetector {
    fn working() -> Self {
        Self {
            fail: false,
            reported_artifact_id: None,
        }
    }
}

impl Detector for TestDetector {
    fn descriptor(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: "test-detector".into(),
            name: "Test detector".into(),
            version: "1".into(),
            kind: CapabilityKind::Detector,
            provenance: Provenance {
                authors: vec!["oxAudit tests".into()],
                source: "local fixture".into(),
                license: "Apache-2.0".into(),
                creation_method: CreationMethod::Authored,
                content_sha256: "a".repeat(64),
            },
            supports_offline: true,
            availability: CapabilityAvailability::Available,
            limitations: Vec::new(),
        }
    }

    fn supports(&self, artifact: &Artifact) -> bool {
        artifact.kind == ArtifactKind::SourceFile
    }

    fn detect(
        &self,
        input: DetectionInput,
        sink: &mut dyn ObservationSink,
    ) -> Result<DetectionSummary, String> {
        if self.fail {
            return Err("fixture detector failed".into());
        }
        sink.emit(ObservationRecord {
            observation: Observation {
                id: ObservationId::new(),
                run_id: input.run_id,
                artifact_id: input.artifact.id.clone(),
                kind: ObservationKind::SourceWeakness,
                detector_id: "test-detector".into(),
                detector_version: "1".into(),
                rule_id: Some("test-rule".into()),
                title: "Fixture weakness".into(),
                summary: "Deterministic test observation".into(),
                evidence_ids: Vec::new(),
            },
            evidence: Vec::new(),
        })?;
        Ok(DetectionSummary {
            artifact_id: self
                .reported_artifact_id
                .clone()
                .unwrap_or_else(|| input.artifact.id.to_string()),
            detector_id: "test-detector".into(),
            candidate_manifest: None,
            warnings: Vec::new(),
        })
    }
}

struct AlwaysCancelled;

impl Cancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

fn artifact() -> Artifact {
    Artifact {
        id: ArtifactId::parse("artifact_fixture").unwrap(),
        kind: ArtifactKind::SourceFile,
        location: ArtifactLocation {
            normalized_path: "src/main.rs".into(),
            canonical_path: None,
            parent_id: None,
        },
        size_bytes: 12,
        media_type: Some("text/x-rust".into()),
        content_sha256: Some("b".repeat(64)),
    }
}

fn request() -> RunRequest {
    RunRequest {
        run: Run::queued(RunKind::Source, "fixture", 1),
        artifacts: vec![artifact()],
    }
}

#[test]
fn successful_run_is_persisted_and_events_are_sequenced() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let detector = TestDetector::working();
    let outcome = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &NoCancellation)
        .unwrap();

    assert_eq!(outcome.run.state, RunState::Completed);
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(repository.observations.lock().unwrap().len(), 1);
    let events = events.events.lock().unwrap();
    assert!(events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
}

#[test]
fn cancellation_reaches_a_durable_terminal_state() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let detector = TestDetector::working();
    let outcome = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &AlwaysCancelled)
        .unwrap();
    assert_eq!(outcome.run.state, RunState::Cancelled);
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Cancelled
    );
}

#[test]
fn detector_failure_marks_the_run_failed() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let detector = TestDetector {
        fail: true,
        reported_artifact_id: None,
    };
    let error = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &NoCancellation)
        .unwrap_err();
    assert!(matches!(error, ApplicationError::Detector { .. }));
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Failed
    );
}

#[test]
fn event_delivery_failure_does_not_replace_durable_truth() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    events.fail.store(true, Ordering::SeqCst);
    let detector = TestDetector::working();
    let outcome = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &NoCancellation)
        .unwrap();
    assert_eq!(outcome.run.state, RunState::Completed);
    assert!(outcome.event_delivery_failures > 0);
    assert!(outcome
        .run
        .warnings
        .iter()
        .any(|warning| warning.code == "event_delivery_failed"));
}

#[test]
fn transient_persistence_failure_is_retried() {
    let repository = MemoryRepository::default();
    repository
        .save_failures_remaining
        .store(1, Ordering::SeqCst);
    let events = MemoryEvents::default();
    let detector = TestDetector::working();
    let outcome = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &NoCancellation)
        .unwrap();
    assert_eq!(outcome.run.state, RunState::Completed);
}

#[test]
fn detector_cannot_invent_an_accounting_identity() {
    let repository = MemoryRepository::default();
    let events = MemoryEvents::default();
    let detector = TestDetector {
        fail: false,
        reported_artifact_id: Some("artifact_invented".into()),
    };
    let error = RunCoordinator::new(&repository, &events)
        .execute(request(), &[&detector], &NoCancellation)
        .unwrap_err();
    assert!(matches!(error, ApplicationError::Manifest(_)));
    assert_eq!(
        repository.run.lock().unwrap().as_ref().unwrap().state,
        RunState::Incomplete
    );
}

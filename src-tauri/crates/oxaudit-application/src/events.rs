use oxaudit_domain::{ArtifactId, ObservationId, RunId, RunState};
use serde::{Deserialize, Serialize};

pub const EVENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    RunStarted,
    StageChanged,
    ArtifactDiscovered,
    ObservationEmitted,
    Warning,
    RunTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunEvent {
    RunStarted,
    StageChanged { state: RunState },
    ArtifactDiscovered { artifact_id: ArtifactId },
    ObservationEmitted { observation_id: ObservationId },
    Warning { code: String, message: String },
    RunTerminal { state: RunState },
}

impl RunEvent {
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::RunStarted => EventKind::RunStarted,
            Self::StageChanged { .. } => EventKind::StageChanged,
            Self::ArtifactDiscovered { .. } => EventKind::ArtifactDiscovered,
            Self::ObservationEmitted { .. } => EventKind::ObservationEmitted,
            Self::Warning { .. } => EventKind::Warning,
            Self::RunTerminal { .. } => EventKind::RunTerminal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub run_id: RunId,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub event: RunEvent,
}

pub struct EventSequencer {
    run_id: RunId,
    next_sequence: u64,
}

impl EventSequencer {
    pub fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            next_sequence: 1,
        }
    }

    pub fn envelope(&mut self, occurred_at_ms: u64, event: RunEvent) -> EventEnvelope {
        let envelope = EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            sequence: self.next_sequence,
            occurred_at_ms,
            event,
        };
        self.next_sequence += 1;
        envelope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_are_versioned_and_strictly_sequenced() {
        let mut sequencer = EventSequencer::new(RunId::parse("run_test").unwrap());
        let first = sequencer.envelope(10, RunEvent::RunStarted);
        let second = sequencer.envelope(
            11,
            RunEvent::StageChanged {
                state: RunState::Detecting,
            },
        );
        assert_eq!(first.schema_version, 1);
        assert_eq!((first.sequence, second.sequence), (1, 2));
        assert_eq!(
            serde_json::to_value(second).unwrap()["event"]["kind"],
            "stage_changed"
        );
    }
}

use serde::{Deserialize, Serialize};

use crate::{DomainError, ProviderSnapshotId, RulePackId, RunId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    Source,
    Secrets,
    Dependencies,
    Binary,
    Firmware,
    Image,
    History,
    Import,
    ExternalEvidence,
    Verification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Discovering,
    Detecting,
    Normalizing,
    Enriching,
    Assessing,
    Persisting,
    Completed,
    Cancelling,
    Cancelled,
    Incomplete,
    Failed,
    Verifying,
}

impl RunState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Incomplete | Self::Failed
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use RunState::*;
        matches!(
            (self, next),
            (Queued, Discovering)
                | (Discovering, Detecting)
                | (Detecting, Normalizing)
                | (Normalizing, Enriching)
                | (Normalizing, Assessing)
                | (Enriching, Assessing)
                | (Assessing, Persisting)
                | (Persisting, Completed)
                | (Completed, Verifying)
                | (Verifying, Completed)
                | (Queued, Cancelling)
                | (Discovering, Cancelling)
                | (Detecting, Cancelling)
                | (Normalizing, Cancelling)
                | (Enriching, Cancelling)
                | (Assessing, Cancelling)
                | (Persisting, Cancelling)
                | (Verifying, Cancelling)
                | (Cancelling, Cancelled)
                | (Queued, Incomplete)
                | (Discovering, Incomplete)
                | (Detecting, Incomplete)
                | (Normalizing, Incomplete)
                | (Enriching, Incomplete)
                | (Assessing, Incomplete)
                | (Persisting, Incomplete)
                | (Verifying, Incomplete)
                | (Queued, Failed)
                | (Discovering, Failed)
                | (Detecting, Failed)
                | (Normalizing, Failed)
                | (Enriching, Failed)
                | (Assessing, Failed)
                | (Persisting, Failed)
                | (Verifying, Failed)
        )
    }
}

impl std::fmt::Display for RunState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: RunId,
    pub kind: RunKind,
    pub target_label: String,
    pub state: RunState,
    pub attempt: u32,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub engine_ids: Vec<String>,
    pub rule_pack_ids: Vec<RulePackId>,
    pub provider_snapshot_ids: Vec<ProviderSnapshotId>,
    pub warnings: Vec<RunWarning>,
}

impl Run {
    pub fn queued(kind: RunKind, target_label: impl Into<String>, now_ms: u64) -> Self {
        Self {
            id: RunId::new(),
            kind,
            target_label: target_label.into(),
            state: RunState::Queued,
            attempt: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            engine_ids: Vec::new(),
            rule_pack_ids: Vec::new(),
            provider_snapshot_ids: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn transition(&mut self, next: RunState, now_ms: u64) -> Result<(), DomainError> {
        if self.state.is_terminal()
            && !(self.state == RunState::Completed && next == RunState::Verifying)
        {
            return Err(DomainError::TerminalRunImmutable);
        }
        if !self.state.can_transition_to(next) {
            return Err(DomainError::IllegalRunTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }
        self.state = next;
        self.updated_at_ms = now_ms;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_run_path_reaches_completed() {
        let mut run = Run::queued(RunKind::Source, "fixture", 1);
        for state in [
            RunState::Discovering,
            RunState::Detecting,
            RunState::Normalizing,
            RunState::Assessing,
            RunState::Persisting,
            RunState::Completed,
        ] {
            run.transition(state, 2).unwrap();
        }
        assert_eq!(run.state, RunState::Completed);
    }

    #[test]
    fn illegal_skip_and_terminal_mutation_are_rejected() {
        let mut run = Run::queued(RunKind::Binary, "fixture", 1);
        assert!(run.transition(RunState::Completed, 2).is_err());
        run.transition(RunState::Failed, 3).unwrap();
        assert_eq!(
            run.transition(RunState::Discovering, 4),
            Err(DomainError::TerminalRunImmutable)
        );
    }
}

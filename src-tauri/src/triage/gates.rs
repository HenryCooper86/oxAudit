//! Falsification gates for a scanner finding.
//!
//! Ported in method from [VulnHunter](https://github.com/capitalone/VulnHunter)
//! (Apache-2.0), whose thesis is that ordinary static analysis reasons backward
//! from dangerous sinks and therefore drowns the user in pattern hits. It
//! reasons forward from entry points, then runs every candidate through gates
//! whose job is to **disprove** it.
//!
//! oxAudit is exactly the tool that argument is aimed at: `scanners/patterns.rs`
//! is fifty regular expressions, and every hit is presented as a result. A
//! finding here is a *candidate* until something has tried and failed to
//! eliminate it.
//!
//! Nothing is transcribed from VulnHunter — it is prompt architecture rather
//! than code, and what is worth taking is the shape of the argument.

use serde::{Deserialize, Serialize};

/// The five questions, in the order they are cheapest to answer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum Gate {
    /// Is this the application doing what it was designed to do?
    Intended,
    /// Is the code reachable in production?
    Reachable,
    /// Is the input genuinely attacker-controlled?
    AttackerControlled,
    /// Is there sanitization between source and sink that actually covers it?
    Sanitized,
    /// Does the attacker gain a capability they did not already have?
    NewCapability,
}

pub const ALL_GATES: [Gate; 5] = [
    Gate::Intended,
    Gate::Reachable,
    Gate::AttackerControlled,
    Gate::Sanitized,
    Gate::NewCapability,
];

impl Gate {
    pub fn question(self) -> &'static str {
        match self {
            Gate::Intended => "Is this the application doing what it was designed to do?",
            Gate::Reachable => "Is this code reachable in a production build?",
            Gate::AttackerControlled => "Is the input genuinely attacker-controlled?",
            Gate::Sanitized => {
                "Is there sanitization between source and sink whose scope matches the sink?"
            }
            Gate::NewCapability => "Does the attacker gain a capability they did not already have?",
        }
    }

    /// What eliminating at this gate means, for the UI and the report.
    pub fn eliminates(self) -> &'static str {
        match self {
            Gate::Intended => "a designed behaviour, not a defect",
            Gate::Reachable => "unreachable in production",
            Gate::AttackerControlled => "the input is not attacker-controlled",
            Gate::Sanitized => "already defended on every path that reaches the sink",
            Gate::NewCapability => "grants nothing the attacker could not already do",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Gate::Intended => "intended",
            Gate::Reachable => "reachable",
            Gate::AttackerControlled => "attackerControlled",
            Gate::Sanitized => "sanitized",
            Gate::NewCapability => "newCapability",
        }
    }
}

/// What a gate concluded. `Unknown` is a first-class answer: an unanswered gate
/// is a red flag rather than a quiet pass, and it is what keeps a triage from
/// claiming more confidence than it earned.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GateVerdict {
    /// The finding survives this gate.
    Survives,
    /// This gate eliminates the finding.
    Eliminates,
    /// Could not be determined.
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GateNote {
    pub gate: Gate,
    pub verdict: GateVerdict,
    /// Why — with a file:line where one applies. A verdict without evidence is
    /// rejected, because "trust me" is what a triage layer exists to replace.
    pub evidence: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum Disposition {
    /// Survived every gate.
    Confirmed,
    /// A gate eliminated it.
    Eliminated { gate: Gate },
    /// Triage ran but could not reach a conclusion.
    Unverified,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Triage {
    /// The finding this verdict belongs to.
    pub finding_id: String,
    pub disposition: Disposition,
    pub entry_point: Option<String>,
    pub data_flow: Option<String>,
    pub gates: Vec<GateNote>,
    pub reviewed_at: String,
}

#[derive(Debug, PartialEq)]
pub enum TriageError {
    /// An elimination that does not say which gate decided it, or why.
    UnsupportedElimination { finding_id: String, reason: String },
    /// A confirmation while a gate is still unanswered.
    IncompleteConfirmation {
        finding_id: String,
        unanswered: Vec<Gate>,
    },
}

impl std::fmt::Display for TriageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriageError::UnsupportedElimination { finding_id, reason } => {
                write!(f, "{finding_id}: elimination is unsupported — {reason}")
            }
            TriageError::IncompleteConfirmation {
                finding_id,
                unanswered,
            } => write!(
                f,
                "{finding_id}: confirmed while {} gate(s) are unanswered: {}",
                unanswered.len(),
                unanswered
                    .iter()
                    .map(|g| g.slug())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl Triage {
    /// Build a verdict, refusing the two ways one can be dishonest.
    ///
    /// An **elimination** must name the gate that decided it and carry
    /// evidence — VulnHunter's rule that a blank gate means the investigation
    /// shortcut past the check, and it is the difference between "we checked"
    /// and "we did not look".
    ///
    /// A **confirmation** must have answered every gate. Confirming while a
    /// gate is `Unknown` overstates what was established, and this is the
    /// direction that costs a user their time.
    pub fn new(
        finding_id: impl Into<String>,
        disposition: Disposition,
        gates: Vec<GateNote>,
        reviewed_at: impl Into<String>,
    ) -> Result<Self, TriageError> {
        let finding_id = finding_id.into();

        if let Disposition::Eliminated { gate } = disposition {
            let note = gates.iter().find(|note| note.gate == gate);
            match note {
                None => {
                    return Err(TriageError::UnsupportedElimination {
                        finding_id,
                        reason: format!("no note for the deciding gate {}", gate.slug()),
                    })
                }
                Some(note) if note.verdict != GateVerdict::Eliminates => {
                    return Err(TriageError::UnsupportedElimination {
                        finding_id,
                        reason: format!("gate {} did not eliminate it", gate.slug()),
                    })
                }
                Some(note) if note.evidence.trim().is_empty() => {
                    return Err(TriageError::UnsupportedElimination {
                        finding_id,
                        reason: format!("gate {} gives no evidence", gate.slug()),
                    })
                }
                Some(_) => {}
            }
        }

        if disposition == Disposition::Confirmed {
            let unanswered: Vec<Gate> = ALL_GATES
                .iter()
                .copied()
                .filter(|gate| {
                    !gates
                        .iter()
                        .any(|note| note.gate == *gate && note.verdict != GateVerdict::Unknown)
                })
                .collect();
            if !unanswered.is_empty() {
                return Err(TriageError::IncompleteConfirmation {
                    finding_id,
                    unanswered,
                });
            }
        }

        Ok(Self {
            finding_id,
            disposition,
            entry_point: None,
            data_flow: None,
            gates,
            reviewed_at: reviewed_at.into(),
        })
    }

    pub fn is_confirmed(&self) -> bool {
        self.disposition == Disposition::Confirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(gate: Gate, verdict: GateVerdict) -> GateNote {
        GateNote {
            gate,
            verdict,
            evidence: format!("checked at src/lib.rs:{}", gate as usize + 1),
        }
    }

    fn all_surviving() -> Vec<GateNote> {
        ALL_GATES
            .iter()
            .map(|gate| note(*gate, GateVerdict::Survives))
            .collect()
    }

    #[test]
    fn a_finding_that_survives_every_gate_can_be_confirmed() {
        let triage = Triage::new("F-1", Disposition::Confirmed, all_surviving(), "2026-08-20")
            .expect("confirms");
        assert!(triage.is_confirmed());
    }

    #[test]
    fn confirming_with_an_unanswered_gate_is_refused() {
        // This is the direction that wastes a user's time: presenting a hit as
        // established when nobody checked whether it is reachable.
        let mut gates = all_surviving();
        gates[1] = note(Gate::Reachable, GateVerdict::Unknown);

        let error = Triage::new("F-2", Disposition::Confirmed, gates, "2026-08-20")
            .expect_err("must refuse");
        assert_eq!(
            error,
            TriageError::IncompleteConfirmation {
                finding_id: "F-2".into(),
                unanswered: vec![Gate::Reachable],
            }
        );
    }

    #[test]
    fn confirming_with_no_gates_at_all_names_every_one_of_them() {
        let error = Triage::new("F-3", Disposition::Confirmed, Vec::new(), "2026-08-20")
            .expect_err("must refuse");
        match error {
            TriageError::IncompleteConfirmation { unanswered, .. } => {
                assert_eq!(unanswered.len(), ALL_GATES.len())
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn an_elimination_must_name_the_gate_that_decided_it() {
        let error = Triage::new(
            "F-4",
            Disposition::Eliminated {
                gate: Gate::Reachable,
            },
            vec![note(Gate::Intended, GateVerdict::Survives)],
            "2026-08-20",
        )
        .expect_err("must refuse");
        assert!(matches!(error, TriageError::UnsupportedElimination { .. }));
    }

    #[test]
    fn an_elimination_whose_gate_did_not_eliminate_is_refused() {
        // Claiming Gate 1 killed it while Gate 1 says it survives is exactly
        // the sort of inconsistency a reviewer would never spot in bulk.
        let error = Triage::new(
            "F-5",
            Disposition::Eliminated {
                gate: Gate::Reachable,
            },
            vec![note(Gate::Reachable, GateVerdict::Survives)],
            "2026-08-20",
        )
        .expect_err("must refuse");
        assert!(matches!(error, TriageError::UnsupportedElimination { .. }));
    }

    #[test]
    fn an_elimination_without_evidence_is_refused() {
        let error = Triage::new(
            "F-6",
            Disposition::Eliminated {
                gate: Gate::Sanitized,
            },
            vec![GateNote {
                gate: Gate::Sanitized,
                verdict: GateVerdict::Eliminates,
                evidence: "   ".into(),
            }],
            "2026-08-20",
        )
        .expect_err("must refuse");
        assert!(matches!(error, TriageError::UnsupportedElimination { .. }));
    }

    #[test]
    fn a_supported_elimination_is_accepted_without_answering_later_gates() {
        // Once a gate eliminates a finding the rest are moot, and demanding
        // them would make honest triage more expensive than sloppy triage.
        let triage = Triage::new(
            "F-7",
            Disposition::Eliminated {
                gate: Gate::Reachable,
            },
            vec![GateNote {
                gate: Gate::Reachable,
                verdict: GateVerdict::Eliminates,
                evidence: "dev-only route, guarded at src/dev.rs:14".into(),
            }],
            "2026-08-20",
        )
        .expect("accepts");
        assert!(!triage.is_confirmed());
    }

    #[test]
    fn unverified_needs_no_justification() {
        // "We ran triage and could not tell" must stay cheap to express, or it
        // gets recorded as something more definite than it is.
        Triage::new("F-8", Disposition::Unverified, Vec::new(), "2026-08-20").expect("accepts");
    }
}

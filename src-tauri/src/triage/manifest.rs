//! The silent-drop guard for batch triage.
//!
//! VulnHunter's rule, worth quoting because it is the whole idea: *"A candidate
//! that was never listed in the table was never evaluated — that is a
//! verification failure, not an implicit rejection."*
//!
//! Their version is a discipline the model is asked to follow — list every
//! candidate, count them, and produce a verdict table with exactly that many
//! rows. A prompt cannot enforce it. Here it is an invariant: reconciliation
//! fails loudly rather than returning the verdicts that happened to come back.
//!
//! This matters more for a security tool than almost anything else it does. A
//! finding that vanishes between "scanned" and "reported" is indistinguishable
//! from one that was never there, and the user has no way to notice.

use std::collections::BTreeSet;

use super::gates::Triage;

/// The candidates that entered triage.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    ids: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum ManifestError {
    /// The same finding was listed twice, so counts cannot be trusted.
    DuplicateCandidates(Vec<String>),
    /// Candidates that came back with no verdict — the silent drop.
    Unevaluated(Vec<String>),
    /// Verdicts for findings that were never candidates.
    Unsolicited(Vec<String>),
    /// Two verdicts for one candidate.
    ConflictingVerdicts(Vec<String>),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn join(ids: &[String]) -> String {
            ids.join(", ")
        }
        match self {
            ManifestError::DuplicateCandidates(ids) => {
                write!(f, "the same finding was listed twice: {}", join(ids))
            }
            ManifestError::Unevaluated(ids) => write!(
                f,
                "{} candidate(s) came back with no verdict and would have been dropped silently: {}",
                ids.len(),
                join(ids)
            ),
            ManifestError::Unsolicited(ids) => write!(
                f,
                "verdicts for findings that were never candidates: {}",
                join(ids)
            ),
            ManifestError::ConflictingVerdicts(ids) => {
                write!(f, "more than one verdict for: {}", join(ids))
            }
        }
    }
}

impl Manifest {
    /// Record the candidates. Duplicates are rejected here rather than
    /// deduplicated, because a duplicated id means the caller's own accounting
    /// is wrong and every count downstream would inherit it.
    pub fn new<I, S>(ids: I) -> Result<Self, ManifestError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let ids: Vec<String> = ids.into_iter().map(Into::into).collect();
        let mut seen = BTreeSet::new();
        let mut duplicates = BTreeSet::new();
        for id in &ids {
            if !seen.insert(id.clone()) {
                duplicates.insert(id.clone());
            }
        }
        if !duplicates.is_empty() {
            return Err(ManifestError::DuplicateCandidates(
                duplicates.into_iter().collect(),
            ));
        }
        Ok(Self { ids })
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Check the verdicts against the candidates and return them in manifest
    /// order.
    ///
    /// Every candidate must have exactly one verdict, and every verdict must
    /// belong to a candidate. Anything else is an error, never a quietly
    /// shorter list.
    pub fn reconcile(&self, verdicts: Vec<Triage>) -> Result<Vec<Triage>, ManifestError> {
        let candidates: BTreeSet<&str> = self.ids.iter().map(String::as_str).collect();

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut conflicting: BTreeSet<String> = BTreeSet::new();
        let mut unsolicited: BTreeSet<String> = BTreeSet::new();
        let mut by_id: std::collections::HashMap<String, Triage> = std::collections::HashMap::new();

        for verdict in verdicts {
            if !candidates.contains(verdict.finding_id.as_str()) {
                unsolicited.insert(verdict.finding_id.clone());
                continue;
            }
            if !seen.insert(verdict.finding_id.clone()) {
                conflicting.insert(verdict.finding_id.clone());
                continue;
            }
            by_id.insert(verdict.finding_id.clone(), verdict);
        }

        if !unsolicited.is_empty() {
            return Err(ManifestError::Unsolicited(
                unsolicited.into_iter().collect(),
            ));
        }
        if !conflicting.is_empty() {
            return Err(ManifestError::ConflictingVerdicts(
                conflicting.into_iter().collect(),
            ));
        }

        let unevaluated: Vec<String> = self
            .ids
            .iter()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect();
        if !unevaluated.is_empty() {
            return Err(ManifestError::Unevaluated(unevaluated));
        }

        // Manifest order, so a report reads the same way twice.
        Ok(self
            .ids
            .iter()
            .map(|id| by_id.remove(id).expect("every id was just accounted for"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::gates::{Disposition, Triage};
    use super::*;

    fn verdict(id: &str) -> Triage {
        Triage::new(id, Disposition::Unverified, Vec::new(), "2026-08-20").expect("builds")
    }

    #[test]
    fn a_complete_set_of_verdicts_reconciles_in_manifest_order() {
        let manifest = Manifest::new(["F-1", "F-2", "F-3"]).expect("builds");
        let reconciled = manifest
            .reconcile(vec![verdict("F-3"), verdict("F-1"), verdict("F-2")])
            .expect("reconciles");
        let ids: Vec<&str> = reconciled.iter().map(|t| t.finding_id.as_str()).collect();
        assert_eq!(ids, vec!["F-1", "F-2", "F-3"]);
    }

    #[test]
    fn a_missing_verdict_is_an_error_rather_than_a_shorter_list() {
        // The whole point. Returning two verdicts for three candidates reads
        // downstream as "one was rejected", and nobody can tell the difference.
        let manifest = Manifest::new(["F-1", "F-2", "F-3"]).expect("builds");
        let error = manifest
            .reconcile(vec![verdict("F-1"), verdict("F-3")])
            .expect_err("must not silently drop");
        assert_eq!(error, ManifestError::Unevaluated(vec!["F-2".into()]));
        assert!(error.to_string().contains("dropped silently"));
    }

    #[test]
    fn every_dropped_candidate_is_named_not_just_counted() {
        let manifest = Manifest::new(["F-1", "F-2", "F-3", "F-4"]).expect("builds");
        let error = manifest
            .reconcile(vec![verdict("F-2")])
            .expect_err("must not silently drop");
        assert_eq!(
            error,
            ManifestError::Unevaluated(vec!["F-1".into(), "F-3".into(), "F-4".into()])
        );
    }

    #[test]
    fn a_verdict_for_something_never_scanned_is_rejected() {
        // An invented finding id is a fabrication, and it is the failure mode
        // to expect when a language model fills the table.
        let manifest = Manifest::new(["F-1"]).expect("builds");
        let error = manifest
            .reconcile(vec![verdict("F-1"), verdict("F-99")])
            .expect_err("must reject");
        assert_eq!(error, ManifestError::Unsolicited(vec!["F-99".into()]));
    }

    #[test]
    fn two_verdicts_for_one_candidate_are_rejected() {
        let manifest = Manifest::new(["F-1", "F-2"]).expect("builds");
        let error = manifest
            .reconcile(vec![verdict("F-1"), verdict("F-1"), verdict("F-2")])
            .expect_err("must reject");
        assert_eq!(
            error,
            ManifestError::ConflictingVerdicts(vec!["F-1".into()])
        );
    }

    #[test]
    fn a_duplicated_candidate_is_caught_when_the_manifest_is_built() {
        // Catching it later would mean every count in the report is already
        // wrong by the time anyone notices.
        let error = Manifest::new(["F-1", "F-2", "F-1"]).expect_err("must reject");
        assert_eq!(
            error,
            ManifestError::DuplicateCandidates(vec!["F-1".into()])
        );
    }

    #[test]
    fn an_empty_manifest_reconciles_with_no_verdicts() {
        let manifest = Manifest::new(Vec::<String>::new()).expect("builds");
        assert!(manifest.is_empty());
        assert!(manifest
            .reconcile(Vec::new())
            .expect("reconciles")
            .is_empty());
    }

    #[test]
    fn an_empty_manifest_still_rejects_an_invented_verdict() {
        let manifest = Manifest::new(Vec::<String>::new()).expect("builds");
        assert!(manifest.reconcile(vec![verdict("F-1")]).is_err());
    }
}

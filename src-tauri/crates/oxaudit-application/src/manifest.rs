use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSnapshot {
    pub stage: String,
    pub expected_ids: Vec<String>,
    pub produced_ids: Vec<String>,
}

impl ManifestSnapshot {
    pub fn validate(&self) -> Result<ManifestReport, ManifestError> {
        let mut manifest = StageManifest::new(self.stage.clone(), self.expected_ids.clone())?;
        for id in &self.produced_ids {
            manifest.record(id.clone());
        }
        manifest.reconcile()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestReport {
    pub stage: String,
    pub expected: usize,
    pub produced: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestError {
    #[error("stage {stage} declares duplicate expected ids: {ids:?}")]
    DuplicateExpected { stage: String, ids: Vec<String> },
    #[error("stage {stage} produced duplicate ids: {ids:?}")]
    DuplicateProduced { stage: String, ids: Vec<String> },
    #[error("stage {stage} dropped ids: {ids:?}")]
    Dropped { stage: String, ids: Vec<String> },
    #[error("stage {stage} invented ids: {ids:?}")]
    Invented { stage: String, ids: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct StageManifest {
    stage: String,
    expected: BTreeSet<String>,
    produced: BTreeMap<String, usize>,
}

impl StageManifest {
    pub fn new(
        stage: impl Into<String>,
        expected_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, ManifestError> {
        let stage = stage.into();
        let mut expected = BTreeSet::new();
        let mut duplicates = BTreeSet::new();
        for id in expected_ids {
            if !expected.insert(id.clone()) {
                duplicates.insert(id);
            }
        }
        if !duplicates.is_empty() {
            return Err(ManifestError::DuplicateExpected {
                stage,
                ids: duplicates.into_iter().collect(),
            });
        }
        Ok(Self {
            stage,
            expected,
            produced: BTreeMap::new(),
        })
    }

    pub fn record(&mut self, id: impl Into<String>) {
        *self.produced.entry(id.into()).or_insert(0) += 1;
    }

    pub fn reconcile(self) -> Result<ManifestReport, ManifestError> {
        let duplicates: Vec<String> = self
            .produced
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(id, _)| id.clone())
            .collect();
        if !duplicates.is_empty() {
            return Err(ManifestError::DuplicateProduced {
                stage: self.stage,
                ids: duplicates,
            });
        }

        let produced: BTreeSet<String> = self.produced.keys().cloned().collect();
        let dropped: Vec<String> = self.expected.difference(&produced).cloned().collect();
        if !dropped.is_empty() {
            return Err(ManifestError::Dropped {
                stage: self.stage,
                ids: dropped,
            });
        }
        let invented: Vec<String> = produced.difference(&self.expected).cloned().collect();
        if !invented.is_empty() {
            return Err(ManifestError::Invented {
                stage: self.stage,
                ids: invented,
            });
        }
        Ok(ManifestReport {
            stage: self.stage,
            expected: self.expected.len(),
            produced: produced.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> StageManifest {
        StageManifest::new("verify", ["a".into(), "b".into()]).unwrap()
    }

    #[test]
    fn exact_accounting_succeeds() {
        let mut manifest = manifest();
        manifest.record("a");
        manifest.record("b");
        assert_eq!(manifest.reconcile().unwrap().produced, 2);
    }

    #[test]
    fn dropped_invented_and_duplicate_outputs_fail_closed() {
        let mut dropped = manifest();
        dropped.record("a");
        assert!(matches!(
            dropped.reconcile(),
            Err(ManifestError::Dropped { .. })
        ));

        let mut invented = manifest();
        invented.record("a");
        invented.record("b");
        invented.record("c");
        assert!(matches!(
            invented.reconcile(),
            Err(ManifestError::Invented { .. })
        ));

        let mut duplicate = manifest();
        duplicate.record("a");
        duplicate.record("a");
        duplicate.record("b");
        assert!(matches!(
            duplicate.reconcile(),
            Err(ManifestError::DuplicateProduced { .. })
        ));
    }
}

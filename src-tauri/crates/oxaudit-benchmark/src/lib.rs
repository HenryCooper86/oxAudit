//! Offline-capable, resumable benchmark orchestration.
//!
//! The crate defines measurement contracts only. Filesystem, SQLite, GUI, and
//! scanner adapters implement its narrow ports in the host application.

use std::collections::{BTreeMap, BTreeSet};

use oxaudit_domain::Provenance;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BENCHMARK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkSuite {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub description: String,
    pub provenance: Provenance,
    pub targets: Vec<BenchmarkTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTarget {
    pub id: String,
    pub input_path: String,
    pub input_sha256: String,
    pub platform: String,
    pub architecture: String,
    /// Scanner families evaluated for this target (for example
    /// `source-pattern` or `secret`). Empty preserves the v1 source default.
    #[serde(default)]
    pub scanner_families: Vec<String>,
    /// Language selector used by source-pattern scanners.
    #[serde(default)]
    pub language: Option<String>,
    pub expected: Vec<ExpectedObservation>,
    #[serde(default)]
    pub expected_absent: Vec<ObservationIdentity>,
    #[serde(default)]
    pub allowed_variants: Vec<AllowedVariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationIdentity {
    pub rule_id: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedObservation {
    pub identity: ObservationIdentity,
    pub count: u32,
    pub evidence_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedVariant {
    pub canonical: ObservationIdentity,
    pub alternatives: Vec<ObservationIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActualObservation {
    pub identity: ObservationIdentity,
    pub evidence_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetResult {
    pub target_id: String,
    pub status: TargetStatus,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub runtime_ms: u64,
    pub peak_memory_bytes: Option<u64>,
    pub misses: Vec<ObservationIdentity>,
    pub unexpected: Vec<ObservationIdentity>,
    pub error: Option<String>,
}

impl TargetResult {
    fn pending(target_id: String) -> Self {
        Self {
            target_id,
            status: TargetStatus::Pending,
            true_positives: 0,
            false_positives: 0,
            false_negatives: 0,
            runtime_ms: 0,
            peak_memory_bytes: None,
            misses: Vec::new(),
            unexpected: Vec::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkMetrics {
    pub corpus_targets: u32,
    pub completed_targets: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub runtime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkState {
    pub schema_version: u32,
    pub suite_id: String,
    pub suite_version: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub results: BTreeMap<String, TargetResult>,
    pub metrics: BenchmarkMetrics,
}

impl BenchmarkState {
    pub fn new(suite: &BenchmarkSuite, now_ms: u64) -> Self {
        let results = suite
            .targets
            .iter()
            .map(|target| (target.id.clone(), TargetResult::pending(target.id.clone())))
            .collect();
        let mut state = Self {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            suite_id: suite.id.clone(),
            suite_version: suite.version.clone(),
            started_at_ms: now_ms,
            updated_at_ms: now_ms,
            completed_at_ms: None,
            results,
            metrics: BenchmarkMetrics {
                corpus_targets: suite.targets.len() as u32,
                completed_targets: 0,
                true_positives: 0,
                false_positives: 0,
                false_negatives: 0,
                precision: None,
                recall: None,
                runtime_ms: 0,
            },
        };
        state.recalculate();
        state
    }

    pub fn recalculate(&mut self) {
        let completed: Vec<&TargetResult> = self
            .results
            .values()
            .filter(|result| {
                matches!(
                    result.status,
                    TargetStatus::Passed | TargetStatus::Failed | TargetStatus::Error
                )
            })
            .collect();
        let true_positives = completed.iter().map(|result| result.true_positives).sum();
        let false_positives = completed.iter().map(|result| result.false_positives).sum();
        let false_negatives = completed.iter().map(|result| result.false_negatives).sum();
        self.metrics.completed_targets = completed.len() as u32;
        self.metrics.true_positives = true_positives;
        self.metrics.false_positives = false_positives;
        self.metrics.false_negatives = false_negatives;
        self.metrics.runtime_ms = completed.iter().map(|result| result.runtime_ms).sum();
        self.metrics.precision = ratio(true_positives, true_positives + false_positives);
        self.metrics.recall = ratio(true_positives, true_positives + false_negatives);
    }
}

impl BenchmarkSuite {
    pub fn validate(&self) -> Result<(), BenchmarkError> {
        validate_suite(self)
    }
}

fn ratio(numerator: u32, denominator: u32) -> Option<f64> {
    (denominator != 0).then_some(numerator as f64 / denominator as f64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub observations: Vec<ActualObservation>,
    pub runtime_ms: u64,
    pub peak_memory_bytes: Option<u64>,
}

pub trait BenchmarkExecutor {
    fn execute(&self, target: &BenchmarkTarget) -> Result<ExecutionResult, String>;
}

pub trait BenchmarkStateStore {
    fn load(&self, suite_id: &str) -> Result<Option<BenchmarkState>, String>;
    /// Implementations must replace the complete state atomically.
    fn save_atomic(&self, state: &BenchmarkState) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunMode {
    Resume,
    Force,
    TallyOnly,
    Targeted(BTreeSet<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BenchmarkError {
    #[error("benchmark suite is invalid: {0}")]
    InvalidSuite(String),
    #[error("benchmark state is incompatible with this suite")]
    IncompatibleState,
    #[error("benchmark state operation failed: {0}")]
    State(String),
}

pub struct BenchmarkRunner<'a> {
    store: &'a dyn BenchmarkStateStore,
    executor: &'a dyn BenchmarkExecutor,
}

impl<'a> BenchmarkRunner<'a> {
    pub fn new(store: &'a dyn BenchmarkStateStore, executor: &'a dyn BenchmarkExecutor) -> Self {
        Self { store, executor }
    }

    pub fn run(
        &self,
        suite: &BenchmarkSuite,
        mode: RunMode,
        now_ms: impl Fn() -> u64,
    ) -> Result<BenchmarkState, BenchmarkError> {
        validate_suite(suite)?;
        let stored = self.store.load(&suite.id).map_err(BenchmarkError::State)?;
        if mode == RunMode::TallyOnly {
            let mut state = stored.ok_or(BenchmarkError::IncompatibleState)?;
            ensure_compatible(&state, suite)?;
            state.recalculate();
            return Ok(state);
        }
        let mut state = match (mode == RunMode::Force, stored) {
            (false, Some(state)) => {
                ensure_compatible(&state, suite)?;
                state
            }
            _ => BenchmarkState::new(suite, now_ms()),
        };
        let selected = match &mode {
            RunMode::Targeted(ids) => {
                if ids
                    .iter()
                    .any(|id| !suite.targets.iter().any(|target| &target.id == id))
                {
                    return Err(BenchmarkError::InvalidSuite(
                        "targeted run names an unknown target".into(),
                    ));
                }
                Some(ids)
            }
            _ => None,
        };

        for target in &suite.targets {
            if selected.is_some_and(|ids| !ids.contains(&target.id)) {
                continue;
            }
            let existing = state
                .results
                .get(&target.id)
                .expect("suite seeded every target");
            if mode == RunMode::Resume
                && matches!(existing.status, TargetStatus::Passed | TargetStatus::Failed)
            {
                continue;
            }
            state.results.get_mut(&target.id).unwrap().status = TargetStatus::Running;
            state.updated_at_ms = now_ms();
            self.store
                .save_atomic(&state)
                .map_err(BenchmarkError::State)?;

            let result = match self.executor.execute(target) {
                Ok(execution) => judge(target, execution),
                Err(error) => TargetResult {
                    target_id: target.id.clone(),
                    status: TargetStatus::Error,
                    true_positives: 0,
                    false_positives: 0,
                    false_negatives: target.expected.iter().map(|item| item.count).sum(),
                    runtime_ms: 0,
                    peak_memory_bytes: None,
                    misses: target
                        .expected
                        .iter()
                        .map(|item| item.identity.clone())
                        .collect(),
                    unexpected: Vec::new(),
                    error: Some(error),
                },
            };
            state.results.insert(target.id.clone(), result);
            state.updated_at_ms = now_ms();
            state.recalculate();
            self.store
                .save_atomic(&state)
                .map_err(BenchmarkError::State)?;
        }
        let all_terminal = state.results.values().all(|result| {
            matches!(
                result.status,
                TargetStatus::Passed | TargetStatus::Failed | TargetStatus::Error
            )
        });
        if all_terminal {
            state.completed_at_ms = Some(now_ms());
        }
        state.updated_at_ms = now_ms();
        state.recalculate();
        self.store
            .save_atomic(&state)
            .map_err(BenchmarkError::State)?;
        Ok(state)
    }
}

fn validate_suite(suite: &BenchmarkSuite) -> Result<(), BenchmarkError> {
    if suite.schema_version != BENCHMARK_SCHEMA_VERSION {
        return Err(BenchmarkError::InvalidSuite(format!(
            "unsupported schema version {}",
            suite.schema_version
        )));
    }
    suite
        .provenance
        .validate()
        .map_err(|error| BenchmarkError::InvalidSuite(error.to_string()))?;
    let mut ids = BTreeSet::new();
    for target in &suite.targets {
        if target.id.trim().is_empty() || !ids.insert(target.id.clone()) {
            return Err(BenchmarkError::InvalidSuite(
                "target ids must be non-empty and unique".into(),
            ));
        }
        if target.input_sha256.len() != 64
            || !target
                .input_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BenchmarkError::InvalidSuite(format!(
                "target {} needs a SHA-256 identity",
                target.id
            )));
        }
        if target.expected.iter().any(|expected| expected.count == 0) {
            return Err(BenchmarkError::InvalidSuite(format!(
                "target {} has a zero-count expectation",
                target.id
            )));
        }
        if target.input_path.trim().is_empty()
            || std::path::Path::new(&target.input_path).is_absolute()
            || std::path::Path::new(&target.input_path)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(BenchmarkError::InvalidSuite(format!(
                "target {} has an unsafe input path",
                target.id
            )));
        }
        if target
            .scanner_families
            .iter()
            .any(|family| !matches!(family.as_str(), "source-pattern" | "secret"))
        {
            return Err(BenchmarkError::InvalidSuite(format!(
                "target {} names an unsupported scanner family",
                target.id
            )));
        }
    }
    Ok(())
}

fn ensure_compatible(state: &BenchmarkState, suite: &BenchmarkSuite) -> Result<(), BenchmarkError> {
    if state.schema_version == BENCHMARK_SCHEMA_VERSION
        && state.suite_id == suite.id
        && state.suite_version == suite.version
    {
        Ok(())
    } else {
        Err(BenchmarkError::IncompatibleState)
    }
}

pub fn judge(target: &BenchmarkTarget, execution: ExecutionResult) -> TargetResult {
    let canonical_identity = |actual: &ObservationIdentity| {
        target
            .allowed_variants
            .iter()
            .find(|variant| variant.alternatives.contains(actual))
            .map(|variant| variant.canonical.clone())
            .unwrap_or_else(|| actual.clone())
    };
    let mut actual_counts = BTreeMap::<(ObservationIdentity, String), u32>::new();
    for actual in &execution.observations {
        *actual_counts
            .entry((
                canonical_identity(&actual.identity),
                actual.evidence_kind.clone(),
            ))
            .or_insert(0) += 1;
    }
    let mut true_positives = 0u32;
    let mut false_negatives = 0u32;
    let mut misses = Vec::new();
    let mut expected_identities = BTreeSet::new();
    for expected in &target.expected {
        expected_identities.insert(expected.identity.clone());
        let actual = actual_counts
            .get(&(expected.identity.clone(), expected.evidence_kind.clone()))
            .copied()
            .unwrap_or(0);
        true_positives += actual.min(expected.count);
        if actual < expected.count {
            false_negatives += expected.count - actual;
            misses.push(expected.identity.clone());
        }
    }
    let forbidden: BTreeSet<_> = target.expected_absent.iter().cloned().collect();
    let unexpected: Vec<ObservationIdentity> = execution
        .observations
        .iter()
        .filter(|actual| {
            let identity = canonical_identity(&actual.identity);
            let evidence_matches = target.expected.iter().any(|expected| {
                expected.identity == identity && expected.evidence_kind == actual.evidence_kind
            });
            !expected_identities.contains(&identity)
                || !evidence_matches
                || forbidden.contains(&actual.identity)
                || forbidden.contains(&identity)
        })
        .map(|actual| actual.identity.clone())
        .collect();
    let false_positives = unexpected.len() as u32;
    TargetResult {
        target_id: target.id.clone(),
        status: if false_positives == 0 && false_negatives == 0 {
            TargetStatus::Passed
        } else {
            TargetStatus::Failed
        },
        true_positives,
        false_positives,
        false_negatives,
        runtime_ms: execution.runtime_ms,
        peak_memory_bytes: execution.peak_memory_bytes,
        misses,
        unexpected,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use oxaudit_domain::CreationMethod;

    use super::*;

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<BenchmarkState>>);

    impl BenchmarkStateStore for MemoryStore {
        fn load(&self, _suite_id: &str) -> Result<Option<BenchmarkState>, String> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn save_atomic(&self, state: &BenchmarkState) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(state.clone());
            Ok(())
        }
    }

    struct Executor;

    impl BenchmarkExecutor for Executor {
        fn execute(&self, target: &BenchmarkTarget) -> Result<ExecutionResult, String> {
            Ok(ExecutionResult {
                observations: target
                    .expected
                    .iter()
                    .flat_map(|expected| {
                        std::iter::repeat(ActualObservation {
                            identity: expected.identity.clone(),
                            evidence_kind: expected.evidence_kind.clone(),
                        })
                        .take(expected.count as usize)
                    })
                    .collect(),
                runtime_ms: 5,
                peak_memory_bytes: Some(1024),
            })
        }
    }

    fn suite() -> BenchmarkSuite {
        BenchmarkSuite {
            schema_version: 1,
            id: "source-smoke".into(),
            version: "1.0.0".into(),
            description: "Small deterministic contract fixture".into(),
            provenance: Provenance {
                authors: vec!["oxAudit contributors".into()],
                source: "repository fixture".into(),
                license: "Apache-2.0".into(),
                creation_method: CreationMethod::Authored,
                content_sha256: "a".repeat(64),
            },
            targets: vec![BenchmarkTarget {
                id: "positive-js".into(),
                input_path: "positive.js".into(),
                input_sha256: "b".repeat(64),
                platform: "any".into(),
                architecture: "any".into(),
                scanner_families: vec!["source-pattern".into()],
                language: Some("javascript".into()),
                expected: vec![ExpectedObservation {
                    identity: ObservationIdentity {
                        rule_id: "js-eval".into(),
                        artifact_path: "positive.js".into(),
                    },
                    count: 1,
                    evidence_kind: "file_location".into(),
                }],
                expected_absent: Vec::new(),
                allowed_variants: Vec::new(),
            }],
        }
    }

    #[test]
    fn runner_persists_after_each_phase_and_tallies_honestly() {
        let store = MemoryStore::default();
        let runner = BenchmarkRunner::new(&store, &Executor);
        let clock = std::sync::atomic::AtomicU64::new(10);
        let state = runner
            .run(&suite(), RunMode::Force, || {
                clock.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            })
            .unwrap();
        assert_eq!(state.metrics.corpus_targets, 1);
        assert_eq!(state.metrics.true_positives, 1);
        assert_eq!(state.metrics.precision, Some(1.0));
        assert_eq!(state.metrics.recall, Some(1.0));
        assert!(state.completed_at_ms.is_some());
    }

    #[test]
    fn resume_does_not_rerun_terminal_targets() {
        let store = MemoryStore::default();
        let runner = BenchmarkRunner::new(&store, &Executor);
        runner.run(&suite(), RunMode::Force, || 10).unwrap();
        let resumed = runner.run(&suite(), RunMode::Resume, || 20).unwrap();
        assert_eq!(resumed.results["positive-js"].runtime_ms, 5);
    }

    #[test]
    fn judge_reports_misses_and_unexpected_observations() {
        let target = &suite().targets[0];
        let result = judge(
            target,
            ExecutionResult {
                observations: vec![ActualObservation {
                    identity: ObservationIdentity {
                        rule_id: "unexpected".into(),
                        artifact_path: "positive.js".into(),
                    },
                    evidence_kind: "file_location".into(),
                }],
                runtime_ms: 1,
                peak_memory_bytes: None,
            },
        );
        assert_eq!(result.status, TargetStatus::Failed);
        assert_eq!((result.false_negatives, result.false_positives), (1, 1));
    }
}

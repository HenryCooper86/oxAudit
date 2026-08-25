//! Measures the scanners against the committed corpus.
//!
//! Shared by the command line and the Quality Lab screen, deliberately. Two
//! implementations would drift, and the desktop app was previously reporting a
//! different — and much weaker — corpus than the CLI and the README.
//!
//! The number this produces is the only defensible answer to "how accurate is
//! it?", so the runner is deliberately unflattering:
//!
//! * **Negatives count.** A corpus of positives measures recall and says
//!   nothing about the false positives that make a scanner unusable in
//!   practice. The corpus is majority negative on purpose, and every negative
//!   is a shape oxAudit was observed firing on incorrectly.
//! * **Collateral hits count.** When a rule fires on a fixture that belongs to
//!   a different rule, that is still a false positive on real content — it is
//!   reported rather than quietly ignored because no expectation named it.
//! * **Per-rule figures are reported, not just an average.** One rule with a
//!   3% precision hides inside a good aggregate, and hiding it is how a
//!   benchmark stops being useful.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One fixture, as recorded in `benchmarks/corpus/suite.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusTarget {
    pub id: String,
    pub input_path: String,
    pub input_sha256: String,
    pub language: Option<String>,
    pub scanner_families: Vec<String>,
    pub rule_id: String,
    pub expected: Vec<ExpectedRule>,
    pub expected_absent: Vec<AbsentRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedRule {
    pub rule_id: String,
    pub minimum: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbsentRule {
    pub rule_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusSuite {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub targets: Vec<CorpusTarget>,
}

/// Counts for one rule, or for the corpus as a whole.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
}

impl Counts {
    /// Of the things this rule flagged, how many should it have flagged?
    ///
    /// `None` when the rule flagged nothing at all: precision is undefined
    /// there, and reporting 0% or 100% would both be inventions.
    pub fn precision(&self) -> Option<f64> {
        let flagged = self.true_positives + self.false_positives;
        (flagged > 0).then(|| f64::from(self.true_positives) / f64::from(flagged))
    }

    /// Of the things this rule should have flagged, how many did it?
    pub fn recall(&self) -> Option<f64> {
        let present = self.true_positives + self.false_negatives;
        (present > 0).then(|| f64::from(self.true_positives) / f64::from(present))
    }

    /// The harmonic mean, so a rule cannot look good by sacrificing one side.
    pub fn f1(&self) -> Option<f64> {
        let (precision, recall) = (self.precision()?, self.recall()?);
        (precision + recall > 0.0).then(|| 2.0 * precision * recall / (precision + recall))
    }
}

/// A rule firing where nothing expected it — a false positive that no
/// expectation named, which is exactly the kind a corpus usually misses.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Collateral {
    pub rule_id: String,
    pub fixture: String,
    pub hits: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleReport {
    pub rule_id: String,
    #[serde(flatten)]
    pub counts: Counts,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkReport {
    pub suite_id: String,
    pub suite_version: String,
    pub fixtures: u32,
    #[serde(flatten)]
    pub totals: Counts,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub rules: Vec<RuleReport>,
    pub collateral: Vec<Collateral>,
    pub misses: Vec<String>,
    /// How many fixtures a grammar could parse. A precision figure means
    /// something different when part of the corpus was measured on text alone,
    /// so the split is reported rather than left implicit.
    pub syntax_analyzed_fixtures: u32,
    pub runtime_ms: u64,
}

#[derive(Debug)]
pub enum CorpusError {
    Unreadable(String),
    Malformed(String),
    /// A fixture's bytes no longer match the hash recorded for it, so the
    /// expectation attached to it may describe different content.
    HashMismatch {
        fixture: String,
    },
}

impl std::fmt::Display for CorpusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(what) => write!(f, "{what}"),
            Self::Malformed(what) => write!(f, "the corpus manifest is malformed: {what}"),
            Self::HashMismatch { fixture } => write!(
                f,
                "{fixture} does not match its recorded hash. The fixture changed without the \
                 manifest being rebuilt, so its expectation may no longer describe it. \
                 Run: node tools/build-corpus-suite.mjs"
            ),
        }
    }
}

pub fn load_suite(corpus_root: &Path) -> Result<CorpusSuite, CorpusError> {
    let manifest = corpus_root.join("suite.json");
    let text = std::fs::read_to_string(&manifest).map_err(|error| {
        CorpusError::Unreadable(format!("cannot read {}: {error}", manifest.display()))
    })?;
    serde_json::from_str(&text).map_err(|error| CorpusError::Malformed(error.to_string()))
}

/// Run every fixture and score the result, reading fixtures from disk.
pub fn run(corpus_root: &Path, suite: &CorpusSuite) -> Result<BenchmarkReport, CorpusError> {
    score(suite, |path| {
        std::fs::read(corpus_root.join(path))
            .map_err(|error| CorpusError::Unreadable(format!("cannot read {path}: {error}")))
    })
}

/// Grammars oxAudit has rules for but this build did not compile in.
///
/// Only the languages the corpus actually exercises, so the note names the
/// reason these particular numbers are lower rather than listing everything.
fn missing_grammars() -> Vec<&'static str> {
    const EXERCISED: [&str; 12] = [
        "javascript",
        "python",
        "java",
        "rust",
        "go",
        "php",
        "ruby",
        "c",
        "cpp",
        "csharp",
        "kotlin",
        "swift",
    ];
    let compiled = crate::scanners::syntax::compiled_grammars();
    EXERCISED
        .into_iter()
        .filter(|language| !compiled.contains(language))
        .collect()
}

/// Score a suite against fixtures supplied by `read_fixture`.
///
/// The indirection is what lets the packaged app score the same corpus as the
/// command line without shipping the repository alongside it.
pub fn score(
    suite: &CorpusSuite,
    mut read_fixture: impl FnMut(&str) -> Result<Vec<u8>, CorpusError>,
) -> Result<BenchmarkReport, CorpusError> {
    let started = std::time::Instant::now();

    let mut per_rule: BTreeMap<String, Counts> = BTreeMap::new();
    let mut totals = Counts::default();
    let mut collateral = Vec::new();
    let mut misses = Vec::new();
    let mut syntax_analyzed_fixtures = 0u32;

    // Only rules the corpus actually covers can be scored. A rule firing
    // outside that set is still recorded as collateral, but it is not silently
    // folded into a precision figure the corpus cannot support.
    let covered: BTreeSet<&str> = suite
        .targets
        .iter()
        .map(|target| target.rule_id.as_str())
        .collect();

    for target in &suite.targets {
        let content = read_fixture(&target.input_path)?;

        let digest = sha256_hex(&content);
        if digest != target.input_sha256 {
            return Err(CorpusError::HashMismatch {
                fixture: target.input_path.clone(),
            });
        }

        let text = String::from_utf8_lossy(&content);
        if crate::scanners::syntax::is_supported(target.language.as_deref().unwrap_or("")) {
            syntax_analyzed_fixtures += 1;
        }
        let hits = observe(&text, target);

        per_rule.entry(target.rule_id.clone()).or_default();

        for expectation in &target.expected {
            let count = hits.get(expectation.rule_id.as_str()).copied().unwrap_or(0);
            let entry = per_rule.entry(expectation.rule_id.clone()).or_default();
            if count >= expectation.minimum {
                entry.true_positives += 1;
                totals.true_positives += 1;
            } else {
                entry.false_negatives += 1;
                totals.false_negatives += 1;
                misses.push(target.id.clone());
            }
        }

        for absent in &target.expected_absent {
            let count = hits.get(absent.rule_id.as_str()).copied().unwrap_or(0);
            let entry = per_rule.entry(absent.rule_id.clone()).or_default();
            if count == 0 {
                // A negative that stays quiet is a true negative. It does not
                // raise precision on its own — only the absence of a false
                // positive does — so nothing is counted here.
            } else {
                entry.false_positives += 1;
                totals.false_positives += 1;
            }
        }

        // Anything that fired but was neither expected nor named absent.
        let named: BTreeSet<&str> = target
            .expected
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .chain(
                target
                    .expected_absent
                    .iter()
                    .map(|rule| rule.rule_id.as_str()),
            )
            .collect();
        for (rule_id, count) in &hits {
            if named.contains(rule_id.as_str()) {
                continue;
            }
            collateral.push(Collateral {
                rule_id: rule_id.clone(),
                fixture: target.input_path.clone(),
                hits: *count,
            });
            if covered.contains(rule_id.as_str()) {
                let entry = per_rule.entry(rule_id.clone()).or_default();
                entry.false_positives += 1;
                totals.false_positives += 1;
            }
        }
    }

    let rules = per_rule
        .into_iter()
        .map(|(rule_id, counts)| RuleReport {
            rule_id,
            precision: counts.precision(),
            recall: counts.recall(),
            f1: counts.f1(),
            counts,
        })
        .collect();

    collateral.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| left.fixture.cmp(&right.fixture))
    });
    misses.sort();

    Ok(BenchmarkReport {
        suite_id: suite.id.clone(),
        suite_version: suite.version.clone(),
        fixtures: suite.targets.len() as u32,
        precision: totals.precision(),
        recall: totals.recall(),
        f1: totals.f1(),
        totals,
        rules,
        collateral,
        misses,
        syntax_analyzed_fixtures,
        runtime_ms: started.elapsed().as_millis() as u64,
    })
}

/// Rule ids that fired on this fixture, with how many times.
fn observe(content: &str, target: &CorpusTarget) -> BTreeMap<String, u32> {
    let wants = |family: &str| target.scanner_families.iter().any(|f| f == family);
    let mut hits: BTreeMap<String, u32> = BTreeMap::new();
    for (rule_id, _evidence) in crate::scanners::benchmark_observations(
        content,
        target.language.as_deref().unwrap_or(""),
        wants("source-pattern"),
        wants("secret"),
    ) {
        *hits.entry(rule_id.to_string()).or_default() += 1;
    }
    hits
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The corpus, compiled into the binary.
///
/// The Quality Lab screen has to score the same fixtures the command line and
/// the README report, and a packaged desktop app has no repository to read
/// them from. Embedding is what keeps the two answers the same number.
static CORPUS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../benchmarks/corpus");

/// Load the embedded suite.
pub fn embedded_suite() -> Result<CorpusSuite, CorpusError> {
    let manifest = CORPUS
        .get_file("suite.json")
        .ok_or_else(|| CorpusError::Unreadable("the embedded corpus has no suite.json".into()))?;
    let text = manifest
        .contents_utf8()
        .ok_or_else(|| CorpusError::Malformed("suite.json is not UTF-8".into()))?;
    serde_json::from_str(text).map_err(|error| CorpusError::Malformed(error.to_string()))
}

/// Score the embedded corpus.
pub fn run_embedded(suite: &CorpusSuite) -> Result<BenchmarkReport, CorpusError> {
    score(suite, |path| {
        CORPUS
            .get_file(path)
            .map(|file| file.contents().to_vec())
            .ok_or_else(|| {
                CorpusError::Unreadable(format!("{path} is missing from the embedded corpus"))
            })
    })
}

/// Render the report the way a person reads it: the aggregate first, then the
/// rules that are dragging it down, then what was missed.
pub fn render_text(report: &BenchmarkReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let percent = |value: Option<f64>| match value {
        Some(value) => format!("{:>6.1}%", value * 100.0),
        None => "     —".to_string(),
    };

    let _ = writeln!(
        out,
        "{} {}  —  {} fixtures in {} ms\n",
        report.suite_id, report.suite_version, report.fixtures, report.runtime_ms
    );
    let _ = writeln!(
        out,
        "  precision {}   recall {}   F1 {}",
        percent(report.precision),
        percent(report.recall),
        percent(report.f1)
    );
    let _ = writeln!(
        out,
        "  {} true positive(s), {} false positive(s), {} false negative(s)",
        report.totals.true_positives, report.totals.false_positives, report.totals.false_negatives
    );
    let _ = writeln!(
        out,
        "  {} of {} fixtures had a grammar; the rest were measured on text alone",
        report.syntax_analyzed_fixtures, report.fixtures
    );
    // A grammar left out at build time lowers precision here, and the numbers
    // alone give no hint that the cause is the binary rather than the rules.
    let missing = missing_grammars();
    if missing.is_empty() {
        let _ = writeln!(out);
    } else {
        let _ = writeln!(
            out,
            "  built without {}: those fixtures score on text alone\n",
            missing.join(", ")
        );
    }

    let _ = writeln!(
        out,
        "{:<26} {:>4} {:>4} {:>4}  {:>8} {:>8} {:>8}",
        "RULE", "TP", "FP", "FN", "PREC", "RECALL", "F1"
    );
    let _ = writeln!(out, "{}", "-".repeat(70));

    // Worst precision first: the point of the table is to find what to fix.
    let mut rules = report.rules.clone();
    rules.sort_by(|left, right| {
        left.precision
            .unwrap_or(f64::MAX)
            .partial_cmp(&right.precision.unwrap_or(f64::MAX))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    for rule in &rules {
        let _ = writeln!(
            out,
            "{:<26} {:>4} {:>4} {:>4}  {} {} {}",
            rule.rule_id,
            rule.counts.true_positives,
            rule.counts.false_positives,
            rule.counts.false_negatives,
            percent(rule.precision),
            percent(rule.recall),
            percent(rule.f1)
        );
    }

    if !report.misses.is_empty() {
        let _ = writeln!(out, "\nMissed ({}):", report.misses.len());
        for miss in &report.misses {
            let _ = writeln!(out, "  {miss}");
        }
    }

    if !report.collateral.is_empty() {
        let _ = writeln!(
            out,
            "\nFired where nothing expected it ({}):",
            report.collateral.len()
        );
        for hit in &report.collateral {
            let _ = writeln!(out, "  {:<24} {} ({}x)", hit.rule_id, hit.fixture, hit.hits);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_is_undefined_rather_than_zero_when_nothing_fired() {
        // Reporting 0% for a rule that flagged nothing would say it was wrong
        // every time it spoke; reporting 100% would say it was never wrong.
        // Both are inventions.
        let counts = Counts::default();
        assert_eq!(counts.precision(), None);
        assert_eq!(counts.recall(), None);
        assert_eq!(counts.f1(), None);
    }

    #[test]
    fn precision_and_recall_measure_different_failures() {
        let counts = Counts {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 1,
        };
        assert_eq!(counts.precision(), Some(0.75));
        assert_eq!(counts.recall(), Some(0.75));
    }

    #[test]
    fn a_rule_that_flags_everything_scores_badly_on_precision() {
        // The shape of generic-password before it was fixed: it caught the
        // real case and a great many others.
        let counts = Counts {
            true_positives: 1,
            false_positives: 99,
            false_negatives: 0,
        };
        assert_eq!(counts.precision(), Some(0.01));
        assert_eq!(counts.recall(), Some(1.0));
        assert!(counts.f1().unwrap() < 0.02, "F1 must not hide it");
    }

    #[test]
    fn a_rule_that_flags_nothing_scores_badly_on_recall() {
        let counts = Counts {
            true_positives: 0,
            false_positives: 0,
            false_negatives: 10,
        };
        assert_eq!(counts.recall(), Some(0.0));
        assert_eq!(counts.precision(), None);
    }

    #[test]
    fn f1_needs_both_sides_to_be_defined() {
        let counts = Counts {
            true_positives: 0,
            false_positives: 5,
            false_negatives: 0,
        };
        assert_eq!(counts.precision(), Some(0.0));
        assert_eq!(counts.recall(), None);
        assert_eq!(counts.f1(), None);
    }

    #[test]
    fn the_committed_corpus_loads_and_every_fixture_matches_its_hash() {
        // Also the guard that a fixture edited without rebuilding the manifest
        // fails here rather than silently changing what the numbers mean.
        let root = corpus_root();
        let suite = load_suite(&root).expect("corpus manifest loads");
        assert!(!suite.targets.is_empty());
        let report = run(&root, &suite).expect("every fixture matches its recorded hash");
        assert_eq!(report.fixtures as usize, suite.targets.len());
    }

    #[test]
    fn the_corpus_carries_more_negatives_than_positives() {
        // A corpus of positives measures recall and says nothing about the
        // false positives that decide whether anyone keeps using the tool.
        let suite = load_suite(&corpus_root()).expect("corpus manifest loads");
        let positives = suite
            .targets
            .iter()
            .filter(|target| !target.expected.is_empty())
            .count();
        let negatives = suite
            .targets
            .iter()
            .filter(|target| !target.expected_absent.is_empty())
            .count();
        assert!(
            negatives > positives,
            "corpus has {positives} positives and {negatives} negatives"
        );
    }

    fn corpus_root() -> std::path::PathBuf {
        // CARGO_MANIFEST_DIR is src-tauri/; the corpus lives beside it.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("benchmarks/corpus")
    }

    #[test]
    fn the_embedded_corpus_matches_the_one_on_disk() {
        // The desktop app scores an embedded copy and the command line scores
        // the directory. When those drifted, the app reported ten fixtures
        // while the CLI and the README reported fifty — two answers to one
        // question, with no error anywhere.
        let disk = load_suite(&corpus_root()).expect("corpus on disk");
        let embedded = embedded_suite().expect("embedded corpus");

        assert_eq!(embedded.id, disk.id);
        assert_eq!(embedded.version, disk.version);
        assert_eq!(embedded.targets.len(), disk.targets.len());

        let ids = |suite: &CorpusSuite| {
            suite
                .targets
                .iter()
                .map(|target| target.id.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(ids(&embedded), ids(&disk));
    }

    #[test]
    fn both_paths_score_the_corpus_identically() {
        // Same fixtures is not enough; the numbers a user reads have to agree.
        let disk = load_suite(&corpus_root()).expect("corpus on disk");
        let from_disk = run(&corpus_root(), &disk).expect("scored from disk");
        let from_embedded = run_embedded(&embedded_suite().expect("embedded")).expect("scored");

        assert_eq!(from_disk.totals, from_embedded.totals);
        assert_eq!(from_disk.precision, from_embedded.precision);
        assert_eq!(from_disk.recall, from_embedded.recall);
        assert_eq!(from_disk.misses, from_embedded.misses);
    }

    #[test]
    fn every_embedded_fixture_matches_its_recorded_hash() {
        // The embedded copy is verified the same way the on-disk one is: a
        // fixture that changed without the manifest being rebuilt would
        // otherwise be scored against an expectation that no longer describes
        // it.
        let suite = embedded_suite().expect("embedded corpus");
        run_embedded(&suite).expect("every embedded fixture matches its hash");
    }
}

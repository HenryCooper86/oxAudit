//! Scoring oxAudit against ground truth nobody here wrote.
//!
//! The committed corpus in `benchmarks/corpus/` is written by the same people
//! who write the rules, so it answers "does it still do what we meant?" and
//! cannot answer "is it any good?". That is not a flaw in the corpus — it is
//! what a regression suite is for — but it does mean 100% on it proves less
//! than the number suggests.
//!
//! The [OWASP Benchmark](https://owasp.org/www-project-benchmark/) is the
//! counterweight: 2,740 generated Java servlets, each labelled vulnerable or
//! safe by the project that generated them, covering eleven weakness classes.
//! It is fetched rather than vendored — it is GPL-2.0 and 239MB — so this
//! module reads whatever `tools/fetch-external-benchmark.mjs` put on disk.
//!
//! Two things about the result are worth stating before the number is:
//!
//! * **oxAudit has rules for six of the eleven categories.** Scoring the other
//!   five would measure absent rules, not inaccurate ones, so they are counted
//!   and reported separately rather than folded into one average that hides
//!   which is which.
//! * **The Benchmark is built for interprocedural taint analysis.** Its test
//!   cases route a value from a request through helper methods and back. Every
//!   README caveat about this analysis being intraprocedural is exactly what
//!   this score measures the cost of.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// One labelled test case.
#[derive(Debug, Clone)]
pub struct ExpectedCase {
    pub name: String,
    pub category: String,
    /// True when the generator planted a real vulnerability here.
    pub vulnerable: bool,
    pub cwe: u32,
}

#[derive(Debug)]
pub enum ExternalError {
    Missing(PathBuf),
    Unreadable(String),
    Malformed(String),
}

impl fmt::Display for ExternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalError::Missing(path) => write!(
                f,
                "no OWASP Benchmark at {}\n\nFetch it with:\n  node tools/fetch-external-benchmark.mjs",
                path.display()
            ),
            ExternalError::Unreadable(message) => write!(f, "{message}"),
            ExternalError::Malformed(message) => write!(f, "{message}"),
        }
    }
}

/// Which oxAudit CWE answers a Benchmark category.
///
/// Not an identity mapping, because the two vocabularies disagree in places
/// that are real rather than clerical: the Benchmark files weak hashes under
/// CWE-328 (reversible one-way hash) where oxAudit reports the broader
/// CWE-327 (broken crypto algorithm), and files predictable randomness under
/// CWE-330 (insufficiently random values) where oxAudit reports the narrower
/// CWE-338 (cryptographically weak PRNG). Treating a near-miss as a miss would
/// understate accuracy for a naming difference.
const CWE_EQUIVALENTS: &[(u32, &[&str])] = &[
    (22, &["CWE-22"]),
    (78, &["CWE-78"]),
    (79, &["CWE-79"]),
    (89, &["CWE-89"]),
    (90, &["CWE-90"]),
    (327, &["CWE-327"]),
    (328, &["CWE-328", "CWE-327"]),
    (330, &["CWE-330", "CWE-338"]),
    (501, &["CWE-501"]),
    (614, &["CWE-614"]),
    (643, &["CWE-643"]),
];

fn accepts(benchmark_cwe: u32, reported: &str) -> bool {
    CWE_EQUIVALENTS
        .iter()
        .find(|(cwe, _)| *cwe == benchmark_cwe)
        .is_some_and(|(_, accepted)| accepted.contains(&reported))
}

/// Does oxAudit carry any rule that could answer this category?
///
/// Asked of the rule table rather than hard-coded, so adding a Java LDAP rule
/// moves a category from "not covered" to "covered" without editing this file
/// — and so the coverage line can never drift from what actually ships.
fn covered(benchmark_cwe: u32) -> bool {
    crate::scanners::patterns::SOURCE_RULES.iter().any(|rule| {
        rule.languages.contains(&"java") && !rule.cwe.is_empty() && accepts(benchmark_cwe, rule.cwe)
    })
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub true_positives: u32,
    pub false_positives: u32,
    pub true_negatives: u32,
    pub false_negatives: u32,
}

impl Counts {
    fn record(&mut self, vulnerable: bool, flagged: bool) {
        match (vulnerable, flagged) {
            (true, true) => self.true_positives += 1,
            (true, false) => self.false_negatives += 1,
            (false, true) => self.false_positives += 1,
            (false, false) => self.true_negatives += 1,
        }
    }

    pub fn cases(&self) -> u32 {
        self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
    }

    /// Of everything reported here, how much was real?
    pub fn precision(&self) -> Option<f64> {
        let flagged = self.true_positives + self.false_positives;
        (flagged > 0).then(|| f64::from(self.true_positives) / f64::from(flagged))
    }

    /// True positive rate — of everything real, how much was reported?
    pub fn recall(&self) -> Option<f64> {
        let real = self.true_positives + self.false_negatives;
        (real > 0).then(|| f64::from(self.true_positives) / f64::from(real))
    }

    /// False positive rate — of everything safe, how much was reported anyway?
    pub fn false_positive_rate(&self) -> Option<f64> {
        let safe = self.false_positives + self.true_negatives;
        (safe > 0).then(|| f64::from(self.false_positives) / f64::from(safe))
    }

    /// The Benchmark's own score: recall minus false positive rate.
    ///
    /// Zero is what guessing achieves — a tool that flags everything scores the
    /// same as one that flags nothing. That is the point of the metric, and it
    /// is why recall alone is not a result.
    pub fn youden_index(&self) -> Option<f64> {
        Some(self.recall()? - self.false_positive_rate()?)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub cwe: u32,
    /// False when oxAudit has no Java rule for this weakness class at all.
    pub covered: bool,
    #[serde(flatten)]
    pub counts: Counts,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReport {
    pub suite: String,
    pub cases: u32,
    /// Totals over the categories oxAudit has rules for.
    pub covered_totals: Counts,
    /// Totals over the categories it does not, kept separate so an average
    /// cannot quietly blend "wrong" with "absent".
    pub uncovered_totals: Counts,
    pub categories: Vec<CategoryScore>,
    pub runtime_ms: u64,
}

/// Read the Benchmark's ground-truth CSV.
pub fn load_expectations(root: &Path) -> Result<Vec<ExpectedCase>, ExternalError> {
    let csv = root.join("expectedresults-1.2.csv");
    if !csv.exists() {
        return Err(ExternalError::Missing(root.to_path_buf()));
    }
    let text = std::fs::read_to_string(&csv).map_err(|error| {
        ExternalError::Unreadable(format!("cannot read {}: {error}", csv.display()))
    })?;

    let mut cases = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        // The first line is a header carrying the suite version as a comment.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 4 {
            return Err(ExternalError::Malformed(format!(
                "{}:{}: expected 4 fields, found {}",
                csv.display(),
                index + 1,
                fields.len()
            )));
        }
        let cwe = fields[3].parse::<u32>().map_err(|_| {
            ExternalError::Malformed(format!(
                "{}:{}: {:?} is not a CWE number",
                csv.display(),
                index + 1,
                fields[3]
            ))
        })?;
        cases.push(ExpectedCase {
            name: fields[0].to_string(),
            category: fields[1].to_string(),
            vulnerable: fields[2].eq_ignore_ascii_case("true"),
            cwe,
        });
    }

    if cases.is_empty() {
        return Err(ExternalError::Malformed(format!(
            "{} contained no test cases",
            csv.display()
        )));
    }
    Ok(cases)
}

/// Every `.properties` file directly inside `directory`.
fn properties_files(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "properties"))
        .collect()
}

/// Score every labelled case by running the real scanner over its source.
pub fn score(root: &Path, cases: &[ExpectedCase]) -> Result<ExternalReport, ExternalError> {
    let started = std::time::Instant::now();
    let sources = root.join("src/main/java/org/owasp/benchmark/testcode");
    if !sources.is_dir() {
        return Err(ExternalError::Missing(root.to_path_buf()));
    }

    // The benchmark's servlets read algorithm names out of
    // `src/main/resources/benchmark.properties`, which is part of the
    // application being scored. A real scan indexes whatever the target
    // configures; this indexes the same thing for the same reason.
    let config = crate::scanners::config_values::ProjectConfig::from_paths(
        properties_files(&root.join("src/main/resources"))
            .iter()
            .map(PathBuf::as_path),
    );

    let mut per_category: BTreeMap<String, CategoryScore> = BTreeMap::new();

    for case in cases {
        let path = sources.join(format!("{}.java", case.name));
        if !path.exists() {
            return Err(ExternalError::Missing(path));
        }
        let outcome = crate::scanners::scan_file_in_project(
            &path,
            &format!("{}.java", case.name),
            // The generated servlets are a few kilobytes; this is headroom.
            1024,
            false,
            true,
            &config,
        );
        let flagged = outcome.findings.iter().any(|finding| {
            finding
                .cwe
                .as_deref()
                .is_some_and(|cwe| accepts(case.cwe, cwe))
        });

        let entry = per_category
            .entry(case.category.clone())
            .or_insert_with(|| CategoryScore {
                category: case.category.clone(),
                cwe: case.cwe,
                covered: covered(case.cwe),
                counts: Counts::default(),
            });
        entry.counts.record(case.vulnerable, flagged);
    }

    let mut covered_totals = Counts::default();
    let mut uncovered_totals = Counts::default();
    for score in per_category.values() {
        let totals = if score.covered {
            &mut covered_totals
        } else {
            &mut uncovered_totals
        };
        totals.true_positives += score.counts.true_positives;
        totals.false_positives += score.counts.false_positives;
        totals.true_negatives += score.counts.true_negatives;
        totals.false_negatives += score.counts.false_negatives;
    }

    Ok(ExternalReport {
        suite: "OWASP Benchmark 1.2".to_string(),
        cases: cases.len() as u32,
        covered_totals,
        uncovered_totals,
        categories: per_category.into_values().collect(),
        runtime_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a miniature corpus shaped like the real one.
    ///
    /// The real Benchmark is 239MB and fetched on demand, so it cannot be a
    /// test dependency. What these tests cover is the scoring arithmetic and
    /// the CSV contract, which is where a silent mistake would misreport a
    /// published number.
    fn corpus(cases: &[(&str, &str, bool, u32, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temporary corpus");
        let sources = dir
            .path()
            .join("src/main/java/org/owasp/benchmark/testcode");
        std::fs::create_dir_all(&sources).expect("source tree");
        let mut csv = String::from("# test name, category, real vulnerability, cwe\n");
        for (name, category, vulnerable, cwe, body) in cases {
            csv.push_str(&format!("{name},{category},{vulnerable},{cwe}\n"));
            std::fs::write(sources.join(format!("{name}.java")), body).expect("case source");
        }
        std::fs::write(dir.path().join("expectedresults-1.2.csv"), csv).expect("csv");
        dir
    }

    const VULNERABLE_EXEC: &str =
        "class T { void f(javax.servlet.http.HttpServletRequest request) throws Exception {\n\
         String cmd = request.getParameter(\"c\");\n\
         Runtime.getRuntime().exec(cmd);\n} }\n";
    const SAFE_EXEC: &str =
        "class T { void f() throws Exception {\n Runtime.getRuntime().exec(\"ls -la\");\n} }\n";

    #[test]
    fn a_reported_vulnerability_counts_as_a_true_positive() {
        let dir = corpus(&[("BenchmarkTest00001", "cmdi", true, 78, VULNERABLE_EXEC)]);
        let cases = load_expectations(dir.path()).expect("expectations");
        let report = score(dir.path(), &cases).expect("score");
        assert_eq!(report.covered_totals.true_positives, 1);
        assert_eq!(report.covered_totals.false_negatives, 0);
    }

    #[test]
    fn a_safe_case_left_alone_counts_as_a_true_negative() {
        let dir = corpus(&[("BenchmarkTest00002", "cmdi", false, 78, SAFE_EXEC)]);
        let cases = load_expectations(dir.path()).expect("expectations");
        let report = score(dir.path(), &cases).expect("score");
        assert_eq!(report.covered_totals.true_negatives, 1);
        assert_eq!(report.covered_totals.false_positives, 0);
    }

    #[test]
    fn categories_without_a_rule_are_counted_apart() {
        // An absent rule is a coverage fact, not an accuracy one. Folding
        // XPath injection into the headline would report oxAudit as inaccurate
        // about something it never claimed to detect.
        let dir = corpus(&[
            ("BenchmarkTest00001", "cmdi", true, 78, VULNERABLE_EXEC),
            // CWE-1004 is not a category the Benchmark scores and oxAudit
            // has no rule for it, so it stands in for "no rule" now that every
            // category the Benchmark does score has one.
            ("BenchmarkTest00003", "httponly", true, 1004, "class T {}\n"),
        ]);
        let cases = load_expectations(dir.path()).expect("expectations");
        let report = score(dir.path(), &cases).expect("score");
        assert_eq!(report.covered_totals.cases(), 1);
        assert_eq!(report.uncovered_totals.cases(), 1);
        assert_eq!(report.uncovered_totals.false_negatives, 1);
        let uncovered = report
            .categories
            .iter()
            .find(|score| score.category == "httponly")
            .expect("httponly scored");
        assert!(!uncovered.covered);
    }

    #[test]
    fn the_youden_index_is_zero_for_a_tool_that_cannot_discriminate() {
        // Flagging everything and flagging nothing both score zero. This is
        // why recall alone is not reported as the result.
        let flag_all = Counts {
            true_positives: 10,
            false_positives: 10,
            true_negatives: 0,
            false_negatives: 0,
        };
        assert_eq!(flag_all.youden_index(), Some(0.0));
        let flag_none = Counts {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 10,
            false_negatives: 10,
        };
        assert_eq!(flag_none.youden_index(), Some(0.0));
    }

    #[test]
    fn a_near_miss_cwe_is_accepted_rather_than_scored_as_wrong() {
        // The Benchmark files weak hashes under CWE-328 and oxAudit reports
        // CWE-327; predictable randomness is CWE-330 there and CWE-338 here.
        // Both are naming differences, not disagreements about the finding.
        assert!(accepts(328, "CWE-327"));
        assert!(accepts(330, "CWE-338"));
        assert!(!accepts(89, "CWE-78"));
    }

    #[test]
    fn coverage_is_read_from_the_rule_table_not_hard_coded() {
        // So that adding a Java LDAP rule moves the category without anyone
        // remembering to edit this file.
        // Every category the Benchmark scores now has a rule, and each of
        // these moved from uncovered to covered without this file being
        // edited — which is the point of reading the rule table.
        for cwe in [22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643] {
            assert!(covered(cwe), "CWE-{cwe} should have a Java rule");
        }
        // A weakness oxAudit carries no rule for still reads as uncovered, so
        // the lookup is discriminating rather than answering yes to anything.
        assert!(!covered(1004), "oxAudit has no HttpOnly rule");
    }

    #[test]
    fn a_missing_corpus_says_how_to_fetch_it() {
        let dir = tempfile::tempdir().expect("empty directory");
        let error = load_expectations(dir.path()).expect_err("no corpus");
        assert!(error.to_string().contains("fetch-external-benchmark"));
    }
}

//! Comparing a scan against a previous one.
//!
//! Adopting a scanner on an existing codebase means meeting a backlog. A team
//! that cannot merge until the backlog is clear will not adopt the scanner;
//! they will turn it off. The way through is to gate on what a change
//! *introduces* and leave the rest visible but non-blocking.
//!
//! In a pipeline the previous scan is an artifact, not a database — so the
//! baseline here is a report file rather than a stored run. `oxaudit-cli scan .
//! --baseline previous.json --fail-on-new high` is the whole workflow.
//!
//! Findings are matched on `(fingerprintVersion, fingerprint)`, the same
//! identity the durable pipeline uses, so a finding that merely moved down the
//! file is not reported as new.

use std::collections::BTreeSet;
use std::path::Path;

use crate::models::Finding;

/// Identity of a finding across runs.
type Identity = (u16, String);

fn identity(finding: &Finding) -> Identity {
    (finding.fingerprint_version, finding.fingerprint.clone())
}

/// What changed between a baseline and the current scan.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    /// Present now, absent from the baseline.
    pub introduced: Vec<Finding>,
    /// Present in both.
    pub unchanged: Vec<Finding>,
    /// Present in the baseline, absent now.
    ///
    /// Report files do not prove compatible coverage. This is unverified
    /// absence, including skipped and deleted files, never a resolution.
    pub no_longer_observed: Vec<Finding>,
}

impl Comparison {
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.introduced.len(),
            self.unchanged.len(),
            self.no_longer_observed.len(),
        )
    }
}

#[derive(Debug)]
pub enum BaselineError {
    Unreadable(String),
    Malformed(String),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(what) => write!(f, "the baseline could not be read: {what}"),
            Self::Malformed(what) => write!(
                f,
                "the baseline is not an oxAudit JSON report: {what}. Produce one with \
                 `oxaudit-cli scan <path> --format json --output baseline.json`."
            ),
        }
    }
}

/// Read the findings out of a previous `--format json` report.
///
/// Only the findings are needed, so a report from an older version with extra
/// or missing summary fields still works — a baseline that stops parsing after
/// an upgrade would silently turn every finding back into a new one, which is
/// the failure mode most likely to make a team stop trusting the gate.
pub fn load(path: &Path) -> Result<Vec<Finding>, BaselineError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| BaselineError::Unreadable(format!("{}: {error}", path.display())))?;
    let document: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| BaselineError::Malformed(error.to_string()))?;
    let findings = document
        .get("findings")
        .ok_or_else(|| BaselineError::Malformed("no `findings` array".to_string()))?;
    let loaded: Vec<Finding> = serde_json::from_value(findings.clone())
        .map_err(|error| BaselineError::Malformed(error.to_string()))?;
    if loaded.iter().any(|finding| {
        finding.fingerprint_version == 0
            || finding.fingerprint.trim().is_empty()
            || finding
                .fingerprint
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
    }) {
        return Err(BaselineError::Malformed(
            "missing or invalid finding identity".into(),
        ));
    }
    Ok(loaded)
}

/// Compare the current findings against a baseline.
pub fn compare(baseline: &[Finding], current: &[Finding]) -> Comparison {
    let baseline_ids: BTreeSet<Identity> = baseline.iter().map(identity).collect();
    let current_ids: BTreeSet<Identity> = current.iter().map(identity).collect();

    let mut comparison = Comparison::default();
    for finding in current {
        if baseline_ids.contains(&identity(finding)) {
            comparison.unchanged.push(finding.clone());
        } else {
            comparison.introduced.push(finding.clone());
        }
    }
    for finding in baseline {
        if !current_ids.contains(&identity(finding)) {
            comparison.no_longer_observed.push(finding.clone());
        }
    }
    comparison
}

/// A one-line summary for the terminal.
pub fn describe(comparison: &Comparison) -> String {
    let (introduced, unchanged, resolved) = comparison.counts();
    format!("{introduced} new, {unchanged} pre-existing, {resolved} no longer observed (coverage unverified)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fingerprint: &str, severity: &str) -> Finding {
        Finding {
            id: fingerprint.into(),
            category: "vulnerability".into(),
            rule_id: "js-eval".into(),
            rule_name: "eval() usage".into(),
            severity: severity.into(),
            title: "eval() usage".into(),
            description: String::new(),
            file_path: format!("src/{fingerprint}.js"),
            line: 1,
            column: 1,
            match_text: "eval(".into(),
            context: String::new(),
            language: "javascript".into(),
            cwe: Some("CWE-95".into()),
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: String::new(),
            entropy: None,
            verified: None,
            analysis: Default::default(),
            analysis_gates: Vec::new(),
            observation_run_id: "run".into(),
            resolved_by_run_id: None,
            fingerprint_version: 1,
            fingerprint: fingerprint.into(),
            in_test_region: false,
            scope: None,
            scope_reason: None,
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    #[test]
    fn a_finding_present_in_both_is_pre_existing() {
        let baseline = vec![finding("a", "high")];
        let current = vec![finding("a", "high")];
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.counts(), (0, 1, 0));
    }

    #[test]
    fn a_finding_absent_from_the_baseline_is_new() {
        let comparison = compare(
            &[finding("a", "high")],
            &[finding("a", "high"), finding("b", "high")],
        );
        assert_eq!(comparison.counts(), (1, 1, 0));
        assert_eq!(comparison.introduced[0].fingerprint, "b");
    }

    #[test]
    fn a_skipped_or_deleted_finding_is_only_no_longer_observed() {
        // Not dropped: a finding disappearing is usually a fix and sometimes a
        // file that stopped being scanned, and those want different responses.
        let comparison = compare(
            &[finding("a", "high"), finding("b", "high")],
            &[finding("a", "high")],
        );
        assert_eq!(comparison.counts(), (0, 1, 1));
        assert_eq!(comparison.no_longer_observed[0].fingerprint, "b");
    }

    #[test]
    fn an_empty_baseline_makes_everything_new() {
        // The first run against no baseline must not silently report a clean
        // comparison.
        let comparison = compare(&[], &[finding("a", "high"), finding("b", "low")]);
        assert_eq!(comparison.counts(), (2, 0, 0));
    }

    #[test]
    fn an_empty_scan_does_not_prove_resolution() {
        let comparison = compare(&[finding("a", "high")], &[]);
        assert_eq!(comparison.counts(), (0, 0, 1));
    }

    #[test]
    fn identity_includes_the_fingerprint_version() {
        // A fingerprint scheme change must not be read as "everything was
        // fixed and an identical set was introduced" — it is a different
        // identity, and the counts have to say so rather than quietly pairing
        // findings computed under different rules.
        let mut old = finding("a", "high");
        old.fingerprint_version = 1;
        let mut new = finding("a", "high");
        new.fingerprint_version = 2;

        let comparison = compare(std::slice::from_ref(&old), std::slice::from_ref(&new));
        assert_eq!(comparison.counts(), (1, 0, 1));
    }

    #[test]
    fn a_moved_finding_is_not_reported_as_new() {
        // The fingerprint is context-based rather than line-based, so inserting
        // a line above a finding must not resurface it as introduced.
        let mut moved = finding("a", "high");
        moved.line = 42;
        let comparison = compare(&[finding("a", "high")], &[moved]);
        assert_eq!(comparison.counts(), (0, 1, 0));
    }

    #[test]
    fn the_summary_names_all_three_counts() {
        let comparison = compare(&[finding("a", "high")], &[finding("b", "high")]);
        assert_eq!(
            describe(&comparison),
            "1 new, 0 pre-existing, 1 no longer observed (coverage unverified)"
        );
    }

    #[test]
    fn a_baseline_report_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("baseline.json");
        let report = serde_json::json!({
            "summary": { "path": "/tmp/project" },
            "findings": [finding("a", "high")],
        });
        std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

        let loaded = load(&path).expect("baseline loads");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].fingerprint, "a");
    }

    #[test]
    fn a_baseline_with_no_findings_array_is_refused_with_a_usable_message() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wrong.json");
        std::fs::write(&path, r#"{"runs":[]}"#).unwrap();

        let error = load(&path).expect_err("a SARIF file is not a baseline");
        let message = error.to_string();
        // Naming the command that produces one is the difference between an
        // error and a dead end.
        assert!(message.contains("--format json"), "{message}");
    }

    #[test]
    fn a_missing_baseline_is_refused_rather_than_treated_as_empty() {
        // Treating a missing baseline as empty would make every finding new and
        // fail the build for a typo in a path.
        let error = load(Path::new("/definitely/not/here.json")).expect_err("must refuse");
        assert!(matches!(error, BaselineError::Unreadable(_)));
    }
    #[test]
    fn empty_matching_identity_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("baseline.json");
        std::fs::write(
            &path,
            serde_json::json!({"findings": [finding("", "high")]}).to_string(),
        )
        .unwrap();
        assert!(load(&path).is_err());
    }
    #[test]
    fn legacy_shape_cannot_silently_default_matching_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("baseline.json");
        for field in ["fingerprint", "fingerprintVersion"] {
            let mut record = serde_json::to_value(finding("a", "high")).unwrap();
            record.as_object_mut().unwrap().remove(field);
            std::fs::write(&path, serde_json::json!({"findings": [record]}).to_string()).unwrap();
            assert!(load(&path).is_err(), "{field}");
        }
    }
}

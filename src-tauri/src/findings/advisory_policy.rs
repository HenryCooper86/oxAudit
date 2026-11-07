//! The committed advisory policy: `.oxaudit/advisory-policy.json`.
//!
//! `policy.json` dismisses source and secret findings by fingerprint. A
//! dependency or image advisory has no source fingerprint; it is named by its
//! advisory id (or any alias) and optionally narrowed to one package,
//! ecosystem and installed version. A dismissed advisory is still reported
//! everywhere, carrying its review, but it no longer gates the build.
//!
//! It is a separate file, not a new entry kind in `policy.json`, because
//! `policy.json` has a closed schema: an older oxAudit treats an entry kind it
//! does not know as an invalid policy and refuses to run source scans, so a
//! CLI pinned in CI would break the moment the file gained one.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::domain::ReviewState;

/// Where the policy lives, relative to the project root.
pub const ADVISORY_POLICY_PATH: &str = ".oxaudit/advisory-policy.json";
const FILE_NAME: &str = "advisory-policy.json";
/// The same cap `policy.json` has.
const MAX_ADVISORY_POLICY_BYTES: u64 = 1024 * 1024;

/// Why an advisory was dismissed, as it travels with the vulnerability into
/// stored runs, JSON, SARIF and the app.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryReview {
    pub state: ReviewState,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// What loading the policy produced.
#[derive(Debug)]
pub enum AdvisoryPolicyStatus {
    Missing,
    Loaded(AdvisoryPolicy),
    /// The file exists but cannot be used, with the reason to show.
    Invalid(String),
}

/// A validated advisory policy.
#[derive(Debug, Default)]
pub struct AdvisoryPolicy {
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    advisory: String,
    package: Option<String>,
    ecosystem: Option<String>,
    version: Option<String>,
    review: AdvisoryReview,
    expires_at: Option<DateTime<Utc>>,
}

/// One reported advisory, as the policy sees it.
#[derive(Debug)]
pub struct AdvisorySubject<'a> {
    /// The advisory id and every alias.
    pub ids: Vec<&'a str>,
    /// The package's ecosystem, when the finding knows it (dependencies do,
    /// image components do not).
    pub ecosystem: Option<&'a str>,
    pub package: &'a str,
    pub version: &'a str,
}

/// The policy's answer for one advisory.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Dismissed(AdvisoryReview),
    /// Only expired entries matched: the advisory gates again.
    Expired,
    None,
}

/// Load `<project_root>/.oxaudit/advisory-policy.json`, opened the same
/// hardened way as `policy.json` (no symlinks, regular files only, size
/// checked before reading).
pub fn load_project_advisory_policy(project_root: &Path) -> AdvisoryPolicyStatus {
    match super::policy::read_project_file(project_root, FILE_NAME, MAX_ADVISORY_POLICY_BYTES) {
        Ok(None) => AdvisoryPolicyStatus::Missing,
        Ok(Some(bytes)) => parse(&bytes),
        Err(error) => AdvisoryPolicyStatus::Invalid(error.message().to_string()),
    }
}

/// Load an advisory policy from an explicit path (`--advisory-policy`).
pub fn load_advisory_policy_file(path: &Path) -> AdvisoryPolicyStatus {
    match super::policy::read_regular_file(path, MAX_ADVISORY_POLICY_BYTES, true) {
        Ok(bytes) => parse(&bytes),
        Err(error) => AdvisoryPolicyStatus::Invalid(error.message().to_string()),
    }
}

/// Parse and validate policy bytes.
fn parse(bytes: &[u8]) -> AdvisoryPolicyStatus {
    match validate(bytes) {
        Ok(policy) => AdvisoryPolicyStatus::Loaded(policy),
        Err(reason) => AdvisoryPolicyStatus::Invalid(reason),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawFile {
    version: u16,
    entries: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawEntry {
    advisory: String,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    version: Option<String>,
    state: ReviewState,
    reason: String,
    #[serde(default)]
    expires_at: Option<String>,
}

fn validate(bytes: &[u8]) -> Result<AdvisoryPolicy, String> {
    let value = super::policy::parse_json_without_duplicates(bytes)
        .map_err(|_| "it is not valid JSON, or repeats a key".to_string())?;
    let raw: RawFile = serde_json::from_value(value).map_err(|error| error.to_string())?;
    if raw.version != 1 {
        return Err(format!("version {} is not supported; use 1", raw.version));
    }
    let advisory_id =
        regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").expect("advisory id pattern");
    let mut entries = Vec::with_capacity(raw.entries.len());
    for (index, entry) in raw.entries.into_iter().enumerate() {
        let at = |problem: &str| format!("entry {}: {problem}", index + 1);
        if !advisory_id.is_match(&entry.advisory) {
            return Err(at(
                "advisory must be an advisory id such as GHSA-xxxx-xxxx-xxxx or CVE-2024-1234",
            ));
        }
        for (field, value) in [
            ("package", &entry.package),
            ("ecosystem", &entry.ecosystem),
            ("version", &entry.version),
        ] {
            if value
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.len() > 256)
            {
                return Err(at(&format!(
                    "{field} must be non-empty and at most 256 bytes"
                )));
            }
        }
        if !matches!(
            entry.state,
            ReviewState::FalsePositive | ReviewState::AcceptedRisk | ReviewState::Suppressed
        ) {
            return Err(at(
                "state must be falsePositive, acceptedRisk or suppressed",
            ));
        }
        if !super::policy::safe_required_text(&entry.reason) {
            return Err(at(
                "reason is required and must not contain credentials, paths or URLs",
            ));
        }
        let expires_at = match &entry.expires_at {
            None => None,
            Some(raw) => Some(
                DateTime::parse_from_rfc3339(raw)
                    .map_err(|_| {
                        at("expiresAt must be an RFC 3339 time such as 2027-01-31T00:00:00Z")
                    })?
                    .with_timezone(&Utc),
            ),
        };
        entries.push(Entry {
            advisory: entry.advisory,
            package: entry.package,
            ecosystem: entry.ecosystem,
            version: entry.version,
            review: AdvisoryReview {
                state: entry.state,
                reason: entry.reason,
                expires_at: entry.expires_at,
            },
            expires_at,
        });
    }
    Ok(AdvisoryPolicy { entries })
}

impl AdvisoryPolicy {
    /// The last matching unexpired entry wins, as with `policy.json`
    /// suppressions.
    pub fn decide(&self, subject: &AdvisorySubject<'_>, now: DateTime<Utc>) -> Decision {
        let mut decision = Decision::None;
        for entry in self.entries.iter().filter(|entry| entry.matches(subject)) {
            if entry.expires_at.is_some_and(|expires| expires <= now) {
                if decision == Decision::None {
                    decision = Decision::Expired;
                }
            } else {
                decision = Decision::Dismissed(entry.review.clone());
            }
        }
        decision
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Entry {
    fn matches(&self, subject: &AdvisorySubject<'_>) -> bool {
        if !subject
            .ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&self.advisory))
        {
            return false;
        }
        if let Some(ecosystem) = &self.ecosystem {
            if subject.ecosystem != Some(ecosystem.as_str()) {
                return false;
            }
        }
        if let Some(package) = &self.package {
            let same = match subject.ecosystem {
                Some(ecosystem) => {
                    crate::advisories::versioning::normalize_package(ecosystem, package)
                        == crate::advisories::versioning::normalize_package(
                            ecosystem,
                            subject.package,
                        )
                }
                None => package == subject.package,
            };
            if !same {
                return false;
            }
        }
        self.version
            .as_deref()
            .is_none_or(|version| version == subject.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> AdvisoryPolicy {
        match parse(json.as_bytes()) {
            AdvisoryPolicyStatus::Loaded(policy) => policy,
            other => panic!("expected a valid policy, got {other:?}"),
        }
    }

    fn invalid(json: &str) -> String {
        match parse(json.as_bytes()) {
            AdvisoryPolicyStatus::Invalid(reason) => reason,
            other => panic!("expected an invalid policy, got {other:?}"),
        }
    }

    fn entry(fields: &str) -> String {
        format!(r#"{{"version": 1, "entries": [{{{fields}}}]}}"#)
    }

    fn subject<'a>(
        ids: &[&'a str],
        ecosystem: Option<&'a str>,
        package: &'a str,
        version: &'a str,
    ) -> AdvisorySubject<'a> {
        AdvisorySubject {
            ids: ids.to_vec(),
            ecosystem,
            package,
            version,
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-11-02T12:00:00Z".parse().unwrap()
    }

    fn state(decision: Decision) -> Option<ReviewState> {
        match decision {
            Decision::Dismissed(review) => Some(review.state),
            _ => None,
        }
    }

    #[test]
    fn an_entry_matches_the_advisory_id_or_any_alias_ignoring_case() {
        let policy = policy(&entry(
            r#""advisory": "cve-2024-1", "state": "acceptedRisk", "reason": "Build-time only""#,
        ));
        let decision = policy.decide(
            &subject(
                &["GHSA-aaaa-bbbb-cccc", "CVE-2024-1"],
                Some("npm"),
                "lodash",
                "4.17.20",
            ),
            now(),
        );
        assert_eq!(
            decision,
            Decision::Dismissed(AdvisoryReview {
                state: ReviewState::AcceptedRisk,
                reason: "Build-time only".into(),
                expires_at: None,
            })
        );
        assert_eq!(
            policy.decide(
                &subject(&["GHSA-other"], Some("npm"), "lodash", "4.17.20"),
                now()
            ),
            Decision::None
        );
    }

    #[test]
    fn narrowers_must_all_match() {
        let policy = policy(&entry(
            r#""advisory": "GHSA-1", "package": "lodash", "ecosystem": "npm", "version": "4.17.20", "state": "falsePositive", "reason": "Not reachable""#,
        ));
        let decide = |package, version, ecosystem| {
            state(policy.decide(&subject(&["GHSA-1"], ecosystem, package, version), now()))
        };
        assert_eq!(
            decide("lodash", "4.17.20", Some("npm")),
            Some(ReviewState::FalsePositive)
        );
        assert_eq!(decide("lodash", "4.17.21", Some("npm")), None);
        assert_eq!(decide("underscore", "4.17.20", Some("npm")), None);
        assert_eq!(decide("lodash", "4.17.20", Some("PyPI")), None);
        // An image component has no ecosystem; an ecosystem narrower cannot match it.
        assert_eq!(decide("lodash", "4.17.20", None), None);
    }

    #[test]
    fn npm_and_pypi_package_names_compare_normalized() {
        let policy = policy(&entry(
            r#""advisory": "GHSA-2", "package": "Django_Rest", "ecosystem": "PyPI", "state": "suppressed", "reason": "Vendored copy is patched""#,
        ));
        assert_eq!(
            state(policy.decide(
                &subject(&["GHSA-2"], Some("PyPI"), "django-rest", "1.0"),
                now()
            )),
            Some(ReviewState::Suppressed)
        );
    }

    #[test]
    fn the_last_matching_entry_wins() {
        let policy = policy(
            r#"{"version": 1, "entries": [
                {"advisory": "GHSA-3", "state": "acceptedRisk", "reason": "First"},
                {"advisory": "GHSA-3", "state": "falsePositive", "reason": "Second"}
            ]}"#,
        );
        assert_eq!(
            state(policy.decide(&subject(&["GHSA-3"], None, "x", "1"), now())),
            Some(ReviewState::FalsePositive)
        );
    }

    #[test]
    fn an_expired_entry_reports_expired_not_dismissed() {
        let expired = policy(&entry(
            r#""advisory": "GHSA-4", "state": "acceptedRisk", "reason": "Until the upgrade", "expiresAt": "2026-01-01T00:00:00Z""#,
        ));
        assert_eq!(
            expired.decide(&subject(&["GHSA-4"], None, "x", "1"), now()),
            Decision::Expired
        );
        // An unexpired entry still wins over an expired one.
        let renewed = policy(
            r#"{"version": 1, "entries": [
                {"advisory": "GHSA-5", "state": "acceptedRisk", "reason": "Old", "expiresAt": "2026-01-01T00:00:00Z"},
                {"advisory": "GHSA-5", "state": "acceptedRisk", "reason": "Renewed", "expiresAt": "2027-01-01T00:00:00Z"}
            ]}"#,
        );
        match renewed.decide(&subject(&["GHSA-5"], None, "x", "1"), now()) {
            Decision::Dismissed(review) => {
                assert_eq!(review.reason, "Renewed");
                assert_eq!(review.expires_at.as_deref(), Some("2027-01-01T00:00:00Z"));
            }
            other => panic!("{other:?}"),
        }
        assert!(invalid(&entry(
            r#""advisory": "GHSA-6", "state": "acceptedRisk", "reason": "x", "expiresAt": "soon""#
        ))
        .contains("expiresAt"));
    }

    #[test]
    fn invalid_files_are_refused_with_a_reason() {
        let cases = [
            r#"{"version": 2, "entries": []}"#.to_string(),
            r#"{"entries": []}"#.to_string(),
            entry(r#""advisory": "GHSA-7", "state": "acceptedRisk", "reason": "x", "severity": "low""#),
            r#"{"version": 1, "entries": [{"advisory": "GHSA-8", "advisory": "GHSA-9", "state": "acceptedRisk", "reason": "x"}]}"#.to_string(),
            entry(r#""advisory": "GHSA-10", "state": "acceptedRisk", "reason": "  ""#),
            entry(r#""advisory": "GHSA-11", "state": "acceptedRisk", "reason": "see C:\\Users\\me\\notes.txt""#),
            entry(r#""advisory": "GHSA-12", "state": "confirmed", "reason": "x""#),
            entry(r#""advisory": "", "state": "acceptedRisk", "reason": "x""#),
            entry(r#""advisory": "GHSA 13", "state": "acceptedRisk", "reason": "x""#),
            entry(r#""advisory": "GHSA-14", "package": "", "state": "acceptedRisk", "reason": "x""#),
            "not json".to_string(),
        ];
        for case in cases {
            let reason = invalid(&case);
            assert!(!reason.trim().is_empty(), "{case}");
        }
    }

    #[test]
    fn reasons_may_link_to_a_ticket() {
        policy(&entry(
            r#""advisory": "GHSA-17", "state": "acceptedRisk", "reason": "Tracked in https://example.com/issues/42""#,
        ));
    }

    #[test]
    fn a_missing_file_is_missing_and_an_oversized_file_is_invalid() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            load_project_advisory_policy(root.path()),
            AdvisoryPolicyStatus::Missing
        ));
        std::fs::create_dir(root.path().join(".oxaudit")).unwrap();
        assert!(matches!(
            load_project_advisory_policy(root.path()),
            AdvisoryPolicyStatus::Missing
        ));
        let path = root.path().join(ADVISORY_POLICY_PATH);
        std::fs::write(
            &path,
            entry(r#""advisory": "GHSA-15", "state": "acceptedRisk", "reason": "Fine""#),
        )
        .unwrap();
        assert!(matches!(
            load_project_advisory_policy(root.path()),
            AdvisoryPolicyStatus::Loaded(_)
        ));
        assert!(matches!(
            load_advisory_policy_file(&path),
            AdvisoryPolicyStatus::Loaded(_)
        ));
        std::fs::write(&path, vec![b' '; MAX_ADVISORY_POLICY_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            load_project_advisory_policy(root.path()),
            AdvisoryPolicyStatus::Invalid(_)
        ));
        assert!(matches!(
            load_advisory_policy_file(&path),
            AdvisoryPolicyStatus::Invalid(_)
        ));
        // An explicit path that does not exist is an error, not a silent no-op.
        assert!(matches!(
            load_advisory_policy_file(&root.path().join("nope.json")),
            AdvisoryPolicyStatus::Invalid(_)
        ));
    }

    #[test]
    fn policy_read_errors_name_the_problem_plainly() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(ADVISORY_POLICY_PATH)).unwrap();
        let AdvisoryPolicyStatus::Invalid(reason) = load_project_advisory_policy(root.path())
        else {
            panic!("a directory is not a policy");
        };
        assert!(reason.contains("is a directory, not a file"), "{reason}");
        assert!(!reason.contains("os error"), "{reason}");
        assert!(
            !reason.contains("advisory-policy.json"),
            "the caller names the path once: {reason}"
        );
        let AdvisoryPolicyStatus::Invalid(reason) =
            load_advisory_policy_file(&root.path().join(ADVISORY_POLICY_PATH))
        else {
            panic!("a directory is not a policy");
        };
        assert!(reason.contains("is a directory, not a file"), "{reason}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_policy_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join(".oxaudit")).unwrap();
        let real = root.path().join("real.json");
        std::fs::write(
            &real,
            entry(r#""advisory": "GHSA-16", "state": "acceptedRisk", "reason": "Fine""#),
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, root.path().join(ADVISORY_POLICY_PATH)).unwrap();
        assert!(matches!(
            load_project_advisory_policy(root.path()),
            AdvisoryPolicyStatus::Invalid(_)
        ));
        // A path named on the command line may be a symlink (a mounted
        // ConfigMap, a Nix store path); the committed project file may not.
        assert!(matches!(
            load_advisory_policy_file(&root.path().join(ADVISORY_POLICY_PATH)),
            AdvisoryPolicyStatus::Loaded(_)
        ));
    }
}

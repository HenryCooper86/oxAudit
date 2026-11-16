//! The committed component policy: `.oxaudit/component-policy.json`.
//!
//! One file states what a project accepts in its third-party components:
//! which licenses, how stale or deprecated a release may be, how severe an
//! open advisory may be, and which named components are approved or
//! rejected outright. Each rule answers `deny` (a violation that fails the
//! build), `warn` (reported, never failing) or `allow`.
//!
//! ```json
//! {
//!   "version": 1,
//!   "licenses": {
//!     "deny": ["category:strong-copyleft", "category:network-copyleft", "SSPL-1.0"],
//!     "warn": ["category:weak-copyleft"],
//!     "allow": ["LGPL-2.1-only"],
//!     "unknown": "warn"
//!   },
//!   "operational": {
//!     "deprecated": "deny",
//!     "maxAgeDays": { "warn": 730, "deny": 1825 },
//!     "maxMajorVersionsBehind": { "warn": 2 }
//!   },
//!   "vulnerabilities": { "deny": "critical", "warn": "high" },
//!   "components": [
//!     { "ecosystem": "npm", "package": "left-pad", "decision": "rejected",
//!       "reason": "Unmaintained; use String.prototype.padStart" }
//!   ]
//! }
//! ```
//!
//! The file is strict, like every other gate file here: an unknown key, an
//! unknown license id or a rule that names one license twice is an error,
//! because a typo must not silently loosen a gate.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::license::{self, Expression, LicenseAssessment, LicenseCategory, LicenseTerm};
use crate::release::ReleaseInfo;

/// Where the policy lives, relative to the project root.
pub const COMPONENT_POLICY_PATH: &str = ".oxaudit/component-policy.json";
pub const COMPONENT_POLICY_FILE_NAME: &str = "component-policy.json";
const MAX_LIST_ENTRIES: usize = 2_000;
const MAX_TEXT_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 500;

/// What a rule does when it matches, ordered by how much it restricts.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Warn,
    Deny,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Deny => "deny",
        }
    }
}

/// Higher is more severe. Unrecognised text ranks 0.
pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn rank(self) -> u8 {
        severity_rank(self.label())
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPolicy {
    version: u16,
    #[serde(default)]
    licenses: RawLicenses,
    #[serde(default)]
    operational: RawOperational,
    #[serde(default)]
    vulnerabilities: RawVulnerabilities,
    #[serde(default)]
    components: Vec<RawComponent>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawLicenses {
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    warn: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    unknown: Option<Action>,
    #[serde(default)]
    allow_only: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawOperational {
    #[serde(default)]
    deprecated: Action,
    #[serde(default)]
    max_age_days: Threshold,
    #[serde(default)]
    max_major_versions_behind: Threshold,
    #[serde(default)]
    stale_after_days: Threshold,
    #[serde(default)]
    unknown: Action,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawVulnerabilities {
    #[serde(default)]
    deny: Option<Severity>,
    #[serde(default)]
    warn: Option<Severity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawComponent {
    ecosystem: String,
    package: String,
    #[serde(default)]
    version: Option<String>,
    decision: Decision,
    reason: String,
    #[serde(default)]
    expires_at: Option<String>,
}

/// A numeric limit with a warning level and a failing level. A value at or
/// above a level triggers it.
#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Threshold {
    #[serde(default)]
    pub warn: Option<u32>,
    #[serde(default)]
    pub deny: Option<u32>,
}

impl Threshold {
    fn action(self, value: u32) -> Action {
        if self.deny.is_some_and(|limit| value >= limit) {
            Action::Deny
        } else if self.warn.is_some_and(|limit| value >= limit) {
            Action::Warn
        } else {
            Action::Allow
        }
    }

    fn limit(self, action: Action) -> Option<u32> {
        match action {
            Action::Deny => self.deny,
            Action::Warn => self.warn,
            Action::Allow => None,
        }
    }

    fn is_set(self) -> bool {
        self.warn.is_some() || self.deny.is_some()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approved,
    Rejected,
}

#[derive(Debug, Clone)]
struct ComponentDecision {
    ecosystem: String,
    package: String,
    version: Option<String>,
    decision: Decision,
    reason: String,
    expires_at_text: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

/// A validated component policy. The default is the policy of a project
/// that has none: everything is reported and nothing is a violation.
#[derive(Debug, Clone, Default)]
pub struct ComponentPolicy {
    by_license: BTreeMap<String, (Action, String)>,
    by_text: BTreeMap<String, (Action, String)>,
    by_category: BTreeMap<LicenseCategory, (Action, String)>,
    unknown_license: Action,
    allow_only: bool,
    deprecated: Action,
    max_age_days: Threshold,
    max_major_versions_behind: Threshold,
    stale_after_days: Threshold,
    unknown_release: Action,
    vulnerability_deny: Option<Severity>,
    vulnerability_warn: Option<Severity>,
    components: Vec<ComponentDecision>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ViolationKind {
    Component,
    License,
    Vulnerability,
    Operational,
}

/// Why a violation does not count: an unexpired `approved` decision.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Waiver {
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub kind: ViolationKind,
    /// The policy key that matched, such as `licenses.deny`.
    pub rule: String,
    /// `deny` or `warn`.
    pub action: Action,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver: Option<Waiver>,
}

impl Violation {
    /// A violation fails the build when it is a `deny` nobody waived.
    pub fn gates(&self) -> bool {
        self.action == Action::Deny && self.waiver.is_none()
    }
}

/// One open advisory against a component, as the policy sees it.
#[derive(Clone, Debug)]
pub struct AdvisoryInput {
    pub id: String,
    pub severity: Option<String>,
}

/// One component, as the policy sees it.
#[derive(Clone, Debug)]
pub struct Subject<'a> {
    pub ecosystem: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub license: &'a LicenseAssessment,
    /// `None` when release facts were not collected for this component.
    pub release: Option<&'a ReleaseInfo>,
    /// Advisories that were not dismissed by the advisory policy.
    pub advisories: &'a [AdvisoryInput],
}

/// The policy's answer for one component.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Evaluation {
    pub violations: Vec<Violation>,
    /// Things a reader should know that are not violations, such as an
    /// approval that has expired.
    pub notes: Vec<String>,
}

fn text_ok(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

/// Compare package names the way the ecosystem's registry does.
pub fn same_package(ecosystem: &str, left: &str, right: &str) -> bool {
    match ecosystem {
        // PEP 503: case-insensitive, with runs of `-`, `_` and `.` equal.
        "PyPI" => {
            let normalize = |name: &str| {
                let mut out = String::new();
                let mut separator = false;
                for character in name.chars() {
                    if matches!(character, '-' | '_' | '.') {
                        separator = true;
                    } else {
                        if separator && !out.is_empty() {
                            out.push('-');
                        }
                        separator = false;
                        out.extend(character.to_lowercase());
                    }
                }
                out
            };
            normalize(left) == normalize(right)
        }
        "NuGet" | "Packagist" => left.eq_ignore_ascii_case(right),
        _ => left == right,
    }
}

impl ComponentPolicy {
    /// Validate a parsed policy document.
    pub fn from_value(value: serde_json::Value) -> Result<Self, String> {
        let raw: RawPolicy = serde_json::from_value(value).map_err(|error| error.to_string())?;
        if raw.version != 1 {
            return Err(format!("version {} is not supported; use 1", raw.version));
        }
        let mut policy = ComponentPolicy {
            unknown_license: raw.licenses.unknown.unwrap_or_default(),
            allow_only: raw.licenses.allow_only,
            deprecated: raw.operational.deprecated,
            max_age_days: raw.operational.max_age_days,
            max_major_versions_behind: raw.operational.max_major_versions_behind,
            stale_after_days: raw.operational.stale_after_days,
            unknown_release: raw.operational.unknown,
            vulnerability_deny: raw.vulnerabilities.deny,
            vulnerability_warn: raw.vulnerabilities.warn,
            ..Default::default()
        };
        for (list, action, entries) in [
            ("licenses.deny", Action::Deny, &raw.licenses.deny),
            ("licenses.warn", Action::Warn, &raw.licenses.warn),
            ("licenses.allow", Action::Allow, &raw.licenses.allow),
        ] {
            if entries.len() > MAX_LIST_ENTRIES {
                return Err(format!("{list} has more than {MAX_LIST_ENTRIES} entries"));
            }
            for entry in entries {
                policy.add_license_rule(list, action, entry)?;
            }
        }
        if policy.allow_only && raw.licenses.allow.is_empty() {
            return Err(
                "licenses.allowOnly needs a non-empty licenses.allow list to allow from".into(),
            );
        }
        if policy.allow_only && raw.licenses.unknown.is_none() {
            // An allow list says nothing about a license nobody could
            // classify; the author has to.
            return Err(
                "licenses.allowOnly needs licenses.unknown set (deny, warn or allow): an \
                 undeclared or unclassified license is not on any list"
                    .into(),
            );
        }
        for (name, threshold) in [
            ("operational.maxAgeDays", policy.max_age_days),
            (
                "operational.maxMajorVersionsBehind",
                policy.max_major_versions_behind,
            ),
            ("operational.staleAfterDays", policy.stale_after_days),
        ] {
            if let (Some(warn), Some(deny)) = (threshold.warn, threshold.deny) {
                if warn > deny {
                    return Err(format!(
                        "{name}: warn ({warn}) must not be above deny ({deny})"
                    ));
                }
            }
            if threshold.warn == Some(0) || threshold.deny == Some(0) {
                return Err(format!("{name}: a limit of 0 would match every component"));
            }
        }
        if let (Some(warn), Some(deny)) = (policy.vulnerability_warn, policy.vulnerability_deny) {
            if warn.rank() > deny.rank() {
                return Err(format!(
                    "vulnerabilities: warn ({}) must not be above deny ({})",
                    warn.label(),
                    deny.label()
                ));
            }
        }
        if raw.components.len() > MAX_LIST_ENTRIES {
            return Err(format!("components has more than {MAX_LIST_ENTRIES} entries"));
        }
        for (index, component) in raw.components.into_iter().enumerate() {
            let at = |problem: &str| format!("components entry {}: {problem}", index + 1);
            for (field, value) in [
                ("ecosystem", Some(&component.ecosystem)),
                ("package", Some(&component.package)),
                ("version", component.version.as_ref()),
            ] {
                if value.is_some_and(|value| !text_ok(value, MAX_TEXT_BYTES)) {
                    return Err(at(&format!(
                        "{field} must be non-empty and at most {MAX_TEXT_BYTES} bytes"
                    )));
                }
            }
            if !text_ok(&component.reason, MAX_REASON_BYTES) {
                return Err(at(&format!(
                    "reason is required, at most {MAX_REASON_BYTES} bytes"
                )));
            }
            let expires_at = match &component.expires_at {
                None => None,
                Some(raw) => Some(
                    DateTime::parse_from_rfc3339(raw)
                        .map_err(|_| {
                            at("expiresAt must be an RFC 3339 time such as 2027-01-31T00:00:00Z")
                        })?
                        .with_timezone(&Utc),
                ),
            };
            policy.components.push(ComponentDecision {
                ecosystem: component.ecosystem,
                package: component.package,
                version: component.version,
                decision: component.decision,
                reason: component.reason,
                expires_at_text: component.expires_at,
                expires_at,
            });
        }
        Ok(policy)
    }

    fn add_license_rule(&mut self, list: &str, action: Action, entry: &str) -> Result<(), String> {
        let entry = entry.trim();
        if !text_ok(entry, MAX_TEXT_BYTES) {
            return Err(format!(
                "{list}: entries must be non-empty and at most {MAX_TEXT_BYTES} bytes"
            ));
        }
        let rule = (action, format!("{list}: {entry}"));
        let duplicate = |existing: &(Action, String)| {
            format!(
                "{list}: {entry} is already listed under {}",
                existing.1.split(':').next().unwrap_or("another list")
            )
        };
        if let Some(slug) = entry.strip_prefix("category:") {
            let category = LicenseCategory::from_slug(slug).ok_or_else(|| {
                format!(
                    "{list}: {slug} is not a license category; use one of {}",
                    LicenseCategory::ALL.map(LicenseCategory::slug).join(", ")
                )
            })?;
            if category == LicenseCategory::Unknown {
                return Err(format!(
                    "{list}: set licenses.unknown instead of listing category:unknown"
                ));
            }
            if let Some(existing) = self.by_category.insert(category, rule) {
                return Err(duplicate(&existing));
            }
            return Ok(());
        }
        if let Some(text) = entry.strip_prefix("text:") {
            let text = text.trim();
            if text.is_empty() {
                return Err(format!("{list}: text: needs the declared license text to match"));
            }
            if let Some(existing) = self.by_text.insert(text.to_lowercase(), rule) {
                return Err(duplicate(&existing));
            }
            return Ok(());
        }
        // An SPDX id, optionally `<id> WITH <exception>`.
        let term = match license::parse(entry) {
            Expression::Term(term) if term.id.is_some() => term,
            _ => {
                return Err(format!(
                    "{list}: {entry} is not a license id this build classifies; use an SPDX id, \
                     category:<name>, or text:<declared text> to match a declaration exactly"
                ))
            }
        };
        if let Some(existing) = self.by_license.insert(term.label(), rule) {
            return Err(duplicate(&existing));
        }
        Ok(())
    }

    /// Whether any rule could produce a violation.
    pub fn has_rules(&self) -> bool {
        fn acts<K>(rules: &BTreeMap<K, (Action, String)>) -> bool {
            rules.values().any(|(action, _)| *action != Action::Allow)
        }
        acts(&self.by_license)
            || acts(&self.by_text)
            || acts(&self.by_category)
            || self.allow_only
            || self.unknown_license != Action::Allow
            || self.deprecated != Action::Allow
            || self.max_age_days.is_set()
            || self.max_major_versions_behind.is_set()
            || self.stale_after_days.is_set()
            || self.unknown_release != Action::Allow
            || self.vulnerability_deny.is_some()
            || self.vulnerability_warn.is_some()
            || self
                .components
                .iter()
                .any(|component| component.decision == Decision::Rejected)
    }

    /// Whether the policy asks anything of release facts. When it does not,
    /// a caller may skip collecting them.
    pub fn uses_release_facts(&self) -> bool {
        self.deprecated != Action::Allow
            || self.max_age_days.is_set()
            || self.max_major_versions_behind.is_set()
            || self.stale_after_days.is_set()
            || self.unknown_release != Action::Allow
    }

    /// Every free-text reason in the policy, for callers that screen them.
    pub fn reasons(&self) -> impl Iterator<Item = &str> {
        self.components
            .iter()
            .map(|component| component.reason.as_str())
    }

    /// The rule for one license term: the most specific match wins — the
    /// exact license (with its exception), then the license id, then the
    /// declared text, then the category.
    fn term_rule(&self, term: &LicenseTerm) -> (Action, String) {
        if let Some(id) = &term.id {
            if let Some(rule) = self.by_license.get(&term.label()) {
                return rule.clone();
            }
            // A rule for the bare license reaches a `WITH` form only when
            // the exception left the category alone. A linking exception
            // changes what the license asks, so the category rule decides.
            if term.exception.is_some() && license::category_of(id) == Some(term.category) {
                if let Some(rule) = self.by_license.get(id) {
                    return rule.clone();
                }
            }
        }
        if let Some(rule) = self.by_text.get(&term.text.to_lowercase()) {
            return rule.clone();
        }
        if term.category == LicenseCategory::Unknown {
            return (self.unknown_license, "licenses.unknown".into());
        }
        if let Some(rule) = self.by_category.get(&term.category) {
            return rule.clone();
        }
        if self.allow_only {
            return (Action::Deny, "licenses.allowOnly".into());
        }
        (Action::Allow, String::new())
    }

    /// The license verdict for a whole declaration: `OR` takes the operand
    /// the policy likes best (the licensee may choose it), `AND` the one it
    /// likes least. Returns the action, the rule that decided, and the
    /// license it decided on.
    fn license_verdict(&self, assessment: &LicenseAssessment) -> (Action, String, String) {
        let Some(declared) = assessment.declared.as_deref() else {
            return (
                self.unknown_license,
                "licenses.unknown".into(),
                "no declared license".into(),
            );
        };
        // Re-parse rather than store the tree: the assessment is plain data
        // that also arrives from stored reports.
        let expression = license::parse(assessment.expression.as_deref().unwrap_or(declared));
        let leaf = |term: &LicenseTerm| {
            let (action, rule) = self.term_rule(term);
            (action, rule, term.label())
        };
        expression.fold(
            &leaf,
            &|scores| {
                scores
                    .into_iter()
                    .max_by_key(|score| score.0)
                    .expect("an expression has operands")
            },
            &|scores| {
                // `min_by_key` returns the first minimum, so the leftmost
                // acceptable choice is the one reported.
                scores
                    .into_iter()
                    .min_by_key(|score| score.0)
                    .expect("an expression has operands")
            },
        )
    }

    /// Evaluate one component.
    pub fn evaluate(&self, subject: &Subject<'_>, now: DateTime<Utc>) -> Evaluation {
        let mut evaluation = Evaluation::default();
        let violation = |kind, rule: &str, action, message: String| Violation {
            kind,
            rule: rule.to_string(),
            action,
            ecosystem: subject.ecosystem.to_string(),
            name: subject.name.to_string(),
            version: subject.version.to_string(),
            message,
            waiver: None,
        };

        // Named decisions first: the last matching unexpired entry wins.
        let mut decision: Option<&ComponentDecision> = None;
        let mut expired = 0usize;
        for entry in self.components.iter().filter(|entry| {
            entry.ecosystem == subject.ecosystem
                && same_package(subject.ecosystem, &entry.package, subject.name)
                && entry
                    .version
                    .as_deref()
                    .is_none_or(|version| version == subject.version)
        }) {
            if entry.expires_at.is_some_and(|expires| expires <= now) {
                expired += 1;
            } else {
                decision = Some(entry);
            }
        }
        if expired > 0 && decision.is_none() {
            evaluation.notes.push(format!(
                "{} {} {}: {expired} component decision(s) matched but expired; the policy \
                 rules apply again",
                subject.ecosystem, subject.name, subject.version
            ));
        }
        if let Some(entry) = decision.filter(|entry| entry.decision == Decision::Rejected) {
            evaluation.violations.push(violation(
                ViolationKind::Component,
                "components.rejected",
                Action::Deny,
                format!("component is rejected: {}", entry.reason),
            ));
        }

        let (action, rule, license) = self.license_verdict(subject.license);
        if action != Action::Allow {
            let message = match rule.as_str() {
                "licenses.unknown" if subject.license.declared.is_none() => {
                    "no declared license was found".to_string()
                }
                "licenses.unknown" => format!("license {license} could not be classified"),
                "licenses.allowOnly" => format!("license {license} is not on the allow list"),
                _ => format!(
                    "license {license} is {} ({})",
                    if action == Action::Deny {
                        "denied"
                    } else {
                        "flagged for review"
                    },
                    subject.license.category.slug()
                ),
            };
            let key = rule.split(':').next().unwrap_or(&rule).to_string();
            evaluation
                .violations
                .push(violation(ViolationKind::License, &key, action, message));
        }

        let open: Vec<(&AdvisoryInput, u8)> = subject
            .advisories
            .iter()
            .map(|advisory| {
                (
                    advisory,
                    severity_rank(advisory.severity.as_deref().unwrap_or("")),
                )
            })
            .collect();
        for (action, level) in [
            (Action::Deny, self.vulnerability_deny),
            (Action::Warn, self.vulnerability_warn),
        ] {
            let Some(level) = level else { continue };
            let matching: Vec<&(&AdvisoryInput, u8)> = open
                .iter()
                .filter(|(_, rank)| *rank >= level.rank())
                .collect();
            let Some(worst) = matching.iter().max_by_key(|(_, rank)| *rank) else {
                continue;
            };
            evaluation.violations.push(violation(
                ViolationKind::Vulnerability,
                &format!("vulnerabilities.{}", action.label()),
                action,
                format!(
                    "{} open advisor{} at or above {}, worst {} ({})",
                    matching.len(),
                    if matching.len() == 1 { "y" } else { "ies" },
                    level.label(),
                    worst.0.severity.as_deref().unwrap_or("unknown"),
                    worst.0.id
                ),
            ));
            // A deny already reports these advisories; do not repeat them as a warning.
            break;
        }

        match subject.release.filter(|release| release.has_facts()) {
            None => {
                if self.unknown_release != Action::Allow {
                    evaluation.violations.push(violation(
                        ViolationKind::Operational,
                        "operational.unknown",
                        self.unknown_release,
                        "release facts were not available for this component".into(),
                    ));
                }
            }
            Some(release) => {
                if release.deprecated == Some(true) && self.deprecated != Action::Allow {
                    let reason = release
                        .deprecated_reason
                        .as_deref()
                        .map(str::trim)
                        .filter(|reason| !reason.is_empty())
                        .map(|reason| {
                            let short: String = reason.chars().take(200).collect();
                            format!(": {short}")
                        })
                        .unwrap_or_default();
                    evaluation.violations.push(violation(
                        ViolationKind::Operational,
                        "operational.deprecated",
                        self.deprecated,
                        format!("the registry marks this version deprecated{reason}"),
                    ));
                }
                let limits = [
                    (
                        "operational.maxAgeDays",
                        self.max_age_days,
                        release.age_days(now),
                        "this version was published {value} days ago (limit {limit})",
                    ),
                    (
                        "operational.maxMajorVersionsBehind",
                        self.max_major_versions_behind,
                        release.major_versions_behind,
                        "this version is {value} major version(s) behind the default release \
                         (limit {limit})",
                    ),
                    (
                        "operational.staleAfterDays",
                        self.stale_after_days,
                        release.days_since_latest_release(now),
                        "the package last published a release {value} days ago (limit {limit})",
                    ),
                ];
                for (rule, threshold, value, template) in limits {
                    let Some(value) = value else { continue };
                    let action = threshold.action(value);
                    if action == Action::Allow {
                        continue;
                    }
                    let limit = threshold.limit(action).unwrap_or_default();
                    evaluation.violations.push(violation(
                        ViolationKind::Operational,
                        rule,
                        action,
                        template
                            .replace("{value}", &value.to_string())
                            .replace("{limit}", &limit.to_string()),
                    ));
                }
            }
        }

        // An approval waives the license and operational findings it was
        // given for. Advisories are waived through the advisory policy,
        // which names the advisory being accepted.
        if let Some(entry) = decision.filter(|entry| entry.decision == Decision::Approved) {
            for violation in &mut evaluation.violations {
                if matches!(
                    violation.kind,
                    ViolationKind::License | ViolationKind::Operational
                ) {
                    violation.waiver = Some(Waiver {
                        reason: entry.reason.clone(),
                        expires_at: entry.expires_at_text.clone(),
                    });
                }
            }
        }
        evaluation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(value: serde_json::Value) -> ComponentPolicy {
        ComponentPolicy::from_value(value).expect("valid policy")
    }

    fn invalid(value: serde_json::Value) -> String {
        ComponentPolicy::from_value(value).expect_err("invalid policy")
    }

    fn now() -> DateTime<Utc> {
        "2026-11-16T00:00:00Z".parse().unwrap()
    }

    fn evaluate(
        policy: &ComponentPolicy,
        declared: Option<&str>,
        release: Option<&ReleaseInfo>,
        advisories: &[AdvisoryInput],
    ) -> Evaluation {
        let assessment = license::assess(declared);
        policy.evaluate(
            &Subject {
                ecosystem: "npm",
                name: "widget",
                version: "1.0.0",
                license: &assessment,
                release,
                advisories,
            },
            now(),
        )
    }

    fn license_action(policy: &ComponentPolicy, declared: Option<&str>) -> Action {
        evaluate(policy, declared, None, &[])
            .violations
            .iter()
            .find(|violation| violation.kind == ViolationKind::License)
            .map_or(Action::Allow, |violation| violation.action)
    }

    fn copyleft_policy() -> ComponentPolicy {
        policy(json!({
            "version": 1,
            "licenses": {
                "deny": ["category:strong-copyleft", "category:network-copyleft"],
                "warn": ["category:weak-copyleft"],
                "allow": ["GPL-2.0-only WITH Classpath-exception-2.0", "MPL-2.0"],
                "unknown": "warn"
            }
        }))
    }

    #[test]
    fn no_policy_means_no_violations() {
        let none = ComponentPolicy::default();
        assert!(!none.has_rules());
        assert!(!none.uses_release_facts());
        let release = ReleaseInfo {
            deprecated: Some(true),
            published_at: Some("2010-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        let advisories = [AdvisoryInput {
            id: "GHSA-1".into(),
            severity: Some("critical".into()),
        }];
        for declared in [None, Some("AGPL-3.0-only"), Some("who knows")] {
            assert_eq!(
                evaluate(&none, declared, Some(&release), &advisories),
                Evaluation::default()
            );
        }
        assert!(!policy(json!({"version": 1})).has_rules());
    }

    #[test]
    fn categories_ids_and_unknowns_each_get_their_action() {
        let policy = copyleft_policy();
        assert!(policy.has_rules());
        assert_eq!(license_action(&policy, Some("MIT")), Action::Allow);
        assert_eq!(license_action(&policy, Some("GPL-3.0-only")), Action::Deny);
        assert_eq!(license_action(&policy, Some("AGPL-3.0-or-later")), Action::Deny);
        assert_eq!(license_action(&policy, Some("LGPL-2.1-only")), Action::Warn);
        // An id rule beats the category rule.
        assert_eq!(license_action(&policy, Some("MPL-2.0")), Action::Allow);
        assert_eq!(license_action(&policy, None), Action::Warn);
        assert_eq!(license_action(&policy, Some("Custom EULA")), Action::Warn);
    }

    #[test]
    fn or_uses_the_best_choice_and_and_the_worst() {
        let policy = copyleft_policy();
        assert_eq!(
            license_action(&policy, Some("GPL-3.0-only OR MIT")),
            Action::Allow
        );
        assert_eq!(
            license_action(&policy, Some("GPL-3.0-only AND MIT")),
            Action::Deny
        );
        assert_eq!(
            license_action(&policy, Some("GPL-3.0-only OR LGPL-3.0-only")),
            Action::Warn
        );
        assert_eq!(
            license_action(&policy, Some("MIT AND Custom-1.0")),
            Action::Warn
        );
        let message = &evaluate(&policy, Some("GPL-3.0-only AND MIT"), None, &[]).violations[0];
        assert_eq!(message.rule, "licenses.deny");
        assert!(message.message.contains("GPL-3.0-only"), "{message:?}");
        assert!(message.gates());
    }

    #[test]
    fn a_license_with_a_linking_exception_is_judged_as_what_it_became() {
        let policy = copyleft_policy();
        // Listed exactly: allowed.
        assert_eq!(
            license_action(&policy, Some("GPL-2.0-only WITH Classpath-exception-2.0")),
            Action::Allow
        );
        // Not listed: weak copyleft after the exception, so the category warns.
        assert_eq!(
            license_action(&policy, Some("GPL-3.0-only WITH GCC-exception-3.1")),
            Action::Warn
        );
        // A deny on the bare id does not reach the exception form.
        let bare = self::policy(json!({
            "version": 1, "licenses": {"deny": ["GPL-2.0-only"]}
        }));
        assert_eq!(license_action(&bare, Some("GPL-2.0-only")), Action::Deny);
        assert_eq!(license_action(&bare, Some("GPL-2.0")), Action::Deny);
        assert_eq!(
            license_action(&bare, Some("GPL-2.0-only WITH Classpath-exception-2.0")),
            Action::Allow
        );
        // An unrecognised exception leaves the license what it was.
        assert_eq!(
            license_action(&bare, Some("GPL-2.0-only WITH Made-Up-exception")),
            Action::Deny
        );
    }

    #[test]
    fn allow_only_denies_everything_not_listed() {
        let policy = policy(json!({
            "version": 1,
            "licenses": {
                "allow": ["MIT", "Apache-2.0", "category:public-domain", "text:Acme Internal"],
                "allowOnly": true,
                "unknown": "warn"
            }
        }));
        assert_eq!(license_action(&policy, Some("MIT")), Action::Allow);
        assert_eq!(license_action(&policy, Some("Unlicense")), Action::Allow);
        assert_eq!(license_action(&policy, Some("acme internal")), Action::Allow);
        assert_eq!(license_action(&policy, Some("ISC")), Action::Deny);
        assert_eq!(license_action(&policy, Some("ISC OR MIT")), Action::Allow);
        // An unclassified license answers to `unknown`, not to the allow list.
        assert_eq!(license_action(&policy, Some("Mystery")), Action::Warn);
        assert_eq!(license_action(&policy, None), Action::Warn);
        let violations = evaluate(&policy, Some("ISC"), None, &[]).violations;
        assert_eq!(violations[0].rule, "licenses.allowOnly");
    }

    #[test]
    fn vulnerability_rules_report_the_worst_open_advisory_once() {
        let policy = policy(json!({
            "version": 1, "vulnerabilities": {"deny": "critical", "warn": "medium"}
        }));
        let advisory = |id: &str, severity: Option<&str>| AdvisoryInput {
            id: id.into(),
            severity: severity.map(String::from),
        };
        let none = evaluate(&policy, Some("MIT"), None, &[advisory("A", Some("low"))]);
        assert!(none.violations.is_empty());
        let warned = evaluate(
            &policy,
            Some("MIT"),
            None,
            &[advisory("A", Some("medium")), advisory("B", Some("HIGH"))],
        );
        assert_eq!(warned.violations.len(), 1);
        assert_eq!(warned.violations[0].action, Action::Warn);
        assert!(warned.violations[0].message.contains("(B)"));
        assert!(warned.violations[0].message.starts_with("2 open advisories"));
        let denied = evaluate(
            &policy,
            Some("MIT"),
            None,
            &[advisory("A", Some("medium")), advisory("C", Some("critical"))],
        );
        assert_eq!(denied.violations.len(), 1);
        assert_eq!(denied.violations[0].rule, "vulnerabilities.deny");
        // A severity nobody stated is not at or above any level.
        let unrated = evaluate(&policy, Some("MIT"), None, &[advisory("D", None)]);
        assert!(unrated.violations.is_empty());
    }

    #[test]
    fn operational_rules_fire_only_on_stated_facts() {
        let policy = policy(json!({
            "version": 1,
            "operational": {
                "deprecated": "deny",
                "maxAgeDays": {"warn": 365, "deny": 1000},
                "maxMajorVersionsBehind": {"deny": 2},
                "staleAfterDays": {"warn": 730}
            }
        }));
        assert!(policy.uses_release_facts());
        // No facts, and `unknown` defaults to allow: nothing fires.
        assert!(evaluate(&policy, Some("MIT"), None, &[]).violations.is_empty());
        let empty = ReleaseInfo::default();
        assert!(evaluate(&policy, Some("MIT"), Some(&empty), &[])
            .violations
            .is_empty());

        let old = ReleaseInfo {
            published_at: Some("2024-11-16T00:00:00Z".into()),
            latest_published_at: Some("2024-11-17T00:00:00Z".into()),
            major_versions_behind: Some(1),
            deprecated: Some(false),
            ..Default::default()
        };
        let rules = |release: &ReleaseInfo| {
            evaluate(&policy, Some("MIT"), Some(release), &[])
                .violations
                .into_iter()
                .map(|violation| (violation.rule, violation.action))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            rules(&old),
            vec![("operational.maxAgeDays".to_string(), Action::Warn)]
        );
        let ancient = ReleaseInfo {
            published_at: Some("2020-01-01T00:00:00Z".into()),
            latest_published_at: Some("2021-01-01T00:00:00Z".into()),
            major_versions_behind: Some(2),
            deprecated: Some(true),
            deprecated_reason: Some("use widget-next".into()),
            ..Default::default()
        };
        assert_eq!(
            rules(&ancient),
            vec![
                ("operational.deprecated".to_string(), Action::Deny),
                ("operational.maxAgeDays".to_string(), Action::Deny),
                ("operational.maxMajorVersionsBehind".to_string(), Action::Deny),
                ("operational.staleAfterDays".to_string(), Action::Warn),
            ]
        );
        let reason = &evaluate(&policy, Some("MIT"), Some(&ancient), &[]).violations[0].message;
        assert!(reason.ends_with("deprecated: use widget-next"), "{reason}");

        let strict = self::policy(json!({
            "version": 1, "operational": {"unknown": "warn"}
        }));
        let missing = evaluate(&strict, Some("MIT"), None, &[]).violations;
        assert_eq!(missing[0].rule, "operational.unknown");
        assert!(!missing[0].gates());
    }

    #[test]
    fn rejected_components_fail_and_approved_ones_waive_license_and_operational_findings() {
        let policy = policy(json!({
            "version": 1,
            "licenses": {"deny": ["category:strong-copyleft"]},
            "operational": {"deprecated": "deny"},
            "vulnerabilities": {"deny": "high"},
            "components": [
                {"ecosystem": "npm", "package": "widget", "decision": "approved",
                 "reason": "Legal review 42", "expiresAt": "2027-01-01T00:00:00Z"},
                {"ecosystem": "npm", "package": "gadget", "version": "2.0.0",
                 "decision": "rejected", "reason": "Known backdoor"},
                {"ecosystem": "PyPI", "package": "Some_Pkg", "decision": "rejected",
                 "reason": "Typosquat"}
            ]
        }));
        let release = ReleaseInfo {
            deprecated: Some(true),
            ..Default::default()
        };
        let advisories = [AdvisoryInput {
            id: "GHSA-9".into(),
            severity: Some("high".into()),
        }];
        let approved = evaluate(&policy, Some("GPL-3.0-only"), Some(&release), &advisories);
        let gating: Vec<&str> = approved
            .violations
            .iter()
            .filter(|violation| violation.gates())
            .map(|violation| violation.rule.as_str())
            .collect();
        // The approval does not cover the advisory.
        assert_eq!(gating, vec!["vulnerabilities.deny"]);
        let waived = approved
            .violations
            .iter()
            .filter(|violation| violation.waiver.is_some())
            .count();
        assert_eq!(waived, 2);

        let assessment = license::assess(Some("MIT"));
        let subject = |ecosystem: &'static str, name: &'static str, version: &'static str| {
            policy.evaluate(
                &Subject {
                    ecosystem,
                    name,
                    version,
                    license: &assessment,
                    release: None,
                    advisories: &[],
                },
                now(),
            )
        };
        assert_eq!(
            subject("npm", "gadget", "2.0.0").violations[0].rule,
            "components.rejected"
        );
        assert!(subject("npm", "gadget", "2.0.1").violations.is_empty());
        assert!(subject("PyPI", "gadget", "2.0.0").violations.is_empty());
        // PyPI names compare normalized.
        assert_eq!(subject("PyPI", "some-pkg", "1").violations.len(), 1);
    }

    #[test]
    fn an_expired_approval_stops_waiving_and_says_so() {
        let policy = policy(json!({
            "version": 1,
            "licenses": {"deny": ["GPL-3.0-only"]},
            "components": [
                {"ecosystem": "npm", "package": "widget", "decision": "approved",
                 "reason": "Until the rewrite", "expiresAt": "2026-01-01T00:00:00Z"}
            ]
        }));
        let outcome = evaluate(&policy, Some("GPL-3.0-only"), None, &[]);
        assert!(outcome.violations[0].gates());
        assert!(outcome.notes[0].contains("expired"), "{:?}", outcome.notes);
    }

    #[test]
    fn invalid_policies_are_refused_with_a_reason() {
        let cases = [
            json!({}),
            json!({"version": 2}),
            json!({"version": 1, "license": {}}),
            json!({"version": 1, "licenses": {"deny": ["GPL-9.9"]}}),
            json!({"version": 1, "licenses": {"deny": ["MIT OR ISC"]}}),
            json!({"version": 1, "licenses": {"deny": ["category:copyleft"]}}),
            json!({"version": 1, "licenses": {"deny": ["category:unknown"]}}),
            json!({"version": 1, "licenses": {"deny": ["MIT"], "allow": ["mit"]}}),
            json!({"version": 1, "licenses": {"deny": ["GPL-2.0"], "warn": ["GPL-2.0-only"]}}),
            json!({"version": 1, "licenses": {"deny": ["text:"]}}),
            json!({"version": 1, "licenses": {"allowOnly": true}}),
            json!({"version": 1, "licenses": {"allow": ["MIT"], "allowOnly": true}}),
            json!({"version": 1, "licenses": {"unknown": "block"}}),
            json!({"version": 1, "operational": {"maxAgeDays": {"warn": 10, "deny": 5}}}),
            json!({"version": 1, "operational": {"maxAgeDays": {"deny": 0}}}),
            json!({"version": 1, "operational": {"maxAgeDays": 30}}),
            json!({"version": 1, "vulnerabilities": {"deny": "medium", "warn": "high"}}),
            json!({"version": 1, "vulnerabilities": {"deny": "severe"}}),
            json!({"version": 1, "components": [
                {"ecosystem": "npm", "package": "x", "decision": "approved", "reason": " "}]}),
            json!({"version": 1, "components": [
                {"ecosystem": "npm", "package": "x", "decision": "maybe", "reason": "y"}]}),
            json!({"version": 1, "components": [
                {"ecosystem": "npm", "package": "x", "decision": "approved", "reason": "y",
                 "expiresAt": "soon"}]}),
            json!({"version": 1, "components": [
                {"ecosystem": "npm", "package": "", "decision": "approved", "reason": "y"}]}),
        ];
        for case in cases {
            let reason = invalid(case.clone());
            assert!(!reason.trim().is_empty(), "{case}");
        }
        let duplicate = invalid(json!({
            "version": 1, "licenses": {"deny": ["MIT"], "allow": ["mit"]}
        }));
        assert!(duplicate.contains("already listed under licenses.deny"), "{duplicate}");
    }

    #[test]
    fn package_names_compare_the_way_their_registry_does() {
        assert!(same_package("PyPI", "Django_Rest.Framework", "django-rest-framework"));
        assert!(same_package("NuGet", "Newtonsoft.Json", "newtonsoft.json"));
        assert!(!same_package("npm", "Lodash", "lodash"));
        assert!(same_package("npm", "@scope/pkg", "@scope/pkg"));
    }
}

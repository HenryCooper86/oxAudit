//! The composition report: every distinct component with its license
//! classification, release facts, open advisories and policy verdict.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::license::{self, LicenseAssessment};
use crate::policy::{
    severity_rank, Action, AdvisoryInput, ComponentPolicy, Subject, Violation, ViolationKind,
};
use crate::release::ReleaseInfo;

/// Carried by every rendering of the report.
pub const DISCLAIMER: &str = "License categories and policy verdicts are engineering triage \
     from declared metadata. They are not legal advice, and a component with no violation is \
     not thereby cleared for use.";

/// One advisory matched to a component.
#[derive(Clone, Debug)]
pub struct ComponentAdvisory {
    pub id: String,
    pub severity: Option<String>,
    /// Dismissed by the advisory policy: reported, never a violation.
    pub dismissed: bool,
}

/// One inventory occurrence handed to [`assess`]. Occurrences of the same
/// ecosystem, name and version are merged into one component.
#[derive(Clone, Debug, Default)]
pub struct ComponentInput {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub lockfile: String,
    pub license: Option<String>,
    /// Declared directly by the project (`true`), pulled in by another
    /// package (`false`), or not established by the lockfile (`None`).
    pub direct: Option<bool>,
    /// A registry release, as opposed to git, path or workspace code.
    pub registry: bool,
    pub advisories: Vec<ComponentAdvisory>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaComponent {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub lockfiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct: Option<bool>,
    pub registry: bool,
    pub license: LicenseAssessment,
    /// Absent when release facts were not collected for this component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseInfo>,
    /// Open advisory ids: matched and not dismissed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dismissed_advisories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    /// The worst unwaived policy action on this component.
    pub verdict: Action,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ViolationCounts {
    pub deny: usize,
    pub warn: usize,
    pub waived: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseCoverage {
    /// `collected`, `cached`, `notCollected` or `partial`.
    pub status: String,
    /// When the facts were fetched (epoch milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at_ms: Option<u64>,
    pub components_with_facts: usize,
    pub components_without_facts: usize,
    pub deprecated: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyInfo {
    /// Where the policy was read from, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// False when no policy file exists: the report classifies and gates
    /// nothing.
    pub loaded: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub generated_at: String,
    pub components: usize,
    pub direct_components: usize,
    /// Components whose lockfile did not establish direct or transitive.
    pub unclassified_relationship: usize,
    /// Components per license category slug.
    pub license_categories: BTreeMap<String, usize>,
    pub undeclared_licenses: usize,
    pub vulnerable_components: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    pub violations: ViolationCounts,
    pub releases: ReleaseCoverage,
    pub policy: PolicyInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaReport {
    pub schema_version: u32,
    pub kind: String,
    pub summary: ScaSummary,
    pub components: Vec<ScaComponent>,
    pub violations: Vec<Violation>,
    pub disclaimer: String,
}

impl ScaReport {
    /// Whether the policy fails this report: any unwaived `deny`.
    pub fn fails(&self) -> bool {
        self.violations.iter().any(Violation::gates)
    }
}

type Key = (String, String, String);

fn release_key(release: &ReleaseInfo) -> Key {
    (
        release.ecosystem.clone(),
        release.name.clone(),
        release.version.clone(),
    )
}

/// Build the report. `releases` holds whatever release facts were collected;
/// a component without an entry is reported as not evaluated.
pub fn assess(
    inputs: Vec<ComponentInput>,
    releases: &[ReleaseInfo],
    policy: &ComponentPolicy,
    now: DateTime<Utc>,
) -> ScaReport {
    let releases: BTreeMap<Key, &ReleaseInfo> = releases
        .iter()
        .map(|release| (release_key(release), release))
        .collect();

    struct Merged {
        lockfiles: Vec<String>,
        license: Option<String>,
        direct: Option<bool>,
        registry: bool,
        advisories: BTreeMap<String, (Option<String>, bool)>,
    }
    let mut merged: BTreeMap<Key, Merged> = BTreeMap::new();
    for input in inputs {
        let entry = merged
            .entry((input.ecosystem, input.name, input.version))
            .or_insert_with(|| Merged {
                lockfiles: Vec::new(),
                license: None,
                direct: None,
                registry: false,
                advisories: BTreeMap::new(),
            });
        if !input.lockfile.is_empty() && !entry.lockfiles.contains(&input.lockfile) {
            entry.lockfiles.push(input.lockfile);
        }
        if entry.license.is_none() {
            entry.license = input.license;
        }
        // Direct anywhere is direct; transitive needs every occurrence to
        // say so; one unknown occurrence leaves the answer unknown.
        entry.direct = match (entry.direct, input.direct, entry.lockfiles.len()) {
            (_, Some(true), _) | (Some(true), _, _) => Some(true),
            (_, value, 1) => value,
            (Some(false), Some(false), _) => Some(false),
            _ => None,
        };
        entry.registry |= input.registry;
        for advisory in input.advisories {
            let slot = entry
                .advisories
                .entry(advisory.id)
                .or_insert((advisory.severity.clone(), advisory.dismissed));
            // An advisory open on any occurrence is open.
            slot.1 &= advisory.dismissed;
            if slot.0.is_none() {
                slot.0 = advisory.severity;
            }
        }
    }

    let mut components = Vec::with_capacity(merged.len());
    let mut violations = Vec::new();
    let mut notes = Vec::new();
    let mut summary = ScaSummary {
        generated_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ..Default::default()
    };
    let mut highest = 0u8;
    for ((ecosystem, name, version), entry) in merged {
        let assessment = license::assess(entry.license.as_deref());
        let release = releases
            .get(&(ecosystem.clone(), name.clone(), version.clone()))
            .copied();
        let open: Vec<AdvisoryInput> = entry
            .advisories
            .iter()
            .filter(|(_, (_, dismissed))| !dismissed)
            .map(|(id, (severity, _))| AdvisoryInput {
                id: id.clone(),
                severity: severity.clone(),
            })
            .collect();
        let evaluation = policy.evaluate(
            &Subject {
                ecosystem: &ecosystem,
                name: &name,
                version: &version,
                license: &assessment,
                release,
                advisories: &open,
            },
            now,
        );
        let verdict = evaluation
            .violations
            .iter()
            .filter(|violation| violation.waiver.is_none())
            .map(|violation| violation.action)
            .max()
            .unwrap_or(Action::Allow);
        for violation in &evaluation.violations {
            match (violation.waiver.is_some(), violation.action) {
                (true, _) => summary.violations.waived += 1,
                (false, Action::Deny) => summary.violations.deny += 1,
                (false, _) => summary.violations.warn += 1,
            }
        }
        violations.extend(evaluation.violations);
        notes.extend(evaluation.notes);

        let worst = open
            .iter()
            .filter_map(|advisory| advisory.severity.as_deref())
            .max_by_key(|severity| severity_rank(severity))
            .map(str::to_ascii_lowercase);
        if !open.is_empty() {
            summary.vulnerable_components += 1;
            highest = highest.max(worst.as_deref().map_or(0, severity_rank));
        }
        *summary
            .license_categories
            .entry(assessment.category.slug().to_string())
            .or_default() += 1;
        if assessment.declared.is_none() {
            summary.undeclared_licenses += 1;
        }
        match entry.direct {
            Some(true) => summary.direct_components += 1,
            Some(false) => {}
            None => summary.unclassified_relationship += 1,
        }
        match release.filter(|release| release.has_facts()) {
            Some(release) => {
                summary.releases.components_with_facts += 1;
                if release.deprecated == Some(true) {
                    summary.releases.deprecated += 1;
                }
            }
            None => summary.releases.components_without_facts += 1,
        }
        components.push(ScaComponent {
            ecosystem,
            name,
            version,
            lockfiles: entry.lockfiles,
            direct: entry.direct,
            registry: entry.registry,
            license: assessment,
            release: release.cloned(),
            advisories: open.into_iter().map(|advisory| advisory.id).collect(),
            dismissed_advisories: entry
                .advisories
                .into_iter()
                .filter(|(_, (_, dismissed))| *dismissed)
                .map(|(id, _)| id)
                .collect(),
            highest_severity: worst,
            verdict,
        });
    }
    // What blocks the build first, then warnings, then what was waived.
    let rank = |violation: &Violation| match (violation.waiver.is_some(), violation.action) {
        (false, Action::Deny) => 0u8,
        (false, _) => 1,
        (true, _) => 2,
    };
    violations.sort_by(|left, right| {
        (rank(left), left.kind, &left.name, &left.version).cmp(&(
            rank(right),
            right.kind,
            &right.name,
            &right.version,
        ))
    });
    summary.components = components.len();
    summary.highest_severity = ["info", "low", "medium", "high", "critical"]
        .into_iter()
        .find(|severity| severity_rank(severity) == highest && highest > 0)
        .map(String::from);
    summary.releases.status = "notCollected".into();
    summary.policy.loaded = false;
    summary.notes = notes;
    ScaReport {
        schema_version: 1,
        kind: "sca".into(),
        summary,
        components,
        violations,
        disclaimer: DISCLAIMER.into(),
    }
}

/// Violations of one kind, for renderers that group them.
pub fn violations_of(report: &ScaReport, kind: ViolationKind) -> Vec<&Violation> {
    report
        .violations
        .iter()
        .filter(|violation| violation.kind == kind)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        "2026-11-16T00:00:00Z".parse().unwrap()
    }

    fn input(name: &str, version: &str, license: Option<&str>) -> ComponentInput {
        ComponentInput {
            ecosystem: "npm".into(),
            name: name.into(),
            version: version.into(),
            lockfile: "package-lock.json".into(),
            license: license.map(String::from),
            direct: Some(true),
            registry: true,
            advisories: Vec::new(),
        }
    }

    fn advisory(id: &str, severity: &str, dismissed: bool) -> ComponentAdvisory {
        ComponentAdvisory {
            id: id.into(),
            severity: Some(severity.into()),
            dismissed,
        }
    }

    #[test]
    fn occurrences_merge_into_one_component_and_keep_every_lockfile() {
        let mut second = input("a", "1.0.0", Some("MIT"));
        second.lockfile = "apps/web/package-lock.json".into();
        second.direct = Some(false);
        second.advisories = vec![advisory("GHSA-1", "high", false)];
        let mut first = input("a", "1.0.0", None);
        first.advisories = vec![
            advisory("GHSA-1", "high", true),
            advisory("GHSA-2", "low", true),
        ];
        let report = assess(
            vec![first, second, input("a", "2.0.0", Some("ISC"))],
            &[],
            &ComponentPolicy::default(),
            now(),
        );
        assert_eq!(report.summary.components, 2);
        let merged = &report.components[0];
        assert_eq!(
            merged.lockfiles,
            vec!["package-lock.json", "apps/web/package-lock.json"]
        );
        // The license one occurrence declared fills the component.
        assert_eq!(merged.license.expression.as_deref(), Some("MIT"));
        // Direct in one lockfile is direct.
        assert_eq!(merged.direct, Some(true));
        // Open on one occurrence is open; dismissed everywhere is dismissed.
        assert_eq!(merged.advisories, vec!["GHSA-1"]);
        assert_eq!(merged.dismissed_advisories, vec!["GHSA-2"]);
        assert_eq!(merged.highest_severity.as_deref(), Some("high"));
        assert_eq!(report.summary.vulnerable_components, 1);
        assert_eq!(report.summary.highest_severity.as_deref(), Some("high"));
        assert_eq!(report.summary.license_categories["permissive"], 2);
        assert!(!report.fails());
        assert_eq!(report.disclaimer, DISCLAIMER);
    }

    #[test]
    fn direct_is_unknown_unless_every_occurrence_agrees_or_one_is_direct() {
        let occurrence = |lockfile: &str, direct| {
            let mut item = input("a", "1.0.0", Some("MIT"));
            item.lockfile = lockfile.into();
            item.direct = direct;
            item
        };
        let direct = |items: Vec<ComponentInput>| {
            assess(items, &[], &ComponentPolicy::default(), now()).components[0].direct
        };
        assert_eq!(direct(vec![occurrence("x", None)]), None);
        assert_eq!(
            direct(vec![occurrence("x", Some(false)), occurrence("y", Some(false))]),
            Some(false)
        );
        assert_eq!(
            direct(vec![occurrence("x", Some(false)), occurrence("y", None)]),
            None
        );
        assert_eq!(
            direct(vec![occurrence("x", None), occurrence("y", Some(true))]),
            Some(true)
        );
    }

    #[test]
    fn the_report_counts_violations_and_fails_only_on_unwaived_denies() {
        let policy = ComponentPolicy::from_value(json!({
            "version": 1,
            "licenses": {"deny": ["category:strong-copyleft"], "unknown": "warn"},
            "operational": {"deprecated": "deny"},
            "components": [
                {"ecosystem": "npm", "package": "c", "decision": "approved",
                 "reason": "Build tool, not shipped"}
            ]
        }))
        .unwrap();
        let releases = vec![ReleaseInfo {
            ecosystem: "npm".into(),
            name: "a".into(),
            version: "1.0.0".into(),
            deprecated: Some(true),
            ..Default::default()
        }];
        let inputs = vec![
            input("a", "1.0.0", Some("MIT")),
            input("b", "1.0.0", None),
            input("c", "1.0.0", Some("GPL-3.0-only")),
        ];
        let report = assess(inputs.clone(), &releases, &policy, now());
        assert_eq!(
            report.summary.violations,
            ViolationCounts {
                deny: 1,
                warn: 1,
                waived: 1
            }
        );
        assert!(report.fails());
        // The failing rule leads the list.
        assert_eq!(report.violations[0].rule, "operational.deprecated");
        let verdicts: Vec<Action> = report.components.iter().map(|c| c.verdict).collect();
        assert_eq!(verdicts, vec![Action::Deny, Action::Warn, Action::Allow]);
        assert_eq!(report.summary.releases.components_with_facts, 1);
        assert_eq!(report.summary.releases.components_without_facts, 2);
        assert_eq!(report.summary.releases.deprecated, 1);
        assert_eq!(report.summary.undeclared_licenses, 1);
        assert_eq!(violations_of(&report, ViolationKind::License).len(), 2);

        // Without the deprecation fact nothing fails: warn and waived only.
        let report = assess(inputs, &[], &policy, now());
        assert!(!report.fails());
    }

    #[test]
    fn the_report_round_trips_through_json() {
        let report = assess(
            vec![input("a", "1.0.0", Some("MIT OR Apache-2.0"))],
            &[],
            &ComponentPolicy::default(),
            now(),
        );
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["kind"], "sca");
        assert_eq!(value["summary"]["generatedAt"], "2026-11-16T00:00:00Z");
        assert_eq!(value["components"][0]["license"]["category"], "permissive");
        assert_eq!(value["components"][0]["verdict"], "allow");
        let back: ScaReport = serde_json::from_value(value).unwrap();
        assert_eq!(back, report);
    }
}

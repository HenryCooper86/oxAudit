//! The portfolio view: composition reports of several projects side by side.
//!
//! Each entry is one project's latest stored report. The portfolio answers
//! three questions: how each project stands against policy, which components
//! the projects share, and where one named component is used.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::policy::{same_package, severity_rank, Action};
use crate::report::{ScaComponent, ScaReport, ViolationCounts};

/// One project's report, with the run it came from.
#[derive(Clone, Debug)]
pub struct ProjectEntry {
    pub target: String,
    pub run_id: String,
    /// When the run finished (epoch milliseconds), when the run records it.
    pub scanned_at_ms: Option<u64>,
    pub report: ScaReport,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRow {
    pub target: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_at_ms: Option<u64>,
    pub components: usize,
    pub vulnerable_components: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    pub license_categories: BTreeMap<String, usize>,
    pub violations: ViolationCounts,
    /// `fail` on any unwaived deny, else `warn` on any warning, else `pass`.
    pub status: String,
    /// False when release facts were not collected, so operational rules
    /// could not be evaluated for this project.
    pub release_facts: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioTotals {
    pub projects: usize,
    pub failing_projects: usize,
    /// Distinct ecosystem/name/version triples across all projects.
    pub distinct_components: usize,
    pub violations: ViolationCounts,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioSummary {
    pub schema_version: u32,
    pub kind: String,
    pub totals: PortfolioTotals,
    pub projects: Vec<ProjectRow>,
}

fn status(counts: &ViolationCounts) -> &'static str {
    if counts.deny > 0 {
        "fail"
    } else if counts.warn > 0 {
        "warn"
    } else {
        "pass"
    }
}

/// One row per project, failing projects first.
pub fn summarize(entries: &[ProjectEntry]) -> PortfolioSummary {
    let mut totals = PortfolioTotals {
        projects: entries.len(),
        ..Default::default()
    };
    let mut distinct = BTreeSet::new();
    let mut projects: Vec<ProjectRow> = entries
        .iter()
        .map(|entry| {
            let summary = &entry.report.summary;
            for component in &entry.report.components {
                distinct.insert((&component.ecosystem, &component.name, &component.version));
            }
            totals.violations.deny += summary.violations.deny;
            totals.violations.warn += summary.violations.warn;
            totals.violations.waived += summary.violations.waived;
            if summary.violations.deny > 0 {
                totals.failing_projects += 1;
            }
            ProjectRow {
                target: entry.target.clone(),
                run_id: entry.run_id.clone(),
                scanned_at_ms: entry.scanned_at_ms,
                components: summary.components,
                vulnerable_components: summary.vulnerable_components,
                highest_severity: summary.highest_severity.clone(),
                license_categories: summary.license_categories.clone(),
                violations: summary.violations.clone(),
                status: status(&summary.violations).into(),
                release_facts: summary.releases.components_with_facts > 0,
            }
        })
        .collect();
    totals.distinct_components = distinct.len();
    projects.sort_by(|left, right| {
        (right.violations.deny, right.violations.warn, &left.target).cmp(&(
            left.violations.deny,
            left.violations.warn,
            &right.target,
        ))
    });
    PortfolioSummary {
        schema_version: 1,
        kind: "portfolio".into(),
        totals,
        projects,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VersionUsage {
    pub version: String,
    pub projects: Vec<String>,
}

/// One package across the portfolio.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComponentUsage {
    pub ecosystem: String,
    pub name: String,
    pub project_count: usize,
    pub versions: Vec<VersionUsage>,
    /// Every license expression declared for the package, across versions.
    pub licenses: Vec<String>,
    pub license_categories: Vec<String>,
    /// The worst verdict any project gave any version.
    pub verdict: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
}

/// Every package in the portfolio, most widely used first.
pub fn components(entries: &[ProjectEntry]) -> Vec<ComponentUsage> {
    struct Usage {
        versions: BTreeMap<String, BTreeSet<String>>,
        projects: BTreeSet<String>,
        licenses: BTreeSet<String>,
        categories: BTreeSet<String>,
        verdict: Action,
        severity: Option<String>,
    }
    let mut packages: BTreeMap<(String, String), Usage> = BTreeMap::new();
    for entry in entries {
        for component in &entry.report.components {
            let usage = packages
                .entry((component.ecosystem.clone(), component.name.clone()))
                .or_insert_with(|| Usage {
                    versions: BTreeMap::new(),
                    projects: BTreeSet::new(),
                    licenses: BTreeSet::new(),
                    categories: BTreeSet::new(),
                    verdict: Action::Allow,
                    severity: None,
                });
            usage
                .versions
                .entry(component.version.clone())
                .or_default()
                .insert(entry.target.clone());
            usage.projects.insert(entry.target.clone());
            if let Some(expression) = &component.license.expression {
                usage.licenses.insert(expression.clone());
            }
            usage
                .categories
                .insert(component.license.category.slug().to_string());
            usage.verdict = usage.verdict.max(component.verdict);
            let rank = |severity: &Option<String>| severity.as_deref().map_or(0, severity_rank);
            if rank(&component.highest_severity) > rank(&usage.severity) {
                usage.severity = component.highest_severity.clone();
            }
        }
    }
    let mut rows: Vec<ComponentUsage> = packages
        .into_iter()
        .map(|((ecosystem, name), usage)| ComponentUsage {
            ecosystem,
            name,
            project_count: usage.projects.len(),
            versions: usage
                .versions
                .into_iter()
                .map(|(version, projects)| VersionUsage {
                    version,
                    projects: projects.into_iter().collect(),
                })
                .collect(),
            licenses: usage.licenses.into_iter().collect(),
            license_categories: usage.categories.into_iter().collect(),
            verdict: usage.verdict,
            highest_severity: usage.severity,
        })
        .collect();
    rows.sort_by(|left, right| {
        (right.project_count, &left.ecosystem, &left.name).cmp(&(
            left.project_count,
            &right.ecosystem,
            &right.name,
        ))
    });
    rows
}

/// One place a component is used.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhereUsed {
    pub target: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_at_ms: Option<u64>,
    pub component: ScaComponent,
}

/// Every project that uses the named package. `ecosystem` and `version`
/// narrow the match when given.
pub fn where_used(
    entries: &[ProjectEntry],
    ecosystem: Option<&str>,
    name: &str,
    version: Option<&str>,
) -> Vec<WhereUsed> {
    let mut found = Vec::new();
    for entry in entries {
        for component in &entry.report.components {
            if ecosystem.is_some_and(|wanted| !wanted.eq_ignore_ascii_case(&component.ecosystem))
                || !same_package(&component.ecosystem, &component.name, name)
                || version.is_some_and(|wanted| wanted != component.version)
            {
                continue;
            }
            found.push(WhereUsed {
                target: entry.target.clone(),
                run_id: entry.run_id.clone(),
                scanned_at_ms: entry.scanned_at_ms,
                component: component.clone(),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ComponentPolicy;
    use crate::report::{assess, ComponentAdvisory, ComponentInput};
    use serde_json::json;

    fn project(target: &str, components: &[(&str, &str, &str, &str)]) -> ProjectEntry {
        let policy = ComponentPolicy::from_value(json!({
            "version": 1,
            "licenses": {"deny": ["category:strong-copyleft"], "warn": ["category:weak-copyleft"]}
        }))
        .unwrap();
        let inputs = components
            .iter()
            .map(|(ecosystem, name, version, license)| ComponentInput {
                ecosystem: (*ecosystem).into(),
                name: (*name).into(),
                version: (*version).into(),
                lockfile: "lock".into(),
                license: Some((*license).into()),
                direct: Some(true),
                registry: true,
                advisories: if *name == "lodash" && *version == "4.17.20" {
                    vec![ComponentAdvisory {
                        id: "GHSA-1".into(),
                        severity: Some("high".into()),
                        dismissed: false,
                    }]
                } else {
                    Vec::new()
                },
            })
            .collect();
        ProjectEntry {
            target: target.into(),
            run_id: format!("run-{target}"),
            scanned_at_ms: Some(1),
            report: assess(inputs, &[], &policy, "2026-11-16T00:00:00Z".parse().unwrap()),
        }
    }

    fn portfolio() -> Vec<ProjectEntry> {
        vec![
            project(
                "/srv/api",
                &[
                    ("npm", "lodash", "4.17.20", "MIT"),
                    ("npm", "readline", "1.0.0", "GPL-3.0-only"),
                ],
            ),
            project(
                "/srv/web",
                &[
                    ("npm", "lodash", "4.17.21", "MIT"),
                    ("npm", "mpl-thing", "2.0.0", "MPL-2.0"),
                ],
            ),
            project("/srv/worker", &[("PyPI", "Django_Rest", "3.0", "BSD-3-Clause")]),
        ]
    }

    #[test]
    fn the_summary_ranks_failing_projects_first_and_totals_distinct_components() {
        let summary = summarize(&portfolio());
        assert_eq!(summary.totals.projects, 3);
        assert_eq!(summary.totals.failing_projects, 1);
        assert_eq!(summary.totals.distinct_components, 5);
        assert_eq!(summary.totals.violations.deny, 1);
        assert_eq!(summary.totals.violations.warn, 1);
        let order: Vec<(&str, &str)> = summary
            .projects
            .iter()
            .map(|row| (row.target.as_str(), row.status.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![("/srv/api", "fail"), ("/srv/web", "warn"), ("/srv/worker", "pass")]
        );
        assert_eq!(summary.projects[0].highest_severity.as_deref(), Some("high"));
        assert!(!summary.projects[0].release_facts);
        assert_eq!(serde_json::to_value(&summary).unwrap()["kind"], "portfolio");
    }

    #[test]
    fn components_group_versions_by_project_with_the_worst_verdict() {
        let rows = components(&portfolio());
        assert_eq!(rows[0].name, "lodash");
        assert_eq!(rows[0].project_count, 2);
        assert_eq!(
            rows[0].versions,
            vec![
                VersionUsage {
                    version: "4.17.20".into(),
                    projects: vec!["/srv/api".into()]
                },
                VersionUsage {
                    version: "4.17.21".into(),
                    projects: vec!["/srv/web".into()]
                },
            ]
        );
        assert_eq!(rows[0].highest_severity.as_deref(), Some("high"));
        let readline = rows.iter().find(|row| row.name == "readline").unwrap();
        assert_eq!(readline.verdict, Action::Deny);
        assert_eq!(readline.license_categories, vec!["strong-copyleft"]);
    }

    #[test]
    fn where_used_matches_names_the_registry_way_and_narrows_on_request() {
        let entries = portfolio();
        let targets = |ecosystem, name, version| {
            where_used(&entries, ecosystem, name, version)
                .into_iter()
                .map(|usage| usage.target)
                .collect::<Vec<_>>()
        };
        assert_eq!(targets(None, "lodash", None), vec!["/srv/api", "/srv/web"]);
        assert_eq!(targets(None, "lodash", Some("4.17.21")), vec!["/srv/web"]);
        assert_eq!(targets(Some("pypi"), "django-rest", None), vec!["/srv/worker"]);
        assert!(targets(Some("npm"), "django-rest", None).is_empty());
        assert!(targets(None, "Lodash", None).is_empty());
    }
}

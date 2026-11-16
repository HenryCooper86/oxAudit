//! Report formats and log commands for CI systems other than GitHub.
//!
//! - JUnit XML, which Jenkins, Azure Pipelines, GitLab, Bitbucket and
//!   CircleCI all render as test results.
//! - GitLab's Code Quality report, shown in merge requests on every tier.
//! - GitLab's Dependency Scanning report (schema 15), for the security
//!   widgets.
//! - Azure Pipelines `##vso[task.logissue]` commands.
//!
//! Everything here renders results a scan already produced; nothing is
//! detected or decided in this module.

use std::path::Path;

use oxaudit_sca::{Action, ScaReport};
use serde_json::{json, Value};

use crate::models::{DependencyScanResult, Finding, Vulnerability};

/// What one JUnit test case reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    Passed,
    /// Fails the suite: a finding at or above the gate.
    Failed {
        message: String,
        detail: String,
    },
    /// Reported without failing: below the gate, dismissed or waived.
    Skipped {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Case {
    pub classname: String,
    pub name: String,
    pub outcome: Outcome,
}

/// Escape text for XML content and attributes, dropping the control
/// characters XML 1.0 cannot carry at all.
fn xml(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            '\r' => {}
            character if character.is_control() => {}
            '\u{FFFE}' | '\u{FFFF}' => {}
            character => out.push(character),
        }
    }
    out
}

/// Render one JUnit suite. An empty case list becomes a single passing case
/// named `completed`: CI test publishers treat a report with no tests as an
/// error, and the scan did run.
pub(super) fn junit(suite: &str, cases: &[Case]) -> Vec<u8> {
    let completed = [Case {
        classname: suite.to_string(),
        name: "completed with nothing to report".into(),
        outcome: Outcome::Passed,
    }];
    let cases = if cases.is_empty() {
        &completed[..]
    } else {
        cases
    };
    let failures = cases
        .iter()
        .filter(|case| matches!(case.outcome, Outcome::Failed { .. }))
        .count();
    let skipped = cases
        .iter()
        .filter(|case| matches!(case.outcome, Outcome::Skipped { .. }))
        .count();
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"oxAudit\" tests=\"{total}\" \
         failures=\"{failures}\" skipped=\"{skipped}\">\n  <testsuite name=\"{name}\" \
         tests=\"{total}\" failures=\"{failures}\" errors=\"0\" skipped=\"{skipped}\">\n",
        total = cases.len(),
        name = xml(suite),
    );
    for case in cases {
        let open = format!(
            "    <testcase classname=\"{}\" name=\"{}\"",
            xml(&case.classname),
            xml(&case.name)
        );
        match &case.outcome {
            Outcome::Passed => out.push_str(&format!("{open}/>\n")),
            Outcome::Failed { message, detail } => out.push_str(&format!(
                "{open}>\n      <failure message=\"{}\">{}</failure>\n    </testcase>\n",
                xml(message),
                xml(detail)
            )),
            Outcome::Skipped { message } => out.push_str(&format!(
                "{open}>\n      <skipped message=\"{}\"/>\n    </testcase>\n",
                xml(message)
            )),
        }
    }
    out.push_str("  </testsuite>\n</testsuites>\n");
    out.into_bytes()
}

/// One case per source finding. `gates` says whether a finding fails the
/// build under the gate in force.
pub(super) fn source_cases(
    findings: &[Finding],
    prefix: &str,
    gates: impl Fn(&Finding) -> bool,
) -> Vec<Case> {
    findings
        .iter()
        .map(|finding| {
            let location = format!("{prefix}{}:{}", finding.file_path, finding.line);
            let message = format!("{} {}", finding.severity.to_uppercase(), finding.title);
            Case {
                classname: format!("{prefix}{}", finding.file_path),
                name: format!("{} (line {})", finding.rule_id, finding.line),
                outcome: if gates(finding) {
                    Outcome::Failed {
                        message,
                        detail: format!(
                            "{location}\n{}\n{}",
                            finding.description, finding.recommendation
                        ),
                    }
                } else {
                    Outcome::Skipped {
                        message: format!("{message} — reported, not gating"),
                    }
                },
            }
        })
        .collect()
}

fn advisory_title(vulnerability: &Vulnerability) -> String {
    let summary = vulnerability.summary.trim();
    if summary.is_empty() {
        vulnerability.id.clone()
    } else {
        format!("{}: {summary}", vulnerability.id)
    }
}

fn fix_text(vulnerability: &Vulnerability) -> String {
    if vulnerability.fixed_versions.is_empty() {
        "No fixed version is published.".into()
    } else {
        format!("Upgrade to {}.", vulnerability.fixed_versions.join(" or "))
    }
}

/// One case per advisory occurrence.
pub(super) fn advisory_cases(
    result: &DependencyScanResult,
    prefix: &str,
    gates: impl Fn(&Vulnerability) -> bool,
) -> Vec<Case> {
    result
        .vulnerabilities
        .iter()
        .map(|vulnerability| {
            let severity = vulnerability
                .severity
                .as_deref()
                .unwrap_or("unknown")
                .to_uppercase();
            let message = format!("{severity} {}", advisory_title(vulnerability));
            Case {
                classname: format!(
                    "{prefix}{}",
                    relative(&vulnerability.lockfile, &result.summary.path)
                ),
                name: format!(
                    "{} {} {}",
                    vulnerability.package_name, vulnerability.installed_version, vulnerability.id
                ),
                outcome: if gates(vulnerability) {
                    Outcome::Failed {
                        message,
                        detail: fix_text(vulnerability),
                    }
                } else if vulnerability.review.is_some() {
                    Outcome::Skipped {
                        message: format!("{message} — dismissed by advisory policy"),
                    }
                } else {
                    Outcome::Skipped {
                        message: format!("{message} — reported, not gating"),
                    }
                },
            }
        })
        .collect()
}

/// One case per policy violation.
pub(super) fn policy_cases(report: &ScaReport) -> Vec<Case> {
    report
        .violations
        .iter()
        .map(|violation| {
            let message = format!("{} [{}]", violation.message, violation.rule);
            Case {
                classname: format!("policy.{}", kind_name(violation.kind)),
                name: format!(
                    "{} {} {} {}",
                    violation.ecosystem, violation.name, violation.version, violation.rule
                ),
                outcome: match (&violation.waiver, violation.action) {
                    (Some(waiver), _) => Outcome::Skipped {
                        message: format!("{message} — waived: {}", waiver.reason),
                    },
                    (None, Action::Deny) => Outcome::Failed {
                        message,
                        detail: String::new(),
                    },
                    (None, _) => Outcome::Skipped {
                        message: format!("{message} — warning"),
                    },
                },
            }
        })
        .collect()
}

fn kind_name(kind: oxaudit_sca::ViolationKind) -> &'static str {
    match kind {
        oxaudit_sca::ViolationKind::Component => "component",
        oxaudit_sca::ViolationKind::License => "license",
        oxaudit_sca::ViolationKind::Vulnerability => "vulnerability",
        oxaudit_sca::ViolationKind::Operational => "operational",
    }
}

/// A lockfile path relative to the scan root, with forward slashes.
fn relative(path: &str, root: &str) -> String {
    let path = path.replace('\\', "/");
    let root = root.replace('\\', "/");
    path.strip_prefix(root.trim_end_matches('/'))
        .map(|rest| rest.trim_start_matches('/').to_string())
        .filter(|rest| !rest.is_empty())
        .unwrap_or(path)
}

fn fingerprint(parts: &[&str]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

/// GitLab Code Quality grades: info, minor, major, critical, blocker.
fn quality_severity(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "blocker",
        "high" => "critical",
        "medium" => "major",
        "low" => "minor",
        _ => "info",
    }
}

fn quality_entry(
    description: String,
    check: &str,
    severity: &str,
    path: String,
    line: usize,
    id: &[&str],
) -> Value {
    json!({
        "description": description,
        "check_name": check,
        "fingerprint": fingerprint(id),
        "severity": quality_severity(severity),
        "location": {"path": path, "lines": {"begin": line.max(1)}},
    })
}

/// Source findings as a GitLab Code Quality report.
pub(super) fn code_quality_source(findings: &[Finding], prefix: &str) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|finding| {
                quality_entry(
                    finding.title.clone(),
                    &finding.rule_id,
                    &finding.severity,
                    format!("{prefix}{}", finding.file_path),
                    finding.line,
                    &["source", &finding.id],
                )
            })
            .collect(),
    )
}

/// Open advisories as Code Quality entries on their lockfile. Dismissed
/// advisories are left out: Code Quality has no state for "reviewed".
pub(super) fn code_quality_advisories(result: &DependencyScanResult, prefix: &str) -> Vec<Value> {
    result
        .vulnerabilities
        .iter()
        .filter(|vulnerability| vulnerability.review.is_none())
        .map(|vulnerability| {
            let lockfile = relative(&vulnerability.lockfile, &result.summary.path);
            quality_entry(
                format!(
                    "{} {}: {}. {}",
                    vulnerability.package_name,
                    vulnerability.installed_version,
                    advisory_title(vulnerability),
                    fix_text(vulnerability)
                ),
                &vulnerability.id,
                vulnerability.severity.as_deref().unwrap_or(""),
                format!("{prefix}{lockfile}"),
                1,
                &[
                    "advisory",
                    &vulnerability.id,
                    &vulnerability.ecosystem,
                    &vulnerability.package_name,
                    &vulnerability.installed_version,
                    &lockfile,
                ],
            )
        })
        .collect()
}

/// Unwaived policy violations as Code Quality entries on the component's
/// first lockfile.
pub(super) fn code_quality_policy(report: &ScaReport, prefix: &str) -> Vec<Value> {
    report
        .violations
        .iter()
        .filter(|violation| violation.waiver.is_none())
        .map(|violation| {
            let lockfile = report
                .components
                .iter()
                .find(|component| {
                    component.ecosystem == violation.ecosystem
                        && component.name == violation.name
                        && component.version == violation.version
                })
                .and_then(|component| component.lockfiles.first().cloned())
                .unwrap_or_default();
            quality_entry(
                format!(
                    "{} {}: {}",
                    violation.name, violation.version, violation.message
                ),
                &violation.rule,
                if violation.action == Action::Deny {
                    "high"
                } else {
                    "low"
                },
                format!("{prefix}{lockfile}"),
                1,
                &[
                    "policy",
                    &violation.rule,
                    &violation.ecosystem,
                    &violation.name,
                    &violation.version,
                ],
            )
        })
        .collect()
}

fn gitlab_severity(severity: Option<&str>) -> &'static str {
    match severity.unwrap_or("").to_ascii_lowercase().as_str() {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        "info" => "Info",
        _ => "Unknown",
    }
}

fn gitlab_package_manager(ecosystem: &str) -> &'static str {
    match ecosystem {
        "npm" => "npm",
        "PyPI" => "pip",
        "Maven" => "maven",
        "crates.io" => "cargo",
        "Go" => "go",
        "NuGet" => "nuget",
        "RubyGems" => "bundler",
        "Packagist" => "composer",
        "Pub" => "pub",
        "Hex" => "mix",
        _ => "unknown",
    }
}

fn gitlab_identifier(id: &str) -> Value {
    let upper = id.to_ascii_uppercase();
    let (kind, url) = if upper.starts_with("CVE-") {
        ("cve", format!("https://www.cve.org/CVERecord?id={upper}"))
    } else if upper.starts_with("GHSA-") {
        ("ghsa", format!("https://github.com/advisories/{id}"))
    } else {
        ("osv", format!("https://osv.dev/vulnerability/{id}"))
    };
    json!({"type": kind, "name": id, "value": id, "url": url})
}

/// GitLab wants `YYYY-MM-DDTHH:MM:SS` in UTC, with no zone suffix.
fn gitlab_time(epoch_ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(epoch_ms).unwrap_or(0))
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

/// A dependency scan as a GitLab Dependency Scanning report. Dismissed
/// advisories are left out, as in Code Quality.
pub(super) fn gitlab_dependency_scanning(
    result: &DependencyScanResult,
    prefix: &str,
    ended_at_ms: u64,
) -> Value {
    let tool = json!({
        "id": "oxaudit",
        "name": "oxAudit",
        "version": env!("CARGO_PKG_VERSION"),
        "vendor": {"name": "oxAudit"},
    });
    let root = &result.summary.path;
    let vulnerabilities: Vec<Value> = result
        .vulnerabilities
        .iter()
        .filter(|vulnerability| vulnerability.review.is_none())
        .map(|vulnerability| {
            let lockfile = relative(&vulnerability.lockfile, root);
            let digest = fingerprint(&[
                &vulnerability.id,
                &vulnerability.ecosystem,
                &vulnerability.package_name,
                &vulnerability.installed_version,
                &lockfile,
            ]);
            let mut identifiers = vec![gitlab_identifier(&vulnerability.id)];
            identifiers.extend(vulnerability.aliases.iter().take(19).map(|alias| gitlab_identifier(alias)));
            let description = if vulnerability.details.trim().is_empty() {
                advisory_title(vulnerability)
            } else {
                vulnerability.details.chars().take(4_000).collect()
            };
            json!({
                // A stable UUID-shaped id, so GitLab tracks the same finding across pipelines.
                "id": format!("{}-{}-{}-{}-{}", &digest[0..8], &digest[8..12], &digest[12..16], &digest[16..20], &digest[20..32]),
                "name": advisory_title(vulnerability).chars().take(255).collect::<String>(),
                "description": description,
                "severity": gitlab_severity(vulnerability.severity.as_deref()),
                "solution": fix_text(vulnerability),
                "identifiers": identifiers,
                "links": vulnerability.references.iter().take(20).map(|url| json!({"url": url})).collect::<Vec<_>>(),
                "location": {
                    "file": format!("{prefix}{lockfile}"),
                    "dependency": {
                        "package": {"name": vulnerability.package_name},
                        "version": vulnerability.installed_version,
                    },
                },
            })
        })
        .collect();
    let mut files: std::collections::BTreeMap<String, (String, Vec<Value>)> = Default::default();
    for dependency in &result.dependencies {
        let lockfile = format!("{prefix}{}", relative(&dependency.lockfile, root));
        let entry = files.entry(lockfile).or_insert_with(|| {
            (
                gitlab_package_manager(&dependency.ecosystem).to_string(),
                Vec::new(),
            )
        });
        if !dependency.name.is_empty() && !dependency.version.is_empty() {
            entry.1.push(json!({
                "package": {"name": dependency.name},
                "version": dependency.version,
            }));
        }
    }
    let started = ended_at_ms.saturating_sub(result.summary.duration_ms);
    json!({
        "version": "15.0.7",
        "scan": {
            "analyzer": tool,
            "scanner": tool,
            "type": "dependency_scanning",
            "start_time": gitlab_time(started),
            "end_time": gitlab_time(ended_at_ms),
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
        "dependency_files": files.into_iter().map(|(path, (package_manager, dependencies))| json!({
            "path": path,
            "package_manager": package_manager,
            "dependencies": dependencies,
        })).collect::<Vec<_>>(),
    })
}

/// The scan root's path inside the CI checkout, with a trailing slash, or
/// empty when the scan root is the checkout or no CI system names one.
/// Finding and lockfile paths are scan-root-relative; CI viewers resolve
/// paths from the checkout root.
pub(super) fn workspace_prefix(scan_root: &Path) -> String {
    workspace_prefix_from(scan_root, |name| std::env::var_os(name))
}

/// Checkout-root variables: GitHub Actions, GitLab CI, Azure Pipelines,
/// Bitbucket Pipelines, Jenkins.
const WORKSPACE_VARIABLES: [&str; 5] = [
    "GITHUB_WORKSPACE",
    "CI_PROJECT_DIR",
    "BUILD_SOURCESDIRECTORY",
    "BITBUCKET_CLONE_DIR",
    "WORKSPACE",
];

fn workspace_prefix_from(
    scan_root: &Path,
    variable: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> String {
    let Ok(root) = scan_root.canonicalize() else {
        return String::new();
    };
    for name in WORKSPACE_VARIABLES {
        let Some(workspace) = variable(name).and_then(|value| std::fs::canonicalize(value).ok())
        else {
            continue;
        };
        if let Ok(relative) = root.strip_prefix(&workspace) {
            return if relative.as_os_str().is_empty() {
                String::new()
            } else {
                format!("{}/", relative.to_string_lossy().replace('\\', "/"))
            };
        }
    }
    String::new()
}

/// Escape a value inside an Azure Pipelines logging command.
fn azure_escape(value: &str) -> String {
    value
        .replace('%', "%AZP25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(';', "%3B")
        .replace(']', "%5D")
}

/// One `##vso[task.logissue]` line per finding, which Azure Pipelines shows
/// on the run and links to the file.
pub(super) fn azure_issue_lines(findings: &[Finding], prefix: &str) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            let kind = match finding.severity.to_ascii_lowercase().as_str() {
                "critical" | "high" => "error",
                _ => "warning",
            };
            format!(
                "##vso[task.logissue type={kind};sourcepath={};linenumber={};columnnumber={};code={}]{}",
                azure_escape(&format!("{prefix}{}", finding.file_path)),
                finding.line,
                finding.column,
                azure_escape(&finding.rule_id),
                azure_escape(&finding.title),
            )
        })
        .collect()
}

/// Emit Azure Pipelines issues on stderr when running under Azure Pipelines.
pub(super) fn emit_azure_issues(findings: &[Finding], scan_root: &Path) {
    if std::env::var_os("TF_BUILD").is_none() {
        return;
    }
    for line in azure_issue_lines(findings, &workspace_prefix(scan_root)) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str) -> Finding {
        serde_json::from_value(json!({
            "id": "f1", "category": "vulnerability", "ruleId": "js-eval", "ruleName": "eval",
            "severity": severity, "title": "eval() of <user> \"input\"", "description": "Dynamic code.",
            "filePath": "src/app.js", "line": 7, "column": 3, "matchText": "eval(x)", "context": "",
            "language": "javascript", "cwe": "CWE-95", "recommendation": "Do not eval.",
            "entropy": null, "verified": null
        }))
        .expect("finding fixture")
    }

    fn vulnerability(id: &str, severity: Option<&str>, dismissed: bool) -> Vulnerability {
        let mut value = json!({
            "id": id, "aliases": ["CVE-2026-0001"], "summary": "Prototype pollution",
            "details": "Long form.", "severity": severity, "cvssScore": null,
            "ecosystem": "npm", "packageName": "lodash", "installedVersion": "4.17.20",
            "fixedVersions": ["4.17.21"], "affectedRange": null,
            "references": ["https://example.com/a"], "published": null, "modified": null,
            "lockfile": "/repo/app/package-lock.json"
        });
        if dismissed {
            value["review"] = json!({"state": "acceptedRisk", "reason": "Build only"});
        }
        serde_json::from_value(value).expect("vulnerability fixture")
    }

    fn result(vulnerabilities: Vec<Vulnerability>) -> DependencyScanResult {
        serde_json::from_value(json!({
            "summary": {"path": "/repo/app", "lockfilesFound": ["/repo/app/package-lock.json"],
                "packagesFound": 1, "packagesQueried": 1, "vulnerabilitiesFound": vulnerabilities.len(),
                "durationMs": 2000},
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                "lockfile": "/repo/app/package-lock.json"}],
            "vulnerabilities": vulnerabilities,
        }))
        .expect("result fixture")
    }

    #[test]
    fn junit_counts_failures_and_skips_and_escapes_everything() {
        let cases = source_cases(&[finding("high"), finding("low")], "app/", |finding| {
            finding.severity == "high"
        });
        let text = String::from_utf8(junit("oxaudit scan", &cases)).unwrap();
        assert!(
            text.contains("tests=\"2\" failures=\"1\" errors=\"0\" skipped=\"1\""),
            "{text}"
        );
        assert!(text.contains("classname=\"app/src/app.js\" name=\"js-eval (line 7)\""));
        assert!(text.contains("HIGH eval() of &lt;user&gt; &quot;input&quot;"));
        assert!(text.contains("app/src/app.js:7&#10;Dynamic code.&#10;Do not eval."));
        assert!(text.contains("<skipped message=\"LOW eval()"));
        assert!(!text.contains("<user>"));
        assert_eq!(xml("a\u{0}b\u{1b}c\r\n"), "abc&#10;");
    }

    #[test]
    fn an_empty_junit_report_still_has_one_passing_case() {
        let text = String::from_utf8(junit("oxaudit deps", &[])).unwrap();
        assert!(text.contains("tests=\"1\" failures=\"0\""), "{text}");
        assert!(text.contains("name=\"completed with nothing to report\"/>"));
    }

    #[test]
    fn advisory_cases_fail_only_when_gating_and_name_dismissals() {
        let result = result(vec![
            vulnerability("GHSA-aaaa", Some("high"), false),
            vulnerability("GHSA-bbbb", Some("high"), true),
            vulnerability("GHSA-cccc", None, false),
        ]);
        let cases = advisory_cases(&result, "", |vulnerability| {
            vulnerability.review.is_none() && vulnerability.severity.is_some()
        });
        assert_eq!(cases[0].classname, "package-lock.json");
        assert_eq!(cases[0].name, "lodash 4.17.20 GHSA-aaaa");
        assert!(
            matches!(&cases[0].outcome, Outcome::Failed { detail, .. } if detail == "Upgrade to 4.17.21.")
        );
        assert!(
            matches!(&cases[1].outcome, Outcome::Skipped { message } if message.contains("dismissed"))
        );
        assert!(
            matches!(&cases[2].outcome, Outcome::Skipped { message } if message.starts_with("UNKNOWN"))
        );
    }

    #[test]
    fn code_quality_entries_are_stable_and_repo_relative() {
        let report = code_quality_source(&[finding("critical")], "services/api/");
        assert_eq!(report[0]["severity"], "blocker");
        assert_eq!(report[0]["check_name"], "js-eval");
        assert_eq!(report[0]["location"]["path"], "services/api/src/app.js");
        assert_eq!(report[0]["location"]["lines"]["begin"], 7);
        assert_eq!(report[0]["fingerprint"].as_str().unwrap().len(), 64);
        assert_eq!(
            report,
            code_quality_source(&[finding("critical")], "services/api/")
        );

        let result = result(vec![
            vulnerability("GHSA-aaaa", Some("medium"), false),
            vulnerability("GHSA-bbbb", Some("high"), true),
        ]);
        let entries = code_quality_advisories(&result, "app/");
        assert_eq!(
            entries.len(),
            1,
            "a dismissed advisory is not a code quality issue"
        );
        assert_eq!(entries[0]["severity"], "major");
        assert_eq!(entries[0]["location"]["path"], "app/package-lock.json");
        assert!(entries[0]["description"]
            .as_str()
            .unwrap()
            .ends_with("Upgrade to 4.17.21."));
    }

    #[test]
    fn the_dependency_scanning_report_has_the_required_shape() {
        let result = result(vec![
            vulnerability("GHSA-aaaa", Some("critical"), false),
            vulnerability("GHSA-bbbb", Some("high"), true),
        ]);
        let report = gitlab_dependency_scanning(&result, "app/", 1_794_787_200_000);
        assert_eq!(report["version"], "15.0.7");
        assert_eq!(report["scan"]["type"], "dependency_scanning");
        assert_eq!(report["scan"]["status"], "success");
        assert_eq!(report["scan"]["end_time"], "2026-11-16T00:00:00");
        assert_eq!(report["scan"]["start_time"], "2026-11-15T23:59:58");
        let found = report["vulnerabilities"].as_array().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["severity"], "Critical");
        assert_eq!(found[0]["location"]["file"], "app/package-lock.json");
        assert_eq!(
            found[0]["location"]["dependency"]["package"]["name"],
            "lodash"
        );
        assert_eq!(found[0]["identifiers"][0]["type"], "ghsa");
        assert_eq!(found[0]["identifiers"][1]["type"], "cve");
        let id = found[0]["id"].as_str().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
        assert_eq!(report["dependency_files"][0]["package_manager"], "npm");
        assert_eq!(
            report["dependency_files"][0]["dependencies"][0]["version"],
            "4.17.20"
        );
    }

    #[test]
    fn the_workspace_prefix_comes_from_whichever_ci_names_the_checkout() {
        let checkout = tempfile::tempdir().unwrap();
        let nested = checkout.path().join("services/api");
        std::fs::create_dir_all(&nested).unwrap();
        let from = |name: &'static str, root: &Path| {
            let value = checkout.path().as_os_str().to_owned();
            workspace_prefix_from(root, move |asked| (asked == name).then(|| value.clone()))
        };
        for name in WORKSPACE_VARIABLES {
            assert_eq!(from(name, &nested), "services/api/", "{name}");
            assert_eq!(from(name, checkout.path()), "", "{name}");
        }
        assert_eq!(workspace_prefix_from(&nested, |_| None), "");
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(from("CI_PROJECT_DIR", elsewhere.path()), "");
    }

    #[test]
    fn azure_issues_escape_their_properties() {
        let mut item = finding("high");
        item.title = "50% done; see [docs]\nnext".into();
        let lines = azure_issue_lines(&[item, finding("low")], "app/");
        assert_eq!(
            lines[0],
            "##vso[task.logissue type=error;sourcepath=app/src/app.js;linenumber=7;columnnumber=3;code=js-eval]50%AZP25 done%3B see [docs%5D%0Anext"
        );
        assert!(lines[1].starts_with("##vso[task.logissue type=warning;"));
    }
}

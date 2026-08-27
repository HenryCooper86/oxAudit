//! Parsing cve-bin-tool's `json2` report into oxAudit's own shapes.
//!
//! cve-bin-tool emits one flat entry per (component × CVE), repeating the
//! vendor/product/version/paths on every row, and groups those rows by the data
//! source they came from. The UI wants the opposite: one row per component,
//! carrying its CVEs. This module does that inversion, and normalizes the parts
//! that differ from our conventions — notably `paths`, which is a single
//! comma-joined string rather than a list.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Scanner identifiers, used for provenance on every component.
pub const CVE_BIN_TOOL: &str = "cve-bin-tool";
pub const GRYPE: &str = "grype";

/// One CVE affecting a detected component.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryVulnerability {
    pub cve_id: String,
    /// Lowercased onto oxAudit's severity scale.
    pub severity: String,
    pub score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    /// Which advisory feed reported it (NVD, OSV, GAD, REDHAT, CURL).
    pub source: String,
    /// cve-bin-tool triage state: NewFound, Mitigated, Confirmed, …
    pub remarks: Option<String>,
    pub epss_probability: Option<f64>,
    /// EPSS percentile against all scored CVEs, `[0, 1]`.
    #[serde(default)]
    pub epss_percentile: Option<f64>,
    /// In CISA's Known Exploited Vulnerabilities catalog — observed exploited
    /// in the wild, the strongest prioritization signal there is.
    #[serde(default)]
    pub known_exploited: bool,
    /// Named in a ransomware campaign, per KEV. Only set when known_exploited.
    #[serde(default)]
    pub ransomware: bool,
    /// Public exploit code exists for this CVE (Exploit-DB).
    #[serde(default)]
    pub public_exploit: bool,
    /// First version carrying the fix, when the scanner reports one. grype
    /// supplies this; cve-bin-tool does not.
    pub fixed_in: Option<String>,
}

/// A component cve-bin-tool detected inside the scanned binaries.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryComponent {
    pub vendor: String,
    pub product: String,
    pub version: String,
    /// Files the component was detected in, relative to the scan target.
    pub paths: Vec<String>,
    pub vulnerabilities: Vec<BinaryVulnerability>,
    /// Which scanners saw this component. The two disagree often enough that
    /// hiding the provenance would make results hard to trust.
    pub detected_by: Vec<String>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryScanSummary {
    pub components: usize,
    pub vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// Findings the source rated at nothing. Counted separately rather than
    /// left out, so the buckets always sum to `vulnerabilities` — a report
    /// where they do not reads as though findings went missing. Debian's OSV
    /// records routinely carry no CVSS, so this is common, not exotic.
    pub unknown: usize,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BinaryScanResult {
    pub target: String,
    pub components: Vec<BinaryComponent>,
    pub summary: BinaryScanSummary,
    /// When the scanner last refreshed its local CVE database.
    pub database_last_updated: Option<String>,
    pub duration_ms: u64,
    /// Scanners that contributed, in the order they ran.
    #[serde(default)]
    pub scanners: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_analysis: Option<oxaudit_scanners::SemanticAnalysisReport>,
}

// --- the wire shape, exactly as cve-bin-tool writes it ---------------------

#[derive(Deserialize)]
struct Json2Report {
    #[serde(default)]
    database_info: Option<DatabaseInfo>,
    #[serde(default)]
    vulnerabilities: Option<Vulnerabilities>,
}

#[derive(Deserialize)]
struct DatabaseInfo {
    #[serde(default)]
    last_updated: Option<String>,
}

#[derive(Deserialize)]
struct Vulnerabilities {
    #[serde(default)]
    report: Vec<SourceReport>,
}

#[derive(Deserialize)]
struct SourceReport {
    #[serde(default)]
    datasource: String,
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    cve_number: String,
    #[serde(default)]
    severity: String,
    /// Numbers arrive as strings, and as "-" when unknown.
    #[serde(default)]
    score: Option<String>,
    #[serde(default)]
    cvss_version: Option<String>,
    #[serde(default)]
    cvss_vector: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    paths: Option<String>,
    #[serde(default)]
    remarks: Option<String>,
    #[serde(default)]
    epss_probability: Option<String>,
}

/// cve-bin-tool writes "-" (and sometimes "unknown") where it has no number.
fn optional_number(raw: Option<&String>) -> Option<f64> {
    raw.map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "-")
        .and_then(|value| value.parse::<f64>().ok())
}

fn optional_text(raw: Option<&String>) -> Option<String> {
    raw.map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "-")
        .map(str::to_string)
}

/// `paths` is one comma-joined string; a component detected in several files
/// repeats them there rather than in a list.
fn split_paths(raw: Option<&String>) -> Vec<String> {
    raw.map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect()
}

/// Map onto the severity scale the rest of the app renders.
pub(crate) fn normalize_severity(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        "" | "none" | "unknown" => "unknown",
        other => return other.to_string(),
    }
    .to_string()
}

/// Parse a `json2` report.
///
/// Unknown and missing fields are tolerated: cve-bin-tool adds keys between
/// releases, and a scan that produced real findings should not be thrown away
/// because one optional metric moved.
pub fn parse_json2(raw: &str, target: &str, duration_ms: u64) -> Result<BinaryScanResult, String> {
    let report: Json2Report = serde_json::from_str(raw)
        .map_err(|e| format!("cve-bin-tool report is not valid JSON: {e}"))?;

    // Keyed by (vendor, product, version) so the flat rows collapse back into
    // one entry per component, in a stable order.
    let mut grouped: BTreeMap<(String, String, String), BinaryComponent> = BTreeMap::new();
    let mut summary = BinaryScanSummary::default();

    for source_report in report.vulnerabilities.map(|v| v.report).unwrap_or_default() {
        for entry in source_report.entries {
            let key = (
                entry.vendor.clone(),
                entry.product.clone(),
                entry.version.clone(),
            );
            let paths = split_paths(entry.paths.as_ref());

            let component = grouped.entry(key).or_insert_with(|| BinaryComponent {
                vendor: entry.vendor.clone(),
                product: entry.product.clone(),
                version: entry.version.clone(),
                paths: Vec::new(),
                vulnerabilities: Vec::new(),
                detected_by: vec![CVE_BIN_TOOL.to_string()],
            });

            for path in paths {
                if !component.paths.contains(&path) {
                    component.paths.push(path);
                }
            }

            if entry.cve_number.trim().is_empty() {
                continue;
            }
            // The same CVE can be reported by more than one feed; keep the
            // first and do not inflate the counts with duplicates.
            if component
                .vulnerabilities
                .iter()
                .any(|existing| existing.cve_id == entry.cve_number)
            {
                continue;
            }

            let severity = normalize_severity(&entry.severity);
            match severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => summary.unknown += 1,
            }
            summary.vulnerabilities += 1;

            component.vulnerabilities.push(BinaryVulnerability {
                cve_id: entry.cve_number.clone(),
                severity,
                score: optional_number(entry.score.as_ref()),
                cvss_version: optional_text(entry.cvss_version.as_ref()),
                cvss_vector: optional_text(entry.cvss_vector.as_ref()),
                source: optional_text(entry.source.as_ref())
                    .unwrap_or_else(|| source_report.datasource.clone()),
                remarks: optional_text(entry.remarks.as_ref()),
                epss_probability: optional_number(entry.epss_probability.as_ref()),
                epss_percentile: None,
                known_exploited: false,
                ransomware: false,
                public_exploit: false,
                fixed_in: None,
            });
        }
    }

    let mut components: Vec<BinaryComponent> = grouped.into_values().collect();
    summary.components = components.len();

    // Most severe component first, so the interesting rows are at the top.
    sort_components(&mut components);

    Ok(BinaryScanResult {
        target: target.to_string(),
        components,
        summary,
        database_last_updated: report.database_info.and_then(|info| info.last_updated),
        duration_ms,
        scanners: vec![CVE_BIN_TOOL.to_string()],
        semantic_analysis: None,
    })
}

/// Merge results from several scanners into one view.
///
/// Components are keyed on (product, version) rather than including the vendor:
/// grype does not report a vendor at all, so keying on it would list every
/// shared component twice. Where both scanners saw a component, the richer
/// vendor string wins and `detected_by` records both.
///
/// CVEs are unioned by id. When both scanners report the same CVE, fields the
/// other left empty are filled in — grype knows the fixed version, cve-bin-tool
/// does not — so merging strictly adds information.
pub fn merge_results(results: Vec<BinaryScanResult>) -> BinaryScanResult {
    let mut merged: Vec<BinaryScanResult> = results.into_iter().collect();
    if merged.len() == 1 {
        return merged.remove(0);
    }

    let target = merged.first().map(|r| r.target.clone()).unwrap_or_default();
    let duration_ms = merged.iter().map(|r| r.duration_ms).sum();
    let database_last_updated = merged
        .iter()
        .filter_map(|r| r.database_last_updated.clone())
        .max();
    let scanners: Vec<String> = merged.iter().flat_map(|r| r.scanners.clone()).collect();

    let mut grouped: BTreeMap<(String, String), BinaryComponent> = BTreeMap::new();
    for result in merged {
        for component in result.components {
            let key = (
                component.product.to_ascii_lowercase(),
                component.version.clone(),
            );
            match grouped.get_mut(&key) {
                None => {
                    grouped.insert(key, component);
                }
                Some(existing) => {
                    // Prefer a non-empty vendor: grype leaves it blank.
                    if existing.vendor.trim().is_empty() && !component.vendor.trim().is_empty() {
                        existing.vendor = component.vendor.clone();
                    }
                    for path in component.paths {
                        if !existing.paths.contains(&path) {
                            existing.paths.push(path);
                        }
                    }
                    for scanner in component.detected_by {
                        if !existing.detected_by.contains(&scanner) {
                            existing.detected_by.push(scanner);
                        }
                    }
                    for vulnerability in component.vulnerabilities {
                        match existing
                            .vulnerabilities
                            .iter_mut()
                            .find(|existing| existing.cve_id == vulnerability.cve_id)
                        {
                            None => existing.vulnerabilities.push(vulnerability),
                            Some(current) => {
                                // Keep whichever scanner knew more.
                                if current.score.is_none() {
                                    current.score = vulnerability.score;
                                }
                                if current.fixed_in.is_none() {
                                    current.fixed_in = vulnerability.fixed_in.clone();
                                }
                                if current.cvss_vector.is_none() {
                                    current.cvss_vector = vulnerability.cvss_vector.clone();
                                }
                                if current.epss_probability.is_none() {
                                    current.epss_probability = vulnerability.epss_probability;
                                }
                                if severity_rank(&vulnerability.severity)
                                    > severity_rank(&current.severity)
                                {
                                    current.severity = vulnerability.severity.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut components: Vec<BinaryComponent> = grouped.into_values().collect();
    for component in &mut components {
        component.vulnerabilities.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.cve_id.cmp(&b.cve_id))
        });
        component.detected_by.sort();
    }
    sort_components(&mut components);

    let summary = summarize(&components);
    BinaryScanResult {
        target,
        components,
        summary,
        database_last_updated,
        duration_ms,
        scanners,
        semantic_analysis: None,
    }
}

/// Counts recomputed from the merged set, never summed across scanners — a CVE
/// both found must not be counted twice.
pub(crate) fn summarize(components: &[BinaryComponent]) -> BinaryScanSummary {
    let mut summary = BinaryScanSummary {
        components: components.len(),
        ..Default::default()
    };
    for component in components {
        for vulnerability in &component.vulnerabilities {
            summary.vulnerabilities += 1;
            match vulnerability.severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => summary.unknown += 1,
            }
        }
    }
    summary
}

fn sort_components(components: &mut [BinaryComponent]) {
    components.sort_by(|a, b| {
        let rank = |component: &BinaryComponent| {
            component
                .vulnerabilities
                .iter()
                .map(|v| severity_rank(&v.severity))
                .max()
                .unwrap_or(0)
        };
        rank(b)
            .cmp(&rank(a))
            .then_with(|| b.vulnerabilities.len().cmp(&a.vulnerabilities.len()))
            .then_with(|| a.product.cmp(&b.product))
            .then_with(|| a.version.cmp(&b.version))
    });
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "$schema": "",
      "metadata": { "timestamp": "2026-08-20T10:00:00" },
      "database_info": { "last_updated": "2026-08-19 22:14:03", "total_entries": { "NVD": 271234 } },
      "vulnerabilities": {
        "summary": { "CRITICAL": 1 },
        "report": [
          {
            "datasource": "NVD",
            "entries": [
              {
                "vendor": "openssl", "product": "openssl", "version": "1.0.2g",
                "cve_number": "CVE-2016-2107", "severity": "HIGH", "score": "5.9",
                "cvss_version": "3", "cvss_vector": "AV:N/AC:H", "source": "NVD",
                "paths": "/fw/bin/httpd, /fw/lib/libssl.so", "remarks": "NewFound",
                "epss_probability": "0.00123"
              },
              {
                "vendor": "openssl", "product": "openssl", "version": "1.0.2g",
                "cve_number": "CVE-2016-6304", "severity": "CRITICAL", "score": "7.5",
                "cvss_version": "3", "source": "NVD", "paths": "/fw/bin/httpd",
                "remarks": "NewFound", "epss_probability": "-"
              },
              {
                "vendor": "gnu", "product": "zlib", "version": "1.2.8",
                "cve_number": "CVE-2016-9840", "severity": "MEDIUM", "score": "-",
                "source": "NVD", "paths": "/fw/lib/libz.so", "remarks": "NewFound"
              }
            ]
          },
          {
            "datasource": "OSV",
            "entries": [
              {
                "vendor": "openssl", "product": "openssl", "version": "1.0.2g",
                "cve_number": "CVE-2016-2107", "severity": "HIGH", "score": "5.9",
                "source": "OSV", "paths": "/fw/bin/httpd", "remarks": "NewFound"
              }
            ]
          }
        ]
      }
    }"#;

    #[test]
    fn flat_rows_collapse_into_one_entry_per_component() {
        let result = parse_json2(SAMPLE, "/fw", 1200).unwrap();

        assert_eq!(result.summary.components, 2);
        let openssl = &result.components[0];
        assert_eq!(openssl.product, "openssl");
        assert_eq!(openssl.version, "1.0.2g");
        assert_eq!(openssl.vulnerabilities.len(), 2);
    }

    #[test]
    fn the_comma_joined_path_string_becomes_a_deduplicated_list() {
        let result = parse_json2(SAMPLE, "/fw", 0).unwrap();
        let openssl = &result.components[0];

        assert_eq!(
            openssl.paths,
            vec!["/fw/bin/httpd".to_string(), "/fw/lib/libssl.so".to_string()],
            "paths repeat across a component's rows and must not duplicate"
        );
    }

    #[test]
    fn a_cve_reported_by_two_feeds_is_counted_once() {
        let result = parse_json2(SAMPLE, "/fw", 0).unwrap();

        assert_eq!(
            result.summary.vulnerabilities, 3,
            "CVE-2016-2107 appears under both NVD and OSV"
        );
        let ids: Vec<&str> = result.components[0]
            .vulnerabilities
            .iter()
            .map(|v| v.cve_id.as_str())
            .collect();
        assert_eq!(ids, vec!["CVE-2016-2107", "CVE-2016-6304"]);
    }

    #[test]
    fn placeholder_dashes_are_absent_values_rather_than_zeroes() {
        let result = parse_json2(SAMPLE, "/fw", 0).unwrap();
        let openssl = &result.components[0];

        let critical = openssl
            .vulnerabilities
            .iter()
            .find(|v| v.cve_id == "CVE-2016-6304")
            .unwrap();
        assert_eq!(critical.epss_probability, None, "\"-\" is not 0.0");

        let zlib = result
            .components
            .iter()
            .find(|c| c.product == "zlib")
            .unwrap();
        assert_eq!(zlib.vulnerabilities[0].score, None, "\"-\" is not a score");
        assert_eq!(zlib.vulnerabilities[0].cvss_vector, None);
    }

    #[test]
    fn severities_are_normalized_and_counted() {
        let result = parse_json2(SAMPLE, "/fw", 0).unwrap();

        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.medium, 1);
        assert_eq!(result.summary.low, 0);
        assert!(result
            .components
            .iter()
            .flat_map(|c| &c.vulnerabilities)
            .all(|v| v.severity.chars().all(|c| !c.is_uppercase())));
    }

    #[test]
    fn the_most_severe_component_sorts_first() {
        let result = parse_json2(SAMPLE, "/fw", 0).unwrap();

        assert_eq!(result.components[0].product, "openssl");
        assert_eq!(result.components[1].product, "zlib");
    }

    #[test]
    fn a_clean_scan_parses_to_an_empty_result_rather_than_an_error() {
        let clean = r#"{"$schema":"","metadata":{},"database_info":{"last_updated":"2026-08-19 22:14:03"},"vulnerabilities":{"summary":{},"report":[]}}"#;
        let result = parse_json2(clean, "/fw", 42).unwrap();

        assert!(result.components.is_empty());
        assert_eq!(result.summary.vulnerabilities, 0);
        assert_eq!(
            result.database_last_updated.as_deref(),
            Some("2026-08-19 22:14:03")
        );
        assert_eq!(result.duration_ms, 42);
    }

    #[test]
    fn unknown_keys_and_a_missing_vulnerabilities_block_are_tolerated() {
        // cve-bin-tool adds fields between releases; a report that still has
        // usable findings must not be discarded over one unexpected key.
        let forward = r#"{"$schema":"","metadata":{},"some_future_key":{"a":1},
          "vulnerabilities":{"report":[{"datasource":"NVD","entries":[
            {"vendor":"v","product":"p","version":"1","cve_number":"CVE-1","severity":"LOW","brand_new_field":true}
          ]}]}}"#;
        let result = parse_json2(forward, "/x", 0).unwrap();
        assert_eq!(result.summary.vulnerabilities, 1);

        let bare = r#"{"$schema":"","metadata":{}}"#;
        assert_eq!(parse_json2(bare, "/x", 0).unwrap().summary.components, 0);
    }

    #[test]
    fn malformed_json_is_reported_rather_than_silently_empty() {
        let error = parse_json2("not json at all", "/x", 0).unwrap_err();
        assert!(error.contains("not valid JSON"), "got: {error}");
    }

    fn component(
        product: &str,
        version: &str,
        scanner: &str,
        cves: &[(&str, &str)],
    ) -> BinaryComponent {
        BinaryComponent {
            vendor: if scanner == GRYPE {
                String::new()
            } else {
                "acme".into()
            },
            product: product.into(),
            version: version.into(),
            paths: vec![format!("/fw/{product}.so")],
            detected_by: vec![scanner.to_string()],
            vulnerabilities: cves
                .iter()
                .map(|(id, severity)| BinaryVulnerability {
                    cve_id: (*id).into(),
                    severity: (*severity).into(),
                    score: None,
                    cvss_version: None,
                    cvss_vector: None,
                    source: scanner.into(),
                    remarks: None,
                    epss_probability: None,
                    epss_percentile: None,
                    known_exploited: false,
                    ransomware: false,
                    public_exploit: false,
                    fixed_in: None,
                })
                .collect(),
        }
    }

    fn result(scanner: &str, components: Vec<BinaryComponent>) -> BinaryScanResult {
        BinaryScanResult {
            target: "/fw".into(),
            summary: BinaryScanSummary {
                components: components.len(),
                ..Default::default()
            },
            components,
            database_last_updated: None,
            duration_ms: 100,
            scanners: vec![scanner.to_string()],
            semantic_analysis: None,
        }
    }

    #[test]
    fn a_component_both_scanners_saw_is_listed_once_with_both_credited() {
        let merged = merge_results(vec![
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "curl",
                    "8.7.1",
                    CVE_BIN_TOOL,
                    &[("CVE-1", "high")],
                )],
            ),
            result(
                GRYPE,
                vec![component("curl", "8.7.1", GRYPE, &[("CVE-1", "high")])],
            ),
        ]);

        assert_eq!(merged.components.len(), 1);
        assert_eq!(
            merged.components[0].detected_by,
            vec!["cve-bin-tool", "grype"]
        );
        assert_eq!(
            merged.summary.vulnerabilities, 1,
            "a CVE both scanners found must not be counted twice"
        );
    }

    #[test]
    fn components_only_one_scanner_saw_are_kept() {
        // The whole point of running both: grype missed OpenSSL and zstd on the
        // real fixture, cve-bin-tool missed nothing it checks for.
        let merged = merge_results(vec![
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "openssl",
                    "1.0.2g",
                    CVE_BIN_TOOL,
                    &[("CVE-A", "critical")],
                )],
            ),
            result(
                GRYPE,
                vec![component("curl", "8.7.1", GRYPE, &[("CVE-B", "high")])],
            ),
        ]);

        let products: Vec<&str> = merged
            .components
            .iter()
            .map(|c| c.product.as_str())
            .collect();
        assert_eq!(products, vec!["openssl", "curl"], "most severe first");
        assert_eq!(merged.summary.components, 2);
        assert_eq!(merged.summary.critical, 1);
        assert_eq!(merged.summary.high, 1);
    }

    #[test]
    fn merging_fills_in_fields_the_other_scanner_left_empty() {
        let mut from_grype = component("curl", "8.7.1", GRYPE, &[("CVE-1", "high")]);
        from_grype.vulnerabilities[0].fixed_in = Some("8.9.0".into());
        from_grype.vulnerabilities[0].score = Some(7.5);

        let merged = merge_results(vec![
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "curl",
                    "8.7.1",
                    CVE_BIN_TOOL,
                    &[("CVE-1", "high")],
                )],
            ),
            result(GRYPE, vec![from_grype]),
        ]);

        let cve = &merged.components[0].vulnerabilities[0];
        assert_eq!(
            cve.fixed_in.as_deref(),
            Some("8.9.0"),
            "grype knows the fix version"
        );
        assert_eq!(cve.score, Some(7.5));
    }

    #[test]
    fn the_vendor_comes_from_whichever_scanner_reports_one() {
        // grype never reports a vendor; keying the merge on it would duplicate
        // every shared component.
        let merged = merge_results(vec![
            result(
                GRYPE,
                vec![component("curl", "8.7.1", GRYPE, &[("CVE-1", "low")])],
            ),
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "curl",
                    "8.7.1",
                    CVE_BIN_TOOL,
                    &[("CVE-1", "low")],
                )],
            ),
        ]);

        assert_eq!(merged.components.len(), 1);
        assert_eq!(merged.components[0].vendor, "acme");
    }

    #[test]
    fn the_more_severe_rating_wins_when_scanners_disagree() {
        let merged = merge_results(vec![
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "curl",
                    "8.7.1",
                    CVE_BIN_TOOL,
                    &[("CVE-1", "medium")],
                )],
            ),
            result(
                GRYPE,
                vec![component("curl", "8.7.1", GRYPE, &[("CVE-1", "critical")])],
            ),
        ]);

        assert_eq!(merged.components[0].vulnerabilities[0].severity, "critical");
        assert_eq!(merged.summary.critical, 1);
        assert_eq!(merged.summary.medium, 0);
    }

    #[test]
    fn merging_a_single_result_is_a_passthrough() {
        let single = result(
            GRYPE,
            vec![component("curl", "8.7.1", GRYPE, &[("CVE-1", "low")])],
        );
        let merged = merge_results(vec![single]);
        assert_eq!(merged.scanners, vec!["grype"]);
        assert_eq!(merged.components.len(), 1);
    }

    #[test]
    fn product_matching_ignores_case_so_one_component_is_not_listed_twice() {
        let merged = merge_results(vec![
            result(
                CVE_BIN_TOOL,
                vec![component(
                    "OpenSSL",
                    "3.0.1",
                    CVE_BIN_TOOL,
                    &[("CVE-1", "high")],
                )],
            ),
            result(
                GRYPE,
                vec![component("openssl", "3.0.1", GRYPE, &[("CVE-2", "low")])],
            ),
        ]);

        assert_eq!(merged.components.len(), 1);
        assert_eq!(merged.components[0].vulnerabilities.len(), 2);
    }

    /// The genuine output of cve-bin-tool 3.4, captured from a real scan rather
    /// than hand-written. Every other test in this module uses a fixture we
    /// authored, which can only ever confirm our own assumptions about the
    /// schema; this one is the check that those assumptions match the tool.
    const REAL_REPORT: &str = include_str!("../../tests/fixtures/cve_bin_tool_3.4_json2.json");

    #[test]
    fn a_real_cve_bin_tool_report_parses_and_inverts() {
        let parsed = parse_json2(REAL_REPORT, "/scan/corpus", 1234).expect("real report parses");

        assert_eq!(
            parsed.components.len(),
            1,
            "ten rows describe one component"
        );
        let curl = &parsed.components[0];
        assert_eq!(curl.vendor, "haxx");
        assert_eq!(curl.product, "curl");
        assert_eq!(curl.version, "8.7.1");
        assert_eq!(
            curl.vulnerabilities.len(),
            10,
            "each row is one CVE against the same component"
        );

        // The counts the tool itself printed, so a change in our tallying shows
        // up as a disagreement with the source rather than passing quietly.
        assert_eq!(parsed.summary.high, 4);
        assert_eq!(parsed.summary.medium, 6);
        assert_eq!(parsed.summary.critical, 0);
        assert_eq!(parsed.summary.low, 0);
        assert_eq!(parsed.summary.components, 1);
        assert_eq!(parsed.summary.vulnerabilities, 10);
    }

    #[test]
    fn a_real_report_carries_the_details_the_ui_renders() {
        let parsed = parse_json2(REAL_REPORT, "/scan/corpus", 0).expect("real report parses");
        let curl = &parsed.components[0];

        assert_eq!(
            curl.paths,
            vec!["/scan/corpus/curl"],
            "paths arrive comma-joined"
        );
        assert_eq!(curl.detected_by, vec![CVE_BIN_TOOL]);

        let first = &curl.vulnerabilities[0];
        assert!(first.cve_id.starts_with("CVE-"));
        assert!(
            first.severity.chars().all(|c| c.is_lowercase()),
            "severities arrive uppercase and must be normalized: {}",
            first.severity
        );
        assert!(
            first.score.is_some(),
            "score arrives as a string, not a number"
        );
        assert_eq!(first.source, "REDHAT");
    }
}

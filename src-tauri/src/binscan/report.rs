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
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BinaryScanResult {
    pub target: String,
    pub components: Vec<BinaryComponent>,
    pub summary: BinaryScanSummary,
    /// When cve-bin-tool last refreshed its local CVE database.
    pub database_last_updated: Option<String>,
    pub duration_ms: u64,
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
fn normalize_severity(raw: &str) -> String {
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
    let report: Json2Report =
        serde_json::from_str(raw).map_err(|e| format!("cve-bin-tool report is not valid JSON: {e}"))?;

    // Keyed by (vendor, product, version) so the flat rows collapse back into
    // one entry per component, in a stable order.
    let mut grouped: BTreeMap<(String, String, String), BinaryComponent> = BTreeMap::new();
    let mut summary = BinaryScanSummary::default();

    for source_report in report
        .vulnerabilities
        .map(|v| v.report)
        .unwrap_or_default()
    {
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
                _ => {}
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
            });
        }
    }

    let mut components: Vec<BinaryComponent> = grouped.into_values().collect();
    summary.components = components.len();

    // Most severe component first, so the interesting rows are at the top.
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

    Ok(BinaryScanResult {
        target: target.to_string(),
        components,
        summary,
        database_last_updated: report.database_info.and_then(|info| info.last_updated),
        duration_ms,
    })
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
        assert_eq!(result.database_last_updated.as_deref(), Some("2026-08-19 22:14:03"));
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
}

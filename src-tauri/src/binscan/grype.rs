//! grype as a second binary scanner.
//!
//! grype and cve-bin-tool see different things and neither subsumes the other.
//! Measured on the same 15 MB of macOS dylibs, grype identified one component
//! family (curl) where cve-bin-tool's ~450 checkers target four; grype in turn
//! reports fix versions, EPSS and KEV, which cve-bin-tool does not. Running
//! both and merging is strictly better than choosing (see
//! `docs/binary-scanning-runtime.md` §5).
//!
//! grype is Apache-2.0 and ships as a single static binary, so unlike
//! cve-bin-tool it has no licence or environment complications.

use std::path::Path;

use serde::Deserialize;

use super::report::{
    BinaryComponent, BinaryScanResult, BinaryScanSummary, BinaryVulnerability, GRYPE,
};

/// Build the argument list for a scan.
///
/// `dir:` is explicit rather than relying on grype's auto-detection, so a path
/// is never reinterpreted as an image reference.
pub fn build_args(target: &Path) -> Vec<String> {
    vec![
        format!("dir:{}", target.display()),
        "--output".into(),
        "json".into(),
    ]
}

/// `grype version` prints a block of `key: value` lines.
pub fn parse_version(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("version") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

// --- grype's JSON, only the parts we use ----------------------------------

#[derive(Deserialize)]
struct GrypeReport {
    #[serde(default)]
    matches: Vec<Match>,
    #[serde(default)]
    descriptor: Option<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(default)]
    db: Option<Db>,
}

#[derive(Deserialize)]
struct Db {
    #[serde(default)]
    built: Option<String>,
    #[serde(default)]
    status: Option<DbStatus>,
}

#[derive(Deserialize)]
struct DbStatus {
    #[serde(default)]
    built: Option<String>,
}

#[derive(Deserialize)]
struct Match {
    vulnerability: Vulnerability,
    artifact: Artifact,
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(default)]
    id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    cvss: Vec<Cvss>,
    #[serde(default)]
    fix: Option<Fix>,
    #[serde(rename = "dataSource", default)]
    data_source: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    /// grype carries EPSS per CVE; cve-bin-tool's own EPSS fetch is currently
    /// broken, so this is often the only exploit-likelihood signal available.
    #[serde(default)]
    epss: Vec<Epss>,
}

#[derive(Deserialize)]
struct Epss {
    #[serde(default)]
    epss: Option<f64>,
}

#[derive(Deserialize)]
struct Cvss {
    #[serde(default)]
    metrics: Option<CvssMetrics>,
    #[serde(default)]
    vector: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct CvssMetrics {
    #[serde(rename = "baseScore", default)]
    base_score: Option<f64>,
}

#[derive(Deserialize)]
struct Fix {
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize)]
struct Artifact {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    locations: Vec<Location>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(default)]
    path: Option<String>,
}

/// grype's own words for severity, onto oxAudit's scale.
fn normalize_severity(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        // grype's floor for "known but not worth acting on"; our scale calls
        // that info rather than inventing a sixth step.
        "negligible" => "info",
        "" | "unknown" => "unknown",
        other => return other.to_string(),
    }
    .to_string()
}

/// Parse a grype JSON report into the shared result shape.
pub fn parse_report(raw: &str, target: &str, duration_ms: u64) -> Result<BinaryScanResult, String> {
    let report: GrypeReport =
        serde_json::from_str(raw).map_err(|e| format!("grype report is not valid JSON: {e}"))?;

    // grype emits one row per (artifact × CVE); collapse to one per artifact.
    let mut grouped: std::collections::BTreeMap<(String, String), BinaryComponent> =
        std::collections::BTreeMap::new();

    for entry in report.matches {
        let key = (entry.artifact.name.clone(), entry.artifact.version.clone());
        let component = grouped.entry(key).or_insert_with(|| BinaryComponent {
            // grype does not report a vendor; leaving it blank lets the merge
            // take cve-bin-tool's when both saw the component.
            vendor: String::new(),
            product: entry.artifact.name.clone(),
            version: entry.artifact.version.clone(),
            paths: Vec::new(),
            vulnerabilities: Vec::new(),
            detected_by: vec![GRYPE.to_string()],
        });

        for location in &entry.artifact.locations {
            if let Some(path) = location.path.as_deref().map(str::trim) {
                if !path.is_empty() && !component.paths.iter().any(|known| known == path) {
                    component.paths.push(path.to_string());
                }
            }
        }

        if entry.vulnerability.id.trim().is_empty() {
            continue;
        }
        if component
            .vulnerabilities
            .iter()
            .any(|known| known.cve_id == entry.vulnerability.id)
        {
            continue;
        }

        let primary = entry.vulnerability.cvss.first();
        let fixed_in = entry
            .vulnerability
            .fix
            .as_ref()
            .filter(|fix| fix.state.as_deref() != Some("not-fixed"))
            .and_then(|fix| fix.versions.first().cloned());

        component.vulnerabilities.push(BinaryVulnerability {
            cve_id: entry.vulnerability.id.clone(),
            severity: normalize_severity(&entry.vulnerability.severity),
            score: primary.and_then(|c| c.metrics.as_ref().and_then(|m| m.base_score)),
            cvss_version: primary.and_then(|c| c.version.clone()),
            cvss_vector: primary.and_then(|c| c.vector.clone()),
            source: entry
                .vulnerability
                .namespace
                .or(entry.vulnerability.data_source)
                .unwrap_or_else(|| GRYPE.to_string()),
            remarks: entry
                .vulnerability
                .fix
                .as_ref()
                .and_then(|f| f.state.clone()),
            epss_probability: entry.vulnerability.epss.first().and_then(|e| e.epss),
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
            public_exploit: false,
            fixed_in,
        });
    }

    let mut components: Vec<BinaryComponent> = grouped.into_values().collect();
    let mut summary = BinaryScanSummary {
        components: components.len(),
        ..Default::default()
    };
    for component in &components {
        for vulnerability in &component.vulnerabilities {
            summary.vulnerabilities += 1;
            match vulnerability.severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => {}
            }
        }
    }
    components.sort_by(|a, b| a.product.cmp(&b.product).then(a.version.cmp(&b.version)));

    let database_last_updated = report.descriptor.and_then(|d| {
        d.db.and_then(|db| db.built.or_else(|| db.status.and_then(|s| s.built)))
    });

    Ok(BinaryScanResult {
        target: target.to_string(),
        components,
        summary,
        database_last_updated,
        duration_ms,
        scanners: vec![GRYPE.to_string()],
        semantic_analysis: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from a real run against the dylib fixture.
    const SAMPLE: &str = r#"{
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-2026-11856", "severity": "Critical",
            "cvss": [{"version": "3.1", "vector": "AV:N/AC:L", "metrics": {"baseScore": 9.8}}],
            "fix": {"versions": ["8.9.0"], "state": "fixed"},
            "namespace": "nvd:cpe", "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-11856",
            "epss": [{"cve": "CVE-2026-11856", "epss": 0.17301, "percentile": 0.96843}]
          },
          "artifact": {"name": "curl", "version": "8.7.1", "type": "binary",
                       "locations": [{"path": "/curl"}]}
        },
        {
          "vulnerability": {
            "id": "CVE-2024-6197", "severity": "High",
            "cvss": [{"metrics": {"baseScore": 7.5}}],
            "fix": {"versions": [], "state": "not-fixed"}, "namespace": "nvd:cpe"
          },
          "artifact": {"name": "curl", "version": "8.7.1", "type": "binary",
                       "locations": [{"path": "/curl"}]}
        },
        {
          "vulnerability": {"id": "CVE-2020-0000", "severity": "Negligible", "cvss": []},
          "artifact": {"name": "zlib", "version": "1.2.8", "locations": [{"path": "/libz.so"}]}
        }
      ],
      "descriptor": {"db": {"status": {"built": "2026-08-19T06:16:13Z"}}}
    }"#;

    /// Captured from a real `grype dir:… -o json` run against macOS dylibs.
    /// A hand-written sample cannot catch a field grype renames or nests
    /// differently; this can.
    const REAL_REPORT: &str = include_str!("../../tests/fixtures/grype-real.json");

    #[test]
    fn a_real_grype_report_parses_with_every_field_we_rely_on() {
        let result = parse_report(REAL_REPORT, "/fw", 86_000).unwrap();

        assert_eq!(result.summary.components, 1, "all three CVEs are curl's");
        let curl = &result.components[0];
        assert_eq!(curl.product, "curl");
        assert_eq!(curl.version, "8.7.1");
        assert_eq!(curl.detected_by, vec![GRYPE.to_string()]);
        assert_eq!(curl.paths, vec!["/curl".to_string()]);

        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.medium, 1);

        // The fields that justify running grype at all.
        let critical = curl
            .vulnerabilities
            .iter()
            .find(|v| v.severity == "critical")
            .expect("a critical finding");
        assert!(critical.score.is_some(), "CVSS base score");
        assert!(critical.cvss_vector.is_some(), "CVSS vector");
        assert!(critical.fixed_in.is_some(), "fix version");
        assert!(critical.epss_probability.is_some(), "EPSS");

        assert!(
            result.database_last_updated.is_some(),
            "the database build date comes from descriptor.db.status.built"
        );
    }

    #[test]
    fn rows_collapse_to_one_entry_per_artifact() {
        let result = parse_report(SAMPLE, "/fw", 900).unwrap();

        assert_eq!(result.summary.components, 2);
        let curl = result
            .components
            .iter()
            .find(|c| c.product == "curl")
            .unwrap();
        assert_eq!(curl.vulnerabilities.len(), 2);
        assert_eq!(curl.paths, vec!["/curl".to_string()]);
    }

    #[test]
    fn a_fixed_version_is_captured_but_not_invented_for_unfixed_cves() {
        let result = parse_report(SAMPLE, "/fw", 0).unwrap();
        let curl = result
            .components
            .iter()
            .find(|c| c.product == "curl")
            .unwrap();

        let fixed = curl
            .vulnerabilities
            .iter()
            .find(|v| v.cve_id == "CVE-2026-11856")
            .unwrap();
        assert_eq!(fixed.fixed_in.as_deref(), Some("8.9.0"));

        let unfixed = curl
            .vulnerabilities
            .iter()
            .find(|v| v.cve_id == "CVE-2024-6197")
            .unwrap();
        assert_eq!(unfixed.fixed_in, None, "a not-fixed CVE has no fix version");
    }

    #[test]
    fn grype_leaves_the_vendor_blank_so_the_merge_can_take_the_better_one() {
        let result = parse_report(SAMPLE, "/fw", 0).unwrap();
        assert!(result.components.iter().all(|c| c.vendor.is_empty()));
        assert!(result
            .components
            .iter()
            .all(|c| c.detected_by == vec![GRYPE.to_string()]));
    }

    #[test]
    fn negligible_maps_onto_info_rather_than_inventing_a_severity() {
        let result = parse_report(SAMPLE, "/fw", 0).unwrap();
        let zlib = result
            .components
            .iter()
            .find(|c| c.product == "zlib")
            .unwrap();

        assert_eq!(zlib.vulnerabilities[0].severity, "info");
        assert_eq!(result.summary.low, 0, "info must not inflate the low count");
    }

    #[test]
    fn epss_is_captured_when_grype_reports_it() {
        let result = parse_report(SAMPLE, "/fw", 0).unwrap();
        let curl = result
            .components
            .iter()
            .find(|c| c.product == "curl")
            .unwrap();

        let scored = curl
            .vulnerabilities
            .iter()
            .find(|v| v.cve_id == "CVE-2026-11856")
            .unwrap();
        assert_eq!(scored.epss_probability, Some(0.17301));

        let without = curl
            .vulnerabilities
            .iter()
            .find(|v| v.cve_id == "CVE-2024-6197")
            .unwrap();
        assert_eq!(without.epss_probability, None);
    }

    #[test]
    fn the_database_build_date_is_read_from_the_descriptor() {
        let result = parse_report(SAMPLE, "/fw", 0).unwrap();
        assert_eq!(
            result.database_last_updated.as_deref(),
            Some("2026-08-19T06:16:13Z")
        );
    }

    #[test]
    fn the_target_is_passed_with_an_explicit_dir_scheme() {
        // Without `dir:` grype may read a path as an image reference.
        let args = build_args(Path::new("/fw/image"));
        assert_eq!(args[0], "dir:/fw/image");
        assert!(args.windows(2).any(|w| w == ["--output", "json"]));
    }

    #[test]
    fn the_version_is_read_from_grypes_key_value_block() {
        let stdout = "Application:         grype\nVersion:             0.117.0\nBuildDate:           2026-08-10\n";
        assert_eq!(parse_version(stdout).as_deref(), Some("0.117.0"));
        assert_eq!(parse_version("Application: grype\n"), None);
    }

    #[test]
    fn an_empty_report_parses_rather_than_erroring() {
        let result = parse_report(r#"{"matches":[]}"#, "/fw", 5).unwrap();
        assert!(result.components.is_empty());
        assert_eq!(result.summary.vulnerabilities, 0);
        assert_eq!(result.scanners, vec![GRYPE.to_string()]);
    }
}

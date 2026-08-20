//! Attaching CVEs to natively detected components.
//!
//! The native scanner produces an inventory; this turns it into a scan. It
//! deliberately does not build a local vulnerability database — that is the
//! single decision that makes cve-bin-tool unusable on a fresh machine, since
//! it refuses to start until a gigabyte has downloaded. oxAudit already has a
//! rate-limited, cached NVD client and an OSV client, and a scan produces tens
//! of components rather than hundreds of thousands.
//!
//! **Two sources, each used where it is authoritative.** This is not
//! redundancy; a detection can only be answered by one of them:
//!
//! - A component found by **signature** carries a vendor and an upstream
//!   version, which is exactly the shape of a CPE — so it goes to **NVD**.
//! - A component found by the **ELF package note** carries a distribution
//!   package name and a packaged version, with no CPE vendor at all — so it
//!   goes to **OSV**, whose distribution ecosystems are keyed on precisely
//!   that.
//!
//! Sending either to the other returns nothing. Measured against the live
//! APIs: `virtualMatchString=cpe:2.3:a:openssl:openssl:3.0.2` returns 56 CVEs,
//! while the same query with `*` in the vendor position returns none — NVD does
//! not treat it as a wildcard, so there is no CPE query for a component whose
//! vendor we do not know. Conversely OSV answers
//! `{"ecosystem":"Debian","name":"curl","version":"7.88.1-10+deb12u5"}` with 68
//! entries, and answers nothing at all for an upstream version.

use std::collections::HashMap;

use serde_json::Value;

use super::scan::Detection;
use crate::binscan::report::{normalize_severity, BinaryVulnerability};
use crate::models::Dependency;

/// Identifies where a CVE came from, on the component's vulnerability list.
pub const SOURCE_NVD: &str = "NVD";
pub const SOURCE_OSV: &str = "OSV";

/// How a component is keyed for enrichment: the same key `scan::fold` groups on.
pub type ComponentKey = (String, String);

pub fn component_key(product: &str, version: &str) -> ComponentKey {
    (product.to_ascii_lowercase(), version.to_string())
}

/// One component, with everything needed to ask about it.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentQuery {
    pub key: ComponentKey,
    pub vendor: String,
    pub product: String,
    /// Upstream version — what NVD's CPE data is keyed on.
    pub version: String,
    /// Packaged version — what OSV's distribution ecosystems compare against.
    pub raw_version: String,
    pub ecosystem: Option<String>,
    /// The name OSV knows this by, which is the distribution's package name and
    /// not necessarily the canonical product. `libzstd` for `zstandard`.
    pub osv_name: Option<String>,
}

/// Map an ELF package note's `type`/`os` onto an OSV ecosystem.
///
/// Returns `None` for a distribution OSV does not carry, which is honest: it
/// leads to "not queried" rather than "no vulnerabilities found", and those are
/// very different statements to put in front of someone auditing firmware.
///
/// The release is deliberately left off. OSV accepts a bare `Debian` and
/// answers across every release, which is what we want — the note says which
/// distribution built the binary, never which release it is running on, and
/// guessing one would narrow the answer on no evidence.
pub fn osv_ecosystem(kind: &str, os: &str) -> Option<String> {
    let os = os.trim().to_ascii_lowercase();
    let ecosystem = match os.as_str() {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "alpine" => "Alpine",
        "rocky linux" | "rocky" => "Rocky Linux",
        "almalinux" | "alma" => "AlmaLinux",
        "wolfi" => "Wolfi",
        "chainguard" => "Chainguard",
        "mageia" => "Mageia",
        "photon os" | "photon" => "Photon OS",
        "opensuse" => "openSUSE",
        "suse" | "sles" => "SUSE",
        _ => {
            // Some builders leave `os` empty and only set `type`. `deb` alone
            // is not enough to name an ecosystem — Debian and Ubuntu are
            // different answers — so this stays unqueried rather than guessing.
            let _ = kind;
            return None;
        }
    };
    Some(ecosystem.to_string())
}

/// A CPE 2.3 match string for NVD's `virtualMatchString`, or `None` when the
/// component cannot be expressed as one.
///
/// The inputs are read out of a scanned binary, so they are attacker-influenced
/// and go into a URL. Rather than escape, anything outside the character set a
/// real CPE uses is refused — a component we cannot name precisely is one we
/// cannot query precisely either, so nothing is lost by declining.
pub fn cpe_match_string(vendor: &str, product: &str, version: &str) -> Option<String> {
    fn component(raw: &str) -> Option<String> {
        let value = raw.trim().to_ascii_lowercase();
        if value.is_empty() {
            return None;
        }
        let valid = value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        let starts_well = value.starts_with(|c: char| c.is_ascii_alphanumeric());
        (valid && starts_well).then_some(value)
    }

    let vendor = component(vendor)?;
    let product = component(product)?;
    let version = component(version)?;
    Some(format!("cpe:2.3:a:{vendor}:{product}:{version}"))
}

/// Pull the fields the UI renders out of an NVD `cves/2.0` response.
///
/// Preferring CVSS v3.1 over v2 matters: the two disagree by design, and an
/// unlabelled mixture of the two makes a severity column meaningless. Where
/// only v2 exists it is used and labelled as such.
pub fn parse_nvd(json: &Value) -> Vec<BinaryVulnerability> {
    let mut out = Vec::new();
    let Some(entries) = json.get("vulnerabilities").and_then(Value::as_array) else {
        return out;
    };

    for entry in entries {
        let Some(cve) = entry.get("cve") else { continue };
        let Some(id) = cve.get("id").and_then(Value::as_str) else {
            continue;
        };

        let metrics = cve.get("metrics");
        let preferred = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
            .into_iter()
            .find_map(|key| {
                metrics?
                    .get(key)
                    .and_then(Value::as_array)
                    .and_then(|list| list.first())
            });

        let data = preferred.and_then(|metric| metric.get("cvssData"));
        let score = data
            .and_then(|d| d.get("baseScore"))
            .and_then(Value::as_f64);
        let vector = data
            .and_then(|d| d.get("vectorString"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let cvss_version = data
            .and_then(|d| d.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string);
        // v3 puts the rating in cvssData; v2 puts it on the metric itself.
        let severity = data
            .and_then(|d| d.get("baseSeverity"))
            .and_then(Value::as_str)
            .or_else(|| {
                preferred
                    .and_then(|m| m.get("baseSeverity"))
                    .and_then(Value::as_str)
            })
            .map(normalize_severity)
            .unwrap_or_else(|| "unknown".to_string());

        out.push(BinaryVulnerability {
            cve_id: id.to_string(),
            severity,
            score,
            cvss_version,
            cvss_vector: vector,
            source: SOURCE_NVD.to_string(),
            remarks: None,
            epss_probability: None,
            fixed_in: None,
        });
    }
    out
}

/// The CVE id inside an OSV identifier.
///
/// OSV names its distribution records `DEBIAN-CVE-2022-4899`, `UBUNTU-CVE-…`
/// and so on, and those records carry no aliases.
pub fn cve_id_from_osv(id: &str) -> String {
    if let Some(index) = id.find("CVE-") {
        let candidate = &id[index..];
        let looks_like_a_cve = candidate
            .strip_prefix("CVE-")
            .map(|rest| {
                let mut parts = rest.splitn(2, '-');
                let year = parts.next().unwrap_or_default();
                let number = parts.next().unwrap_or_default();
                year.len() == 4
                    && year.chars().all(|c| c.is_ascii_digit())
                    && !number.is_empty()
                    && number.chars().all(|c| c.is_ascii_digit())
            })
            .unwrap_or(false);
        if looks_like_a_cve {
            return candidate.to_string();
        }
    }
    id.to_string()
}

/// Convert an OSV result into the shape the binary-scan UI renders.
///
/// `fixed_in` is the reason this path is worth having beyond coverage: OSV
/// reports the version that carries the fix, and cve-bin-tool never does.
pub fn from_osv(vulnerability: &crate::models::Vulnerability) -> BinaryVulnerability {
    // Prefer an explicit CVE alias. Distribution records have no `aliases`
    // array at all, so the number has to come out of the id itself — and it
    // must, because DEBIAN-CVE-2022-4899 is not something a user can look up
    // anywhere.
    let cve_id = vulnerability
        .aliases
        .iter()
        .find(|alias| alias.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| cve_id_from_osv(&vulnerability.id));

    BinaryVulnerability {
        cve_id,
        severity: vulnerability
            .severity
            .as_deref()
            .map(normalize_severity)
            .unwrap_or_else(|| "unknown".to_string()),
        score: vulnerability.cvss_score.map(f64::from),
        cvss_version: None,
        cvss_vector: None,
        source: SOURCE_OSV.to_string(),
        remarks: None,
        epss_probability: None,
        fixed_in: vulnerability.fixed_versions.first().cloned(),
    }
}

/// Build the query list from raw detections.
///
/// Detections with no version are dropped: there is no useful question to ask
/// about "some OpenSSL". They still appear as components, so the finding is not
/// lost — it simply cannot be enriched.
pub fn queries_from(detections: &[Detection]) -> Vec<ComponentQuery> {
    let mut seen: HashMap<ComponentKey, ComponentQuery> = HashMap::new();

    for detection in detections {
        let Some(version) = detection.version.as_deref().filter(|v| !v.is_empty()) else {
            continue;
        };
        let key = component_key(&detection.product, version);
        let entry = seen.entry(key.clone()).or_insert_with(|| ComponentQuery {
            key,
            vendor: detection.vendor.clone(),
            product: detection.product.clone(),
            version: version.to_string(),
            raw_version: detection
                .raw_version
                .clone()
                .unwrap_or_else(|| version.to_string()),
            ecosystem: detection.ecosystem.clone(),
            osv_name: detection.package_name.clone(),
        });
        // One file may be seen by both detectors. Keep whichever fact the other
        // lacks, so a component detected by note *and* signature can be asked
        // about both ways.
        if entry.vendor.is_empty() && !detection.vendor.is_empty() {
            entry.vendor = detection.vendor.clone();
        }
        if entry.ecosystem.is_none() {
            entry.ecosystem = detection.ecosystem.clone();
        }
        if entry.osv_name.is_none() {
            entry.osv_name = detection.package_name.clone();
        }
        if entry.raw_version == entry.version {
            // A packaged version is strictly more useful to OSV than an
            // upstream one, so a note's version wins over a signature's.
            if let Some(raw) = detection.raw_version.as_deref() {
                if raw != version {
                    entry.raw_version = raw.to_string();
                }
            }
        }
    }

    let mut queries: Vec<ComponentQuery> = seen.into_values().collect();
    queries.sort_by(|a, b| a.key.cmp(&b.key));
    queries
}

/// The OSV dependency list, for the components that can be asked that way.
pub fn osv_dependencies(queries: &[ComponentQuery]) -> Vec<Dependency> {
    queries
        .iter()
        .filter_map(|query| {
            Some(Dependency {
                ecosystem: query.ecosystem.clone()?,
                // OSV's distribution ecosystems key on the distribution's own
                // package name; the canonical product would match nothing.
                name: query
                    .osv_name
                    .clone()
                    .unwrap_or_else(|| query.product.clone()),
                version: query.raw_version.clone(),
                lockfile: String::new(),
            })
        })
        .collect()
}

/// Attach vulnerabilities to a result and recompute its counts.
///
/// Takes the whole result rather than its components so the summary cannot be
/// left stale: a caller who attached CVEs and forgot to re-tally would produce
/// a report whose headline numbers say zero while the list below shows
/// findings.
///
/// De-duplicates by CVE id within a component: NVD and OSV overlap, and the
/// same CVE arriving twice would inflate every number in the summary.
pub fn apply(
    result: &mut crate::binscan::report::BinaryScanResult,
    mut found: HashMap<ComponentKey, Vec<BinaryVulnerability>>,
) {
    for component in result.components.iter_mut() {
        let key = component_key(&component.product, &component.version);
        let Some(vulnerabilities) = found.remove(&key) else {
            continue;
        };
        for vulnerability in vulnerabilities {
            if component
                .vulnerabilities
                .iter()
                .any(|existing| existing.cve_id == vulnerability.cve_id)
            {
                continue;
            }
            component.vulnerabilities.push(vulnerability);
        }
        // Most severe first, so the badge and the list agree.
        component.vulnerabilities.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then(a.cve_id.cmp(&b.cve_id))
        });
    }
    result.summary = crate::binscan::report::summarize(&result.components);
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

// --- the network layer -----------------------------------------------------

/// Most components we will ask NVD about in one scan.
///
/// Without an API key NVD allows five requests per thirty seconds, so each
/// query costs about six seconds of wall clock. A firmware image with two
/// hundred components would take twenty minutes. The cap bounds that, and
/// whatever it excludes is *reported* rather than quietly dropped — a scan that
/// looks complete but is not is the failure mode this whole module exists to
/// avoid.
pub const MAX_NVD_QUERIES: usize = 100;

pub struct Enrichment {
    pub found: HashMap<ComponentKey, Vec<BinaryVulnerability>>,
    /// Things the user needs to know that are not failures: a rate-limit
    /// warning, a cap, a source that did not answer.
    pub notes: Vec<String>,
}

/// Ask both sources about every component they can answer for.
///
/// A failure in one source is a note, not an error. The two see different
/// things, so half an answer is worth far more than none.
pub async fn enrich(
    state: &crate::cve::CveState,
    queries: &[ComponentQuery],
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    on_progress: std::sync::Arc<dyn Fn(String) + Send + Sync>,
) -> Enrichment {
    use std::sync::atomic::Ordering;

    let mut found: HashMap<ComponentKey, Vec<BinaryVulnerability>> = HashMap::new();
    let mut notes = Vec::new();
    let _ = &cancel;

    // OSV first, one request per distribution package.
    //
    // Not the batch endpoint, even though it would be a single request:
    // `/v1/querybatch` answers with ids and modification times only, so every
    // record comes back with no severity, no CVSS vector and no fixed version.
    // Measured, that turns four real Debian findings into four entries rated
    // "unknown" with no remediation — worse than useless, because a summary
    // reading "0 critical, 0 high" invites the reader to relax. OSV is fast and
    // is not rate-limited the way NVD is, so the extra requests are cheap.
    let dependencies = osv_dependencies(queries);
    if !dependencies.is_empty() {
        for (index, (query, dependency)) in queries
            .iter()
            .filter(|q| q.ecosystem.is_some())
            .zip(dependencies.iter())
            .enumerate()
        {
            if cancel.load(Ordering::Relaxed) {
                notes.push(format!(
                    "cancelled after {index} of {} OSV lookups; results are partial",
                    dependencies.len()
                ));
                break;
            }
            on_progress(format!(
                "OSV {}/{}: {} {}",
                index + 1,
                dependencies.len(),
                dependency.name,
                dependency.version
            ));
            match state
                .osv
                .query_package(&dependency.ecosystem, &dependency.name, &dependency.version)
                .await
            {
                Ok(vulnerabilities) if !vulnerabilities.is_empty() => {
                    found
                        .entry(query.key.clone())
                        .or_default()
                        .extend(vulnerabilities.iter().map(from_osv));
                }
                Ok(_) => {}
                Err(error) => notes.push(format!(
                    "OSV lookup for {} {} failed: {error}",
                    dependency.name, dependency.version
                )),
            }
        }
    }

    // NVD second: one throttled request per component.
    let askable: Vec<(&ComponentQuery, String)> = queries
        .iter()
        .filter_map(|query| {
            cpe_match_string(&query.vendor, &query.product, &query.version)
                .map(|cpe| (query, cpe))
        })
        .collect();

    if askable.len() > MAX_NVD_QUERIES {
        notes.push(format!(
            "{} components could be looked up in NVD; only the first {} were, to stay inside its rate limit. Set an NVD API key in Settings to raise it.",
            askable.len(),
            MAX_NVD_QUERIES
        ));
    }
    if !askable.is_empty() && state.api_key.lock().unwrap().is_none() {
        notes.push(
            "No NVD API key is set, so lookups are limited to five requests per thirty seconds. Setting one in Settings makes this roughly ten times faster."
                .to_string(),
        );
    }

    let total = askable.len().min(MAX_NVD_QUERIES);
    for (index, (query, cpe)) in askable.into_iter().take(MAX_NVD_QUERIES).enumerate() {
        if cancel.load(Ordering::Relaxed) {
            notes.push(format!(
                "cancelled after {index} of {total} NVD lookups; results are partial"
            ));
            break;
        }
        on_progress(format!(
            "NVD {}/{}: {} {}",
            index + 1,
            total,
            query.product,
            query.version
        ));
        match state
            .nvd_get(&[
                ("virtualMatchString", cpe),
                ("resultsPerPage", "200".to_string()),
            ])
            .await
        {
            Ok(json) => {
                let parsed = parse_nvd(&json);
                if !parsed.is_empty() {
                    found.entry(query.key.clone()).or_default().extend(parsed);
                }
            }
            Err(error) => notes.push(format!(
                "NVD lookup for {} {} failed: {error}",
                query.product, query.version
            )),
        }
    }

    Enrichment { found, notes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binscan::report::BinaryComponent;

    #[test]
    fn a_debian_package_note_names_an_osv_ecosystem() {
        assert_eq!(osv_ecosystem("deb", "Debian").as_deref(), Some("Debian"));
        assert_eq!(osv_ecosystem("deb", "ubuntu").as_deref(), Some("Ubuntu"));
        assert_eq!(osv_ecosystem("apk", "Alpine").as_deref(), Some("Alpine"));
    }

    #[test]
    fn an_unknown_distribution_is_not_queried_rather_than_guessed() {
        // "not queried" and "no vulnerabilities" must not look the same to
        // someone auditing firmware.
        assert_eq!(osv_ecosystem("deb", ""), None);
        assert_eq!(osv_ecosystem("rpm", "Some Vendor OS"), None);
    }

    #[test]
    fn a_cpe_needs_a_vendor_so_a_package_note_alone_cannot_make_one() {
        // Measured: NVD does not treat `*` in the vendor position as a
        // wildcard, so there is no query to fall back to.
        assert_eq!(cpe_match_string("", "zstd", "1.5.7"), None);
        assert_eq!(
            cpe_match_string("openssl", "openssl", "3.0.2").as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.0.2")
        );
    }

    #[test]
    fn a_cpe_is_lowercased_the_way_nvd_keys_them() {
        assert_eq!(
            cpe_match_string("OpenSSL", "OpenSSL", "3.0.2").as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.0.2")
        );
    }

    #[test]
    fn a_component_name_carrying_url_or_cpe_syntax_is_refused() {
        // Product and version are read out of a scanned binary, so they are
        // attacker-influenced and end up in a request URL.
        assert_eq!(cpe_match_string("openssl", "openssl", "3.0.2&x=1"), None);
        assert_eq!(cpe_match_string("openssl", "open:ssl", "3.0.2"), None);
        assert_eq!(cpe_match_string("openssl", "openssl", "3.0.2 OR 1"), None);
        assert_eq!(cpe_match_string("openssl", "../../etc", "3.0.2"), None);
        assert_eq!(cpe_match_string("openssl", "-leading", "3.0.2"), None);
    }

    const REAL_NVD: &str = include_str!("../../../tests/fixtures/nvd_cpe_openssl.json");

    #[test]
    fn a_real_nvd_response_parses() {
        // Captured from services.nvd.nist.gov for
        // virtualMatchString=cpe:2.3:a:openssl:openssl:3.0.2.
        let json: Value = serde_json::from_str(REAL_NVD).expect("valid JSON");
        let parsed = parse_nvd(&json);

        assert_eq!(parsed.len(), 2, "the fixture holds two CVEs");
        let first = &parsed[0];
        assert!(first.cve_id.starts_with("CVE-"));
        assert_eq!(first.source, SOURCE_NVD);
        assert!(first.score.is_some());
        assert!(first.cvss_vector.is_some());
        assert!(
            first.severity.chars().all(|c| c.is_lowercase()),
            "NVD reports HIGH; the UI renders lowercase: {}",
            first.severity
        );
    }

    #[test]
    fn cvss_v31_is_preferred_over_v2_where_both_exist() {
        // The fixture's first entry carries both. Mixing the two scales in one
        // column would make the severity meaningless — v2 rates it 5.0 and
        // v3.1 rates the same CVE 7.5.
        let json: Value = serde_json::from_str(REAL_NVD).expect("valid JSON");
        let parsed = parse_nvd(&json);
        assert_eq!(parsed[0].cvss_version.as_deref(), Some("3.1"));
        assert_eq!(parsed[0].score, Some(7.5));
        assert_eq!(parsed[0].severity, "high");
    }

    #[test]
    fn a_response_with_no_vulnerabilities_yields_none_rather_than_failing() {
        let empty: Value = serde_json::json!({ "totalResults": 0, "vulnerabilities": [] });
        assert!(parse_nvd(&empty).is_empty());
        assert!(parse_nvd(&serde_json::json!({})).is_empty());
    }

    fn osv_vulnerability(id: &str, aliases: &[&str], fixed: &[&str]) -> crate::models::Vulnerability {
        crate::models::Vulnerability {
            id: id.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: String::new(),
            details: String::new(),
            severity: Some("HIGH".into()),
            cvss_score: Some(7.5),
            ecosystem: "Debian".into(),
            package_name: "curl".into(),
            installed_version: "7.88.1-10+deb12u5".into(),
            fixed_versions: fixed.iter().map(|f| f.to_string()).collect(),
            affected_range: None,
            references: Vec::new(),
            published: None,
            modified: None,
            lockfile: String::new(),
        }
    }

    #[test]
    fn an_osv_distribution_id_is_reported_under_its_cve_alias() {
        // OSV names these DEBIAN-CVE-2024-11053; the CVE id is what a user can
        // actually look up.
        let converted = from_osv(&osv_vulnerability(
            "DEBIAN-CVE-2024-11053",
            &["CVE-2024-11053"],
            &["8.11.1-1"],
        ));
        assert_eq!(converted.cve_id, "CVE-2024-11053");
        assert_eq!(converted.fixed_in.as_deref(), Some("8.11.1-1"));
        assert_eq!(converted.severity, "high");
        assert_eq!(converted.source, SOURCE_OSV);
    }

    #[test]
    fn an_osv_entry_with_no_cve_alias_keeps_its_own_id() {
        let converted = from_osv(&osv_vulnerability("GHSA-abcd-1234", &[], &[]));
        assert_eq!(converted.cve_id, "GHSA-abcd-1234");
        assert_eq!(converted.fixed_in, None);
    }

    #[test]
    fn a_distribution_record_with_no_aliases_still_yields_a_cve_id() {
        // Debian's OSV records carry no `aliases` array at all, so the id is
        // the only place the CVE number appears. DEBIAN-CVE-2022-4899 is not
        // something a user can look up anywhere.
        let converted = from_osv(&osv_vulnerability("DEBIAN-CVE-2022-4899", &[], &[]));
        assert_eq!(converted.cve_id, "CVE-2022-4899");
    }

    #[test]
    fn reading_a_cve_id_out_of_an_osv_id_is_conservative() {
        assert_eq!(cve_id_from_osv("DEBIAN-CVE-2022-4899"), "CVE-2022-4899");
        assert_eq!(cve_id_from_osv("UBUNTU-CVE-2024-56433"), "CVE-2024-56433");
        assert_eq!(cve_id_from_osv("CVE-2024-56433"), "CVE-2024-56433");
        // Not CVE-shaped: left exactly as it is rather than mangled into
        // something that looks like a real identifier.
        assert_eq!(cve_id_from_osv("GHSA-abcd-1234"), "GHSA-abcd-1234");
        assert_eq!(cve_id_from_osv("PYSEC-2021-CVE-bogus"), "PYSEC-2021-CVE-bogus");
        assert_eq!(cve_id_from_osv("RUSTSEC-2021-0001"), "RUSTSEC-2021-0001");
    }

    fn detection(
        vendor: &str,
        product: &str,
        version: Option<&str>,
        raw: Option<&str>,
        ecosystem: Option<&str>,
    ) -> Detection {
        Detection {
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: version.map(str::to_string),
            raw_version: raw.map(str::to_string),
            ecosystem: ecosystem.map(str::to_string),
            package_name: ecosystem.map(|_| product.to_string()),
            path: "/fw/lib/x.so".into(),
            source: super::super::scan::DetectionSource::Content,
            truncated: false,
        }
    }

    #[test]
    fn a_component_seen_by_both_detectors_can_be_asked_about_both_ways() {
        // The package note knows the ecosystem and the packaged version; the
        // signature knows the CPE vendor. Losing either halves the coverage.
        let queries = queries_from(&[
            detection("", "curl", Some("8.14.1"), Some("8.14.1-2+deb13u4"), Some("Debian")),
            detection("haxx", "curl", Some("8.14.1"), Some("8.14.1"), None),
        ]);

        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].vendor, "haxx");
        assert_eq!(queries[0].ecosystem.as_deref(), Some("Debian"));
        assert_eq!(queries[0].raw_version, "8.14.1-2+deb13u4");
        assert!(cpe_match_string(&queries[0].vendor, &queries[0].product, &queries[0].version).is_some());
    }

    #[test]
    fn a_versionless_detection_produces_no_query() {
        // There is no useful question to ask about "some OpenSSL", but it stays
        // a component, so the finding is not lost.
        assert!(queries_from(&[detection("openssl", "openssl", None, None, None)]).is_empty());
    }

    #[test]
    fn osv_is_asked_using_the_packaged_version_not_the_upstream_one() {
        // Debian's OSV entries compare against 8.14.1-2+deb13u4. Asking with
        // the upstream 8.14.1 matches nothing, silently.
        let queries = queries_from(&[detection(
            "",
            "curl",
            Some("8.14.1"),
            Some("8.14.1-2+deb13u4"),
            Some("Debian"),
        )]);
        let deps = osv_dependencies(&queries);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "8.14.1-2+deb13u4");
        assert_eq!(deps[0].ecosystem, "Debian");
    }

    #[test]
    fn a_component_without_an_ecosystem_is_left_out_of_the_osv_batch() {
        let queries = queries_from(&[detection("openssl", "openssl", Some("3.0.2"), None, None)]);
        assert!(osv_dependencies(&queries).is_empty());
    }

    fn scan_result(components: Vec<BinaryComponent>) -> crate::binscan::report::BinaryScanResult {
        crate::binscan::report::BinaryScanResult {
            target: "/fw".into(),
            components,
            summary: Default::default(),
            database_last_updated: None,
            duration_ms: 0,
            scanners: vec!["oxaudit".into()],
        }
    }

    fn component(product: &str, version: &str) -> BinaryComponent {
        BinaryComponent {
            vendor: String::new(),
            product: product.into(),
            version: version.into(),
            paths: vec!["/fw/lib/x.so".into()],
            vulnerabilities: Vec::new(),
            detected_by: vec!["oxaudit".into()],
        }
    }

    fn vulnerability(id: &str, severity: &str, source: &str) -> BinaryVulnerability {
        BinaryVulnerability {
            cve_id: id.into(),
            severity: severity.into(),
            score: None,
            cvss_version: None,
            cvss_vector: None,
            source: source.into(),
            remarks: None,
            epss_probability: None,
            fixed_in: None,
        }
    }

    #[test]
    fn the_same_cve_from_both_sources_is_recorded_once() {
        // NVD and OSV overlap heavily. Counting a CVE twice inflates every
        // number in the summary.
        let mut result = scan_result(vec![component("curl", "8.14.1")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("curl", "8.14.1"),
            vec![
                vulnerability("CVE-2024-11053", "medium", SOURCE_NVD),
                vulnerability("CVE-2024-11053", "medium", SOURCE_OSV),
                vulnerability("CVE-2024-7264", "low", SOURCE_OSV),
            ],
        );
        apply(&mut result, found);

        assert_eq!(result.components[0].vulnerabilities.len(), 2);
        assert_eq!(result.summary.vulnerabilities, 2, "the summary must not double-count either");
    }

    #[test]
    fn the_severity_buckets_always_sum_to_the_total() {
        // Debian's OSV records routinely carry no CVSS. If an unrated finding
        // is counted in the total but in no bucket, an exported report looks
        // like findings went missing between the two numbers.
        let mut result = scan_result(vec![component("shadow", "4.17.4")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("shadow", "4.17.4"),
            vec![
                vulnerability("CVE-2013-4235", "medium", SOURCE_OSV),
                vulnerability("CVE-2024-56433", "low", SOURCE_OSV),
                vulnerability("CVE-2007-5686", "unknown", SOURCE_OSV),
            ],
        );
        apply(&mut result, found);

        let s = &result.summary;
        assert_eq!(s.unknown, 1);
        assert_eq!(
            s.critical + s.high + s.medium + s.low + s.unknown,
            s.vulnerabilities
        );
    }

    #[test]
    fn the_summary_is_recomputed_rather_than_left_at_zero() {
        // Attaching findings without re-tallying gives a report whose headline
        // says clean while the list below shows CVEs.
        let mut result = scan_result(vec![component("openssl", "3.0.2")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("openssl", "3.0.2"),
            vec![
                vulnerability("CVE-1", "critical", SOURCE_NVD),
                vulnerability("CVE-2", "high", SOURCE_NVD),
                vulnerability("CVE-3", "low", SOURCE_OSV),
            ],
        );
        apply(&mut result, found);

        assert_eq!(result.summary.components, 1);
        assert_eq!(result.summary.vulnerabilities, 3);
        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.low, 1);
    }

    #[test]
    fn vulnerabilities_are_ordered_most_severe_first() {
        let mut result = scan_result(vec![component("openssl", "3.0.2")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("openssl", "3.0.2"),
            vec![
                vulnerability("CVE-3", "low", SOURCE_NVD),
                vulnerability("CVE-1", "critical", SOURCE_NVD),
                vulnerability("CVE-2", "medium", SOURCE_NVD),
            ],
        );
        apply(&mut result, found);

        let order: Vec<&str> = result.components[0]
            .vulnerabilities
            .iter()
            .map(|v| v.cve_id.as_str())
            .collect();
        assert_eq!(order, vec!["CVE-1", "CVE-2", "CVE-3"]);
    }

    #[test]
    fn a_component_with_no_results_keeps_an_empty_list_rather_than_being_dropped() {
        let mut result = scan_result(vec![component("zstd", "1.5.7"), component("curl", "8.14.1")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("curl", "8.14.1"),
            vec![vulnerability("CVE-1", "high", SOURCE_NVD)],
        );
        apply(&mut result, found);

        assert_eq!(result.components.len(), 2);
        assert!(result.components[0].vulnerabilities.is_empty());
        assert_eq!(result.components[1].vulnerabilities.len(), 1);
        assert_eq!(result.summary.components, 2, "a component with no CVEs is still a component");
    }

    #[test]
    fn matching_is_case_insensitive_on_the_product_name() {
        // fold() lowercases its key; a mismatch here would silently attach
        // nothing to a component whose signature capitalizes differently.
        let mut result = scan_result(vec![component("OpenSSL", "3.0.2")]);
        let mut found = HashMap::new();
        found.insert(
            component_key("openssl", "3.0.2"),
            vec![vulnerability("CVE-1", "high", SOURCE_NVD)],
        );
        apply(&mut result, found);
        assert_eq!(result.components[0].vulnerabilities.len(), 1);
    }
}

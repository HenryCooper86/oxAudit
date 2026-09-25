use crate::models::{Dependency, Vulnerability};
use serde_json::Value;
use std::error::Error;

const OSV_BASE: &str = "https://api.osv.dev/v1";

/// OSV requires all three package coordinates. Keep this predicate shared by
/// request construction, progress accounting, and cache receipts so a package
/// is never recorded as queried unless it was eligible for the request.
pub fn is_queryable_dependency(dependency: &Dependency) -> bool {
    dependency.ecosystem != "unknown"
        && !dependency.name.trim().is_empty()
        && !dependency.version.trim().is_empty()
}

pub fn queryable_dependencies(deps: &[Dependency]) -> impl Iterator<Item = &Dependency> {
    deps.iter()
        .filter(|dependency| is_queryable_dependency(dependency))
}

pub fn dependency_query_key(dependency: &Dependency) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        dependency.ecosystem, dependency.name, dependency.version
    )
}

pub fn query_keys(deps: &[Dependency]) -> Vec<String> {
    queryable_dependencies(deps)
        .map(dependency_query_key)
        .collect()
}

fn validate_query_count(count: usize) -> Result<(), String> {
    let limit = crate::deps::lockfiles::MAX_DEPENDENCIES;
    if count > limit {
        Err(format!(
            "resource limit: OSV query exceeds {limit} dependencies"
        ))
    } else {
        Ok(())
    }
}

/// A batch response only identifies advisory ids. Every one must have a full
/// record before the scan can present the batch as an advisory result; omitting
/// an unavailable detail record would turn a known candidate into a false
/// "no vulnerabilities" result.
fn ensure_advisory_records_complete(
    required_ids: &std::collections::BTreeSet<String>,
    records: &std::collections::HashMap<String, Value>,
) -> Result<(), String> {
    let missing = required_ids
        .iter()
        .filter(|id| !records.contains_key(*id))
        .take(5)
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        for id in required_ids {
            if id.trim().is_empty()
                || records[id].get("id").and_then(Value::as_str) != Some(id.as_str())
            {
                return Err(format!("OSV advisory detail coverage is incomplete: record identity does not match requested advisory {id}"));
            }
        }
        return Ok(());
    }

    Err(format!(
        "OSV advisory detail coverage is incomplete; missing record(s): {}",
        missing.join(", "),
    ))
}

/// The OSV batch endpoint must answer once for every submitted query. A short
/// response would otherwise omit packages, and a long response used to index
/// past the submitted chunk. Pagination is not implemented here, so a token is
/// an incomplete coverage error rather than an apparently clean partial page.
pub(super) fn decode_batch_results(
    response: &Value,
    expected_count: usize,
) -> Result<Vec<Value>, String> {
    let results = response
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "OSV batch response is missing its results array".to_string())?;
    if results.len() != expected_count {
        return Err(format!(
            "OSV batch response returned {} results for {expected_count} queries; advisory coverage is incomplete",
            results.len()
        ));
    }
    for result in results {
        let result = result.as_object().ok_or_else(|| {
            "OSV batch result must be an object; advisory coverage is incomplete".to_string()
        })?;
        if let Some(token) = result.get("next_page_token") {
            let token = token.as_str().ok_or_else(|| {
                "OSV batch pagination token must be a string; advisory coverage is incomplete"
                    .to_string()
            })?;
            if !token.is_empty() {
                return Err(
                    "OSV batch response is paginated; advisory coverage is incomplete".into(),
                );
            }
        }
        if let Some(vulns) = result.get("vulns") {
            let vulns = vulns.as_array().ok_or_else(|| {
                "OSV batch vulns must be an array; advisory coverage is incomplete".to_string()
            })?;
            for vuln in vulns {
                if !vuln.is_object()
                    || vuln
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or(true, |id| id.trim().is_empty())
                {
                    return Err("OSV batch advisory requires a nonempty string id; advisory coverage is incomplete".into());
                }
            }
        }
    }
    Ok(results.clone())
}

pub struct OsvClient {
    pub http: reqwest::Client,
}

impl OsvClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Query OSV for a single package@version.
    pub async fn query_package(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>, String> {
        if ecosystem == "unknown" {
            return Ok(Vec::new());
        }
        let body = serde_json::json!({
            "package": { "ecosystem": ecosystem, "name": name },
            "version": version
        });
        let resp = self
            .http
            .post(format!("{OSV_BASE}/query"))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "OSV transport error");
                let mut cur: Option<&dyn std::error::Error> = e.source();
                while let Some(c) = cur {
                    tracing::warn!(cause = %c, "OSV transport error cause");
                    cur = c.source();
                }
                format!("OSV request failed: {e}")
            })?;
        if !resp.status().is_success() {
            return Err(format!("OSV returned {}", resp.status()));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("OSV response parse failed: {e}"))?;
        Ok(parse_vulns(
            json.get("vulns")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            ecosystem,
            name,
            version,
        ))
    }

    /// Batch query OSV (up to 1000 per request). Returns a map keyed by
    /// "ecosystem\0name\0version" with any found vulnerabilities.
    ///
    /// The batch endpoint answers with `id` and `modified` only — no aliases,
    /// severity, CVSS, fixed versions, or details. Use [`Self::resolve_full`]
    /// (or [`Self::query_batch_full`]) to turn the candidates into full
    /// records.
    pub async fn query_batch(
        &self,
        deps: &[Dependency],
    ) -> Result<std::collections::HashMap<String, Vec<Vulnerability>>, String> {
        let queryable: Vec<&Dependency> = queryable_dependencies(deps).collect();
        validate_query_count(queryable.len())?;
        let mut out = std::collections::HashMap::new();
        if queryable.is_empty() {
            return Ok(out);
        }

        for chunk in queryable.chunks(1000) {
            let queries: Vec<Value> = chunk
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "package": { "ecosystem": d.ecosystem, "name": d.name },
                        "version": d.version
                    })
                })
                .collect();
            let resp = self
                .http
                .post(format!("{OSV_BASE}/querybatch"))
                .json(&serde_json::json!({ "queries": queries }))
                .send()
                .await
                .map_err(|e| format!("OSV batch request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("OSV returned {}", resp.status()));
            }
            let json: Value = resp
                .json()
                .await
                .map_err(|e| format!("OSV batch response parse failed: {e}"))?;
            let results = decode_batch_results(&json, chunk.len())?;
            for (i, res) in results.iter().enumerate() {
                let dep = chunk[i];
                if let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) {
                    let parsed =
                        parse_vulns(vulns.clone(), &dep.ecosystem, &dep.name, &dep.version);
                    if !parsed.is_empty() {
                        let key = dependency_query_key(dep);
                        out.insert(key, parsed);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Replace batch-returned skeletons with full OSV records.
    ///
    /// The batch answers which advisories affect which packages, and nothing
    /// else — the skeletons it returns carry no aliases (so no CVE, and no
    /// KEV/EPSS/public-exploit signal), no severity, no CVSS vector, and no
    /// fixed versions. Full records are fetched per advisory id, deduplicated
    /// so a GHSA shared by twenty packages costs one request, with bounded
    /// concurrency and a hard cap so a pathological result cannot run away.
    pub async fn resolve_full(
        &self,
        candidates: &std::collections::HashMap<String, Vec<Vulnerability>>,
        deps: &[Dependency],
    ) -> Result<std::collections::HashMap<String, Vec<Vulnerability>>, String> {
        const MAX_ADVISORY_IDS: usize = 600;
        let by_key: std::collections::HashMap<String, &Dependency> = deps
            .iter()
            .map(|dep| (dependency_query_key(dep), dep))
            .collect();
        let mut ids = std::collections::BTreeSet::new();
        for vulns in candidates.values() {
            for vuln in vulns {
                ids.insert(vuln.id.clone());
            }
            if ids.len() > MAX_ADVISORY_IDS {
                return Err(format!(
                    "OSV advisory detail coverage is incomplete: more than {MAX_ADVISORY_IDS} unique advisory records require resolution"
                ));
            }
        }

        let mut records: std::collections::HashMap<String, Value> =
            std::collections::HashMap::new();
        let id_list: Vec<&String> = ids.iter().collect();
        for chunk in id_list.chunks(20) {
            let fetched = futures::future::join_all(chunk.iter().map(|id| {
                let client = self;
                async move { ((*id).clone(), client.get_vuln(id).await) }
            }))
            .await;
            for (id, fetched) in fetched {
                let record = fetched
                    .map_err(|error| {
                        format!("OSV advisory detail lookup failed for {id}: {error}")
                    })?
                    .ok_or_else(|| format!("OSV advisory detail record is unavailable for {id}"))?;
                records.insert(id, record);
            }
        }
        ensure_advisory_records_complete(&ids, &records)?;

        let mut out = std::collections::HashMap::new();
        for (key, skeletons) in candidates {
            let Some(dep) = by_key.get(key) else { continue };
            let full: Vec<Value> = skeletons
                .iter()
                .filter_map(|skeleton| records.get(&skeleton.id).cloned())
                .collect();
            if !full.is_empty() {
                out.insert(
                    key.clone(),
                    parse_vulns(full, &dep.ecosystem, &dep.name, &dep.version),
                );
            }
        }
        Ok(out)
    }

    /// [`Self::query_batch`] followed by [`Self::resolve_full`]: one call that
    /// returns full advisory records for every affected package.
    pub async fn query_batch_full(
        &self,
        deps: &[Dependency],
    ) -> Result<std::collections::HashMap<String, Vec<Vulnerability>>, String> {
        let candidates = self.query_batch(deps).await?;
        self.resolve_full(&candidates, deps).await
    }

    /// Fetch the full OSV record for an id (e.g. GHSA-xxxx or CVE-xxxx).
    /// Returns Ok(None) when OSV does not know the id.
    pub async fn get_vuln(&self, id: &str) -> Result<Option<Value>, String> {
        let url = format!("{OSV_BASE}/vulns/{}", urlencode(id));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OSV request failed: {e}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("OSV returned {}", resp.status()));
        }
        resp.json()
            .await
            .map(Some)
            .map_err(|e| format!("parse failed: {e}"))
    }

    /// Search all known vulnerabilities for a package (no version).
    pub async fn search_package(&self, ecosystem: &str, name: &str) -> Result<Vec<Value>, String> {
        if ecosystem == "unknown" {
            return Ok(Vec::new());
        }
        let body = serde_json::json!({
            "package": { "ecosystem": ecosystem, "name": name }
        });
        let resp = self
            .http
            .post(format!("{OSV_BASE}/query"))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OSV request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("OSV returned {}", resp.status()));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("OSV response parse failed: {e}"))?;
        Ok(json
            .get("vulns")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }
}

fn urlencode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Convert raw OSV vuln objects into our Vulnerability model. Shared by the
/// network client and the local advisory database so both produce identical
/// findings and evidence.
pub(crate) fn parse_vulns(
    raw: Vec<Value>,
    ecosystem: &str,
    package_name: &str,
    installed_version: &str,
) -> Vec<Vulnerability> {
    let mut out = Vec::new();
    for v in raw {
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let aliases = v
            .get("aliases")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let summary = v
            .get("summary")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let details = v
            .get("details")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let published = v
            .get("published")
            .and_then(|x| x.as_str())
            .map(String::from);
        let modified = v.get("modified").and_then(|x| x.as_str()).map(String::from);
        let references = v
            .get("references")
            .and_then(|r| r.as_array())
            .map(|r| {
                r.iter()
                    .filter_map(|x| x.get("url").and_then(|u| u.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // severity: prefer CVSS score, fall back to affected[].database_specific.severity
        let (severity, cvss_score) = extract_cvss(&v);

        // Keep matching package entries intact: ranges and explicit versions are a union.
        // Display strings are descriptive only; consumers must use structured evidence.
        let records = v
            .get("affected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|aff| {
                aff.pointer("/package/ecosystem").and_then(Value::as_str) == Some(ecosystem)
                    && aff.pointer("/package/name").and_then(Value::as_str) == Some(package_name)
            })
            .cloned()
            .collect::<Vec<_>>();
        let affected_evidence = if records.is_empty() {
            None
        } else {
            Some(crate::models::AffectedEvidence {
                ecosystem: ecosystem.into(),
                package_name: package_name.into(),
                records: records.clone(),
            })
        };
        let mut fixed = Vec::new();
        let mut range_parts = Vec::new();
        for aff in &records {
            for range in aff
                .get("ranges")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let kind = range
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let mut events = Vec::new();
                for event in range
                    .get("events")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(fix) = event.get("fixed").and_then(Value::as_str) {
                        fixed.push(fix.to_owned());
                    }
                    events.push(event.to_string());
                }
                range_parts.push(format!("{kind}: {}", events.join(" → ")));
            }
        }
        fixed.sort();
        fixed.dedup();

        out.push(Vulnerability {
            occurrence: Default::default(),
            affected_evidence,
            id,
            aliases,
            summary,
            details,
            severity,
            cvss_score,
            epss: None,
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
            public_exploit: false,
            direct_usage: Default::default(),
            ecosystem: ecosystem.to_string(),
            package_name: package_name.to_string(),
            installed_version: installed_version.to_string(),
            fixed_versions: fixed,
            affected_range: if range_parts.is_empty() {
                None
            } else {
                Some(range_parts.join(", "))
            },
            references,
            published,
            modified,
            lockfile: String::new(),
        });
    }
    out
}

fn extract_cvss(v: &Value) -> (Option<String>, Option<f32>) {
    // OSV severity array: [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..." }]
    if let Some(sev) = v.get("severity").and_then(|s| s.as_array()) {
        for s in sev {
            let score_str = s.get("score").and_then(|x| x.as_str()).unwrap_or("");
            let score = score_str
                .parse::<f32>()
                .ok()
                .or_else(|| cvss_vector_to_score(score_str));
            if let Some(score) = score {
                return (Some(score_to_severity(score)), Some(score));
            }
        }
    }
    // Fallback: affected[].database_specific.severity ("HIGH", ...)
    if let Some(affected) = v.get("affected").and_then(|a| a.as_array()) {
        for aff in affected {
            if let Some(db) = aff.get("database_specific") {
                if let Some(sev) = db.get("severity").and_then(|x| x.as_str()) {
                    return (Some(sev.to_ascii_lowercase()), None);
                }
            }
        }
    }
    (None, None)
}

/// Compute the CVSS base score from a vector string (v3.x or v2.0).
pub fn cvss_vector_to_score(vector: &str) -> Option<f32> {
    let v = vector.trim();
    if v.starts_with("CVSS:3") || v.starts_with("CVSS3") {
        cvss31_base(v)
    } else if v.starts_with("AV:") || v.starts_with("CVSS:2") || v.starts_with("CVSS2") {
        cvss2_base(v)
    } else {
        None
    }
}

/// CVSS v3.0/3.1 base score (spec formulas, no environmental/temporal).
fn cvss31_base(v: &str) -> Option<f32> {
    let mut metrics = std::collections::HashMap::new();
    for part in v.split('/') {
        if let Some((k, val)) = part.split_once(':') {
            metrics.insert(
                k.trim().to_ascii_uppercase(),
                val.trim().to_ascii_uppercase(),
            );
        }
    }
    let get = |k: &str| metrics.get(k).map(|s| s.as_str());

    let av = match get("AV")? {
        "N" => 0.85f32,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.77f32,
        "H" => 0.44,
        _ => return None,
    };
    let ui = match get("UI")? {
        "N" => 0.85f32,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = get("S")? == "C";
    let pr = match (get("PR")?, scope_changed) {
        ("N", _) => 0.85f32,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let c = match get("C")? {
        "H" => 0.56f32,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let i = match get("I")? {
        "H" => 0.56f32,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let a = match get("A")? {
        "H" => 0.56f32,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        let impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15);
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (6.42 * iss + exploitability).min(10.0)
    };
    // round up to one decimal (per spec)
    Some((base * 10.0).ceil() / 10.0)
}

/// CVSS v2.0 base score.
fn cvss2_base(v: &str) -> Option<f32> {
    let mut metrics = std::collections::HashMap::new();
    for part in v.split('/') {
        if let Some((k, val)) = part.split_once(':') {
            metrics.insert(
                k.trim().to_ascii_uppercase(),
                val.trim().to_ascii_uppercase(),
            );
        }
    }
    let get = |k: &str| metrics.get(k).map(|s| s.as_str());

    let av = match get("AV")? {
        "N" => 1.0f32,
        "A" => 0.646,
        "L" => 0.395,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.71f32,
        "M" => 0.61,
        "H" => 0.35,
        _ => return None,
    };
    let au = match get("AU")? {
        "M" => 0.45f32,
        "S" => 0.56,
        "N" => 0.704,
        _ => return None,
    };
    let c = match get("C")? {
        "C" => 0.66f32,
        "P" => 0.275,
        "N" => 0.0,
        _ => return None,
    };
    let i = match get("I")? {
        "C" => 0.66f32,
        "P" => 0.275,
        "N" => 0.0,
        _ => return None,
    };
    let a = match get("A")? {
        "C" => 0.66f32,
        "P" => 0.275,
        "N" => 0.0,
        _ => return None,
    };

    let impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a));
    let exploitability = 20.0 * av * ac * au;
    let f = if impact == 0.0 { 0.0 } else { 1.176 };
    let base = (0.6 * impact + 0.4 * exploitability - 1.5) * f;
    // round to one decimal (standard rounding)
    Some((base * 10.0).round() / 10.0)
}

pub fn score_to_severity(score: f32) -> String {
    match score {
        s if s >= 9.0 => "critical".into(),
        s if s >= 7.0 => "high".into(),
        s if s >= 4.0 => "medium".into(),
        s if s > 0.0 => "low".into(),
        _ => "info".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixes_match_queried_package_and_preserve_every_interval() {
        let result = super::parse_vulns(
            vec![serde_json::json!({"id":"OSV-test","affected":[
              {"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}]},
              {"package":{"ecosystem":"npm","name":"target"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"},{"introduced":"2.0.0"},{"fixed":"2.0.1"}]}]}
            ]})],
            "npm",
            "target",
            "1.0.0",
        );
        assert_eq!(result[0].fixed_versions, vec!["1.0.1", "2.0.1"]);
        let evidence = result[0].affected_evidence.as_ref().unwrap();
        assert_eq!(evidence.records.len(), 1);
        assert_eq!(
            evidence.records[0]["ranges"][0]["events"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(evidence.records[0]["package"]["name"], "target");
        let decoded: crate::models::Vulnerability =
            serde_json::from_value(serde_json::to_value(&result[0]).unwrap()).unwrap();
        assert_eq!(decoded.affected_evidence.unwrap().records, evidence.records);
    }

    #[test]
    fn cvss31_vectors() {
        // well-known vectors from NVD calculator
        assert_eq!(
            cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
            Some(5.3)
        );
        // scope-changed example (CVE-2020-0601 style vector)
        assert_eq!(
            cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"),
            Some(9.6)
        );
    }

    #[test]
    fn oversized_osv_batches_are_rejected_before_chunking() {
        assert!(validate_query_count(crate::deps::lockfiles::MAX_DEPENDENCIES).is_ok());
        let error = validate_query_count(crate::deps::lockfiles::MAX_DEPENDENCIES + 1)
            .expect_err("oversized batch");
        assert!(error.contains("resource limit"), "{error}");
    }

    #[test]
    fn query_keys_and_count_match_the_dependencies_sent_to_osv() {
        let dependency = |ecosystem: &str, name: &str, version: &str| Dependency {
            occurrence: Default::default(),
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
            lockfile: "fixture.lock".into(),
        };
        let deps = vec![
            dependency("npm", "complete", "1.0.0"),
            dependency("unknown", "ignored", "1.0.0"),
            dependency("npm", "", "1.0.0"),
            dependency("npm", "no-version", ""),
        ];

        let sent = queryable_dependencies(&deps).collect::<Vec<_>>();
        assert_eq!(sent.len(), 1);
        assert_eq!(query_keys(&deps), vec![dependency_query_key(sent[0])]);
    }

    #[test]
    fn missing_advisory_detail_cannot_be_rendered_as_an_empty_result() {
        let required = ["GHSA-present", "GHSA-missing"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let records = std::collections::HashMap::from([(
            "GHSA-present".to_owned(),
            serde_json::json!({ "id": "GHSA-present" }),
        )]);

        let error = ensure_advisory_records_complete(&required, &records)
            .expect_err("a batch candidate must never disappear when detail lookup fails");

        assert!(error.contains("incomplete"), "{error}");
        assert!(error.contains("GHSA-missing"), "{error}");
    }

    #[test]
    fn batch_response_requires_exactly_one_result_per_query() {
        let exact = serde_json::json!({ "results": [{}, {}] });
        assert_eq!(
            decode_batch_results(&exact, 2)
                .expect("exact response")
                .len(),
            2
        );

        for response in [
            serde_json::json!({}),
            serde_json::json!({ "results": [{}] }),
            serde_json::json!({ "results": [{}, {}, {}] }),
        ] {
            let error = decode_batch_results(&response, 2).expect_err("incomplete response");
            assert!(
                error.contains("incomplete") || error.contains("missing"),
                "{error}"
            );
        }
    }

    #[test]
    fn batch_response_with_a_next_page_token_is_not_complete() {
        let response = serde_json::json!({
            "results": [{ "next_page_token": "more-results" }],
        });

        let error = decode_batch_results(&response, 1).expect_err("pagination is unsupported");

        assert!(error.contains("paginated"), "{error}");
    }

    #[test]
    fn batch_response_rejects_malformed_package_results_and_advisory_ids() {
        for result in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({"vulns": {}}),
            serde_json::json!({"vulns": null}),
            serde_json::json!({"next_page_token": null}),
            serde_json::json!({"next_page_token": 5}),
            serde_json::json!({"next_page_token": false}),
            serde_json::json!({"vulns": [null]}),
            serde_json::json!({"vulns": [{}]}),
            serde_json::json!({"vulns": [{"id": 5}]}),
            serde_json::json!({"vulns": [{"id": ""}]}),
            serde_json::json!({"vulns": [{"id": "  "}]}),
        ] {
            let response = serde_json::json!({"results": [result]});
            assert!(
                decode_batch_results(&response, 1).is_err(),
                "accepted {response}"
            );
        }
        for result in [
            serde_json::json!({}),
            serde_json::json!({"vulns": []}),
            serde_json::json!({"next_page_token": "", "vulns": [{"id": "GHSA-valid"}]}),
        ] {
            assert!(decode_batch_results(&serde_json::json!({"results": [result]}), 1).is_ok());
        }
    }

    #[test]
    fn resolved_advisory_record_must_identify_the_requested_id() {
        let required = std::collections::BTreeSet::from(["GHSA-requested".into()]);
        for record in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({"id": ""}),
            serde_json::json!({"id": " "}),
            serde_json::json!({"id": 3}),
            serde_json::json!({"id": "GHSA-other"}),
        ] {
            let records = std::collections::HashMap::from([("GHSA-requested".into(), record)]);
            assert!(
                ensure_advisory_records_complete(&required, &records).is_err(),
                "accepted {records:?}"
            );
        }
        let records = std::collections::HashMap::from([(
            "GHSA-requested".into(),
            serde_json::json!({"id": "GHSA-requested"}),
        )]);
        assert!(ensure_advisory_records_complete(&required, &records).is_ok());
    }

    #[test]
    fn cvss2_vectors() {
        assert_eq!(
            cvss_vector_to_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"),
            Some(7.5)
        );
        assert_eq!(
            cvss_vector_to_score("AV:L/AC:H/Au:N/C:C/I:C/A:C"),
            Some(6.2)
        );
    }

    #[test]
    fn parses_real_osv_record() {
        // captured live response for lodash@4.17.15 (see /tmp/osv_lodash.json)
        let raw = match std::fs::read_to_string("/tmp/osv_lodash.json") {
            Ok(s) => s,
            Err(_) => {
                eprintln!("skipping: /tmp/osv_lodash.json not present");
                return;
            }
        };
        let json: Value = serde_json::from_str(&raw).unwrap();
        let vulns = parse_vulns(
            json["vulns"].as_array().unwrap().clone(),
            "npm",
            "lodash",
            "4.17.15",
        );
        assert!(!vulns.is_empty());
        let with_sev = vulns
            .iter()
            .filter(|v| v.severity.is_some() || v.cvss_score.is_some())
            .count();
        assert!(with_sev > 0, "expected severity data in OSV records");
        assert!(
            vulns.iter().any(|v| !v.fixed_versions.is_empty()),
            "expected fixed versions derivable from ranges"
        );
        // every record must carry a summary or details
        for v in &vulns {
            assert!(v.summary.len() + v.details.len() > 0);
        }
    }
}

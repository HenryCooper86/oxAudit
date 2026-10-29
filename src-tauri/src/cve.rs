use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::deps::osv::{score_to_severity, OsvClient};
use crate::models::{CveDetail, CveItem, CveSearchResult};

const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a fetched KEV catalog is reused.
const KEV_TTL: Duration = Duration::from_secs(60 * 60);
/// How long a failed KEV fetch is remembered before the next attempt — long
/// enough that a burst of lookups during an outage does not hammer CISA,
/// short enough that the catalog comes back as soon as the feed does.
const KEV_FAILURE_RETRY: Duration = Duration::from_secs(60);

/// Shared state for NVD rate limiting + caching. Managed as its own Tauri state
/// so async commands can hold a reference across awaits (no MutexGuard crossing
/// an await point).
pub struct CveState {
    pub http: reqwest::Client,
    pub osv: OsvClient,
    /// (timestamp, count) of requests in the current 30s window
    pub window: Mutex<(Instant, usize)>,
    pub cache: Mutex<HashMap<String, (Instant, CveSearchResult)>>,
    /// The CISA KEV catalog, fetched at most once an hour. Research is
    /// interactive — a user opens several CVEs in a session — so re-downloading
    /// 1,671 entries per lookup would be wasteful. Only a successfully
    /// fetched catalog is stored here.
    pub kev: Mutex<Option<(Instant, crate::exploit::KevSet)>>,
    /// The last KEV failure, kept for [`KEV_FAILURE_RETRY`]. Never stored as
    /// an empty catalog: "could not check" must not read as "nothing exploited".
    kev_failure: Mutex<Option<(Instant, String)>>,
    kev_url: String,
}

impl CveState {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http: http.clone(),
            osv: OsvClient::new(http),
            window: Mutex::new((Instant::now(), 0)),
            cache: Mutex::new(HashMap::new()),
            kev: Mutex::new(None),
            kev_failure: Mutex::new(None),
            kev_url: crate::exploit::KEV_URL.to_string(),
        }
    }

    /// The KEV catalog, from the hour-long cache or freshly fetched.
    ///
    /// A failure is an `Err` with the reason, never an empty set: callers
    /// treat KEV as enrichment and carry on, but they must be able to say
    /// the signal was unavailable rather than imply nothing is exploited.
    /// Failures are not cached as a catalog; they are remembered only for
    /// [`KEV_FAILURE_RETRY`].
    pub(crate) async fn kev_set(&self) -> Result<crate::exploit::KevSet, String> {
        if let Some((fetched, set)) = self.kev.lock().unwrap().as_ref() {
            if fetched.elapsed() < KEV_TTL {
                return Ok(set.clone());
            }
        }
        if let Some((failed, reason)) = self.kev_failure.lock().unwrap().as_ref() {
            if failed.elapsed() < KEV_FAILURE_RETRY {
                return Err(reason.clone());
            }
        }
        match self.fetch_kev().await {
            Ok(set) => {
                *self.kev.lock().unwrap() = Some((Instant::now(), set.clone()));
                *self.kev_failure.lock().unwrap() = None;
                Ok(set)
            }
            Err(reason) => {
                *self.kev_failure.lock().unwrap() = Some((Instant::now(), reason.clone()));
                Err(reason)
            }
        }
    }

    async fn fetch_kev(&self) -> Result<crate::exploit::KevSet, String> {
        let response = self
            .http
            .get(&self.kev_url)
            .send()
            .await
            .map_err(|e| format!("CISA KEV catalog lookup failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("CISA KEV catalog returned {}", response.status()));
        }
        let body = response
            .text()
            .await
            .map_err(|e| format!("CISA KEV catalog could not be read: {e}"))?;
        crate::exploit::KevSet::parse(&body)
            .map_err(|e| format!("CISA KEV catalog could not be parsed: {e}"))
    }

    /// EPSS score and percentile for one CVE. `Ok(None)` means FIRST answered
    /// and has no score for it; `Err` means the lookup itself failed.
    async fn epss_for(&self, id: &str) -> Result<Option<(f64, f64)>, String> {
        let response = self
            .http
            .get(EPSS_URL)
            .query(&[("cve", id)])
            .send()
            .await
            .map_err(|e| format!("EPSS lookup failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("EPSS returned {}", response.status()));
        }
        let text = response
            .text()
            .await
            .map_err(|e| format!("EPSS response could not be read: {e}"))?;
        let scores = crate::exploit::parse_epss(&text)
            .map_err(|e| format!("EPSS response could not be parsed: {e}"))?;
        Ok(scores.get(id).copied())
    }

    /// Enforce NVD rate limits: 5 req / 30s without a key, 50 with one.
    async fn throttle(&self, authenticated: bool) {
        let limit = if authenticated { 50 } else { 5 };
        loop {
            let sleep = {
                let mut w = self.window.lock().unwrap();
                let (start, count) = *w;
                if start.elapsed() >= Duration::from_secs(30) {
                    *w = (Instant::now(), 0);
                    None
                } else if count >= limit {
                    let wait = Duration::from_secs(30) - start.elapsed();
                    Some(wait)
                } else {
                    None
                }
            };
            match sleep {
                Some(wait) => tokio::time::sleep(wait).await,
                None => {
                    let mut w = self.window.lock().unwrap();
                    w.1 += 1;
                    break;
                }
            }
        }
    }

    pub(crate) async fn nvd_get(
        &self,
        params: &[(&str, String)],
        api_key: Option<&str>,
    ) -> Result<Value, String> {
        let api_key = api_key.map(str::trim).filter(|key| !key.is_empty());
        self.throttle(api_key.is_some()).await;
        let mut url = reqwest::Url::parse(NVD_BASE).map_err(|e| e.to_string())?;
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in params {
                q.append_pair(k, v);
            }
        }
        let mut req = self.http.get(url);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("NVD request failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "NVD returned {status}: {}",
                body.chars().take(300).collect::<String>()
            ));
        }
        resp.json()
            .await
            .map_err(|e| format!("NVD response parse failed: {e}"))
    }

    fn cache_get(&self, key: &str) -> Option<CveSearchResult> {
        let cache = self.cache.lock().unwrap();
        if let Some((ts, res)) = cache.get(key) {
            if ts.elapsed() < CACHE_TTL {
                return Some(res.clone());
            }
        }
        None
    }

    fn cache_put(&self, key: &str, res: CveSearchResult) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 200 {
            cache.clear();
        }
        cache.insert(key.to_string(), (Instant::now(), res));
    }
}

/// Free-text CVE search via NVD keywordSearch.
pub async fn search_cves(
    state: &CveState,
    api_key: Option<&str>,
    query: &str,
    start_index: usize,
    per_page: usize,
    recent_days: Option<u64>,
) -> Result<CveSearchResult, String> {
    let per_page = per_page.clamp(1, 100);
    let cache_key = format!("s:{query}:{start_index}:{per_page}:{recent_days:?}");
    if let Some(hit) = state.cache_get(&cache_key) {
        return Ok(hit);
    }

    let mut params: Vec<(&str, String)> = vec![
        ("resultsPerPage", per_page.to_string()),
        ("startIndex", start_index.to_string()),
    ];
    let q = query.trim();
    if !q.is_empty() {
        params.push(("keywordSearch", q.to_string()));
    }
    if let Some(days) = recent_days {
        let since = chrono::Utc::now() - chrono::Duration::days(days as i64);
        params.push((
            "lastModStartDate",
            since.format("%Y-%m-%dT%H:%M:%S%.3f").to_string() + "Z",
        ));
        params.push((
            "lastModEndDate",
            chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3f")
                .to_string()
                + "Z",
        ));
    }

    let json = state.nvd_get(&params, api_key).await?;
    let total = json
        .get("totalResults")
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as usize;
    let items = parse_cve_items(json);

    let result = CveSearchResult { total, items };
    state.cache_put(&cache_key, result.clone());
    Ok(result)
}

/// Fetch full detail for a CVE id: NVD record + OSV enrichment.
pub async fn cve_detail(
    state: &CveState,
    api_key: Option<&str>,
    id: &str,
) -> Result<CveDetail, String> {
    let id = id.trim().to_ascii_uppercase();
    if !id.starts_with("CVE-") {
        return Err("id must look like CVE-YYYY-XXXX".into());
    }
    let json = state.nvd_get(&[("cveId", id.clone())], api_key).await?;
    let raw = json.clone();
    let items = parse_cve_items(json);
    let mut item = items
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| format!("CVE {id} not found in NVD"))?;

    // Exploitation signal: is this CVE known-exploited (KEV), and what is its
    // EPSS score? Both are best-effort — a failure leaves the fields at their
    // defaults rather than failing the lookup. `CveDetail` has no channel to
    // tell the UI a signal was unavailable, so failures are logged.
    match state.kev_set().await {
        Ok(kev) => {
            let (known_exploited, ransomware) = kev.signal(&id);
            item.known_exploited = known_exploited;
            item.ransomware = ransomware;
        }
        Err(reason) => tracing::warn!(cve = %id, %reason, "KEV signal unavailable for CVE detail"),
    }
    match state.epss_for(&id).await {
        Ok(Some((epss, percentile))) => {
            item.epss = Some(epss);
            item.epss_percentile = Some(percentile);
        }
        Ok(None) => {}
        Err(reason) => tracing::warn!(cve = %id, %reason, "EPSS signal unavailable for CVE detail"),
    }

    let osv = state.osv.get_vuln(&id).await.unwrap_or(None);

    Ok(CveDetail { item, raw, osv })
}

/// Search OSV for all known vulnerabilities of a package (research mode).
pub async fn osv_package_vulns(
    state: &CveState,
    ecosystem: &str,
    name: &str,
) -> Result<Vec<Value>, String> {
    state.osv.search_package(ecosystem, name).await
}

fn parse_cve_items(json: Value) -> Vec<CveItem> {
    let mut items = Vec::new();
    let vulns = json
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for entry in vulns {
        let Some(cve) = entry.get("cve") else {
            continue;
        };
        let id = cve
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }

        let description = cve
            .get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                    .or_else(|| arr.first())
            })
            .and_then(|d| d.get("value").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();

        let (severity, cvss_score) = extract_nvd_severity(cve);

        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .map(String::from);
        let modified = cve
            .get("lastModified")
            .and_then(|v| v.as_str())
            .map(String::from);

        // affected products from configurations[].nodes[].cpeMatch[].criteria
        let mut products: Vec<String> = Vec::new();
        if let Some(configs) = cve.get("configurations").and_then(|c| c.as_array()) {
            for config in configs {
                if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                    for node in nodes {
                        if let Some(matches) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                            for m in matches {
                                if let Some(criteria) = m.get("criteria").and_then(|c| c.as_str()) {
                                    if let Some(p) = cpe_product(criteria) {
                                        if !products.contains(&p) {
                                            products.push(p);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if products.len() > 20 {
            products.truncate(20);
            products.push("…".into());
        }

        let references = cve
            .get("references")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let cwes = cve
            .get("weaknesses")
            .and_then(|w| w.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| {
                        w.get("description")
                            .and_then(|d| d.as_array())
                            .and_then(|d| {
                                d.iter()
                                    .find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en"))
                            })
                    })
                    .filter_map(|d| d.get("value").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        items.push(CveItem {
            id,
            severity,
            cvss_score,
            description,
            published,
            modified,
            affected_products: products,
            references,
            cwes,
            epss: None,
            epss_percentile: None,
            known_exploited: false,
            ransomware: false,
        });
    }
    items
}

/// Severity and base score from an NVD 2.0 `metrics` object.
///
/// CVSS v3.1 is preferred, then v3.0, then v4.0, then v2. Within one version
/// NVD lists several scorers — its own assessment (`"type": "Primary"`) and
/// CNA scores (`"Secondary"`), often with the CNA first — so the Primary
/// metric wins and a Secondary one is used only when no Primary exists.
fn extract_nvd_severity(cve: &Value) -> (Option<String>, Option<f32>) {
    let Some(metrics) = cve.get("metrics").and_then(|m| m.as_object()) else {
        return (None, None);
    };
    for key in [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV40",
        "cvssMetricV2",
    ] {
        let Some(entries) = metrics.get(key).and_then(|m| m.as_array()) else {
            continue;
        };
        let scored = |entry: &&Value| {
            entry
                .get("cvssData")
                .and_then(|d| d.get("baseScore"))
                .and_then(|s| s.as_f64())
                .is_some()
        };
        let chosen = entries
            .iter()
            .filter(scored)
            .find(|entry| entry.get("type").and_then(|t| t.as_str()) == Some("Primary"))
            .or_else(|| entries.iter().find(scored));
        let Some(entry) = chosen else {
            continue;
        };
        let data = &entry["cvssData"];
        let score = data["baseScore"].as_f64().unwrap_or_default() as f32;
        // v3/v4 carry baseSeverity in cvssData; NVD 2.0 puts v2's on the metric.
        let severity = data
            .get("baseSeverity")
            .or_else(|| entry.get("baseSeverity"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| score_to_severity(score));
        return (Some(severity), Some(score));
    }
    (None, None)
}

/// Extract "vendor:product" from a CPE 2.3 string.
fn cpe_product(criteria: &str) -> Option<String> {
    // cpe:2.3:part:vendor:product:version:...
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() < 5 || parts[0] != "cpe" {
        return None;
    }
    let vendor = parts[3];
    let product = parts[4];
    if product.is_empty() || product == "*" || product == "-" {
        return None;
    }
    if vendor.is_empty() || vendor == "*" || vendor == "-" {
        return Some(product.to_string());
    }
    Some(format!("{vendor}:{product}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cpe_product_reads_vendor_and_product_fields() {
        assert_eq!(
            cpe_product("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").as_deref(),
            Some("apache:log4j")
        );
        assert_eq!(
            cpe_product("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*").as_deref(),
            Some("linux:linux_kernel")
        );
        // Wildcard vendor: the product alone.
        assert_eq!(
            cpe_product("cpe:2.3:a:*:openssl:*:*:*:*:*:*:*:*").as_deref(),
            Some("openssl")
        );
        assert_eq!(cpe_product("cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"), None);
        assert_eq!(cpe_product("cpe:2.3:a:apache"), None);
        assert_eq!(cpe_product(""), None);
    }

    fn metric(source: &str, kind: &str, score: f64, severity: &str) -> Value {
        json!({
            "source": source,
            "type": kind,
            "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": severity}
        })
    }

    #[test]
    fn nvd_severity_prefers_the_primary_metric_over_a_secondary_listed_first() {
        let cve = json!({"metrics": {"cvssMetricV31": [
            metric("cna@vendor.example", "Secondary", 5.3, "MEDIUM"),
            metric("nvd@nist.gov", "Primary", 9.8, "CRITICAL"),
        ]}});
        assert_eq!(
            extract_nvd_severity(&cve),
            (Some("critical".to_string()), Some(9.8))
        );
    }

    #[test]
    fn nvd_severity_falls_back_to_a_secondary_metric_and_older_versions() {
        let secondary_only = json!({"metrics": {"cvssMetricV31": [
            metric("cna@vendor.example", "Secondary", 7.5, "HIGH"),
        ]}});
        assert_eq!(
            extract_nvd_severity(&secondary_only),
            (Some("high".to_string()), Some(7.5))
        );
        // v3.1 outranks v2 even when v2 is Primary.
        let mixed = json!({"metrics": {
            "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                "cvssData": {"version": "2.0", "baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV31": [metric("cna@vendor.example", "Secondary", 8.1, "HIGH")],
        }});
        assert_eq!(
            extract_nvd_severity(&mixed),
            (Some("high".to_string()), Some(8.1))
        );
        // NVD 2.0 puts v2 baseSeverity on the metric, not inside cvssData.
        let v2_only = json!({"metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov",
            "type": "Primary", "cvssData": {"version": "2.0", "baseScore": 4.3},
            "baseSeverity": "MEDIUM"}]}});
        assert_eq!(
            extract_nvd_severity(&v2_only),
            (Some("medium".to_string()), Some(4.3))
        );
        assert_eq!(extract_nvd_severity(&json!({"metrics": {}})), (None, None));
        assert_eq!(extract_nvd_severity(&json!({})), (None, None));
    }

    #[test]
    fn parse_cve_items_reads_an_nvd_2_0_page() {
        let page = json!({
            "resultsPerPage": 2,
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2024-07-24T17:08:24.167",
                    "descriptions": [
                        {"lang": "es", "value": "Apache Log4j2 ... (es)"},
                        {"lang": "en", "value": "Apache Log4j2 JNDI features ..."}
                    ],
                    "metrics": {"cvssMetricV31": [
                        metric("nvd@nist.gov", "Primary", 10.0, "CRITICAL")
                    ]},
                    "weaknesses": [
                        {"source": "nvd@nist.gov", "type": "Primary",
                         "description": [{"lang": "en", "value": "CWE-917"}]},
                        {"source": "security@apache.org", "type": "Secondary",
                         "description": [{"lang": "en", "value": "CWE-502"}]}
                    ],
                    "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
                        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
                        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"},
                        {"vulnerable": true, "criteria": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"}
                    ]}]}],
                    "references": [
                        {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "security@apache.org"}
                    ]
                }},
                {"cve": {"id": "", "descriptions": []}},
                {"notACve": {}},
                {"cve": {"id": "CVE-2026-0001", "descriptions": [{"lang": "fr", "value": "seulement"}]}}
            ]
        });
        let items = parse_cve_items(page);
        assert_eq!(items.len(), 2, "entries without an id are skipped");
        let log4shell = &items[0];
        assert_eq!(log4shell.id, "CVE-2021-44228");
        assert_eq!(log4shell.description, "Apache Log4j2 JNDI features ...");
        assert_eq!(log4shell.severity.as_deref(), Some("critical"));
        assert_eq!(log4shell.cvss_score, Some(10.0));
        assert_eq!(
            log4shell.published.as_deref(),
            Some("2021-12-10T10:15:09.143")
        );
        assert_eq!(
            log4shell.modified.as_deref(),
            Some("2024-07-24T17:08:24.167")
        );
        assert_eq!(
            log4shell.affected_products,
            vec![
                "apache:log4j".to_string(),
                "debian:debian_linux".to_string()
            ]
        );
        assert_eq!(log4shell.cwes, vec!["CWE-917", "CWE-502"]);
        assert_eq!(
            log4shell.references,
            vec!["https://logging.apache.org/log4j/2.x/security.html"]
        );
        assert!(!log4shell.known_exploited);
        assert_eq!(log4shell.epss, None);
        // No English description: the first one stands in.
        assert_eq!(items[1].description, "seulement");
        assert_eq!(items[1].severity, None);
        assert!(parse_cve_items(json!({})).is_empty());
    }

    #[test]
    fn parse_cve_items_bounds_affected_products() {
        let matches: Vec<Value> = (0..30)
            .map(|i| json!({"criteria": format!("cpe:2.3:a:vendor:product{i}:*:*:*:*:*:*:*:*")}))
            .collect();
        let page = json!({"vulnerabilities": [{"cve": {"id": "CVE-2026-0002",
            "configurations": [{"nodes": [{"cpeMatch": matches}]}]}}]});
        let items = parse_cve_items(page);
        assert_eq!(items[0].affected_products.len(), 21);
        assert_eq!(items[0].affected_products[0], "vendor:product0");
        assert_eq!(items[0].affected_products[20], "…");
    }

    fn offline_http() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    /// Serve each body once, in order, with the given status.
    async fn serve(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (format!("http://{address}/kev"), server)
    }

    const KEV_BODY: &str = r#"{"vulnerabilities":[{"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known","cwes":["CWE-917"]}]}"#;

    #[tokio::test]
    async fn a_failed_kev_fetch_is_an_error_and_is_not_cached_as_an_empty_catalog() {
        let (url, server) = serve(vec![("503 Service Unavailable", "down")]).await;
        let state = CveState {
            kev_url: url,
            ..CveState::new(offline_http())
        };
        let error = state
            .kev_set()
            .await
            .expect_err("a 503 is not an empty catalog");
        server.await.unwrap();
        assert!(error.contains("503"), "{error}");
        assert!(
            state.kev.lock().unwrap().is_none(),
            "a failure must not be cached as the catalog"
        );
        // Within the short retry window the failure is reported again, not
        // turned into an empty set.
        assert!(state.kev_set().await.is_err());
    }

    #[tokio::test]
    async fn an_unparseable_kev_body_is_an_error() {
        let (url, server) = serve(vec![("200 OK", "<html>maintenance</html>")]).await;
        let state = CveState {
            kev_url: url,
            ..CveState::new(offline_http())
        };
        assert!(state.kev_set().await.is_err());
        server.await.unwrap();
        assert!(state.kev.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn kev_recovers_after_the_failure_window_and_caches_success() {
        let (url, server) = serve(vec![
            ("500 Internal Server Error", ""),
            ("200 OK", KEV_BODY),
        ])
        .await;
        let state = CveState {
            kev_url: url,
            ..CveState::new(offline_http())
        };
        assert!(state.kev_set().await.is_err());
        // Age the failure past its retry window.
        if let Some((at, _)) = state.kev_failure.lock().unwrap().as_mut() {
            *at -= KEV_FAILURE_RETRY + Duration::from_secs(1);
        }
        let kev = state.kev_set().await.expect("second fetch succeeds");
        server.await.unwrap();
        assert_eq!(kev.signal("CVE-2021-44228"), (true, true));
        assert!(state.kev_failure.lock().unwrap().is_none());
        // Served from the cache now; the server has no more responses.
        let cached = state.kev_set().await.expect("cached");
        assert_eq!(cached.signal("CVE-2021-44228"), (true, true));
    }
}

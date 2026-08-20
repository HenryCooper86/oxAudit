use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::deps::osv::{score_to_severity, OsvClient};
use crate::models::{CveDetail, CveItem, CveSearchResult};

const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Shared state for NVD rate limiting + caching. Managed as its own Tauri state
/// so async commands can hold a reference across awaits (no MutexGuard crossing
/// an await point).
pub struct CveState {
    pub http: reqwest::Client,
    pub osv: OsvClient,
    pub api_key: Mutex<Option<String>>,
    /// (timestamp, count) of requests in the current 30s window
    pub window: Mutex<(Instant, usize)>,
    pub cache: Mutex<HashMap<String, (Instant, CveSearchResult)>>,
    /// The CISA KEV catalog, fetched at most once an hour. Research is
    /// interactive — a user opens several CVEs in a session — so re-downloading
    /// 1,671 entries per lookup would be wasteful.
    pub kev: Mutex<Option<(Instant, crate::exploit::KevSet)>>,
}

impl CveState {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http: http.clone(),
            osv: OsvClient::new(http),
            api_key: Mutex::new(None),
            window: Mutex::new((Instant::now(), 0)),
            cache: Mutex::new(HashMap::new()),
            kev: Mutex::new(None),
        }
    }

    /// The KEV catalog, from the hour-long cache or freshly fetched.
    ///
    /// A failed fetch yields an empty set, never an error: KEV is enrichment,
    /// and a CVE lookup must not fail because CISA's feed was briefly down.
    pub(crate) async fn kev_set(&self) -> crate::exploit::KevSet {
        const KEV_TTL: Duration = Duration::from_secs(60 * 60);
        if let Some((fetched, set)) = self.kev.lock().unwrap().as_ref() {
            if fetched.elapsed() < KEV_TTL {
                return set.clone();
            }
        }
        let set = match self.http.get(crate::exploit::KEV_URL).send().await {
            Ok(response) if response.status().is_success() => response
                .text()
                .await
                .ok()
                .and_then(|body| crate::exploit::KevSet::parse(&body).ok())
                .unwrap_or_default(),
            _ => crate::exploit::KevSet::default(),
        };
        *self.kev.lock().unwrap() = Some((Instant::now(), set.clone()));
        set
    }

    /// Enforce NVD rate limits: 5 req / 30s without a key, 50 with one.
    async fn throttle(&self) {
        let limit = if self.api_key.lock().unwrap().is_some() {
            50
        } else {
            5
        };
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

    pub(crate) async fn nvd_get(&self, params: &[(&str, String)]) -> Result<Value, String> {
        self.throttle().await;
        let mut url = reqwest::Url::parse(NVD_BASE).map_err(|e| e.to_string())?;
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in params {
                q.append_pair(k, v);
            }
        }
        let key = self.api_key.lock().unwrap().clone();
        let mut req = self.http.get(url);
        if let Some(key) = &key {
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

    let json = state.nvd_get(&params).await?;
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
pub async fn cve_detail(state: &CveState, id: &str) -> Result<CveDetail, String> {
    let id = id.trim().to_ascii_uppercase();
    if !id.starts_with("CVE-") {
        return Err("id must look like CVE-YYYY-XXXX".into());
    }
    let json = state.nvd_get(&[("cveId", id.clone())]).await?;
    let raw = json.clone();
    let items = parse_cve_items(json);
    let mut item = items
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| format!("CVE {id} not found in NVD"))?;

    // Exploitation signal: is this CVE known-exploited (KEV), and what is its
    // EPSS score? Both are best-effort — a failure leaves the fields at their
    // safe defaults rather than failing the lookup.
    let kev = state.kev_set().await;
    let (known_exploited, ransomware) = kev.signal(&id);
    item.known_exploited = known_exploited;
    item.ransomware = ransomware;
    if let Ok(body) = state
        .http
        .get("https://api.first.org/data/v1/epss")
        .query(&[("cve", id.as_str())])
        .send()
        .await
    {
        if let Ok(text) = body.text().await {
            if let Ok(scores) = crate::exploit::parse_epss(&text) {
                if let Some((epss, percentile)) = scores.get(&id) {
                    item.epss = Some(*epss);
                    item.epss_percentile = Some(*percentile);
                }
            }
        }
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

        let (severity, cvss_score) = extract_nvd_severity(&cve);

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

fn extract_nvd_severity(cve: &Value) -> (Option<String>, Option<f32>) {
    // Prefer CVSS v3.1, then v3.0, then v2
    if let Some(metrics) = cve.get("metrics").and_then(|m| m.as_object()) {
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            if let Some(arr) = metrics.get(key).and_then(|m| m.as_array()) {
                if let Some(first) = arr.first() {
                    let data = first.get("cvssData");
                    if let Some(score) =
                        data.and_then(|d| d.get("baseScore").and_then(|s| s.as_f64()))
                    {
                        let sev = data
                            .and_then(|d| d.get("baseSeverity").and_then(|s| s.as_str()))
                            .map(|s| s.to_ascii_lowercase())
                            .unwrap_or_else(|| score_to_severity(score as f32));
                        return (Some(sev), Some(score as f32));
                    }
                }
            }
        }
    }
    (None, None)
}

/// Extract "vendor:product" from a CPE 2.3 string.
fn cpe_product(criteria: &str) -> Option<String> {
    // cpe:2.3:part:vendor:product:version:...
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() >= 5 {
        let vendor = parts[2];
        let product = parts[3];
        if !vendor.is_empty() && !product.is_empty() && product != "*" {
            return Some(format!("{vendor}:{product}"));
        }
        if product != "*" {
            return Some(product.to_string());
        }
    }
    None
}

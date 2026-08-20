use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Scanning (source code + secrets)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub path: String,
    pub include_git: bool,
    pub follow_symlinks: bool,
    pub max_file_size_kb: u64,
    pub scan_secrets: bool,
    pub scan_vulnerabilities: bool,
    pub extra_ignored_dirs: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            path: String::new(),
            include_git: false,
            follow_symlinks: false,
            max_file_size_kb: 1024,
            scan_secrets: true,
            scan_vulnerabilities: true,
            extra_ignored_dirs: Vec::new(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub path: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u64,
    pub secrets_found: usize,
    pub vulnerabilities_found: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// rule_id -> number of matches
    pub rules_fired: std::collections::BTreeMap<String, usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// "secret" | "vulnerability"
    pub category: String,
    pub rule_id: String,
    pub rule_name: String,
    /// critical | high | medium | low | info
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    /// the matched snippet (truncated)
    pub match_text: String,
    /// a few lines of surrounding source context
    pub context: String,
    pub language: String,
    pub cwe: Option<String>,
    pub recommendation: String,
    /// Shannon entropy of the matched secret value (secrets only)
    pub entropy: Option<f32>,
    /// reserved for live verification (None = not verified)
    pub verified: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------
// Dependency / application scanning
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub lockfile: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    /// OSV id, e.g. GHSA-xxxx or CVE-xxxx
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub details: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f32>,
    /// EPSS probability of exploitation in the next 30 days, `[0, 1]`.
    #[serde(default)]
    pub epss: Option<f64>,
    /// EPSS percentile against all scored CVEs, `[0, 1]`.
    #[serde(default)]
    pub epss_percentile: Option<f64>,
    /// In CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub known_exploited: bool,
    /// Named in a ransomware campaign, per KEV.
    #[serde(default)]
    pub ransomware: bool,
    pub ecosystem: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_versions: Vec<String>,
    pub affected_range: Option<String>,
    pub references: Vec<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub lockfile: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DepScanSummary {
    pub path: String,
    pub lockfiles_found: Vec<String>,
    pub packages_found: usize,
    pub packages_queried: usize,
    pub vulnerabilities_found: usize,
    pub duration_ms: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DependencyScanResult {
    pub summary: DepScanSummary,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LockfileInfo {
    pub path: String,
    pub kind: String,
    pub packages: usize,
}

// ---------------------------------------------------------------------------
// CVE research
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CveItem {
    pub id: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub affected_products: Vec<String>,
    pub references: Vec<String>,
    pub cwes: Vec<String>,
    /// EPSS probability of exploitation in the next 30 days, `[0, 1]`.
    #[serde(default)]
    pub epss: Option<f64>,
    /// EPSS percentile against all scored CVEs, `[0, 1]`.
    #[serde(default)]
    pub epss_percentile: Option<f64>,
    /// In CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub known_exploited: bool,
    /// Named in a ransomware campaign, per KEV.
    #[serde(default)]
    pub ransomware: bool,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CveSearchResult {
    pub total: usize,
    pub items: Vec<CveItem>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CveDetail {
    pub item: CveItem,
    pub raw: serde_json::Value,
    pub osv: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// AI assistant
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AiSettings {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f32,
    pub timeout_secs: u64,
    pub max_tokens: u32,
    pub system_prompt: String,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://api.openai.com/v1".into(),
            api_key: String::new(),
            model: "gpt-4o-mini".into(),
            temperature: 0.2,
            timeout_secs: 120,
            max_tokens: 2048,
            system_prompt: DEFAULT_SYSTEM_PROMPT.into(),
        }
    }
}

pub const DEFAULT_SYSTEM_PROMPT: &str = "You are VulnCompanion, an expert application security engineer \
and vulnerability researcher embedded in a desktop security tool. You help developers and security \
analysts understand vulnerabilities, exploit details, remediation steps and CVE research. Be precise, \
concrete and actionable. When analyzing code, reference exact lines and suggest specific fixes. \
Never invent CVEs or exploit details you are not confident about — say so when you are uncertain.";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanSettings {
    pub max_file_size_kb: u64,
    pub follow_symlinks: bool,
    pub include_git: bool,
    pub ignored_dirs: Vec<String>,
    pub scan_secrets: bool,
    pub scan_vulnerabilities: bool,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            max_file_size_kb: 1024,
            follow_symlinks: false,
            include_git: false,
            ignored_dirs: default_ignored_dirs(),
            scan_secrets: true,
            scan_vulnerabilities: true,
        }
    }
}

pub fn default_ignored_dirs() -> Vec<String> {
    [
        "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build",
        "target", ".next", ".nuxt", ".output", "out", "coverage", ".tox",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "Pods", ".gradle",
        ".idea", ".vscode", ".svn", ".hg", "bower_components", "jspm_packages",
        ".cache", ".parcel-cache", "env", ".env", "site-packages", "lib64",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub ai: AiSettings,
    pub scan: ScanSettings,
    pub nvd_api_key: Option<String>,
    pub theme: String,
    /// Explicit path to a cve-bin-tool executable. Empty means "find it on
    /// PATH". Defaulted so settings files written before binary scanning
    /// existed still load.
    #[serde(default)]
    pub binary_scanner_path: Option<String>,
    /// How cve-bin-tool runs: "auto" | "native" | "docker". Docker is often the
    /// runtime that works, since our image carries the upstream NVD fix.
    #[serde(default)]
    pub binary_scanner_runtime: Option<String>,
    /// Explicit grype path. Empty means "find it on PATH".
    #[serde(default)]
    pub grype_path: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            ai: AiSettings::default(),
            scan: ScanSettings::default(),
            nvd_api_key: None,
            theme: "dark".into(),
            binary_scanner_path: None,
            binary_scanner_runtime: None,
            grype_path: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Client-chosen id used to aggregate per-conversation token/cost usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StreamStarted {
    pub run_id: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChatResponse {
    pub content: String,
    pub model: Option<String>,
    pub usage: Option<Usage>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AiStatus {
    pub ok: bool,
    pub message: String,
    pub model: Option<String>,
    pub latency_ms: u64,
}

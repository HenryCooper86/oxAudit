use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Scanning (source code + secrets)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub path: String,
    pub include_git: bool,
    pub follow_symlinks: bool,
    pub max_file_size_kb: u64,
    pub scan_secrets: bool,
    pub scan_vulnerabilities: bool,
    pub extra_ignored_dirs: Vec<String>,
    #[serde(default)]
    pub ignore_invalid_policy: bool,
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
            ignore_invalid_policy: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

/// How far oxAudit could qualify a pattern match.
///
/// A regex over raw text cannot tell code from a sentence about code. When a
/// grammar is available the match is checked against the parse tree and this is
/// `Syntax`; when it is not, the match stands on text alone and this is `Text`.
///
/// Reported rather than hidden, because a reviewer deciding how much to trust a
/// finding should be told which of the two produced it. Defaults to `Text` so
/// findings persisted before the distinction existed do not claim a
/// verification that never happened.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalysisTier {
    /// The rule matched file text; no grammar was available for the language.
    #[default]
    Text,
    /// A grammar parsed the file and the match sits in code, not in a comment
    /// or a string literal.
    Syntax,
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
    /// This finding's weakness class (CWE) is represented in CISA's Known
    /// Exploited Vulnerabilities catalog — attackers are actively exploiting
    /// this *kind* of bug in the wild. A source finding has no CVE, so this is
    /// a class-level signal, not a per-finding one. EPSS, being CVE-keyed, does
    /// not apply.
    #[serde(default)]
    pub cwe_exploited: bool,
    /// How many exploited CVEs share this finding's CWE.
    #[serde(default)]
    pub cwe_exploited_count: usize,
    pub recommendation: String,
    /// Shannon entropy of the matched secret value (secrets only)
    pub entropy: Option<f32>,
    /// reserved for live verification (None = not verified)
    pub verified: Option<bool>,
    /// Whether a grammar qualified this match or it stands on text alone.
    #[serde(default)]
    pub analysis: AnalysisTier,
    /// What the dataflow analysis worked out, phrased as answers to the
    /// falsification gates.
    ///
    /// Suggestions, never decisions: the review form starts from these and a
    /// person submits it. Empty when the analysis had nothing to contribute.
    #[serde(default)]
    pub analysis_gates: Vec<crate::triage::gates::GateNote>,
    /// The finding sits inside a region the language marks as test-only — a
    /// Rust `#[cfg(test)]` module, a JUnit `@Test` method, a `def test_*`.
    ///
    /// Recorded by the scanner because it is the only stage holding the parse
    /// tree; the path classifier consumes it. Separate from `scope` so that
    /// precedence stays in one place: a `#[cfg(test)]` module inside
    /// `node_modules` is still somebody else's code first.
    ///
    /// Not serialized: it is an in-process hand-off, and by the time a finding
    /// reaches the UI or a report the answer has already been folded into
    /// `scope` and `scope_reason`, which say the same thing more usefully.
    #[serde(skip)]
    pub in_test_region: bool,
    #[serde(default)]
    pub observation_run_id: String,
    #[serde(default)]
    pub resolved_by_run_id: Option<String>,
    #[serde(default)]
    pub fingerprint_version: u16,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub scope: Option<crate::findings::domain::FindingScope>,
    #[serde(default)]
    pub scope_reason: Option<String>,
    #[serde(default)]
    pub review: Option<crate::findings::domain::ReviewRecord>,
    #[serde(default)]
    pub review_history: Vec<crate::findings::domain::ReviewRecord>,
    #[serde(default)]
    pub diff_status: Option<crate::findings::domain::DiffStatus>,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub lockfile: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DepScanSummary {
    pub path: String,
    pub lockfiles_found: Vec<String>,
    pub packages_found: usize,
    pub packages_queried: usize,
    pub vulnerabilities_found: usize,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DependencyScanResult {
    pub summary: DepScanSummary,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
#[serde(default, rename_all = "camelCase")]
pub struct AiSettings {
    pub enabled: bool,
    pub base_url: String,
    pub model: String,
    pub temperature: f32,
    pub timeout_secs: u64,
    pub max_tokens: u32,
    #[serde(default = "default_context_window")]
    pub context_window: u32,
    pub system_prompt: String,
}

fn default_context_window() -> u32 {
    128_000
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://api.openai.com/v1".into(),
            model: "gpt-4o-mini".into(),
            temperature: 0.2,
            timeout_secs: 120,
            max_tokens: 2048,
            context_window: default_context_window(),
            system_prompt: DEFAULT_SYSTEM_PROMPT.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct CredentialPresence {
    pub ai_api_key: bool,
    pub nvd_api_key: bool,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum CredentialMutation {
    Unchanged,
    Replace { value: String },
    Delete,
}

impl Drop for CredentialMutation {
    fn drop(&mut self) {
        if let Self::Replace { value } = self {
            zeroize::Zeroize::zeroize(value);
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveSettingsRequest {
    pub settings: AppSettings,
    pub ai_api_key: CredentialMutation,
    pub nvd_api_key: CredentialMutation,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SaveSettingsResult {
    pub settings: AppSettings,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAiRequest {
    pub settings: AiSettings,
    pub ai_api_key: CredentialMutation,
}

pub const DEFAULT_SYSTEM_PROMPT: &str = "You are oxAudit, an expert application security engineer \
and vulnerability researcher embedded in a desktop security tool. You help developers and security \
analysts understand vulnerabilities, exploit details, remediation steps and CVE research. Be precise, \
concrete and actionable. When analyzing code, reference exact lines and suggest specific fixes. \
Never invent CVEs or exploit details you are not confident about — say so when you are uncertain.";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
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
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "target",
        ".next",
        ".nuxt",
        ".output",
        "out",
        "coverage",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "Pods",
        ".gradle",
        ".idea",
        ".vscode",
        ".svn",
        ".hg",
        "bower_components",
        "jspm_packages",
        ".cache",
        ".parcel-cache",
        "env",
        ".env",
        "site-packages",
        "lib64",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default, rename_all = "camelCase")]
pub struct AppSettings {
    pub ai: AiSettings,
    pub scan: ScanSettings,
    pub credentials: CredentialPresence,
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
    /// Extra hosts the assistant's `web_fetch` tool may read from, on top of
    /// the advisory sources in `agent::egress::DEFAULT_ALLOWED_HOSTS`. Entries
    /// may be bare hosts or pasted URLs. Defaulted so settings files written
    /// before the egress policy existed still load.
    #[serde(default)]
    pub agent_allowed_fetch_hosts: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            ai: AiSettings::default(),
            scan: ScanSettings::default(),
            credentials: CredentialPresence::default(),
            theme: "dark".into(),
            binary_scanner_path: None,
            binary_scanner_runtime: None,
            grype_path: None,
            agent_allowed_fetch_hosts: Vec::new(),
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

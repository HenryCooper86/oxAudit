//! The parsed template model. Everything here is plain data; behaviour lives
//! in the protocol modules.

use std::collections::BTreeSet;

use oxaudit_domain::Severity;
use serde::{Deserialize, Serialize};

use crate::dsl::Expr;

/// Protocols the engine can plan and evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Dns,
    Tcp,
    Ssl,
    File,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Dns => "dns",
            Protocol::Tcp => "tcp",
            Protocol::Ssl => "ssl",
            Protocol::File => "file",
        }
    }
}

/// Whether oxAudit can run a template. A template that is not supported is
/// reported as "not evaluated" with the reasons, never as clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reasons", rename_all = "snake_case")]
pub enum Support {
    Supported,
    NotEvaluated(Vec<String>),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Classification {
    pub cve_id: Vec<String>,
    pub cwe_id: Vec<String>,
    pub cvss_metrics: Option<String>,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Info {
    pub name: String,
    pub author: Vec<String>,
    pub severity: Severity,
    /// The template declared a severity oxAudit does not know (`unknown`,
    /// `undefined`, a typo) or none at all; it is reported as `Info`.
    pub severity_unrecognised: bool,
    pub description: String,
    pub reference: Vec<String>,
    /// Lowercase, trimmed, de-duplicated.
    pub tags: Vec<String>,
    pub classification: Classification,
    pub metadata: Vec<(String, serde_json::Value)>,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherKind {
    Status,
    Size,
    Word,
    Regex,
    Binary,
    Dsl,
}

/// A literal (word or binary) pattern. Templated words (`{{Hostname}}`) are
/// compiled per evaluation.
#[derive(Debug, Clone)]
pub struct LiteralPattern {
    pub text: String,
    pub bytes: Vec<u8>,
    pub templated: bool,
    pub(crate) compiled: Option<regex::bytes::Regex>,
}

#[derive(Debug, Clone)]
pub struct RegexPattern {
    pub source: String,
    pub(crate) compiled: regex::bytes::Regex,
}

#[derive(Debug, Clone)]
pub struct DslSource {
    pub source: String,
    pub expr: Expr,
}

#[derive(Debug, Clone)]
pub struct Matcher {
    pub kind: MatcherKind,
    /// `None` means the protocol's default part.
    pub part: Option<String>,
    pub condition: Condition,
    pub negative: bool,
    pub case_insensitive: bool,
    pub hex_encoded: bool,
    pub match_all: bool,
    pub internal: bool,
    pub name: Option<String>,
    pub words: Vec<LiteralPattern>,
    pub regexes: Vec<RegexPattern>,
    pub binary: Vec<LiteralPattern>,
    pub status: Vec<i64>,
    pub size: Vec<i64>,
    pub dsl: Vec<DslSource>,
}

#[derive(Debug, Clone)]
pub enum ExtractorKind {
    Regex {
        patterns: Vec<RegexPattern>,
        group: usize,
    },
    Kval {
        keys: Vec<String>,
    },
    Dsl {
        exprs: Vec<DslSource>,
    },
}

#[derive(Debug, Clone)]
pub struct Extractor {
    pub kind: ExtractorKind,
    pub name: Option<String>,
    pub part: Option<String>,
    pub internal: bool,
    pub case_insensitive: bool,
}

/// Matchers and extractors of one request block.
#[derive(Debug, Clone)]
pub struct Operators {
    pub matchers_condition: Condition,
    pub matchers: Vec<Matcher>,
    pub extractors: Vec<Extractor>,
}

impl Default for Operators {
    fn default() -> Self {
        Operators {
            matchers_condition: Condition::Or,
            matchers: Vec::new(),
            extractors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttackType {
    #[default]
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

/// Inline payload sets in declaration order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payloads {
    pub attack: AttackType,
    pub sets: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone)]
pub struct HttpBlock {
    pub id: Option<String>,
    pub name: Option<String>,
    pub method: String,
    pub paths: Vec<String>,
    pub raw: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub payloads: Payloads,
    pub redirects: bool,
    pub host_redirects: bool,
    pub max_redirects: u32,
    pub cookie_reuse: bool,
    pub stop_at_first_match: bool,
    pub iterate_all: bool,
    pub req_condition: bool,
    pub skip_variables_check: bool,
    pub disable_path_automerge: bool,
    pub max_size: Option<usize>,
    /// Keep every response of the block so `status_code_1`-style variables
    /// resolve. Set only when some expression references one.
    pub keep_history: bool,
    pub ops: Operators,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsType {
    A,
    Aaaa,
    Cname,
    Ns,
    Mx,
    Txt,
    Soa,
    Ptr,
    Caa,
    Srv,
}

impl DnsType {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::Aaaa => "AAAA",
            DnsType::Cname => "CNAME",
            DnsType::Ns => "NS",
            DnsType::Mx => "MX",
            DnsType::Txt => "TXT",
            DnsType::Soa => "SOA",
            DnsType::Ptr => "PTR",
            DnsType::Caa => "CAA",
            DnsType::Srv => "SRV",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsClass {
    Inet,
    Csnet,
    Chaos,
    Hesiod,
    None,
    Any,
}

#[derive(Debug, Clone)]
pub struct DnsBlock {
    pub id: Option<String>,
    pub name: String,
    pub qtype: DnsType,
    pub class: DnsClass,
    pub recursion: bool,
    pub retries: u32,
    pub payloads: Payloads,
    pub ops: Operators,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInput {
    pub data: Option<String>,
    pub hex: bool,
    pub read: Option<usize>,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TcpBlock {
    pub id: Option<String>,
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub exclude_ports: Option<Vec<u16>>,
    pub inputs: Vec<TcpInput>,
    pub read_size: usize,
    pub read_all: bool,
    pub stop_at_first_match: bool,
    pub payloads: Payloads,
    pub ops: Operators,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TlsVersion {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsVersion::Ssl3 => "sslv3",
            TlsVersion::Tls10 => "tls10",
            TlsVersion::Tls11 => "tls11",
            TlsVersion::Tls12 => "tls12",
            TlsVersion::Tls13 => "tls13",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SslBlock {
    pub id: Option<String>,
    pub address: String,
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
    pub ops: Operators,
}

#[derive(Debug, Clone)]
pub struct FileBlock {
    pub id: Option<String>,
    /// Lowercase, no leading dot. May contain `all`.
    pub extensions: Vec<String>,
    pub denylist: Vec<String>,
    /// `None` means no limit (`max-size: no`).
    pub max_size: Option<u64>,
    pub no_recursive: bool,
    pub archive: bool,
    pub ops: Operators,
}

#[derive(Debug, Clone)]
pub struct Template {
    pub id: String,
    /// Where the template came from (a path or pack entry); informational.
    pub origin: String,
    pub info: Info,
    /// Template-level `variables` and `constants`, in order.
    pub variables: Vec<(String, String)>,
    pub stop_at_first_match: bool,
    pub http: Vec<HttpBlock>,
    pub dns: Vec<DnsBlock>,
    pub tcp: Vec<TcpBlock>,
    pub ssl: Vec<SslBlock>,
    pub file: Vec<FileBlock>,
    pub(crate) support: Support,
}

impl Template {
    pub fn support(&self) -> Support {
        self.support.clone()
    }

    pub fn is_supported(&self) -> bool {
        self.support == Support::Supported
    }

    pub fn tags(&self) -> &[String] {
        &self.info.tags
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.info.tags.iter().any(|t| t == tag)
    }

    pub fn protocols(&self) -> BTreeSet<Protocol> {
        let mut set = BTreeSet::new();
        if !self.http.is_empty() {
            set.insert(Protocol::Http);
        }
        if !self.dns.is_empty() {
            set.insert(Protocol::Dns);
        }
        if !self.tcp.is_empty() {
            set.insert(Protocol::Tcp);
        }
        if !self.ssl.is_empty() {
            set.insert(Protocol::Ssl);
        }
        if !self.file.is_empty() {
            set.insert(Protocol::File);
        }
        set
    }

    /// Carries the `dos` tag: must never run.
    pub fn is_destructive(&self) -> bool {
        self.has_tag("dos")
    }

    /// Carries `intrusive` or `fuzz`: off unless explicitly enabled.
    pub fn is_intrusive(&self) -> bool {
        self.has_tag("intrusive") || self.has_tag("fuzz")
    }
}

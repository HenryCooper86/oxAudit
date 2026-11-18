//! YARA rule compilation and byte scanning for oxAudit, built on YARA-X.
//!
//! This crate is pure: it receives rule text and bytes and returns data. It
//! never walks the filesystem or touches the network. `include` directives are
//! disabled; resolving them is the host's job.
//!
//! Every rule source is compiled on its own so that one broken file does not
//! sink a pack. Sources that do not compile are reported in
//! [`RuleSet::skipped`] rather than silently dropped.

use std::collections::BinaryHeap;
use std::time::Duration;

use oxaudit_domain::Severity;
use serde::Serialize;
use thiserror::Error;

/// Version of the embedded YARA-X engine, recorded as the detector version.
pub const YARA_X_VERSION: &str = yara_x::VERSION;

/// Most string matches kept per rule per scan; the rest are only counted.
pub const MAX_STRING_MATCHES_PER_RULE: usize = 32;
/// Longest excerpt of matched data kept per string match, in bytes.
pub const MAX_EXCERPT_BYTES: usize = 64;

const DEFAULT_MAX_SOURCES: usize = 20_000;
const DEFAULT_MAX_SOURCE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// One YARA source file, compiled under its own namespace.
#[derive(Debug, Clone)]
pub struct RuleSource {
    pub namespace: String,
    /// Pack-relative file path, used in messages only.
    pub origin: String,
    pub text: String,
}

/// Bounds on what [`RuleSet::compile`] accepts.
#[derive(Debug, Clone)]
pub struct CompileLimits {
    pub max_sources: usize,
    pub max_source_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_sources: DEFAULT_MAX_SOURCES,
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

/// A source that did not compile, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedSource {
    pub origin: String,
    /// 1-based line of the first error, when YARA-X reports a location.
    pub line: Option<u32>,
    pub message: String,
}

/// A rule metadata value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum MetaValue {
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
    /// A string that is not valid UTF-8.
    Bytes(Vec<u8>),
}

/// A compiled rule, as listed by [`RuleSet::rules`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub namespace: String,
    pub identifier: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, MetaValue)>,
    pub origin: String,
    pub severity: Severity,
    /// Private rules are never reported as matches.
    pub private: bool,
    pub global: bool,
}

/// Errors from [`RuleSet::compile`]. Individual bad sources are not errors;
/// they land in [`RuleSet::skipped`].
#[derive(Debug, Error)]
pub enum YaraError {
    #[error("no rule sources were given")]
    NoSources,
    #[error("{count} rule sources exceed the limit of {max}")]
    TooManySources { count: usize, max: usize },
    #[error("rule source `{origin}` is {bytes} bytes, over the limit of {max}")]
    SourceTooLarge {
        origin: String,
        bytes: usize,
        max: usize,
    },
    #[error("rule sources total {bytes} bytes, over the limit of {max}")]
    TotalTooLarge { bytes: usize, max: usize },
}

/// Errors from [`FileScanner::scan`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScanError {
    #[error("scan timed out")]
    Timeout,
    #[error("YARA engine error: {0}")]
    Engine(String),
}

/// One string match inside a rule match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: u64,
    /// Up to [`MAX_EXCERPT_BYTES`] bytes of the matched data, lowercase hex.
    pub excerpt_hex: String,
}

/// A rule that matched a scanned buffer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub severity: Severity,
    pub meta: Vec<(String, MetaValue)>,
    /// At most [`MAX_STRING_MATCHES_PER_RULE`], sorted by offset.
    pub strings: Vec<StringMatch>,
    /// String matches beyond the cap, counted but not kept.
    pub strings_truncated: u64,
}

/// Compiled rules. Share it across threads; each thread makes its own
/// [`FileScanner`].
pub struct RuleSet {
    rules: yara_x::Rules,
    infos: Vec<RuleInfo>,
    skipped: Vec<SkippedSource>,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.infos.len())
            .field("skipped", &self.skipped.len())
            .finish()
    }
}

fn new_compiler() -> yara_x::Compiler<'static> {
    let mut compiler = yara_x::Compiler::new();
    // This crate receives text only; it must never read other files.
    compiler.enable_includes(false);
    compiler
}

fn line_of(text: &str, offset: usize) -> u32 {
    let end = offset.min(text.len());
    let newlines = text.as_bytes()[..end]
        .iter()
        .filter(|b| **b == b'\n')
        .count();
    u32::try_from(newlines + 1).unwrap_or(u32::MAX)
}

/// Text between the first pair of backticks, as YARA-X quotes identifiers.
fn backticked(title: &str) -> Option<&str> {
    let start = title.find('`')? + 1;
    let len = title[start..].find('`')?;
    Some(&title[start..start + len])
}

fn describe_error(source: &RuleSource, err: &yara_x::errors::CompileError) -> SkippedSource {
    use yara_x::errors::CompileError as E;
    let first_label = err.labels().next();
    let line = first_label
        .as_ref()
        .map(|l| line_of(&source.text, l.span().start()));
    let message = match err {
        E::UnknownModule(_) => {
            let name = backticked(err.title()).unwrap_or("?");
            format!("module `{name}` is not available in oxAudit")
        }
        E::IncludeNotAllowed(_) => {
            "`include` directives are not supported; inline the included rules".to_string()
        }
        _ => match first_label {
            Some(label) if !label.text().is_empty() => {
                format!("{}: {}", err.title(), label.text())
            }
            _ => err.title().to_string(),
        },
    };
    SkippedSource {
        origin: source.origin.clone(),
        line,
        message,
    }
}

/// Compile one source in a fresh compiler and return its rule identifiers.
/// Nothing from a failing source can leak into the real compiler this way.
fn trial(source: &RuleSource) -> Result<Vec<String>, SkippedSource> {
    let mut compiler = new_compiler();
    add_to(&mut compiler, source)?;
    Ok(compiler
        .build()
        .iter()
        .map(|r| r.identifier().to_string())
        .collect())
}

fn add_to(
    compiler: &mut yara_x::Compiler<'static>,
    source: &RuleSource,
) -> Result<(), SkippedSource> {
    compiler.new_namespace(&source.namespace);
    compiler
        .add_source(yara_x::SourceCode::from(source.text.as_str()).with_origin(&source.origin))
        .map(|_| ())
        .map_err(|e| describe_error(source, &e))
}

fn meta_value(value: yara_x::MetaValue<'_>) -> MetaValue {
    match value {
        yara_x::MetaValue::Integer(i) => MetaValue::Integer(i),
        yara_x::MetaValue::Float(f) => MetaValue::Float(f),
        yara_x::MetaValue::Bool(b) => MetaValue::Bool(b),
        yara_x::MetaValue::String(s) => MetaValue::String(s.to_string()),
        yara_x::MetaValue::Bytes(b) => MetaValue::Bytes(b.to_vec()),
    }
}

fn rule_meta(rule: &yara_x::Rule<'_, '_>) -> Vec<(String, MetaValue)> {
    rule.metadata()
        .map(|(k, v)| (k.to_string(), meta_value(v)))
        .collect()
}

fn rule_tags(rule: &yara_x::Rule<'_, '_>) -> Vec<String> {
    rule.tags().map(|t| t.identifier().to_string()).collect()
}

impl RuleSet {
    /// Compile every source separately. Returns `Err` only for limit
    /// violations or an empty input; sources that fail to compile are listed
    /// in [`skipped`](Self::skipped), and an all-skipped set is `Ok` with no
    /// rules.
    pub fn compile(sources: &[RuleSource], limits: &CompileLimits) -> Result<RuleSet, YaraError> {
        if sources.is_empty() {
            return Err(YaraError::NoSources);
        }
        if sources.len() > limits.max_sources {
            return Err(YaraError::TooManySources {
                count: sources.len(),
                max: limits.max_sources,
            });
        }
        let mut total = 0usize;
        for s in sources {
            if s.text.len() > limits.max_source_bytes {
                return Err(YaraError::SourceTooLarge {
                    origin: s.origin.clone(),
                    bytes: s.text.len(),
                    max: limits.max_source_bytes,
                });
            }
            total = total.saturating_add(s.text.len());
        }
        if total > limits.max_total_bytes {
            return Err(YaraError::TotalTooLarge {
                bytes: total,
                max: limits.max_total_bytes,
            });
        }

        let mut skipped = Vec::new();
        let mut accepted: Vec<&RuleSource> = Vec::new();
        let mut origin_by_ns_rule = std::collections::HashMap::new();
        let mut compiler = new_compiler();
        for source in sources {
            let identifiers = match trial(source) {
                Ok(ids) => ids,
                Err(skip) => {
                    skipped.push(skip);
                    continue;
                }
            };
            match add_to(&mut compiler, source) {
                Ok(()) => {
                    accepted.push(source);
                    for id in identifiers {
                        origin_by_ns_rule
                            .insert((source.namespace.clone(), id), source.origin.clone());
                    }
                }
                Err(skip) => {
                    // Failed only in combination with earlier sources (for
                    // example a duplicate rule name in one namespace). YARA-X
                    // may have kept some of its rules, so rebuild from the
                    // sources already accepted.
                    skipped.push(skip);
                    compiler = new_compiler();
                    for prior in &accepted {
                        // These compiled before and nothing was removed.
                        let _ = add_to(&mut compiler, prior);
                    }
                }
            }
        }

        let rules = compiler.build();

        let mut infos: Vec<RuleInfo> = rules
            .iter()
            .map(|r| {
                let meta = rule_meta(&r);
                let severity = severity_from_meta(&meta);
                let key = (r.namespace().to_string(), r.identifier().to_string());
                RuleInfo {
                    origin: origin_by_ns_rule.get(&key).cloned().unwrap_or_default(),
                    namespace: key.0,
                    identifier: key.1,
                    tags: rule_tags(&r),
                    meta,
                    severity,
                    private: r.is_private(),
                    global: r.is_global(),
                }
            })
            .collect();
        infos.sort_by(|a, b| (&a.namespace, &a.identifier).cmp(&(&b.namespace, &b.identifier)));

        Ok(RuleSet {
            rules,
            infos,
            skipped,
        })
    }

    /// Every compiled rule, private ones included, sorted by namespace then
    /// identifier.
    pub fn rules(&self) -> &[RuleInfo] {
        &self.infos
    }

    /// Sources that did not compile, with the reason.
    pub fn skipped(&self) -> &[SkippedSource] {
        &self.skipped
    }

    /// A scanner for one thread. Reuse it across files.
    pub fn scanner(&self) -> FileScanner<'_> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        // `console.log` must not write to the host's stdout.
        scanner.console_log(|_| {});
        FileScanner { scanner }
    }
}

/// Scans byte buffers against a [`RuleSet`]. Not shared between threads.
pub struct FileScanner<'r> {
    scanner: yara_x::Scanner<'r>,
}

fn map_scan_error(err: yara_x::ScanError) -> ScanError {
    match err {
        yara_x::ScanError::Timeout => ScanError::Timeout,
        other => ScanError::Engine(other.to_string()),
    }
}

impl FileScanner<'_> {
    /// Scan `bytes`. Private rules are evaluated but never reported. Results
    /// are sorted by (namespace, rule).
    ///
    /// YARA-X checks its timeout against a clock that ticks once a second, so
    /// the scan can overrun a sub-second timeout by up to about a second.
    pub fn scan(&mut self, bytes: &[u8], timeout: Duration) -> Result<Vec<RuleMatch>, ScanError> {
        self.scanner.set_timeout(timeout);
        let results = self.scanner.scan(bytes).map_err(map_scan_error)?;
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let meta = rule_meta(&rule);
            let severity = severity_from_meta(&meta);
            let (strings, truncated) = collect_strings(&rule, bytes);
            out.push(RuleMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule_tags(&rule),
                severity,
                meta,
                strings,
                strings_truncated: truncated,
            });
        }
        out.sort_by(|a, b| (&a.namespace, &a.rule).cmp(&(&b.namespace, &b.rule)));
        Ok(out)
    }
}

/// Keep the `MAX_STRING_MATCHES_PER_RULE` earliest matches without holding
/// every match of a hostile buffer in memory.
fn collect_strings(rule: &yara_x::Rule<'_, '_>, bytes: &[u8]) -> (Vec<StringMatch>, u64) {
    // Max-heap on (offset, length, identifier): the root is the match to drop.
    let mut heap: BinaryHeap<(usize, usize, &str)> = BinaryHeap::new();
    let mut total: u64 = 0;
    for pattern in rule.patterns() {
        let ident = pattern.identifier();
        for m in pattern.matches() {
            let range = m.range();
            total += 1;
            heap.push((range.start, range.end.saturating_sub(range.start), ident));
            if heap.len() > MAX_STRING_MATCHES_PER_RULE {
                heap.pop();
            }
        }
    }
    let kept = heap.len() as u64;
    let mut items = heap.into_vec();
    items.sort();
    let strings = items
        .into_iter()
        .map(|(offset, length, ident)| {
            let end = offset.saturating_add(length.min(MAX_EXCERPT_BYTES));
            let slice = bytes.get(offset..end.min(bytes.len())).unwrap_or(&[]);
            StringMatch {
                identifier: ident.to_string(),
                offset: offset as u64,
                length: length as u64,
                excerpt_hex: hex(slice),
            }
        })
        .collect();
    (strings, total - kept)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" => Some(Severity::Info),
        _ => None,
    }
}

/// Severity of a rule from its metadata.
///
/// A `severity` string (key and value case-insensitive) wins. Otherwise an
/// integer `score` maps to >=80 critical, >=60 high, >=40 medium, >=20 low,
/// below that info. With neither, the severity is medium.
pub fn severity_from_meta(meta: &[(String, MetaValue)]) -> Severity {
    for (key, value) in meta {
        if key.eq_ignore_ascii_case("severity") {
            if let MetaValue::String(s) = value {
                if let Some(sev) = parse_severity(s) {
                    return sev;
                }
            }
        }
    }
    for (key, value) in meta {
        if key.eq_ignore_ascii_case("score") {
            if let MetaValue::Integer(n) = value {
                return match *n {
                    80.. => Severity::Critical,
                    60..=79 => Severity::High,
                    40..=59 => Severity::Medium,
                    20..=39 => Severity::Low,
                    _ => Severity::Info,
                };
            }
        }
    }
    Severity::Medium
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn timeout_error_maps() {
        assert_eq!(
            map_scan_error(yara_x::ScanError::Timeout),
            ScanError::Timeout
        );
    }

    #[test]
    fn rule_set_is_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<RuleSet>();
    }
}

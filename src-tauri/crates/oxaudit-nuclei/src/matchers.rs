//! Matchers: building them from YAML and evaluating them against a response.
//!
//! # Response parts
//!
//! [`ResponseParts`] maps part names to values. Each protocol module
//! documents the names it exposes:
//!
//! * http: `body`, `header`, `all_headers`, `status_code`, `content_length`,
//!   `raw`, `response`, `all`, `request`, `host`, `url`, `duration`,
//!   `cookies_from_response`, `headers_from_response`, one variable per
//!   response header (lowercase, `-` -> `_`), and TLS facts when supplied.
//! * dns: `rcode`, `question`, `answer`, `ns`, `extra`, `raw`/`body`/`all`,
//!   `request`, `host`, `type`.
//! * tcp: `data`, `raw`/`body`/`all`, `request`, `host`, `port`, plus one part
//!   per named read.
//! * ssl: the certificate and handshake facts, see `ssl.rs`.
//! * file: `raw`/`all`/`body`/`data`, `path`.

use std::borrow::Cow;

use regex::bytes::{Regex, RegexBuilder};

use crate::dsl::{eval, values_equal, EvalContext, Value, Vars};
use crate::extractors::{build_extractors, run_extractors};
use crate::model::{
    Condition, DslSource, LiteralPattern, Matcher, MatcherKind, Operators, RegexPattern,
};
use crate::support::{clip, parse_dsl, Reasons};
use crate::vars::interpolate_lenient;
use crate::yaml::Yaml;

const MAX_PATTERN_BYTES: usize = 64 * 1024;
const REGEX_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const MAX_SPANS: usize = 200;
const MAX_VALUES: usize = 50;
const MAX_VALUE_CHARS: usize = 200;

/// Compiles a regex over bytes with the engine's size limits.
pub(crate) fn compile_regex(pattern: &str, case_insensitive: bool) -> Result<Regex, String> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err("pattern is longer than 64 KiB".into());
    }
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(8 * 1024 * 1024)
        .build()
        .map_err(|e| e.to_string())
}

/// A regex that matches `bytes` literally.
pub(crate) fn literal_regex(bytes: &[u8], case_insensitive: bool) -> Result<Regex, String> {
    let pattern = match std::str::from_utf8(bytes) {
        Ok(text) => regex::escape(text),
        Err(_) => {
            let mut p = String::from("(?-u:");
            for b in bytes {
                p.push_str(&format!("\\x{b:02X}"));
            }
            p.push(')');
            p
        }
    };
    compile_regex(&pattern, case_insensitive)
}

/// What a response exposes to matchers, extractors and DSL expressions.
#[derive(Debug, Clone)]
pub struct ResponseParts {
    vars: Vars,
    kval: Vec<(String, String)>,
    default_part: &'static str,
    /// Record byte offsets of word/regex/binary matches.
    pub collect_spans: bool,
}

impl ResponseParts {
    pub fn new(default_part: &'static str) -> Self {
        ResponseParts {
            vars: Vars::new(),
            kval: Vec::new(),
            default_part,
            collect_spans: false,
        }
    }

    pub fn set(&mut self, name: &str, value: impl Into<Value>) {
        self.vars.insert(name.to_string(), value.into());
    }

    /// Sets the same value under several names (aliases such as `raw`/`all`).
    pub fn set_all(&mut self, names: &[&str], value: Value) {
        for name in names {
            self.vars.insert((*name).to_string(), value.clone());
        }
    }

    /// Lower-priority variables (target, template, dynamic). Existing parts
    /// win.
    pub fn with_base_vars(mut self, base: &Vars) -> Self {
        for (k, v) in base {
            self.vars.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self
    }

    /// Adds a key/value pair visible to `kval` extractors (headers, cookies).
    pub fn add_kval(&mut self, key: &str, value: &str) {
        self.kval.push((normalise_key(key), value.to_string()));
    }

    pub fn vars(&self) -> &Vars {
        &self.vars
    }

    pub fn vars_mut(&mut self) -> &mut Vars {
        &mut self.vars
    }

    pub fn default_part(&self) -> &'static str {
        self.default_part
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.vars
            .get(name)
            .or_else(|| self.vars.get(&name.to_ascii_lowercase()))
    }

    /// The part a matcher or extractor selects, `None` for the default.
    pub fn part(&self, selected: Option<&str>) -> Option<&Value> {
        self.get(selected.unwrap_or(self.default_part))
    }

    pub fn part_bytes(&self, selected: Option<&str>) -> Option<Cow<'_, [u8]>> {
        self.part(selected).map(Value::to_bytes)
    }

    pub(crate) fn kval(&self, key: &str) -> Option<String> {
        let key = normalise_key(key);
        self.kval
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
            .or_else(|| self.vars.get(&key).map(|v| v.to_text().into_owned()))
    }
}

pub(crate) fn normalise_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

/// A byte range matched inside a part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSpan {
    pub start: usize,
    pub end: usize,
    pub matcher: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchOutcome {
    /// The block's matcher condition held.
    pub matched: bool,
    /// `matched`, and at least one matcher that is not `internal` is among
    /// the ones that matched. Internal matchers gate later requests but do
    /// not produce a result.
    pub reportable: bool,
    /// Names of the matching, non-internal, named matchers.
    pub matcher_names: Vec<String>,
    pub matched_values: Vec<String>,
    pub spans: Vec<MatchSpan>,
    /// Evaluation problems (unknown variable, type error, missing part). A
    /// matcher that errored did not match.
    pub warnings: Vec<String>,
}

// ----------------------------------------------------------------- building

pub(crate) fn build_operators(y: &Yaml, reasons: &mut Reasons) -> Operators {
    let mut ops = Operators::default();
    if let Some(cond) = y.string("matchers-condition") {
        match cond.to_ascii_lowercase().as_str() {
            "and" => ops.matchers_condition = Condition::And,
            "or" | "" => {}
            other => reasons.add(format!("unknown matchers-condition `{other}`")),
        }
    }
    for m in y.maps("matchers") {
        if let Some(matcher) = build_matcher(m, reasons) {
            ops.matchers.push(matcher);
        }
    }
    ops.extractors = build_extractors(y, reasons);
    ops
}

fn parse_condition(y: &Yaml, what: &str, reasons: &mut Reasons) -> Condition {
    match y
        .string("condition")
        .map(|c| c.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("or") => Condition::Or,
        Some("and") => Condition::And,
        Some(other) => {
            reasons.add(format!("unknown condition `{other}` on a {what}"));
            Condition::Or
        }
    }
}

fn build_matcher(y: &Yaml, reasons: &mut Reasons) -> Option<Matcher> {
    let type_name = y.string("type").unwrap_or_default().to_ascii_lowercase();
    let kind = match type_name.as_str() {
        "status" => MatcherKind::Status,
        "size" => MatcherKind::Size,
        "word" => MatcherKind::Word,
        "regex" => MatcherKind::Regex,
        "binary" => MatcherKind::Binary,
        "dsl" => MatcherKind::Dsl,
        "xpath" => {
            reasons.add("uses an xpath matcher");
            return None;
        }
        "" => {
            reasons.add("has a matcher without a type");
            return None;
        }
        other => {
            reasons.add(format!("uses unknown matcher type `{other}`"));
            return None;
        }
    };
    let part = y.string("part").filter(|p| !p.is_empty() && p != "default");
    if let Some(p) = &part {
        if p.to_ascii_lowercase().starts_with("interactsh") {
            reasons.add("matches on an interactsh (out-of-band) part");
        }
    }
    let hex_encoded = match y
        .string("encoding")
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") => false,
        Some("hex") => true,
        Some(other) => {
            reasons.add(format!("uses matcher encoding `{other}`"));
            false
        }
    };
    let case_insensitive = y.boolean("case-insensitive");
    let mut matcher = Matcher {
        kind,
        part,
        condition: parse_condition(y, "matcher", reasons),
        negative: y.boolean("negative"),
        case_insensitive,
        hex_encoded,
        match_all: y.boolean("match-all"),
        internal: y.boolean("internal"),
        name: y.string("name").filter(|n| !n.is_empty()),
        words: Vec::new(),
        regexes: Vec::new(),
        binary: Vec::new(),
        status: Vec::new(),
        size: Vec::new(),
        dsl: Vec::new(),
    };
    match kind {
        MatcherKind::Status => matcher.status = int_list(y, "status"),
        MatcherKind::Size => matcher.size = int_list(y, "size"),
        MatcherKind::Word => {
            for word in y.raw_list("words") {
                if let Some(p) = word_pattern(&word, hex_encoded, case_insensitive, reasons) {
                    matcher.words.push(p);
                }
            }
        }
        MatcherKind::Binary => {
            for item in y.raw_list("binary") {
                match crate::dsl::functions::hex_decode(&item) {
                    Ok(bytes) => match literal_regex(&bytes, false) {
                        Ok(re) => matcher.binary.push(LiteralPattern {
                            text: item,
                            bytes,
                            templated: false,
                            compiled: Some(re),
                        }),
                        Err(e) => reasons.add(format!("binary pattern does not compile: {e}")),
                    },
                    Err(_) => reasons.add(format!(
                        "binary matcher pattern is not valid hex: {}",
                        clip(&item)
                    )),
                }
            }
        }
        MatcherKind::Regex => {
            for pattern in y.raw_list("regex") {
                match compile_regex(&pattern, case_insensitive) {
                    Ok(compiled) => matcher.regexes.push(RegexPattern {
                        source: pattern,
                        compiled,
                    }),
                    Err(e) => reasons.add(format!(
                        "regex does not compile under the Rust regex crate ({e}): {}",
                        clip(&pattern)
                    )),
                }
            }
        }
        MatcherKind::Dsl => {
            for source in y.raw_list("dsl") {
                if let Some(expr) = parse_dsl(&source, reasons) {
                    matcher.dsl.push(DslSource { source, expr });
                }
            }
        }
    }
    Some(matcher)
}

fn int_list(y: &Yaml, key: &str) -> Vec<i64> {
    match y.get(key) {
        Some(Yaml::Seq(items)) => items
            .iter()
            .filter_map(|i| i.scalar_text().and_then(|s| s.trim().parse().ok()))
            .collect(),
        Some(other) => other
            .scalar_text()
            .and_then(|s| s.trim().parse().ok())
            .into_iter()
            .collect(),
        None => Vec::new(),
    }
}

fn word_pattern(
    word: &str,
    hex_encoded: bool,
    case_insensitive: bool,
    reasons: &mut Reasons,
) -> Option<LiteralPattern> {
    let bytes = if hex_encoded {
        match crate::dsl::functions::hex_decode(word) {
            Ok(b) => b,
            Err(_) => {
                reasons.add(format!("hex-encoded word is not valid hex: {}", clip(word)));
                return None;
            }
        }
    } else {
        word.as_bytes().to_vec()
    };
    let templated = !hex_encoded && word.contains("{{");
    if templated {
        // Words are interpolated leniently, but a call to a helper that does
        // not exist is still reported.
        if let Ok(exprs) = crate::vars::expressions_in(word) {
            for e in &exprs {
                crate::support::check_expr(e, reasons);
            }
        }
    }
    let compiled = if templated {
        None
    } else {
        match literal_regex(&bytes, case_insensitive) {
            Ok(re) => Some(re),
            Err(e) => {
                reasons.add(format!("word does not compile as a pattern: {e}"));
                return None;
            }
        }
    };
    Some(LiteralPattern {
        text: word.to_string(),
        bytes,
        templated,
        compiled,
    })
}

// --------------------------------------------------------------- evaluation

struct Single {
    matched: bool,
    values: Vec<String>,
    spans: Vec<(usize, usize)>,
    /// The matcher could not be evaluated; negation must not flip it.
    errored: bool,
}

impl Single {
    fn errored() -> Self {
        Single {
            matched: false,
            values: Vec::new(),
            spans: Vec::new(),
            errored: true,
        }
    }
}

fn lossy(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars().take(MAX_VALUE_CHARS).collect()
}

/// Shared word/regex/binary loop. `find` returns the first match range of
/// pattern `i`, and `all` all of its ranges.
fn match_patterns(
    regexes: &[&Regex],
    haystack: &[u8],
    condition: Condition,
    match_all: bool,
    want_spans: bool,
) -> Single {
    let mut values = Vec::new();
    let mut spans = Vec::new();
    let mut any = false;
    for re in regexes {
        match re.find(haystack) {
            None => {
                if condition == Condition::And {
                    return Single {
                        matched: false,
                        values: Vec::new(),
                        spans: Vec::new(),
                        errored: false,
                    };
                }
            }
            Some(first) => {
                if condition == Condition::Or && any && !match_all {
                    continue;
                }
                any = true;
                values.push(lossy(&haystack[first.start()..first.end()]));
                if want_spans {
                    for m in re.find_iter(haystack).take(MAX_SPANS) {
                        spans.push((m.start(), m.end()));
                    }
                }
            }
        }
    }
    Single {
        matched: any && !regexes.is_empty(),
        values,
        spans,
        errored: false,
    }
}

fn evaluate_one(
    m: &Matcher,
    parts: &ResponseParts,
    ctx: &mut dyn EvalContext,
    warnings: &mut Vec<String>,
) -> Single {
    match m.kind {
        MatcherKind::Status => {
            let Some(value) = parts.get("status_code") else {
                warnings.push("status matcher: no status_code for this protocol".into());
                return Single::errored();
            };
            let matched = m
                .status
                .iter()
                .any(|s| values_equal(value, &Value::Int(*s)));
            Single {
                matched,
                values: Vec::new(),
                spans: Vec::new(),
                errored: false,
            }
        }
        MatcherKind::Size => {
            let Some(bytes) = parts.part_bytes(m.part.as_deref()) else {
                warnings.push(missing_part(m, parts));
                return Single::errored();
            };
            let len = bytes.len() as i64;
            Single {
                matched: m.size.contains(&len),
                values: Vec::new(),
                spans: Vec::new(),
                errored: false,
            }
        }
        MatcherKind::Word | MatcherKind::Binary | MatcherKind::Regex => {
            let Some(bytes) = parts.part_bytes(m.part.as_deref()) else {
                warnings.push(missing_part(m, parts));
                return Single::errored();
            };
            let mut owned: Vec<Regex> = Vec::new();
            let mut refs: Vec<&Regex> = Vec::new();
            match m.kind {
                MatcherKind::Regex => refs.extend(m.regexes.iter().map(|r| &r.compiled)),
                MatcherKind::Binary => {
                    refs.extend(m.binary.iter().filter_map(|b| b.compiled.as_ref()))
                }
                _ => {
                    // Templated words are compiled now; the rest were
                    // compiled at load. Both are collected before borrowing.
                    for w in &m.words {
                        if let Some(re) = &w.compiled {
                            refs.push(re);
                        } else {
                            let text = interpolate_lenient(&w.text, parts.vars(), ctx).bytes;
                            match literal_regex(&text, m.case_insensitive) {
                                Ok(re) => owned.push(re),
                                Err(e) => warnings.push(format!("word could not be compiled: {e}")),
                            }
                        }
                    }
                }
            }
            let mut all: Vec<&Regex> = refs;
            all.extend(owned.iter());
            match_patterns(
                &all,
                &bytes,
                m.condition,
                m.match_all,
                parts.collect_spans && !m.negative,
            )
        }
        MatcherKind::Dsl => {
            let mut results = Vec::new();
            let mut errored = false;
            for d in &m.dsl {
                match eval(&d.expr, parts.vars(), ctx) {
                    Ok(Value::Bool(b)) => results.push(b),
                    Ok(other) => {
                        warnings.push(format!(
                            "dsl `{}` returned {} instead of a bool",
                            clip(&d.source),
                            other.type_name()
                        ));
                        errored = true;
                        results.push(false);
                    }
                    Err(e) => {
                        warnings.push(format!("dsl `{}`: {e}", clip(&d.source)));
                        errored = true;
                        results.push(false);
                    }
                }
            }
            let matched = match m.condition {
                Condition::And => !results.is_empty() && results.iter().all(|b| *b),
                Condition::Or => results.iter().any(|b| *b),
            };
            Single {
                matched,
                values: Vec::new(),
                spans: Vec::new(),
                errored: errored && !matched,
            }
        }
    }
}

fn missing_part(m: &Matcher, parts: &ResponseParts) -> String {
    format!(
        "matcher part `{}` is not available for this response",
        m.part.as_deref().unwrap_or(parts.default_part())
    )
}

/// Evaluates the block's matchers against `parts`.
pub fn evaluate_matchers(
    ops: &Operators,
    parts: &ResponseParts,
    ctx: &mut dyn EvalContext,
) -> MatchOutcome {
    let mut outcome = MatchOutcome::default();
    if ops.matchers.is_empty() {
        return outcome;
    }
    let mut all_true = true;
    let mut any_true = false;
    let mut any_visible = false;
    for m in &ops.matchers {
        let single = evaluate_one(m, parts, ctx, &mut outcome.warnings);
        let matched = if single.errored {
            false
        } else {
            single.matched != m.negative
        };
        if matched {
            any_true = true;
            if !m.internal {
                any_visible = true;
                if let Some(name) = &m.name {
                    if !outcome.matcher_names.contains(name) {
                        outcome.matcher_names.push(name.clone());
                    }
                }
                if !m.negative {
                    for v in single.values {
                        if outcome.matched_values.len() < MAX_VALUES
                            && !outcome.matched_values.contains(&v)
                        {
                            outcome.matched_values.push(v);
                        }
                    }
                    for (start, end) in single.spans {
                        if outcome.spans.len() < MAX_SPANS {
                            outcome.spans.push(MatchSpan {
                                start,
                                end,
                                matcher: m.name.clone(),
                            });
                        }
                    }
                }
            }
        } else {
            all_true = false;
            if ops.matchers_condition == Condition::And {
                break;
            }
        }
    }
    outcome.matched = match ops.matchers_condition {
        Condition::And => all_true,
        Condition::Or => any_true,
    };
    outcome.reportable = outcome.matched && any_visible;
    if !outcome.matched {
        outcome.matcher_names.clear();
        outcome.matched_values.clear();
        outcome.spans.clear();
    }
    outcome
}

/// The result of running a block's extractors and matchers on one response.
#[derive(Debug, Clone, Default)]
pub struct BlockResult {
    /// A result should be reported.
    pub matched: bool,
    /// The matcher condition held even if only internal matchers matched.
    pub gate_passed: bool,
    pub matcher_names: Vec<String>,
    pub matched_values: Vec<String>,
    pub spans: Vec<MatchSpan>,
    /// Non-internal extractor output, only when `matched`.
    pub extracted: Vec<(String, Vec<String>)>,
    /// Internal extractor output, for later requests.
    pub internal: Vec<(String, Vec<String>)>,
    pub warnings: Vec<String>,
}

/// Extractors run first (internal values are visible to the matchers), then
/// matchers. A block with extractors only matches when one extracts a value.
pub fn evaluate_block(
    ops: &Operators,
    parts: &mut ResponseParts,
    ctx: &mut dyn EvalContext,
) -> BlockResult {
    let mut result = BlockResult::default();
    let extracted = run_extractors(ops, parts, ctx);
    result.warnings.extend(extracted.warnings);
    result.internal = extracted.internal;
    if ops.matchers.is_empty() {
        let any = extracted.reported.iter().any(|(_, v)| !v.is_empty());
        result.matched = any;
        result.gate_passed = any;
        if any {
            result.extracted = extracted.reported;
            result.spans = extracted
                .spans
                .into_iter()
                .map(|(start, end, matcher)| MatchSpan {
                    start,
                    end,
                    matcher,
                })
                .collect();
        }
        return result;
    }
    let outcome = evaluate_matchers(ops, parts, ctx);
    result.warnings.extend(outcome.warnings);
    result.gate_passed = outcome.matched;
    result.matched = outcome.reportable;
    if result.matched {
        result.matcher_names = outcome.matcher_names;
        result.matched_values = outcome.matched_values;
        result.spans = outcome.spans;
        result.spans.extend(
            extracted
                .spans
                .into_iter()
                .map(|(start, end, matcher)| MatchSpan {
                    start,
                    end,
                    matcher,
                }),
        );
        result.extracted = extracted.reported;
    }
    result
}

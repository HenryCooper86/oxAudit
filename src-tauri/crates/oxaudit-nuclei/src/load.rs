//! Template loading and support classification.

use std::collections::HashSet;

use oxaudit_domain::Severity;

use crate::model::{Classification, Info, Support, Template};
use crate::support::{clip, Reasons};
use crate::vars::expressions_in;
use crate::yaml::{parse_document, Yaml};

/// Size limits applied while loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLimits {
    /// Maximum template size in bytes (default 1 MiB).
    pub max_bytes: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        LoadLimits {
            max_bytes: 1024 * 1024,
        }
    }
}

/// A template that cannot be loaded at all. Templates that load but cannot
/// run are [`Support::NotEvaluated`] instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    #[error("template is {bytes} bytes, larger than the {max} byte limit")]
    TooLarge { bytes: usize, max: usize },
    #[error("invalid YAML: {0}")]
    Yaml(String),
    #[error("template is not a YAML mapping")]
    NotAMapping,
    #[error("template has no `id`")]
    MissingId,
    #[error("template has no `info.name`")]
    MissingName,
}

/// Top-level keys for protocols and features oxAudit does not run.
const UNSUPPORTED_KEYS: &[(&str, &str)] = &[
    ("headless", "uses the headless protocol"),
    ("code", "uses the code protocol (never executed)"),
    ("javascript", "uses the javascript protocol"),
    ("flow", "uses `flow` orchestration"),
    ("workflows", "is a workflow"),
    ("workflow", "is a workflow"),
    ("websocket", "uses the websocket protocol"),
    ("whois", "uses the whois protocol"),
];

impl Template {
    /// Parses a template. `origin` is recorded for display only.
    pub fn load(yaml: &str, origin: &str, limits: LoadLimits) -> Result<Template, TemplateError> {
        if yaml.len() > limits.max_bytes {
            return Err(TemplateError::TooLarge {
                bytes: yaml.len(),
                max: limits.max_bytes,
            });
        }
        let root = parse_document(yaml).map_err(TemplateError::Yaml)?;
        if root.as_map().is_none() {
            return Err(TemplateError::NotAMapping);
        }
        let id = root
            .string("id")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(TemplateError::MissingId)?;
        let info_y = root.get("info").filter(|i| i.as_map().is_some());
        let name = info_y
            .and_then(|i| i.string("name"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(TemplateError::MissingName)?;
        let info = build_info(info_y, name);

        let mut reasons = Reasons::default();
        for (key, why) in UNSUPPORTED_KEYS {
            if root.has(key) {
                reasons.add(*why);
            }
        }
        if root.boolean("self-contained") {
            reasons.add("is self-contained (supplies its own targets)");
        }

        let mut variables = Vec::new();
        for key in ["constants", "variables"] {
            if let Some(entries) = root.get(key).and_then(Yaml::as_map) {
                for (k, v) in entries {
                    if let Some(text) = v.scalar_text() {
                        variables.push((k.clone(), text));
                    }
                }
            }
        }

        let http_key = ["http", "requests"].into_iter().find(|k| root.has(k));
        let tcp_key = ["tcp", "network"].into_iter().find(|k| root.has(k));
        let http: Vec<_> = http_key
            .map(|k| root.maps(k))
            .unwrap_or_default()
            .into_iter()
            .map(|b| crate::http::build_block(b, &variables, &mut reasons))
            .collect();
        let dns = root
            .maps("dns")
            .into_iter()
            .map(|b| crate::dns::build_block(b, &mut reasons))
            .collect();
        let tcp = tcp_key
            .map(|k| root.maps(k))
            .unwrap_or_default()
            .into_iter()
            .map(|b| crate::tcp::build_block(b, &mut reasons))
            .collect();
        let ssl = root
            .maps("ssl")
            .into_iter()
            .map(|b| crate::ssl::build_block(b, &mut reasons))
            .collect();
        let file = root
            .maps("file")
            .into_iter()
            .map(|b| crate::file::build_block(b, &mut reasons))
            .collect();

        let mut template = Template {
            id,
            origin: origin.to_string(),
            info,
            variables,
            stop_at_first_match: root.boolean("stop-at-first-match"),
            http,
            dns,
            tcp,
            ssl,
            file,
            support: Support::Supported,
        };

        if let Some(entries) = root.as_map() {
            for (key, value) in entries {
                if key != "info" {
                    walk_strings(value, TextKind::Normal, &mut reasons, 0);
                }
            }
        }
        if template.protocols().is_empty() {
            reasons.add("has no supported protocol block (http, dns, tcp, ssl, file)");
        }
        if !reasons.is_empty() {
            template.support = Support::NotEvaluated(reasons.into_vec());
        }
        Ok(template)
    }
}

fn build_info(info: Option<&Yaml>, name: String) -> Info {
    let empty = Yaml::Map(Vec::new());
    let y = info.unwrap_or(&empty);
    let raw_severity = y
        .string("severity")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let (severity, unrecognised) = match raw_severity.as_str() {
        "info" => (Severity::Info, false),
        "low" => (Severity::Low, false),
        "medium" => (Severity::Medium, false),
        "high" => (Severity::High, false),
        "critical" => (Severity::Critical, false),
        _ => (Severity::Info, true),
    };
    let mut seen = HashSet::new();
    let tags = y
        .string_list("tags")
        .into_iter()
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| seen.insert(t.clone()))
        .collect();
    let classification = match y.get("classification") {
        Some(c) => Classification {
            cve_id: c.string_list("cve-id"),
            cwe_id: c.string_list("cwe-id"),
            cvss_metrics: c.string("cvss-metrics"),
            cvss_score: c.float("cvss-score"),
            epss_score: c.float("epss-score"),
            cpe: c.string("cpe"),
        },
        None => Classification::default(),
    };
    let metadata = y
        .get("metadata")
        .and_then(Yaml::as_map)
        .map(|entries| {
            entries
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v, 0)))
                .collect()
        })
        .unwrap_or_default();
    Info {
        name,
        author: y.string_list("author"),
        severity,
        severity_unrecognised: unrecognised,
        description: y.string("description").unwrap_or_default(),
        reference: y.raw_list("reference"),
        tags,
        classification,
        metadata,
        remediation: y.string("remediation").unwrap_or_default(),
    }
}

fn to_json(y: &Yaml, depth: usize) -> serde_json::Value {
    use serde_json::Value as J;
    if depth > 16 {
        return J::Null;
    }
    match y {
        Yaml::Null => J::Null,
        Yaml::Bool(b) => J::Bool(*b),
        Yaml::Int(n) => J::from(*n),
        Yaml::Float(f) => serde_json::Number::from_f64(*f).map_or(J::Null, J::Number),
        Yaml::Str(s) => J::String(s.clone()),
        Yaml::Seq(items) => J::Array(items.iter().map(|i| to_json(i, depth + 1)).collect()),
        Yaml::Map(entries) => J::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v, depth + 1)))
                .collect(),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TextKind {
    Normal,
    /// Regex patterns are never interpolated (Nuclei does not either).
    Regex,
    /// Matcher words and binary patterns: interpolated leniently.
    Words,
    /// A plain DSL expression, checked where the matcher/extractor was built.
    Dsl,
}

/// Looks for out-of-band interaction and for `{{...}}` expressions that cannot
/// be run, in every string outside `info`.
fn walk_strings(y: &Yaml, kind: TextKind, reasons: &mut Reasons, depth: usize) {
    if depth > 64 {
        return;
    }
    match y {
        Yaml::Str(s) => check_string(s, kind, reasons),
        Yaml::Seq(items) => {
            for item in items {
                walk_strings(item, kind, reasons, depth + 1);
            }
        }
        Yaml::Map(entries) => {
            for (key, value) in entries {
                let child = match key.to_ascii_lowercase().as_str() {
                    "regex" => TextKind::Regex,
                    "words" | "binary" => TextKind::Words,
                    "dsl" => TextKind::Dsl,
                    _ => TextKind::Normal,
                };
                walk_strings(value, child, reasons, depth + 1);
            }
        }
        _ => {}
    }
}

fn check_string(s: &str, kind: TextKind, reasons: &mut Reasons) {
    if s.to_ascii_lowercase().contains("interactsh") {
        reasons.add("uses interactsh (out-of-band interaction)");
    }
    match kind {
        TextKind::Regex | TextKind::Dsl => {}
        TextKind::Words => {
            // Already checked leniently when the matcher was built.
        }
        TextKind::Normal => match expressions_in(s) {
            Ok(exprs) => {
                for e in &exprs {
                    crate::support::check_expr(e, reasons);
                }
            }
            Err(e) => reasons.add(format!(
                "has a {{{{...}}}} expression that does not parse ({e}): {}",
                clip(s)
            )),
        },
    }
}

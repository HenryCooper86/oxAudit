//! Extractors: `regex` (with `group`), `kval` and `dsl`.
//!
//! `internal: true` extractors are not reported; their first value becomes a
//! variable for the rest of the template run, and is visible to the block's
//! matchers and to extractors that run after it.

use crate::dsl::{eval, EvalContext, Value};
use crate::matchers::{compile_regex, normalise_key, ResponseParts};
use crate::model::{DslSource, Extractor, ExtractorKind, Operators, RegexPattern};
use crate::support::{clip, parse_dsl, Reasons};
use crate::yaml::Yaml;

const MAX_VALUES_PER_EXTRACTOR: usize = 1000;
const MAX_VALUE_BYTES: usize = 64 * 1024;

pub(crate) fn build_extractors(y: &Yaml, reasons: &mut Reasons) -> Vec<Extractor> {
    let mut out = Vec::new();
    for e in y.maps("extractors") {
        let type_name = e.string("type").unwrap_or_default().to_ascii_lowercase();
        let case_insensitive = e.boolean("case-insensitive");
        let kind = match type_name.as_str() {
            "regex" => {
                let mut patterns = Vec::new();
                for p in e.raw_list("regex") {
                    match compile_regex(&p, case_insensitive) {
                        Ok(compiled) => patterns.push(RegexPattern {
                            source: p,
                            compiled,
                        }),
                        Err(err) => reasons.add(format!(
                            "extractor regex does not compile under the Rust regex crate ({err}): {}",
                            clip(&p)
                        )),
                    }
                }
                let group = e
                    .int("group")
                    .and_then(|g| usize::try_from(g).ok())
                    .unwrap_or(0);
                ExtractorKind::Regex { patterns, group }
            }
            "kval" => ExtractorKind::Kval {
                keys: e.raw_list("kval"),
            },
            "dsl" => {
                let mut exprs = Vec::new();
                for source in e.raw_list("dsl") {
                    if let Some(expr) = parse_dsl(&source, reasons) {
                        exprs.push(DslSource { source, expr });
                    }
                }
                ExtractorKind::Dsl { exprs }
            }
            "json" => {
                reasons.add("uses a json (jq) extractor");
                continue;
            }
            "xpath" => {
                reasons.add("uses an xpath extractor");
                continue;
            }
            "" => {
                reasons.add("has an extractor without a type");
                continue;
            }
            other => {
                reasons.add(format!("uses unknown extractor type `{other}`"));
                continue;
            }
        };
        let part = e.string("part").filter(|p| !p.is_empty() && p != "default");
        if part
            .as_deref()
            .is_some_and(|p| p.to_ascii_lowercase().starts_with("interactsh"))
        {
            reasons.add("extracts from an interactsh (out-of-band) part");
        }
        out.push(Extractor {
            kind,
            name: e.string("name").filter(|n| !n.is_empty()),
            part,
            internal: e.boolean("internal"),
            case_insensitive,
        });
    }
    out
}

#[derive(Debug, Default)]
pub struct Extraction {
    /// Reported values, grouped by extractor name (`""` when unnamed).
    pub reported: Vec<(String, Vec<String>)>,
    /// Internal values by name.
    pub internal: Vec<(String, Vec<String>)>,
    pub warnings: Vec<String>,
    /// Byte ranges of reported regex extractions, when the parts ask for them.
    pub spans: Vec<(usize, usize, Option<String>)>,
}

fn push_group(groups: &mut Vec<(String, Vec<String>)>, name: &str, values: Vec<String>) {
    if let Some((_, existing)) = groups.iter_mut().find(|(n, _)| n == name) {
        for v in values {
            if !existing.contains(&v) {
                existing.push(v);
            }
        }
    } else {
        groups.push((name.to_string(), values));
    }
}

/// Runs every extractor of the block. Internal extractors' first value is
/// stored in `parts` so later extractors and the matchers can use it.
pub fn run_extractors(
    ops: &Operators,
    parts: &mut ResponseParts,
    ctx: &mut dyn EvalContext,
) -> Extraction {
    let mut out = Extraction::default();
    for ex in &ops.extractors {
        let mut values: Vec<String> = Vec::new();
        match &ex.kind {
            ExtractorKind::Regex { patterns, group } => {
                let Some(bytes) = parts.part_bytes(ex.part.as_deref()) else {
                    out.warnings.push(format!(
                        "extractor part `{}` is not available",
                        ex.part.as_deref().unwrap_or(parts.default_part())
                    ));
                    continue;
                };
                'patterns: for p in patterns {
                    for caps in p.compiled.captures_iter(&bytes) {
                        let Some(m) = caps.get(*group) else { continue };
                        let slice = m.as_bytes();
                        let slice = slice.get(..MAX_VALUE_BYTES).unwrap_or(slice);
                        let text = String::from_utf8_lossy(slice).into_owned();
                        if parts.collect_spans && !ex.internal && out.spans.len() < 200 {
                            out.spans.push((m.start(), m.end(), ex.name.clone()));
                        }
                        if !values.contains(&text) {
                            values.push(text);
                        }
                        if values.len() >= MAX_VALUES_PER_EXTRACTOR {
                            break 'patterns;
                        }
                    }
                }
            }
            ExtractorKind::Kval { keys } => {
                for key in keys {
                    match parts.kval(key) {
                        Some(v) => {
                            if !values.contains(&v) {
                                values.push(v);
                            }
                        }
                        None => out
                            .warnings
                            .push(format!("kval key `{}` not present", normalise_key(key))),
                    }
                }
            }
            ExtractorKind::Dsl { exprs } => {
                for d in exprs {
                    match eval(&d.expr, parts.vars(), ctx) {
                        Ok(Value::Null) => {}
                        Ok(v) => {
                            let text = v.to_text().into_owned();
                            if !text.is_empty() && !values.contains(&text) {
                                values.push(text);
                            }
                        }
                        Err(e) => out
                            .warnings
                            .push(format!("dsl extractor `{}`: {e}", clip(&d.source))),
                    }
                }
            }
        }
        let name = ex.name.clone().unwrap_or_default();
        if ex.internal {
            if let (false, Some(first)) = (name.is_empty(), values.first()) {
                parts.set(&name, first.as_str());
            }
            if !values.is_empty() {
                push_group(&mut out.internal, &name, values);
            }
        } else if !values.is_empty() {
            push_group(&mut out.reported, &name, values);
        }
    }
    out
}

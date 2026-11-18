//! `{{expr}}` interpolation and template variables.
//!
//! Nested markers (`generate_jwt(j, "{{alg}}")`) are evaluated innermost
//! first, and each nested result is bound into the enclosing expression as a
//! value, never spliced into its source. Substituted values are never
//! rescanned or parsed, so a response-derived variable that contains `{{...}}`
//! or expression text cannot inject an expression.

use std::collections::BTreeSet;

use crate::dsl::{eval, parse, DslError, EvalContext, Expr, Value, VarLookup, Vars};

/// Upper bound on interpolated output.
pub const MAX_INTERPOLATED_BYTES: usize = 1024 * 1024;
const MAX_NESTED_MARKERS: usize = 16;

/// Result of interpolating one string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Interpolated {
    /// The output. Bytes, because helpers such as `hex_decode` produce
    /// non-UTF-8 data that must reach the wire untouched.
    pub bytes: Vec<u8>,
    /// Plain variables that were not defined. Their `{{name}}` text is left
    /// in `bytes`. A request with unresolved variables is skipped by the
    /// planner (Nuclei does the same).
    pub unresolved: Vec<String>,
}

impl Interpolated {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

struct State<'a> {
    vars: &'a dyn VarLookup,
    ctx: &'a mut dyn EvalContext,
    unresolved: Vec<String>,
    strict: bool,
}

/// Interpolates `text`. An undefined variable is left as written and listed
/// in [`Interpolated::unresolved`]; a malformed or failing expression is an
/// error.
pub fn interpolate_detailed(
    text: &str,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
) -> Result<Interpolated, DslError> {
    run(text, vars, ctx, true)
}

/// Like [`interpolate_detailed`], but an expression that cannot be parsed or
/// evaluated is left as literal text. Used for matcher words, where a
/// response-side `{{ item.name }}` is far more likely than a typo.
pub fn interpolate_lenient(
    text: &str,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
) -> Interpolated {
    run(text, vars, ctx, false).unwrap_or_else(|_| Interpolated {
        bytes: text.as_bytes().to_vec(),
        unresolved: Vec::new(),
    })
}

/// `interpolate(text, &vars, ctx)`: unresolved variables stay as written.
pub fn interpolate(
    text: &str,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
) -> Result<String, DslError> {
    interpolate_detailed(text, vars, ctx).map(|r| r.text())
}

fn run(
    text: &str,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
    strict: bool,
) -> Result<Interpolated, DslError> {
    if !text.contains("{{") {
        return Ok(Interpolated {
            bytes: text.as_bytes().to_vec(),
            unresolved: Vec::new(),
        });
    }
    let mut state = State {
        vars,
        ctx,
        unresolved: Vec::new(),
        strict,
    };
    let bytes = expand(text, &mut state, 0)?;
    let mut seen = BTreeSet::new();
    state.unresolved.retain(|n| seen.insert(n.clone()));
    Ok(Interpolated {
        bytes,
        unresolved: state.unresolved,
    })
}

/// Index of the `}}` that closes a `{{` whose body starts at `start`.
fn find_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut j = start;
    while j + 1 < bytes.len() {
        if bytes[j] == b'{' && bytes[j + 1] == b'{' {
            depth += 1;
            j += 2;
        } else if bytes[j] == b'}' && bytes[j + 1] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(j);
            }
            j += 2;
        } else {
            j += 1;
        }
    }
    None
}

fn expand(text: &str, st: &mut State<'_>, depth: usize) -> Result<Vec<u8>, DslError> {
    if depth > MAX_NESTED_MARKERS {
        return Err(DslError::Limit("interpolation nested too deeply".into()));
    }
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && bytes.get(i + 1) == Some(&b'{') {
            if let Some(end) = find_close(bytes, i + 2) {
                // `{{` and `}}` are ASCII, so these are char boundaries.
                let inner = &text[i + 2..end];
                match expand_marker(inner, st, depth)? {
                    Some(replacement) => out.extend_from_slice(&replacement),
                    None => out.extend_from_slice(&bytes[i..end + 2]),
                }
                if out.len() > MAX_INTERPOLATED_BYTES {
                    return Err(DslError::Limit("interpolated output exceeds 1 MiB".into()));
                }
                i = end + 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Ok(out)
}

/// `Ok(None)` keeps the marker as literal text.
fn expand_marker(
    inner: &str,
    st: &mut State<'_>,
    depth: usize,
) -> Result<Option<Vec<u8>>, DslError> {
    Ok(marker_value(inner, st, depth)?.map(|value| value.to_bytes().into_owned()))
}

/// Prefix of the identifiers that stand in for nested markers while the
/// enclosing expression is parsed.
const NESTED_PLACEHOLDER: &str = "__oxaudit_nested_";

/// Evaluates one marker body. Nested markers are evaluated first, each to a
/// value, and are bound into the enclosing expression as values: a nested
/// marker becomes a placeholder identifier (bound as a variable) or, inside
/// a string literal, is replaced in the parsed literal. A nested value is
/// therefore never parsed as expression source, whatever text it holds.
fn marker_value(inner: &str, st: &mut State<'_>, depth: usize) -> Result<Option<Value>, DslError> {
    if depth > MAX_NESTED_MARKERS {
        return Err(DslError::Limit("interpolation nested too deeply".into()));
    }
    let mut nested = Vars::new();
    let source: String = if inner.contains("{{") {
        let bytes = inner.as_bytes();
        let mut out = String::with_capacity(inner.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' && bytes.get(i + 1) == Some(&b'{') {
                if let Some(end) = find_close(bytes, i + 2) {
                    let before = st.unresolved.len();
                    let value = marker_value(&inner[i + 2..end], st, depth + 1)?;
                    if st.unresolved.len() != before {
                        return Ok(None);
                    }
                    match value {
                        Some(value) => {
                            let name = format!("{NESTED_PLACEHOLDER}{}__", nested.len());
                            out.push_str(&name);
                            nested.insert(name, value);
                        }
                        // A nested marker that is not an expression stays
                        // as the template wrote it.
                        None => out.push_str(&inner[i..end + 2]),
                    }
                    i = end + 2;
                    continue;
                }
            }
            let ch_len = inner[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&inner[i..i + ch_len]);
            i += ch_len;
        }
        out
    } else {
        inner.to_string()
    };
    let source = source.trim();
    if source.is_empty() {
        return Ok(None);
    }
    let mut expr = match parse(source) {
        Ok(e) => e,
        Err(e) if st.strict => return Err(e),
        Err(_) => return Ok(None),
    };
    if !expr.is_dynamic() {
        return Ok(None);
    }
    if !nested.is_empty() {
        bind_nested_literals(&mut expr, &nested);
    }
    let lookup = Nested {
        nested: &nested,
        base: st.vars,
    };
    match eval(&expr, &lookup, st.ctx) {
        Ok(value) => Ok(Some(value)),
        Err(DslError::UnknownVariable(name)) => {
            st.unresolved.push(name);
            Ok(None)
        }
        Err(e) if st.strict => Err(e),
        Err(_) => Ok(None),
    }
}

/// Nested-marker values first, then the caller's variables.
struct Nested<'a> {
    nested: &'a Vars,
    base: &'a dyn VarLookup,
}

impl VarLookup for Nested<'_> {
    fn lookup(&self, name: &str) -> Option<&Value> {
        if name.starts_with(NESTED_PLACEHOLDER) {
            if let Some(value) = self.nested.get(name) {
                return Some(value);
            }
        }
        self.base.lookup(name)
    }
}

/// Replaces placeholders inside parsed string literals with the text of
/// their nested values (`"{{alg}}"` is the literal holding `alg`'s value).
fn bind_nested_literals(expr: &mut Expr, nested: &Vars) {
    match expr {
        Expr::Lit(Value::String(text)) if text.contains(NESTED_PLACEHOLDER) => {
            // One pass, so a value that happens to contain a placeholder
            // name is never substituted again.
            let mut bound = String::with_capacity(text.len());
            let mut rest: &str = text;
            while let Some(at) = rest.find(NESTED_PLACEHOLDER) {
                bound.push_str(&rest[..at]);
                let after = &rest[at..];
                let value = after[NESTED_PLACEHOLDER.len()..]
                    .find("__")
                    .map(|end| &after[..NESTED_PLACEHOLDER.len() + end + 2])
                    .and_then(|name| nested.get(name).map(|value| (name.len(), value)));
                match value {
                    Some((len, value)) => {
                        bound.push_str(&value.to_text());
                        rest = &after[len..];
                    }
                    None => {
                        bound.push_str(&after[..NESTED_PLACEHOLDER.len()]);
                        rest = &after[NESTED_PLACEHOLDER.len()..];
                    }
                }
            }
            bound.push_str(rest);
            *expr = Expr::Lit(Value::from(bound));
        }
        Expr::Lit(_) | Expr::Var(_) => {}
        Expr::Unary(_, e) => bind_nested_literals(e, nested),
        Expr::Binary(_, a, b) => {
            bind_nested_literals(a, nested);
            bind_nested_literals(b, nested);
        }
        Expr::In(a, list) => {
            bind_nested_literals(a, nested);
            list.iter_mut()
                .for_each(|e| bind_nested_literals(e, nested));
        }
        Expr::Call(_, args) => args
            .iter_mut()
            .for_each(|e| bind_nested_literals(e, nested)),
        Expr::Ternary(a, b, c) => {
            bind_nested_literals(a, nested);
            bind_nested_literals(b, nested);
            bind_nested_literals(c, nested);
        }
    }
}

/// Parses every `{{...}}` expression in `text` without evaluating it. Used at
/// load time so unsupported expressions are found before any request is sent.
pub fn expressions_in(text: &str) -> Result<Vec<Expr>, DslError> {
    let mut found = Vec::new();
    scan(text, &mut found, 0)?;
    Ok(found)
}

fn scan(text: &str, found: &mut Vec<Expr>, depth: usize) -> Result<(), DslError> {
    if depth > MAX_NESTED_MARKERS {
        return Err(DslError::Limit("interpolation nested too deeply".into()));
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && bytes.get(i + 1) == Some(&b'{') {
            if let Some(end) = find_close(bytes, i + 2) {
                let inner = &text[i + 2..end];
                let source = if inner.contains("{{") {
                    scan(inner, found, depth + 1)?;
                    flatten_nested(inner)
                } else {
                    inner.to_string()
                };
                if !source.trim().is_empty() {
                    found.push(parse(source.trim())?);
                }
                i = end + 2;
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}

/// Replaces nested markers with a placeholder identifier so the enclosing
/// expression can be parsed on its own.
fn flatten_nested(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && bytes.get(i + 1) == Some(&b'{') {
            if let Some(end) = find_close(bytes, i + 2) {
                out.push_str("__nested__");
                i = end + 2;
                continue;
            }
        }
        let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// Evaluates the template-level `variables` in order, each able to see the
/// ones before it and `base`. An unresolvable variable keeps its literal
/// text (and stays usable in later interpolations as that text).
pub fn resolve_template_variables(
    declared: &[(String, String)],
    base: &Vars,
    ctx: &mut dyn EvalContext,
) -> Vars {
    let mut resolved = Vars::new();
    for (name, raw) in declared {
        let value = {
            let layers = crate::dsl::Scope::new(&[&resolved, base]);
            interpolate_lenient(raw, &layers, ctx).text()
        };
        resolved.insert(name.clone(), Value::from(value));
    }
    resolved
}

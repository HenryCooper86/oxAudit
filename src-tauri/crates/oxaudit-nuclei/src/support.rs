//! Collects the reasons a template cannot be evaluated.

use crate::dsl::{functions, parse, DslError, Expr, Value};

/// Ordered, de-duplicated human-readable reasons.
#[derive(Debug, Default)]
pub(crate) struct Reasons(Vec<String>);

impl Reasons {
    pub fn add(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.0.contains(&reason) {
            self.0.push(reason);
        }
    }

    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Records every call in `expr` that oxAudit cannot run.
pub(crate) fn check_expr(expr: &Expr, reasons: &mut Reasons) {
    expr.walk(&mut |node| {
        let Expr::Call(name, args) = node else {
            return;
        };
        if functions::UNSUPPORTED.contains(&name.as_str()) {
            reasons.add(format!(
                "uses helper function `{name}`, which oxAudit does not implement"
            ));
            return;
        }
        match functions::check_call(name, args.len()) {
            Ok(()) => {}
            Err(DslError::UnknownFunction(_)) => reasons.add(format!(
                "uses unknown helper function `{name}`"
            )),
            Err(e) => reasons.add(format!("calls `{name}` incorrectly: {e}")),
        }
        if name == "generate_jwt" {
            if let Some(Expr::Lit(Value::String(alg))) = args.get(1) {
                let upper = alg.to_ascii_uppercase();
                if !matches!(upper.as_str(), "" | "NONE" | "HS256" | "HS384" | "HS512") {
                    reasons.add(format!(
                        "generate_jwt with algorithm {upper} is not implemented (HS256/HS384/HS512/none only)"
                    ));
                }
            }
        }
    });
}

/// Parses a plain DSL expression (matcher/extractor `dsl` entry) and checks
/// its calls.
pub(crate) fn parse_dsl(source: &str, reasons: &mut Reasons) -> Option<Expr> {
    match parse(source) {
        Ok(expr) => {
            check_expr(&expr, reasons);
            Some(expr)
        }
        Err(e) => {
            reasons.add(format!(
                "DSL expression does not parse ({e}): {}",
                clip(source)
            ));
            None
        }
    }
}

pub(crate) fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push_str("...");
    }
    out
}

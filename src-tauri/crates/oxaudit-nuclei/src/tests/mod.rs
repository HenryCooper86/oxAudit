//! Test fixtures are original templates written for this crate.

mod dsl_tests;
mod hostile_tests;
mod http_tests;
mod load_tests;
mod matcher_tests;
mod protocol_tests;

use crate::dsl::{eval_str, Value, Vars, XorShiftContext};
use crate::{LoadLimits, Support, Template};

pub(crate) fn load(yaml: &str) -> Template {
    Template::load(yaml, "test.yaml", LoadLimits::default())
        .unwrap_or_else(|e| panic!("template failed to load: {e}\n{yaml}"))
}

pub(crate) fn load_supported(yaml: &str) -> Template {
    let t = load(yaml);
    assert_eq!(t.support(), Support::Supported, "{yaml}");
    t
}

pub(crate) fn reasons(yaml: &str) -> Vec<String> {
    match load(yaml).support() {
        Support::NotEvaluated(r) => r,
        Support::Supported => Vec::new(),
    }
}

pub(crate) fn ctx() -> XorShiftContext {
    XorShiftContext::default()
}

pub(crate) fn ev_with(src: &str, vars: &Vars) -> Value {
    eval_str(src, vars, &mut ctx()).unwrap_or_else(|e| panic!("`{src}` failed: {e}"))
}

pub(crate) fn ev(src: &str) -> Value {
    ev_with(src, &Vars::new())
}

pub(crate) fn evs(src: &str) -> String {
    ev(src).to_text().into_owned()
}

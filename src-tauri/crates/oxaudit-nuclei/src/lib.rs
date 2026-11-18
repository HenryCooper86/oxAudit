//! A native, pure implementation of the Nuclei template format.
//!
//! The crate parses templates, classifies what it can run, plans requests and
//! evaluates responses. It performs no I/O and no networking: a host layer
//! sends the planned requests and feeds the responses back.
//!
//! Absence is never proof. A template the crate cannot evaluate is
//! [`Support::NotEvaluated`] with reasons; a request it cannot build is a
//! [`SkipReason`]; neither is a clean result.

/// The crate version, recorded as the detector version of template matches.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod dns;
pub mod dsl;
pub mod extractors;
pub mod file;
pub mod http;
mod http_raw;
mod load;
pub mod matchers;
pub mod model;
pub mod payloads;
pub mod result;
pub mod ssl;
mod support;
pub mod tcp;
pub mod vars;
mod yaml;

pub use dns::{
    dns_truncations, evaluate_dns, plan_dns, DnsQuerySpec, DnsResponseData, DnsTarget, PlannedDns,
};
pub use dsl::{DslError, EvalContext, Value, Vars, XorShiftContext};
pub use file::{evaluate_file, evaluate_file_with, plan_file, FileRuleSpec};
pub use http::{
    HttpRequestSpec, HttpResponseData, HttpRun, HttpTarget, RedirectMode, RedirectPolicy,
    RunLimits, StepOutcome,
};
pub use load::{LoadLimits, TemplateError};
pub use matchers::{
    evaluate_block, evaluate_matchers, BlockResult, MatchOutcome, MatchSpan, ResponseParts,
};
pub use model::{Protocol, Support, Template};
pub use result::{FileLine, SkipReason, TemplateMatch, Truncation};
pub use ssl::{evaluate_ssl, plan_ssl, PlannedSsl, SslProbeSpec, SslResponseData};
pub use tcp::{
    evaluate_tcp, plan_tcp, tcp_truncations, PlannedTcp, TcpResponseData, TcpSessionSpec, TcpStep,
    TcpTarget,
};
pub use vars::{interpolate, interpolate_detailed, Interpolated};

#[cfg(test)]
mod tests;

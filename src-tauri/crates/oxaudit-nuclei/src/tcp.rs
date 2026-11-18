//! TCP (`tcp` / legacy `network`) planning and evaluation.
//!
//! # Response parts
//!
//! `data` (default): the final read from the socket. `raw` / `body` / `all`:
//! everything received, in order. `request`: what was sent. `host`, `port`,
//! and one part per named `read` input. Binary data is exposed as bytes.

use crate::dsl::{eval, functions, parse, DslError, EvalContext, Expr, Value, Vars};
use crate::http::{split_host_port, RunLimits};
use crate::matchers::{build_operators, evaluate_block, ResponseParts};
use crate::model::{Protocol, TcpBlock, TcpInput, Template};
use crate::payloads::{build_payloads, PayloadPlan};
use crate::result::{SkipReason, TemplateMatch, Truncation};
use crate::support::Reasons;
use crate::vars::{interpolate_detailed, interpolate_lenient, resolve_template_variables};
use crate::yaml::Yaml;

/// Ports Nuclei treats as "somebody else's service": a user-supplied port in
/// this list does not override a template's `port`.
const DEFAULT_RESERVED_PORTS: [u16; 6] = [80, 443, 8080, 8443, 8081, 53];
const DEFAULT_READ_SIZE: usize = 1024;
const MAX_READ_SIZE: usize = 16 * 1024 * 1024;

/// A host/port target for TCP and SSL templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpTarget {
    pub host: String,
    pub port: Option<u16>,
}

impl TcpTarget {
    /// Accepts `host`, `host:port`, `tls://host:port` or a URL.
    pub fn parse(input: &str) -> Result<TcpTarget, String> {
        let input = input.trim();
        let rest = input.split_once("://").map_or(input, |(_, r)| r);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err("missing host".into());
        }
        Ok(TcpTarget { host, port })
    }

    pub fn variables(&self) -> Vars {
        let mut vars = Vars::new();
        let bracketed = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let hostname = match self.port {
            Some(p) => format!("{bracketed}:{p}"),
            None => bracketed,
        };
        vars.insert("Hostname".into(), Value::from(hostname));
        vars.insert("Host".into(), Value::from(self.host.clone()));
        vars.insert(
            "Port".into(),
            Value::from(self.port.map(|p| p.to_string()).unwrap_or_default()),
        );
        if self.host.parse::<std::net::IpAddr>().is_err() {
            crate::dns::domain_vars(&self.host, &mut vars);
        }
        vars
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpStep {
    Send(Vec<u8>),
    Read { size: usize, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSessionSpec {
    pub request_index: usize,
    pub host: String,
    pub port: u16,
    /// `tls://` prefix: wrap the connection in TLS.
    pub tls: bool,
    pub steps: Vec<TcpStep>,
    /// Bytes to read at the end (ignored when `read_all`).
    pub read_size: usize,
    /// Read until the peer closes.
    pub read_all: bool,
    pub payload_values: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTcp {
    pub request_index: usize,
    pub spec: Result<TcpSessionSpec, SkipReason>,
}

#[derive(Debug, Clone, Default)]
pub struct TcpResponseData {
    /// Everything sent, in order.
    pub request: Vec<u8>,
    /// The final read.
    pub data: Vec<u8>,
    /// Everything received, in order.
    pub raw: Vec<u8>,
    /// Named reads.
    pub named: Vec<(String, Vec<u8>)>,
}

fn parse_ports(text: &str, reasons: &mut Reasons) -> Vec<u16> {
    text.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.parse::<u16>() {
            Ok(n) => Some(n),
            Err(_) => {
                reasons.add(format!("uses port `{p}`, which is not a number"));
                None
            }
        })
        .collect()
}

pub(crate) fn build_block(y: &Yaml, reasons: &mut Reasons) -> TcpBlock {
    let mut hosts = y.raw_list("host");
    if hosts.is_empty() {
        hosts.push("{{Hostname}}".into());
    }
    let ports = y
        .string("port")
        .map(|p| parse_ports(&p, reasons))
        .unwrap_or_default();
    let exclude_ports = y.string("exclude-ports").map(|p| parse_ports(&p, reasons));
    let mut inputs = Vec::new();
    for input in y.maps("inputs") {
        let hex = match input
            .string("type")
            .map(|t| t.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("text") => false,
            Some("hex") => true,
            Some(other) => {
                reasons.add(format!("uses network input type `{other}`"));
                false
            }
        };
        let read = input
            .int("read")
            .or_else(|| input.int("read-size"))
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .map(|n| n.min(MAX_READ_SIZE));
        inputs.push(TcpInput {
            data: input.string("data"),
            hex,
            read,
            name: input.string("name").filter(|n| !n.is_empty()),
        });
    }
    TcpBlock {
        id: y.string("id"),
        hosts,
        ports,
        exclude_ports,
        inputs,
        read_size: y
            .int("read-size")
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .map_or(DEFAULT_READ_SIZE, |n| n.min(MAX_READ_SIZE)),
        read_all: y.boolean("read-all"),
        stop_at_first_match: y.boolean("stop-at-first-match"),
        payloads: build_payloads(y, reasons),
        ops: build_operators(y, reasons),
    }
}

fn scope_for(template: &Template, target: &TcpTarget, ctx: &mut dyn EvalContext) -> Vars {
    let mut base = target.variables();
    let declared = resolve_template_variables(&template.variables, &base, ctx);
    base.extend(declared);
    base
}

fn skip_from(e: DslError) -> SkipReason {
    match e {
        DslError::Unsupported(m) => SkipReason::Unsupported(m),
        other => SkipReason::Expression(other.to_string()),
    }
}

fn render_input(
    input: &TcpInput,
    scope: &Vars,
    ctx: &mut dyn EvalContext,
) -> Result<Vec<u8>, SkipReason> {
    let Some(data) = &input.data else {
        return Ok(Vec::new());
    };
    // Nuclei documents `data: hex_decode('...')` without braces.
    if !data.contains("{{") {
        if let Ok(expr @ Expr::Call(..)) = parse(data.trim()) {
            if expr
                .functions()
                .iter()
                .all(|f| functions::is_implemented(f))
            {
                let value = eval(&expr, scope, ctx).map_err(skip_from)?;
                let bytes = value.to_bytes().into_owned();
                return if input.hex { hex(&bytes) } else { Ok(bytes) };
            }
        }
    }
    let out = interpolate_detailed(data, scope, ctx).map_err(skip_from)?;
    if !out.unresolved.is_empty() {
        return Err(SkipReason::UnresolvedVariable(out.unresolved));
    }
    if input.hex {
        hex(&out.bytes)
    } else {
        Ok(out.bytes)
    }
}

fn hex(bytes: &[u8]) -> Result<Vec<u8>, SkipReason> {
    functions::hex_decode(&String::from_utf8_lossy(bytes))
        .map_err(|_| SkipReason::Malformed("input of type hex is not valid hex".into()))
}

/// Every TCP session the template wants against `target`.
pub fn plan_tcp(
    template: &Template,
    target: &TcpTarget,
    ctx: &mut dyn EvalContext,
    limits: &RunLimits,
) -> Vec<PlannedTcp> {
    let base = scope_for(template, target, ctx);
    let mut out = Vec::new();
    for (index, block) in template.tcp.iter().enumerate() {
        let plan = PayloadPlan::new(&block.payloads, limits.max_payload_combinations);
        for combo in 0..plan.total() {
            let mut scope = base.clone();
            let mut payload_values = Vec::new();
            for (k, v) in plan.combination(combo) {
                let text = interpolate_lenient(&v, &base, ctx).text();
                scope.insert(k.clone(), Value::from(text.clone()));
                payload_values.push((k, text));
            }
            for host_template in &block.hosts {
                let mut push = |spec: Result<TcpSessionSpec, SkipReason>| {
                    out.push(PlannedTcp {
                        request_index: index,
                        spec,
                    });
                };
                let address = match interpolate_detailed(host_template, &scope, ctx) {
                    Ok(a) if a.unresolved.is_empty() => a.text(),
                    Ok(a) => {
                        push(Err(SkipReason::UnresolvedVariable(a.unresolved)));
                        continue;
                    }
                    Err(e) => {
                        push(Err(skip_from(e)));
                        continue;
                    }
                };
                let (tls, address) = match address.strip_prefix("tls://") {
                    Some(rest) => (true, rest.to_string()),
                    None => (false, address),
                };
                let (host, written_port) = match split_host_port(&address) {
                    Ok(hp) => hp,
                    Err(e) => {
                        push(Err(SkipReason::Malformed(format!("host `{address}`: {e}"))));
                        continue;
                    }
                };
                let ports: Vec<u16> = if block.ports.is_empty() {
                    match written_port.or(target.port) {
                        Some(p) => vec![p],
                        None => {
                            push(Err(SkipReason::Malformed(
                                "no port in the template or the target".into(),
                            )));
                            continue;
                        }
                    }
                } else {
                    let reserved: &[u16] = block
                        .exclude_ports
                        .as_deref()
                        .unwrap_or(&DEFAULT_RESERVED_PORTS);
                    match target.port.filter(|p| !reserved.contains(p)) {
                        Some(p) => vec![p],
                        None => block.ports.clone(),
                    }
                };
                for port in ports {
                    let mut steps = Vec::new();
                    let mut failed: Option<SkipReason> = None;
                    for input in &block.inputs {
                        match render_input(input, &scope, ctx) {
                            Ok(bytes) => {
                                if input.data.is_some() {
                                    steps.push(TcpStep::Send(bytes));
                                }
                            }
                            Err(e) => {
                                failed = Some(e);
                                break;
                            }
                        }
                        if let Some(size) = input.read {
                            steps.push(TcpStep::Read {
                                size,
                                name: input.name.clone(),
                            });
                        }
                    }
                    push(match failed {
                        Some(e) => Err(e),
                        None => Ok(TcpSessionSpec {
                            request_index: index,
                            host: host.clone(),
                            port,
                            tls,
                            steps,
                            read_size: block.read_size,
                            read_all: block.read_all,
                            payload_values: payload_values.clone(),
                        }),
                    });
                }
            }
        }
    }
    out
}

/// The planner caps [`plan_tcp`] applies to `template` under `limits`: one
/// entry per TCP block whose payload combinations were cut short.
pub fn tcp_truncations(template: &Template, limits: &RunLimits) -> Vec<Truncation> {
    template
        .tcp
        .iter()
        .enumerate()
        .filter_map(|(index, block)| {
            PayloadPlan::new(&block.payloads, limits.max_payload_combinations)
                .truncation(Protocol::Tcp, index)
        })
        .collect()
}

fn bytes_value(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) => Value::str(s),
        Err(_) => Value::Bytes(bytes.to_vec()),
    }
}

/// Evaluates what a session collected.
pub fn evaluate_tcp(
    template: &Template,
    spec: &TcpSessionSpec,
    target: &TcpTarget,
    resp: &TcpResponseData,
    ctx: &mut dyn EvalContext,
) -> Option<TemplateMatch> {
    let block = template.tcp.get(spec.request_index)?;
    let mut scope = scope_for(template, target, ctx);
    for (k, v) in &spec.payload_values {
        scope.insert(k.clone(), Value::from(v.clone()));
    }
    let mut parts = ResponseParts::new("data");
    parts.set("data", bytes_value(&resp.data));
    parts.set_all(&["raw", "body", "all"], bytes_value(&resp.raw));
    parts.set("request", bytes_value(&resp.request));
    parts.set("host", spec.host.as_str());
    parts.set("port", Value::Int(i64::from(spec.port)));
    for (name, bytes) in &resp.named {
        parts.set(name, bytes_value(bytes));
    }
    let mut parts = parts.with_base_vars(&scope);
    let result = evaluate_block(&block.ops, &mut parts, ctx);
    if !result.matched {
        return None;
    }
    Some(TemplateMatch {
        template_id: template.id.clone(),
        name: template.info.name.clone(),
        severity: template.info.severity,
        matcher_names: result.matcher_names,
        extracted: result.extracted,
        protocol: Protocol::Tcp,
        request_index: spec.request_index,
        matched_at: format!("{}:{}", spec.host, spec.port),
        lines: Vec::new(),
        matched_values: result.matched_values,
        warnings: result.warnings,
    })
}

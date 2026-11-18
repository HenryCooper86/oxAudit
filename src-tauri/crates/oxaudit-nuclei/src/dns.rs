//! DNS planning and evaluation.
//!
//! # Response parts
//!
//! `rcode` (e.g. `NOERROR`), `question`, `answer`, `ns` (authority), `extra`
//! (additional), `raw` / `body` / `all` (default, the whole message as text),
//! `request`, `host`, `type`, plus target variables. Record lines use the
//! `name<TAB>ttl<TAB>IN<TAB>TYPE<TAB>data` layout of Go's DNS library, so
//! `"IN\tCNAME"` works as a word.

use crate::dsl::{DslError, EvalContext, Value, Vars};
use crate::http::RunLimits;
use crate::matchers::{build_operators, evaluate_block, ResponseParts};
use crate::model::{DnsBlock, DnsClass, DnsType, Protocol, Template};
use crate::payloads::{build_payloads, PayloadPlan};
use crate::result::{SkipReason, TemplateMatch};
use crate::support::Reasons;
use crate::vars::{interpolate_detailed, interpolate_lenient, resolve_template_variables};
use crate::yaml::Yaml;

/// Adds `FQDN`, `RDN`, `DN`, `TLD` and `SD` for a host name. The registrable
/// domain is taken as the last two labels; there is no public-suffix list, so
/// `a.example.co.uk` gets `RDN` `co.uk`.
pub(crate) fn domain_vars(host: &str, vars: &mut Vars) {
    let fqdn = host.trim_end_matches('.');
    let labels: Vec<&str> = fqdn.split('.').filter(|l| !l.is_empty()).collect();
    let tld = labels.last().copied().unwrap_or_default();
    let (rdn, dn, sd) = if labels.len() >= 2 {
        let n = labels.len();
        (
            labels[n - 2..].join("."),
            labels[n - 2].to_string(),
            labels[..n - 2].join("."),
        )
    } else {
        (fqdn.to_string(), fqdn.to_string(), String::new())
    };
    vars.insert("FQDN".into(), Value::from(fqdn.to_string()));
    vars.insert("RDN".into(), Value::from(rdn));
    vars.insert("DN".into(), Value::from(dn));
    vars.insert("TLD".into(), Value::from(tld.to_string()));
    vars.insert("SD".into(), Value::from(sd));
}

/// A DNS target: a fully qualified name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTarget {
    pub fqdn: String,
}

impl DnsTarget {
    /// Accepts a bare name, `host:port` or a URL; keeps only the host.
    pub fn parse(input: &str) -> Result<DnsTarget, String> {
        let input = input.trim();
        let rest = input.split_once("://").map_or(input, |(_, r)| r);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        let (host, _) = crate::http::split_host_port(authority)?;
        let fqdn = host.trim_end_matches('.').to_string();
        if fqdn.is_empty() {
            return Err("empty target".into());
        }
        Ok(DnsTarget { fqdn })
    }

    pub fn variables(&self) -> Vars {
        let mut vars = Vars::new();
        domain_vars(&self.fqdn, &mut vars);
        vars.insert("Host".into(), Value::from(self.fqdn.clone()));
        vars.insert("Hostname".into(), Value::from(self.fqdn.clone()));
        vars
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuerySpec {
    pub name: String,
    pub qtype: DnsType,
    pub class: DnsClass,
    pub recursion: bool,
    pub retries: u32,
    pub request_index: usize,
    pub payload_values: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedDns {
    pub request_index: usize,
    pub spec: Result<DnsQuerySpec, SkipReason>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsResponseData {
    pub rcode: String,
    pub question: String,
    pub answers: Vec<String>,
    pub authority: Vec<String>,
    pub additional: Vec<String>,
    /// The whole message as text, as `dig` would print it.
    pub raw: String,
}

pub(crate) fn build_block(y: &Yaml, reasons: &mut Reasons) -> DnsBlock {
    let qtype = match y
        .string("type")
        .map(|t| t.trim().to_ascii_uppercase())
        .as_deref()
    {
        None | Some("") | Some("A") => DnsType::A,
        Some("AAAA") => DnsType::Aaaa,
        Some("CNAME") => DnsType::Cname,
        Some("NS") => DnsType::Ns,
        Some("MX") => DnsType::Mx,
        Some("TXT") => DnsType::Txt,
        Some("SOA") => DnsType::Soa,
        Some("PTR") => DnsType::Ptr,
        Some("CAA") => DnsType::Caa,
        Some("SRV") => DnsType::Srv,
        Some(other) => {
            reasons.add(format!(
                "uses DNS record type {other}, which is not supported"
            ));
            DnsType::A
        }
    };
    let class = match y
        .string("class")
        .map(|c| c.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("inet") => DnsClass::Inet,
        Some("csnet") => DnsClass::Csnet,
        Some("chaos") => DnsClass::Chaos,
        Some("hesiod") => DnsClass::Hesiod,
        Some("none") => DnsClass::None,
        Some("any") => DnsClass::Any,
        Some(other) => {
            reasons.add(format!("uses unknown DNS class `{other}`"));
            DnsClass::Inet
        }
    };
    if y.boolean("trace") {
        reasons.add("uses DNS trace");
    }
    let recursion = match y.get("recursion") {
        Some(Yaml::Bool(b)) => *b,
        _ => true,
    };
    DnsBlock {
        id: y.string("id"),
        name: y.string("name").unwrap_or_else(|| "{{FQDN}}".into()),
        qtype,
        class,
        recursion,
        retries: y
            .int("retries")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(3)
            .min(10),
        payloads: build_payloads(y, reasons),
        ops: build_operators(y, reasons),
    }
}

fn scope_for(template: &Template, target: &DnsTarget, ctx: &mut dyn EvalContext) -> Vars {
    let mut base = target.variables();
    let declared = resolve_template_variables(&template.variables, &base, ctx);
    base.extend(declared);
    base
}

/// Every DNS question the template asks of `target`.
pub fn plan_dns(
    template: &Template,
    target: &DnsTarget,
    ctx: &mut dyn EvalContext,
    limits: &RunLimits,
) -> Vec<PlannedDns> {
    let base = scope_for(template, target, ctx);
    let mut out = Vec::new();
    for (index, block) in template.dns.iter().enumerate() {
        let plan = PayloadPlan::new(&block.payloads, limits.max_payload_combinations);
        for combo in 0..plan.total() {
            let pairs = plan.combination(combo);
            let mut scope = base.clone();
            let mut payload_values = Vec::new();
            for (k, v) in pairs {
                let text = interpolate_lenient(&v, &base, ctx).text();
                scope.insert(k.clone(), Value::from(text.clone()));
                payload_values.push((k, text));
            }
            let spec = match interpolate_detailed(&block.name, &scope, ctx) {
                Ok(name) if !name.unresolved.is_empty() => {
                    Err(SkipReason::UnresolvedVariable(name.unresolved))
                }
                Ok(name) => Ok(DnsQuerySpec {
                    name: name.text(),
                    qtype: block.qtype,
                    class: block.class,
                    recursion: block.recursion,
                    retries: block.retries,
                    request_index: index,
                    payload_values,
                }),
                Err(DslError::Unsupported(m)) => Err(SkipReason::Unsupported(m)),
                Err(e) => Err(SkipReason::Expression(e.to_string())),
            };
            out.push(PlannedDns {
                request_index: index,
                spec,
            });
        }
    }
    out
}

/// Evaluates one DNS response against the block that produced `spec`.
pub fn evaluate_dns(
    template: &Template,
    spec: &DnsQuerySpec,
    target: &DnsTarget,
    resp: &DnsResponseData,
    ctx: &mut dyn EvalContext,
) -> Option<TemplateMatch> {
    let block = template.dns.get(spec.request_index)?;
    let mut scope = scope_for(template, target, ctx);
    for (k, v) in &spec.payload_values {
        scope.insert(k.clone(), Value::from(v.clone()));
    }
    let mut parts = ResponseParts::new("raw");
    parts.set("rcode", resp.rcode.as_str());
    parts.set("question", resp.question.as_str());
    parts.set("answer", resp.answers.join("\n"));
    parts.set("ns", resp.authority.join("\n"));
    parts.set("extra", resp.additional.join("\n"));
    parts.set_all(&["raw", "body", "all"], Value::from(resp.raw.clone()));
    parts.set(
        "request",
        format!("{}\tIN\t{}", spec.name, spec.qtype.as_str()),
    );
    parts.set("host", target.fqdn.as_str());
    parts.set("type", spec.qtype.as_str());
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
        protocol: Protocol::Dns,
        request_index: spec.request_index,
        matched_at: spec.name.clone(),
        lines: Vec::new(),
        matched_values: result.matched_values,
        warnings: result.warnings,
    })
}

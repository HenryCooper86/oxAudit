//! SSL/TLS handshake planning and evaluation.
//!
//! # Response parts
//!
//! `response` (default, JSON of every field below), `host`, `ip`, `port`,
//! `sni`, `tls_version`, `tls_connection`, `cipher`, `key_exchange`,
//! `probe_status`, `subject_cn`, `subject_dn`, `subject_org`, `subject_an`,
//! `issuer_cn`, `issuer_dn`, `issuer_org`, `serial`, `not_before`,
//! `not_after` (Unix seconds), `fingerprint_hash` (lines `md5:...`,
//! `sha1:...`, `sha256:...`), `expired`, `self_signed`, `mismatched`,
//! `wildcard_certificate`, `domains`, `emails`.
//!
//! List-valued fields (`subject_an`, `subject_org`, `issuer_org`, `domains`,
//! `emails`) are exposed as one comma-joined string.
//! `expired`, `mismatched`, `wildcard_certificate` and `domains` are computed
//! here from the certificate facts; `self_signed` is supplied by the host.

use crate::dsl::{DslError, EvalContext, Value, Vars};
use crate::http::split_host_port;
use crate::matchers::{build_operators, evaluate_block, ResponseParts};
use crate::model::{Protocol, SslBlock, Template, TlsVersion};
use crate::result::{SkipReason, TemplateMatch};
use crate::support::Reasons;
use crate::tcp::TcpTarget;
use crate::vars::{interpolate_detailed, resolve_template_variables};
use crate::yaml::Yaml;

/// A handshake for the host to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslProbeSpec {
    pub request_index: usize,
    pub host: String,
    pub port: u16,
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedSsl {
    pub request_index: usize,
    pub spec: Result<SslProbeSpec, SkipReason>,
}

/// What the handshake revealed. Timestamps are Unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SslResponseData {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub sni: String,
    /// e.g. `tls13`.
    pub tls_version: String,
    pub cipher: String,
    pub key_exchange: String,
    pub tls_connection: String,
    pub probe_status: bool,
    pub subject_cn: String,
    pub subject_dn: String,
    pub subject_org: Vec<String>,
    pub subject_an: Vec<String>,
    pub issuer_cn: String,
    pub issuer_dn: String,
    pub issuer_org: Vec<String>,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint_md5: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    pub self_signed: bool,
    pub emails: Vec<String>,
}

fn version_of(text: &str, reasons: &mut Reasons) -> Option<TlsVersion> {
    match text.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "sslv3" => Some(TlsVersion::Ssl3),
        "tls10" => Some(TlsVersion::Tls10),
        "tls11" => Some(TlsVersion::Tls11),
        "tls12" => Some(TlsVersion::Tls12),
        "tls13" => Some(TlsVersion::Tls13),
        other => {
            reasons.add(format!("uses unknown TLS version `{other}`"));
            None
        }
    }
}

pub(crate) fn build_block(y: &Yaml, reasons: &mut Reasons) -> SslBlock {
    if y.boolean("tls_version_enum") {
        reasons.add("enumerates TLS versions (tls_version_enum)");
    }
    if y.boolean("tls_cipher_enum") {
        reasons.add("enumerates TLS ciphers (tls_cipher_enum)");
    }
    if y.has("tls_cipher_types") {
        reasons.add("selects TLS cipher types (tls_cipher_types)");
    }
    if !y.raw_list("cipher_suites").is_empty() {
        reasons.add("restricts TLS cipher suites (cipher_suites)");
    }
    if let Some(mode) = y.string("scan_mode") {
        if !matches!(mode.to_ascii_lowercase().as_str(), "" | "auto" | "ctls") {
            reasons.add(format!("uses SSL scan_mode `{mode}`"));
        }
    }
    SslBlock {
        id: y.string("id"),
        address: y.string("address").unwrap_or_else(|| "{{Hostname}}".into()),
        min_version: y
            .string("min_version")
            .and_then(|v| version_of(&v, reasons)),
        max_version: y
            .string("max_version")
            .and_then(|v| version_of(&v, reasons)),
        ops: build_operators(y, reasons),
    }
}

fn scope_for(template: &Template, target: &TcpTarget, ctx: &mut dyn EvalContext) -> Vars {
    let mut base = target.variables();
    let declared = resolve_template_variables(&template.variables, &base, ctx);
    base.extend(declared);
    base
}

/// Every handshake the template wants against `target`. The port defaults to
/// the target's, then 443.
pub fn plan_ssl(
    template: &Template,
    target: &TcpTarget,
    ctx: &mut dyn EvalContext,
) -> Vec<PlannedSsl> {
    let mut scope = scope_for(template, target, ctx);
    if target.port.is_none() {
        scope.insert("Port".into(), Value::from("443"));
    }
    template
        .ssl
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let spec = (|| {
                let rendered =
                    interpolate_detailed(&block.address, &scope, ctx).map_err(|e| match e {
                        DslError::Unsupported(m) => SkipReason::Unsupported(m),
                        other => SkipReason::Expression(other.to_string()),
                    })?;
                if !rendered.unresolved.is_empty() {
                    return Err(SkipReason::UnresolvedVariable(rendered.unresolved));
                }
                let address = rendered.text();
                let address = address
                    .strip_prefix("tls://")
                    .unwrap_or(&address)
                    .to_string();
                let (host, port) = split_host_port(&address)
                    .map_err(|e| SkipReason::Malformed(format!("address `{address}`: {e}")))?;
                Ok(SslProbeSpec {
                    request_index: index,
                    host,
                    port: port.or(target.port).unwrap_or(443),
                    min_version: block.min_version,
                    max_version: block.max_version,
                })
            })();
            PlannedSsl {
                request_index: index,
                spec,
            }
        })
        .collect()
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => pattern == host,
    }
}

impl SslResponseData {
    /// Subject CN plus SANs, de-duplicated, in that order.
    pub fn domains(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for name in std::iter::once(&self.subject_cn).chain(&self.subject_an) {
            if !name.is_empty() && !out.contains(name) {
                out.push(name.clone());
            }
        }
        out
    }

    /// The certificate does not cover the SNI (or the host when there is
    /// none).
    pub fn mismatched(&self) -> bool {
        let wanted = if self.sni.is_empty() {
            &self.host
        } else {
            &self.sni
        };
        if wanted.is_empty() {
            return false;
        }
        !self.domains().iter().any(|d| name_matches(d, wanted))
    }

    pub fn expired(&self, now: i64) -> bool {
        self.not_after != 0 && self.not_after < now
    }

    pub fn wildcard(&self) -> bool {
        self.domains().iter().any(|d| d.starts_with("*."))
    }
}

/// Adds the certificate parts to `parts`. `now` is Unix seconds.
pub(crate) fn insert_cert_parts(parts: &mut ResponseParts, d: &SslResponseData, now: i64) {
    let join = |v: &[String]| Value::from(v.join(","));
    parts.set("ip", d.ip.as_str());
    parts.set("sni", d.sni.as_str());
    parts.set("tls_version", d.tls_version.as_str());
    parts.set("tls_connection", d.tls_connection.as_str());
    parts.set("cipher", d.cipher.as_str());
    parts.set("key_exchange", d.key_exchange.as_str());
    parts.set("probe_status", Value::Bool(d.probe_status));
    parts.set("subject_cn", d.subject_cn.as_str());
    parts.set("subject_dn", d.subject_dn.as_str());
    parts.set("subject_org", join(&d.subject_org));
    parts.set("subject_an", join(&d.subject_an));
    parts.set("issuer_cn", d.issuer_cn.as_str());
    parts.set("issuer_dn", d.issuer_dn.as_str());
    parts.set("issuer_org", join(&d.issuer_org));
    parts.set("serial", d.serial.as_str());
    parts.set("not_before", Value::Int(d.not_before));
    parts.set("not_after", Value::Int(d.not_after));
    parts.set(
        "fingerprint_hash",
        format!(
            "md5:{}\nsha1:{}\nsha256:{}",
            d.fingerprint_md5, d.fingerprint_sha1, d.fingerprint_sha256
        ),
    );
    parts.set("expired", Value::Bool(d.expired(now)));
    parts.set("self_signed", Value::Bool(d.self_signed));
    parts.set("mismatched", Value::Bool(d.mismatched()));
    parts.set("wildcard_certificate", Value::Bool(d.wildcard()));
    parts.set("domains", join(&d.domains()));
    parts.set("emails", join(&d.emails));
}

fn to_json(d: &SslResponseData, now: i64) -> String {
    serde_json::json!({
        "host": d.host, "ip": d.ip, "port": d.port, "sni": d.sni,
        "tls_version": d.tls_version, "cipher": d.cipher,
        "key_exchange": d.key_exchange, "tls_connection": d.tls_connection,
        "probe_status": d.probe_status,
        "subject_cn": d.subject_cn, "subject_dn": d.subject_dn,
        "subject_org": d.subject_org, "subject_an": d.subject_an,
        "issuer_cn": d.issuer_cn, "issuer_dn": d.issuer_dn, "issuer_org": d.issuer_org,
        "serial": d.serial, "not_before": d.not_before, "not_after": d.not_after,
        "fingerprint_md5": d.fingerprint_md5, "fingerprint_sha1": d.fingerprint_sha1,
        "fingerprint_sha256": d.fingerprint_sha256,
        "expired": d.expired(now), "self_signed": d.self_signed,
        "mismatched": d.mismatched(), "wildcard_certificate": d.wildcard(),
        "domains": d.domains(), "emails": d.emails,
    })
    .to_string()
}

/// Evaluates a handshake result.
pub fn evaluate_ssl(
    template: &Template,
    spec: &SslProbeSpec,
    target: &TcpTarget,
    resp: &SslResponseData,
    ctx: &mut dyn EvalContext,
) -> Option<TemplateMatch> {
    let block = template.ssl.get(spec.request_index)?;
    let scope = scope_for(template, target, ctx);
    let now = ctx.now_unix();
    let mut parts = ResponseParts::new("response");
    parts.set("response", to_json(resp, now));
    parts.set(
        "host",
        if resp.host.is_empty() {
            spec.host.as_str()
        } else {
            resp.host.as_str()
        },
    );
    parts.set("port", Value::Int(i64::from(spec.port)));
    insert_cert_parts(&mut parts, resp, now);
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
        protocol: Protocol::Ssl,
        request_index: spec.request_index,
        matched_at: format!("{}:{}", spec.host, spec.port),
        lines: Vec::new(),
        matched_values: result.matched_values,
        warnings: result.warnings,
    })
}

//! Stored evidence for a live match: bounded, redacted excerpts of what was
//! sent and what came back.
//!
//! Each side is capped at [`EXCERPT_CAP`] bytes with a truncated marker. The
//! values of credential-bearing headers are replaced by `[REDACTED]`:
//! `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
//! `X-Api-Key`, `X-Auth-Token`, and any header whose name contains `token`,
//! `secret`, `password`, `passwd`, `api-key`, `api_key` or `apikey`. Binary
//! bodies are rendered as a hex preview.
//!
//! URLs (the request line, `Location`, `Content-Location` and `Referer`
//! values, and a match's `matchedAt`) go through [`redact_url`]: user info
//! and the values of query or fragment parameters whose names look
//! credential-bearing are replaced by `[REDACTED]`.

use oxaudit_domain::{ArtifactId, NetworkExchangeEvidence};
use oxaudit_nuclei::{
    DnsQuerySpec, DnsResponseData, HttpResponseData, SslResponseData, TcpResponseData,
    TcpSessionSpec, TemplateMatch,
};
use sha2::{Digest, Sha256};

pub(crate) const EXCERPT_CAP: usize = 4096;
pub(crate) const REDACTED: &str = "[REDACTED]";
const TRUNCATED_MARK: &str = "\n[truncated]";

/// True for a header whose value must never be stored.
pub(crate) fn is_sensitive_header(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    matches!(
        n.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
    ) || [
        "token", "secret", "password", "passwd", "api-key", "api_key", "apikey",
    ]
    .iter()
    .any(|needle| n.contains(needle))
}

/// The value to store for a header.
pub(crate) fn redact_header<'a>(name: &str, value: &'a str) -> std::borrow::Cow<'a, str> {
    if is_sensitive_header(name) {
        REDACTED.into()
    } else if is_url_header(name) {
        redact_url(value, false).into()
    } else {
        value.into()
    }
}

fn is_url_header(name: &str) -> bool {
    let n = name.trim();
    ["location", "content-location", "referer"]
        .iter()
        .any(|h| n.eq_ignore_ascii_case(h))
}

/// Query-parameter name fragments that mark a credential (matched case
/// insensitively anywhere in the decoded name).
const CREDENTIAL_PARAMS: &[&str] = &[
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "signature",
    "sig",
    "session",
    "sid",
    "jwt",
    "bearer",
    "credential",
    "apikey",
    "api_key",
    "access_token",
    "client_secret",
];

/// True for a query parameter whose value must never be stored or printed.
pub(crate) fn is_credential_param(name: &str) -> bool {
    let decoded = percent_encoding::percent_decode_str(name)
        .decode_utf8_lossy()
        .to_ascii_lowercase();
    CREDENTIAL_PARAMS
        .iter()
        .any(|marker| decoded.contains(marker))
}

/// `url` as it may be stored or printed: user info, and the values of query
/// and fragment parameters whose names look credential-bearing, become
/// `[REDACTED]`. With `all_values` (a template that reports credentials)
/// every parameter value is redacted. Anything that is not a URL passes
/// through unchanged apart from those rules.
pub(crate) fn redact_url(url: &str, all_values: bool) -> String {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };
    let mut out = redact_userinfo(base);
    if let Some(query) = query {
        out.push('?');
        out.push_str(&redact_pairs(query, all_values));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(&redact_pairs(fragment, all_values));
    }
    out
}

fn redact_userinfo(base: &str) -> String {
    let Some(scheme_end) = base.find("://") else {
        return base.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = base[authority_start..]
        .find('/')
        .map_or(base.len(), |i| authority_start + i);
    match base[authority_start..authority_end].rfind('@') {
        Some(at) => format!(
            "{}{REDACTED}{}",
            &base[..authority_start],
            &base[authority_start + at..]
        ),
        None => base.to_owned(),
    }
}

fn redact_pairs(text: &str, all_values: bool) -> String {
    text.split('&')
        .map(|part| match part.split_once('=') {
            Some((name, value))
                if !value.is_empty() && (all_values || is_credential_param(name)) =>
            {
                format!("{name}={REDACTED}")
            }
            None if all_values && !part.is_empty() => REDACTED.to_owned(),
            _ => part.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Text when the bytes are printable UTF-8, otherwise a hex preview. The
/// result is at most `cap` bytes; the flag says whether anything was cut.
pub(crate) fn render_bytes(bytes: &[u8], cap: usize) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) if is_texty(s) => truncate_str(s, cap),
        _ => hex_preview(bytes, cap),
    }
}

fn is_texty(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

fn hex_preview(bytes: &[u8], cap: usize) -> (String, bool) {
    let header = format!("[binary, {} bytes]\n", bytes.len());
    let mut out = header;
    let mut truncated = false;
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let line = format!(
            "{:08x}  {}\n",
            i * 16,
            chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if out.len() + line.len() > cap {
            truncated = true;
            break;
        }
        out.push_str(&line);
    }
    (out, truncated)
}

/// Cuts at a char boundary so the result is at most `cap` bytes.
pub(crate) fn truncate_str(s: &str, cap: usize) -> (String, bool) {
    if s.len() <= cap {
        return (s.to_string(), false);
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

/// Appends the marker so a reader of the stored text knows it was cut.
fn finish((mut text, truncated): (String, bool)) -> (String, bool) {
    if truncated {
        // Keep the total within the cap.
        let (cut, _) = truncate_str(&text, EXCERPT_CAP.saturating_sub(TRUNCATED_MARK.len()));
        text = cut;
        text.push_str(TRUNCATED_MARK);
    }
    (text, truncated)
}

/// What was sent for an HTTP request (after defaults and cookies).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SentHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn render_head_and_body(head: String, body: &[u8]) -> (String, bool) {
    if head.len() >= EXCERPT_CAP {
        return finish(truncate_str(&head, EXCERPT_CAP));
    }
    let room = EXCERPT_CAP - head.len();
    let (body_text, cut) = render_bytes(body, room);
    finish((head + &body_text, cut))
}

/// The request as text: request line, redacted headers, body.
pub(crate) fn render_http_request(req: &SentHttpRequest) -> (String, bool) {
    let mut head = format!(
        "{} {} HTTP/1.1\r\n",
        req.method,
        redact_url(&req.url, false)
    );
    for (k, v) in &req.headers {
        head.push_str(&format!("{k}: {}\r\n", redact_header(k, v)));
    }
    head.push_str("\r\n");
    render_head_and_body(head, &req.body)
}

/// The response as text: status line, redacted headers, body excerpt.
/// `already_truncated` is set when the body was cut by the response cap.
pub(crate) fn render_http_response(
    resp: &HttpResponseData,
    already_truncated: bool,
) -> (String, bool) {
    let version = if resp.version.is_empty() {
        "HTTP/1.1"
    } else {
        &resp.version
    };
    let mut head = format!("{version} {} {}\r\n", resp.status, resp.reason);
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {}\r\n", redact_header(k, v)));
    }
    head.push_str("\r\n");
    let (text, cut) = render_head_and_body(head, &resp.body);
    (text, cut || already_truncated)
}

pub(crate) fn render_dns_request(spec: &DnsQuerySpec) -> (String, bool) {
    finish(truncate_str(
        &format!("{}\tIN\t{}", spec.name, spec.qtype.as_str()),
        EXCERPT_CAP,
    ))
}

pub(crate) fn render_dns_response(resp: &DnsResponseData) -> (String, bool) {
    finish(truncate_str(&resp.raw, EXCERPT_CAP))
}

pub(crate) fn render_tcp_request(spec: &TcpSessionSpec, resp: &TcpResponseData) -> (String, bool) {
    let head = format!(
        "{}{}:{}\n",
        if spec.tls { "tls://" } else { "" },
        spec.host,
        spec.port
    );
    render_head_and_body(head, &resp.request)
}

pub(crate) fn render_tcp_response(resp: &TcpResponseData) -> (String, bool) {
    finish(render_bytes(&resp.raw, EXCERPT_CAP))
}

pub(crate) fn render_ssl_request(host: &str, port: u16) -> (String, bool) {
    finish(truncate_str(
        &format!("TLS handshake with {host}:{port}"),
        EXCERPT_CAP,
    ))
}

pub(crate) fn render_ssl_response(d: &SslResponseData) -> (String, bool) {
    let text = format!(
        "tls_version: {}\ncipher: {}\nsubject_dn: {}\nissuer_dn: {}\nsubject_an: {}\nserial: {}\nnot_before: {}\nnot_after: {}\nsha256: {}\nself_signed: {}",
        d.tls_version,
        d.cipher,
        d.subject_dn,
        d.issuer_dn,
        d.subject_an.join(", "),
        d.serial,
        d.not_before,
        d.not_after,
        d.fingerprint_sha256,
        d.self_signed
    );
    finish(truncate_str(&text, EXCERPT_CAP))
}

/// A deterministic artifact id for a live target, so every match against the
/// same target shares it. The caller may replace it with the run's own
/// artifact id.
pub(crate) fn artifact_id_for(target: &str) -> ArtifactId {
    let digest = hex::encode(Sha256::digest(target.as_bytes()));
    ArtifactId::parse(format!("artifact_live_{}", &digest[..32]))
        .unwrap_or_else(|_| ArtifactId::new())
}

/// Assembles the evidence record from rendered excerpts. The request text
/// carries its own truncated marker; the record's flag is the response's.
pub(crate) fn evidence(
    protocol: &str,
    target: &str,
    request: (String, bool),
    response: (String, bool),
    matched: &TemplateMatch,
) -> NetworkExchangeEvidence {
    NetworkExchangeEvidence {
        artifact_id: artifact_id_for(target),
        protocol: protocol.to_string(),
        target: target.to_string(),
        request: request.0,
        response_excerpt: response.0,
        response_truncated: response.1,
        matcher_names: matched.matcher_names.clone(),
        extracted: matched.extracted.clone(),
    }
}

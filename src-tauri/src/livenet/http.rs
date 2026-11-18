//! HTTP execution of `oxaudit_nuclei::HttpRequestSpec`.
//!
//! One reqwest client per run:
//! * `.no_proxy()` unless an explicit proxy is configured (environment
//!   variables are never read);
//! * a resolver that answers only from the pinned map, so reqwest can never
//!   look a name up on its own;
//! * `redirect(Policy::none())` and `retry(never())`: every redirect hop is
//!   followed here, after a scope check, and nothing is re-sent behind the
//!   governor's back;
//! * certificates are not verified (targets are commonly self-signed and the
//!   tool is assessing, not trusting, them); the leaf certificate is captured
//!   for the template's certificate parts;
//! * HTTP/1.1 (the build has no HTTP/2 support), gzip decoding on, body read
//!   with a hard byte cap.
//!
//! The socket destination is always the checked URL's host. A template
//! `Host` header is sent as a header to that in-scope server (virtual-host
//! testing) and never changes where the connection goes; behind a proxy, a
//! `Host` header that differs from the URL host is dropped, because a proxy
//! may route by it. `@tls-sni` is ignored: the SNI is always the URL host.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use oxaudit_nuclei::{HttpRequestSpec, HttpResponseData, RedirectMode};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Method, Url};
use tokio::time::Instant;

use super::exchange::SentHttpRequest;
use super::resolve::{PinnedHosts, PinnedResolve};
use super::scope::{HostId, Refusal};
use super::{ssl, Net, NetFailure};

const MAX_COOKIES_PER_HOST: usize = 50;
const MAX_COOKIE_BYTES: usize = 4096;
/// Upper bound for a template's `@timeout:` annotation.
const MAX_ANNOTATED_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds the run's HTTP client.
pub(crate) fn build_client(
    pinned: Arc<PinnedHosts>,
    limits: &super::LiveLimits,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .dns_resolver(Arc::new(PinnedResolve { pinned }))
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .gzip(true)
        .http1_only()
        .connect_timeout(limits.timeout)
        .timeout(limits.timeout)
        .pool_max_idle_per_host(limits.per_host_concurrency as usize);
    builder = match &limits.proxy {
        Some(proxy) => builder
            .no_proxy()
            .proxy(reqwest::Proxy::all(proxy.as_str()).map_err(|e| format!("invalid proxy: {e}"))?),
        None => builder.no_proxy(),
    };
    builder
        .build()
        .map_err(|e| format!("cannot prepare the HTTP client: {e}"))
}

/// One stored cookie.
#[derive(Debug, Clone)]
struct Cookie {
    name: String,
    value: String,
    /// Set over https or flagged `Secure`: never sent over plain http.
    secure: bool,
}

/// Cookies kept for one template against one target, keyed by the exact
/// host they came from. A cookie is only ever sent back to that host (on any
/// port, as a browser does); the `Domain` attribute is ignored (stricter
/// than a browser). A cookie that was set over https, or carries `Secure`,
/// is only ever sent over https.
#[derive(Debug, Default)]
pub(crate) struct CookieJar {
    by_host: HashMap<HostId, Vec<Cookie>>,
}

impl CookieJar {
    /// Stores the `Set-Cookie` headers of a response from `host` received
    /// over `scheme`.
    pub(crate) fn store(&mut self, host: &HostId, scheme: &str, headers: &[(String, String)]) {
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("set-cookie") || v.len() > MAX_COOKIE_BYTES {
                continue;
            }
            let mut parts = v.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
                continue;
            };
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            if name.is_empty() {
                continue;
            }
            let secure = scheme.eq_ignore_ascii_case("https")
                || parts.any(|attribute| attribute.trim().eq_ignore_ascii_case("secure"));
            let jar = self.by_host.entry(host.clone()).or_default();
            if let Some(existing) = jar.iter_mut().find(|c| c.name == name) {
                existing.value = value;
                existing.secure = secure;
            } else if jar.len() < MAX_COOKIES_PER_HOST {
                jar.push(Cookie {
                    name,
                    value,
                    secure,
                });
            }
        }
    }

    /// The `Cookie` header value for a request to `host` over `scheme`, if
    /// any cookie may be sent.
    pub(crate) fn header_for(&self, host: &HostId, scheme: &str) -> Option<String> {
        let https = scheme.eq_ignore_ascii_case("https");
        let sendable: Vec<String> = self
            .by_host
            .get(host)?
            .iter()
            .filter(|c| https || !c.secure)
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        (!sendable.is_empty()).then(|| sendable.join("; "))
    }
}

/// Scheme, host and effective port: what decides whether a redirect stays
/// with the server the credentials were meant for.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme().eq_ignore_ascii_case(b.scheme())
        && HostId::from_url_host(a) == HostId::from_url_host(b)
        && a.port_or_known_default() == b.port_or_known_default()
}

/// One request (with its redirect hops) and what came of it.
#[derive(Debug)]
pub(crate) struct HttpExchange {
    pub outcome: Result<HttpResponseData, NetFailure>,
    /// The last request actually sent.
    pub sent: Option<SentHttpRequest>,
    /// The final body was cut at the response cap.
    pub truncated: bool,
    /// Redirect hops scope refused (not followed).
    pub refused: Vec<Refusal>,
    pub notes: Vec<String>,
}

/// Go's `CanonicalMIMEHeaderKey`, so matchers written for Nuclei's
/// `Content-Type: ...` header dump work.
pub(crate) fn canonical_header(name: &str) -> String {
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return name.to_string();
    }
    let mut upper = true;
    name.chars()
        .map(|c| {
            let out = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == '-';
            out
        })
        .collect()
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// The run's HTTP executor.
pub(crate) struct HttpExecutor {
    client: reqwest::Client,
    user_agent: String,
    proxied: bool,
}

impl HttpExecutor {
    pub(crate) fn new(client: reqwest::Client, version: &str, proxied: bool) -> Self {
        HttpExecutor {
            client,
            user_agent: format!("oxAudit/{version} (authorized security scan)"),
            proxied,
        }
    }

    /// Sends `spec`, following redirects as its policy allows. Every hop is
    /// scope-checked and admitted by the governor before it is sent.
    pub(crate) async fn execute(
        &self,
        net: &Net,
        spec: &HttpRequestSpec,
        jar: &mut CookieJar,
    ) -> HttpExchange {
        let mut ex = HttpExchange {
            outcome: Err(NetFailure::Protocol("not sent".into())),
            sent: None,
            truncated: false,
            refused: Vec::new(),
            notes: Vec::new(),
        };
        if spec.tls_sni.is_some() {
            ex.notes
                .push("@tls-sni is not supported; the SNI is the URL host".into());
        }
        let mut url = match Url::parse(&spec.url) {
            Ok(u) => u,
            Err(e) => {
                ex.outcome = Err(NetFailure::Protocol(format!("invalid URL: {e}")));
                return ex;
            }
        };
        let mut method = match Method::from_bytes(spec.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                ex.outcome = Err(NetFailure::Protocol(format!(
                    "invalid method `{}`",
                    spec.method
                )));
                return ex;
            }
        };
        let mut headers = spec.headers.clone();
        let mut body = spec.body.clone();
        let max_hops = match spec.follow_redirects.mode {
            RedirectMode::None => 0,
            _ => spec.follow_redirects.max.min(net.limits.max_redirects_cap),
        };
        let timeout = spec
            .timeout_ms
            .map(|ms| {
                Duration::from_millis(ms).clamp(Duration::from_secs(1), MAX_ANNOTATED_TIMEOUT)
            })
            .unwrap_or(net.limits.timeout);
        let cap = spec
            .max_response_bytes
            .unwrap_or(net.limits.max_response_bytes)
            .clamp(1, net.limits.max_response_bytes);
        let mut origin: Option<HostId> = None;
        let mut last: Option<HttpResponseData> = None;

        for hop in 0..=max_hops {
            // `host-redirects` (same host only): a hop to another host is
            // not followed by policy. Nothing would be sent, so it is not a
            // scope refusal.
            if let (Some(o), Some(prev)) = (&origin, &last) {
                if spec.follow_redirects.mode == RedirectMode::SameHost
                    && HostId::from_url_host(&url).as_ref() != Some(o)
                {
                    ex.outcome = Ok(prev.clone());
                    return ex;
                }
            }
            // Scope, before anything is admitted or sent.
            let (host, port) = match net.scope.check_url(&url) {
                Ok(hp) => hp,
                Err(r) => {
                    match last.take() {
                        Some(prev) => {
                            // An off-scope redirect is not followed; the 3xx
                            // is the final response.
                            ex.refused.push(r);
                            ex.outcome = Ok(prev);
                        }
                        None => ex.outcome = Err(NetFailure::Refused(r)),
                    }
                    return ex;
                }
            };
            if origin.is_none() {
                origin = Some(host.clone());
            }
            if let HostId::Name(n) = &host {
                if let Err(m) = net.pinned.addresses_for(&HostId::Name(n.clone())) {
                    ex.outcome = match last.take() {
                        Some(prev) => Ok(prev),
                        None => Err(NetFailure::Unresolved(m)),
                    };
                    return ex;
                }
            }

            // Headers: the template's, then defaults, then the jar.
            let mut sent_headers: Vec<(String, String)> = Vec::new();
            for (k, v) in &headers {
                if k.eq_ignore_ascii_case("content-length") {
                    continue;
                }
                if k.eq_ignore_ascii_case("host") && self.proxied {
                    let url_authority = url_authority(&url);
                    if !v.trim().eq_ignore_ascii_case(&url_authority)
                        && !v.trim().eq_ignore_ascii_case(&host.url_host())
                    {
                        ex.notes.push(
                            "a Host header that differs from the URL host was dropped because a proxy is in use".into(),
                        );
                        continue;
                    }
                }
                sent_headers.push((k.clone(), v.clone()));
            }
            let has = |name: &str, hs: &[(String, String)]| {
                hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
            };
            if !has("user-agent", &sent_headers) {
                sent_headers.push(("User-Agent".into(), self.user_agent.clone()));
            }
            if !has("accept", &sent_headers) {
                sent_headers.push(("Accept".into(), "*/*".into()));
            }
            if !has("accept-language", &sent_headers) {
                sent_headers.push(("Accept-Language".into(), "en".into()));
            }
            if spec.cookie_reuse {
                if let Some(c) = jar.header_for(&host, url.scheme()) {
                    match sent_headers
                        .iter_mut()
                        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                    {
                        Some((_, v)) => {
                            v.push_str("; ");
                            v.push_str(&c);
                        }
                        None => sent_headers.push(("Cookie".into(), c)),
                    }
                }
            }
            let mut header_map = reqwest::header::HeaderMap::new();
            for (k, v) in &sent_headers {
                let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) else {
                    ex.outcome = Err(NetFailure::Protocol(format!("invalid header `{k}`")));
                    return ex;
                };
                header_map.append(name, value);
            }

            let _admission = match net.admit(&host.key()).await {
                Ok(a) => a,
                Err(h) => {
                    ex.outcome = Err(NetFailure::Halted(h));
                    return ex;
                }
            };
            ex.sent = Some(SentHttpRequest {
                method: method.to_string(),
                url: url.to_string(),
                headers: sent_headers,
                body: body.clone(),
            });
            let started = Instant::now();
            let deadline = started + timeout;
            let request = self
                .client
                .request(method.clone(), url.clone())
                .headers(header_map)
                .timeout(timeout)
                .body(body.clone());
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) => {
                    // The URL may carry a secret in its query: the message
                    // names only the scope-checked destination.
                    let is_connect = e.is_connect() || e.is_timeout();
                    let msg = format!("{}: {}", destination(&host, port), error_chain(e));
                    ex.outcome = Err(if is_connect {
                        NetFailure::Connect(msg)
                    } else {
                        NetFailure::Protocol(msg)
                    });
                    return ex;
                }
            };
            let status = response.status();
            let version = format!("{:?}", response.version());
            let resp_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        canonical_header(k.as_str()),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            let peer = response.remote_addr();
            let tls = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|t| t.peer_certificate())
                .and_then(|der| {
                    ssl::http_tls_facts(
                        der,
                        &host.key(),
                        host.name().unwrap_or_default(),
                        peer,
                        port,
                    )
                });
            let (body_bytes, truncated) = read_capped(response, cap, deadline).await;
            ex.truncated = truncated;
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if spec.cookie_reuse {
                jar.store(&host, url.scheme(), &resp_headers);
            }
            let resp = HttpResponseData {
                status: status.as_u16(),
                reason: status.canonical_reason().unwrap_or_default().to_string(),
                version,
                headers: resp_headers,
                body: body_bytes,
                url: Some(url.to_string()),
                duration_ms,
                tls,
            };

            let next = (hop < max_hops && is_redirect(resp.status))
                .then(|| {
                    resp.headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                        .and_then(|(_, loc)| url.join(loc.trim()).ok())
                })
                .flatten();
            let Some(next) = next else {
                ex.outcome = Ok(resp);
                return ex;
            };
            // 301/302/303 become GET without a body; 307/308 keep both.
            if matches!(resp.status, 301..=303) && method != Method::HEAD {
                method = Method::GET;
                body.clear();
                headers.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("content-type")
                        && !k.eq_ignore_ascii_case("transfer-encoding")
                });
            }
            // Credentials do not follow a redirect to another origin
            // (scheme, host or port), and the virtual host does not follow
            // one to another host.
            let other_host = HostId::from_url_host(&next).as_ref() != Some(&host);
            if other_host || !same_origin(&url, &next) {
                headers.retain(|(k, _)| {
                    !(other_host && k.eq_ignore_ascii_case("host"))
                        && !k.eq_ignore_ascii_case("authorization")
                        && !k.eq_ignore_ascii_case("cookie")
                        && !k.eq_ignore_ascii_case("proxy-authorization")
                });
            }
            url = next;
            last = Some(resp);
        }
        // Unreachable: the last hop always returns. Keep the compiler happy
        // without a panic.
        if let Some(prev) = last {
            ex.outcome = Ok(prev);
        }
        ex
    }
}

fn url_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

/// `host:port` as scope checked it, for messages.
fn destination(host: &HostId, port: u16) -> String {
    format!("{}:{port}", host.url_host())
}

/// The error and its causes, without the request URL (which may carry a
/// secret in its query string).
fn error_chain(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(&e);
    let mut depth = 0;
    while let Some(s) = source {
        if depth >= 4 {
            break;
        }
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
        depth += 1;
    }
    msg
}

/// Reads the body up to `cap` bytes before `deadline`. A read error or the
/// deadline ends the body early; what arrived is kept and flagged.
async fn read_capped(
    response: reqwest::Response,
    cap: usize,
    deadline: Instant,
) -> (Vec<u8>, bool) {
    use futures::StreamExt;

    let declared_over = response.content_length().is_some_and(|n| n > cap as u64);
    // Read one byte past the cap to know whether there was more.
    let probe = cap.saturating_add(1);
    let mut body: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    let mut stream = response.bytes_stream();
    let mut truncated = declared_over;
    while body.len() < probe {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                let room = probe - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) => break,
            Ok(Some(Err(_))) | Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    truncated |= body.len() > cap;
    body.truncate(cap);
    (body, truncated)
}

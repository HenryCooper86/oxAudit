//! HTTP planning and evaluation.
//!
//! Later requests depend on earlier responses (internal extractors, request
//! conditions), so planning is a small state machine:
//!
//! ```text
//! let mut run = HttpRun::new(&template, target, ctx);
//! while let Some(step) = run.next_request() {
//!     match step {
//!         Ok(spec) => { /* send it */ run.on_response(response); }
//!         Err(skip) => { /* report the skip */ }
//!     }
//! }
//! let matches = run.finish();
//! ```
//!
//! # Response parts
//!
//! `body` (default), `header` / `all_headers`, `status_code`,
//! `content_length`, `raw` / `response` / `all` (status line, headers, body),
//! `request`, `host`, `url`, `duration` (seconds), `cookies_from_response`,
//! `headers_from_response`, one variable per response header (lowercase, `-`
//! to `_`, repeated headers joined with `, `), and, when the response carries
//! TLS facts, the certificate parts documented in `ssl.rs`. With request
//! conditions, every part also exists with a `_N` suffix for response N of the
//! block (1-based), the current response included.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::dsl::{DslError, EvalContext, Value, VarLookup, Vars};
use crate::http_raw::{parse_raw, RawRequest};
use crate::matchers::{build_operators, evaluate_block, normalise_key, ResponseParts};
use crate::model::{HttpBlock, Operators, Protocol, Template};
use crate::payloads::{build_payloads, PayloadPlan, DEFAULT_MAX_COMBINATIONS};
use crate::result::{SkipReason, TemplateMatch, Truncation};
use crate::ssl::{insert_cert_parts, SslResponseData};
use crate::support::Reasons;
use crate::vars::{
    expressions_in, interpolate_detailed, interpolate_lenient, resolve_template_variables,
    Interpolated,
};
use crate::yaml::Yaml;

// ------------------------------------------------------------------ target

/// A parsed HTTP(S) target and the variables derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    pub scheme: String,
    /// Host without brackets or port.
    pub host: String,
    /// The port as written, if any.
    pub port: Option<u16>,
    /// Path as written, `""` when none.
    pub path: String,
}

impl HttpTarget {
    /// Accepts `https://host:port/path`, `host:port/path` and `host`.
    /// A target without a scheme is `http`.
    pub fn parse(input: &str) -> Result<HttpTarget, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty target".into());
        }
        let (scheme, rest) = match input.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("http".to_string(), input),
        };
        if scheme != "http" && scheme != "https" {
            return Err(format!("unsupported scheme `{scheme}`"));
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err("missing host".into());
        }
        let path = tail
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(HttpTarget {
            scheme,
            host,
            port,
            path,
        })
    }

    fn host_for_url(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// `host[:port]` with the port only when it was written.
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host_for_url()),
            None => self.host_for_url(),
        }
    }

    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or(if self.scheme == "https" { 443 } else { 80 })
    }

    pub fn root_url(&self) -> String {
        format!("{}://{}", self.scheme, self.authority())
    }

    /// The path without trailing slashes.
    fn base_path(&self) -> &str {
        self.path.trim_end_matches('/')
    }

    pub fn base_url(&self) -> String {
        format!("{}{}", self.root_url(), self.base_path())
    }

    /// Target variables: `BaseURL`, `RootURL`, `Hostname`, `Host`, `Port`,
    /// `Path`, `File`, `Scheme`, and the domain parts (`FQDN`, `RDN`, `DN`,
    /// `TLD`, `SD`) when the host is a name.
    pub fn variables(&self) -> Vars {
        let mut vars = Vars::new();
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        vars.insert("BaseURL".into(), Value::from(self.base_url()));
        vars.insert("RootURL".into(), Value::from(self.root_url()));
        vars.insert("Hostname".into(), Value::from(self.authority()));
        vars.insert("Host".into(), Value::from(self.host.clone()));
        vars.insert(
            "Port".into(),
            Value::from(self.effective_port().to_string()),
        );
        vars.insert("Path".into(), Value::from(go_dir(path)));
        vars.insert("File".into(), Value::from(go_base(path)));
        vars.insert("Scheme".into(), Value::from(self.scheme.clone()));
        if self.host.parse::<std::net::IpAddr>().is_err() {
            crate::dns::domain_vars(&self.host, &mut vars);
        }
        vars
    }
}

pub(crate) fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| format!("invalid port `{p}`"))?,
            ),
            None if tail.is_empty() => None,
            None => return Err("garbage after IPv6 literal".into()),
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, p)) if !host.contains(':') => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{p}`"))?;
            Ok((host.to_string(), Some(port)))
        }
        Some(_) => Ok((authority.to_string(), None)),
        None => Ok((authority.to_string(), None)),
    }
}

/// Go's `path.Dir` for slash paths.
fn go_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => {
            let dir = path[..=i].trim_end_matches('/');
            if dir.is_empty() {
                "/".into()
            } else {
                dir.into()
            }
        }
        None => ".".into(),
    }
}

/// Go's `path.Base`, except that the root has an empty file name.
fn go_base(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

// ------------------------------------------------------------ public types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMode {
    None,
    SameHost,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectPolicy {
    pub mode: RedirectMode,
    pub max: u32,
}

/// One HTTP request for the host to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub method: String,
    pub url: String,
    /// In template order. A `Host` header, when present, is meant to be sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub follow_redirects: RedirectPolicy,
    /// Reuse the template's cookie jar across requests.
    pub cookie_reuse: bool,
    /// Index of the `http` block in the template.
    pub request_index: usize,
    /// 1-based sequence number inside the block.
    pub step: usize,
    pub payload_values: Vec<(String, String)>,
    pub max_response_bytes: Option<usize>,
    /// `@timeout:` annotation.
    pub timeout_ms: Option<u64>,
    /// `@tls-sni:` annotation.
    pub tls_sni: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpResponseData {
    pub status: u16,
    pub reason: String,
    /// e.g. `HTTP/1.1`; defaults to that when empty.
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Final URL after redirects.
    pub url: Option<String>,
    pub duration_ms: u64,
    pub tls: Option<SslResponseData>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepOutcome {
    /// This response produced a reportable result.
    pub matched: bool,
    /// The run should end: a match with `stop-at-first-match`.
    pub stop: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    /// Hard cap on payload combinations per request template.
    pub max_payload_combinations: usize,
    /// Cap on `iterate-all` fan-out per request.
    pub max_iterate_all_variants: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        RunLimits {
            max_payload_combinations: DEFAULT_MAX_COMBINATIONS,
            max_iterate_all_variants: 100,
        }
    }
}

// ------------------------------------------------------------ block builder

fn history_var(name: &str) -> Option<usize> {
    let (base, n) = name.rsplit_once('_')?;
    if base.is_empty() || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok().filter(|n| *n >= 1)
}

pub(crate) fn build_block(
    y: &Yaml,
    template_vars: &[(String, String)],
    reasons: &mut Reasons,
) -> HttpBlock {
    for (key, what) in [
        ("unsafe", "uses `unsafe` raw HTTP"),
        ("pipeline", "uses HTTP pipelining"),
        ("race", "uses a race-condition attack"),
        ("global-matchers", "uses global-matchers"),
        ("self-contained", "has a self-contained HTTP request"),
    ] {
        if y.boolean(key) {
            reasons.add(what);
        }
    }
    if y.has("fuzzing") {
        reasons.add("uses fuzzing");
    }
    if y.has("analyzer") {
        reasons.add("uses a response analyzer");
    }
    if y.has("digest-username") || y.has("digest-password") {
        reasons.add("uses HTTP digest authentication");
    }
    if y.string("signature").is_some_and(|s| !s.is_empty()) {
        reasons.add("uses request signing (`signature`)");
    }
    let payloads = build_payloads(y, reasons);
    let ops = build_operators(y, reasons);
    let mut paths = y.raw_list("path");
    let raw = y.raw_list("raw");
    if paths.is_empty() && raw.is_empty() {
        paths.push("{{BaseURL}}".into());
    }
    for text in &raw {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some(annotation) = trimmed.strip_prefix('@') else {
                break;
            };
            let name = annotation
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !matches!(name.as_str(), "host" | "tls-sni" | "timeout") {
                reasons.add(format!("uses the raw request annotation `@{name}`"));
            }
        }
    }
    let headers: Vec<(String, String)> = y
        .get("headers")
        .and_then(Yaml::as_map)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.scalar_text().map(|t| (k.clone(), t)))
                .collect()
        })
        .unwrap_or_default();
    let body = y.string("body");

    let disable_cookie = y.boolean("disable-cookie");
    let cookie_reuse = !disable_cookie || y.boolean("cookie-reuse") && !y.has("disable-cookie");
    let max_redirects = y
        .int("max-redirects")
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(10)
        .min(100);

    let mut block = HttpBlock {
        id: y.string("id"),
        name: y.string("name"),
        method: y
            .string("method")
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".into()),
        paths,
        raw,
        headers,
        body,
        payloads,
        redirects: y.boolean("redirects"),
        host_redirects: y.boolean("host-redirects"),
        max_redirects,
        cookie_reuse,
        stop_at_first_match: y.boolean("stop-at-first-match"),
        iterate_all: y.boolean("iterate-all"),
        req_condition: y.boolean("req-condition"),
        skip_variables_check: y.boolean("skip-variables-check"),
        disable_path_automerge: y.boolean("disable-path-automerge"),
        max_size: y.int("max-size").and_then(|n| usize::try_from(n).ok()),
        keep_history: false,
        ops,
    };
    block.keep_history = block.req_condition || references_history(&block, template_vars);
    block
}

/// True when some expression in the block reads a `name_N` variable that is
/// not a payload or template variable.
fn references_history(block: &HttpBlock, template_vars: &[(String, String)]) -> bool {
    let mut names: BTreeSet<String> = BTreeSet::new();
    collect_ops_vars(&block.ops, &mut names);
    let mut texts: Vec<&str> = block.paths.iter().map(String::as_str).collect();
    texts.extend(block.raw.iter().map(String::as_str));
    texts.extend(block.headers.iter().map(|(_, v)| v.as_str()));
    texts.extend(block.body.as_deref());
    for text in texts {
        if let Ok(exprs) = expressions_in(text) {
            for e in exprs {
                names.extend(e.variables());
            }
        }
    }
    let defined: BTreeSet<&str> = block
        .payloads
        .sets
        .iter()
        .map(|(n, _)| n.as_str())
        .chain(template_vars.iter().map(|(n, _)| n.as_str()))
        .collect();
    names
        .iter()
        .any(|n| history_var(n).is_some() && !defined.contains(n.as_str()))
}

pub(crate) fn collect_ops_vars(ops: &Operators, names: &mut BTreeSet<String>) {
    use crate::model::ExtractorKind;
    for m in &ops.matchers {
        for d in &m.dsl {
            names.extend(d.expr.variables());
        }
    }
    for e in &ops.extractors {
        if let ExtractorKind::Dsl { exprs } = &e.kind {
            for d in exprs {
                names.extend(d.expr.variables());
            }
        }
    }
}

// ------------------------------------------------------------------- run

/// Request conditions keep every response of the block in memory, so they are
/// only honoured for blocks that send a bounded number of requests.
const MAX_HISTORY_REQUESTS: usize = 64;

struct BlockPlan {
    sources: usize,
    combos: usize,
    total: usize,
}

struct Pending {
    block: usize,
    url: String,
    request_text: String,
    scope: Vars,
}

/// Records which of the watched names were looked up.
struct Tracking<'a> {
    vars: &'a Vars,
    watch: &'a BTreeMap<String, Vec<String>>,
    used: RefCell<BTreeSet<String>>,
}

impl VarLookup for Tracking<'_> {
    fn lookup(&self, name: &str) -> Option<&Value> {
        let found = self.vars.get(name);
        if found.is_some() && self.watch.contains_key(name) {
            self.used.borrow_mut().insert(name.to_string());
        }
        found
    }
}

/// Drives one HTTP-protocol template against one target.
pub struct HttpRun<'t> {
    template: &'t Template,
    target: HttpTarget,
    ctx: Box<dyn EvalContext>,
    limits: RunLimits,
    base: Vars,
    dynamic: Vars,
    dynamic_multi: BTreeMap<String, Vec<String>>,
    block: usize,
    job: usize,
    cur_job: usize,
    plan: Option<BlockPlan>,
    history: Vec<Vars>,
    step: usize,
    queue: VecDeque<Vec<(String, String)>>,
    history_on: bool,
    pending: Option<Pending>,
    matches: Vec<TemplateMatch>,
    warnings: Vec<String>,
    truncations: Vec<Truncation>,
    stopped: bool,
}

impl<'t> HttpRun<'t> {
    pub fn new(template: &'t Template, target: HttpTarget, ctx: Box<dyn EvalContext>) -> Self {
        Self::with_limits(template, target, ctx, RunLimits::default())
    }

    pub fn with_limits(
        template: &'t Template,
        target: HttpTarget,
        mut ctx: Box<dyn EvalContext>,
        limits: RunLimits,
    ) -> Self {
        let mut base = target.variables();
        let declared = resolve_template_variables(&template.variables, &base, ctx.as_mut());
        base.extend(declared);
        HttpRun {
            template,
            target,
            ctx,
            limits,
            base,
            dynamic: Vars::new(),
            dynamic_multi: BTreeMap::new(),
            block: 0,
            job: 0,
            cur_job: 0,
            plan: None,
            history: Vec::new(),
            step: 0,
            queue: VecDeque::new(),
            history_on: false,
            pending: None,
            matches: Vec::new(),
            warnings: Vec::new(),
            truncations: Vec::new(),
            stopped: false,
        }
    }

    /// Notes from planning that do not narrow coverage.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Every planner cap that cut this run's requests short so far (payload
    /// combinations, request conditions, `iterate-all` fan-out). Each one
    /// means part of the template was not evaluated against the target.
    pub fn truncations(&self) -> &[Truncation] {
        &self.truncations
    }

    fn truncated(&mut self, message: String) {
        let truncation = Truncation {
            protocol: Protocol::Http,
            request_index: self.block,
            message,
        };
        if !self.truncations.contains(&truncation) {
            self.truncations.push(truncation);
        }
    }

    pub fn matches(&self) -> &[TemplateMatch] {
        &self.matches
    }

    /// The next request, or a reason it was skipped, or `None` when done.
    /// Every call moves on: a request whose response never arrived is simply
    /// not answered.
    pub fn next_request(&mut self) -> Option<Result<HttpRequestSpec, SkipReason>> {
        self.pending = None;
        loop {
            if self.stopped {
                return None;
            }
            if let Some(overrides) = self.queue.pop_front() {
                return Some(self.build(self.cur_job, Some(overrides)));
            }
            let template = self.template;
            let block = template.http.get(self.block)?;
            if self.plan.is_none() {
                let sources = if block.raw.is_empty() {
                    block.paths.len()
                } else {
                    block.raw.len()
                };
                let payload_plan =
                    PayloadPlan::new(&block.payloads, self.limits.max_payload_combinations);
                if let Some(truncation) = payload_plan.truncation(Protocol::Http, self.block) {
                    if !self.truncations.contains(&truncation) {
                        self.truncations.push(truncation);
                    }
                }
                let combos = payload_plan.total().max(1);
                let total = if payload_plan.total() == 0 {
                    0
                } else {
                    sources.saturating_mul(combos)
                };
                self.history_on = block.keep_history && total <= MAX_HISTORY_REQUESTS;
                if block.keep_history && !self.history_on {
                    self.truncated(format!(
                        "http request {}: request conditions disabled, the block sends {total} requests (more than {MAX_HISTORY_REQUESTS}), so matchers that compare earlier responses were not evaluated",
                        self.block
                    ));
                }
                self.plan = Some(BlockPlan {
                    sources,
                    combos,
                    total,
                });
            }
            let total = self.plan.as_ref().map_or(0, |p| p.total);
            if self.job >= total {
                self.block += 1;
                self.job = 0;
                self.plan = None;
                self.history.clear();
                self.step = 0;
                continue;
            }
            let job = self.job;
            self.job += 1;
            self.cur_job = job;
            return Some(self.build(job, None));
        }
    }

    fn build(
        &mut self,
        job: usize,
        overrides: Option<Vec<(String, String)>>,
    ) -> Result<HttpRequestSpec, SkipReason> {
        let template = self.template;
        let block_index = self.block;
        let Some(block) = template.http.get(block_index) else {
            return Err(SkipReason::Malformed("no such request block".into()));
        };
        let (combos, sources) = self
            .plan
            .as_ref()
            .map_or((1, 1), |p| (p.combos.max(1), p.sources.max(1)));
        let (source_index, combo_index) = (job / combos % sources, job % combos);
        let payload_plan = PayloadPlan::new(&block.payloads, self.limits.max_payload_combinations);
        let payload_pairs = payload_plan.combination(combo_index);

        let mut dynamic = self.dynamic.clone();
        let is_variant = overrides.is_some();
        for (k, v) in overrides.unwrap_or_default() {
            dynamic.insert(k, Value::from(v));
        }
        let mut scope = self.base.clone();
        scope.extend(dynamic.iter().map(|(k, v)| (k.clone(), v.clone())));
        let mut payload_values = Vec::with_capacity(payload_pairs.len());
        for (name, value) in &payload_pairs {
            let evaluated = interpolate_lenient(value, &scope, self.ctx.as_mut()).text();
            payload_values.push((name.clone(), evaluated));
        }
        for (name, value) in &payload_values {
            scope.insert(name.clone(), Value::from(value.clone()));
        }

        let watch: BTreeMap<String, Vec<String>> = if block.iterate_all && !is_variant {
            self.dynamic_multi
                .iter()
                .filter(|(_, v)| v.len() > 1)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        } else {
            BTreeMap::new()
        };
        let tracking = Tracking {
            vars: &scope,
            watch: &watch,
            used: RefCell::new(BTreeSet::new()),
        };
        let mut unresolved: Vec<String> = Vec::new();
        let mut interp =
            |text: &str, ctx: &mut dyn EvalContext| -> Result<Interpolated, SkipReason> {
                let out = interpolate_detailed(text, &tracking, ctx).map_err(|e| match e {
                    DslError::Unsupported(m) => SkipReason::Unsupported(m),
                    other => SkipReason::Expression(other.to_string()),
                })?;
                unresolved.extend(out.unresolved.iter().cloned());
                Ok(out)
            };

        let ctx = self.ctx.as_mut();
        let mut spec_method;
        let url;
        let mut headers: Vec<(String, String)> = Vec::new();
        let body: Vec<u8>;
        let mut timeout_ms = None;
        let mut tls_sni = None;
        if block.raw.is_empty() {
            spec_method = interp(&block.method, ctx)?.text();
            let path = block
                .paths
                .get(source_index)
                .map(String::as_str)
                .unwrap_or("");
            let path = interp(path, ctx)?.text();
            url = join_url(
                &self.target,
                &self.target,
                &path,
                block.disable_path_automerge,
            );
            for (k, v) in &block.headers {
                headers.push((interp(k, ctx)?.text(), interp(v, ctx)?.text()));
            }
            body = match &block.body {
                Some(b) => interp(b, ctx)?.bytes,
                None => Vec::new(),
            };
        } else {
            let raw_text = block
                .raw
                .get(source_index)
                .map(String::as_str)
                .unwrap_or("");
            let rendered = interp(raw_text, ctx)?;
            let parsed: RawRequest = parse_raw(&rendered.bytes).map_err(SkipReason::Malformed)?;
            let base_target = match &parsed.host_override {
                Some(h) => HttpTarget::parse(&if h.contains("://") {
                    h.clone()
                } else {
                    format!("{}://{h}", self.target.scheme)
                })
                .map_err(|e| SkipReason::Malformed(format!("@Host: {e}")))?,
                None => self.target.clone(),
            };
            url = join_url(
                &base_target,
                &self.target,
                &parsed.uri,
                block.disable_path_automerge || parsed.host_override.is_some(),
            );
            spec_method = parsed.method;
            headers = parsed.headers;
            body = parsed.body;
            timeout_ms = parsed.timeout_ms;
            tls_sni = parsed.tls_sni.map(|s| {
                if s == "request.host" {
                    headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                } else {
                    s
                }
            });
        }
        if spec_method.is_empty() {
            spec_method = "GET".into();
        }
        // Variables defined by the template's own text are resolved; anything
        // still unresolved means the request cannot be built.
        let unresolved_names: Vec<String> = {
            let mut seen = BTreeSet::new();
            unresolved
                .into_iter()
                .filter(|n| seen.insert(n.clone()))
                .collect()
        };
        if !block.skip_variables_check && !unresolved_names.is_empty() {
            return Err(SkipReason::UnresolvedVariable(unresolved_names));
        }
        let used = tracking.used.into_inner();
        if !used.is_empty() && block.iterate_all {
            self.enqueue_variants(&watch, &used);
        }
        // The message names the scheme only: the URL may carry a secret.
        let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
        if scheme != "http" && scheme != "https" {
            return Err(SkipReason::Malformed(if scheme.is_empty() {
                "the request URL has no http:// or https:// scheme".into()
            } else {
                format!("unsupported URL scheme `{scheme}`")
            }));
        }
        self.step += 1;
        let step = self.step;
        let request_text = render_request(&spec_method, &url, &headers, &body);
        self.pending = Some(Pending {
            block: block_index,
            url: url.clone(),
            request_text,
            scope,
        });
        Ok(HttpRequestSpec {
            method: spec_method,
            url,
            headers,
            body,
            follow_redirects: redirect_policy(block),
            cookie_reuse: block.cookie_reuse,
            request_index: block_index,
            step,
            payload_values,
            max_response_bytes: block.max_size,
            timeout_ms,
            tls_sni,
        })
    }

    /// Queues the other value combinations of the dynamic variables a request
    /// used, when `iterate-all` is set.
    fn enqueue_variants(&mut self, watch: &BTreeMap<String, Vec<String>>, used: &BTreeSet<String>) {
        let lists: Vec<(&String, &Vec<String>)> =
            watch.iter().filter(|(k, _)| used.contains(*k)).collect();
        // Every combination but the first (the request just built).
        let further = lists
            .iter()
            .try_fold(1usize, |acc, (_, values)| acc.checked_mul(values.len()))
            .map(|n| n.saturating_sub(1));
        if further.is_none_or(|n| n > self.limits.max_iterate_all_variants) {
            self.truncated(format!(
                "http request {}: iterate-all sent only {} of {} further value combinations (the cap is {})",
                self.block,
                self.limits.max_iterate_all_variants,
                further.map_or_else(|| "more than 2^64".to_owned(), |n| n.to_string()),
                self.limits.max_iterate_all_variants
            ));
        }
        let mut combos: Vec<Vec<(String, String)>> = vec![Vec::new()];
        for (name, values) in lists {
            let mut next = Vec::new();
            for existing in &combos {
                for v in values {
                    let mut c = existing.clone();
                    c.push((name.clone(), v.clone()));
                    next.push(c);
                    if next.len() > self.limits.max_iterate_all_variants + 1 {
                        break;
                    }
                }
            }
            combos = next;
        }
        // The first combination (every first value) is the request just built.
        for c in combos
            .into_iter()
            .skip(1)
            .take(self.limits.max_iterate_all_variants)
        {
            self.queue.push_back(c);
        }
    }

    /// Evaluates the response to the request most recently returned.
    pub fn on_response(&mut self, resp: HttpResponseData) -> StepOutcome {
        let template = self.template;
        let Some(pending) = self.pending.take() else {
            return StepOutcome {
                warnings: vec!["response received without a pending request".into()],
                ..StepOutcome::default()
            };
        };
        let Some(block) = template.http.get(pending.block) else {
            return StepOutcome::default();
        };
        let now = self.ctx.now_unix();
        let response_vars = response_vars(&resp, &pending, &self.target, now);
        if self.history_on {
            self.history.push(response_vars.clone());
        }
        let mut parts = ResponseParts::new("body");
        for (k, v) in response_vars {
            parts.set(&k, v);
        }
        for (k, v) in &resp.headers {
            parts.add_kval(k, v);
        }
        for (name, value) in set_cookies(&resp.headers) {
            parts.add_kval(&name, &value);
        }
        for (i, entry) in self.history.iter().enumerate() {
            for (k, v) in entry {
                parts.set(&format!("{k}_{}", i + 1), v.clone());
            }
        }
        let mut parts = parts.with_base_vars(&pending.scope);

        let result = evaluate_block(&block.ops, &mut parts, self.ctx.as_mut());
        let history_len = self.history.len();
        let mut warnings: Vec<String> = result
            .warnings
            .into_iter()
            .filter(|w| !is_future_history_warning(w, history_len, self.history_on))
            .collect();
        for (name, values) in &result.internal {
            if name.is_empty() {
                continue;
            }
            if let Some(first) = values.first() {
                self.dynamic
                    .insert(name.clone(), Value::from(first.clone()));
            }
            self.dynamic_multi.insert(name.clone(), values.clone());
        }
        let mut stop = false;
        if result.matched {
            self.matches.push(TemplateMatch {
                template_id: template.id.clone(),
                name: template.info.name.clone(),
                severity: template.info.severity,
                matcher_names: result.matcher_names,
                extracted: result.extracted,
                protocol: crate::model::Protocol::Http,
                request_index: pending.block,
                matched_at: resp.url.clone().unwrap_or_else(|| pending.url.clone()),
                lines: Vec::new(),
                matched_values: result.matched_values,
                warnings: warnings.clone(),
            });
            if block.stop_at_first_match || template.stop_at_first_match {
                self.stopped = true;
                stop = true;
            }
        }
        warnings.dedup();
        StepOutcome {
            matched: result.matched,
            stop,
            warnings,
        }
    }

    /// Ends the run and returns every result.
    pub fn finish(self) -> Vec<TemplateMatch> {
        self.matches
    }
}

fn is_future_history_warning(warning: &str, history_len: usize, enabled: bool) -> bool {
    if !enabled {
        return false;
    }
    let Some(start) = warning.find("unknown variable `") else {
        return false;
    };
    let rest = &warning[start + "unknown variable `".len()..];
    let name = rest.split('`').next().unwrap_or_default();
    history_var(name).is_some_and(|n| n > history_len)
}

fn redirect_policy(block: &HttpBlock) -> RedirectPolicy {
    let mode = if block.host_redirects {
        RedirectMode::SameHost
    } else if block.redirects {
        RedirectMode::Any
    } else {
        RedirectMode::None
    };
    RedirectPolicy {
        mode,
        max: block.max_redirects,
    }
}

/// Resolves a request path against a base. `base` supplies scheme and
/// authority; `automerge_base` supplies the path that a relative path is
/// appended to (Nuclei merges the target's own path into `/x` style paths).
fn join_url(base: &HttpTarget, automerge_base: &HttpTarget, path: &str, no_merge: bool) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return path.to_string();
    }
    if path.is_empty() {
        return base.base_url();
    }
    let prefix = if no_merge {
        ""
    } else {
        automerge_base.base_path()
    };
    let sep = if path.starts_with('/') { "" } else { "/" };
    format!("{}{prefix}{sep}{path}", base.root_url())
}

fn render_request(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> String {
    let mut out = format!("{method} {url} HTTP/1.1\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(&String::from_utf8_lossy(body));
    out
}

fn text_or_bytes(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) => Value::str(s),
        Err(_) => Value::Bytes(bytes.to_vec()),
    }
}

fn set_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let pair = v.split(';').next()?;
            let (name, value) = pair.split_once('=')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// The response-derived variables (no suffix).
fn response_vars(
    resp: &HttpResponseData,
    pending: &Pending,
    target: &HttpTarget,
    now: i64,
) -> Vars {
    let mut vars = Vars::new();
    let mut by_name: Vec<(String, Vec<&str>)> = Vec::new();
    for (k, v) in &resp.headers {
        let key = normalise_key(k);
        match by_name.iter_mut().find(|(n, _)| *n == key) {
            Some((_, values)) => values.push(v),
            None => by_name.push((key, vec![v])),
        }
    }
    for (name, values) in by_name {
        vars.insert(name, Value::from(values.join(", ")));
    }
    let header_text: String = resp
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let version = if resp.version.is_empty() {
        "HTTP/1.1"
    } else {
        &resp.version
    };
    let status_line = if resp.reason.is_empty() {
        format!("{version} {}", resp.status)
    } else {
        format!("{version} {} {}", resp.status, resp.reason)
    };
    let mut raw = format!("{status_line}\r\n{header_text}\r\n").into_bytes();
    raw.extend_from_slice(&resp.body);
    let content_length = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<i64>().ok())
        .unwrap_or(resp.body.len() as i64);
    let cookies: Vec<String> = set_cookies(&resp.headers)
        .into_iter()
        .map(|(n, v)| format!("{n}: {v}"))
        .collect();
    let headers_lines: Vec<String> = resp
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {v}", normalise_key(k)))
        .collect();
    let url = resp.url.clone().unwrap_or_else(|| pending.url.clone());

    let body = text_or_bytes(&resp.body);
    let raw_value = text_or_bytes(&raw);
    vars.insert("body".into(), body);
    for name in ["raw", "response", "all"] {
        vars.insert(name.into(), raw_value.clone());
    }
    let header_value = Value::from(header_text);
    vars.insert("header".into(), header_value.clone());
    vars.insert("all_headers".into(), header_value);
    vars.insert("status_code".into(), Value::Int(i64::from(resp.status)));
    vars.insert("content_length".into(), Value::Int(content_length));
    vars.insert("request".into(), Value::from(pending.request_text.clone()));
    vars.insert("host".into(), Value::from(target.host.clone()));
    vars.insert("url".into(), Value::from(url.clone()));
    vars.insert("matched".into(), Value::from(url));
    vars.insert(
        "duration".into(),
        Value::Float(resp.duration_ms as f64 / 1000.0),
    );
    vars.insert(
        "cookies_from_response".into(),
        Value::from(cookies.join("\n")),
    );
    vars.insert(
        "headers_from_response".into(),
        Value::from(headers_lines.join("\n")),
    );
    if let Some(tls) = &resp.tls {
        let mut parts = ResponseParts::new("body");
        insert_cert_parts(&mut parts, tls, now);
        vars.extend(parts.vars().iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    vars
}

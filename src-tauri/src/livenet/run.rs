//! The live-run orchestrator.
//!
//! For each target × template × applicable protocol:
//!
//! * **HTTP** runs against every target. A URL target is used as written. A
//!   bare `host` / `host:port` / IP target is probed once per run, like
//!   Nuclei's input normalisation: `GET https://host[:port]/` first, then
//!   `GET http://host[:port]/` (ports 443 and 80 when none was given); the
//!   first scheme that returns any HTTP response is used for every HTTP
//!   template against that target. Each probe is an ordinary governed,
//!   scope-checked request. If neither answers, the target's HTTP templates
//!   are not evaluated.
//! * **DNS** runs against targets that are host names (an IP target is not
//!   evaluated for DNS). DNS templates run even when the name did not
//!   resolve, since `NXDOMAIN` is often what they look for.
//! * **TCP** and **SSL** run against `host[:port]`; a URL target contributes
//!   its port (explicit, or the scheme's default; SSL uses 443 for an
//!   `http://` URL without a port).
//!
//! Work runs on a dedicated thread with a current-thread runtime, because
//! the template crate's HTTP state machine is not `Send`. `run_live` itself
//! returns a `Send` future. Dropping that future does not stop the run: set
//! `cancel` for that. Pairs run with bounded concurrency
//! ([`PAIR_CONCURRENCY`]) under the governor's per-host and rate limits.
//! Cancellation is checked before every outbound attempt. A target with
//! `max_host_errors` consecutive connection failures is marked unreachable
//! and its remaining templates are not evaluated. Per-template errors never
//! abort the run.
//!
//! Coverage honesty: a planner cap that cut a template's requests short (see
//! `oxaudit_nuclei::Truncation`) becomes a not-evaluated row naming what was
//! sent and is counted in [`LiveRunOutput::truncated`]; a target for which no
//! request of any template was answered (connection failures, protocol
//! errors, skipped requests, or no applicable template) is listed in
//! [`LiveRunOutput::unreachable_targets`]; and [`LiveRunOutput::evaluated`]
//! counts the template × target × protocol checks that got at least one
//! answer, so a caller can tell "nothing matched" from "nothing was
//! evaluated".

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use oxaudit_domain::NetworkExchangeEvidence;
use oxaudit_nuclei::{
    dns_truncations, evaluate_dns, evaluate_ssl, evaluate_tcp, plan_dns, plan_ssl, plan_tcp,
    tcp_truncations, DnsTarget, HttpRequestSpec, HttpRun, HttpTarget, Protocol, RedirectMode,
    RedirectPolicy, RunLimits, TcpTarget, Template, TemplateMatch, Truncation, XorShiftContext,
};

use super::dns::{execute_dns, DnsQuerier, SystemDns};
use super::exchange;
use super::http::{build_client, CookieJar, HttpExecutor};
use super::limits::{Governor, Halt, LiveLimits};
use super::resolve::{pin_hosts, HostResolver, SystemResolver};
use super::scope::{HostId, Refusal, ScanTarget, Scope, TargetKind};
use super::ssl::execute_ssl;
use super::tcp::execute_tcp;
use super::{BoxFuture, Net, NetFailure};

/// Template × target pairs in flight at once.
pub(crate) const PAIR_CONCURRENCY: usize = 25;
/// Entries kept in `not_evaluated`; the rest are counted in a note.
pub(crate) const MAX_NOT_EVALUATED: usize = 10_000;
/// Distinct refused hosts kept.
pub(crate) const MAX_REFUSED_HOSTS: usize = 100;
/// Distinct template evaluation warnings (matcher errors and the like) kept
/// as run notes; the rest are counted in one note.
pub(crate) const MAX_TEMPLATE_WARNINGS: usize = 200;

#[derive(Clone)]
pub(crate) struct LiveTemplate {
    pub template: Arc<Template>,
    pub pack: String,
    pub file: String,
}

pub(crate) struct LiveRunInput<'a> {
    pub templates: &'a [LiveTemplate],
    pub scope: Scope,
    pub limits: LiveLimits,
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<dyn Fn(LiveProgress) + Send + Sync>,
    pub user_agent_version: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveProgress {
    pub pairs_total: usize,
    pub pairs_done: usize,
    pub requests_sent: u64,
    pub matches: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct LiveMatch {
    pub template_id: String,
    pub pack: String,
    pub file: String,
    /// The target as typed.
    pub target: String,
    pub protocol: Protocol,
    pub matched: TemplateMatch,
    /// Redacted, bounded request/response excerpts. `artifact_id` is a
    /// deterministic per-target id (`artifact_live_<hash>`); the caller may
    /// replace it.
    pub evidence: Option<NetworkExchangeEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveNotEvaluated {
    pub template_id: String,
    pub pack: String,
    pub file: String,
    /// `None` for a template-level reason (unsupported, `dos`, no network
    /// protocol).
    pub protocol: Option<Protocol>,
    /// The target as typed, or `*` for a template-level reason.
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LiveRunOutput {
    pub matches: Vec<LiveMatch>,
    pub not_evaluated: Vec<LiveNotEvaluated>,
    pub requests_sent: u64,
    pub requests_refused: u64,
    /// Distinct refused hosts (host only, never a URL), capped.
    pub refused_hosts: Vec<String>,
    /// Every pinned name and the addresses used for it.
    pub resolved: Vec<(String, Vec<IpAddr>)>,
    /// Targets that could not be resolved or stopped answering.
    pub unreachable_targets: Vec<(String, String)>,
    /// Why the run did not finish (cancelled, out of budget, ...). Empty
    /// when every pair was attempted.
    pub incomplete_reasons: Vec<String>,
    /// Template × target × protocol checks that got at least one answer.
    /// Zero means nothing was evaluated, whatever else happened.
    pub evaluated: usize,
    /// Checks a planner cap cut short (each is also a not-evaluated row).
    pub truncated: usize,
    /// Set when the run stopped sending early: the halt and the exact entry
    /// of `incomplete_reasons` that describes it, so a caller can tell a
    /// cancellation and an exhausted request budget from other reasons
    /// without parsing text.
    pub halted: Option<(Halt, String)>,
    pub notes: Vec<String>,
}

/// Injectable network dependencies (tests use stubs; the product uses the
/// system resolver).
#[derive(Clone)]
pub(crate) struct NetDeps {
    pub resolver: Arc<dyn HostResolver>,
    pub dns: Arc<dyn DnsQuerier>,
}

/// Runs the templates against the scope's targets.
pub(crate) async fn run_live(input: LiveRunInput<'_>) -> LiveRunOutput {
    run_live_with(input, None).await
}

struct OwnedInput {
    templates: Vec<LiveTemplate>,
    scope: Scope,
    limits: LiveLimits,
    cancel: Arc<AtomicBool>,
    progress: Arc<dyn Fn(LiveProgress) + Send + Sync>,
    version: String,
}

fn failed(reason: String) -> LiveRunOutput {
    LiveRunOutput {
        incomplete_reasons: vec![reason],
        ..LiveRunOutput::default()
    }
}

pub(crate) async fn run_live_with(input: LiveRunInput<'_>, deps: Option<NetDeps>) -> LiveRunOutput {
    let owned = OwnedInput {
        templates: input.templates.to_vec(),
        scope: input.scope,
        limits: input.limits,
        cancel: input.cancel,
        progress: input.progress,
        version: input.user_agent_version.to_string(),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("oxaudit-livenet".into())
        .spawn(move || {
            let out = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(execute(owned, deps)),
                Err(e) => failed(format!("cannot start the live scan runtime: {e}")),
            };
            let _ = tx.send(out);
        });
    if let Err(e) = spawned {
        return failed(format!("cannot start the live scan thread: {e}"));
    }
    rx.await
        .unwrap_or_else(|_| failed("the live scan stopped unexpectedly".into()))
}

/// Resolver used when the system configuration cannot be read: every
/// lookup fails, so names become "could not resolve", never a guess.
struct Unavailable(String);

impl HostResolver for Unavailable {
    fn lookup_ip<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        let m = self.0.clone();
        Box::pin(async move { Err(m) })
    }
}

impl DnsQuerier for Unavailable {
    fn query<'a>(
        &'a self,
        _name: &'a str,
        _qtype: oxaudit_nuclei::model::DnsType,
    ) -> BoxFuture<'a, Result<oxaudit_nuclei::DnsResponseData, String>> {
        let m = self.0.clone();
        Box::pin(async move { Err(m) })
    }
}

fn system_deps(limits: &LiveLimits) -> NetDeps {
    let resolver: Arc<dyn HostResolver> = match SystemResolver::new(limits.timeout) {
        Ok(r) => Arc::new(r),
        Err(e) => Arc::new(Unavailable(e)),
    };
    let dns: Arc<dyn DnsQuerier> = match SystemDns::new(limits.timeout) {
        Ok(d) => Arc::new(d),
        Err(e) => Arc::new(Unavailable(e)),
    };
    NetDeps { resolver, dns }
}

struct TargetState {
    failures: Cell<u32>,
    /// Some connection to this target succeeded during the run.
    reached: Cell<bool>,
    /// Connection failures over the whole run (not reset by a success) and
    /// the last one's message.
    failures_total: Cell<u32>,
    last_failure: RefCell<Option<String>>,
    /// Some request of some template against this target was answered.
    answered: Cell<bool>,
    /// The last failure of any kind (connection, exchange, unsupported...).
    last_any_failure: RefCell<Option<String>>,
    /// Mirrors `unreachable` for attempts queued at the governor.
    dead: Arc<AtomicBool>,
    unreachable: RefCell<Option<String>>,
    http_base: tokio::sync::OnceCell<Result<HttpTarget, String>>,
}

#[derive(Default)]
struct Collect {
    matches: Vec<LiveMatch>,
    not_evaluated: Vec<LiveNotEvaluated>,
    seen: HashSet<(String, String, Option<Protocol>, String, String)>,
    overflow: usize,
    refused: u64,
    refused_hosts: BTreeSet<String>,
    notes: Vec<String>,
    unreachable: Vec<(String, String)>,
    evaluated: usize,
    truncated: usize,
    template_warnings: Vec<String>,
    template_warnings_dropped: usize,
}

struct State<'r> {
    net: Net,
    http: Option<HttpExecutor>,
    dns: Arc<dyn DnsQuerier>,
    targets: Vec<ScanTarget>,
    per_target: Vec<TargetState>,
    out: RefCell<Collect>,
    progress: &'r Arc<dyn Fn(LiveProgress) + Send + Sync>,
    pairs_total: usize,
    pairs_done: Cell<usize>,
    seed: Cell<u64>,
    now: i64,
}

impl State<'_> {
    fn ctx(&self) -> XorShiftContext {
        let s = self
            .seed
            .get()
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.seed.set(s);
        XorShiftContext::new(s, self.now)
    }

    fn note(&self, note: impl Into<String>) {
        let note = note.into();
        let mut out = self.out.borrow_mut();
        if !out.notes.contains(&note) && out.notes.len() < 1000 {
            out.notes.push(note);
        }
    }

    fn not_evaluated(
        &self,
        lt: &LiveTemplate,
        protocol: Option<Protocol>,
        target: &str,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        let mut out = self.out.borrow_mut();
        let key = (
            lt.template.id.clone(),
            lt.file.clone(),
            protocol,
            target.to_string(),
            reason.clone(),
        );
        if !out.seen.insert(key) {
            return;
        }
        if out.not_evaluated.len() >= MAX_NOT_EVALUATED {
            out.overflow += 1;
            return;
        }
        out.not_evaluated.push(LiveNotEvaluated {
            template_id: lt.template.id.clone(),
            pack: lt.pack.clone(),
            file: lt.file.clone(),
            protocol,
            target: target.to_string(),
            reason,
        });
    }

    /// A planner cap cut this check short: listed as partly evaluated.
    fn truncation(&self, lt: &LiveTemplate, target: &str, truncation: &Truncation) {
        self.out.borrow_mut().truncated += 1;
        self.not_evaluated(
            lt,
            Some(truncation.protocol),
            target,
            format!("partly evaluated: {}", truncation.message),
        );
    }

    /// An evaluation problem reported by the template engine (a matcher that
    /// could not be evaluated, for example). Deduplicated and capped.
    fn template_warning(&self, lt: &LiveTemplate, warning: &str) {
        let note = format!("{} ({}): {warning}", lt.template.id, lt.file);
        let mut out = self.out.borrow_mut();
        if out.template_warnings.contains(&note) {
            return;
        }
        if out.template_warnings.len() >= MAX_TEMPLATE_WARNINGS {
            out.template_warnings_dropped += 1;
            return;
        }
        out.template_warnings.push(note);
    }

    /// One request of a check against target `ti` was answered.
    fn answered(&self, ti: usize) {
        self.per_target[ti].answered.set(true);
    }

    /// A check finished with at least one answer.
    fn evaluated(&self) {
        self.out.borrow_mut().evaluated += 1;
    }

    fn refused(&self, r: &Refusal) {
        let mut out = self.out.borrow_mut();
        out.refused += 1;
        if out.refused_hosts.len() < MAX_REFUSED_HOSTS {
            out.refused_hosts.insert(r.host.clone());
        }
    }

    fn add_match(
        &self,
        lt: &LiveTemplate,
        target: &ScanTarget,
        protocol: Protocol,
        mut matched: TemplateMatch,
        request: (String, bool),
        response: (String, bool),
    ) {
        // A URL may carry a secret in its query string.
        matched.matched_at = exchange::redact_url(&matched.matched_at, false);
        let evidence = exchange::evidence(
            protocol.as_str(),
            &target.input,
            request,
            response,
            &matched,
        );
        self.out.borrow_mut().matches.push(LiveMatch {
            template_id: lt.template.id.clone(),
            pack: lt.pack.clone(),
            file: lt.file.clone(),
            target: target.input.clone(),
            protocol,
            matched,
            evidence: Some(evidence),
        });
    }

    fn unreachable(&self, ti: usize) -> Option<String> {
        self.per_target[ti].unreachable.borrow().clone()
    }

    fn connect_ok(&self, ti: usize) {
        self.per_target[ti].failures.set(0);
        self.per_target[ti].reached.set(true);
    }

    fn connect_failed(&self, ti: usize, message: &str) {
        let t = &self.per_target[ti];
        let n = t.failures.get().saturating_add(1);
        t.failures.set(n);
        t.failures_total
            .set(t.failures_total.get().saturating_add(1));
        *t.last_failure.borrow_mut() = Some(message.to_string());
        if n >= self.net.limits.max_host_errors && t.unreachable.borrow().is_none() {
            let reason = format!(
                "{n} consecutive connection failures (last: {message}); remaining templates were not evaluated"
            );
            *t.unreachable.borrow_mut() = Some(reason.clone());
            t.dead.store(true, Ordering::SeqCst);
            self.out
                .borrow_mut()
                .unreachable
                .push((self.targets[ti].input.clone(), reason));
        }
    }

    /// Records a failure of one attempt. Returns true when the pair must
    /// stop (the run is halting).
    fn failure(&self, ti: usize, f: &NetFailure, last: &mut Option<String>) -> bool {
        match f {
            NetFailure::Halted(_) => return true,
            NetFailure::Refused(r) => self.refused(r),
            NetFailure::Connect(m) => self.connect_failed(ti, m),
            _ => {}
        }
        *last = Some(f.to_string());
        *self.per_target[ti].last_any_failure.borrow_mut() = Some(f.to_string());
        false
    }

    /// The unresolved reason for a name target, if it did not resolve.
    fn unresolved(&self, target: &ScanTarget) -> Option<String> {
        match &target.host {
            HostId::Name(n) => self
                .net
                .pinned
                .addresses_for(&HostId::Name(n.clone()))
                .err()
                .map(|m| format!("could not resolve {n}: {m}")),
            HostId::Ip(_) => None,
        }
    }

    /// The pair cannot start or continue: the run is halting or the target
    /// stopped answering.
    fn blocked(&self, ti: usize) -> Option<String> {
        if let Some(h) = self.net.gov.halted() {
            return Some(format!("not evaluated: {h}"));
        }
        self.unreachable(ti)
            .map(|u| format!("target unreachable: {u}"))
    }

    /// The run's `Net` with this target's unreachable flag.
    fn target_net(&self, ti: usize) -> Net {
        Net {
            abort: Some(self.per_target[ti].dead.clone()),
            ..self.net.clone()
        }
    }

    fn progress(&self) {
        let matches = self.out.borrow().matches.len();
        (self.progress)(LiveProgress {
            pairs_total: self.pairs_total,
            pairs_done: self.pairs_done.get(),
            requests_sent: self.net.gov.sent(),
            matches,
        });
    }
}

fn probe_spec(url: String) -> HttpRequestSpec {
    HttpRequestSpec {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
        follow_redirects: RedirectPolicy {
            mode: RedirectMode::None,
            max: 0,
        },
        cookie_reuse: false,
        request_index: 0,
        step: 0,
        payload_values: Vec::new(),
        max_response_bytes: Some(1024),
        timeout_ms: None,
        tls_sni: None,
    }
}

/// The HTTP base of a target, probed once per run for a bare host.
async fn http_base(state: &State<'_>, net: &Net, ti: usize) -> Result<HttpTarget, String> {
    let target = &state.targets[ti];
    if let TargetKind::Url { scheme, path } = &target.kind {
        return Ok(HttpTarget {
            scheme: scheme.clone(),
            host: target.host.key(),
            port: target.port,
            path: path.clone(),
        });
    }
    let Some(http) = &state.http else {
        return Err("the HTTP client is unavailable".into());
    };
    let mut errors = Vec::new();
    for (scheme, default_port) in [("https", 443u16), ("http", 80)] {
        let port = target.port.unwrap_or(default_port);
        let url = format!("{scheme}://{}:{port}/", target.host.url_host());
        let ex = http
            .execute(net, &probe_spec(url), &mut CookieJar::default())
            .await;
        for r in &ex.refused {
            state.refused(r);
        }
        match ex.outcome {
            Ok(_) => {
                state.connect_ok(ti);
                return Ok(HttpTarget {
                    scheme: scheme.into(),
                    host: target.host.key(),
                    port: target.port,
                    path: String::new(),
                });
            }
            Err(NetFailure::Halted(h)) => return Err(format!("not evaluated: {h}")),
            Err(f) => {
                let mut last = None;
                state.failure(ti, &f, &mut last);
                errors.push(format!("{scheme}: {f}"));
            }
        }
    }
    Err(format!(
        "no HTTP service answered on https or http ({})",
        errors.join("; ")
    ))
}

async fn run_http(state: &State<'_>, net: &Net, ti: usize, lt: &LiveTemplate) {
    let target = &state.targets[ti];
    let proto = Some(Protocol::Http);
    if let Some(u) = state.unresolved(target) {
        state.not_evaluated(lt, proto, &target.input, u);
        return;
    }
    if let Some(b) = state.blocked(ti) {
        state.not_evaluated(lt, proto, &target.input, b);
        return;
    }
    let Some(http) = &state.http else {
        state.not_evaluated(lt, proto, &target.input, "the HTTP client is unavailable");
        return;
    };
    let base = state.per_target[ti]
        .http_base
        .get_or_init(|| http_base(state, net, ti))
        .await
        .clone();
    let base = match base {
        Ok(b) => b,
        Err(reason) => {
            state.not_evaluated(lt, proto, &target.input, reason);
            return;
        }
    };
    let mut run = HttpRun::new(&lt.template, base, Box::new(state.ctx()));
    let mut jar = CookieJar::default();
    let mut answered = 0usize;
    let mut stopped = false;
    let mut last: Option<String> = None;
    while let Some(step) = run.next_request() {
        if let Some(b) = state.blocked(ti) {
            state.not_evaluated(lt, proto, &target.input, b);
            return;
        }
        let spec = match step {
            Ok(spec) => spec,
            Err(skip) => {
                last.get_or_insert_with(|| format!("request skipped: {skip}"));
                continue;
            }
        };
        let ex = http.execute(net, &spec, &mut jar).await;
        for r in &ex.refused {
            state.refused(r);
        }
        for n in &ex.notes {
            state.note(format!("{} ({}): {n}", lt.template.id, lt.file));
        }
        match ex.outcome {
            Ok(resp) => {
                state.connect_ok(ti);
                state.answered(ti);
                answered += 1;
                let request = ex
                    .sent
                    .as_ref()
                    .map(exchange::render_http_request)
                    .unwrap_or_default();
                let response = exchange::render_http_response(&resp, ex.truncated);
                let outcome = run.on_response(resp);
                for warning in &outcome.warnings {
                    state.template_warning(lt, warning);
                }
                if outcome.matched {
                    if let Some(m) = run.matches().last().cloned() {
                        state.add_match(lt, target, Protocol::Http, m, request, response);
                    }
                }
                if outcome.stop {
                    stopped = true;
                    break;
                }
            }
            Err(f) => {
                if let NetFailure::Halted(h) = f {
                    state.not_evaluated(lt, proto, &target.input, format!("not evaluated: {h}"));
                    return;
                }
                state.failure(ti, &f, &mut last);
            }
        }
    }
    for warning in run.warnings() {
        state.template_warning(lt, warning);
    }
    if answered == 0 {
        let reason = last.unwrap_or_else(|| "the template produced no request".into());
        state.not_evaluated(lt, proto, &target.input, reason);
        return;
    }
    state.evaluated();
    if !stopped {
        for truncation in run.truncations() {
            state.truncation(lt, &target.input, truncation);
        }
    }
}

async fn run_dns(state: &State<'_>, net: &Net, ti: usize, lt: &LiveTemplate) {
    let target = &state.targets[ti];
    let proto = Some(Protocol::Dns);
    let Some(name) = target.host.name() else {
        state.not_evaluated(
            lt,
            proto,
            &target.input,
            "DNS templates need a host name target",
        );
        return;
    };
    if lt.template.dns.iter().any(|b| !b.recursion) {
        state.note(format!(
            "{} ({}): `recursion: false` is not honoured; the system resolver is asked to recurse",
            lt.template.id, lt.file
        ));
    }
    let dt = DnsTarget {
        fqdn: name.to_string(),
    };
    let mut ctx = state.ctx();
    let limits = RunLimits::default();
    let planned = plan_dns(&lt.template, &dt, &mut ctx, &limits);
    let mut answered = 0usize;
    let mut stopped = false;
    let mut last: Option<String> = None;
    for p in planned {
        if let Some(h) = state.net.gov.halted() {
            state.not_evaluated(lt, proto, &target.input, format!("not evaluated: {h}"));
            return;
        }
        let spec = match p.spec {
            Ok(s) => s,
            Err(skip) => {
                last.get_or_insert_with(|| format!("question skipped: {skip}"));
                continue;
            }
        };
        match execute_dns(net, state.dns.as_ref(), &spec).await {
            Ok(resp) => {
                state.answered(ti);
                answered += 1;
                if let Some(m) = evaluate_dns(&lt.template, &spec, &dt, &resp, &mut ctx) {
                    let request = exchange::render_dns_request(&spec);
                    let response = exchange::render_dns_response(&resp);
                    state.add_match(lt, target, Protocol::Dns, m, request, response);
                    if lt.template.stop_at_first_match {
                        stopped = true;
                        break;
                    }
                }
            }
            Err(f) => {
                if state.failure(ti, &f, &mut last) {
                    state.not_evaluated(lt, proto, &target.input, f.to_string());
                    return;
                }
            }
        }
    }
    if answered == 0 {
        let reason = last.unwrap_or_else(|| "the template asked no question".into());
        state.not_evaluated(lt, proto, &target.input, reason);
        return;
    }
    state.evaluated();
    if !stopped {
        for truncation in dns_truncations(&lt.template, &limits) {
            state.truncation(lt, &target.input, &truncation);
        }
    }
}

fn tcp_target(target: &ScanTarget, ssl: bool) -> TcpTarget {
    let port = match (&target.kind, ssl) {
        (TargetKind::Url { scheme, .. }, true) if target.port.is_none() && scheme == "http" => None,
        _ => target.network_port(),
    };
    TcpTarget {
        host: target.host.key(),
        port,
    }
}

async fn run_tcp(state: &State<'_>, net: &Net, ti: usize, lt: &LiveTemplate) {
    let target = &state.targets[ti];
    let proto = Some(Protocol::Tcp);
    if let Some(u) = state.unresolved(target) {
        state.not_evaluated(lt, proto, &target.input, u);
        return;
    }
    let tt = tcp_target(target, false);
    let mut ctx = state.ctx();
    let limits = RunLimits::default();
    let planned = plan_tcp(&lt.template, &tt, &mut ctx, &limits);
    let mut answered = 0usize;
    let mut stopped = false;
    let mut last: Option<String> = None;
    for p in planned {
        if let Some(b) = state.blocked(ti) {
            state.not_evaluated(lt, proto, &target.input, b);
            return;
        }
        let spec = match p.spec {
            Ok(s) => s,
            Err(skip) => {
                last.get_or_insert_with(|| format!("session skipped: {skip}"));
                continue;
            }
        };
        match execute_tcp(net, &spec).await {
            Ok(resp) => {
                state.connect_ok(ti);
                state.answered(ti);
                answered += 1;
                if let Some(m) = evaluate_tcp(&lt.template, &spec, &tt, &resp, &mut ctx) {
                    let request = exchange::render_tcp_request(&spec, &resp);
                    let response = exchange::render_tcp_response(&resp);
                    state.add_match(lt, target, Protocol::Tcp, m, request, response);
                    let block_stop = lt
                        .template
                        .tcp
                        .get(spec.request_index)
                        .is_some_and(|b| b.stop_at_first_match);
                    if lt.template.stop_at_first_match || block_stop {
                        stopped = true;
                        break;
                    }
                }
            }
            Err(f) => {
                if state.failure(ti, &f, &mut last) {
                    state.not_evaluated(lt, proto, &target.input, f.to_string());
                    return;
                }
            }
        }
    }
    if answered == 0 {
        let reason = last.unwrap_or_else(|| "the template opened no session".into());
        state.not_evaluated(lt, proto, &target.input, reason);
        return;
    }
    state.evaluated();
    if !stopped {
        for truncation in tcp_truncations(&lt.template, &limits) {
            state.truncation(lt, &target.input, &truncation);
        }
    }
}

async fn run_ssl(state: &State<'_>, net: &Net, ti: usize, lt: &LiveTemplate) {
    let target = &state.targets[ti];
    let proto = Some(Protocol::Ssl);
    if let Some(u) = state.unresolved(target) {
        state.not_evaluated(lt, proto, &target.input, u);
        return;
    }
    let tt = tcp_target(target, true);
    let mut ctx = state.ctx();
    let planned = plan_ssl(&lt.template, &tt, &mut ctx);
    let mut answered = 0usize;
    let mut last: Option<String> = None;
    for p in planned {
        if let Some(b) = state.blocked(ti) {
            state.not_evaluated(lt, proto, &target.input, b);
            return;
        }
        let spec = match p.spec {
            Ok(s) => s,
            Err(skip) => {
                last.get_or_insert_with(|| format!("probe skipped: {skip}"));
                continue;
            }
        };
        match execute_ssl(net, &spec).await {
            Ok(resp) => {
                state.connect_ok(ti);
                state.answered(ti);
                answered += 1;
                if let Some(m) = evaluate_ssl(&lt.template, &spec, &tt, &resp, &mut ctx) {
                    let request = exchange::render_ssl_request(&resp.host, spec.port);
                    let response = exchange::render_ssl_response(&resp);
                    state.add_match(lt, target, Protocol::Ssl, m, request, response);
                }
            }
            Err(f) => {
                if state.failure(ti, &f, &mut last) {
                    state.not_evaluated(lt, proto, &target.input, f.to_string());
                    return;
                }
            }
        }
    }
    if answered == 0 {
        let reason = last.unwrap_or_else(|| "the template made no probe".into());
        state.not_evaluated(lt, proto, &target.input, reason);
        return;
    }
    state.evaluated();
}

async fn run_pair(state: &State<'_>, ti: usize, lt: &LiveTemplate) {
    let net = state.target_net(ti);
    for proto in lt.template.protocols() {
        match proto {
            Protocol::Http => run_http(state, &net, ti, lt).await,
            Protocol::Dns => run_dns(state, &net, ti, lt).await,
            Protocol::Tcp => run_tcp(state, &net, ti, lt).await,
            Protocol::Ssl => run_ssl(state, &net, ti, lt).await,
            Protocol::File => {}
        }
    }
    state.pairs_done.set(state.pairs_done.get() + 1);
    state.progress();
}

/// Template-level filtering: what can run against live targets at all.
fn runnable(lt: &LiveTemplate, collect: &mut Vec<LiveNotEvaluated>) -> bool {
    let t = &lt.template;
    let mut skip = |protocol: Option<Protocol>, reason: String| {
        collect.push(LiveNotEvaluated {
            template_id: t.id.clone(),
            pack: lt.pack.clone(),
            file: lt.file.clone(),
            protocol,
            target: "*".into(),
            reason,
        });
    };
    if t.is_destructive() {
        skip(None, "templates tagged `dos` never run".into());
        return false;
    }
    if let oxaudit_nuclei::Support::NotEvaluated(reasons) = t.support() {
        skip(None, format!("not supported: {}", reasons.join("; ")));
        return false;
    }
    let protocols = t.protocols();
    if protocols.contains(&Protocol::File) {
        skip(
            Some(Protocol::File),
            "file blocks need a local path, not a live target".into(),
        );
    }
    if !protocols.iter().any(|p| *p != Protocol::File) {
        return false;
    }
    true
}

async fn execute(input: OwnedInput, deps: Option<NetDeps>) -> LiveRunOutput {
    let mut out = LiveRunOutput::default();
    out.notes.extend(input.scope.notes().iter().cloned());
    if let Err(e) = input.limits.validate() {
        out.incomplete_reasons.push(format!("invalid limits: {e}"));
        return out;
    }
    let limits = input.limits.clone();
    let deps = deps.unwrap_or_else(|| system_deps(&limits));
    let scope = Arc::new(input.scope);
    let proxy_host = limits.proxy.as_ref().and_then(|u| {
        u.host_str()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
    });
    let pinned = Arc::new(
        pin_hosts(
            &scope,
            deps.resolver.as_ref(),
            limits.timeout,
            proxy_host.as_deref(),
        )
        .await,
    );
    out.resolved = pinned.resolved();
    out.notes.extend(pinned.notes().iter().cloned());
    if let Some(p) = &proxy_host {
        out.notes.push(format!(
            "HTTP requests go through the configured proxy {p}. Scope is checked on every request URL, but the proxy resolves target names itself, so the pinned addresses do not bind HTTP requests. DNS, TCP and SSL templates connect directly."
        ));
    }
    let gov = Arc::new(Governor::new(&limits, input.cancel.clone()));
    let net = Net {
        scope: scope.clone(),
        pinned: pinned.clone(),
        gov: gov.clone(),
        limits: limits.clone(),
        abort: None,
    };
    let http = match build_client(pinned.clone(), &limits) {
        Ok(c) => Some(HttpExecutor::new(c, &input.version, limits.proxy.is_some())),
        Err(e) => {
            out.incomplete_reasons.push(e);
            None
        }
    };

    let targets: Vec<ScanTarget> = scope.targets().to_vec();
    let mut template_level = Vec::new();
    let templates: Vec<&LiveTemplate> = input
        .templates
        .iter()
        .filter(|lt| runnable(lt, &mut template_level))
        .collect();

    for t in &targets {
        if let HostId::Name(n) = &t.host {
            if let Some(f) = pinned.failure(n) {
                out.unreachable_targets
                    .push((t.input.clone(), format!("could not resolve {n}: {f}")));
            }
        }
    }

    let pairs: Vec<(usize, &LiveTemplate)> = (0..targets.len())
        .flat_map(|ti| templates.iter().map(move |lt| (ti, *lt)))
        .collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    let state = State {
        net,
        http,
        dns: deps.dns.clone(),
        per_target: targets
            .iter()
            .map(|_| TargetState {
                failures: Cell::new(0),
                reached: Cell::new(false),
                failures_total: Cell::new(0),
                last_failure: RefCell::new(None),
                answered: Cell::new(false),
                last_any_failure: RefCell::new(None),
                dead: Arc::new(AtomicBool::new(false)),
                unreachable: RefCell::new(None),
                http_base: tokio::sync::OnceCell::new(),
            })
            .collect(),
        targets,
        out: RefCell::new(Collect::default()),
        progress: &input.progress,
        pairs_total: pairs.len(),
        pairs_done: Cell::new(0),
        seed: Cell::new(seed),
        now,
    };
    state.progress();

    futures::stream::iter(pairs)
        .for_each_concurrent(PAIR_CONCURRENCY, |(ti, lt)| {
            let state = &state;
            async move {
                if let Some(h) = state.net.gov.halted() {
                    // Not started: listed so the outcome stays honest.
                    let target = &state.targets[ti];
                    for p in lt.template.protocols() {
                        if p != Protocol::File {
                            state.not_evaluated(
                                lt,
                                Some(p),
                                &target.input,
                                format!("not evaluated: {h}"),
                            );
                        }
                    }
                    return;
                }
                run_pair(state, ti, lt).await;
            }
        })
        .await;

    // A target that was tried but never answered a single connection is
    // unreachable even when it stayed under the consecutive-failure
    // cut-off (a run with only a few requests per target never reaches it).
    // A target for which no request of any template was answered (protocol
    // errors, skipped requests, or no template that applies to it) was not
    // evaluated at all and is listed too, unless the run halted, in which
    // case its checks already carry the halt as their reason.
    let run_halted = matches!(gov.halted(), Some(Halt::Cancelled | Halt::BudgetExhausted));
    for (ti, t) in state.per_target.iter().enumerate() {
        let input = &state.targets[ti].input;
        let listed = t.unreachable.borrow().is_some()
            || out
                .unreachable_targets
                .iter()
                .any(|(target, _)| target == input);
        if listed {
            continue;
        }
        let reason = if !t.reached.get() && t.failures_total.get() > 0 {
            let last = t.last_failure.borrow().clone().unwrap_or_default();
            format!(
                "no connection to this target succeeded ({} connection failure(s); last: {last})",
                t.failures_total.get()
            )
        } else if !t.answered.get() && !run_halted && !templates.is_empty() {
            match t.last_any_failure.borrow().as_deref() {
                Some(last) => format!(
                    "no request of any template was answered (last failure: {last})"
                ),
                None => "no request of any template was answered; every check was skipped or does not apply to this target (each is listed as not evaluated)".to_owned(),
            }
        } else {
            continue;
        };
        state
            .out
            .borrow_mut()
            .unreachable
            .push((input.clone(), reason));
    }
    let collect = state.out.into_inner();
    let done = state.pairs_done.get();
    let halt_reason = match gov.halted() {
        Some(Halt::Cancelled) => Some((
            Halt::Cancelled,
            format!(
                "the run was cancelled; {done} of {} template-target pairs finished",
                state.pairs_total
            ),
        )),
        Some(Halt::BudgetExhausted) => Some((
            Halt::BudgetExhausted,
            format!(
                "the request budget of {} requests was reached; {done} of {} template-target pairs finished",
                limits.max_requests, state.pairs_total
            ),
        )),
        Some(Halt::TargetUnreachable) | None => None,
    };
    if let Some((halt, reason)) = halt_reason {
        out.incomplete_reasons.push(reason.clone());
        out.halted = Some((halt, reason));
    }
    out.matches = collect.matches;
    out.not_evaluated = template_level;
    out.not_evaluated.extend(collect.not_evaluated);
    if collect.overflow > 0 {
        out.notes.push(format!(
            "{} further not-evaluated entries were not listed",
            collect.overflow
        ));
    }
    out.requests_sent = gov.sent();
    out.requests_refused = collect.refused;
    out.refused_hosts = collect.refused_hosts.into_iter().collect();
    out.unreachable_targets.extend(collect.unreachable);
    out.notes.extend(collect.notes);
    out.notes.extend(collect.template_warnings);
    if collect.template_warnings_dropped > 0 {
        out.notes.push(format!(
            "{} further template evaluation warnings were not listed",
            collect.template_warnings_dropped
        ));
    }
    out.evaluated = collect.evaluated;
    out.truncated = collect.truncated;
    out
}

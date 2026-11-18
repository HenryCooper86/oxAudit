//! Loopback servers, resolver stubs and template fixtures for the livenet
//! tests. Nothing here touches an external network.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oxaudit_nuclei::model::DnsType;
use oxaudit_nuclei::{DnsResponseData, LoadLimits, Template};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::livenet::dns::{response_data, DnsQuerier};
use crate::livenet::limits::{Governor, LiveLimits};
use crate::livenet::resolve::{pin_hosts, HostResolver, PinnedHosts};
use crate::livenet::run::{run_live_with, LiveRunInput, LiveRunOutput, LiveTemplate, NetDeps};
use crate::livenet::scope::{Scope, ScopeLimits};
use crate::livenet::{BoxFuture, Net};

pub(super) const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ------------------------------------------------------------- templates

/// A template with the given protocol body.
pub(super) fn template(id: &str, body: &str) -> LiveTemplate {
    let yaml = format!("id: {id}\ninfo:\n  name: Livenet test {id}\n  severity: medium\n{body}");
    let template = Template::load(&yaml, "test", LoadLimits::default()).expect("template loads");
    assert!(
        template.is_supported(),
        "fixture must be supported: {:?}",
        template.support()
    );
    LiveTemplate {
        template: Arc::new(template),
        pack: "test-pack".into(),
        file: format!("{id}.yaml"),
    }
}

/// `count` copies of a simple GET template with distinct ids.
pub(super) fn get_templates(count: usize, path: &str) -> Vec<LiveTemplate> {
    (0..count)
        .map(|i| {
            template(
                &format!("get-{i}"),
                &format!(
                    "http:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}{path}\"\n    matchers:\n      - type: status\n        status: [200]\n"
                ),
            )
        })
        .collect()
}

pub(super) fn scope(targets: &[String]) -> Scope {
    Scope::parse(targets, ScopeLimits::default()).expect("scope parses")
}

// -------------------------------------------------------------- stubs

/// A resolver stub: `first` answers for the first lookup of a name, `later`
/// (if set) for any further lookup. Counts lookups per name.
#[derive(Default)]
pub(super) struct StubResolver {
    pub first: HashMap<String, Vec<IpAddr>>,
    pub later: HashMap<String, Vec<IpAddr>>,
    pub calls: Mutex<HashMap<String, usize>>,
}

impl StubResolver {
    pub(super) fn with(names: &[(&str, IpAddr)]) -> Self {
        let mut s = StubResolver::default();
        for (n, ip) in names {
            s.first.entry((*n).to_string()).or_default().push(*ip);
        }
        s
    }

    pub(super) fn calls(&self, name: &str) -> usize {
        self.calls
            .lock()
            .expect("lock")
            .get(name)
            .copied()
            .unwrap_or(0)
    }
}

impl HostResolver for StubResolver {
    fn lookup_ip<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        let n = {
            let mut calls = self.calls.lock().expect("lock");
            let c = calls.entry(name.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        let answer = if n > 1 {
            self.later.get(name).or_else(|| self.first.get(name))
        } else {
            self.first.get(name)
        }
        .cloned();
        Box::pin(async move { answer.ok_or_else(|| "NXDOMAIN (stub)".to_string()) })
    }
}

/// A DNS stub answering from a table and recording every question.
#[derive(Default)]
pub(super) struct StubDns {
    pub answers: HashMap<(String, &'static str), Vec<String>>,
    pub asked: Mutex<Vec<String>>,
}

impl DnsQuerier for StubDns {
    fn query<'a>(
        &'a self,
        name: &'a str,
        qtype: DnsType,
    ) -> BoxFuture<'a, Result<DnsResponseData, String>> {
        self.asked.lock().expect("lock").push(name.to_string());
        let answers = self
            .answers
            .get(&(name.to_string(), qtype.as_str()))
            .cloned();
        Box::pin(async move {
            Ok(match answers {
                Some(a) => response_data(name, qtype, "NOERROR", a, Vec::new(), Vec::new()),
                None => response_data(name, qtype, "NXDOMAIN", Vec::new(), Vec::new(), Vec::new()),
            })
        })
    }
}

pub(super) fn deps(resolver: Arc<StubResolver>, dns: Arc<StubDns>) -> NetDeps {
    NetDeps { resolver, dns }
}

pub(super) fn plain_deps() -> NetDeps {
    deps(
        Arc::new(StubResolver::default()),
        Arc::new(StubDns::default()),
    )
}

pub(super) fn fast_limits() -> LiveLimits {
    LiveLimits {
        requests_per_second: 1000,
        timeout: Duration::from_secs(5),
        ..LiveLimits::default()
    }
}

/// Runs templates against targets with injected network dependencies.
pub(super) async fn run(
    templates: &[LiveTemplate],
    targets: &[String],
    limits: LiveLimits,
    deps: NetDeps,
) -> LiveRunOutput {
    run_with_cancel(
        templates,
        targets,
        limits,
        deps,
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

pub(super) async fn run_with_cancel(
    templates: &[LiveTemplate],
    targets: &[String],
    limits: LiveLimits,
    deps: NetDeps,
    cancel: Arc<AtomicBool>,
) -> LiveRunOutput {
    run_live_with(
        LiveRunInput {
            templates,
            scope: scope(targets),
            limits,
            cancel,
            progress: Arc::new(|_| {}),
            user_agent_version: "9.9.9-test",
        },
        Some(deps),
    )
    .await
}

/// A `Net` for calling an executor directly.
pub(super) async fn net(targets: &[String], limits: LiveLimits, resolver: &StubResolver) -> Net {
    let scope = Arc::new(scope(targets));
    let pinned: Arc<PinnedHosts> =
        Arc::new(pin_hosts(&scope, resolver, limits.timeout, None).await);
    Net {
        scope,
        pinned,
        gov: Arc::new(Governor::new(&limits, Arc::new(AtomicBool::new(false)))),
        limits,
        abort: None,
    }
}

// ------------------------------------------------------------ servers

/// One request a test server received.
#[derive(Debug, Clone)]
pub(super) struct Seen {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub(super) struct Reply {
    pub bytes: Vec<u8>,
    pub delay: Duration,
}

impl Reply {
    pub(super) fn now(bytes: Vec<u8>) -> Self {
        Reply {
            bytes,
            delay: Duration::ZERO,
        }
    }
}

/// An HTTP/1.1 response with `Content-Length` and `Connection: close`.
pub(super) fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A loopback HTTP server. Records every request and the peak number of
/// requests handled at once.
pub(super) struct TestServer {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub max_in_flight: Arc<AtomicUsize>,
}

impl TestServer {
    pub(super) fn port(&self) -> u16 {
        self.addr.port()
    }

    pub(super) fn hits(&self) -> usize {
        self.seen.lock().expect("lock").len()
    }

    pub(super) fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

pub(super) async fn serve(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let handler: Handler = Arc::new(handler);
    {
        let (seen, max_in_flight) = (seen.clone(), max_in_flight.clone());
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (seen, handler, in_flight, max_in_flight) = (
                    seen.clone(),
                    handler.clone(),
                    in_flight.clone(),
                    max_in_flight.clone(),
                );
                tokio::spawn(async move {
                    handle(sock, seen, handler, in_flight, max_in_flight).await;
                });
            }
        });
    }
    TestServer {
        addr,
        seen,
        max_in_flight,
    }
}

async fn handle(
    mut sock: TcpStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    handler: Handler,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return;
        }
        match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
        // A TLS ClientHello on this plain-HTTP port: hang up at once.
        if buf.first() == Some(&0x16) {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let request = Seen {
        method,
        path,
        headers,
        body,
    };
    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    max_in_flight.fetch_max(now, Ordering::SeqCst);
    seen.lock().expect("lock").push(request.clone());
    let reply = handler(&request);
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let _ = sock.write_all(&reply.bytes).await;
    let _ = sock.shutdown().await;
    in_flight.fetch_sub(1, Ordering::SeqCst);
}

/// A listener that must never be contacted: it only counts connections.
pub(super) struct Tripwire {
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
}

impl Tripwire {
    pub(super) fn port(&self) -> u16 {
        self.addr.port()
    }

    pub(super) fn contacts(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

pub(super) async fn tripwire() -> Tripwire {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((_sock, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    Tripwire { addr, accepted }
}

/// A loopback port with nothing listening on it.
pub(super) async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

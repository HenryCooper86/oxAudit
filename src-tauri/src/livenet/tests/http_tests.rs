use std::sync::Arc;
use std::time::{Duration, Instant};

use oxaudit_nuclei::{HttpRequestSpec, Protocol, RedirectMode, RedirectPolicy};

use super::support::*;
use crate::livenet::http::{build_client, CookieJar, HttpExecutor};
use crate::livenet::limits::LiveLimits;
use crate::livenet::NetFailure;

fn spec(url: String) -> HttpRequestSpec {
    HttpRequestSpec {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
        follow_redirects: RedirectPolicy {
            mode: RedirectMode::None,
            max: 0,
        },
        cookie_reuse: true,
        request_index: 0,
        step: 1,
        payload_values: Vec::new(),
        max_response_bytes: None,
        timeout_ms: None,
        tls_sni: None,
    }
}

async fn executor(
    targets: &[String],
    limits: LiveLimits,
    resolver: &StubResolver,
) -> (crate::livenet::Net, HttpExecutor) {
    let net = net(targets, limits, resolver).await;
    let client = build_client(net.pinned.clone(), &net.limits).expect("client");
    (net, HttpExecutor::new(client, "9.9.9-test", false))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_matching_template_yields_a_match_with_redacted_evidence() {
    let server = serve(|req| {
        if req.path == "/probe" {
            Reply::now(response(
                200,
                &[
                    ("Set-Cookie", "session=server-secret; HttpOnly"),
                    ("Server", "loopback"),
                ],
                b"hello oxaudit-canary",
            ))
        } else {
            Reply::now(response(404, &[], b"no"))
        }
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let t = template(
        "canary",
        concat!(
            "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/probe\"\n",
            "    headers:\n      Authorization: Bearer client-secret\n",
            "    matchers:\n      - type: word\n        words: [\"oxaudit-canary\"]\n",
            "      - type: word\n        part: header\n        words: [\"Server: loopback\"]\n",
            "    matchers-condition: and\n",
        ),
    );
    let out = run(
        &[t],
        std::slice::from_ref(&target),
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(out.matches.len(), 1, "{out:?}");
    let m = &out.matches[0];
    assert_eq!(m.protocol, Protocol::Http);
    assert_eq!(m.target, target);
    assert_eq!(m.pack, "test-pack");
    let ev = m.evidence.as_ref().expect("evidence");
    assert_eq!(ev.protocol, "http");
    assert!(
        ev.request.contains("GET http://127.0.0.1:"),
        "{}",
        ev.request
    );
    assert!(ev.request.contains("Authorization: [REDACTED]"));
    assert!(!ev.request.contains("client-secret"));
    assert!(ev.response_excerpt.contains("Set-Cookie: [REDACTED]"));
    assert!(!ev.response_excerpt.contains("server-secret"));
    assert!(ev.response_excerpt.contains("hello oxaudit-canary"));
    assert!(ev.artifact_id.as_str().starts_with("artifact_live_"));

    let seen = server.requests();
    assert_eq!(seen.len(), 1);
    let ua = seen[0].header("user-agent").expect("ua");
    assert_eq!(ua, "oxAudit/9.9.9-test (authorized security scan)");
    assert_eq!(seen[0].header("accept"), Some("*/*"));
    assert_eq!(seen[0].header("accept-language"), Some("en"));
    assert_eq!(
        seen[0].header("authorization"),
        Some("Bearer client-secret")
    );
    assert_eq!(out.requests_sent, 1);
    assert_eq!(out.requests_refused, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_off_scope_redirect_is_not_followed() {
    let trip = tripwire().await;
    let other_port = trip.port();
    let server = serve(move |req| {
        let to = match req.path.as_str() {
            "/ip" => format!("http://127.0.0.1:{other_port}/stolen"),
            "/name" => format!("http://evil.test:{other_port}/stolen"),
            "/meta" => "http://169.254.169.254/latest/meta-data/".to_string(),
            _ => "/".to_string(),
        };
        Reply::now(response(302, &[("Location", &to)], b"moved"))
    })
    .await;
    let target = format!("http://app.test:{}", server.port());
    let resolver = Arc::new(StubResolver::with(&[
        ("app.test", LOOPBACK),
        ("evil.test", LOOPBACK),
    ]));
    let t = template(
        "redir",
        concat!(
            "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/ip\"\n      - \"{{BaseURL}}/name\"\n      - \"{{BaseURL}}/meta\"\n",
            "    redirects: true\n    max-redirects: 5\n",
            "    matchers:\n      - type: status\n        status: [302]\n",
        ),
    );
    let out = run(
        &[t],
        &[target],
        fast_limits(),
        deps(resolver.clone(), Arc::new(StubDns::default())),
    )
    .await;
    assert_eq!(trip.contacts(), 0, "the off-scope listener was contacted");
    assert_eq!(server.hits(), 3);
    assert_eq!(out.requests_sent, 3);
    assert_eq!(out.requests_refused, 3);
    for host in ["127.0.0.1", "evil.test", "169.254.169.254"] {
        assert!(
            out.refused_hosts.contains(&host.to_string()),
            "{:?}",
            out.refused_hosts
        );
    }
    assert_eq!(
        resolver.calls("evil.test"),
        0,
        "an off-scope name is never resolved"
    );
    // The 3xx is the final response, so a status matcher sees it.
    assert_eq!(out.matches.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_scope_redirect_is_followed_up_to_the_cap() {
    let server = serve(|req| {
        let n: u32 = req.path.trim_start_matches("/r/").parse().unwrap_or(0);
        Reply::now(response(
            302,
            &[("Location", &format!("/r/{}", n + 1))],
            b"",
        ))
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let body = |max: u32| {
        format!(
            "http:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}/r/0\"\n    redirects: true\n    max-redirects: {max}\n    matchers:\n      - type: word\n        part: url\n        words: [\"/r/\"]\n"
        )
    };
    let out = run(
        &[template("three", &body(3))],
        std::slice::from_ref(&target),
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(server.hits(), 4, "1 request + 3 redirects");
    assert!(out.matches[0].matched.matched_at.ends_with("/r/3"));

    let server = serve(|req| {
        let n: u32 = req.path.trim_start_matches("/r/").parse().unwrap_or(0);
        Reply::now(response(
            301,
            &[("Location", &format!("/r/{}", n + 1))],
            b"",
        ))
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    run(
        &[template("fifty", &body(50))],
        &[target],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(server.hits(), 11, "capped at 10 redirects");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_host_redirects_stop_at_another_host() {
    let b = serve(|_| Reply::now(response(200, &[], b"b"))).await;
    let b_port = b.port();
    let a = serve(move |_| {
        Reply::now(response(
            302,
            &[("Location", &format!("http://two.test:{b_port}/"))],
            b"",
        ))
    })
    .await;
    let resolver = Arc::new(StubResolver::with(&[
        ("one.test", LOOPBACK),
        ("two.test", LOOPBACK),
    ]));
    let targets = [
        format!("http://one.test:{}", a.port()),
        format!("http://two.test:{b_port}"),
    ];
    let t = template(
        "samehost",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    host-redirects: true\n    matchers:\n      - type: status\n        status: [302]\n",
    );
    let out = run(
        &[t],
        &targets[..1],
        fast_limits(),
        deps(resolver, Arc::new(StubDns::default())),
    )
    .await;
    assert_eq!(b.hits(), 0);
    assert_eq!(
        out.requests_refused, 0,
        "not followed by policy, not refused"
    );
    assert_eq!(out.matches.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_template_host_header_never_moves_the_connection() {
    let trip = tripwire().await;
    let server = serve(|_| Reply::now(response(200, &[], b"vhost ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let header = format!(
        "http:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}/\"\n    headers:\n      Host: \"127.0.0.1:{}\"\n    matchers:\n      - type: word\n        words: [\"vhost ok\"]\n",
        trip.port()
    );
    let annotation = format!(
        "http:\n  - raw:\n      - |\n        @Host: http://127.0.0.1:{}\n        GET /x HTTP/1.1\n        Host: {{{{Hostname}}}}\n\n    matchers:\n      - type: word\n        words: [\"vhost ok\"]\n",
        trip.port()
    );
    let out = run(
        &[
            template("hosthdr", &header),
            template("hostann", &annotation),
        ],
        &[target],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(trip.contacts(), 0);
    let seen = server.requests();
    assert_eq!(
        seen.len(),
        1,
        "only the Host-header request reached the target"
    );
    assert_eq!(
        seen[0].header("host"),
        Some(format!("127.0.0.1:{}", trip.port()).as_str()),
        "sent as a header value to the in-scope server"
    );
    assert_eq!(out.matches.len(), 1);
    assert_eq!(out.matches[0].template_id, "hosthdr");
    assert_eq!(out.requests_refused, 1);
    let ann = out
        .not_evaluated
        .iter()
        .find(|n| n.template_id == "hostann")
        .expect("annotation template not evaluated");
    assert!(ann.reason.contains("refused by scope"), "{}", ann.reason);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_raw_request_template_works() {
    let server = serve(|req| {
        if req.method == "POST" && req.path == "/login" && req.body == b"user=admin&pass=x" {
            Reply::now(response(200, &[], b"welcome admin"))
        } else {
            Reply::now(response(400, &[], b"bad"))
        }
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let t = template(
        "rawpost",
        concat!(
            "http:\n  - raw:\n      - |\n        POST /login HTTP/1.1\n        Host: {{Hostname}}\n        Content-Type: application/x-www-form-urlencoded\n        Content-Length: 999\n\n        user=admin&pass=x\n",
            "    matchers:\n      - type: word\n        words: [\"welcome admin\"]\n",
        ),
    );
    let out = run(&[t], &[target], fast_limits(), plain_deps()).await;
    assert_eq!(out.matches.len(), 1, "{out:?}");
    let seen = server.requests();
    assert_eq!(
        seen[0].header("content-length"),
        Some("17"),
        "computed by the client"
    );
    assert!(out.matches[0]
        .evidence
        .as_ref()
        .expect("ev")
        .request
        .starts_with("POST "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookies_never_leak_to_another_host() {
    let a = serve(|req| {
        if req.path == "/set" {
            Reply::now(response(
                200,
                &[("Set-Cookie", "session=abc; Path=/")],
                b"set",
            ))
        } else {
            Reply::now(response(200, &[], b"ok"))
        }
    })
    .await;
    let c = serve(|_| Reply::now(response(200, &[], b"other"))).await;
    let targets = [
        format!("http://app.test:{}", a.port()),
        format!("http://other.test:{}", c.port()),
    ];
    let resolver = StubResolver::with(&[("app.test", LOOPBACK), ("other.test", LOOPBACK)]);
    let (net, http) = executor(&targets, fast_limits(), &resolver).await;
    let mut jar = CookieJar::default();
    let r = http
        .execute(
            &net,
            &spec(format!("http://app.test:{}/set", a.port())),
            &mut jar,
        )
        .await;
    assert!(r.outcome.is_ok());
    let r = http
        .execute(
            &net,
            &spec(format!("http://other.test:{}/check", c.port())),
            &mut jar,
        )
        .await;
    assert!(r.outcome.is_ok());
    let r = http
        .execute(
            &net,
            &spec(format!("http://app.test:{}/check", a.port())),
            &mut jar,
        )
        .await;
    assert!(r.outcome.is_ok());
    assert_eq!(
        c.requests()[0].header("cookie"),
        None,
        "cookie leaked to another host"
    );
    let a_seen = a.requests();
    assert_eq!(a_seen[1].header("cookie"), Some("session=abc"));

    // With cookie reuse off, nothing is stored or sent.
    let mut jar = CookieJar::default();
    let mut no_reuse = spec(format!("http://app.test:{}/set", a.port()));
    no_reuse.cookie_reuse = false;
    http.execute(&net, &no_reuse, &mut jar).await;
    let mut again = spec(format!("http://app.test:{}/check", a.port()));
    again.cookie_reuse = false;
    http.execute(&net, &again, &mut jar).await;
    assert_eq!(a.requests().last().expect("seen").header("cookie"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_response_cap_truncates() {
    let big = vec![b'a'; 100_000];
    let server = serve(move |_| Reply::now(response(200, &[], &big))).await;
    let targets = [format!("http://127.0.0.1:{}", server.port())];
    let limits = LiveLimits {
        max_response_bytes: 1024,
        ..fast_limits()
    };
    let (net, http) = executor(&targets, limits, &StubResolver::default()).await;
    let ex = http
        .execute(
            &net,
            &spec(format!("{}/big", targets[0])),
            &mut CookieJar::default(),
        )
        .await;
    let resp = ex.outcome.expect("response");
    assert_eq!(resp.body.len(), 1024);
    assert!(ex.truncated);

    // A template's own max-size is honoured below the cap.
    let mut small = spec(format!("{}/big", targets[0]));
    small.max_response_bytes = Some(10);
    let ex = http.execute(&net, &small, &mut CookieJar::default()).await;
    assert_eq!(ex.outcome.expect("response").body.len(), 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_timeout_is_honoured() {
    let server = serve(|_| Reply {
        bytes: response(200, &[], b"late"),
        delay: Duration::from_secs(6),
    })
    .await;
    let targets = [format!("http://127.0.0.1:{}", server.port())];
    let limits = LiveLimits {
        timeout: Duration::from_secs(1),
        ..fast_limits()
    };
    let (net, http) = executor(&targets, limits, &StubResolver::default()).await;
    let start = Instant::now();
    let ex = http
        .execute(
            &net,
            &spec(format!("{}/", targets[0])),
            &mut CookieJar::default(),
        )
        .await;
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    assert!(
        matches!(ex.outcome, Err(NetFailure::Connect(_))),
        "{:?}",
        ex.outcome
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_that_is_not_pinned_cannot_be_reached() {
    // Even if a URL somehow named a host that was never resolved, the client
    // refuses to look it up.
    let server = serve(|_| Reply::now(response(200, &[], b"x"))).await;
    let targets = [format!("http://pinned.test:{}", server.port())];
    let resolver = StubResolver::with(&[("pinned.test", LOOPBACK)]);
    let (net, _) = executor(&targets, fast_limits(), &resolver).await;
    let client = build_client(net.pinned.clone(), &net.limits).expect("client");
    let err = client
        .get(format!("http://localhost:{}/", server.port()))
        .send()
        .await
        .expect_err("unpinned name must not resolve");
    assert!(
        err.is_connect() || err.to_string().contains("pinned"),
        "{err}"
    );
    assert_eq!(server.hits(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bare_host_is_probed_https_then_http() {
    let server = serve(|_| Reply::now(response(200, &[], b"plain http"))).await;
    let target = format!("127.0.0.1:{}", server.port());
    let t = template(
        "bare",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/page\"\n    matchers:\n      - type: word\n        words: [\"plain http\"]\n",
    );
    let out = run(&[t], &[target], fast_limits(), plain_deps()).await;
    assert_eq!(out.matches.len(), 1, "{out:?}");
    assert!(out.matches[0]
        .matched
        .matched_at
        .starts_with("http://127.0.0.1:"));
    // https attempt (refused by TLS) + http probe + the template request
    assert_eq!(out.requests_sent, 3);
    assert_eq!(server.requests().last().expect("seen").path, "/page");
}

/// Proxy environment variables must be ignored. The child process runs with
/// them pointing at a listener in this process that must never be
/// contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_environment_variables_are_ignored() {
    let trip = tripwire().await;
    let proxy = format!("http://127.0.0.1:{}", trip.port());
    let exe = std::env::current_exe().expect("test binary");
    let output = tokio::process::Command::new(exe)
        .args([
            "--exact",
            "livenet::tests::http_tests::proxy_env_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OXAUDIT_LIVENET_PROXY_CHILD", "1")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .await
        .expect("child runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        trip.contacts(),
        0,
        "the proxy from the environment was used"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run in a child process by proxy_environment_variables_are_ignored"]
async fn proxy_env_child() {
    if std::env::var_os("OXAUDIT_LIVENET_PROXY_CHILD").is_none() {
        return;
    }
    assert!(std::env::var_os("HTTP_PROXY").is_some());
    let server = serve(|_| Reply::now(response(200, &[], b"direct"))).await;
    let resolver = Arc::new(StubResolver::with(&[("direct.test", LOOPBACK)]));
    let t = template(
        "direct",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: word\n        words: [\"direct\"]\n",
    );
    let out = run(
        &[t],
        &[
            format!("http://127.0.0.1:{}", server.port()),
            format!("http://direct.test:{}", server.port()),
        ],
        fast_limits(),
        deps(resolver, Arc::new(StubDns::default())),
    )
    .await;
    assert_eq!(out.matches.len(), 2, "{out:?}");
    assert_eq!(server.hits(), 2);
}

/// A loopback HTTPS server (self-signed) recording each request's path and
/// headers and answering with `handler`.
async fn serve_https(
    handler: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
) -> (
    u16,
    Arc<std::sync::Mutex<Vec<(String, Vec<(String, String)>)>>>,
) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let ck = rcgen::generate_simple_self_signed(vec!["app.test".to_string()]).expect("cert");
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (acceptor, record, handler) = (acceptor.clone(), record.clone(), handler.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let mut lines = head.split("\r\n");
                let path = lines
                    .next()
                    .unwrap_or_default()
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let headers = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let reply = handler(&path);
                record.lock().expect("lock").push((path, headers));
                let _ = tls.write_all(&reply).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_and_secure_cookies_do_not_follow_https_to_http_on_the_same_host() {
    let plain = serve(|_| Reply::now(response(200, &[], b"landing"))).await;
    let plain_port = plain.port();
    let (tls_port, tls_seen) = serve_https(move |path| {
        if path == "/set" {
            response(
                200,
                &[("Set-Cookie", "session=SECRETCOOKIE; Path=/")],
                b"set",
            )
        } else {
            response(
                302,
                &[("Location", &format!("http://app.test:{plain_port}/landing"))],
                b"",
            )
        }
    })
    .await;
    let targets = [
        format!("https://app.test:{tls_port}"),
        format!("http://app.test:{plain_port}"),
    ];
    let resolver = StubResolver::with(&[("app.test", LOOPBACK)]);
    let (net, http) = executor(&targets, fast_limits(), &resolver).await;
    let mut jar = CookieJar::default();
    let set = http
        .execute(
            &net,
            &spec(format!("https://app.test:{tls_port}/set")),
            &mut jar,
        )
        .await;
    assert!(set.outcome.is_ok(), "{:?}", set.outcome);
    let mut go = spec(format!("https://app.test:{tls_port}/go"));
    go.headers = vec![
        ("Authorization".into(), "Bearer SECRETBEARER".into()),
        ("Cookie".into(), "extra=SECRETHEADER".into()),
    ];
    go.follow_redirects = RedirectPolicy {
        mode: RedirectMode::Any,
        max: 3,
    };
    let r = http.execute(&net, &go, &mut jar).await;
    assert!(r.outcome.is_ok(), "{:?}", r.outcome);
    // The https hop got the credentials and the cookie...
    let tls_requests = tls_seen.lock().expect("lock").clone();
    let go_headers = &tls_requests.last().expect("go").1;
    assert!(go_headers.iter().any(|(k, _)| k == "authorization"));
    // ...the plain-http hop on the same host got none of them.
    let landing = plain.requests();
    assert_eq!(landing.len(), 1);
    assert_eq!(landing[0].path, "/landing");
    assert_eq!(landing[0].header("authorization"), None);
    assert_eq!(landing[0].header("cookie"), None, "{landing:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_do_not_follow_a_redirect_to_another_port_on_the_same_host() {
    let b = serve(|_| Reply::now(response(200, &[], b"b"))).await;
    let b_port = b.port();
    let a = serve(move |_| {
        Reply::now(response(
            302,
            &[("Location", &format!("http://app.test:{b_port}/b"))],
            b"",
        ))
    })
    .await;
    let targets = [
        format!("http://app.test:{}", a.port()),
        format!("http://app.test:{b_port}"),
    ];
    let resolver = StubResolver::with(&[("app.test", LOOPBACK)]);
    let (net, http) = executor(&targets, fast_limits(), &resolver).await;
    let mut go = spec(format!("http://app.test:{}/a", a.port()));
    go.headers = vec![
        ("Authorization".into(), "Bearer SECRETBEARER".into()),
        ("Proxy-Authorization".into(), "Basic SECRETPROXY".into()),
        ("Cookie".into(), "extra=SECRETHEADER".into()),
        ("X-Kept".into(), "yes".into()),
    ];
    go.follow_redirects = RedirectPolicy {
        mode: RedirectMode::Any,
        max: 3,
    };
    let r = http.execute(&net, &go, &mut CookieJar::default()).await;
    assert!(r.outcome.is_ok(), "{:?}", r.outcome);
    assert_eq!(
        a.requests()[0].header("authorization"),
        Some("Bearer SECRETBEARER")
    );
    let seen = b.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("authorization"), None);
    assert_eq!(seen[0].header("proxy-authorization"), None);
    assert_eq!(seen[0].header("cookie"), None);
    assert_eq!(seen[0].header("x-kept"), Some("yes"));
}

#[test]
fn the_cookie_jar_never_sends_secure_or_https_cookies_over_http() {
    let host = crate::livenet::scope::HostId::parse("app.test").expect("host");
    let mut jar = CookieJar::default();
    jar.store(
        &host,
        "http",
        &[
            ("Set-Cookie".into(), "plain=1; Path=/".into()),
            (
                "Set-Cookie".into(),
                "flagged=2; Path=/; Secure; HttpOnly".into(),
            ),
        ],
    );
    jar.store(&host, "https", &[("Set-Cookie".into(), "tls=3".into())]);
    assert_eq!(jar.header_for(&host, "http").as_deref(), Some("plain=1"));
    assert_eq!(
        jar.header_for(&host, "https").as_deref(),
        Some("plain=1; flagged=2; tls=3")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_messages_and_stored_urls_never_carry_query_secrets() {
    // A connection failure: the message names host:port, never the URL.
    let port = closed_port().await;
    let targets = [format!("http://127.0.0.1:{port}")];
    let (net, http) = executor(&targets, fast_limits(), &StubResolver::default()).await;
    let r = http
        .execute(
            &net,
            &spec(format!("http://127.0.0.1:{port}/x?token=SECRETQUERY")),
            &mut CookieJar::default(),
        )
        .await;
    let message = r.outcome.expect_err("refused").to_string();
    assert!(!message.contains("SECRETQUERY"), "{message}");
    assert!(!message.contains("token="), "{message}");
    assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");

    // A match: matchedAt and the stored request line are redacted.
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let t = template(
        "query",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/p?api_key=SECRETKEY&page=1\"\n    matchers:\n      - type: status\n        status: [200]\n",
    );
    let out = run(&[t], &[target], fast_limits(), plain_deps()).await;
    let found = &out.matches[0];
    assert!(
        found
            .matched
            .matched_at
            .ends_with("/p?api_key=[REDACTED]&page=1"),
        "{}",
        found.matched.matched_at
    );
    let evidence = found.evidence.as_ref().expect("evidence");
    assert!(
        !evidence.request.contains("SECRETKEY"),
        "{}",
        evidence.request
    );
    assert_eq!(
        server.requests()[0].path,
        "/p?api_key=SECRETKEY&page=1",
        "the request itself is unchanged"
    );
}

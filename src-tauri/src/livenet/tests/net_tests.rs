//! TCP sessions and TLS probes against loopback servers.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oxaudit_nuclei::model::TlsVersion;
use oxaudit_nuclei::{Protocol, SslProbeSpec};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::support::*;
use crate::livenet::ssl::{execute_ssl, versions_for};
use crate::livenet::NetFailure;

/// A line-protocol server: answers `PING\r\n` with a banner, records what it
/// received, then closes.
async fn ping_server() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let got = Arc::new(Mutex::new(Vec::new()));
    let record = got.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                record.lock().expect("lock").extend_from_slice(&buf[..n]);
                if &buf[..n] == b"PING\r\n" {
                    let _ = sock.write_all(b"PONG oxaudit-tcp\r\n").await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_send_and_named_read() {
    let (addr, got) = ping_server().await;
    let t = template(
        "ping",
        concat!(
            "tcp:\n  - host:\n      - \"{{Hostname}}\"\n",
            "    inputs:\n      - data: \"50494e470d0a\"\n        type: hex\n        read: 64\n        name: banner\n",
            "    matchers:\n      - type: word\n        part: banner\n        words: [\"PONG oxaudit-tcp\"]\n",
        ),
    );
    let out = run(
        &[t],
        &[format!("127.0.0.1:{}", addr.port())],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(out.matches.len(), 1, "{out:?}");
    assert_eq!(out.matches[0].protocol, Protocol::Tcp);
    assert_eq!(got.lock().expect("lock").as_slice(), b"PING\r\n");
    let ev = out.matches[0].evidence.as_ref().expect("ev");
    assert!(ev.request.contains("PING"));
    assert!(ev.response_excerpt.contains("PONG"));
    assert_eq!(out.requests_sent, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_to_an_off_scope_host_or_port_is_refused() {
    let trip = tripwire().await;
    let (addr, _) = ping_server().await;
    let fixed = template(
        "fixedhost",
        &format!(
            "tcp:\n  - host:\n      - \"127.0.0.1:{}\"\n    inputs:\n      - data: \"PING\\r\\n\"\n    matchers:\n      - type: word\n        words: [PONG]\n",
            trip.port()
        ),
    );
    let out = run(
        &[fixed],
        &[format!("127.0.0.1:{}", addr.port())],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(trip.contacts(), 0);
    assert_eq!(out.requests_refused, 1);
    assert_eq!(out.requests_sent, 0);
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["tls.test".to_string()]).expect("cert");
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (cert, key)
}

/// A TLS server that completes the handshake, writes a line and closes.
async fn tls_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let (cert, key) = self_signed();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handshakes = Arc::new(AtomicUsize::new(0));
    let count = handshakes.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (acceptor, count) = (acceptor.clone(), count.clone());
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    count.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 64];
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(200),
                        tls.read(&mut buf),
                    )
                    .await;
                    let _ = tls.write_all(b"HELLO-TLS\r\n").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (addr, handshakes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_probe_reports_certificate_facts() {
    let (addr, handshakes) = tls_server().await;
    let resolver = StubResolver::with(&[("tls.test", LOOPBACK)]);
    let targets = [format!("tls.test:{}", addr.port())];
    let net = net(&targets, fast_limits(), &resolver).await;
    let data = execute_ssl(
        &net,
        &SslProbeSpec {
            request_index: 0,
            host: "tls.test".into(),
            port: addr.port(),
            min_version: None,
            max_version: None,
        },
    )
    .await
    .expect("handshake");
    // The server counts after it reads the client's Finished, which can
    // land just after the client returns.
    for _ in 0..100 {
        if handshakes.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(handshakes.load(Ordering::SeqCst), 1);
    assert_eq!(data.subject_cn, "rcgen self signed cert");
    assert!(
        data.subject_an.contains(&"tls.test".to_string()),
        "{:?}",
        data.subject_an
    );
    assert!(data.self_signed);
    assert_eq!(data.tls_version, "tls13");
    assert!(data.cipher.starts_with("TLS_"), "{}", data.cipher);
    assert_eq!(data.sni, "tls.test");
    assert_eq!(data.ip, "127.0.0.1");
    assert_eq!(data.fingerprint_sha256.len(), 64);
    assert!(data.not_after > data.not_before);
    assert!(data.probe_status);

    // TLS 1.2 only.
    let data = execute_ssl(
        &net,
        &SslProbeSpec {
            request_index: 0,
            host: "tls.test".into(),
            port: addr.port(),
            min_version: Some(TlsVersion::Tls12),
            max_version: Some(TlsVersion::Tls12),
        },
    )
    .await
    .expect("handshake");
    assert_eq!(data.tls_version, "tls12");

    // Older than 1.2 cannot be probed: not evaluated, nothing sent.
    let before = net.gov.sent();
    let err = execute_ssl(
        &net,
        &SslProbeSpec {
            request_index: 0,
            host: "tls.test".into(),
            port: addr.port(),
            min_version: None,
            max_version: Some(TlsVersion::Tls11),
        },
    )
    .await
    .expect_err("tls11");
    assert!(matches!(err, NetFailure::Unsupported(_)), "{err:?}");
    assert_eq!(net.gov.sent(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssl_and_tls_tcp_templates_run_end_to_end() {
    let (addr, _) = tls_server().await;
    let resolver = Arc::new(StubResolver::with(&[("tls.test", LOOPBACK)]));
    let ssl = template(
        "selfsigned",
        concat!(
            "ssl:\n  - address: \"{{Host}}:{{Port}}\"\n",
            "    matchers:\n      - type: dsl\n        dsl:\n          - \"self_signed == true\"\n          - \"contains(subject_an, 'tls.test')\"\n        condition: and\n",
        ),
    );
    let tcp_tls = template(
        "tlsbanner",
        concat!(
            "tcp:\n  - host:\n      - \"tls://{{Hostname}}\"\n    inputs:\n      - data: \"hi\\r\\n\"\n",
            "    matchers:\n      - type: word\n        words: [\"HELLO-TLS\"]\n",
        ),
    );
    let out = run(
        &[ssl, tcp_tls],
        &[format!("tls.test:{}", addr.port())],
        fast_limits(),
        deps(resolver, Arc::new(StubDns::default())),
    )
    .await;
    let mut ids: Vec<&str> = out.matches.iter().map(|m| m.template_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["selfsigned", "tlsbanner"], "{out:?}");
}

#[test]
fn tls_version_window() {
    assert_eq!(versions_for(None, None).expect("ok").len(), 2);
    assert_eq!(
        versions_for(Some(TlsVersion::Tls13), None).expect("ok"),
        vec![&rustls::version::TLS13]
    );
    assert_eq!(
        versions_for(Some(TlsVersion::Tls10), Some(TlsVersion::Tls12)).expect("ok"),
        vec![&rustls::version::TLS12]
    );
    assert!(versions_for(None, Some(TlsVersion::Tls11)).is_err());
    assert!(versions_for(Some(TlsVersion::Tls13), Some(TlsVersion::Tls12)).is_err());
}

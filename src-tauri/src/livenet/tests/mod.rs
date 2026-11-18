//! Tests for live-target networking. Every server is a loopback listener
//! started inside the test; resolvers are stubs; templates are authored
//! here. No external network is used.

mod coverage_tests;
mod dns_tests;
mod exchange_tests;
mod http_tests;
mod limits_tests;
mod net_tests;
mod scope_tests;
mod support;

use std::sync::Arc;

use super::run::LiveTemplate;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_level_exclusions_are_reported() {
    let plain = get_templates(1, "/").remove(0);
    let yaml = "id: dos-t\ninfo:\n  name: D\n  severity: high\n  tags: dos,cve\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status: [200]\n";
    let tagged = LiveTemplate {
        template: Arc::new(
            oxaudit_nuclei::Template::load(yaml, "t", oxaudit_nuclei::LoadLimits::default())
                .expect("loads"),
        ),
        pack: "p".into(),
        file: "dos.yaml".into(),
    };
    let file_only = template(
        "fileonly",
        "file:\n  - extensions: [txt]\n    matchers:\n      - type: word\n        words: [x]\n",
    );
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let out = run(
        &[tagged, file_only, plain],
        &[format!("http://127.0.0.1:{}", server.port())],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.template_id == "dos-t" && n.reason.contains("dos") && n.target == "*"));
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.template_id == "fileonly" && n.reason.contains("local path")));
    assert_eq!(server.hits(), 1, "only the ordinary template ran");
    assert_eq!(out.matches.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_limits_fail_closed() {
    let out = run(
        &get_templates(1, "/"),
        &["http://127.0.0.1:9/".to_string()],
        crate::livenet::LiveLimits {
            requests_per_second: 0,
            ..fast_limits()
        },
        plain_deps(),
    )
    .await;
    assert_eq!(out.requests_sent, 0);
    assert!(out.incomplete_reasons[0].contains("invalid limits"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_is_reported() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    let templates = get_templates(3, "/");
    let out = crate::livenet::run::run_live_with(
        crate::livenet::LiveRunInput {
            templates: &templates,
            scope: scope(&[format!("http://127.0.0.1:{}", server.port())]),
            limits: fast_limits(),
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            progress: Arc::new(move |p| record.lock().expect("lock").push(p)),
            user_agent_version: "t",
        },
        Some(plain_deps()),
    )
    .await;
    assert_eq!(out.matches.len(), 3);
    let seen = seen.lock().expect("lock");
    let last = seen.last().expect("progress");
    assert_eq!((last.pairs_total, last.pairs_done, last.matches), (3, 3, 3));
}

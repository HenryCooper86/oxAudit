use std::net::IpAddr;
use std::sync::Arc;

use oxaudit_nuclei::Protocol;

use super::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_is_resolved_once_and_pinned() {
    let server = serve(|_| Reply::now(response(200, &[], b"pinned"))).await;
    let mut resolver = StubResolver::with(&[("pin.test", LOOPBACK)]);
    // A second lookup would move the host somewhere else (rebinding).
    resolver
        .later
        .insert("pin.test".into(), vec!["10.255.255.1".parse().expect("ip")]);
    let resolver = Arc::new(resolver);
    let target = format!("http://pin.test:{}", server.port());
    let t = template(
        "three",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n      - \"{{BaseURL}}/b\"\n      - \"{{BaseURL}}/c\"\n    matchers:\n      - type: word\n        words: [pinned]\n",
    );
    let mut templates = vec![t];
    templates.extend(get_templates(5, "/d"));
    let out = run(
        &templates,
        &[target],
        fast_limits(),
        deps(resolver.clone(), Arc::new(StubDns::default())),
    )
    .await;
    assert_eq!(resolver.calls("pin.test"), 1, "resolved once per run");
    assert_eq!(server.hits(), 8, "every request reached the pinned address");
    assert_eq!(
        out.resolved,
        vec![("pin.test".to_string(), vec![LOOPBACK])],
        "the pinned set is reported"
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("pin.test") && n.contains("non-public")),
        "a name resolving to loopback is visible: {:?}",
        out.notes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolvable_host_is_not_evaluated_not_a_failed_run() {
    let resolver = Arc::new(StubResolver::default());
    let t = template(
        "nores",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status: [200]\n",
    );
    let out = run(
        &[t],
        &["http://missing.test/".to_string()],
        fast_limits(),
        deps(resolver, Arc::new(StubDns::default())),
    )
    .await;
    assert!(
        out.incomplete_reasons.is_empty(),
        "{:?}",
        out.incomplete_reasons
    );
    assert_eq!(out.requests_sent, 0);
    assert_eq!(out.not_evaluated.len(), 1);
    assert!(out.not_evaluated[0].reason.contains("could not resolve"));
    assert_eq!(out.unreachable_targets.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_answers_for_a_typed_name_are_dropped() {
    let server = serve(|_| Reply::now(response(200, &[], b"x"))).await;
    let resolver = Arc::new(StubResolver::with(&[
        (
            "meta.test",
            "169.254.169.254".parse::<IpAddr>().expect("ip"),
        ),
        (
            "mixed.test",
            "169.254.169.254".parse::<IpAddr>().expect("ip"),
        ),
        ("mixed.test", LOOPBACK),
    ]));
    let out = run(
        &get_templates(1, "/"),
        &[
            "http://meta.test/".to_string(),
            format!("http://mixed.test:{}/", server.port()),
        ],
        fast_limits(),
        deps(resolver, Arc::new(StubDns::default())),
    )
    .await;
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.target == "http://meta.test/" && n.reason.contains("metadata")));
    assert_eq!(
        out.resolved,
        vec![("mixed.test".to_string(), vec![LOOPBACK])],
        "only the loopback answer is kept"
    );
    assert_eq!(out.matches.len(), 1);
    assert!(out.notes.iter().any(|n| n.contains("169.254.169.254")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_questions_are_scope_checked() {
    let mut dns = StubDns::default();
    dns.answers.insert(
        ("www.example.test".into(), "CNAME"),
        vec!["www.example.test.\t300\tIN\tCNAME\tdangling.cloud.example.".into()],
    );
    let dns = Arc::new(dns);
    let resolver = Arc::new(StubResolver::default());
    let sub = template(
        "cname",
        concat!(
            "dns:\n  - name: \"www.{{FQDN}}\"\n    type: CNAME\n",
            "    matchers:\n      - type: word\n        words: [\"IN\\tCNAME\", \"dangling.cloud.example\"]\n        condition: and\n",
            "    extractors:\n      - type: regex\n        name: cname\n        part: answer\n        group: 1\n        regex: [\"CNAME\\\\t(\\\\S+)\"]\n",
        ),
    );
    let elsewhere = template(
        "elsewhere",
        "dns:\n  - name: \"evil.example.net\"\n    type: TXT\n    matchers:\n      - type: word\n        words: [IN]\n",
    );
    let out = run(
        &[sub, elsewhere],
        &["example.test".to_string()],
        fast_limits(),
        deps(resolver, dns.clone()),
    )
    .await;
    let asked = dns.asked.lock().expect("lock").clone();
    assert_eq!(
        asked,
        ["www.example.test"],
        "only the in-scope question was asked"
    );
    assert_eq!(out.matches.len(), 1);
    let m = &out.matches[0];
    assert_eq!(m.protocol, Protocol::Dns);
    assert_eq!(
        m.matched.extracted,
        [(
            "cname".to_string(),
            vec!["dangling.cloud.example.".to_string()]
        )]
    );
    assert!(m
        .evidence
        .as_ref()
        .expect("ev")
        .response_excerpt
        .contains("ANSWER SECTION"));
    assert_eq!(out.requests_refused, 1);
    assert_eq!(out.refused_hosts, ["evil.example.net"]);
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.template_id == "elsewhere" && n.reason.contains("refused by scope")));
    assert_eq!(out.requests_sent, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_templates_need_a_name_target() {
    let t = template(
        "a",
        "dns:\n  - name: \"{{FQDN}}\"\n    type: A\n    matchers:\n      - type: word\n        words: [IN]\n",
    );
    let out = run(&[t], &["10.0.0.9".to_string()], fast_limits(), plain_deps()).await;
    assert_eq!(out.requests_sent, 0);
    assert!(out.not_evaluated[0].reason.contains("host name"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unusable_nat64_and_metadata_answers_are_dropped_and_noted() {
    let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
    let mut resolver = StubResolver::default();
    resolver.first.insert(
        "mixed.test".into(),
        vec![
            ip("0.0.0.0"),
            ip("224.0.0.1"),
            ip("255.255.255.255"),
            ip("::"),
            ip("ff02::1"),
            ip("64:ff9b::a9fe:a9fe"),
            ip("64:ff9b:1::a9fe:a9fe"),
            ip("64:ff9b:1:a9fe:a9:fe00::"),
            ip("64:ff9b::e000:1"),
            ip("fd00:ec2::23"),
            LOOPBACK,
            ip("64:ff9b::7f00:1"),
        ],
    );
    let scope = scope(&["http://mixed.test/".to_string()]);
    let pinned = crate::livenet::resolve::pin_hosts(
        &scope,
        &resolver,
        std::time::Duration::from_secs(1),
        None,
    )
    .await;
    assert_eq!(
        pinned.get("mixed.test").expect("pinned"),
        [LOOPBACK, ip("64:ff9b::7f00:1")],
        "only usable answers are kept"
    );
    let notes = pinned.notes().join("\n");
    for dropped in [
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "ff02::1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a9fe:a9fe",
        "64:ff9b:1:a9fe:a9:fe00::",
        "64:ff9b::e000:1",
        "fd00:ec2::23",
    ] {
        assert!(notes.contains(dropped), "{dropped} not noted: {notes}");
    }
    assert!(
        pinned.notes().contains(&"mixed.test resolved to unspecified, multicast or broadcast address(es) 0.0.0.0, 224.0.0.1, 255.255.255.255, ::, ff02::1, 64:ff9b::e000:1, which can never be a target; they were not used".to_string()),
        "{notes}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_question_sent_is_the_normalised_name_that_was_scope_checked() {
    use oxaudit_nuclei::model::{DnsClass, DnsType};
    use oxaudit_nuclei::DnsQuerySpec;

    let resolver = StubResolver::default();
    let targets = [
        "example.test".to_string(),
        "xn--bcher-kva.example".to_string(),
    ];
    let net = net(&targets, fast_limits(), &resolver).await;
    let dns = StubDns::default();
    for name in [
        "www.example\u{3002}test",
        "WWW.Example.TEST.",
        "B\u{fc}cher.example",
    ] {
        let spec = DnsQuerySpec {
            name: name.into(),
            qtype: DnsType::A,
            class: DnsClass::Inet,
            recursion: true,
            retries: 1,
            request_index: 0,
            payload_values: Vec::new(),
        };
        crate::livenet::dns::execute_dns(&net, &dns, &spec)
            .await
            .unwrap_or_else(|f| panic!("{name}: {f}"));
    }
    assert_eq!(
        dns.asked.lock().expect("lock").clone(),
        [
            "www.example.test",
            "www.example.test",
            "xn--bcher-kva.example"
        ]
    );
}

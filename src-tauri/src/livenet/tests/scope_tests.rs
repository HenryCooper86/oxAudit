use std::net::IpAddr;

use crate::livenet::scope::{HostId, RefusalReason, Scope, ScopeError, ScopeLimits, TargetKind};

fn parse(targets: &[&str]) -> Result<Scope, ScopeError> {
    let owned: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
    Scope::parse(&owned, ScopeLimits::default())
}

fn ok(targets: &[&str]) -> Scope {
    parse(targets).unwrap_or_else(|e| panic!("{targets:?} should parse: {e}"))
}

fn ip(s: &str) -> HostId {
    HostId::Ip(s.parse::<IpAddr>().expect("ip"))
}

fn name(s: &str) -> HostId {
    HostId::Name(s.into())
}

#[test]
fn accepted_target_forms() {
    let cases: &[(&str, HostId, Option<u16>)] = &[
        (
            "https://Example.COM:8443/app",
            name("example.com"),
            Some(8443),
        ),
        ("http://example.com", name("example.com"), None),
        ("https://example.com:443/", name("example.com"), None),
        (
            "http://bücher.example/",
            name("xn--bcher-kva.example"),
            None,
        ),
        ("http://[2001:db8::1]:8080/x", ip("2001:db8::1"), Some(8080)),
        ("example.com", name("example.com"), None),
        ("Example.com.", name("example.com"), None),
        ("example.com:22", name("example.com"), Some(22)),
        (
            "_sip.internal-host.lan",
            name("_sip.internal-host.lan"),
            None,
        ),
        ("10.0.0.5", ip("10.0.0.5"), None),
        ("10.0.0.5:8080", ip("10.0.0.5"), Some(8080)),
        ("127.0.0.1", ip("127.0.0.1"), None),
        ("::1", ip("::1"), None),
        ("[::1]", ip("::1"), None),
        ("[::1]:8443", ip("::1"), Some(8443)),
        ("[::ffff:10.1.2.3]:80", ip("10.1.2.3"), Some(80)),
        ("169.254.169.254", ip("169.254.169.254"), None),
    ];
    for (input, host, port) in cases {
        let s = ok(&[input]);
        let t = &s.targets()[0];
        assert_eq!(&t.host, host, "{input}");
        assert_eq!(&t.port, port, "{input}");
    }
    let url = ok(&["https://example.com/app/"]);
    assert_eq!(
        url.targets()[0].kind,
        TargetKind::Url {
            scheme: "https".into(),
            path: "/app/".into()
        }
    );
}

#[test]
fn cidr_ranges_expand() {
    let s = ok(&["192.168.1.0/30"]);
    let hosts: Vec<String> = s.targets().iter().map(|t| t.input.clone()).collect();
    assert_eq!(
        hosts,
        ["192.168.1.1", "192.168.1.2"],
        "network and broadcast skipped"
    );
    assert_eq!(ok(&["10.0.0.7/32"]).targets().len(), 1);
    assert_eq!(ok(&["10.0.0.0/31"]).targets().len(), 2);
    assert_eq!(ok(&["fd00::/126"]).targets().len(), 4);
    assert_eq!(ok(&["10.9.0.0/24"]).targets().len(), 254);
}

#[test]
fn rejected_target_forms() {
    let cases = [
        "",
        "   ",
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "http://user:pw@example.com/",
        "http://user@example.com/",
        "*.example.com",
        "http://*.example.com/",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/23",
        "10.0.0.0/8",
        "exa mple.com",
        "-bad.example",
        "bad-.example",
        "a..b",
        "0.0.0.0",
        "0.1.2.3",
        "::",
        "[::]:80",
        "224.0.0.1",
        "239.1.1.1:5000",
        "255.255.255.255",
        "ff02::1",
        "127.1",
        "http://127.1/",
        "2130706433",
        "example.com:0",
        "example.com:99999",
        "example.com:http",
        "example.com/path",
        "user@example.com",
        "example.com?x",
        "fe80::1%eth0",
        "1:2:3",
        "[::1",
        "224.0.0.0/30",
    ];
    for input in cases {
        assert!(parse(&[input]).is_err(), "`{input}` must be rejected");
    }
    let long_label = format!("{}.example", "a".repeat(64));
    assert!(parse(&[long_label.as_str()]).is_err());
}

#[test]
fn target_and_address_caps() {
    let many: Vec<String> = (0..1001).map(|i| format!("host{i}.example")).collect();
    assert!(matches!(
        Scope::parse(&many, ScopeLimits::default()),
        Err(ScopeError::TooManyTargets {
            given: 1001,
            max: 1000
        })
    ));
    let thousand: Vec<String> = (0..1000).map(|i| format!("host{i}.example")).collect();
    assert!(Scope::parse(&thousand, ScopeLimits::default()).is_ok());
    assert!(matches!(
        parse(&["10.1.0.0/24", "10.2.0.0/25"]),
        Err(ScopeError::TooManyAddresses { .. })
    ));
    assert!(matches!(parse(&[]), Err(ScopeError::Empty)));
}

#[test]
fn port_rules() {
    let s = ok(&[
        "bare.example",
        "pinned.example:8080",
        "http://web.example/",
        "https://app.example:8443/",
    ]);
    for port in [1, 22, 80, 443, 65535] {
        assert!(
            s.check_connect("bare.example", port).is_ok(),
            "bare host, port {port}"
        );
    }
    assert!(s.check_connect("pinned.example", 8080).is_ok());
    let r = s
        .check_connect("pinned.example", 8081)
        .expect_err("other port");
    assert_eq!(r.reason, RefusalReason::PortNotInScope);
    assert!(s.check_connect("web.example", 80).is_ok());
    assert!(
        s.check_connect("web.example", 443).is_ok(),
        "http->https upgrade"
    );
    assert!(s.check_connect("web.example", 8080).is_err());
    assert!(s.check_connect("app.example", 8443).is_ok());
    assert!(s.check_connect("app.example", 443).is_err());
    assert!(s.check_connect("app.example", 80).is_err());

    // A bare entry for the same host widens it.
    let merged = ok(&["merged.example:8080", "merged.example"]);
    assert!(merged.check_connect("merged.example", 9999).is_ok());
}

#[test]
fn hosts_are_normalised_the_same_way_for_checks() {
    let s = ok(&["example.com", "127.0.0.1:8080"]);
    assert_eq!(s.check_connect("EXAMPLE.com.", 80), Ok(name("example.com")));
    // Numeric spellings are the address they denote; the check and the
    // connection agree.
    assert_eq!(s.check_connect("0x7f.0.0.1", 8080), Ok(ip("127.0.0.1")));
    assert_eq!(
        s.check_connect("[::ffff:127.0.0.1]", 8080),
        Ok(ip("127.0.0.1"))
    );
    assert!(s.check_connect("2130706433", 9090).is_err());
    for hostile in [
        "evil.example/@example.com",
        "example.com@evil.example",
        "example.com#@evil",
        "evil.example\\example.com",
        "example.com evil",
        "",
    ] {
        assert!(s.check_connect(hostile, 80).is_err(), "`{hostile}`");
    }
}

#[test]
fn subdomains_are_not_in_scope_but_may_be_asked_about() {
    let s = ok(&["example.com", "10.0.0.5"]);
    let r = s
        .check_connect("www.example.com", 443)
        .expect_err("subdomain");
    assert_eq!(r.reason, RefusalReason::NotInScope);
    assert!(s.check_connect("notexample.com", 443).is_err());
    assert!(s.check_dns_question("example.com").is_ok());
    assert!(s.check_dns_question("Example.COM.").is_ok());
    assert!(s.check_dns_question("www.example.com").is_ok());
    assert!(s.check_dns_question("_dmarc.example.com").is_ok());
    assert!(s.check_dns_question("a.b.c.example.com.").is_ok());
    assert!(s.check_dns_question("notexample.com").is_err());
    assert!(s.check_dns_question("example.com.evil.net").is_err());
    assert!(s.check_dns_question("evil.net").is_err());
    assert!(
        s.check_dns_question("10.0.0.5").is_err(),
        "an IP is not a question"
    );
    assert!(s.check_dns_question("5.0.0.10.in-addr.arpa").is_ok());
    assert!(s.check_dns_question("6.0.0.10.in-addr.arpa").is_err());
}

#[test]
fn reverse_v6_question() {
    let s = ok(&["2001:db8::1"]);
    let rev = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    assert!(s.check_dns_question(rev).is_ok());
    let other = "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    assert!(s.check_dns_question(other).is_err());
}

#[test]
fn metadata_endpoints_are_refused_unless_typed() {
    let s = ok(&["example.com"]);
    for host in [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
        "[::ffff:169.254.169.254]",
        "metadata.google.internal",
        "metadata.azure.com",
    ] {
        let r = s.check_connect(host, 80).expect_err(host);
        assert_eq!(r.reason, RefusalReason::CloudMetadata, "{host}");
        assert!(r.to_string().contains("metadata"), "{r}");
    }
    let typed = ok(&["169.254.169.254", "metadata.google.internal"]);
    assert!(typed.check_connect("169.254.169.254", 80).is_ok());
    assert!(typed.check_connect("metadata.google.internal", 80).is_ok());
    assert!(typed.check_connect("169.254.170.2", 80).is_err());
}

#[test]
fn a_cidr_range_does_not_type_a_metadata_address() {
    let s = ok(&["169.254.169.0/24"]);
    assert!(
        s.check_connect("169.254.169.10", 80).is_ok(),
        "link-local range typed"
    );
    let r = s
        .check_connect("169.254.169.254", 80)
        .expect_err("metadata");
    assert_eq!(r.reason, RefusalReason::CloudMetadata);
    assert!(s.notes().iter().any(|n| n.contains("169.254.169.254")));
    assert_eq!(s.targets().len(), 253);
}

#[test]
fn private_loopback_and_link_local_targets_are_allowed_when_typed() {
    let s = ok(&[
        "10.1.2.3",
        "192.168.0.10:443",
        "127.0.0.1",
        "fe80::1",
        "169.254.10.10",
    ]);
    assert!(s.check_connect("10.1.2.3", 22).is_ok());
    assert!(s.check_connect("192.168.0.10", 443).is_ok());
    assert!(s.check_connect("127.0.0.1", 9).is_ok());
    assert!(s.check_connect("fe80::1", 80).is_ok());
    assert!(s.check_connect("169.254.10.10", 80).is_ok());
    assert!(s.check_connect("10.1.2.4", 22).is_err());
}

#[test]
fn urls_are_checked_on_scheme_host_and_port() {
    let s = ok(&["http://app.example:8080/"]);
    let u = |s: &str| reqwest::Url::parse(s).expect("url");
    assert!(s.check_url(&u("http://app.example:8080/x?y")).is_ok());
    assert!(s.check_url(&u("https://app.example:8080/")).is_ok());
    assert!(s.check_url(&u("http://app.example/")).is_err());
    assert!(s
        .check_url(&u("http://app.example:8080@evil.example:8080/"))
        .is_err());
    let r = s
        .check_url(&u("ftp://app.example:8080/"))
        .expect_err("scheme");
    assert!(matches!(r.reason, RefusalReason::UnsupportedScheme(_)));
}

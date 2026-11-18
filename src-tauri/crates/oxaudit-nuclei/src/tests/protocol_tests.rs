use super::*;
use crate::dns::{evaluate_dns, plan_dns, DnsResponseData, DnsTarget};
use crate::model::{DnsClass, DnsType, TlsVersion};
use crate::ssl::{evaluate_ssl, plan_ssl, SslResponseData};
use crate::tcp::{evaluate_tcp, plan_tcp, TcpResponseData, TcpStep, TcpTarget};
use crate::{evaluate_file, plan_file, Protocol, RunLimits, SkipReason};

fn header(body: &str) -> String {
    format!("id: t\ninfo:\n  name: Proto\n  severity: low\n{body}")
}

// -------------------------------------------------------------------- DNS

const DNS: &str = concat!(
    "dns:\n",
    "  - name: \"www.{{FQDN}}\"\n    type: CNAME\n    class: inet\n    recursion: false\n    retries: 2\n",
    "    matchers-condition: and\n    matchers:\n",
    "      - type: word\n        words: [\"IN\\tCNAME\", \"target.example.\"]\n        condition: and\n",
    "      - type: word\n        part: rcode\n        words: [NOERROR]\n",
    "    extractors:\n      - type: regex\n        name: cname\n        part: answer\n        group: 1\n        regex: [\"CNAME\\\\t(\\\\S+)\"]\n",
);

#[test]
fn dns_planning() {
    let t = load_supported(&header(DNS));
    let target = DnsTarget::parse("https://example.com:8080/x").expect("target");
    assert_eq!(target.fqdn, "example.com");
    let plan = plan_dns(&t, &target, &mut ctx(), &RunLimits::default());
    assert_eq!(plan.len(), 1);
    let spec = plan[0].spec.as_ref().expect("spec");
    assert_eq!(spec.name, "www.example.com");
    assert_eq!(spec.qtype, DnsType::Cname);
    assert_eq!(spec.class, DnsClass::Inet);
    assert!(!spec.recursion);
    assert_eq!(spec.retries, 2);
}

#[test]
fn dns_defaults_and_all_supported_types() {
    let t = load_supported(&header(
        "dns:\n  - matchers:\n      - type: word\n        words: [IN]\n",
    ));
    let spec = plan_dns(
        &t,
        &DnsTarget::parse("a.test").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    )
    .remove(0)
    .spec
    .expect("spec");
    assert_eq!(
        (
            spec.name.as_str(),
            spec.qtype,
            spec.class,
            spec.recursion,
            spec.retries
        ),
        ("a.test", DnsType::A, DnsClass::Inet, true, 3)
    );
    for ty in [
        "A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "PTR", "CAA", "SRV", "txt",
    ] {
        let t = load_supported(&header(&format!("dns:\n  - name: '{{{{FQDN}}}}'\n    type: {ty}\n    matchers:\n      - type: word\n        words: [IN]\n")));
        assert_eq!(t.dns[0].qtype.as_str(), ty.to_uppercase());
    }
    for class in ["inet", "csnet", "chaos", "hesiod", "none", "any"] {
        load_supported(&header(&format!(
            "dns:\n  - class: {class}\n    matchers:\n      - type: word\n        words: [IN]\n"
        )));
    }
}

#[test]
fn dns_target_variables() {
    let v = DnsTarget::parse("a.b.example.com").expect("t").variables();
    let get = |k: &str| v[k].to_text().into_owned();
    assert_eq!(get("FQDN"), "a.b.example.com");
    assert_eq!(get("RDN"), "example.com");
    assert_eq!(get("DN"), "example");
    assert_eq!(get("TLD"), "com");
    assert_eq!(get("SD"), "a.b");
    assert_eq!(
        DnsTarget::parse("example.com.").expect("t").fqdn,
        "example.com"
    );
    assert!(DnsTarget::parse("").is_err());
}

#[test]
fn dns_evaluation() {
    let t = load_supported(&header(DNS));
    let target = DnsTarget::parse("example.com").expect("target");
    let spec = plan_dns(&t, &target, &mut ctx(), &RunLimits::default())
        .remove(0)
        .spec
        .expect("spec");
    let answer = "www.example.com.\t300\tIN\tCNAME\ttarget.example.";
    let resp = DnsResponseData {
        rcode: "NOERROR".into(),
        question: "www.example.com.\tIN\tCNAME".into(),
        answers: vec![answer.into()],
        authority: vec![],
        additional: vec![],
        raw: format!(";; ANSWER SECTION:\n{answer}\n"),
    };
    let m = evaluate_dns(&t, &spec, &target, &resp, &mut ctx()).expect("matches");
    assert_eq!(m.protocol, Protocol::Dns);
    assert_eq!(m.matched_at, "www.example.com");
    assert_eq!(
        m.extracted,
        [("cname".to_string(), vec!["target.example.".to_string()])]
    );
    let nx = DnsResponseData {
        rcode: "NXDOMAIN".into(),
        raw: String::new(),
        ..DnsResponseData::default()
    };
    assert!(evaluate_dns(&t, &spec, &target, &nx, &mut ctx()).is_none());
    let wrong_rcode = DnsResponseData {
        rcode: "SERVFAIL".into(),
        ..resp.clone()
    };
    assert!(
        evaluate_dns(&t, &spec, &target, &wrong_rcode, &mut ctx()).is_none(),
        "matchers-condition and"
    );
}

#[test]
fn dns_parts_and_payloads() {
    let t = load_supported(&header(concat!(
        "dns:\n  - name: '{{sub}}.{{FQDN}}'\n    type: A\n    attack: batteringram\n    payloads:\n      sub: [www, mail]\n",
        "    matchers:\n      - type: dsl\n        dsl: ['contains(answer, \"192.0.2.1\") && contains(ns, \"ns1\") && contains(extra, \"glue\") && question == \"q\" && host == \"example.com\" && type == \"A\" && contains(request, \"IN\")']\n",
    )));
    let target = DnsTarget::parse("example.com").expect("t");
    let plan = plan_dns(&t, &target, &mut ctx(), &RunLimits::default());
    let names: Vec<_> = plan
        .iter()
        .map(|p| p.spec.clone().expect("spec").name)
        .collect();
    assert_eq!(names, ["www.example.com", "mail.example.com"]);
    let spec = plan[0].spec.clone().expect("spec");
    assert_eq!(
        spec.payload_values,
        [("sub".to_string(), "www".to_string())]
    );
    let resp = DnsResponseData {
        rcode: "NOERROR".into(),
        question: "q".into(),
        answers: vec!["www.example.com.\t60\tIN\tA\t192.0.2.1".into()],
        authority: vec!["example.com.\t60\tIN\tNS\tns1.example.com.".into()],
        additional: vec!["glue".into()],
        raw: String::new(),
    };
    assert!(evaluate_dns(&t, &spec, &target, &resp, &mut ctx()).is_some());
}

#[test]
fn dns_unresolved_name_is_a_skip() {
    let t = load_supported(&header("dns:\n  - name: '{{nope}}.{{FQDN}}'\n    matchers:\n      - type: word\n        words: [IN]\n"));
    let plan = plan_dns(
        &t,
        &DnsTarget::parse("a.test").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    );
    assert_eq!(
        plan[0].spec,
        Err(SkipReason::UnresolvedVariable(vec!["nope".into()]))
    );
}

// -------------------------------------------------------------------- TCP

const TCP: &str = concat!(
    "tcp:\n  - inputs:\n",
    "      - data: \"{{hex_decode('50494e47')}}\"\n",
    "      - data: \"0d0a\"\n        type: hex\n",
    "      - read: 8\n        name: banner\n",
    "    host: ['{{Hostname}}']\n    port: 6379\n    read-size: 64\n",
    "    matchers:\n      - type: word\n        part: banner\n        words: ['+PONG']\n",
);

#[test]
fn tcp_planning_and_port_rules() {
    let t = load_supported(&header(TCP));
    let plan = |input: &str| {
        plan_tcp(
            &t,
            &TcpTarget::parse(input).expect("t"),
            &mut ctx(),
            &RunLimits::default(),
        )
        .into_iter()
        .map(|p| p.spec.expect("spec"))
        .collect::<Vec<_>>()
    };
    let specs = plan("10.0.0.1");
    assert_eq!(specs.len(), 1);
    let s = &specs[0];
    assert_eq!(
        (s.host.as_str(), s.port, s.tls, s.read_size, s.read_all),
        ("10.0.0.1", 6379, false, 64, false)
    );
    assert_eq!(
        s.steps,
        [
            TcpStep::Send(b"PING".to_vec()),
            TcpStep::Send(vec![0x0d, 0x0a]),
            TcpStep::Read {
                size: 8,
                name: Some("banner".into())
            },
        ]
    );
    assert_eq!(
        plan("10.0.0.1:2222")[0].port,
        2222,
        "a non-reserved input port wins"
    );
    assert_eq!(
        plan("10.0.0.1:443")[0].port,
        6379,
        "a reserved input port does not"
    );
    assert_eq!(plan("tls://10.0.0.1:8080")[0].port, 6379);
}

#[test]
fn tcp_multiple_ports_exclude_ports_and_tls_prefix() {
    let t = load_supported(&header("tcp:\n  - host: ['tls://{{Host}}']\n    port: '5432, 5433'\n    exclude-ports: '5433'\n    inputs:\n      - data: hello\n    matchers:\n      - type: word\n        words: [ok]\n"));
    let specs = |input: &str| {
        plan_tcp(
            &t,
            &TcpTarget::parse(input).expect("t"),
            &mut ctx(),
            &RunLimits::default(),
        )
        .into_iter()
        .map(|p| p.spec.expect("spec"))
        .map(|s| (s.port, s.tls))
        .collect::<Vec<_>>()
    };
    assert_eq!(specs("h.test"), [(5432, true), (5433, true)]);
    assert_eq!(specs("h.test:9000"), [(9000, true)]);
    assert_eq!(
        specs("h.test:5433"),
        [(5432, true), (5433, true)],
        "excluded ports use the template list"
    );
    let t = load_supported(&header("tcp:\n  - host: ['{{Host}}:22', '{{Hostname}}']\n    inputs:\n      - data: x\n    matchers:\n      - type: word\n        words: [ok]\n"));
    let plan = plan_tcp(
        &t,
        &TcpTarget::parse("h.test:2200").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    );
    let ports: Vec<_> = plan
        .into_iter()
        .map(|p| p.spec.expect("spec").port)
        .collect();
    assert_eq!(ports, [22, 2200]);
    let plan = plan_tcp(
        &t,
        &TcpTarget::parse("h.test").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    );
    assert_eq!(plan[0].spec.as_ref().expect("spec").port, 22);
    assert!(
        matches!(plan[1].spec, Err(SkipReason::Malformed(_))),
        "no port anywhere"
    );
}

#[test]
fn tcp_input_forms() {
    let t = load_supported(&header(concat!(
        "variables:\n  greet: HELO\n",
        "tcp:\n  - host: ['{{Hostname}}']\n    port: 25\n    read-all: true\n    inputs:\n",
        "      - data: \"{{greet}} {{Host}}\\r\\n\"\n",
        "      - data: hex_decode('ff00')\n",
        "      - read: 4\n",
        "      - data: 'xx'\n        read: 2\n        name: both\n",
        "    matchers:\n      - type: word\n        words: ['250']\n",
    )));
    let spec = plan_tcp(
        &t,
        &TcpTarget::parse("mail.test").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    )
    .remove(0)
    .spec
    .expect("spec");
    assert!(spec.read_all);
    assert_eq!(
        spec.steps,
        [
            TcpStep::Send(b"HELO mail.test\r\n".to_vec()),
            TcpStep::Send(vec![0xff, 0x00]),
            TcpStep::Read {
                size: 4,
                name: None
            },
            TcpStep::Send(b"xx".to_vec()),
            TcpStep::Read {
                size: 2,
                name: Some("both".into())
            },
        ]
    );
    let t = load_supported(&header("tcp:\n  - host: ['{{Hostname}}']\n    port: 1\n    inputs:\n      - data: zz\n        type: hex\n    matchers:\n      - type: word\n        words: [a]\n"));
    let plan = plan_tcp(
        &t,
        &TcpTarget::parse("h.test").expect("t"),
        &mut ctx(),
        &RunLimits::default(),
    );
    assert!(matches!(plan[0].spec, Err(SkipReason::Malformed(_))));
}

#[test]
fn tcp_evaluation() {
    let t = load_supported(&header(TCP));
    let target = TcpTarget::parse("10.0.0.1").expect("t");
    let spec = plan_tcp(&t, &target, &mut ctx(), &RunLimits::default())
        .remove(0)
        .spec
        .expect("spec");
    let resp = TcpResponseData {
        request: b"PING\r\n".to_vec(),
        data: b"tail".to_vec(),
        raw: b"+PONG\r\ntail".to_vec(),
        named: vec![("banner".into(), b"+PONG\r\n".to_vec())],
    };
    let m = evaluate_tcp(&t, &spec, &target, &resp, &mut ctx()).expect("match");
    assert_eq!(
        (m.protocol, m.matched_at.as_str()),
        (Protocol::Tcp, "10.0.0.1:6379")
    );
    let silent = TcpResponseData {
        named: vec![("banner".into(), b"-ERR".to_vec())],
        ..resp.clone()
    };
    assert!(evaluate_tcp(&t, &spec, &target, &silent, &mut ctx()).is_none());
}

#[test]
fn tcp_parts_and_binary_matching() {
    let t = load_supported(&header(concat!(
        "tcp:\n  - host: ['{{Hostname}}']\n    port: 9\n    inputs:\n      - data: hi\n    matchers-condition: and\n    matchers:\n",
        "      - type: binary\n        binary: ['00ff00']\n",
        "      - type: word\n        part: data\n        words: ['END']\n",
        "      - type: word\n        part: all\n        words: ['HEAD']\n",
        "      - type: dsl\n        dsl: ['port == 9 && contains(request, \"hi\") && contains(host, \"h.test\")']\n",
        "    extractors:\n      - type: regex\n        regex: ['H[A-Z]+']\n        part: raw\n",
    )));
    let target = TcpTarget::parse("h.test").expect("t");
    let spec = plan_tcp(&t, &target, &mut ctx(), &RunLimits::default())
        .remove(0)
        .spec
        .expect("spec");
    let mut raw = b"HEAD".to_vec();
    raw.extend([0x00, 0xff, 0x00]);
    raw.extend(b"END");
    let resp = TcpResponseData {
        request: b"hi".to_vec(),
        data: raw.clone(),
        raw,
        named: vec![],
    };
    let m = evaluate_tcp(&t, &spec, &target, &resp, &mut ctx()).expect("match");
    assert_eq!(m.extracted, [(String::new(), vec!["HEAD".to_string()])]);
}

// -------------------------------------------------------------------- SSL

const SSL: &str = concat!(
    "ssl:\n  - address: '{{Host}}:{{Port}}'\n    min_version: tls10\n    max_version: tls12\n",
    "    matchers:\n",
    "      - type: dsl\n        name: expired\n        dsl: ['expired == true']\n",
    "      - type: dsl\n        name: mismatch\n        dsl: ['mismatched']\n",
    "      - type: dsl\n        name: self-signed\n        dsl: ['self_signed']\n",
    "      - type: word\n        name: weak\n        part: tls_version\n        words: [tls10, sslv3]\n",
    "      - type: word\n        name: wild\n        part: subject_an\n        words: ['*.']\n",
    "      - type: dsl\n        name: corp\n        dsl: ['contains(issuer_org, \"Acme\") && contains(domains, \"example.test\") && contains(fingerprint_hash, \"sha1:bb\")']\n",
);

fn cert() -> SslResponseData {
    SslResponseData {
        host: "example.test".into(),
        ip: "192.0.2.10".into(),
        port: 443,
        sni: "example.test".into(),
        tls_version: "tls13".into(),
        cipher: "TLS_AES_128_GCM_SHA256".into(),
        tls_connection: "ctls".into(),
        probe_status: true,
        subject_cn: "example.test".into(),
        subject_dn: "CN=example.test".into(),
        subject_an: vec!["example.test".into(), "*.example.test".into()],
        issuer_cn: "Acme CA".into(),
        issuer_dn: "CN=Acme CA,O=Acme".into(),
        issuer_org: vec!["Acme".into()],
        serial: "01".into(),
        not_before: 1_600_000_000,
        not_after: 1_900_000_000,
        fingerprint_md5: "aa".into(),
        fingerprint_sha1: "bb".into(),
        fingerprint_sha256: "cc".into(),
        ..SslResponseData::default()
    }
}

#[test]
fn ssl_planning() {
    let t = load_supported(&header(SSL));
    let plan = plan_ssl(
        &t,
        &TcpTarget::parse("example.test").expect("t"),
        &mut ctx(),
    );
    let spec = plan[0].spec.as_ref().expect("spec");
    assert_eq!((spec.host.as_str(), spec.port), ("example.test", 443));
    assert_eq!(
        (spec.min_version, spec.max_version),
        (Some(TlsVersion::Tls10), Some(TlsVersion::Tls12))
    );
    let plan = plan_ssl(
        &t,
        &TcpTarget::parse("example.test:8443").expect("t"),
        &mut ctx(),
    );
    assert_eq!(plan[0].spec.as_ref().expect("spec").port, 8443);
    let t = load_supported(&header(
        "ssl:\n  - matchers:\n      - type: dsl\n        dsl: ['expired']\n",
    ));
    let spec = plan_ssl(&t, &TcpTarget::parse("h.test").expect("t"), &mut ctx())
        .remove(0)
        .spec
        .expect("spec");
    assert_eq!((spec.port, spec.min_version), (443, None));
}

#[test]
fn ssl_evaluation_of_certificate_facts() {
    let t = load_supported(&header(SSL));
    let target = TcpTarget::parse("example.test").expect("t");
    let spec = plan_ssl(&t, &target, &mut ctx())
        .remove(0)
        .spec
        .expect("spec");
    // Healthy certificate: only the wildcard and corp matchers hold.
    let m = evaluate_ssl(&t, &spec, &target, &cert(), &mut ctx()).expect("match");
    assert_eq!(m.matcher_names, ["wild", "corp"]);
    // Expired (the test clock is 1_700_000_000), self-signed, wrong name, old TLS.
    let bad = SslResponseData {
        not_after: 1_650_000_000,
        self_signed: true,
        sni: "other.test".into(),
        tls_version: "tls10".into(),
        subject_an: vec![],
        ..cert()
    };
    let m = evaluate_ssl(&t, &spec, &target, &bad, &mut ctx()).expect("match");
    assert_eq!(
        m.matcher_names,
        ["expired", "mismatch", "self-signed", "weak", "corp"]
    );
    assert_eq!(m.protocol, Protocol::Ssl);
    assert_eq!(m.matched_at, "example.test:443");
}

#[test]
fn ssl_derived_facts() {
    let c = cert();
    assert!(!c.expired(1_700_000_000) && c.expired(2_000_000_000));
    assert!(!c.mismatched());
    assert!(c.wildcard());
    assert_eq!(c.domains(), ["example.test", "*.example.test"]);
    let wild_only = SslResponseData {
        subject_cn: "".into(),
        subject_an: vec!["*.example.test".into()],
        sni: "www.example.test".into(),
        ..cert()
    };
    assert!(!wild_only.mismatched(), "a wildcard covers one label");
    let deep = SslResponseData {
        sni: "a.b.example.test".into(),
        ..wild_only.clone()
    };
    assert!(deep.mismatched(), "but not two");
    let bare = SslResponseData {
        sni: "example.test".into(),
        ..wild_only
    };
    assert!(bare.mismatched(), "and not the bare domain");
    assert!(
        !SslResponseData {
            not_after: 0,
            ..cert()
        }
        .expired(i64::MAX),
        "unknown expiry is not 'expired'"
    );
}

#[test]
fn ssl_response_part_is_json() {
    let t = load_supported(&header("ssl:\n  - address: '{{Hostname}}'\n    matchers:\n      - type: word\n        words: ['\"tls_version\":\"tls13\"', '\"issuer_cn\":\"Acme CA\"']\n        condition: and\n"));
    let target = TcpTarget::parse("example.test").expect("t");
    let spec = plan_ssl(&t, &target, &mut ctx())
        .remove(0)
        .spec
        .expect("spec");
    assert!(evaluate_ssl(&t, &spec, &target, &cert(), &mut ctx()).is_some());
}

// ------------------------------------------------------------------- File

const FILE: &str = concat!(
    "file:\n  - extensions: [env, conf]\n    denylist: [bak]\n    matchers-condition: or\n    matchers:\n",
    "      - type: word\n        name: aws\n        words: [AKIA, aws_secret]\n",
    "      - type: regex\n        name: pw\n        regex: ['password\\s*=\\s*\\S+']\n",
    "    extractors:\n      - type: regex\n        name: pass\n        group: 1\n        regex: ['password\\s*=\\s*(\\S+)']\n",
);

#[test]
fn file_matching_with_line_numbers() {
    let t = load_supported(&header(FILE));
    let content = b"line one\nAKIAXXXX here\npassword = hunter2\nAKIA again\n";
    let matches = evaluate_file(&t, "/etc/app.conf", content);
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(
        (m.protocol, m.matched_at.as_str()),
        (Protocol::File, "/etc/app.conf")
    );
    assert_eq!(m.matcher_names, ["aws", "pw"]);
    assert_eq!(
        m.extracted,
        [("pass".to_string(), vec!["hunter2".to_string()])]
    );
    let at = |line: usize, start: usize| {
        m.lines
            .iter()
            .find(|l| l.line == line && l.start_column == start)
            .unwrap_or_else(|| panic!("no span at {line}:{start} in {:?}", m.lines))
    };
    let aws = at(2, 1);
    assert_eq!(
        (aws.end_column, aws.start_offset, aws.end_offset),
        (5, 9, 13)
    );
    assert_eq!(aws.text, "AKIAXXXX here");
    assert_eq!(aws.matcher.as_deref(), Some("aws"));
    let pw = at(3, 1);
    assert_eq!(
        (pw.end_column, pw.start_offset, pw.end_offset),
        (19, 23, 41)
    );
    assert_eq!(pw.matcher.as_deref(), Some("pw"));
    let extracted = at(3, 12);
    assert_eq!((extracted.end_column, extracted.start_offset), (19, 34));
    assert_eq!(extracted.matcher.as_deref(), Some("pass"));
    let again = at(4, 1);
    assert_eq!(
        again.start_offset, 42,
        "every occurrence of the matching word is located"
    );
    let lines: Vec<_> = m.lines.iter().map(|l| (l.line, l.start_column)).collect();
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(lines, sorted, "ordered by position");
}

#[test]
fn file_columns_with_crlf_and_multiline_matches() {
    let t = load_supported(&header("file:\n  - extensions: [all]\n    matchers:\n      - type: regex\n        regex: ['(?s)BEGIN.*?END']\n      - type: word\n        words: ['tail']\n"));
    let content = b"a\r\nBEGIN x\r\nmore END tail\r\n";
    let m = &evaluate_file(&t, "k.pem", content)[0];
    let begin = m.lines.iter().find(|l| l.line == 2).expect("line 2");
    assert_eq!(
        (begin.start_column, begin.end_column),
        (1, 8),
        "clamped to the end of the first line"
    );
    assert_eq!(begin.text, "BEGIN x");
    assert!(begin.end_offset > 13, "offsets still cover the whole match");
    let tail = m.lines.iter().find(|l| l.line == 3).expect("line 3");
    assert_eq!(tail.text, "more END tail");
}

#[test]
fn file_extension_rules() {
    let t = load_supported(&header(FILE));
    let rules = plan_file(&t);
    assert_eq!(rules.len(), 1);
    let r = &rules[0];
    assert_eq!(r.extensions, ["env", "conf"]);
    assert!(r.denylist.contains(&"png".to_string()) && r.denylist.contains(&"bak".to_string()));
    assert_eq!(
        (r.max_size, r.no_recursive, r.archive),
        (Some(5 * 1024 * 1024), false, false)
    );
    for (path, ok) in [
        ("a/b/app.conf", true),
        ("a/b/APP.CONF", true),
        ("/x/.env", true),
        ("/x/prod.env", true),
        ("/x/app.txt", false),
        ("/x/app.bak", false),
        ("/x/conf", false),
        ("C:\\x\\a.conf", true),
    ] {
        assert_eq!(r.accepts(path), ok, "{path}");
    }
    let content = b"password = x";
    assert!(evaluate_file(&t, "/x/app.txt", content).is_empty());
    assert!(evaluate_file(&t, "/x/app.conf", content).len() == 1);
}

#[test]
fn file_all_extensions_and_default_denylist() {
    let t = load_supported(&header("file:\n  - extensions: [all]\n    matchers:\n      - type: word\n        words: [needle]\n"));
    let r = &plan_file(&t)[0];
    assert!(r.extensions.is_empty());
    for (path, ok) in [
        ("a.py", true),
        ("a", true),
        ("a.txt", false),
        ("a.png", false),
        ("a.tar.gz", false),
        ("a.gz", false),
    ] {
        assert_eq!(r.accepts(path), ok, "{path}");
    }
    // Listing an extension next to `all` removes it from the default denylist.
    let t = load_supported(&header("file:\n  - extensions: [all, txt]\n    matchers:\n      - type: word\n        words: [needle]\n"));
    let r = &plan_file(&t)[0];
    assert!(r.accepts("notes.txt") && !r.accepts("pic.png"));
    // No extensions at all behaves like `all`.
    let t = load_supported(&header(
        "file:\n  - matchers:\n      - type: word\n        words: [needle]\n",
    ));
    assert!(plan_file(&t)[0].accepts("x.rs"));
    // User denylist applies.
    let t = load_supported(&header("file:\n  - extensions: [all]\n    denylist: [.go, py]\n    matchers:\n      - type: word\n        words: [needle]\n"));
    let r = &plan_file(&t)[0];
    assert!(!r.accepts("a.go") && !r.accepts("a.py") && r.accepts("a.rs"));
}

#[test]
fn file_max_size_and_options() {
    let t = load_supported(&header("file:\n  - extensions: [all]\n    max-size: 10b\n    no-recursive: true\n    archive: true\n    matchers:\n      - type: word\n        words: [needle]\n"));
    let r = &plan_file(&t)[0];
    assert_eq!(
        (r.max_size, r.no_recursive, r.archive),
        (Some(10), true, true)
    );
    assert!(evaluate_file(&t, "a.rs", b"needle").len() == 1);
    assert!(
        evaluate_file(&t, "a.rs", b"needle needle needle").is_empty(),
        "over max-size"
    );
    for (text, want) in [
        ("5Mb", Some(5 * 1024 * 1024)),
        ("2gb", Some(2 << 30)),
        ("1kb", Some(1024)),
        ("no", None),
        ("100", Some(100)),
    ] {
        let t = load_supported(&header(&format!(
            "file:\n  - max-size: {text}\n    matchers:\n      - type: word\n        words: [x]\n"
        )));
        assert_eq!(plan_file(&t)[0].max_size, want, "{text}");
    }
    assert!(!reasons(&header(
        "file:\n  - max-size: lots\n    matchers:\n      - type: word\n        words: [x]\n"
    ))
    .is_empty());
}

#[test]
fn file_negative_and_no_match() {
    let t = load_supported(&header("file:\n  - extensions: [all]\n    matchers:\n      - type: word\n        words: [needle]\n"));
    assert!(evaluate_file(&t, "a.rs", b"haystack").is_empty());
    let neg = load_supported(&header("file:\n  - extensions: [all]\n    matchers:\n      - type: word\n        negative: true\n        words: [needle]\n"));
    let m = evaluate_file(&neg, "a.rs", b"haystack");
    assert_eq!(m.len(), 1);
    assert!(m[0].lines.is_empty(), "a negative match has no location");
}

#[test]
fn file_binary_content_and_dsl() {
    let t = load_supported(&header("file:\n  - extensions: [all]\n    matchers:\n      - type: binary\n        binary: ['7f454c46']\n      - type: dsl\n        dsl: ['starts_with(raw, \"x\")']\n"));
    let m = evaluate_file(&t, "bin", &[0x7f, b'E', b'L', b'F', 0xff, 0x00]);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].lines[0].line, 1);
    assert!(evaluate_file(&t, "bin", &[0x00, 0x01]).is_empty());
}

#[test]
fn file_only_matches_declared_protocol_blocks() {
    let t = load_supported(&header(&format!("{FILE}http:\n  - path: ['{{{{BaseURL}}}}']\n    matchers:\n      - type: status\n        status: [200]\n")));
    assert_eq!(evaluate_file(&t, "a.conf", b"password = x").len(), 1);
    let http_only = load_supported(&header("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n"));
    assert!(evaluate_file(&http_only, "a.conf", b"x").is_empty());
}

#[test]
fn dns_and_tcp_payload_caps_are_reported_as_truncations() {
    let big = (0..30)
        .map(|i| format!("'p{i}'"))
        .collect::<Vec<_>>()
        .join(",");
    let limits = RunLimits {
        max_payload_combinations: 50,
        ..RunLimits::default()
    };
    let dns = load_supported(&header(&format!(
        "dns:\n  - name: '{{{{a}}}}.{{{{b}}}}.{{{{FQDN}}}}'\n    attack: clusterbomb\n    payloads:\n      a: [{big}]\n      b: [{big}]\n    matchers:\n      - type: word\n        words: [IN]\n"
    )));
    let target = DnsTarget::parse("a.test").expect("t");
    assert_eq!(plan_dns(&dns, &target, &mut ctx(), &limits).len(), 50);
    let cut = crate::dns_truncations(&dns, &limits);
    assert_eq!(cut.len(), 1, "{cut:?}");
    assert_eq!(cut[0].protocol, Protocol::Dns);
    assert_eq!(
        cut[0].message,
        "dns request 0: only 50 of 900 payload combinations were sent (the cap is 50)"
    );
    assert!(crate::dns_truncations(&dns, &RunLimits::default()).is_empty());

    let tcp = load_supported(&header(&format!(
        "tcp:\n  - inputs:\n      - data: '{{{{a}}}}{{{{b}}}}'\n    host: ['{{{{Hostname}}}}']\n    port: 6379\n    attack: clusterbomb\n    payloads:\n      a: [{big}]\n      b: [{big}]\n    matchers:\n      - type: word\n        words: [x]\n"
    )));
    let target = TcpTarget::parse("10.0.0.1").expect("t");
    assert_eq!(plan_tcp(&tcp, &target, &mut ctx(), &limits).len(), 50);
    let cut = crate::tcp_truncations(&tcp, &limits);
    assert_eq!(cut.len(), 1, "{cut:?}");
    assert_eq!(cut[0].protocol, Protocol::Tcp);
    assert!(cut[0].message.contains("only 50 of 900"), "{cut:?}");
}

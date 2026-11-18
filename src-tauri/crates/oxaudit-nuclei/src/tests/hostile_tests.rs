use super::*;
use crate::dns::{plan_dns, DnsTarget};
use crate::dsl::{eval_str, parse};
use crate::tcp::{plan_tcp, TcpTarget};
use crate::vars::{interpolate, interpolate_detailed};
use crate::{evaluate_file, plan_file, plan_ssl, HttpResponseData, HttpRun, HttpTarget, RunLimits};

/// Loads `src`, then drives every planner and evaluator the template offers.
fn exercise(src: &str) {
    let Ok(t) = Template::load(src, "hostile", LoadLimits::default()) else {
        return;
    };
    let _ = (
        t.support(),
        t.protocols(),
        t.is_destructive(),
        t.is_intrusive(),
    );
    let mut run = HttpRun::with_limits(
        &t,
        HttpTarget::parse("http://h.test/a").expect("target"),
        Box::new(ctx()),
        RunLimits {
            max_payload_combinations: 20,
            max_iterate_all_variants: 5,
        },
    );
    let mut n = 0;
    while let Some(step) = run.next_request() {
        n += 1;
        assert!(n < 10_000, "runaway planning");
        if step.is_ok() {
            run.on_response(HttpResponseData {
                status: 200,
                body: b"id=1 id=2 token=abc \xff\xfe".to_vec(),
                headers: vec![("X-A".into(), "b".into())],
                ..HttpResponseData::default()
            });
        }
    }
    let _ = run.finish();
    let limits = RunLimits {
        max_payload_combinations: 20,
        ..RunLimits::default()
    };
    let _ = plan_dns(
        &t,
        &DnsTarget::parse("a.test").expect("t"),
        &mut ctx(),
        &limits,
    );
    let tcp = TcpTarget::parse("a.test:1").expect("t");
    let _ = plan_tcp(&t, &tcp, &mut ctx(), &limits);
    let _ = plan_ssl(&t, &tcp, &mut ctx());
    let _ = plan_file(&t);
    let _ = evaluate_file(&t, "a.txt", b"id=1 \x00\xff needle");
    let _ = evaluate_file(&t, "a.conf", b"");
}

fn wrap(extra: &str) -> String {
    format!("id: h\ninfo:\n  name: H\n{extra}")
}

#[test]
fn hostile_yaml_and_templates_never_panic() {
    let big_list = format!("[{}]", vec!["1"; 5000].join(","));
    let nested = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    let anchors: String = {
        let mut s = String::from("x0: &a0 [a, a, a, a, a, a, a, a, a, a]\n");
        for i in 1..30 {
            s.push_str(&format!(
                "x{i}: &a{i} [{}]\n",
                vec![format!("*a{}", i - 1); 10].join(", ")
            ));
        }
        s
    };
    let snippets: Vec<String> = vec![
        String::new(),
        "\0".into(),
        "id".into(),
        "id: t\ninfo: [1,2,3]\n".into(),
        "id: t\ninfo:\n  name: n\nhttp: 7\n".into(),
        "id: t\ninfo:\n  name: n\nhttp:\n  - 1\n  - [2]\n  - null\n".into(),
        "id: &a t\ninfo: *a\n".into(),
        wrap("http:\n  - path: 5\n    matchers: oops\n    extractors: [1,2]\n"),
        wrap("http:\n  - path: [[a], {b: c}]\n    headers: [x]\n    body: [1]\n"),
        wrap("http:\n  - path: ['{{']\n"),
        wrap("http:\n  - path: ['}}{{']\n"),
        wrap("http:\n  - path: ['{{{{{{{{{{{{{{{{{{{{x}}}}}}}}}}}}}}}}}}}}']\n"),
        wrap(&format!("http:\n  - path: ['{}']\n", "{{".repeat(3000))),
        wrap(&format!("http:\n  - path: ['{}x{}']\n", "{{".repeat(200), "}}".repeat(200))),
        wrap(&format!("http:\n  - path: ['{{{{{}}}}}']\n", "(".repeat(5000))),
        wrap(&format!("http:\n  - path: ['{{{{{}}}}}']\n", vec!["1"; 3000].join("+"))),
        wrap("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: []\n      - type: regex\n      - type: status\n      - type: dsl\n"),
        wrap("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [abc, 99999999999999999999, -1]\n      - type: size\n        size: ['x']\n"),
        wrap("http:\n  - path: ['{{BaseURL}}']\n    max-redirects: 99999999999999999999\n    max-size: -5\n"),
        wrap("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['(a+)+$', '(?i)(x{1000}){1000}', '\\\\', '[', '(?P<n>a)(?P<n>b)']\n"),
        wrap("http:\n  - path: ['{{BaseURL}}']\n    extractors:\n      - type: regex\n        regex: ['(a)']\n        group: -3\n      - type: regex\n        regex: ['(a)']\n        group: 99999999999\n      - type: kval\n        kval: [1, [2]]\n"),
        wrap("http:\n  - raw:\n      - ''\n      - '@'\n      - '@Host'\n      - '\\n\\n\\n'\n      - 'GET'\n      - 'GET / HTTP/1.1\\nHost'\n"),
        wrap("http:\n  - raw:\n      - |\n        @Host: http://\n        GET / HTTP/1.1\n      - |\n        @Host: [::1\n        GET / HTTP/1.1\n      - |\n        @Host: x:99999\n        GET / HTTP/1.1\n"),
        wrap("http:\n  - raw:\n      - \"GET /\\r\\nHost: a\\r\\n\\r\\n\\u0000\\u00ff\"\n"),
        wrap(&format!("http:\n  - path: ['{{{{BaseURL}}}}/{{{{a}}}}/{{{{b}}}}/{{{{c}}}}']\n    attack: clusterbomb\n    payloads:\n      a: {big_list}\n      b: {big_list}\n      c: {big_list}\n")),
        wrap("http:\n  - path: ['{{BaseURL}}/{{a}}']\n    attack: clusterbomb\n    payloads:\n      a: []\n      b: []\n"),
        wrap("http:\n  - path: ['{{BaseURL}}/{{a}}']\n    attack: pitchfork\n    payloads:\n      a: [1]\n      b: [1,2,3]\n"),
        wrap("http:\n  - path: ['{{BaseURL}}/{{a}}']\n    payloads: 5\n"),
        wrap("http:\n  - path: ['{{BaseURL}}/{{repeat(\"aaaaaaaa\", 999999999)}}']\n"),
        wrap("http:\n  - path: ['{{BaseURL}}/{{rand_text_alpha(99999999)}}']\n"),
        wrap("http:\n  - path: ['{{BaseURL}}/{{1/0}}{{x}}']\n"),
        wrap("variables:\n  a: '{{b}}'\n  b: '{{a}}'\n  c: '{{c}}'\nhttp:\n  - path: ['{{BaseURL}}/{{a}}{{c}}']\n"),
        wrap("variables: [1, 2]\nconstants: 5\nhttp:\n  - path: ['{{BaseURL}}']\n"),
        wrap("dns:\n  - name: ''\n    type: 5\n    retries: -1\n    class: [x]\n"),
        wrap("dns:\n  - name: '{{FQDN}}{{FQDN}}{{FQDN}}'\n    retries: 99999999999\n"),
        wrap("tcp:\n  - host: [1, [2], '']\n    port: '1,,70000,-1,abc'\n    inputs: [1, {data: [x]}, {read: -4}, {read: 99999999999}, {type: hex, data: '{{x}}'}]\n    read-size: -5\n"),
        wrap("tcp:\n  - host: ['tls://', 'tls://:', '[::1', ':80', 'a:b:c']\n    inputs:\n      - data: hex_decode('zz')\n      - data: hex_decode()\n      - data: 'len(' \n"),
        wrap("ssl:\n  - address: ''\n    min_version: [a]\n"),
        wrap("ssl:\n  - address: '{{Host}}:{{nope}}'\n"),
        wrap("file:\n  - extensions: [1, [2], '', '.', '..', ',']\n    denylist: 5\n    max-size: ''\n"),
        wrap("file:\n  - extensions: [all]\n    max-size: 99999999999999999999999gb\n    matchers:\n      - type: word\n        words: ['']\n      - type: regex\n        regex: ['', '^', '$', '(?m)^$', '.*']\n"),
        wrap(&format!("file:\n  - extensions: [all]\n    matchers:\n      - type: word\n        words: ['{}']\n", "A".repeat(100_000))),
        format!("id: t\ninfo:\n  name: n\n  tags: {big_list}\n  author: {big_list}\n"),
        format!("id: t\ninfo:\n  name: n\n  metadata: {nested}\n"),
        nested,
        anchors,
        "id: t\ninfo:\n  name: n\n<<: *missing\n".into(),
        "id: t\ninfo:\n  name: !!binary aGk=\n".into(),
        "id: t\ninfo:\n  name: n\n? [complex, key]\n: value\n".into(),
        "id: t\ninfo:\n  name: n\n...\n---\nsecond: doc\n".into(),
        "\u{feff}id: t\ninfo:\n  name: n\n".into(),
        "id: \"\\x00\\uD800\"\ninfo:\n  name: n\n".into(),
        wrap("flow: |\n  for(;;){}\nhttp: []\n"),
    ];
    assert!(snippets.len() >= 48);
    for s in &snippets {
        exercise(s);
    }
}

#[test]
fn random_garbage_never_panics() {
    // A deterministic stream of printable and non-printable text.
    let mut c = ctx();
    use crate::dsl::EvalContext;
    for round in 0..200 {
        let len = (c.rand_u64() % 300) as usize;
        let alphabet: &[u8] = if round % 2 == 0 {
            b"{}()[]\"'\\ :-_,.0123456789abcxyz\n\t&|!=<>+*/%^~?@#$"
        } else {
            b"\x00\x01\x7f{{}}idinfohttp:- \n"
        };
        let text: String = (0..len)
            .map(|_| alphabet[(c.rand_u64() % alphabet.len() as u64) as usize] as char)
            .collect();
        exercise(&text);
        exercise(&wrap(&format!(
            "http:\n  - path: ['{}']\n",
            text.replace('\'', "")
        )));
        let _ = parse(&text);
        let _ = eval_str(&text, &Vars::new(), &mut ctx());
        let _ = interpolate(&text, &Vars::new(), &mut ctx());
        let _ = interpolate_detailed(&format!("{{{{{text}}}}}"), &Vars::new(), &mut ctx());
    }
}

#[test]
fn hostile_expressions_are_errors_not_panics() {
    let long_string = format!("'{}'", "a".repeat(100_000));
    let cases: Vec<String> = vec![
        long_string,
        "1".repeat(100_000),
        format!("{}1", "-".repeat(1000)),
        format!("f({})", vec!["1"; 5000].join(",")),
        format!("{}", "len(".repeat(500)),
        "9223372036854775807 + 1".into(),
        "9223372036854775807 * 9223372036854775807".into(),
        "-9223372036854775808 / -1".into(),
        "2 ** 100000".into(),
        "10 ** 400".into(),
        "(0 - 9223372036854775807 - 1) % -1".into(),
        "1 << 63 << 63".into(),
        "99999999999999999999999999".into(),
        "'a' =~ '('".into(),
        "'a' =~ '(a{1000}){1000}'".into(),
        "regex('(?i)((a{100}){100}){100}', 'a')".into(),
        "replace('', '', 'x')".into(),
        "substr('a', 1)".into(),
        "base64_decode('!!!')".into(),
        "hex_decode('abc')".into(),
        "url_decode('%zz')".into(),
        "url_decode('%')".into(),
        "html_unescape('&#99999999999;&#x110000;&#;&;&')".into(),
        "to_unix_time('9999999999999-99-99')".into(),
        "date_time('%Y', 9223372036854775807)".into(),
        "date_time('%Y', -9223372036854775807)".into(),
        "compare_versions('1.2.3', '>>>')".into(),
        "json_minify('{\"a\":' )".into(),
        format!("json_minify('{}1{}')", "[".repeat(1000), "]".repeat(1000)),
        "rand_int(9223372036854775807, -9223372036854775807)".into(),
        "rand_int(-9223372036854775807, 9223372036854775807)".into(),
        "dec_to_hex(-1)".into(),
        "ip_format('999.1.1.1', 1)".into(),
        "ip_format('1.2.3', 1)".into(),
        "trim('é', 'é')".into(),
        "reverse('🙂é')".into(),
        "equals_any()".into(),
        "mmh3(hex_decode('00'))".into(),
        "gzip_decode(hex_decode('1f8b0800'))".into(),
        "zlib_decode('x')".into(),
    ];
    for src in cases {
        let _ = eval_str(&src, &Vars::new(), &mut ctx());
        let _ = interpolate(&format!("{{{{{src}}}}}"), &Vars::new(), &mut ctx());
    }
}

#[test]
fn deflate_bombs_are_capped() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&vec![0u8; 20 * 1024 * 1024]).expect("write");
    let compressed = enc.finish().expect("finish");
    let mut vars = Vars::new();
    vars.insert("blob".into(), Value::Bytes(compressed));
    let r = eval_str("len(gzip_decode(blob))", &vars, &mut ctx());
    assert!(r.is_err(), "decompression over 4 MiB is refused");
}

#[test]
fn regex_denial_of_service_is_contained() {
    let t = load(&wrap("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['(a+)+$']\n"));
    let mut run = HttpRun::new(
        &t,
        HttpTarget::parse("http://h.test").expect("t"),
        Box::new(ctx()),
    );
    run.next_request();
    let start = std::time::Instant::now();
    run.on_response(HttpResponseData {
        status: 200,
        body: format!("{}!", "a".repeat(200_000)).into_bytes(),
        ..HttpResponseData::default()
    });
    assert!(start.elapsed().as_secs() < 5, "linear-time regex engine");
}

#[test]
fn oversized_templates_are_refused_before_parsing() {
    let huge = "a: ".to_string() + &"x".repeat(2 * 1024 * 1024);
    assert!(matches!(
        Template::load(&huge, "h", LoadLimits::default()),
        Err(crate::TemplateError::TooLarge { .. })
    ));
}

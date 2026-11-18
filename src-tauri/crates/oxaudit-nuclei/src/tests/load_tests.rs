use super::*;
use crate::{LoadLimits, Protocol, TemplateError};
use oxaudit_domain::Severity;

fn tpl(extra: &str) -> String {
    format!("id: t\ninfo:\n  name: T\n  severity: info\n{extra}")
}

const HTTP_OK: &str = "http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n";

/// Loads `tpl(extra)` and asserts one NotEvaluated reason mentions `needle`.
fn assert_reason(extra: &str, needle: &str) {
    let r = reasons(&tpl(extra));
    assert!(
        r.iter().any(|reason| reason.contains(needle)),
        "expected a reason containing {needle:?}, got {r:?} for:\n{extra}"
    );
}

#[test]
fn info_fields_are_normalised() {
    let t = load_supported(&format!(
        "id: CVE-2024-0001\ninfo:\n  name: Example\n  author: alice, bob\n  severity: HIGH\n  description: |\n    multi\n    line\n  reference:\n    - https://a.example/1\n    - https://a.example/2\n  tags: Cve,XSS, cve ,  Panel\n  remediation: patch it\n  classification:\n    cve-id: CVE-2024-0001\n    cwe-id: [CWE-79, CWE-80]\n    cvss-metrics: CVSS:3.1/AV:N\n    cvss-score: 7.5\n    epss-score: 0.25\n    cpe: cpe:2.3:a:x:y\n  metadata:\n    max-request: 2\n    vendor: acme\n    shodan-query: [a, b]\n{HTTP_OK}"
    ));
    assert_eq!(t.id, "CVE-2024-0001");
    assert_eq!(t.origin, "test.yaml");
    assert_eq!(t.info.name, "Example");
    assert_eq!(t.info.author, ["alice", "bob"]);
    assert_eq!(t.info.severity, Severity::High);
    assert!(!t.info.severity_unrecognised);
    assert_eq!(t.info.description, "multi\nline\n");
    assert_eq!(
        t.info.reference,
        ["https://a.example/1", "https://a.example/2"]
    );
    assert_eq!(t.tags(), ["cve", "xss", "panel"]);
    assert_eq!(t.info.remediation, "patch it");
    let c = &t.info.classification;
    assert_eq!(c.cve_id, ["CVE-2024-0001"]);
    assert_eq!(c.cwe_id, ["CWE-79", "CWE-80"]);
    assert_eq!(c.cvss_metrics.as_deref(), Some("CVSS:3.1/AV:N"));
    assert_eq!((c.cvss_score, c.epss_score), (Some(7.5), Some(0.25)));
    assert_eq!(c.cpe.as_deref(), Some("cpe:2.3:a:x:y"));
    assert!(t
        .info
        .metadata
        .iter()
        .any(|(k, v)| k == "vendor" && v == "acme"));
    assert!(t
        .info
        .metadata
        .iter()
        .any(|(k, v)| k == "max-request" && v == 2));
}

#[test]
fn author_tags_and_reference_accept_string_or_list() {
    let t = load_supported(&format!("id: t\ninfo:\n  name: T\n  author: [a, 'b,c']\n  tags: [One, two]\n  reference: https://x.example\n{HTTP_OK}"));
    assert_eq!(t.info.author, ["a", "b", "c"]);
    assert_eq!(t.tags(), ["one", "two"]);
    assert_eq!(t.info.reference, ["https://x.example"]);
}

#[test]
fn severity_mapping_and_unknown_flag() {
    for (text, want, unrecognised) in [
        ("info", Severity::Info, false),
        ("low", Severity::Low, false),
        ("Medium", Severity::Medium, false),
        ("high", Severity::High, false),
        ("critical", Severity::Critical, false),
        ("unknown", Severity::Info, true),
        ("undefined", Severity::Info, true),
        ("catastrophic", Severity::Info, true),
    ] {
        let t = load(&format!(
            "id: t\ninfo:\n  name: T\n  severity: {text}\n{HTTP_OK}"
        ));
        assert_eq!(
            (t.info.severity, t.info.severity_unrecognised),
            (want, unrecognised),
            "{text}"
        );
    }
    let t = load(&format!("id: t\ninfo:\n  name: T\n{HTTP_OK}"));
    assert!(
        t.info.severity_unrecognised,
        "a missing severity is flagged"
    );
}

#[test]
fn destructive_and_intrusive_tags() {
    let t = load(&tpl(HTTP_OK).replace("severity: info", "severity: info\n  tags: dos,cve"));
    assert!(t.is_destructive() && !t.is_intrusive());
    for tag in ["intrusive", "fuzz"] {
        let t = load(
            &tpl(HTTP_OK).replace("severity: info", &format!("severity: info\n  tags: {tag}")),
        );
        assert!(t.is_intrusive() && !t.is_destructive(), "{tag}");
    }
    let t = load(&tpl(HTTP_OK));
    assert!(!t.is_intrusive() && !t.is_destructive());
}

#[test]
fn legacy_keys_requests_and_network() {
    let t = load_supported(&tpl("requests:\n  - path: ['{{BaseURL}}/x']\n    matchers:\n      - type: status\n        status: [200]\nnetwork:\n  - inputs:\n      - data: 'hi'\n    host: ['{{Hostname}}']\n    port: 25\n    matchers:\n      - type: word\n        words: ['220']\n"));
    assert_eq!(
        t.protocols().into_iter().collect::<Vec<_>>(),
        [Protocol::Http, Protocol::Tcp]
    );
    assert_eq!(t.http.len(), 1);
    assert_eq!(t.tcp.len(), 1);
}

#[test]
fn protocols_reported() {
    let t = load_supported(&tpl("dns:\n  - name: '{{FQDN}}'\n    type: A\n    matchers:\n      - type: word\n        words: [IN]\nssl:\n  - address: '{{Host}}:{{Port}}'\n    matchers:\n      - type: dsl\n        dsl: ['expired']\nfile:\n  - extensions: [all]\n    matchers:\n      - type: word\n        words: [x]\n"));
    assert_eq!(
        t.protocols().into_iter().collect::<Vec<_>>(),
        [Protocol::Dns, Protocol::Ssl, Protocol::File]
    );
}

#[test]
fn unknown_extra_keys_do_not_fail_loading() {
    let t = load_supported(&format!(
        "id: t\ninfo:\n  name: T\n  severity: low\n  custom-field: whatever\n  nested:\n    a: [1, 2]\nsignature: some-signature\nextra-top-level: {{a: 1}}\n# digest: 4a0a00-comment\n{HTTP_OK}    unknown-http-key: 5\n    threads: 4\n    max-size: 1024\n"
    ));
    assert_eq!(t.http.len(), 1);
}

#[test]
fn load_errors() {
    let limits = LoadLimits::default();
    let l = |s: &str| Template::load(s, "x", limits).expect_err(s);
    assert_eq!(l("info:\n  name: T\n"), TemplateError::MissingId);
    assert_eq!(l("id: ''\ninfo:\n  name: T\n"), TemplateError::MissingId);
    assert_eq!(l("id: t\n"), TemplateError::MissingName);
    assert_eq!(
        l("id: t\ninfo:\n  severity: low\n"),
        TemplateError::MissingName
    );
    assert_eq!(l("- a\n- b\n"), TemplateError::NotAMapping);
    assert_eq!(l("just a string"), TemplateError::NotAMapping);
    assert!(matches!(l("id: [unclosed"), TemplateError::Yaml(_)));
    assert!(matches!(l("id: t\n\tbad: tab"), TemplateError::Yaml(_)));
    let big = format!(
        "id: t\ninfo:\n  name: T\n  description: {}\n",
        "x".repeat(1024 * 1024)
    );
    assert!(matches!(
        l(&big),
        TemplateError::TooLarge { max: 1048576, .. }
    ));
    assert!(Template::load(
        &big,
        "x",
        LoadLimits {
            max_bytes: 2 * 1024 * 1024
        }
    )
    .is_ok());
    // Exactly at the limit is accepted.
    let edge = format!(
        "id: t\ninfo:\n  name: T\n  description: {}\n",
        "x".repeat(1024 * 1024 - 40)
    );
    assert!(edge.len() <= 1024 * 1024);
    assert!(Template::load(&edge, "x", limits).is_ok());
}

#[test]
fn numeric_id_and_name_are_accepted() {
    let t = load(&format!("id: 123\ninfo:\n  name: 456\n{HTTP_OK}"));
    assert_eq!((t.id.as_str(), t.info.name.as_str()), ("123", "456"));
}

// ------------------------------------------------- NotEvaluated triggers

#[test]
fn unsupported_protocol_keys() {
    assert_reason(
        "headless:\n  - steps:\n      - action: navigate\n        args: {url: '{{BaseURL}}'}\n",
        "headless",
    );
    assert_reason("code:\n  - engine: [sh]\n    source: id\n", "code protocol");
    assert_reason("javascript:\n  - code: 'x'\n", "javascript");
    assert_reason(&format!("flow: http(1) && http(2)\n{HTTP_OK}"), "flow");
    assert_reason("workflows:\n  - template: a.yaml\n", "workflow");
    assert_reason(
        "websocket:\n  - address: 'ws://{{Hostname}}'\n",
        "websocket",
    );
    assert_reason("whois:\n  - query: '{{Host}}'\n", "whois");
    assert_reason(
        &format!("self-contained: true\n{HTTP_OK}"),
        "self-contained",
    );
}

#[test]
fn code_templates_are_never_supported() {
    let r = reasons(&tpl("code:\n  - engine: [sh]\n    source: echo hi\n    matchers:\n      - type: word\n        words: [hi]\n"));
    assert!(r.iter().any(|s| s.contains("never executed")), "{r:?}");
    assert!(!load(&tpl("code:\n  - engine: [sh]\n    source: x\n")).is_supported());
}

#[test]
fn interactsh_is_out_of_band() {
    assert_reason("http:\n  - path: ['{{BaseURL}}/?u=http://{{interactsh-url}}']\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n", "interactsh");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        part: interactsh_request\n        words: [x]\n", "interactsh");
    assert_reason("http:\n  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{interactsh-url}}\n    matchers:\n      - type: status\n        status: [200]\n", "interactsh");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['contains(interactsh_protocol, \"dns\")']\n", "interactsh");
    // The word may appear in the description without effect.
    let t = load(&format!(
        "id: t\ninfo:\n  name: T\n  description: mentions interactsh in prose\n{HTTP_OK}"
    ));
    assert!(t.is_supported());
}

#[test]
fn unsafe_http_features() {
    for (flag, needle) in [
        ("unsafe: true", "unsafe"),
        ("pipeline: true", "pipelining"),
        ("race: true", "race"),
        ("global-matchers: true", "global-matchers"),
        ("self-contained: true", "self-contained"),
        (
            "fuzzing:\n      - part: query\n        type: replace\n        fuzz: ['a']",
            "fuzzing",
        ),
        ("analyzer:\n      name: time_delay", "analyzer"),
        ("digest-username: u\n    digest-password: p", "digest"),
        ("signature: aws", "signing"),
    ] {
        assert_reason(
            &format!("http:\n  - path: ['{{{{BaseURL}}}}']\n    {flag}\n    matchers:\n      - type: status\n        status: [200]\n"),
            needle,
        );
    }
}

#[test]
fn xpath_json_and_unknown_matchers_and_extractors() {
    let m = |matcher: &str| {
        format!("http:\n  - path: ['{{{{BaseURL}}}}']\n    matchers:\n      - {matcher}\n")
    };
    let e = |extractor: &str| {
        format!("http:\n  - path: ['{{{{BaseURL}}}}']\n    extractors:\n      - {extractor}\n")
    };
    assert_reason(
        &m("type: xpath\n        xpath: ['//title']"),
        "xpath matcher",
    );
    assert_reason(
        &e("type: xpath\n        xpath: ['//title']"),
        "xpath extractor",
    );
    assert_reason(&e("type: json\n        json: ['.[] | .id']"), "json");
    assert_reason(
        &m("type: llm\n        prompt: is it?"),
        "unknown matcher type `llm`",
    );
    assert_reason(&m("type: bogus"), "unknown matcher type `bogus`");
    assert_reason(
        &m("type: word\n        words: [a]\n        encoding: base64"),
        "encoding",
    );
    assert_reason(&e("type: bogus"), "unknown extractor type `bogus`");
    assert_reason(
        &m("type: word\n        words: [zz]\n        condition: xor"),
        "condition",
    );
    assert_reason("matchers-condition: xor\nhttp:\n  - path: ['{{BaseURL}}']\n    matchers-condition: xor\n    matchers:\n      - type: status\n        status: [200]\n", "matchers-condition");
}

#[test]
fn unparseable_or_unimplemented_expressions() {
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['1 +']\n", "does not parse");
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}/{{1 +}}']\n",
        "does not parse",
    );
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}']\n    headers:\n      X: '{{len(}}'\n",
        "does not parse",
    );
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['aes_gcm(\"k\", \"p\") == \"x\"']\n", "aes_gcm");
    for f in [
        "generate_java_gadget",
        "generate_dotnet_gadget",
        "print_debug",
        "wait_for",
        "resolve",
        "rand_ip",
    ] {
        assert_reason(
            &format!("http:\n  - path: ['{{{{BaseURL}}}}/{{{{{f}(\"a\")}}}}']\n"),
            f,
        );
    }
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}/{{frobnicate(1)}}']\n",
        "frobnicate",
    );
    assert_reason("http:\n  - path: ['{{BaseURL}}/{{len(1, 2)}}']\n", "len");
    assert_reason(
        "variables:\n  v: '{{nope_fn(1)}}'\nhttp:\n  - path: ['{{BaseURL}}']\n",
        "nope_fn",
    );
    assert_reason(
        "tcp:\n  - host: ['{{Hostname}}']\n    inputs:\n      - data: '{{wait_for(1)}}'\n",
        "wait_for",
    );
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    extractors:\n      - type: dsl\n        dsl: ['frob(1)']\n", "frob");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: ['{{frobnicate(1)}}']\n", "frobnicate");
}

#[test]
fn jwt_algorithms_other_than_hmac_are_not_evaluated() {
    assert_reason("variables:\n  j: '{{generate_jwt(\"{}\", \"RS256\", \"k\")}}'\nhttp:\n  - path: ['{{BaseURL}}']\n", "RS256");
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}/{{generate_jwt(\"{}\", \"ES384\")}}']\n",
        "ES384",
    );
    for ok in ["HS256", "hs384", "HS512", "none", ""] {
        let r = reasons(&tpl(&format!("http:\n  - path: ['{{{{BaseURL}}}}/{{{{generate_jwt(\"{{}}\", \"{ok}\", \"k\")}}}}']\n")));
        assert!(r.is_empty(), "{ok}: {r:?}");
    }
}

#[test]
fn bad_regexes_and_patterns() {
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['(?<=a)b']\n", "regex");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    extractors:\n      - type: regex\n        regex: ['(unclosed']\n", "regex");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['(a{1000}){1000}']\n", "regex");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: binary\n        binary: ['zz']\n", "hex");
    assert_reason("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        encoding: hex\n        words: ['xyz']\n", "hex");
    // RE2-style classes still compile.
    assert!(reasons(&tpl("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['[[:alnum:]]{16}', '(?m)^a$', '(?s)a.b', '\\bx\\b']\n")).is_empty());
}

#[test]
fn braces_in_regex_are_not_interpolated() {
    let r = reasons(&tpl("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: regex\n        regex: ['a{{2}}', '{{not an expr}}']\n"));
    assert!(r.iter().all(|s| !s.contains("does not parse")), "{r:?}");
}

#[test]
fn payload_problems() {
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}/{{a}}']\n    attack: bogus\n    payloads:\n      a: [1]\n",
        "attack type",
    );
    assert_reason(
        "http:\n  - path: ['{{BaseURL}}/{{a}}']\n    payloads:\n      a: wordlists/files.txt\n",
        "wordlist",
    );
    assert_reason("http:\n  - path: ['{{BaseURL}}/{{a}}']\n    attack: clusterbomb\n    payloads:\n      a: [1]\n", "fewer than two");
    assert!(reasons(&tpl("http:\n  - path: ['{{BaseURL}}/{{a}}']\n    attack: pitchfork\n    payloads:\n      a: [1, 2]\n      b: [3, 4]\n")).is_empty());
}

#[test]
fn raw_annotations_other_than_the_supported_ones() {
    assert_reason(
        "http:\n  - raw:\n      - |\n        @weird: 1\n        GET / HTTP/1.1\n        Host: x\n",
        "@weird",
    );
    assert!(reasons(&tpl("http:\n  - raw:\n      - |\n        @Host: a.test\n        @timeout: 5s\n        @tls-sni: a.test\n        GET / HTTP/1.1\n        Host: x\n")).is_empty());
}

#[test]
fn dns_ssl_tcp_file_specific_triggers() {
    assert_reason(
        "dns:\n  - name: '{{FQDN}}'\n    type: DS\n",
        "DNS record type DS",
    );
    assert_reason(
        "dns:\n  - name: '{{FQDN}}'\n    type: A\n    trace: true\n",
        "trace",
    );
    assert_reason("dns:\n  - name: '{{FQDN}}'\n    class: bogus\n", "class");
    assert_reason(
        "ssl:\n  - address: '{{Host}}'\n    tls_version_enum: true\n",
        "TLS versions",
    );
    assert_reason(
        "ssl:\n  - address: '{{Host}}'\n    tls_cipher_enum: true\n",
        "ciphers",
    );
    assert_reason(
        "ssl:\n  - address: '{{Host}}'\n    cipher_suites: [TLS_AES_128_GCM_SHA256]\n",
        "cipher",
    );
    assert_reason(
        "ssl:\n  - address: '{{Host}}'\n    scan_mode: openssl\n",
        "scan_mode",
    );
    assert_reason(
        "ssl:\n  - address: '{{Host}}'\n    min_version: tls99\n",
        "TLS version",
    );
    assert_reason("tcp:\n  - host: ['{{Hostname}}']\n    port: ssh\n", "port");
    assert_reason(
        "tcp:\n  - host: ['{{Hostname}}']\n    inputs:\n      - data: x\n        type: base64\n",
        "input type",
    );
    assert_reason("file:\n  - extensions: ['application/json']\n", "mime");
    assert_reason(
        "file:\n  - extensions: [all]\n    mime-type: true\n",
        "mime",
    );
}

#[test]
fn a_template_with_no_supported_block_is_not_evaluated() {
    let r = reasons(&tpl(""));
    assert!(
        r.iter().any(|s| s.contains("no supported protocol block")),
        "{r:?}"
    );
    assert!(!load(&tpl("headless: []\n")).is_supported());
}

#[test]
fn every_trigger_is_found_at_load_not_at_run() {
    // A supported-looking template with the unsupported thing buried in the
    // second request is still not evaluated before any request exists.
    let t = load(&tpl("http:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n  - path: ['{{BaseURL}}/{{aes_gcm(\"k\", \"p\")}}']\n"));
    assert!(!t.is_supported());
}

#[test]
fn multiple_reasons_are_all_listed_once() {
    let r = reasons(&tpl("headless: []\nflow: x\nhttp:\n  - unsafe: true\n    path: ['{{BaseURL}}/{{interactsh-url}}']\n    race: true\n"));
    assert!(r.len() >= 5, "{r:?}");
    let mut dedup = r.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), r.len());
}

#[test]
fn yaml_scalar_styles_in_realistic_templates() {
    let t = load_supported(
        "id: styles\ninfo:\n  name: \"Quoted: with colon\"\n  severity: low\n  description: >-\n    folded text\n    on two lines\n  tags: [a, b]\nhttp:\n  - raw:\n      - |+\n        POST / HTTP/1.1\n        Host: {{Hostname}}\n        Content-Length: 6\n\n        0\n\n        G\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: body\n        words:\n          - 'it''s a \"word\"'\n          - \"tab\\there\"\n        condition: or\n      - {type: status, status: [200, 301]}\n",
    );
    assert_eq!(t.info.name, "Quoted: with colon");
    assert_eq!(t.info.description, "folded text on two lines");
    assert_eq!(t.http[0].ops.matchers.len(), 2);
    assert_eq!(t.http[0].ops.matchers[0].words[0].text, "it's a \"word\"");
    assert_eq!(t.http[0].ops.matchers[0].words[1].text, "tab\there");
    assert!(t.http[0].raw[0].ends_with("G\n"));
}

#[test]
fn yaml_aliases_and_merge_keys_are_bounded_but_work() {
    let t = load_supported(
        "id: t\ninfo:\n  name: T\nhttp:\n  - path: &p ['{{BaseURL}}/a']\n    matchers: &m\n      - type: status\n        status: [200]\n  - path: *p\n    matchers: *m\n",
    );
    assert_eq!(t.http.len(), 2);
    assert_eq!(t.http[1].paths, ["{{BaseURL}}/a"]);
}

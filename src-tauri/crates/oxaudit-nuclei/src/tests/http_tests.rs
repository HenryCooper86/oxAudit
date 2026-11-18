use super::*;
use crate::http_raw::parse_raw;
use crate::model::{AttackType, Payloads};
use crate::payloads::PayloadPlan;
use crate::{
    HttpResponseData, HttpRun, HttpTarget, RedirectMode, RunLimits, SkipReason, TemplateMatch,
};

fn target(url: &str) -> HttpTarget {
    HttpTarget::parse(url).expect("target")
}

fn run<'t>(t: &'t Template, url: &str) -> HttpRun<'t> {
    HttpRun::new(t, target(url), Box::new(ctx()))
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponseData {
    HttpResponseData {
        status,
        reason: "OK".into(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.as_bytes().to_vec(),
        ..HttpResponseData::default()
    }
}

fn header(yaml_http: &str) -> String {
    format!("id: t\ninfo:\n  name: T\n  severity: medium\nhttp:\n{yaml_http}")
}

/// Drives a run to the end answering every request with `answer`, collecting
/// the specs it produced.
fn drive(
    t: &Template,
    url: &str,
    mut answer: impl FnMut(&crate::HttpRequestSpec) -> HttpResponseData,
) -> (
    Vec<Result<crate::HttpRequestSpec, SkipReason>>,
    Vec<TemplateMatch>,
) {
    let mut run = run(t, url);
    let mut specs = Vec::new();
    while let Some(step) = run.next_request() {
        if let Ok(spec) = &step {
            run.on_response(answer(spec));
        }
        specs.push(step);
    }
    (specs, run.finish())
}

#[test]
fn target_variable_table_from_the_docs() {
    let vars = target("https://example.com:443/foo/bar.php").variables();
    let expected = [
        ("BaseURL", "https://example.com:443/foo/bar.php"),
        ("RootURL", "https://example.com:443"),
        ("Hostname", "example.com:443"),
        ("Host", "example.com"),
        ("Port", "443"),
        ("Path", "/foo"),
        ("File", "bar.php"),
        ("Scheme", "https"),
    ];
    for (name, value) in expected {
        assert_eq!(vars[name].to_text(), value, "{name}");
    }
    assert_eq!(vars["FQDN"].to_text(), "example.com");
}

#[test]
fn target_parsing_variants() {
    let v = target("example.com").variables();
    assert_eq!(v["BaseURL"].to_text(), "http://example.com");
    assert_eq!(v["Hostname"].to_text(), "example.com");
    assert_eq!(v["Port"].to_text(), "80");
    assert_eq!(v["Path"].to_text(), "/");
    assert_eq!(v["File"].to_text(), "");
    let v = target("https://example.com").variables();
    assert_eq!(v["Port"].to_text(), "443");
    let v = target("http://[::1]:8080/x/").variables();
    assert_eq!(v["Host"].to_text(), "::1");
    assert_eq!(v["Hostname"].to_text(), "[::1]:8080");
    assert_eq!(v["BaseURL"].to_text(), "http://[::1]:8080/x");
    assert!(!v.contains_key("FQDN"), "no domain parts for an IP literal");
    let v = target("HTTP://user:pw@Example.com:81/a/b/?q=1#f").variables();
    assert_eq!(v["BaseURL"].to_text(), "http://Example.com:81/a/b");
    assert_eq!(v["Path"].to_text(), "/a/b");
    assert_eq!(v["File"].to_text(), "b");
    for bad in ["", "ftp://x", "http://", "http://x:notaport", "http://[::1"] {
        assert!(HttpTarget::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn simple_get_with_matchers() {
    let t = load_supported(&header(concat!(
        "  - method: GET\n",
        "    path:\n      - \"{{BaseURL}}/.git/config\"\n      - \"{{RootURL}}/admin\"\n",
        "    headers:\n      X-Test: \"{{Host}}\"\n      Accept: text/html\n",
        "    matchers:\n      - type: word\n        words: ['[core]']\n",
    )));
    let (specs, matches) = drive(&t, "https://example.com:8443/app/", |spec| {
        if spec.url.ends_with("/.git/config") {
            resp(200, &[], "[core]\nrepositoryformatversion = 0")
        } else {
            resp(404, &[], "nope")
        }
    });
    let specs: Vec<_> = specs.into_iter().map(|s| s.expect("spec")).collect();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].method, "GET");
    assert_eq!(specs[0].url, "https://example.com:8443/app/.git/config");
    assert_eq!(specs[1].url, "https://example.com:8443/admin");
    assert_eq!(
        specs[0].headers,
        [
            ("X-Test".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "text/html".to_string())
        ]
    );
    assert_eq!(specs[0].follow_redirects.mode, RedirectMode::None);
    assert_eq!(
        (specs[0].request_index, specs[0].step, specs[1].step),
        (0, 1, 2)
    );
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.template_id, "t");
    assert_eq!(m.matched_at, "https://example.com:8443/app/.git/config");
    assert_eq!(m.protocol, crate::Protocol::Http);
    assert_eq!(m.severity, oxaudit_domain::Severity::Medium);
}

#[test]
fn relative_paths_merge_with_the_target_path() {
    let t = load_supported(&header(
        "  - path: ['/x', 'y', '']\n    matchers:\n      - type: status\n        status: [200]\n",
    ));
    let (specs, _) = drive(&t, "http://h.test/base", |_| resp(200, &[], ""));
    let urls: Vec<_> = specs.into_iter().map(|s| s.expect("spec").url).collect();
    assert_eq!(
        urls,
        [
            "http://h.test/base/x",
            "http://h.test/base/y",
            "http://h.test/base"
        ]
    );
    let t = load_supported(&header("  - path: ['/x']\n    disable-path-automerge: true\n    matchers:\n      - type: status\n        status: [200]\n"));
    let (specs, _) = drive(&t, "http://h.test/base", |_| resp(200, &[], ""));
    assert_eq!(specs[0].as_ref().expect("spec").url, "http://h.test/x");
}

#[test]
fn post_with_body_and_helper_functions() {
    let t = load_supported(&header(concat!(
        "  - method: post\n    path: ['{{BaseURL}}/api']\n",
        "    headers:\n      Authorization: \"Basic {{base64('user:pass')}}\"\n",
        "    body: 'a={{url_encode(\"x y\")}}&len={{len(\"abcd\")}}'\n",
        "    matchers:\n      - type: status\n        status: [200]\n",
    )));
    let (specs, matches) = drive(&t, "http://h.test", |_| resp(200, &[], ""));
    let spec = specs[0].as_ref().expect("spec");
    assert_eq!(spec.method, "POST");
    assert_eq!(spec.headers[0].1, "Basic dXNlcjpwYXNz");
    assert_eq!(spec.body, b"a=x+y&len=4");
    assert_eq!(matches.len(), 1);
}

#[test]
fn unresolved_variables_skip_the_request_with_a_reason() {
    let t = load_supported(&header("  - path: ['{{BaseURL}}/{{missing}}/{{Host}}']\n    matchers:\n      - type: status\n        status: [200]\n"));
    let mut r = run(&t, "http://h.test");
    assert_eq!(
        r.next_request(),
        Some(Err(SkipReason::UnresolvedVariable(vec!["missing".into()])))
    );
    assert_eq!(r.next_request(), None);
    // The check can be turned off by the template.
    let t = load_supported(&header("  - path: ['{{BaseURL}}/{{missing}}']\n    skip-variables-check: true\n    matchers:\n      - type: status\n        status: [200]\n"));
    let spec = run(&t, "http://h.test")
        .next_request()
        .expect("one")
        .expect("spec");
    assert_eq!(spec.url, "http://h.test/{{missing}}");
}

#[test]
fn template_variables_and_constants() {
    let t = load_supported(
        "id: t\ninfo:\n  name: T\nconstants:\n  c1: fixed\nvariables:\n  a1: value\n  a2: \"{{base64('hello')}}\"\n  a3: \"{{c1}}-{{a1}}\"\nhttp:\n  - path: ['{{BaseURL}}/?x={{a3}}']\n    headers:\n      Another: '{{a2}}'\n    matchers:\n      - type: word\n        words: ['{{a2}}']\n",
    );
    let (specs, matches) = drive(&t, "http://h.test", |_| resp(200, &[], "..aGVsbG8=.."));
    let spec = specs[0].as_ref().expect("spec");
    assert_eq!(spec.url, "http://h.test/?x=fixed-value");
    assert_eq!(spec.headers[0].1, "aGVsbG8=");
    assert_eq!(matches.len(), 1, "words see template variables");
}

// ------------------------------------------------------------------ raw

#[test]
fn raw_request_parsing() {
    let raw = b"POST /path2/ HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 99\n\na=test&b=pd\n";
    let r = parse_raw(raw).expect("parses");
    assert_eq!(r.method, "POST");
    assert_eq!(r.uri, "/path2/");
    assert_eq!(
        r.headers,
        [
            ("Host".to_string(), "example.com".to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            )
        ],
        "Content-Length is recomputed by the host"
    );
    assert_eq!(r.body, b"a=test&b=pd");
    // CRLF input, blank URI form, no body.
    let r = parse_raw(b"GET HTTP/1.1\r\nHost: x\r\n\r\n").expect("parses");
    assert_eq!(
        (r.method.as_str(), r.uri.as_str(), r.body.len()),
        ("GET", "", 0)
    );
    // Lower-case methods are normalised; the HTTP version is optional.
    assert_eq!(
        parse_raw(b"get /a\nHost: x\n").expect("parses").method,
        "GET"
    );
    // A body that contains blank lines is kept whole.
    let r = parse_raw(b"POST / HTTP/1.1\nHost: x\n\nline1\n\nline3").expect("parses");
    assert_eq!(r.body, b"line1\n\nline3");
}

#[test]
fn raw_annotations() {
    let raw = b"@Host: https://api.example.net:8443\n@timeout: 25s\n@tls-sni: request.host\nGET /k HTTP/1.1\nHost: api.example.net\n";
    let r = parse_raw(raw).expect("parses");
    assert_eq!(
        r.host_override.as_deref(),
        Some("https://api.example.net:8443")
    );
    assert_eq!(r.timeout_ms, Some(25_000));
    assert_eq!(r.tls_sni.as_deref(), Some("request.host"));
    assert_eq!(
        parse_raw(b"@timeout: 500ms\nGET / HTTP/1.1\n")
            .expect("ok")
            .timeout_ms,
        Some(500)
    );
    assert!(parse_raw(b"@timeout: soon\nGET / HTTP/1.1\n").is_err());
    assert!(parse_raw(b"@bogus: 1\nGET / HTTP/1.1\n").is_err());
}

#[test]
fn raw_request_errors() {
    for bad in [
        &b""[..],
        b"\n\n",
        b"JUSTONE\n",
        b"GET / HTTP/1.1 extra\n",
        b"G3T / HTTP/1.1\n",
        b"GET / HTTP/1.1\nNoColonHere\n",
        b"GET / HTTP/1.1\n bad: folded\n",
        b"GET / HTTP/1.1\nbad name: x\n",
    ] {
        assert!(
            parse_raw(bad).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn raw_requests_through_the_planner() {
    let t = load_supported(&header(concat!(
        "  - raw:\n",
        "      - |\n        GET /a?x={{rand_text_alpha(4)}} HTTP/1.1\n        Host: {{Hostname}}\n        X-Dyn: {{Hostname}}\n\n",
        "      - |\n        GET HTTP/1.1\n        Host: {{Hostname}}\n\n",
        "      - |\n        @Host: other.test:9000\n        POST /v HTTP/1.1\n        Host: other.test:9000\n\n        k=v\n\n",
        "      - |\n        @timeout: 3s\n        GET {{BaseURL}}/abs HTTP/1.1\n        Host: {{Hostname}}\n\n",
        "    matchers:\n      - type: status\n        status: [200]\n",
    )));
    let (specs, _) = drive(&t, "https://h.test:8443/root", |_| resp(200, &[], ""));
    let s: Vec<_> = specs.into_iter().map(|s| s.expect("spec")).collect();
    assert_eq!(s.len(), 4);
    assert!(
        s[0].url.starts_with("https://h.test:8443/root/a?x="),
        "{}",
        s[0].url
    );
    assert_eq!(
        s[0].headers[0],
        ("Host".to_string(), "h.test:8443".to_string())
    );
    assert_eq!(s[1].url, "https://h.test:8443/root");
    assert_eq!(s[2].url, "https://other.test:9000/v");
    assert_eq!(s[2].method, "POST");
    assert_eq!(s[2].body, b"k=v");
    assert_eq!(s[3].url, "https://h.test:8443/root/abs");
    assert_eq!(s[3].timeout_ms, Some(3000));
}

#[test]
fn malformed_raw_requests_are_skips() {
    let t = load_supported(&header("  - raw:\n      - |\n        this is not http\n    matchers:\n      - type: status\n        status: [200]\n"));
    let mut r = run(&t, "http://h.test");
    assert!(matches!(
        r.next_request(),
        Some(Err(SkipReason::Malformed(_)))
    ));
}

// ------------------------------------------------------- payload attacks

fn sets(attack: AttackType, sets: &[(&str, &[&str])]) -> Payloads {
    Payloads {
        attack,
        sets: sets
            .iter()
            .map(|(n, v)| (n.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect(),
    }
}

fn combos(p: &Payloads, cap: usize) -> Vec<Vec<(String, String)>> {
    let plan = PayloadPlan::new(p, cap);
    (0..plan.total()).map(|i| plan.combination(i)).collect()
}

fn flat(c: &[Vec<(String, String)>]) -> Vec<String> {
    c.iter()
        .map(|row| {
            row.iter()
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect()
}

#[test]
fn payload_combination_order() {
    let ram = sets(
        AttackType::BatteringRam,
        &[("a", &["1", "2", "3"]), ("b", &["x"])],
    );
    assert_eq!(flat(&combos(&ram, 100)), ["1+1", "2+2", "3+3"]);
    let fork = sets(
        AttackType::Pitchfork,
        &[("a", &["1", "2", "3"]), ("b", &["x", "y"])],
    );
    assert_eq!(flat(&combos(&fork, 100)), ["1+x", "2+y"]);
    let bomb = sets(
        AttackType::ClusterBomb,
        &[("a", &["1", "2"]), ("b", &["x", "y", "z"])],
    );
    assert_eq!(
        flat(&combos(&bomb, 100)),
        ["1+x", "1+y", "1+z", "2+x", "2+y", "2+z"]
    );
    let three = sets(
        AttackType::ClusterBomb,
        &[("a", &["1", "2"]), ("b", &["x", "y"]), ("c", &["p", "q"])],
    );
    assert_eq!(
        flat(&combos(&three, 100)),
        ["1+x+p", "1+x+q", "1+y+p", "1+y+q", "2+x+p", "2+x+q", "2+y+p", "2+y+q"]
    );
    let empty = sets(AttackType::ClusterBomb, &[("a", &["1"]), ("b", &[])]);
    assert!(combos(&empty, 100).is_empty());
    let none = Payloads::default();
    assert_eq!(PayloadPlan::new(&none, 5).total(), 1);
}

#[test]
fn payload_cap_is_a_hard_limit() {
    let big: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
    let refs: Vec<&str> = big.iter().map(String::as_str).collect();
    let p = sets(
        AttackType::ClusterBomb,
        &[("a", &refs), ("b", &refs), ("c", &refs)],
    );
    let plan = PayloadPlan::new(&p, 250);
    assert_eq!(plan.total(), 250);
    assert!(plan.truncated());
    assert_eq!(plan.combination(249).len(), 3);
    assert!(plan.combination(250).is_empty());
    assert!(!PayloadPlan::new(&sets(AttackType::BatteringRam, &[("a", &["1"])]), 250).truncated());
}

#[test]
fn payload_attacks_through_the_planner() {
    let bodies = |attack: &str, payloads: &str, body: &str| {
        let t = load_supported(&header(&format!(
            "  - method: POST\n    path: ['{{{{BaseURL}}}}/login']\n    body: '{body}'\n    attack: {attack}\n    payloads:\n{payloads}    matchers:\n      - type: status\n        status: [200]\n"
        )));
        let (specs, _) = drive(&t, "http://h.test", |_| resp(200, &[], ""));
        specs
            .into_iter()
            .map(|s| String::from_utf8(s.expect("spec").body).expect("utf8"))
            .collect::<Vec<_>>()
    };
    let two = "      user: [admin, root]\n      pass: [a, b, c]\n";
    assert_eq!(
        bodies("clusterbomb", two, "u={{user}}&p={{pass}}"),
        [
            "u=admin&p=a",
            "u=admin&p=b",
            "u=admin&p=c",
            "u=root&p=a",
            "u=root&p=b",
            "u=root&p=c"
        ]
    );
    assert_eq!(
        bodies("pitchfork", two, "u={{user}}&p={{pass}}"),
        ["u=admin&p=a", "u=root&p=b"]
    );
    assert_eq!(
        bodies("batteringram", "      v: ['1', '2']\n", "x={{v}}&y={{v}}"),
        ["x=1&y=1", "x=2&y=2"]
    );
    // Default attack is batteringram, and payload values can use helpers.
    assert_eq!(
        bodies(
            "batteringram",
            "      v: [\"{{to_upper('ab')}}\", 7]\n",
            "{{v}}"
        ),
        ["AB", "7"]
    );
}

#[test]
fn payload_values_are_reported_on_the_spec_and_capped_by_run_limits() {
    let big = (0..100)
        .map(|i| format!("'{i}'"))
        .collect::<Vec<_>>()
        .join(",");
    let t = load_supported(&header(&format!(
        "  - path: ['{{{{BaseURL}}}}/{{{{a}}}}/{{{{b}}}}']\n    attack: clusterbomb\n    payloads:\n      a: [{big}]\n      b: [{big}]\n    matchers:\n      - type: status\n        status: [200]\n"
    )));
    let mut r = HttpRun::with_limits(
        &t,
        target("http://h.test"),
        Box::new(ctx()),
        RunLimits {
            max_payload_combinations: 37,
            ..RunLimits::default()
        },
    );
    let mut n = 0;
    let mut last = None;
    while let Some(step) = r.next_request() {
        last = Some(step.expect("spec"));
        r.on_response(resp(200, &[], ""));
        n += 1;
    }
    assert_eq!(n, 37);
    let truncations = r.truncations();
    assert_eq!(truncations.len(), 1, "{truncations:?}");
    assert_eq!(
        truncations[0].message,
        "http request 0: only 37 of 10000 payload combinations were sent (the cap is 37)"
    );
    assert!(
        r.warnings().is_empty(),
        "a cap is a truncation, not a warning"
    );
    assert_eq!(
        last.expect("last").payload_values,
        [
            ("a".to_string(), "0".to_string()),
            ("b".to_string(), "36".to_string())
        ]
    );
}

// ------------------------------------------------- chaining and conditions

const CHAIN: &str = concat!(
    "  - raw:\n",
    "      - |\n        GET /login HTTP/1.1\n        Host: {{Hostname}}\n\n",
    "      - |\n        POST /do?t={{token}} HTTP/1.1\n        Host: {{Hostname}}\n        Content-Type: application/x-www-form-urlencoded\n\n        csrf={{token}}&u=admin\n\n",
    "    extractors:\n      - type: regex\n        name: token\n        part: body\n        group: 1\n        regex: ['name=\"csrf\" value=\"([a-f0-9]+)\"']\n        internal: true\n",
    "    matchers:\n      - type: dsl\n        dsl: [\"status_code == 200 && contains(body, 'welcome')\"]\n",
);

#[test]
fn internal_extractor_chains_two_requests() {
    let t = load_supported(&header(CHAIN));
    let mut r = run(&t, "http://h.test");
    let first = r.next_request().expect("first").expect("spec");
    assert_eq!(first.url, "http://h.test/login");
    let out = r.on_response(resp(200, &[], "<input name=\"csrf\" value=\"abc123\">"));
    assert!(!out.matched);
    let second = r.next_request().expect("second").expect("spec");
    assert_eq!(second.url, "http://h.test/do?t=abc123");
    assert_eq!(second.body, b"csrf=abc123&u=admin");
    let out = r.on_response(resp(200, &[], "welcome admin"));
    assert!(out.matched, "{out:?}");
    assert!(r.next_request().is_none());
    let matches = r.finish();
    assert_eq!(matches.len(), 1);
    assert!(
        matches[0].extracted.is_empty(),
        "internal values are never reported"
    );
}

#[test]
fn chained_request_is_skipped_when_the_first_gave_nothing() {
    let t = load_supported(&header(CHAIN));
    let mut r = run(&t, "http://h.test");
    r.next_request().expect("first").expect("spec");
    r.on_response(resp(200, &[], "no token here"));
    assert_eq!(
        r.next_request(),
        Some(Err(SkipReason::UnresolvedVariable(vec!["token".into()])))
    );
}

#[test]
fn internal_matcher_and_extractor_across_http_blocks() {
    let t = load_supported(&header(concat!(
        "  - path: ['{{BaseURL}}/probe']\n",
        "    matchers:\n      - type: word\n        words: ['plugin-active']\n        internal: true\n",
        "    extractors:\n      - type: regex\n        name: rid\n        internal: true\n        group: 1\n        regex: ['rid=(\\d+)']\n",
        "  - path: ['{{BaseURL}}/item/{{rid}}']\n",
        "    matchers:\n      - type: word\n        name: found\n        words: ['item-body']\n",
    )));
    let (specs, matches) = drive(&t, "http://h.test", |spec| {
        if spec.url.ends_with("/probe") {
            resp(200, &[], "plugin-active rid=77")
        } else {
            resp(200, &[], "item-body")
        }
    });
    assert_eq!(
        specs[1].as_ref().expect("spec").url,
        "http://h.test/item/77"
    );
    assert_eq!(specs[1].as_ref().expect("spec").request_index, 1);
    assert_eq!(
        matches.len(),
        1,
        "the internal matcher of block 0 is not reported"
    );
    assert_eq!(matches[0].request_index, 1);
    assert_eq!(matches[0].matcher_names, ["found"]);
}

#[test]
fn request_conditions_use_numeric_suffixes() {
    let t = load_supported(&header(concat!(
        "  - method: GET\n    path: ['{{BaseURL}}/a', '{{BaseURL}}/b']\n",
        "    matchers:\n      - type: dsl\n        dsl:\n          - \"status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')\"\n",
    )));
    assert!(t.http[0].keep_history);
    let mut r = run(&t, "http://h.test");
    r.next_request().expect("a").expect("spec");
    let out = r.on_response(resp(404, &[], "missing"));
    assert!(!out.matched);
    assert!(
        out.warnings.is_empty(),
        "a not-yet-seen suffix is not a warning: {:?}",
        out.warnings
    );
    r.next_request().expect("b").expect("spec");
    let out = r.on_response(resp(200, &[], "xx secret_string xx"));
    assert!(out.matched, "{out:?}");
    assert_eq!(r.finish().len(), 1);
}

#[test]
fn history_is_kept_only_when_an_expression_needs_it() {
    let plain = load_supported(&header("  - path: ['{{BaseURL}}/a']\n    matchers:\n      - type: dsl\n        dsl: ['status_code == 200']\n"));
    assert!(!plain.http[0].keep_history);
    let explicit = load_supported(&header("  - path: ['{{BaseURL}}/a']\n    req-condition: true\n    matchers:\n      - type: status\n        status: [200]\n"));
    assert!(explicit.http[0].keep_history);
    // A payload named like a suffixed variable is not history.
    let payload = load_supported(&header("  - path: ['{{BaseURL}}/{{item_1}}']\n    payloads:\n      item_1: [a]\n    matchers:\n      - type: dsl\n        dsl: ['len(item_1) > 0']\n"));
    assert!(!payload.http[0].keep_history);
}

#[test]
fn stop_at_first_match() {
    let body = |flag: &str| {
        header(&format!(
            "  - path: ['{{{{BaseURL}}}}/a', '{{{{BaseURL}}}}/b', '{{{{BaseURL}}}}/c']\n    {flag}\n    matchers:\n      - type: status\n        status: [200]\n"
        ))
    };
    let (specs, matches) = drive(
        &load_supported(&body("stop-at-first-match: true")),
        "http://h.test",
        |_| resp(200, &[], ""),
    );
    assert_eq!((specs.len(), matches.len()), (1, 1));
    let (specs, matches) = drive(
        &load_supported(&body("stop-at-first-match: false")),
        "http://h.test",
        |_| resp(200, &[], ""),
    );
    assert_eq!((specs.len(), matches.len()), (3, 3));
    let stopping = load_supported(&body("stop-at-first-match: true"));
    let mut r = run(&stopping, "http://h.test");
    r.next_request();
    assert!(r.on_response(resp(200, &[], "")).stop);
}

#[test]
fn redirect_and_cookie_settings() {
    let policy = |extra: &str| {
        let t = load_supported(&header(&format!("  - path: ['{{{{BaseURL}}}}']\n    {extra}\n    matchers:\n      - type: status\n        status: [200]\n")));
        let spec = run(&t, "http://h.test")
            .next_request()
            .expect("one")
            .expect("spec");
        (spec.follow_redirects, spec.cookie_reuse)
    };
    let (p, cookies) = policy("");
    assert_eq!((p.mode, p.max, cookies), (RedirectMode::None, 10, true));
    let (p, _) = policy("redirects: true");
    assert_eq!((p.mode, p.max), (RedirectMode::Any, 10));
    let (p, _) = policy("redirects: true\n    max-redirects: 3");
    assert_eq!((p.mode, p.max), (RedirectMode::Any, 3));
    let (p, _) = policy("host-redirects: true");
    assert_eq!(p.mode, RedirectMode::SameHost);
    let (_, cookies) = policy("disable-cookie: true");
    assert!(!cookies);
    let (_, cookies) = policy("cookie-reuse: true");
    assert!(cookies);
    let (_, cookies) = policy("disable_cookie: true");
    assert!(!cookies, "underscore spelling");
}

#[test]
fn iterate_all_fans_out_over_extracted_values() {
    let tpl = |iterate: &str| {
        load_supported(&header(&format!(
            "  - path: ['{{{{BaseURL}}}}/list']\n    extractors:\n      - type: regex\n        name: id\n        internal: true\n        group: 1\n        regex: ['id=(\\d+)']\n  - path: ['{{{{BaseURL}}}}/item/{{{{id}}}}']\n    {iterate}\n    matchers:\n      - type: status\n        status: [200]\n"
        )))
    };
    let answer = |spec: &crate::HttpRequestSpec| {
        if spec.url.ends_with("/list") {
            resp(200, &[], "id=1 id=2 id=3")
        } else {
            resp(200, &[], "")
        }
    };
    let (specs, _) = drive(&tpl(""), "http://h.test", answer);
    let urls: Vec<_> = specs.into_iter().map(|s| s.expect("spec").url).collect();
    assert_eq!(urls, ["http://h.test/list", "http://h.test/item/1"]);
    let (specs, matches) = drive(&tpl("iterate-all: true"), "http://h.test", answer);
    let urls: Vec<_> = specs.into_iter().map(|s| s.expect("spec").url).collect();
    assert_eq!(
        urls,
        [
            "http://h.test/list",
            "http://h.test/item/1",
            "http://h.test/item/2",
            "http://h.test/item/3"
        ]
    );
    assert_eq!(matches.len(), 3);
}

#[test]
fn iterate_all_fan_out_cap_is_reported_as_a_truncation() {
    let t = load_supported(&header(
        "  - path: ['{{BaseURL}}/list']\n    extractors:\n      - type: regex\n        name: id\n        internal: true\n        group: 1\n        regex: ['id=(\\d+)']\n  - path: ['{{BaseURL}}/item/{{id}}']\n    iterate-all: true\n    matchers:\n      - type: status\n        status: [200]\n",
    ));
    let mut r = HttpRun::with_limits(
        &t,
        target("http://h.test"),
        Box::new(ctx()),
        RunLimits {
            max_iterate_all_variants: 2,
            ..RunLimits::default()
        },
    );
    let mut urls = Vec::new();
    while let Some(step) = r.next_request() {
        let spec = step.expect("spec");
        let body = if spec.url.ends_with("/list") {
            "id=1 id=2 id=3 id=4 id=5"
        } else {
            ""
        };
        urls.push(spec.url);
        r.on_response(resp(200, &[], body));
    }
    assert_eq!(urls.len(), 4, "{urls:?}");
    let cut = r.truncations();
    assert_eq!(cut.len(), 1, "{cut:?}");
    assert_eq!(cut[0].request_index, 1);
    assert_eq!(
        cut[0].message,
        "http request 1: iterate-all sent only 2 of 4 further value combinations (the cap is 2)"
    );
}

#[test]
fn response_parts_exposed_to_matchers() {
    let t = load_supported(&header(concat!(
        "  - path: ['{{BaseURL}}']\n    matchers-condition: and\n    matchers:\n",
        "      - type: dsl\n        dsl:\n          - 'status_code == 301'\n          - 'content_length == 11'\n          - 'x_custom == \"1, 2\"'\n          - 'contains(header, \"Location: /next\")'\n          - 'contains(all_headers, \"X-Custom: 1\")'\n          - 'contains(raw, \"HTTP/1.1 301\") && contains(response, \"hello world\") && contains(all, \"X-Custom\")'\n          - 'contains(request, \"GET http://h.test\")'\n          - 'host == \"h.test\" && url == \"http://h.test\"'\n          - 'duration >= 0.25 && duration < 1'\n          - 'contains(cookies_from_response, \"sid: abc\")'\n          - 'contains(headers_from_response, \"x_custom: 1\")'\n        condition: and\n",
        "      - type: word\n        part: location\n        words: ['/next']\n",
    )));
    let mut r = run(&t, "http://h.test");
    r.next_request().expect("one").expect("spec");
    let mut response = resp(
        301,
        &[
            ("Location", "/next"),
            ("X-Custom", "1"),
            ("X-Custom", "2"),
            ("Set-Cookie", "sid=abc; Path=/"),
        ],
        "hello world",
    );
    response.duration_ms = 250;
    let out = r.on_response(response);
    assert!(out.matched, "{out:?}");
}

#[test]
fn kval_extractor_reads_headers_and_cookies() {
    let t = load_supported(&header(
        "  - path: ['{{BaseURL}}']\n    extractors:\n      - type: kval\n        name: kv\n        kval: [content_type, sid]\n",
    ));
    let (_, matches) = drive(&t, "http://h.test", |_| {
        resp(
            200,
            &[
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "sid=xyz; HttpOnly"),
            ],
            "",
        )
    });
    assert_eq!(
        matches[0].extracted,
        [(
            "kv".to_string(),
            vec!["text/plain".to_string(), "xyz".to_string()]
        )]
    );
}

#[test]
fn binary_bodies_are_matched_as_bytes() {
    let t = load_supported(&header("  - path: ['{{BaseURL}}/f.zip']\n    matchers:\n      - type: binary\n        binary: ['504B0304']\n"));
    let mut r = run(&t, "http://h.test");
    r.next_request();
    let mut response = resp(200, &[], "");
    response.body = vec![0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe];
    assert!(r.on_response(response).matched);
}

#[test]
fn response_without_request_is_harmless() {
    let t = load_supported(&header(
        "  - path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n",
    ));
    let mut r = run(&t, "http://h.test");
    let out = r.on_response(resp(200, &[], ""));
    assert!(!out.matched && !out.warnings.is_empty());
}

#[test]
fn request_conditions_are_bounded_for_large_blocks() {
    let big = (0..100)
        .map(|i| format!("'{i}'"))
        .collect::<Vec<_>>()
        .join(",");
    let t = load_supported(&header(&format!(
        "  - path: ['{{{{BaseURL}}}}/{{{{a}}}}']\n    payloads:\n      a: [{big}]\n    req-condition: true\n    matchers:\n      - type: dsl\n        dsl: ['status_code_1 == 200']\n"
    )));
    let mut r = run(&t, "http://h.test");
    r.next_request();
    r.on_response(resp(200, &[], ""));
    assert!(r
        .truncations()
        .iter()
        .any(|t| t.message.contains("request conditions disabled")));
}

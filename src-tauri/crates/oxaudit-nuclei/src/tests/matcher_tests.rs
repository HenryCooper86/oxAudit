use super::*;
use crate::dsl::Value;
use crate::matchers::{build_operators, evaluate_block, evaluate_matchers, ResponseParts};
use crate::model::Operators;
use crate::support::Reasons;
use crate::yaml::parse_document;

fn ops(src: &str) -> Operators {
    let doc = parse_document(src).expect("yaml");
    let mut reasons = Reasons::default();
    let ops = build_operators(&doc, &mut reasons);
    assert!(
        reasons.is_empty(),
        "unexpected reasons: {:?}",
        reasons.into_vec()
    );
    ops
}

fn http_parts(status: i64, header: &str, body: &str) -> ResponseParts {
    let mut p = ResponseParts::new("body");
    p.set("body", body);
    p.set("header", header);
    p.set("all_headers", header);
    p.set("status_code", Value::Int(status));
    p.set("content_length", Value::Int(body.len() as i64));
    p.set("raw", format!("HTTP/1.1 {status} OK\r\n{header}\r\n{body}"));
    p
}

fn matched(ops: &Operators, parts: &ResponseParts) -> bool {
    evaluate_matchers(ops, parts, &mut ctx()).matched
}

#[test]
fn word_matcher_fields() {
    let parts = http_parts(
        200,
        "Server: nginx\r\nX-Powered-By: PHP\r\n",
        "Hello World [core]",
    );
    // or (default)
    assert!(matched(
        &ops("matchers:\n - type: word\n   words: [nope, '[core]']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: word\n   words: [nope, nada]"),
        &parts
    ));
    // and
    assert!(matched(
        &ops("matchers:\n - type: word\n   condition: and\n   words: [Hello, World]"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: word\n   condition: and\n   words: [Hello, nope]"),
        &parts
    ));
    // part
    assert!(matched(
        &ops("matchers:\n - type: word\n   part: header\n   words: ['Server: nginx']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: word\n   part: body\n   words: ['Server: nginx']"),
        &parts
    ));
    // case-insensitive
    assert!(!matched(
        &ops("matchers:\n - type: word\n   words: [hello world]"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: word\n   case-insensitive: true\n   words: [hello world]"),
        &parts
    ));
    // negative
    assert!(matched(
        &ops("matchers:\n - type: word\n   negative: true\n   part: header\n   words: [PHPSESSID]"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: word\n   negative: true\n   part: header\n   words: [nginx]"),
        &parts
    ));
    // hex-encoded words: "50494e47" is "PING"
    let ping = http_parts(200, "", "xx PING xx");
    assert!(matched(
        &ops("matchers:\n - type: word\n   encoding: hex\n   words: ['50494e47']"),
        &ping
    ));
    assert!(!matched(
        &ops("matchers:\n - type: word\n   encoding: hex\n   words: ['50494e48']"),
        &ping
    ));
    // raw part includes the status line
    assert!(matched(
        &ops("matchers:\n - type: word\n   part: raw\n   words: ['HTTP/1.1 200']"),
        &parts
    ));
}

#[test]
fn match_all_reports_every_matching_word() {
    let parts = http_parts(200, "", "alpha beta gamma");
    let plain = ops("matchers:\n - type: word\n   words: [alpha, beta, nope]");
    let all = ops("matchers:\n - type: word\n   match-all: true\n   words: [alpha, beta, nope]");
    assert_eq!(
        evaluate_matchers(&plain, &parts, &mut ctx()).matched_values,
        ["alpha"]
    );
    assert_eq!(
        evaluate_matchers(&all, &parts, &mut ctx()).matched_values,
        ["alpha", "beta"]
    );
}

#[test]
fn words_are_interpolated_with_leniency() {
    let mut parts = http_parts(200, "", "welcome admin.example.test {{ x.y }}");
    parts.set("Host", "admin.example.test");
    assert!(matched(
        &ops("matchers:\n - type: word\n   words: ['welcome {{Host}}']"),
        &parts
    ));
    // An undefined variable stays literal, so it can match literally.
    assert!(matched(
        &ops("matchers:\n - type: word\n   words: ['{{ x.y }}']"),
        &parts
    ));
}

#[test]
fn regex_matcher_fields() {
    let parts = http_parts(200, "Location: https://Evil.example/\r\n", "id=42 Name=Bob");
    assert!(matched(
        &ops("matchers:\n - type: regex\n   regex: ['id=\\d+']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: regex\n   regex: ['id=x\\d+']"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: regex\n   condition: and\n   regex: ['id=\\d+', 'Name=\\w+']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: regex\n   condition: and\n   regex: ['id=\\d+', 'Nope=\\w+']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: regex\n   regex: ['name=bob']"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: regex\n   case-insensitive: true\n   regex: ['name=bob']"),
        &parts
    ));
    assert!(matched(
        &ops(
            "matchers:\n - type: regex\n   part: header\n   regex: ['(?i)^location: https://evil']"
        ),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: regex\n   negative: true\n   regex: ['zzz']"),
        &parts
    ));
    let o = evaluate_matchers(
        &ops("matchers:\n - type: regex\n   regex: ['id=(\\d+)']"),
        &parts,
        &mut ctx(),
    );
    assert_eq!(o.matched_values, ["id=42"]);
}

#[test]
fn binary_matcher() {
    let mut parts = ResponseParts::new("body");
    parts.set(
        "body",
        Value::Bytes(vec![0x00, 0x50, 0x4b, 0x03, 0x04, 0xff]),
    );
    assert!(matched(
        &ops("matchers:\n - type: binary\n   binary: ['504B0304']"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: binary\n   binary: ['deadbeef', '04ff']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: binary\n   binary: ['deadbeef']"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: binary\n   condition: and\n   binary: ['504b', 'deadbeef']"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: binary\n   condition: and\n   binary: ['504b', 'ff']"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: binary\n   negative: true\n   binary: ['deadbeef']"),
        &parts
    ));
}

#[test]
fn status_and_size_matchers() {
    let parts = http_parts(302, "", "12345");
    assert!(matched(
        &ops("matchers:\n - type: status\n   status: [200, 302]"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: status\n   status: [200, 404]"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: status\n   negative: true\n   status: [200]"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: size\n   size: [5]"),
        &parts
    ));
    assert!(!matched(
        &ops("matchers:\n - type: size\n   size: [6, 7]"),
        &parts
    ));
    assert!(matched(
        &ops("matchers:\n - type: size\n   part: header\n   size: [0]"),
        &parts
    ));
    // No status part (not an HTTP response): warns, does not match, even negated.
    let none = ResponseParts::new("data");
    let o = evaluate_matchers(
        &ops("matchers:\n - type: status\n   negative: true\n   status: [200]"),
        &none,
        &mut ctx(),
    );
    assert!(!o.matched);
    assert!(!o.warnings.is_empty());
}

#[test]
fn dsl_matcher_fields() {
    let parts = http_parts(200, "Content-Type: text/html\r\n", "secret page");
    let all = ops("matchers:\n - type: dsl\n   condition: and\n   dsl:\n    - 'status_code == 200'\n    - 'contains(body, \"secret\")'");
    assert!(matched(&all, &parts));
    let fail = ops("matchers:\n - type: dsl\n   condition: and\n   dsl:\n    - 'status_code == 200'\n    - 'contains(body, \"nope\")'");
    assert!(!matched(&fail, &parts));
    let any =
        ops("matchers:\n - type: dsl\n   dsl:\n    - 'status_code == 404'\n    - 'len(body) > 3'");
    assert!(matched(&any, &parts));
    assert!(matched(
        &ops("matchers:\n - type: dsl\n   negative: true\n   dsl: ['status_code == 404']"),
        &parts
    ));
}

#[test]
fn dsl_errors_are_warnings_and_do_not_match() {
    let parts = http_parts(200, "", "x");
    let o = evaluate_matchers(
        &ops("matchers:\n - type: dsl\n   dsl: ['missing_var == 1']"),
        &parts,
        &mut ctx(),
    );
    assert!(!o.matched);
    assert!(
        o.warnings
            .iter()
            .any(|w| w.contains("unknown variable `missing_var`")),
        "{:?}",
        o.warnings
    );
    // Negation does not turn a failed evaluation into a match.
    let neg = evaluate_matchers(
        &ops("matchers:\n - type: dsl\n   negative: true\n   dsl: ['missing_var == 1']"),
        &parts,
        &mut ctx(),
    );
    assert!(!neg.matched);
    let non_bool = evaluate_matchers(
        &ops("matchers:\n - type: dsl\n   dsl: ['len(body)']"),
        &parts,
        &mut ctx(),
    );
    assert!(!non_bool.matched);
    assert!(non_bool
        .warnings
        .iter()
        .any(|w| w.contains("instead of a bool")));
}

#[test]
fn matchers_condition_and_or_with_names() {
    let parts = http_parts(200, "Server: nginx\r\n", "php body");
    let src_or = "matchers:\n - type: word\n   name: nginx\n   part: header\n   words: [nginx]\n - type: word\n   name: php\n   words: [php]\n - type: word\n   name: iis\n   words: [IIS]";
    let o = evaluate_matchers(&ops(src_or), &parts, &mut ctx());
    assert!(o.matched);
    assert_eq!(
        o.matcher_names,
        ["nginx", "php"],
        "every matching named matcher is reported"
    );
    let src_and = format!("matchers-condition: and\n{src_or}");
    let o = evaluate_matchers(&ops(&src_and), &parts, &mut ctx());
    assert!(!o.matched);
    assert!(o.matcher_names.is_empty());
    let ok_and = "matchers-condition: and\nmatchers:\n - type: word\n   name: a\n   words: [php]\n - type: status\n   status: [200]";
    let o = evaluate_matchers(&ops(ok_and), &parts, &mut ctx());
    assert!(o.matched);
    assert_eq!(o.matcher_names, ["a"]);
}

#[test]
fn internal_matchers_gate_but_do_not_report() {
    let parts = http_parts(200, "", "marker here");
    let only_internal = ops("matchers:\n - type: word\n   internal: true\n   words: [marker]");
    let o = evaluate_matchers(&only_internal, &parts, &mut ctx());
    assert!(o.matched && !o.reportable);
    let mut p = parts.clone();
    let b = evaluate_block(&only_internal, &mut p, &mut ctx());
    assert!(!b.matched && b.gate_passed);
    let mixed = ops("matchers:\n - type: word\n   internal: true\n   name: hidden\n   words: [marker]\n - type: word\n   name: shown\n   words: [here]");
    let o = evaluate_matchers(&mixed, &parts, &mut ctx());
    assert!(o.reportable);
    assert_eq!(o.matcher_names, ["shown"]);
}

#[test]
fn extractor_only_block_matches_when_something_is_extracted() {
    let parts = http_parts(200, "", "key=AKIA1234 other");
    let block = ops("extractors:\n - type: regex\n   name: key\n   regex: ['AKIA[0-9]+']");
    let mut p = parts.clone();
    let r = evaluate_block(&block, &mut p, &mut ctx());
    assert!(r.matched);
    assert_eq!(
        r.extracted,
        [("key".to_string(), vec!["AKIA1234".to_string()])]
    );
    let miss = ops("extractors:\n - type: regex\n   regex: ['ZZZ[0-9]+']");
    assert!(!evaluate_block(&miss, &mut parts.clone(), &mut ctx()).matched);
    // Neither matchers nor extractors: nothing to report.
    assert!(!evaluate_block(&ops("id: x"), &mut parts.clone(), &mut ctx()).matched);
}

#[test]
fn extractors_regex_group_kval_dsl() {
    let mut parts = http_parts(
        200,
        "Content-Type: text/html\r\nX-Request-Id: abc-1\r\n",
        "<title>Hi</title><title>Yo</title><title>Hi</title>",
    );
    parts.set("content_type", "text/html");
    parts.set("x_request_id", "abc-1");
    parts.add_kval("Content-Type", "text/html");
    parts.add_kval("X-Request-Id", "abc-1");
    parts.add_kval("session", "s3cr3t");
    let block = ops(concat!(
        "extractors:\n",
        " - type: regex\n   name: whole\n   regex: ['<title>[A-Za-z]+</title>']\n",
        " - type: regex\n   name: titles\n   group: 1\n   regex: ['<title>([A-Za-z]+)</title>']\n",
        " - type: regex\n   name: nogroup\n   group: 9\n   regex: ['<title>([A-Za-z]+)</title>']\n",
        " - type: kval\n   name: headers\n   kval: [content_type, X-Request-Id, SESSION, absent]\n",
        " - type: dsl\n   name: size\n   dsl: ['len(body)', 'status_code + 1']\n",
    ));
    let r = evaluate_block(&block, &mut parts, &mut ctx());
    assert!(r.matched);
    let get = |n: &str| {
        r.extracted
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        get("whole").expect("whole").len(),
        2,
        "duplicates are collapsed"
    );
    assert_eq!(get("titles").expect("titles"), ["Hi", "Yo"]);
    assert_eq!(get("nogroup"), None);
    assert_eq!(
        get("headers").expect("headers"),
        ["text/html", "abc-1", "s3cr3t"]
    );
    assert_eq!(get("size").expect("size"), ["51", "201"]);
    assert!(r.warnings.iter().any(|w| w.contains("`absent`")));
}

#[test]
fn internal_extractors_are_not_reported_and_feed_later_matchers() {
    let mut parts = http_parts(200, "", "token=abc123 ok");
    let block = ops(concat!(
        "extractors:\n",
        " - type: regex\n   name: tok\n   internal: true\n   group: 1\n   regex: ['token=(\\w+)']\n",
        " - type: dsl\n   name: shown\n   dsl: ['\"Token is \" + tok']\n",
        "matchers:\n",
        " - type: dsl\n   dsl: ['tok == \"abc123\"']\n",
    ));
    let r = evaluate_block(&block, &mut parts, &mut ctx());
    assert!(r.matched);
    assert_eq!(
        r.internal,
        [("tok".to_string(), vec!["abc123".to_string()])]
    );
    assert_eq!(
        r.extracted,
        [("shown".to_string(), vec!["Token is abc123".to_string()])]
    );
}

#[test]
fn extractor_case_insensitive_and_missing_part() {
    let mut parts = http_parts(200, "", "Version: ABC");
    let block = ops("extractors:\n - type: regex\n   case-insensitive: true\n   name: v\n   regex: ['version: (\\w+)']\n   group: 1");
    assert!(evaluate_block(&block, &mut parts, &mut ctx()).matched);
    let bad_part = ops("extractors:\n - type: regex\n   part: nonexistent\n   regex: ['x']");
    let r = evaluate_block(&bad_part, &mut parts, &mut ctx());
    assert!(!r.matched);
    assert!(!r.warnings.is_empty());
}

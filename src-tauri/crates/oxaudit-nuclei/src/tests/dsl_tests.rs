use super::*;
use crate::dsl::{parse, DslError, EvalContext, Expr};
use crate::vars::{interpolate, interpolate_detailed};

fn err(src: &str) -> DslError {
    eval_str(src, &Vars::new(), &mut ctx()).expect_err(src)
}

fn vars(pairs: &[(&str, Value)]) -> Vars {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn literals_and_strings() {
    assert_eq!(ev("42"), Value::Int(42));
    assert_eq!(ev("-7"), Value::Int(-7));
    assert_eq!(ev("0x1f"), Value::Int(31));
    assert_eq!(ev("1.5"), Value::Float(1.5));
    assert_eq!(ev("2e2"), Value::Float(200.0));
    assert_eq!(ev("true"), Value::Bool(true));
    assert_eq!(ev("false"), Value::Bool(false));
    assert_eq!(evs("'single'"), "single");
    assert_eq!(evs("\"double\""), "double");
    assert_eq!(evs(r#""a\nb\t\"q\"\\""#), "a\nb\t\"q\"\\");
    assert_eq!(evs(r"'it\'s'"), "it's");
    assert_eq!(evs(r#""\x41B""#), "AB");
    assert_eq!(evs(r#""\d+""#), "\\d+");
    assert_eq!(evs("`raw\\n`"), "raw\\n");
}

#[test]
fn every_operator() {
    assert_eq!(ev("1 + 2"), Value::Int(3));
    assert_eq!(ev("5 - 8"), Value::Int(-3));
    assert_eq!(ev("6 * 7"), Value::Int(42));
    assert_eq!(ev("8 / 2"), Value::Int(4));
    assert_eq!(ev("7 / 2"), Value::Float(3.5));
    assert_eq!(ev("7 % 4"), Value::Int(3));
    // i64::MIN / -1 and % -1 overflow in Rust; they must not panic.
    assert!(eval_str(
        "(0 - 9223372036854775807 - 1) / -1",
        &Vars::new(),
        &mut ctx()
    )
    .is_ok());
    assert!(eval_str(
        "(0 - 9223372036854775807 - 1) % -1",
        &Vars::new(),
        &mut ctx()
    )
    .is_ok());
    assert_eq!(ev("2 ** 10"), Value::Int(1024));
    assert_eq!(ev("6 & 3"), Value::Int(2));
    assert_eq!(ev("6 | 3"), Value::Int(7));
    assert_eq!(ev("6 ^ 3"), Value::Int(5));
    assert_eq!(ev("1 << 4"), Value::Int(16));
    assert_eq!(ev("256 >> 4"), Value::Int(16));
    assert_eq!(ev("~0"), Value::Int(-1));
    assert_eq!(ev("1 == 1"), Value::Bool(true));
    assert_eq!(ev("1 != 1"), Value::Bool(false));
    assert_eq!(ev("1 < 2"), Value::Bool(true));
    assert_eq!(ev("2 <= 2"), Value::Bool(true));
    assert_eq!(ev("3 > 4"), Value::Bool(false));
    assert_eq!(ev("4 >= 5"), Value::Bool(false));
    assert_eq!(ev("true && false"), Value::Bool(false));
    assert_eq!(ev("true || false"), Value::Bool(true));
    assert_eq!(ev("!true"), Value::Bool(false));
    assert_eq!(ev(r#""hello" =~ "^h.*o$""#), Value::Bool(true));
    assert_eq!(ev(r#""hello" !~ "^x""#), Value::Bool(true));
    assert_eq!(ev("200 in (200, 301)"), Value::Bool(true));
    assert_eq!(ev("404 in (200, 301)"), Value::Bool(false));
    assert_eq!(evs(r#"200 == 200 ? "up" : "down""#), "up");
    assert_eq!(evs(r#"1 == 2 ? "up" : "down""#), "down");
    assert_eq!(evs(r#""a" + "b" + 1"#), "ab1");
    assert_eq!(ev("(1 + 2) * 3"), Value::Int(9));
}

#[test]
fn precedence() {
    assert_eq!(ev("1 + 2 * 3"), Value::Int(7));
    assert_eq!(ev("2 * 3 + 1"), Value::Int(7));
    assert_eq!(ev("2 + 3 ** 2"), Value::Int(11));
    assert_eq!(ev("2 ** 3 * 2"), Value::Int(16));
    assert_eq!(ev("1 + 2 == 3 && 2 * 2 == 4"), Value::Bool(true));
    assert_eq!(ev("true || false && false"), Value::Bool(true));
    assert_eq!(ev("false && false || true"), Value::Bool(true));
    assert_eq!(ev("!false && !false"), Value::Bool(true));
    assert_eq!(ev("-2 ** 2"), Value::Int(4));
    assert_eq!(ev("1 << 2 + 1"), Value::Int(8));
    assert_eq!(ev("1 + 1 == 2 ? 10 : 20"), Value::Int(10));
    assert_eq!(ev("1 > 2 ? 1 : 2 > 1 ? 3 : 4"), Value::Int(3));
}

#[test]
fn short_circuit_skips_errors() {
    assert_eq!(ev("false && nope > 1"), Value::Bool(false));
    assert_eq!(ev("true || nope > 1"), Value::Bool(true));
}

#[test]
fn variables_and_loose_comparison() {
    let v = vars(&[
        ("status_code", Value::Int(200)),
        ("status_code_2", Value::Int(404)),
        ("header_name", Value::str("x")),
        ("content_length", Value::str("1500")),
        ("body", Value::str("hello world")),
    ]);
    assert_eq!(ev_with("status_code == 200", &v), Value::Bool(true));
    assert_eq!(ev_with("status_code_2 == 404", &v), Value::Bool(true));
    assert_eq!(ev_with("header_name == 'x'", &v), Value::Bool(true));
    // A numeric string compares as a number against a number.
    assert_eq!(ev_with("content_length >= 1024", &v), Value::Bool(true));
    assert_eq!(ev_with("content_length == 1500", &v), Value::Bool(true));
    // A non-numeric string is not equal to a number, and cannot be ordered.
    assert_eq!(ev_with("body == 200", &v), Value::Bool(false));
    assert!(eval_str("body > 200", &v, &mut ctx()).is_err());
    // Arithmetic on strings is strict.
    assert!(eval_str("content_length * 2", &v, &mut ctx()).is_err());
    assert_eq!(
        ev_with("to_number(content_length) * 2", &v),
        Value::Int(3000)
    );
}

#[test]
fn unknown_variable_is_an_error_not_a_panic() {
    assert_eq!(
        err("missing == 1"),
        DslError::UnknownVariable("missing".into())
    );
}

#[test]
fn type_errors() {
    assert!(matches!(err("1 && true"), DslError::Type(_)));
    assert!(matches!(err("!1"), DslError::Type(_)));
    assert!(matches!(err("\"a\" - 1"), DslError::Type(_)));
    assert!(matches!(err("1 / 0"), DslError::Eval(_)));
    assert!(matches!(err("1 % 0"), DslError::Eval(_)));
    assert!(matches!(err("1 << 70"), DslError::Eval(_)));
    assert!(matches!(err("nope(1)"), DslError::UnknownFunction(_)));
    assert!(matches!(err("len()"), DslError::Arity { .. }));
}

#[test]
fn parse_errors() {
    for bad in [
        "", "1 +", "(1", "1)", "'open", "1 ? 2", "a b", "@", "1 in 2", "f(,)",
    ] {
        assert!(parse(bad).is_err(), "{bad:?} should not parse");
    }
}

#[test]
fn parser_reports_variables_and_calls() {
    let e = parse("len(body) > 3 && contains(header, x)").expect("parses");
    assert_eq!(e.variables(), ["body", "header", "x"]);
    assert_eq!(e.functions(), ["len", "contains"]);
    assert!(e.is_dynamic());
    assert!(!parse("2 == 2").expect("parses").is_dynamic());
    assert!(matches!(parse("a.b").expect("parses"), Expr::Var(n) if n == "a.b"));
}

#[test]
fn nesting_depth_is_capped() {
    let deep = format!("{}1{}", "(".repeat(200), ")".repeat(200));
    assert!(matches!(parse(&deep), Err(DslError::Limit(_))));
    let ok = format!("{}1{}", "(".repeat(30), ")".repeat(30));
    assert!(parse(&ok).is_ok());
    let chain = vec!["1"; 400].join(" + ");
    assert!(matches!(parse(&chain), Err(DslError::Limit(_))));
    let nots = format!("{}true", "!".repeat(500));
    assert!(matches!(parse(&nots), Err(DslError::Limit(_))));
}

// ------------------------------------------------------------- functions

#[test]
fn encoding_functions() {
    assert_eq!(evs(r#"base64("Hello")"#), "SGVsbG8=");
    assert_eq!(evs(r#"base64_decode("SGVsbG8=")"#), "Hello");
    assert_eq!(evs(r#"base64_py("Hello")"#), "SGVsbG8=\n");
    let long = evs(r#"base64_py(repeat("a", 100))"#);
    assert_eq!(long.lines().next().map(str::len), Some(76));
    assert!(long.ends_with('\n'));
    assert_eq!(evs(r#"hex_encode("aa")"#), "6161");
    assert_eq!(evs(r#"hex_decode("6161")"#), "aa");
    assert_eq!(ev(r#"hex_decode("ff00")"#), Value::Bytes(vec![0xff, 0x00]));
    assert_eq!(
        evs(r#"url_encode("https://projectdiscovery.io/test?a=1")"#),
        "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1"
    );
    assert_eq!(
        evs(r#"url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")"#),
        "https://projectdiscovery.io?test=1"
    );
    assert_eq!(evs(r#"url_encode("a b")"#), "a+b");
    assert_eq!(
        evs(r#"html_escape("<body>test</body>")"#),
        "&lt;body&gt;test&lt;/body&gt;"
    );
    assert_eq!(evs(r#"html_escape("a&b'\"")"#), "a&amp;b&#39;&#34;");
    assert_eq!(
        evs(r#"html_unescape("&lt;body&gt;test&lt;/body&gt;")"#),
        "<body>test</body>"
    );
    assert_eq!(
        evs(r#"html_unescape("&#65;&#x42;&amp;&bogus;")"#),
        "AB&&bogus;"
    );
}

#[test]
fn compression_functions() {
    // Vectors from the Nuclei reference, produced by Go.
    assert_eq!(
        evs(
            r#"gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))"#
        ),
        "Hello"
    );
    assert_eq!(
        evs(r#"zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))"#),
        "Hello"
    );
    // Our own encoder round-trips and produces valid framing.
    assert_eq!(evs(r#"gzip_decode(gzip("round trip"))"#), "round trip");
    assert_eq!(evs(r#"zlib_decode(zlib("round trip"))"#), "round trip");
    assert_eq!(evs(r#"hex_encode(gzip("x"))"#).get(..6), Some("1f8b08"));
    assert_eq!(evs(r#"hex_encode(zlib("x"))"#).get(..2), Some("78"));
    assert!(matches!(
        err(r#"gzip_decode("not gzip")"#),
        DslError::Eval(_)
    ));
}

#[test]
fn hash_functions() {
    assert_eq!(evs(r#"md5("Hello")"#), "8b1a9953c4611296a827abf8c47804d7");
    assert_eq!(
        evs(r#"sha1("Hello")"#),
        "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0"
    );
    assert_eq!(
        evs(r#"sha256("Hello")"#),
        "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
    );
    assert_eq!(
        evs(r#"sha512("Hello")"#),
        "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"
    );
    // MurmurHash3 x86_32, seed 0, checked against an independent implementation.
    assert_eq!(evs(r#"mmh3("Hello")"#), "316307400");
    assert_eq!(evs(r#"mmh3("")"#), "0");
    assert_eq!(
        evs(r#"mmh3("The quick brown fox jumps over the lazy dog")"#),
        "776992547"
    );
    // Values above i32::MAX come out negative, which is what favicon hashes look like.
    assert_eq!(evs(r#"mmh3("test")"#), "-1167338989");
    assert_eq!(
        evs(r#"hmac("sha1", "test", "scrt")"#),
        "8856b111056d946d5c6c92a21b43c233596623c6"
    );
    assert_eq!(
        evs(r#"hmac("sha256", "test", "scrt")"#),
        "1f1bff5574f18426eb376d6dd5368a754e67a798aa2074644d5e3fd4c90c7a92"
    );
    assert_eq!(
        evs(r#"hmac("md5", "test", "scrt")"#),
        "9e6613fcfbed611e814b71f979314301"
    );
    assert_eq!(
        evs(r#"hmac("sha512", "data", "k")"#).get(..32),
        Some("35147d6a9f273e3c3edd49a4f6c16614")
    );
    assert!(matches!(
        err(r#"hmac("crc32", "a", "b")"#),
        DslError::Eval(_)
    ));
}

#[test]
fn jwt() {
    let hs256 =
        evs(r#"generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "HS256", "hello-world")"#);
    assert_eq!(
        hs256,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U"
    );
    let none = evs(r#"generate_jwt("{\"a\":1}", "none")"#);
    assert!(
        none.ends_with('.'),
        "unsigned token has an empty signature: {none}"
    );
    assert!(none.starts_with("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."));
    assert_eq!(evs(r#"generate_jwt("{\"a\":1}")"#), none);
    let hs384 = evs(r#"generate_jwt("{\"a\":1}", "hs384", "k")"#);
    assert_eq!(hs384.split('.').count(), 3);
    let aged = evs(r#"generate_jwt("{\"a\":1}", "HS256", "k", 2000000000)"#);
    let payload = aged.split('.').nth(1).expect("payload");
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("b64");
    assert_eq!(
        String::from_utf8(decoded).expect("utf8"),
        r#"{"a":1,"exp":2000000000,"iat":1700000000}"#
    );
    assert!(matches!(
        err(r#"generate_jwt("{}", "RS256", "k")"#),
        DslError::Unsupported(_)
    ));
    assert!(matches!(
        err(r#"generate_jwt("[1]", "HS256", "k")"#),
        DslError::Eval(_)
    ));
}

#[test]
fn json_functions() {
    assert_eq!(
        evs(r#"json_minify("{ \"name\": \"John Doe\", \"foo\": \"bar\" }")"#),
        r#"{"foo":"bar","name":"John Doe"}"#
    );
    assert_eq!(
        evs(r#"json_prettify("{\"foo\":\"bar\",\"name\":\"John Doe\"}")"#),
        "{\n \"foo\": \"bar\",\n \"name\": \"John Doe\"\n}"
    );
    assert_eq!(
        evs(r#"json_minify("[1, {\"b\":2,\"a\":[]}]")"#),
        r#"[1,{"a":[],"b":2}]"#
    );
    assert!(matches!(err(r#"json_minify("{nope")"#), DslError::Eval(_)));
}

#[test]
fn string_functions() {
    assert_eq!(evs(r#"concat("Hello", 123, "world")"#), "Hello123world");
    assert_eq!(
        evs(r#"join("_", 123, "hello", "world")"#),
        "123_hello_world"
    );
    assert_eq!(ev(r#"contains("Hello", "lo")"#), Value::Bool(true));
    assert_eq!(ev(r#"contains("Hello", "xyz")"#), Value::Bool(false));
    assert_eq!(
        ev(r#"contains_all("Hello everyone", "lo", "every")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"contains_all("Hello everyone", "lo", "nope")"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"contains_any("Hello everyone", "abc", "llo")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"contains_any("Hello everyone", "abc")"#),
        Value::Bool(false)
    );
    assert_eq!(ev(r#"starts_with("Hello", "He")"#), Value::Bool(true));
    assert_eq!(ev(r#"starts_with("Hello", "x", "He")"#), Value::Bool(true));
    assert_eq!(ev(r#"ends_with("Hello", "lo")"#), Value::Bool(true));
    assert_eq!(ev(r#"ends_with("Hello", "He")"#), Value::Bool(false));
    assert_eq!(
        ev(r#"line_starts_with("Hi\nHello", "He")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"line_starts_with("Hi\nHello", "ll")"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"line_ends_with("Hello\nHi", "lo")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"line_ends_with("Hello\nHi", "He")"#),
        Value::Bool(false)
    );
    assert_eq!(ev(r#"equals_any(200, 200, 201)"#), Value::Bool(true));
    assert_eq!(ev(r#"equals_any("a", "b", "c")"#), Value::Bool(false));
    assert_eq!(ev(r#"len("Hello")"#), Value::Int(5));
    assert_eq!(ev(r#"len(hex_decode("ff00ff"))"#), Value::Int(3));
    assert_eq!(evs(r#"remove_bad_chars("abcd", "bc")"#), "ad");
    assert_eq!(evs(r#"repeat("../", 5)"#), "../../../../../");
    assert_eq!(evs(r#"replace("Hello", "He", "Ha")"#), "Hallo");
    assert_eq!(evs(r#"replace_regex("He123llo", "(\\d+)", "")"#), "Hello");
    assert_eq!(evs(r#"replace_regex("abc", "(b)", "[$1]")"#), "a[b]c");
    assert_eq!(evs(r#"reverse("abc")"#), "cba");
    assert_eq!(evs(r#"to_lower("HELLO")"#), "hello");
    assert_eq!(evs(r#"to_upper("hello")"#), "HELLO");
    assert_eq!(evs(r#"toupper("hello")"#), "HELLO");
    assert_eq!(evs(r#"trim("aaaHelloddd", "ad")"#), "Hello");
    assert_eq!(evs(r#"trim_left("aaaHelloddd", "ad")"#), "Helloddd");
    assert_eq!(evs(r#"trim_right("aaaHelloddd", "ad")"#), "aaaHello");
    assert_eq!(evs(r#"trim_prefix("aaHelloaa", "aa")"#), "Helloaa");
    assert_eq!(evs(r#"trim_suffix("aaHelloaa", "aa")"#), "aaHello");
    assert_eq!(evs(r#"trim_space("  Hello  ")"#), "Hello");
    assert_eq!(ev(r#"regex("H([a-z]+)o", "Hello")"#), Value::Bool(true));
    assert_eq!(ev(r#"regex("^x", "Hello")"#), Value::Bool(false));
    assert_eq!(
        ev(r#"regex_any("H([a-z]+)o", "World", "Hello")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"regex_all("H([a-z]+)o", "Hallo", "Hello")"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"regex_all("H([a-z]+)o", "Hallo", "World")"#),
        Value::Bool(false)
    );
    assert_eq!(evs(r#"to_string(12)"#), "12");
    assert_eq!(ev(r#"to_number("42")"#), Value::Int(42));
    assert_eq!(ev(r#"to_number("4.5")"#), Value::Float(4.5));
    assert!(matches!(err(r#"to_number("x")"#), DslError::Eval(_)));
}

#[test]
fn number_base_functions() {
    assert_eq!(ev(r#"bin_to_dec("0b1010")"#), Value::Int(10));
    assert_eq!(ev("bin_to_dec(1010)"), Value::Int(10));
    assert_eq!(ev(r#"hex_to_dec("ff")"#), Value::Int(255));
    assert_eq!(ev(r#"hex_to_dec("0xff")"#), Value::Int(255));
    assert_eq!(ev(r#"oct_to_dec("0o1234567")"#), Value::Int(342391));
    assert_eq!(ev("oct_to_dec(1234567)"), Value::Int(342391));
    assert_eq!(evs("dec_to_hex(7001)"), "1b59");
    assert_eq!(evs(r#"dec_to_hex("255")"#), "ff");
    assert!(matches!(err(r#"bin_to_dec("12")"#), DslError::Eval(_)));
}

#[test]
fn version_comparison() {
    assert_eq!(
        ev(r#"compare_versions('v1.0.0', '>v0.0.1', '<v1.0.1')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.3', '>=1.2.3')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.3', '<1.2.3')"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.3', '=1.2.3')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.3', '!=1.2.3')"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.3', '>= 1.0, < 2.0')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('2.5.0', '< 1.0 || >= 2.0')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('1.9.0', '^1.2.0')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('2.0.0', '^1.2.0')"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"compare_versions('1.2.9', '~1.2.0')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('1.3.0', '~1.2.0')"#),
        Value::Bool(false)
    );
    assert_eq!(
        ev(r#"compare_versions('1.0.0-beta', '<1.0.0')"#),
        Value::Bool(true)
    );
    assert_eq!(
        ev(r#"compare_versions('10.0', '>9.9.9')"#),
        Value::Bool(true)
    );
    assert!(matches!(
        err(r#"compare_versions('nope', '>1')"#),
        DslError::Eval(_)
    ));
}

#[test]
fn time_functions() {
    assert_eq!(
        evs(r#"date_time("%Y-%M-%D %H:%m", 1654870680)"#),
        "2022-06-10 14:18"
    );
    assert_eq!(
        evs(r#"date_time("%Y-%M-%D %H:%m:%S", 0)"#),
        "1970-01-01 00:00:00"
    );
    assert_eq!(
        evs(r#"date_time("2006-01-02 15:04", 1654870680)"#),
        "2022-06-10 14:18"
    );
    assert_eq!(
        evs(r#"date_time("Mon Jan 02 2006", 1654870680)"#),
        "Fri Jun 10 2022"
    );
    assert_eq!(evs(r#"date_time("%Y")"#), "2023"); // fixed test clock: 1700000000
    assert_eq!(
        ev(r#"to_unix_time("2022-01-13T16:30:10+00:00")"#),
        Value::Int(1642091410)
    );
    assert_eq!(
        ev(r#"to_unix_time("2022-01-13 16:30:10")"#),
        Value::Int(1642091410)
    );
    assert_eq!(
        ev(r#"to_unix_time("2022-01-13T16:30:10+02:00")"#),
        Value::Int(1642091410 - 7200)
    );
    assert_eq!(
        ev(r#"to_unix_time("13-01-2022 16:30:10", "02-01-2006 15:04:05")"#),
        Value::Int(1642091410)
    );
    assert_eq!(ev(r#"to_unix_time("2022-01-13")"#), Value::Int(1642032000));
    assert_eq!(ev("unix_time()"), Value::Int(1_700_000_000));
    assert_eq!(ev("unix_time(10)"), Value::Int(1_700_000_010));
    assert!(matches!(
        err(r#"to_unix_time("garbage")"#),
        DslError::Eval(_)
    ));
}

#[test]
fn ip_format_indexes() {
    assert_eq!(evs(r#"ip_format("127.0.0.1", 1)"#), "127.0.0.1");
    assert_eq!(evs(r#"ip_format("127.0.0.1", 2)"#), "127.1");
    assert_eq!(evs(r#"ip_format("127.0.0.1", 3)"#), "0177.0.0.01");
    assert_eq!(evs(r#"ip_format("127.0.0.1", 4)"#), "0x7f.0x0.0x0.0x1");
    assert_eq!(evs(r#"ip_format("127.0.0.1", 5)"#), "2130706433");
    assert_eq!(
        evs(r#"ip_format("127.0.0.1", 6)"#),
        "01111111000000000000000000000001"
    );
    assert_eq!(evs(r#"ip_format("127.0.0.1", 7)"#), "127.0x1");
    assert_eq!(
        evs(r#"ip_format("127.0.0.1", 8)"#),
        "00:00:00:00:00:ffff:7f00:0001"
    );
    assert_eq!(
        evs(r#"ip_format("127.0.0.1", 9)"#),
        "%31%32%37%2E%30%2E%30%2E%31"
    );
    assert!(matches!(
        err(r#"ip_format("127.0.0.1", 10)"#),
        DslError::Unsupported(_)
    ));
    assert!(matches!(err(r#"ip_format("::1", 1)"#), DslError::Eval(_)));
}

#[test]
fn random_functions_use_the_injected_context() {
    let a = evs("rand_text_alpha(12)");
    let b = evs("rand_text_alpha(12)");
    assert_eq!(a, b, "a fresh deterministic context repeats");
    assert_eq!(a.len(), 12);
    assert!(a.chars().all(|c| c.is_ascii_alphabetic()));
    assert!(evs("rand_text_alphanumeric(40)")
        .chars()
        .all(|c| c.is_ascii_alphanumeric()));
    assert!(evs("rand_text_numeric(30)")
        .chars()
        .all(|c| c.is_ascii_digit()));
    assert!(evs(r#"rand_text_alpha(200, "abcdefghijklmnopqrstuvwxyz")"#)
        .chars()
        .all(|c| c.is_ascii_uppercase()));
    assert!(matches!(
        err(r#"rand_text_numeric(5, "0123456789")"#),
        DslError::Eval(_)
    ));
    assert!(evs(r#"rand_base(50, "xyz")"#)
        .chars()
        .all(|c| "xyz".contains(c)));
    assert_eq!(evs("rand_base(7)").len(), 7);
    assert_eq!(evs("rand_char()").chars().count(), 1);
    assert!("abc".contains(&evs(r#"rand_char("abc")"#)));
    let n = ev("rand_int(5, 9)");
    assert!(matches!(n, Value::Int(5..=9)), "{n:?}");
    assert!(matches!(ev("rand_int()"), Value::Int(n) if (0..i32::MAX as i64).contains(&n)));
    assert_eq!(ev("rand_int(3, 3)"), Value::Int(3));
    let mut c = ctx();
    let first = c.rand_u64();
    assert_ne!(first, c.rand_u64());
}

#[test]
fn allocation_amplifying_helpers_are_capped() {
    assert!(matches!(
        err(r#"repeat("abcdefgh", 1000000000)"#),
        DslError::Limit(_)
    ));
    assert!(matches!(
        err("rand_text_alpha(100000000)"),
        DslError::Limit(_)
    ));
    assert!(matches!(err("rand_base(999999999)"), DslError::Limit(_)));
    let big = "x".repeat(900_000);
    let v = vars(&[("big", Value::from(big))]);
    assert!(eval_str("big + big", &v, &mut ctx()).is_err());
    assert!(eval_str(r#"replace(big, "x", "yyyy")"#, &v, &mut ctx()).is_err());
    assert!(eval_str("repeat(big, 5)", &v, &mut ctx()).is_err());
}

#[test]
fn unimplemented_helpers_are_not_known() {
    use crate::dsl::functions::{is_implemented, UNSUPPORTED};
    for f in UNSUPPORTED {
        assert!(!is_implemented(f), "{f}");
        assert!(matches!(
            eval_str(&format!("{f}(1)"), &Vars::new(), &mut ctx()),
            Err(DslError::UnknownFunction(_)) | Err(DslError::Arity { .. })
        ));
    }
}

// ---------------------------------------------------------- interpolation

#[test]
fn interpolation_replaces_variables_and_functions() {
    let v = vars(&[("name", Value::str("world")), ("n", Value::Int(3))]);
    let mut c = ctx();
    assert_eq!(
        interpolate("hello {{name}}!", &v, &mut c).expect("ok"),
        "hello world!"
    );
    assert_eq!(interpolate("{{n}}/{{ n }}", &v, &mut c).expect("ok"), "3/3");
    assert_eq!(
        interpolate("{{base64('hi')}}", &v, &mut c).expect("ok"),
        "aGk="
    );
    assert_eq!(
        interpolate("{{to_upper(name)}}", &v, &mut c).expect("ok"),
        "WORLD"
    );
    assert_eq!(
        interpolate("{{name + '-' + n}}", &v, &mut c).expect("ok"),
        "world-3"
    );
    assert_eq!(
        interpolate("no markers", &v, &mut c).expect("ok"),
        "no markers"
    );
}

#[test]
fn constant_expressions_stay_literal() {
    let mut c = ctx();
    assert_eq!(
        interpolate("{{2 == 2}}", &Vars::new(), &mut c).expect("ok"),
        "{{2 == 2}}"
    );
    assert_eq!(
        interpolate("{{7*7}}", &Vars::new(), &mut c).expect("ok"),
        "{{7*7}}"
    );
}

#[test]
fn unresolved_variables_are_reported_and_left_in_place() {
    let v = vars(&[("a", Value::str("1"))]);
    let mut c = ctx();
    let r = interpolate_detailed("x={{a}}&y={{b}}&z={{b}}&w={{c}}", &v, &mut c).expect("ok");
    assert_eq!(r.text(), "x=1&y={{b}}&z={{b}}&w={{c}}");
    assert_eq!(r.unresolved, ["b", "c"]);
    assert_eq!(interpolate("{{b}}", &v, &mut c).expect("ok"), "{{b}}");
}

#[test]
fn nested_markers_resolve_innermost_first() {
    let v = vars(&[
        ("alg", Value::str("HS256")),
        ("sig", Value::str("hello-world")),
    ]);
    let mut c = ctx();
    let out = interpolate(
        r#"{{generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "{{alg}}", "{{sig}}")}}"#,
        &v,
        &mut c,
    )
    .expect("ok");
    assert_eq!(
        out,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U"
    );
    // A nested variable that is missing leaves the whole marker alone.
    let r = interpolate_detailed(r#"{{base64("{{nope}}")}}"#, &v, &mut c).expect("ok");
    assert_eq!(r.unresolved, ["nope"]);
    assert_eq!(r.text(), r#"{{base64("{{nope}}")}}"#);
}

#[test]
fn substituted_values_are_not_reinterpolated() {
    let v = vars(&[("token", Value::str("{{md5('x')}}"))]);
    let mut c = ctx();
    assert_eq!(
        interpolate("t={{token}}", &v, &mut c).expect("ok"),
        "t={{md5('x')}}"
    );
}

#[test]
fn interpolation_keeps_binary_results_as_bytes() {
    let mut c = ctx();
    let r = interpolate_detailed("{{hex_decode('ff00fe')}}", &Vars::new(), &mut c).expect("ok");
    assert_eq!(r.bytes, [0xff, 0x00, 0xfe]);
}

#[test]
fn interpolation_errors() {
    let mut c = ctx();
    assert!(interpolate("{{1 +}}", &Vars::new(), &mut c).is_err());
    assert!(interpolate("{{len(1, 2)}}", &Vars::new(), &mut c).is_err());
    let big = vars(&[("a", Value::from("x".repeat(600_000)))]);
    assert!(
        interpolate("{{a}}{{a}}", &big, &mut c).is_err(),
        "output is capped at 1 MiB"
    );
    // Unterminated and stray markers are text.
    assert_eq!(
        interpolate("{{ open", &Vars::new(), &mut c).expect("ok"),
        "{{ open"
    );
    assert_eq!(
        interpolate("close }}", &Vars::new(), &mut c).expect("ok"),
        "close }}"
    );
    assert_eq!(
        interpolate("{\"a\":{\"b\":1}}", &Vars::new(), &mut c).expect("ok"),
        "{\"a\":{\"b\":1}}"
    );
}

#[test]
fn lenient_interpolation_keeps_unparseable_text() {
    use crate::vars::interpolate_lenient;
    let mut c = ctx();
    let v = vars(&[("Host", Value::str("a.test"))]);
    assert_eq!(
        interpolate_lenient("{{Host}} {{ $x }}", &v, &mut c).text(),
        "a.test {{ $x }}"
    );
}

#[test]
fn template_variables_resolve_in_order() {
    use crate::vars::resolve_template_variables;
    let declared = vec![
        ("a1".to_string(), "value".to_string()),
        ("a2".to_string(), "{{base64('hello')}}".to_string()),
        ("a3".to_string(), "{{a1}}-{{a2}}".to_string()),
        ("a4".to_string(), "{{later}}".to_string()),
    ];
    let out = resolve_template_variables(&declared, &Vars::new(), &mut ctx());
    assert_eq!(out["a1"], Value::str("value"));
    assert_eq!(out["a2"], Value::str("aGVsbG8="));
    assert_eq!(out["a3"], Value::str("value-aGVsbG8="));
    assert_eq!(out["a4"], Value::str("{{later}}"));
}

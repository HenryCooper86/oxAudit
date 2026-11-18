use std::time::Duration;

use oxaudit_domain::Severity;
use oxaudit_yara::{
    severity_from_meta, CompileLimits, MetaValue, RuleMatch, RuleSet, RuleSource, ScanError,
    YaraError, MAX_EXCERPT_BYTES, MAX_STRING_MATCHES_PER_RULE,
};

const T: Duration = Duration::from_secs(10);

fn src(ns: &str, origin: &str, text: &str) -> RuleSource {
    RuleSource {
        namespace: ns.into(),
        origin: origin.into(),
        text: text.into(),
    }
}

fn set(text: &str) -> RuleSet {
    let s = RuleSet::compile(&[src("ns", "a.yar", text)], &CompileLimits::default()).unwrap();
    assert!(s.skipped().is_empty(), "skipped: {:?}", s.skipped());
    s
}

fn scan(rs: &RuleSet, bytes: &[u8]) -> Vec<RuleMatch> {
    rs.scanner().scan(bytes, T).unwrap()
}

fn names(m: &[RuleMatch]) -> Vec<&str> {
    m.iter().map(|m| m.rule.as_str()).collect()
}

#[test]
fn text_string_match_has_offset_length_and_hex_excerpt() {
    let rs = set(r#"rule r { strings: $a = "needle" condition: $a }"#);
    let m = scan(&rs, b"hay needle hay");
    assert_eq!(m.len(), 1);
    let s = &m[0].strings[0];
    assert_eq!(s.identifier, "$a");
    assert_eq!((s.offset, s.length), (4, 6));
    assert_eq!(s.excerpt_hex, "6e6565646c65");
    assert_eq!(m[0].namespace, "ns");
    assert_eq!(m[0].strings_truncated, 0);
    assert!(scan(&rs, b"nothing here").is_empty());
}

#[test]
fn hex_strings_with_wildcards_and_jumps() {
    let rs = set(
        "rule h { strings: $a = { 4D ?? 90 [1-3] 00 FF } condition: $a }
         rule nibble { strings: $a = { 4? 5A } condition: $a }",
    );
    let m = scan(&rs, &[0x4d, 0x11, 0x90, 1, 2, 0x00, 0xff]);
    assert_eq!(names(&m), ["h"]);
    assert_eq!(m[0].strings[0].length, 7);
    // Too many bytes in the jump.
    assert!(!names(&scan(&rs, &[0x4d, 0x11, 0x90, 1, 2, 3, 4, 5, 0x00, 0xff])).contains(&"h"));
    assert_eq!(names(&scan(&rs, &[0x41, 0x5a])), ["nibble"]);
}

#[test]
fn regex_strings() {
    let rs = set(r#"rule re { strings: $a = /ab[0-9]{2,3}c/ condition: $a }"#);
    assert_eq!(names(&scan(&rs, b"xx ab123c yy")), ["re"]);
    assert!(scan(&rs, b"ab1c").is_empty());
}

#[test]
fn nocase_wide_fullword() {
    let rs = set(r#"rule nc { strings: $a = "Secret" nocase condition: $a }
           rule w { strings: $a = "AB" wide condition: $a }
           rule fw { strings: $a = "word" fullword condition: $a }"#);
    assert_eq!(names(&scan(&rs, b"a SECRET b")), ["nc"]);
    assert_eq!(names(&scan(&rs, b"A\0B\0")), ["w"]);
    assert_eq!(names(&scan(&rs, b"a word b")), ["fw"]);
    assert!(scan(&rs, b"swordfish").is_empty());
}

#[test]
fn counts_offsets_and_filesize() {
    let rs = set(r#"rule cnt { strings: $a = "ab" condition: #a == 3 }
           rule off { strings: $a = "ab" condition: @a[2] == 3 }
           rule fs { condition: filesize < 8 and filesize > 2 }"#);
    let m = scan(&rs, b"ab,ab,ab");
    assert_eq!(names(&m), ["cnt", "off"]);
    assert_eq!(m[0].strings.len(), 3);
    assert_eq!(names(&scan(&rs, b"abc")), ["fs"]);
}

#[test]
fn math_entropy() {
    let rs = set(r#"import "math"
           rule high { condition: math.entropy(0, filesize) > 7.5 }
           rule low { condition: math.entropy(0, filesize) < 1.0 }"#);
    let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    assert_eq!(names(&scan(&rs, &uniform)), ["high"]);
    assert_eq!(names(&scan(&rs, &[7u8; 512])), ["low"]);
}

#[test]
fn hash_md5() {
    let rs = set(r#"import "hash"
           rule md5 { condition: hash.md5(0, filesize) == "5d41402abc4b2a76b9719d911017c592" }"#);
    assert_eq!(names(&scan(&rs, b"hello")), ["md5"]);
    assert!(scan(&rs, b"hellO").is_empty());
}

#[test]
fn elf_module_is_false_on_non_elf() {
    let rs = set(r#"import "elf"
           rule e { condition: elf.type == elf.ET_EXEC }
           rule n { condition: not defined elf.type }"#);
    assert_eq!(names(&scan(&rs, b"plain text")), ["n"]);
}

#[test]
fn pe_module_on_minimal_header() {
    let rs = set(r#"import "pe"
           rule is_pe { condition: pe.is_pe }
           rule dll { condition: pe.is_dll() }
           rule sixteen { condition: pe.machine == pe.MACHINE_I386 }"#);
    // Minimal PE32: DOS header, PE signature, COFF header, 224-byte optional header.
    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x14cu16.to_le_bytes()); // machine i386
    pe[0x46..0x48].copy_from_slice(&0u16.to_le_bytes()); // sections
    pe[0x54..0x56].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
    pe[0x56..0x58].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics
    pe[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
    let m = scan(&rs, &pe);
    assert_eq!(names(&m), ["is_pe", "sixteen"]);
    assert!(scan(&rs, b"MZ not really").is_empty());
}

#[test]
fn tags_and_all_meta_types() {
    let rs = set(r#"rule tagged : alpha beta {
             meta:
               s = "text"
               i = 42
               n = -7
               f = 1.5
               b = true
             condition: true
           }"#);
    let m = scan(&rs, b"x");
    assert_eq!(m[0].tags, ["alpha", "beta"]);
    assert_eq!(
        m[0].meta,
        vec![
            ("s".into(), MetaValue::String("text".into())),
            ("i".into(), MetaValue::Integer(42)),
            ("n".into(), MetaValue::Integer(-7)),
            ("f".into(), MetaValue::Float(1.5)),
            ("b".into(), MetaValue::Bool(true)),
        ]
    );
    let info = &rs.rules()[0];
    assert_eq!(info.tags, ["alpha", "beta"]);
    assert_eq!(info.origin, "a.yar");
    assert_eq!(info.meta.len(), 5);
}

#[test]
fn private_and_global_rules() {
    let rs = set(r#"private rule helper { strings: $a = "key" condition: $a }
           rule uses_helper { condition: helper }
           global rule only_small { condition: filesize < 20 }"#);
    let infos = rs.rules();
    assert!(
        infos
            .iter()
            .find(|r| r.identifier == "helper")
            .unwrap()
            .private
    );
    assert!(
        infos
            .iter()
            .find(|r| r.identifier == "only_small")
            .unwrap()
            .global
    );
    // Private rules are evaluated but never reported.
    assert_eq!(names(&scan(&rs, b"a key")), ["only_small", "uses_helper"]);
    // The global rule gates every rule in its namespace.
    assert!(scan(&rs, b"a key and a lot more padding bytes").is_empty());
}

#[test]
fn same_rule_name_in_two_namespaces() {
    let rs = RuleSet::compile(
        &[
            src(
                "zeta",
                "z.yar",
                r#"rule dup { strings: $a = "x" condition: $a }"#,
            ),
            src(
                "alpha",
                "a.yar",
                r#"rule dup { strings: $a = "x" condition: $a }"#,
            ),
        ],
        &CompileLimits::default(),
    )
    .unwrap();
    assert!(rs.skipped().is_empty());
    assert_eq!(rs.rules().len(), 2);
    let m = scan(&rs, b"x");
    let got: Vec<_> = m
        .iter()
        .map(|m| (m.namespace.as_str(), m.rule.as_str()))
        .collect();
    assert_eq!(got, [("alpha", "dup"), ("zeta", "dup")]);
    let origins: Vec<_> = rs.rules().iter().map(|r| r.origin.as_str()).collect();
    assert_eq!(origins, ["a.yar", "z.yar"]);
}

#[test]
fn duplicate_rule_in_one_namespace_skips_the_later_source() {
    let rs = RuleSet::compile(
        &[
            src("n", "one.yar", "rule d { condition: true }"),
            src(
                "n",
                "two.yar",
                "rule other { condition: true } rule d { condition: true }",
            ),
        ],
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(rs.skipped().len(), 1);
    assert_eq!(rs.skipped()[0].origin, "two.yar");
    // Nothing from the skipped source leaks in.
    let ids: Vec<_> = rs.rules().iter().map(|r| r.identifier.as_str()).collect();
    assert_eq!(ids, ["d"]);
}

#[test]
fn broken_source_is_skipped_and_others_compile() {
    let rs = RuleSet::compile(
        &[
            src("a", "good1.yar", "rule g1 { condition: true }"),
            src(
                "b",
                "bad.yar",
                "rule ok_but_lost { condition: true }\n\nrule broken {\n  condition: nope_undefined\n}\n",
            ),
            src("c", "good2.yar", "rule g2 { condition: true }"),
        ],
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(rs.rules().len(), 2);
    assert_eq!(rs.skipped().len(), 1);
    let skip = &rs.skipped()[0];
    assert_eq!(skip.origin, "bad.yar");
    assert_eq!(skip.line, Some(4));
    assert!(skip.message.contains("nope_undefined"), "{}", skip.message);
    assert_eq!(names(&scan(&rs, b"")), ["g1", "g2"]);
}

#[test]
fn syntax_error_has_line_and_all_skipped_is_ok() {
    let rs = RuleSet::compile(
        &[src("a", "x.yar", "rule a {\n condition: true\n}\nrule {")],
        &CompileLimits::default(),
    )
    .unwrap();
    assert!(rs.rules().is_empty());
    assert_eq!(rs.skipped().len(), 1);
    assert_eq!(rs.skipped()[0].line, Some(4));
    assert!(scan(&rs, b"anything").is_empty());
    let json = serde_json::to_string(&rs.skipped()[0]).unwrap();
    assert!(json.contains("\"origin\"") && json.contains("\"line\":4"));
}

#[test]
fn unavailable_modules_are_skipped_with_their_name() {
    for module in ["cuckoo", "vt", "magic", "no_such_module"] {
        let rs = RuleSet::compile(
            &[
                src(
                    "m",
                    "m.yar",
                    &format!("import \"{module}\"\nrule r {{ condition: true }}"),
                ),
                src("g", "g.yar", "rule fine { condition: true }"),
            ],
            &CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(rs.rules().len(), 1, "{module}");
        let skip = &rs.skipped()[0];
        assert_eq!(skip.origin, "m.yar");
        assert!(skip.message.contains(module), "{}", skip.message);
        assert!(
            skip.message.contains("not available in oxAudit"),
            "{}",
            skip.message
        );
    }
}

#[test]
fn include_is_refused() {
    let rs = RuleSet::compile(
        &[
            src(
                "a",
                "inc.yar",
                "include \"/etc/passwd\"\nrule r { condition: true }",
            ),
            src("b", "ok.yar", "rule ok { condition: true }"),
        ],
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(rs.rules().len(), 1);
    assert_eq!(rs.skipped()[0].origin, "inc.yar");
    assert_eq!(rs.skipped()[0].line, Some(1));
    assert!(
        rs.skipped()[0].message.contains("include"),
        "{}",
        rs.skipped()[0].message
    );
}

#[test]
fn compile_limits() {
    let ok = src("n", "a.yar", "rule a { condition: true }");
    assert!(matches!(
        RuleSet::compile(&[], &CompileLimits::default()),
        Err(YaraError::NoSources)
    ));
    let limits = CompileLimits {
        max_sources: 1,
        ..CompileLimits::default()
    };
    assert!(matches!(
        RuleSet::compile(&[ok.clone(), ok.clone()], &limits),
        Err(YaraError::TooManySources { count: 2, max: 1 })
    ));
    let limits = CompileLimits {
        max_source_bytes: 10,
        ..CompileLimits::default()
    };
    match RuleSet::compile(std::slice::from_ref(&ok), &limits) {
        Err(YaraError::SourceTooLarge {
            origin, max: 10, ..
        }) => assert_eq!(origin, "a.yar"),
        other => panic!("{other:?}"),
    }
    let limits = CompileLimits {
        max_total_bytes: ok.text.len() + 1,
        ..CompileLimits::default()
    };
    assert!(RuleSet::compile(std::slice::from_ref(&ok), &limits).is_ok());
    assert!(matches!(
        RuleSet::compile(&[ok.clone(), ok], &limits),
        Err(YaraError::TotalTooLarge { .. })
    ));
    let d = CompileLimits::default();
    assert_eq!(
        (d.max_sources, d.max_source_bytes, d.max_total_bytes),
        (20_000, 1 << 20, 256 << 20)
    );
}

#[test]
fn string_matches_are_capped_and_counted() {
    let rs = set(r#"rule many { strings: $a = "a" condition: $a }"#);
    let bytes = vec![b'a'; 100];
    let m = scan(&rs, &bytes);
    assert_eq!(m[0].strings.len(), MAX_STRING_MATCHES_PER_RULE);
    assert_eq!(
        m[0].strings_truncated,
        100 - MAX_STRING_MATCHES_PER_RULE as u64
    );
    // The earliest offsets are kept, in order.
    let offsets: Vec<u64> = m[0].strings.iter().map(|s| s.offset).collect();
    assert_eq!(offsets, (0..32).collect::<Vec<u64>>());
}

#[test]
fn string_matches_from_several_patterns_are_sorted_by_offset() {
    let rs = set(r#"rule two { strings: $a = "bb" $b = "aa" condition: all of them }"#);
    let m = scan(&rs, b"aa..bb..aa");
    let got: Vec<_> = m[0]
        .strings
        .iter()
        .map(|s| (s.offset, s.identifier.as_str()))
        .collect();
    assert_eq!(got, [(0, "$b"), (4, "$a"), (8, "$b")]);
}

#[test]
fn excerpt_is_capped() {
    let rs = set(r#"rule big { strings: $a = /x{200}/ condition: $a }"#);
    let m = scan(&rs, &vec![b'x'; 300]);
    let s = &m[0].strings[0];
    assert!(s.length > MAX_EXCERPT_BYTES as u64);
    assert_eq!(s.excerpt_hex.len(), MAX_EXCERPT_BYTES * 2);
    assert!(s.excerpt_hex.chars().all(|c| c == '7' || c == '8'));
}

#[test]
fn severity_mapping_table() {
    let s = |k: &str, v: MetaValue| vec![(k.to_string(), v)];
    let st = |k: &str, v: &str| s(k, MetaValue::String(v.into()));
    let n = |k: &str, v: i64| s(k, MetaValue::Integer(v));
    assert_eq!(severity_from_meta(&[]), Severity::Medium);
    for (v, want) in [
        ("critical", Severity::Critical),
        ("HIGH", Severity::High),
        ("Medium", Severity::Medium),
        ("low", Severity::Low),
        ("info", Severity::Info),
        ("Informational", Severity::Info),
    ] {
        assert_eq!(severity_from_meta(&st("severity", v)), want, "{v}");
    }
    assert_eq!(severity_from_meta(&st("SEVERITY", "low")), Severity::Low);
    assert_eq!(
        severity_from_meta(&st("severity", "bogus")),
        Severity::Medium
    );
    for (score, want) in [
        (100, Severity::Critical),
        (80, Severity::Critical),
        (79, Severity::High),
        (60, Severity::High),
        (59, Severity::Medium),
        (40, Severity::Medium),
        (39, Severity::Low),
        (20, Severity::Low),
        (19, Severity::Info),
        (0, Severity::Info),
        (-5, Severity::Info),
    ] {
        assert_eq!(severity_from_meta(&n("score", score)), want, "{score}");
    }
    assert_eq!(severity_from_meta(&n("Score", 85)), Severity::Critical);
    // A score that is not an integer is ignored.
    assert_eq!(severity_from_meta(&st("score", "99")), Severity::Medium);
    // severity wins over score; an unparsable severity falls back to score.
    let both = vec![
        ("score".to_string(), MetaValue::Integer(90)),
        ("severity".to_string(), MetaValue::String("low".into())),
    ];
    assert_eq!(severity_from_meta(&both), Severity::Low);
    let bad = vec![
        ("severity".to_string(), MetaValue::String("???".into())),
        ("score".to_string(), MetaValue::Integer(65)),
    ];
    assert_eq!(severity_from_meta(&bad), Severity::High);
}

#[test]
fn severity_flows_into_rule_info_and_matches() {
    let rs = set(r#"rule a { meta: severity = "Critical" condition: true }
           rule b { meta: score = 45 condition: true }
           rule c { condition: true }"#);
    let got: Vec<_> = rs.rules().iter().map(|r| r.severity).collect();
    assert_eq!(
        got,
        [Severity::Critical, Severity::Medium, Severity::Medium]
    );
    let m = scan(&rs, b"");
    assert_eq!(m[0].severity, Severity::Critical);
    assert_eq!(m[1].severity, Severity::Medium);
}

#[test]
fn pathological_rule_times_out() {
    // A quadratic loop over the buffer: far too slow to finish, so only the
    // timeout can end the scan.
    let rs = set(
        "rule slow { condition: for all i in (0..filesize) : (for all j in (0..filesize) : (uint8(i) == uint8(j) and uint8(j) == 0)) }",
    );
    let bytes = vec![0u8; 4 * 1024 * 1024];
    let mut sc = rs.scanner();
    // YARA-X's clock ticks once a second, so a 1ms timeout fires within
    // about a second.
    let r = sc.scan(&bytes, Duration::from_millis(1));
    assert_eq!(r, Err(ScanError::Timeout));
    // The scanner is reusable afterwards.
    assert!(sc.scan(b"abc", T).is_ok());
}

#[test]
fn empty_and_hostile_inputs_do_not_panic() {
    let rs = set(r#"rule always { condition: true }
           rule never { strings: $a = "x" condition: $a }
           rule size0 { condition: filesize == 0 }"#);
    assert_eq!(names(&scan(&rs, b"")), ["always", "size0"]);
    let mut sc = rs.scanner();
    for bytes in [&[0u8; 1][..], &[0xff; 1000][..], b"\xef\xbb\xbf"] {
        sc.scan(bytes, T).unwrap();
    }
    // Hostile rule text.
    let junk = [
        "\0\0\0",
        "rule",
        "rule a { strings: $a = { [",
        "rule a { condition: 1 / 0 }",
        "rule a { strings: $a = /(((((((((((((((((((((((((a)))))))))))))))))))))))))*/ condition: $a }",
        &"(".repeat(100_000),
        "import \"pe\" rule a { condition: pe.sections[999999999].name == \"x\" }",
    ];
    for (i, text) in junk.iter().enumerate() {
        let r = RuleSet::compile(
            &[src("j", &format!("j{i}.yar"), text)],
            &CompileLimits::default(),
        );
        assert!(r.is_ok());
    }
}

#[test]
fn rule_set_is_send_and_sync_and_shareable() {
    fn assert<T: Send + Sync>() {}
    assert::<RuleSet>();
    let rs = std::sync::Arc::new(set(r#"rule r { strings: $a = "z" condition: $a }"#));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let rs = rs.clone();
            std::thread::spawn(move || rs.scanner().scan(b"zz", T).unwrap().len())
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 1);
    }
}

#[test]
fn output_serialises_camel_case() {
    let rs = set(r#"rule r : t { meta: m = 1 strings: $a = "q" condition: $a }"#);
    let json = serde_json::to_value(scan(&rs, b"q")).unwrap();
    assert!(json[0]["stringsTruncated"].is_number());
    assert!(json[0]["strings"][0]["excerptHex"].is_string());
    assert_eq!(json[0]["severity"], "medium");
    let info = serde_json::to_value(&rs.rules()[0]).unwrap();
    assert_eq!(info["meta"][0][1]["type"], "integer");
}

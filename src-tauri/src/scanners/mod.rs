pub mod dataflow;
pub mod patterns;
pub mod secrets;
pub mod syntax;
pub mod testscope;

use std::collections::BTreeSet;
use std::path::Path;

use crate::findings::redaction;
use crate::fs_utils;
use crate::models::Finding;

/// Rule ids that fire on this content, for the corpus benchmark and the
/// criterion throughput benches. Public so `benches/scanning.rs` can measure
/// the same path a scan takes rather than an approximation of it.
pub fn benchmark_observations(
    content: &str,
    language: &str,
    source_patterns: bool,
    secret_patterns: bool,
) -> Vec<(&'static str, &'static str)> {
    let mut observations = Vec::new();
    // Parsed once and shared: both engines ask the same tree what is comment
    // and what is code, so the benchmark and a real scan cannot disagree.
    let parsed = syntax::parse(content, language);
    let spans = parsed.spans();
    if source_patterns {
        observations.extend(
            patterns::scan_content(content, language)
                .into_iter()
                .filter(|hit| spans.allows_code_match(hit.offset))
                .filter(|hit| assess_sink(&parsed, content, hit).reportable)
                .map(|hit| (patterns::SOURCE_RULES[hit.rule_index].id, "file_location")),
        );
    }
    if secret_patterns {
        observations.extend(
            secrets::scan_content(content)
                .into_iter()
                .filter(|hit| spans.allows_secret_match(hit.offset))
                .map(|hit| (secrets::SECRET_RULES[hit.rule_index].id, "redacted_secret")),
        );
    }
    observations
}

/// Should a pattern match be reported, given what reaches its sink?
///
/// Only a value *positively shown* to be constant is dropped. Anything the
/// analysis cannot decide — no grammar, no enclosing call, an unresolvable
/// name — is reported, because a false negative in a security scanner costs
/// more than a false positive.
///
/// Rules that are not about a call argument are unaffected: they have no
/// enclosing call, so the analysis returns `Unknown` and the finding stands.
/// Has this file applied the hardening a guarded rule looks for?
///
/// Only hardening that is *code* counts. A comment saying "use defusedxml"
/// documents the problem; it does not fix it, and matching raw text cannot
/// tell the difference.
fn hardening_present(rule_id: &str, content: &str, spans: &syntax::SyntaxSpans) -> bool {
    let Some(pattern) = patterns::guard_pattern(rule_id) else {
        return false;
    };
    pattern
        .find_iter(content)
        .any(|found| spans.allows_hardening_match(found.start()))
}

/// What the dataflow analysis concluded about one pattern match.
struct SinkAssessment {
    /// False when the value is provably beyond an attacker's choosing.
    reportable: bool,
    /// Gate answers to carry into the review, if the analysis found any.
    gates: Vec<crate::triage::gates::GateNote>,
}

fn assess_sink(
    parsed: &syntax::FileSyntax,
    content: &str,
    hit: &patterns::PatternHit,
) -> SinkAssessment {
    // The rule's weakness class decides which transforms count as sanitizing.
    let cwe = patterns::SOURCE_RULES[hit.rule_index].cwe;
    let sink_cwe = (!cwe.is_empty()).then_some(cwe);
    // A defect that is the absence of hardening is disproved by the hardening
    // appearing anywhere in the file, as code.
    let rule_id = patterns::SOURCE_RULES[hit.rule_index].id;
    if hardening_present(rule_id, content, parsed.spans()) {
        return SinkAssessment {
            reportable: false,
            gates: Vec::new(),
        };
    }

    // Some command sinks stop being shell sinks the moment they are handed an
    // argument vector: the OS receives argv directly and no shell ever parses
    // it, so metacharacters are inert. `system("tar", "-czf", dir)` is exactly
    // what this rule's own remediation text tells you to write, and reporting
    // it means reporting the fix.
    if patterns::argv_form_is_safe(rule_id) {
        if let Some(count) = parsed.argument_count_at(hit.offset) {
            if count > 1 {
                return SinkAssessment {
                    reportable: false,
                    gates: Vec::new(),
                };
            }
        }
    }

    let taint = parsed.taint_at(content, hit.offset, sink_cwe);

    // Cleared outright: nobody can choose the value, or a transform covering
    // this weakness already neutralized it.
    let cleared = matches!(
        taint,
        dataflow::Taint::Constant | dataflow::Taint::Sanitized { .. }
    );

    // For a few weakness classes, taking a caller-supplied value is the
    // ordinary case rather than the defect — an HTTP wrapper takes a URL, a
    // file helper takes a path. Reporting those on any parameter made js-ssrf
    // fire 148 times across one dependency tree, half of every finding. Those
    // classes need the value to come from outside the program.
    //
    // Whether a parameter is reachable from a request handler needs a call
    // graph, so this is a deliberate trade of recall for a rule somebody will
    // leave switched on.
    let insufficient_origin = dataflow::requires_external_origin(sink_cwe)
        && !matches!(
            taint,
            dataflow::Taint::Tainted {
                origin: dataflow::Origin::External
            }
        );

    SinkAssessment {
        reportable: !cleared && !insufficient_origin,
        gates: dataflow::gate_notes(taint, sink_cwe),
    }
}

pub struct ScanFileOutcome {
    pub findings: Vec<Finding>,
    // Consumed by the durable scan service introduced in the next foundation slice.
    #[allow(dead_code)]
    pub covered_families: Vec<String>,
}

impl ScanFileOutcome {
    fn skipped() -> Self {
        Self {
            findings: Vec::new(),
            covered_families: Vec::new(),
        }
    }
}

fn secret_redaction_values(hits: &[secrets::SecretHit]) -> Vec<String> {
    let mut unique = BTreeSet::new();
    for hit in hits {
        if !hit.secret_value.is_empty() {
            unique.insert(hit.secret_value.clone());
        }
        if hit.secret_value.contains(['\r', '\n']) {
            for line in hit.secret_value.lines().filter(|line| !line.is_empty()) {
                unique.insert(line.to_owned());
            }
        }
    }
    let mut values = unique.into_iter().collect::<Vec<_>>();
    values.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    values
}

fn redact_detected_secrets(text: &str, values: &[String]) -> String {
    values.iter().fold(text.to_owned(), |safe, value| {
        redaction::redact_exact(&safe, value)
    })
}

/// Scan a single file and produce findings. Returns an empty vec when the file
/// is binary, too large, or unreadable.
#[cfg(test)]
pub fn scan_file(
    root: &Path,
    path: &Path,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
) -> Vec<Finding> {
    let relative_path = fs_utils::display_path(root, path);
    scan_file_with_relative_path(
        path,
        &relative_path,
        max_file_size_kb,
        scan_secrets,
        scan_vulnerabilities,
    )
    .findings
}

/// Scan a canonical contained file while preserving its caller-validated
/// lexical identity in findings.
pub fn scan_file_with_relative_path(
    path: &Path,
    relative_path: &str,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
) -> ScanFileOutcome {
    let max_bytes = max_file_size_kb.saturating_mul(1024);
    let content = match fs_utils::read_text_file(path, max_bytes) {
        Some(c) => c,
        None => return ScanFileOutcome::skipped(),
    };
    let starts = fs_utils::line_starts(&content);
    let rel = relative_path.to_string();
    let mut findings = Vec::new();
    let mut covered_families = Vec::new();
    // Parsed once and shared by both engines, so a scan and the benchmark
    // cannot disagree about what counts as a comment.
    let detected_language = fs_utils::detect_language(path).unwrap_or("");
    let parsed = syntax::parse(&content, detected_language);
    let spans = parsed.spans();
    let secret_hits: Vec<_> = secrets::scan_content(&content)
        .into_iter()
        .filter(|hit| spans.allows_secret_match(hit.offset))
        .collect();
    let secret_values = secret_redaction_values(&secret_hits);
    // Walked once, and only for a file that actually produced a finding: the
    // tree walk is wasted on the overwhelming majority of files that yield
    // nothing.
    let test_regions = std::cell::OnceCell::new();
    let in_test_region = |offset: usize| -> bool {
        test_regions
            .get_or_init(|| parsed.test_regions(&content, detected_language))
            .iter()
            .any(|region| region.contains(&offset))
    };

    if scan_secrets {
        covered_families.push("secret".to_string());
        for hit in &secret_hits {
            let rule = &secrets::SECRET_RULES[hit.rule_index];
            let (line, col) = fs_utils::line_col(&starts, hit.offset);
            let context = fs_utils::context_lines(&content, &starts, line - 1, 2);
            let match_text = secrets::truncate(
                &redact_detected_secrets(&hit.match_text, &secret_values),
                240,
            );
            let context = redact_detected_secrets(&context, &secret_values);
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                category: "secret".into(),
                rule_id: rule.id.into(),
                rule_name: rule.name.into(),
                severity: rule.severity.into(),
                title: rule.name.into(),
                description: rule.description.into(),
                file_path: rel.clone(),
                line,
                column: col,
                match_text,
                context,
                language: String::new(),
                cwe_exploited: false,
                cwe_exploited_count: 0,
                cwe: None,
                recommendation: rule.recommendation.into(),
                entropy: Some(hit.entropy),
                verified: None,
                // Secret matches are checked against the tree for comments
                // only; a credential in a string literal is the normal case.
                analysis: if spans.analyzed() {
                    crate::models::AnalysisTier::Syntax
                } else {
                    crate::models::AnalysisTier::Text
                },
                // A secret is a literal, not a call argument; there is no sink
                // for the dataflow analysis to reason about.
                analysis_gates: Vec::new(),
                observation_run_id: String::new(),
                resolved_by_run_id: None,
                fingerprint_version: 0,
                fingerprint: String::new(),
                in_test_region: in_test_region(hit.offset),
                scope: None,
                scope_reason: None,
                review: None,
                review_history: Vec::new(),
                diff_status: None,
            });
        }
    }

    if scan_vulnerabilities {
        if let Some(lang) = fs_utils::detect_language(path) {
            covered_families.push("vulnerability".to_string());
            let hits = patterns::scan_content(&content, lang);
            for hit in hits {
                // A rule matching inside a comment or a string literal is
                // describing code rather than being it — the single largest
                // false-positive class the corpus measured.
                if !spans.allows_code_match(hit.offset) {
                    continue;
                }
                // A sink whose argument is provably a constant, or sanitized
                // for this weakness, is not a finding: nobody can choose the
                // value that reaches it.
                let assessment = assess_sink(&parsed, &content, &hit);
                if !assessment.reportable {
                    continue;
                }
                let rule = &patterns::SOURCE_RULES[hit.rule_index];
                let (line, col) = fs_utils::line_col(&starts, hit.offset);
                let context = fs_utils::context_lines(&content, &starts, line - 1, 2);
                findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: "vulnerability".into(),
                    rule_id: rule.id.into(),
                    rule_name: rule.name.into(),
                    severity: rule.severity.into(),
                    title: rule.name.into(),
                    description: rule.message.into(),
                    file_path: rel.clone(),
                    line,
                    column: col,
                    match_text: secrets::truncate(
                        &redact_detected_secrets(&hit.match_text, &secret_values),
                        240,
                    ),
                    context: redact_detected_secrets(&context, &secret_values),
                    language: lang.into(),
                    cwe_exploited: false,
                    cwe_exploited_count: 0,
                    cwe: Some(rule.cwe.into()),
                    recommendation: rule.recommendation.into(),
                    entropy: None,
                    verified: None,
                    analysis: if spans.analyzed() {
                        crate::models::AnalysisTier::Syntax
                    } else {
                        crate::models::AnalysisTier::Text
                    },
                    analysis_gates: assessment.gates.clone(),
                    observation_run_id: String::new(),
                    resolved_by_run_id: None,
                    fingerprint_version: 0,
                    fingerprint: String::new(),
                    in_test_region: in_test_region(hit.offset),
                    scope: None,
                    scope_reason: None,
                    review: None,
                    review_history: Vec::new(),
                    diff_status: None,
                });
            }
        }
    }

    ScanFileOutcome {
        findings,
        covered_families,
    }
}

#[cfg(test)]
mod tests {
    use super::scan_file_with_relative_path;

    const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";

    #[test]
    fn scanner_retains_all_thirty_matches_for_one_rule() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("credentials.txt");
        let source = (0..30)
            .map(|_| format!("token = \"{CANARY}\";"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&source_path, source).expect("secret fixture");

        let outcome =
            scan_file_with_relative_path(&source_path, "credentials.txt", 64, true, false);
        let matching = outcome
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "generic-api-key")
            .count();

        assert_eq!(matching, 30);
    }

    #[test]
    fn readable_text_reports_only_enabled_supported_families() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let javascript = directory.path().join("app.js");
        let text = directory.path().join("notes.txt");
        std::fs::write(&javascript, "eval(input);\n").expect("javascript fixture");
        std::fs::write(&text, "ordinary text\n").expect("text fixture");

        let both = scan_file_with_relative_path(&javascript, "app.js", 64, true, true);
        let unsupported = scan_file_with_relative_path(&text, "notes.txt", 64, false, true);
        let disabled = scan_file_with_relative_path(&javascript, "app.js", 64, false, false);

        assert_eq!(both.covered_families, ["secret", "vulnerability"]);
        assert!(unsupported.covered_families.is_empty());
        assert!(disabled.covered_families.is_empty());
    }

    #[test]
    fn committed_quality_corpus_passes_the_real_scanner_paths() {
        let suite: oxaudit_benchmark::BenchmarkSuite = serde_json::from_str(include_str!(
            "../../../benchmarks/ground-truth/source-smoke/suite.json"
        ))
        .expect("committed suite");
        for target in &suite.targets {
            let content = match target.input_path.as_str() {
                "positive.js" => {
                    include_str!("../../../benchmarks/ground-truth/source-smoke/positive.js")
                }
                "negative.js" => {
                    include_str!("../../../benchmarks/ground-truth/source-smoke/negative.js")
                }
                "python-shell-positive.py" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/python-shell-positive.py"
                ),
                "python-shell-negative.py" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/python-shell-negative.py"
                ),
                "c-strcpy-positive.c" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/c-strcpy-positive.c"
                ),
                "c-strcpy-negative.c" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/c-strcpy-negative.c"
                ),
                "go-md5-positive.go" => {
                    include_str!("../../../benchmarks/ground-truth/source-smoke/go-md5-positive.go")
                }
                "go-md5-negative.go" => {
                    include_str!("../../../benchmarks/ground-truth/source-smoke/go-md5-negative.go")
                }
                "generic-api-key-positive.txt" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/generic-api-key-positive.txt"
                ),
                "generic-api-key-negative.txt" => include_str!(
                    "../../../benchmarks/ground-truth/source-smoke/generic-api-key-negative.txt"
                ),
                path => panic!("unwired committed fixture {path}"),
            };
            let observations = super::benchmark_observations(
                content,
                target.language.as_deref().unwrap_or(""),
                target
                    .scanner_families
                    .iter()
                    .any(|family| family == "source-pattern"),
                target
                    .scanner_families
                    .iter()
                    .any(|family| family == "secret"),
            )
            .into_iter()
            .map(
                |(rule_id, evidence_kind)| oxaudit_benchmark::ActualObservation {
                    identity: oxaudit_benchmark::ObservationIdentity {
                        rule_id: rule_id.into(),
                        artifact_path: target.input_path.clone(),
                    },
                    evidence_kind: evidence_kind.into(),
                },
            )
            .collect();
            let result = oxaudit_benchmark::judge(
                target,
                oxaudit_benchmark::ExecutionResult {
                    observations,
                    runtime_ms: 0,
                    peak_memory_bytes: None,
                },
            );
            assert_eq!(
                result.status,
                oxaudit_benchmark::TargetStatus::Passed,
                "{} failed: misses={:?}, unexpected={:?}",
                target.id,
                result.misses,
                result.unexpected
            );
        }
    }

    #[test]
    fn skipped_files_report_no_findings_or_coverage() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let missing = directory.path().join("missing.js");
        let binary = directory.path().join("binary.js");
        let oversized = directory.path().join("oversized.js");
        std::fs::write(&binary, b"eval(input);\0binary").expect("binary fixture");
        std::fs::write(&oversized, "eval(input);\n").expect("oversized fixture");

        for outcome in [
            scan_file_with_relative_path(&missing, "missing.js", 64, true, true),
            scan_file_with_relative_path(&binary, "binary.js", 64, true, true),
            scan_file_with_relative_path(&oversized, "oversized.js", 0, true, true),
        ] {
            assert!(outcome.findings.is_empty());
            assert!(outcome.covered_families.is_empty());
        }
    }

    #[test]
    fn vulnerability_only_findings_redact_detected_credentials() {
        const PASSWORD_CANARY: &str = "VulnOnlyCanary-7D4zP9q2";
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("app.js");
        std::fs::write(
            &source_path,
            format!("const password = \"{PASSWORD_CANARY}\";\n"),
        )
        .expect("hardcoded password fixture");

        let outcome = scan_file_with_relative_path(&source_path, "app.js", 64, false, true);

        assert_eq!(outcome.covered_families, ["vulnerability"]);
        assert!(outcome
            .findings
            .iter()
            .all(|finding| finding.category == "vulnerability"));
        let serialized = serde_json::to_string(&outcome.findings).expect("serializable findings");
        assert!(!serialized.contains(PASSWORD_CANARY));
        assert!(serialized.contains("[REDACTED]"));
    }

    /// Scan one source string and list the rules that fired.
    fn rules_firing(name: &str, source: &str) -> Vec<String> {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let path = directory.path().join(name);
        std::fs::write(&path, source).expect("fixture");
        let outcome = scan_file_with_relative_path(&path, name, 64, false, true);
        let mut rules: Vec<String> = outcome
            .findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect();
        rules.sort();
        rules
    }

    #[test]
    fn xxe_is_reported_when_the_parser_is_left_at_its_defaults() {
        let rules = rules_firing(
            "Parse.java",
            "class Parse {\n  void go() throws Exception {\n    var f = DocumentBuilderFactory.newInstance();\n    f.newDocumentBuilder().parse(input);\n  }\n}\n",
        );
        assert!(rules.iter().any(|rule| rule == "java-xxe"), "{rules:?}");
    }

    #[test]
    fn xxe_is_not_reported_once_the_parser_is_hardened() {
        let rules = rules_firing(
            "Parse.java",
            "class Parse {\n  void go() throws Exception {\n    var f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(input);\n  }\n}\n",
        );
        assert!(!rules.iter().any(|rule| rule == "java-xxe"), "{rules:?}");
    }

    #[test]
    fn a_comment_naming_the_fix_does_not_count_as_the_fix() {
        // The guard asks whether the hardening is *in the code*. A comment
        // mentioning `defusedxml` is a plan, not a mitigation — and this is
        // exactly how the mechanism first went wrong: a fixture's own comment
        // suppressed the finding it was written to prove.
        let rules = rules_firing(
            "parse.py",
            "# TODO: switch to defusedxml\nimport xml.etree.ElementTree as ET\nET.parse(path)\n",
        );
        assert!(rules.iter().any(|rule| rule == "py-xxe"), "{rules:?}");
    }

    #[test]
    fn importing_the_safe_parser_does_count_as_the_fix() {
        let rules = rules_firing(
            "parse.py",
            "import defusedxml.ElementTree as ET\nET.parse(path)\n",
        );
        assert!(!rules.iter().any(|rule| rule == "py-xxe"), "{rules:?}");
    }

    // --------------------------------------------- newly grammared languages

    #[test]
    fn prose_about_a_sink_is_not_a_sink_in_php_ruby_and_c() {
        // These four languages shipped rules with no grammar behind them, so
        // every one of these fired. None of these files contain a live call.
        let cases = [
            (
                "a.php",
                "<?php\n// Never call eval($_GET['x']) here.\n# exec($cmd) was removed.\n$n = \"do not use system($cmd)\";\n",
            ),
            (
                "b.rb",
                "# Avoid eval(params[:x]).\n=begin\nMarshal.load(untrusted) was removed.\n=end\nN = \"never call system(cmd)\"\n",
            ),
            (
                "c.c",
                "/* strcpy(dst, src) is banned. */\n// gets(buf) must never appear.\nconst char *N = \"no sprintf(buf, fmt)\";\n",
            ),
            (
                "d.cpp",
                "// strcat(a, b) is banned.\nauto n = R\"(never call gets(buf))\";\n",
            ),
        ];
        for (name, source) in cases {
            assert_eq!(rules_firing(name, source), Vec::<String>::new(), "{name}");
        }
    }

    #[test]
    fn real_calls_in_those_languages_are_still_reported() {
        // The counterpart: suppression must not have swallowed the language.
        assert!(
            rules_firing("a.php", "<?php\nfunction f($r) { return eval($r['x']); }\n")
                .iter()
                .any(|rule| rule == "php-eval")
        );
        assert!(
            rules_firing("b.rb", "def f(params)\n  eval(params[:x])\nend\n")
                .iter()
                .any(|rule| rule == "rb-eval")
        );
        assert!(
            rules_firing("c.c", "void f(char *d, char **v) { strcpy(d, v[1]); }\n")
                .iter()
                .any(|rule| rule == "c-strcpy")
        );
    }

    #[test]
    fn an_argument_vector_is_not_a_shell_sink() {
        // The rule's own remediation says to use an argument array. Reporting
        // that form reports the fix as the defect.
        let argv = rules_firing("r.rb", "def f(d)\n  system(\"tar\", \"-czf\", d)\nend\n");
        assert!(!argv.iter().any(|rule| rule == "rb-system"), "{argv:?}");

        let shell = rules_firing("r.rb", "def f(d)\n  system(\"tar -czf #{d}\")\nend\n");
        assert!(shell.iter().any(|rule| rule == "rb-system"), "{shell:?}");
    }

    #[test]
    fn the_argv_exemption_does_not_leak_to_other_languages() {
        // C's system() takes exactly one argument and is a shell sink whatever
        // it is given, so nothing about argument shape may excuse it.
        let rules = rules_firing(
            "c.c",
            "#include <stdlib.h>\nvoid f(char **v) { system(v[1]); }\n",
        );
        assert!(rules.iter().any(|rule| rule == "c-system"), "{rules:?}");
    }
}

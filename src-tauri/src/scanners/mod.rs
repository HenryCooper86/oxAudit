pub mod config_values;
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
        let mut hits = patterns::scan_content(content, language);
        parsed.drop_nested_duplicates(&mut hits);
        observations.extend(
            hits.into_iter()
                .filter(|hit| spans.allows_code_match(hit.offset))
                .filter(|hit| {
                    assess_sink(
                        &parsed,
                        content,
                        hit,
                        &config_values::ProjectConfig::default(),
                    )
                    .reportable
                })
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
    config: &config_values::ProjectConfig,
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

    // A few rules are about *which* value reached the sink rather than who
    // chose it. An algorithm name that cannot be resolved is not evidence of
    // anything, so these stay silent rather than reporting on suspicion.
    if let Some((index, values)) = patterns::resolved_argument_values(rule_id) {
        let resolved = parsed.resolved_argument(content, hit.offset, index, config);
        if !resolved.is_some_and(|value| patterns::names_algorithm(&value, values)) {
            return SinkAssessment {
                reportable: false,
                gates: Vec::new(),
            };
        }
    }

    let taint = match patterns::sink_argument(rule_id) {
        Some(index) => parsed.taint_of_argument(content, hit.offset, sink_cwe, index),
        None => parsed.taint_at(content, hit.offset, sink_cwe),
    };

    // Cleared outright: nobody can choose the value, or a transform covering
    // this weakness already neutralized it.
    //
    // Not for the classes where the call itself is the defect. Nothing done to
    // the result of `Math.random()` makes it unpredictable, so reading the
    // arguments of the chain it sits in only finds reasons to hide it.
    let cleared = !dataflow::call_is_the_defect(sink_cwe)
        && matches!(
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
    scan_file_in_project(
        path,
        relative_path,
        max_file_size_kb,
        scan_secrets,
        scan_vulnerabilities,
        &config_values::ProjectConfig::default(),
    )
}

/// Scan one file with the target's own configuration available.
///
/// Some rules cannot decide from the file in front of them: the digest
/// algorithm a servlet uses is frequently a key in a `.properties` file
/// somewhere else in the same project. `config` carries what those files say;
/// an empty one simply means no rule that needs it will fire.
pub fn scan_file_in_project(
    path: &Path,
    relative_path: &str,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
    config: &config_values::ProjectConfig,
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
            let mut hits = patterns::scan_content(&content, lang);
            // One nested expression is one defect, not one per constructor.
            parsed.drop_nested_duplicates(&mut hits);
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
                let assessment = assess_sink(&parsed, &content, &hit, config);
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
    use super::config_values::ProjectConfig;
    use super::{scan_file_in_project, scan_file_with_relative_path};

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

    /// Scan one source file beside one properties file, and list the rules
    /// that fired.
    fn rules_firing_with_config(name: &str, source: &str, properties: &str) -> Vec<String> {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let path = directory.path().join(name);
        std::fs::write(&path, source).expect("fixture");
        let config_path = directory.path().join("application.properties");
        std::fs::write(&config_path, properties).expect("properties");
        let config = ProjectConfig::from_paths([path.as_path(), config_path.as_path()]);
        let outcome = scan_file_in_project(&path, name, 64, false, true, &config);
        let mut rules: Vec<String> = outcome
            .findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect();
        rules.sort();
        rules
    }

    const DIGEST_FROM_CONFIG: &str = "import java.security.MessageDigest;\n\
        class Digest {\n\
        \x20 byte[] hash(java.util.Properties props, byte[] data) throws Exception {\n\
        \x20   String algorithm = props.getProperty(\"digest\", \"SHA-512\");\n\
        \x20   return MessageDigest.getInstance(algorithm).digest(data);\n\
        \x20 }\n\
        }\n";

    #[test]
    fn the_configured_algorithm_wins_over_the_default_written_in_the_source() {
        // This is the whole point of reading configuration: the source says
        // SHA-512 and the application computes MD5.
        let rules = rules_firing_with_config("Digest.java", DIGEST_FROM_CONFIG, "digest=MD5\n");
        assert!(
            rules.iter().any(|rule| rule == "java-configured-weak-hash"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_strong_configured_algorithm_is_not_reported() {
        let rules = rules_firing_with_config("Digest.java", DIGEST_FROM_CONFIG, "digest=SHA-256\n");
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn an_algorithm_no_configuration_names_is_not_reported() {
        // Without the key, the literal default is what the call returns, and
        // SHA-512 is not a finding. Nothing here may be guessed at.
        let rules = rules_firing_with_config("Digest.java", DIGEST_FROM_CONFIG, "other=MD5\n");
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn a_literal_weak_digest_is_reported_once_not_twice() {
        // `java-weak-hash` and `java-configured-weak-hash` match at the same
        // offset; the literal form supersedes.
        let rules = rules_firing(
            "Digest.java",
            "import java.security.MessageDigest;\n\
             class Digest {\n\
             \x20 byte[] hash(byte[] data) throws Exception {\n\
             \x20   return MessageDigest.getInstance(\"MD5\").digest(data);\n\
             \x20 }\n\
             }\n",
        );
        assert_eq!(rules, vec!["java-weak-hash".to_string()], "{rules:?}");
    }

    #[test]
    fn a_nested_sink_of_one_rule_is_reported_once() {
        let rules = rules_firing(
            "Read.java",
            "import javax.servlet.http.HttpServletRequest;\n\
             class Read {\n\
             \x20 void go(HttpServletRequest request) throws Exception {\n\
             \x20   String path = \"/data/\" + request.getParameter(\"name\");\n\
             \x20   new java.io.FileInputStream(new java.io.File(path)).close();\n\
             \x20 }\n\
             }\n",
        );
        let reported = rules
            .iter()
            .filter(|rule| *rule == "java-path-traversal")
            .count();
        assert_eq!(reported, 1, "one statement, one finding: {rules:?}");
    }

    #[test]
    fn the_outer_call_is_the_one_kept_when_sinks_nest() {
        // The inner constructor takes the constant root and the outer takes
        // the attacker's segment. Keeping the inner hit would report the safe
        // half of the expression and drop the unsafe one.
        let rules = rules_firing(
            "Read.java",
            "import javax.servlet.http.HttpServletRequest;\n\
             class Read {\n\
             \x20 java.io.File go(HttpServletRequest request) {\n\
             \x20   return new java.io.File(new java.io.File(\"/data\"), request.getParameter(\"n\"));\n\
             \x20 }\n\
             }\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-path-traversal"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_path_that_survives_a_containment_check_is_not_reported() {
        let rules = rules_firing(
            "Read.java",
            "import javax.servlet.http.HttpServletRequest;\n\
             class Read {\n\
             \x20 java.io.File go(HttpServletRequest request) throws Exception {\n\
             \x20   java.io.File f = new java.io.File(\"/data\", request.getParameter(\"n\"));\n\
             \x20   if (!f.getCanonicalPath().startsWith(\"/data/\")) throw new RuntimeException();\n\
             \x20   return f;\n\
             \x20 }\n\
             }\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-path-traversal"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_path_reached_only_through_a_parameter_is_not_reported() {
        // CWE-22 requires an inbound origin. Taking a path is what a file
        // helper does, and this is the trade that keeps the rule usable.
        let rules = rules_firing(
            "Read.java",
            "class Read {\n\
             \x20 java.io.File go(String name) {\n\
             \x20   return new java.io.File(\"/data/\" + name);\n\
             \x20 }\n\
             }\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-path-traversal"),
            "{rules:?}"
        );
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

    // ------------------------------------------------ C#, Kotlin, and Swift

    #[test]
    fn prose_about_a_sink_is_not_a_sink_in_the_newest_languages() {
        let cases = [
            (
                "A.cs",
                "// Never call Process.Start(userInput) here.\n/// <summary>MD5.Create() is banned.</summary>\nclass A { string N = @\"no BinaryFormatter()\"; }\n",
            ),
            (
                "A.kt",
                "// Runtime.getRuntime().exec(cmd) is banned.\n/* DocumentBuilderFactory.newInstance() needs hardening. */\nval note = \"\"\"never call exec(cmd)\"\"\"\n",
            ),
            (
                "A.swift",
                "// URLCredential(trust: t) accepts any certificate.\n/* Insecure.MD5 is broken. */\nlet note = \"do not call arc4random()\"\n",
            ),
        ];
        for (name, source) in cases {
            assert_eq!(rules_firing(name, source), Vec::<String>::new(), "{name}");
        }
    }

    #[test]
    fn kotlin_reuses_the_jvm_rules() {
        // Kotlin calls the same APIs, so the Java rules apply verbatim rather
        // than being duplicated under new ids.
        let rules = rules_firing(
            "A.kt",
            "class A {\n    fun run(command: String) {\n        Runtime.getRuntime().exec(command)\n    }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_kotlin_literal_argument_is_recognised_as_constant() {
        // Kotlin spells its argument list `value_arguments` with no field
        // label, so every call looked argument-less until that was handled —
        // and a literal command came back Unknown instead of Constant.
        let rules = rules_firing(
            "A.kt",
            "class A {\n    fun listing() {\n        Runtime.getRuntime().exec(\"ls -la\")\n    }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    #[test]
    fn formatting_a_weak_random_value_does_not_excuse_it() {
        // `.toString(36).slice(2)` supplies constant arguments to the chain,
        // and reading them cleared the finding. Nothing done to the output of
        // Math.random() makes it unpredictable.
        let rules = rules_firing(
            "a.js",
            "function createSession(user) {\n  const sessionToken = Math.random().toString(36).slice(2);\n  return sessionToken;\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "js-insecure-random"),
            "{rules:?}"
        );
    }

    #[test]
    fn naming_the_broken_algorithm_is_not_proof_of_safety() {
        // `createHash("md5")` takes exactly one argument, and it is the
        // constant naming the broken hash. Reading that as "nobody can choose
        // this value, so it is safe" suppressed the canonical weak-hash
        // finding — but only when the call stood alone, since a chained
        // `.update(data)` made the chain tainted and reported it anyway.
        let rules = rules_firing(
            "h.js",
            "const crypto = require(\"crypto\");\nfunction f() {\n  return crypto.createHash(\"md5\");\n}\n",
        );
        assert!(rules.iter().any(|rule| rule == "js-weak-hash"), "{rules:?}");
    }

    #[test]
    fn a_generator_named_only_in_a_comment_is_not_a_finding() {
        // These rules match a secret-ish name and then a generator up to 160
        // characters later, so the match *starts* in code while the generator
        // it found sits in a comment. Capture group one moves the finding to
        // the generator, which is what suppression then checks.
        let rules = rules_firing(
            "A.kt",
            "class Tokens {\n    /* Historical: this used Random() to build a session token. */\n    private val generator = java.security.SecureRandom()\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "kt-insecure-random"),
            "{rules:?}"
        );
    }

    #[test]
    fn sql_built_into_a_variable_is_still_sql_injection() {
        // Found by the OWASP Benchmark, not by the corpus: java-sql-concat
        // required the concatenation to sit inside the execute call, so it
        // scored zero true positives across 272 labelled SQL injection cases.
        // Every fixture written for it beforehand happened to use the inline
        // shape, because they were written by someone who knew the pattern.
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f(java.sql.Connection db, javax.servlet.http.HttpServletRequest request) throws Exception {\n    String id = request.getParameter(\"id\");\n    String sql = \"SELECT * FROM users WHERE id = \" + id;\n    db.prepareStatement(sql).executeQuery();\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-sql-concat"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_constant_query_in_a_variable_is_not_reported() {
        // The widened rule matches any prepare/execute taking an identifier,
        // so what keeps it usable is dataflow resolving that identifier. If
        // this ever regresses, the rule fires on every prepared statement
        // ever written.
        for source in [
            "class R {\n  void f(java.sql.Connection db, String id) throws Exception {\n    String sql = \"SELECT * FROM users WHERE id = ?\";\n    java.sql.PreparedStatement st = db.prepareStatement(sql);\n    st.setString(1, id);\n    st.executeQuery();\n  }\n}\n",
            "class R {\n  void f(java.sql.Connection db) throws Exception {\n    db.prepareStatement(\"SELECT 1\").executeQuery();\n  }\n}\n",
        ] {
            let rules = rules_firing("R.java", source);
            assert!(!rules.iter().any(|rule| rule == "java-sql-concat"), "{rules:?}");
        }
    }

    // --------------------------------------- weak crypto and weak randomness

    #[test]
    fn a_broken_algorithm_is_broken_whatever_the_mode() {
        // Found by the OWASP Benchmark: java-cipher-ecb reads the *mode*, so
        // `DES/CBC/PKCS5Padding` passed every check while being 56-bit DES.
        // Zero true positives across 130 labelled cases.
        let rules = rules_firing(
            "E.java",
            "class E { javax.crypto.Cipher f() throws Exception { return javax.crypto.Cipher.getInstance(\"DES/CBC/PKCS5Padding\"); } }\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-weak-cipher"),
            "{rules:?}"
        );

        let strong = rules_firing(
            "E.java",
            "class E { javax.crypto.Cipher f() throws Exception { return javax.crypto.Cipher.getInstance(\"AES/GCM/NOPADDING\"); } }\n",
        );
        assert!(strong.is_empty(), "{strong:?}");
    }

    #[test]
    fn sha1_and_sha_1_name_the_same_broken_hash() {
        for algorithm in ["SHA1", "SHA-1", "sha1", "MD5"] {
            let rules = rules_firing(
                "D.java",
                &format!("class D {{ java.security.MessageDigest f() throws Exception {{ return java.security.MessageDigest.getInstance(\"{algorithm}\"); }} }}\n"),
            );
            assert!(
                rules.iter().any(|rule| rule == "java-weak-hash"),
                "{algorithm}: {rules:?}"
            );
        }
        // The optional hyphen must not swallow the strong SHA-2 family.
        for algorithm in ["SHA-512", "SHA-256", "SHA-384"] {
            let rules = rules_firing(
                "D.java",
                &format!("class D {{ java.security.MessageDigest f() throws Exception {{ return java.security.MessageDigest.getInstance(\"{algorithm}\"); }} }}\n"),
            );
            assert!(rules.is_empty(), "{algorithm}: {rules:?}");
        }
    }

    #[test]
    fn a_weak_generator_is_reported_without_a_secret_name_nearby() {
        // java-insecure-random asks whether a *secret* came from a weak
        // generator and needs a name to decide. That question has an answer
        // only sometimes; whether the generator is cryptographic always does.
        let rules = rules_firing(
            "L.java",
            "class L { int f() { return new java.util.Random().nextInt(99); } }\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-weak-prng"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_secure_generator_is_not_reported() {
        let rules = rules_firing(
            "L.java",
            "class L { int f() throws Exception { return java.security.SecureRandom.getInstance(\"SHA1PRNG\").nextInt(99); } }\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-weak-prng"),
            "{rules:?}"
        );
    }

    #[test]
    fn the_precise_randomness_rule_supersedes_the_broad_one() {
        // Both describe the same call. Reporting both makes the reviewer
        // answer the broad question twice and dilutes the precise finding
        // with the vague one beside it.
        let rules = rules_firing(
            "S.java",
            "class S { String sessionToken() { java.util.Random r = new java.util.Random(); return Long.toString(r.nextLong()); } }\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-insecure-random"),
            "{rules:?}"
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-weak-prng"),
            "the broad rule should have been superseded: {rules:?}"
        );
    }

    #[test]
    fn a_weak_generator_survives_a_constant_in_its_chain() {
        // `new java.util.Random().nextInt(99)` was cleared by the constant 99,
        // because the exemption list named CWE-338 and this rule reports the
        // sibling number CWE-330. Nineteen findings went missing for a
        // vocabulary difference.
        let rules = rules_firing(
            "L.java",
            "class L { int f() { int n = new java.util.Random().nextInt(99); return n; } }\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-weak-prng"),
            "{rules:?}"
        );
    }

    #[test]
    fn taking_the_runtime_once_and_using_it_later_is_still_command_injection() {
        // The rule required `Runtime.getRuntime().exec(` as a single chain, so
        // the ordinary two-statement form went undetected — 93 of the OWASP
        // Benchmark's 126 labelled cases, and none of them exotic.
        let rules = rules_firing(
            "A.java",
            "class A {\n  void f(javax.servlet.http.HttpServletRequest request) throws Exception {\n    Runtime r = Runtime.getRuntime();\n    r.exec(request.getParameter(\"cmd\"));\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_literal_command_through_a_held_runtime_is_not_reported() {
        let rules = rules_firing(
            "A.java",
            "class A {\n  void f() throws Exception {\n    Runtime r = Runtime.getRuntime();\n    r.exec(\"ls -la\");\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    #[test]
    fn the_rule_anchors_on_acquiring_a_runtime_not_on_the_word() {
        // Widening this to proximity risks turning any nearby `.exec(` into a
        // command-injection finding. `RuntimeException` in a catch clause is
        // the shape that would do it, so the anchor requires a Runtime to
        // actually be obtained.
        let rules = rules_firing(
            "A.java",
            "class A {\n  void f(QueryEngine engine, String query) {\n    try { engine.start(); }\n    catch (RuntimeException error) { engine.exec(query); }\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    // ------------------------------------ values the analysis can settle

    #[test]
    fn a_flags_constant_beside_the_argument_does_not_flip_the_verdict() {
        // One unresolved argument makes a whole call unresolved, so a static
        // constant sitting next to the argument a rule cares about used to
        // decide the outcome: `execute(sql, RETURN_GENERATED_KEYS)` reported
        // where `execute(sql)` did not, for no difference in the SQL.
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f(java.sql.Statement st) throws Exception {\n    String sql = \"SELECT * FROM users WHERE id = 1\";\n    st.execute(sql, java.sql.Statement.RETURN_GENERATED_KEYS);\n  }\n}\n",
        );
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn a_member_that_could_hold_input_keeps_its_unknown() {
        // The constant rule is a naming convention, so it is drawn tightly:
        // only SCREAMING_SNAKE_CASE. `config.userInput` must not qualify.
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f(java.sql.Statement st, Config config) throws Exception {\n    String sql = \"SELECT * FROM users WHERE id = \" + config.userInput;\n    st.execute(sql);\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-sql-concat"),
            "{rules:?}"
        );
    }

    #[test]
    fn an_array_of_literals_is_a_constant() {
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f() throws Exception {\n    Runtime r = Runtime.getRuntime();\n    r.exec(new String[] {\"ls\", \"-la\"});\n  }\n}\n",
        );
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn an_array_holding_one_tainted_element_is_tainted() {
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f(javax.servlet.http.HttpServletRequest request) throws Exception {\n    Runtime r = Runtime.getRuntime();\n    r.exec(new String[] {\"sh\", \"-c\", request.getParameter(\"cmd\")});\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-runtime-exec"),
            "{rules:?}"
        );
    }

    #[test]
    fn an_accessor_taking_a_constant_key_is_not_a_constant() {
        // The guard on a change that was tried and reverted. Treating an
        // unmodelled callee as a function of its arguments removes 28 false
        // SQL reports from the OWASP Benchmark and hides 11 real injections,
        // because `get("id")` takes a constant key and returns request data.
        // If this test ever starts failing, that trade has been made again.
        let rules = rules_firing(
            "R.java",
            "class R {\n  void f(java.sql.Statement st, Params params) throws Exception {\n    String sql = \"SELECT * FROM users WHERE id = \" + params.get(\"id\");\n    st.execute(sql);\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-sql-concat"),
            "{rules:?}"
        );
    }

    // ------------------------------------------- XSS, LDAP, and XPath

    #[test]
    fn an_unescaped_value_written_to_the_response_is_reported() {
        let rules = rules_firing(
            "S.java",
            "class S {\n  void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {\n    response.getWriter().println(request.getParameter(\"q\"));\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-xss-response"),
            "{rules:?}"
        );
    }

    #[test]
    fn an_html_encoder_clears_the_response_sink() {
        // encodeForHTML escapes markup and nothing else, so it excuses this
        // sink and would not excuse a command or a query.
        let rules = rules_firing(
            "S.java",
            "class S {\n  void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {\n    response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(request.getParameter(\"q\")));\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-xss-response"),
            "{rules:?}"
        );
    }

    #[test]
    fn every_argument_to_a_writer_counts() {
        // `format(Locale.US, param, obj)` puts the format string second, and
        // an attacker-controlled format string reads the argument list. Fixing
        // this rule to a single argument position cost 71 true positives.
        let rules = rules_firing(
            "S.java",
            "class S {\n  void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {\n    Object[] obj = {\"a\", \"b\"};\n    response.getWriter().format(java.util.Locale.US, request.getParameter(\"q\"), obj);\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-xss-response"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_placeholder_ldap_filter_is_not_the_defect() {
        // The remediation this rule recommends. The value bound to {0} is
        // attacker-controlled exactly as it should be, so reading every
        // argument reported the fix.
        let rules = rules_firing(
            "D.java",
            "class D {\n  void f(javax.naming.directory.DirContext ctx, javax.servlet.http.HttpServletRequest request) throws Exception {\n    String filter = \"(&(objectclass=person)(uid={0}))\";\n    Object[] args = {request.getParameter(\"uid\")};\n    ctx.search(\"dc=example,dc=com\", filter, args, new javax.naming.directory.SearchControls());\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-ldap-injection"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_concatenated_ldap_filter_is_reported() {
        let rules = rules_firing(
            "D.java",
            "class D {\n  void f(javax.naming.directory.DirContext ctx, javax.servlet.http.HttpServletRequest request) throws Exception {\n    String filter = \"(&(objectclass=person)(uid=\" + request.getParameter(\"uid\") + \"))\";\n    ctx.search(\"dc=example,dc=com\", filter, new javax.naming.directory.SearchControls());\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-ldap-injection"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_constant_xpath_expression_survives_a_document_parameter() {
        // The document is a parameter and so not constant, but it is not the
        // injection vector — the expression is.
        let rules = rules_firing(
            "E.java",
            "class E {\n  void f(org.w3c.dom.Document document) throws Exception {\n    javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();\n    String expression = \"/Employees/Employee[@id='fixed']\";\n    xpath.evaluate(expression, document);\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-xpath-injection"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_concatenated_xpath_expression_is_reported() {
        let rules = rules_firing(
            "E.java",
            "class E {\n  void f(javax.servlet.http.HttpServletRequest request, org.w3c.dom.Document document) throws Exception {\n    javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();\n    String expression = \"/Employees/Employee[@id='\" + request.getParameter(\"id\") + \"']\";\n    xpath.evaluate(expression, document);\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-xpath-injection"),
            "{rules:?}"
        );
    }

    // ------------------------------- secure cookies and trust boundaries

    #[test]
    fn a_cookie_with_secure_switched_off_is_reported() {
        // The constant `false` is the whole finding, so CWE-614 has to be
        // exempt from argument-based clearing. It was not, and the rule
        // scored zero on all 36 labelled cases until it was.
        let rules = rules_firing(
            "S.java",
            "class S {\n  void f(javax.servlet.http.HttpServletResponse response) {\n    javax.servlet.http.Cookie c = new javax.servlet.http.Cookie(\"sid\", \"x\");\n    c.setSecure(false);\n    response.addCookie(c);\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-insecure-cookie"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_secure_cookie_is_not_reported() {
        let rules = rules_firing(
            "S.java",
            "class S {\n  void f(javax.servlet.http.HttpServletResponse response) {\n    javax.servlet.http.Cookie c = new javax.servlet.http.Cookie(\"sid\", \"x\");\n    c.setSecure(true);\n    c.setHttpOnly(true);\n    response.addCookie(c);\n  }\n}\n",
        );
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn a_request_chosen_session_key_is_reported() {
        let rules = rules_firing(
            "P.java",
            "class P {\n  void f(javax.servlet.http.HttpServletRequest request) {\n    request.getSession().setAttribute(request.getParameter(\"key\"), \"10340\");\n  }\n}\n",
        );
        assert!(
            rules.iter().any(|rule| rule == "java-trust-boundary"),
            "{rules:?}"
        );
    }

    #[test]
    fn a_request_value_under_a_fixed_key_is_not_reported() {
        // The Benchmark labels this vulnerable and oxAudit deliberately does
        // not report it. Storing a request value in the session under a key
        // the application chose is what every login form does; reporting it
        // costs 50 true positives there and would produce a rule nobody
        // leaves switched on, which is the same trade already made for
        // path traversal and SSRF.
        let rules = rules_firing(
            "P.java",
            "class P {\n  void f(javax.servlet.http.HttpServletRequest request) {\n    request.getSession().setAttribute(\"userId\", request.getParameter(\"id\"));\n  }\n}\n",
        );
        assert!(
            !rules.iter().any(|rule| rule == "java-trust-boundary"),
            "{rules:?}"
        );
    }
}

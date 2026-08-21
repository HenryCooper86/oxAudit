pub mod patterns;
pub mod secrets;

use std::collections::BTreeSet;
use std::path::Path;

use crate::findings::redaction;
use crate::fs_utils;
use crate::models::Finding;

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
    let secret_hits = secrets::scan_content(&content);
    let secret_values = secret_redaction_values(&secret_hits);

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
                observation_run_id: String::new(),
                resolved_by_run_id: None,
                fingerprint_version: 0,
                fingerprint: String::new(),
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
                    observation_run_id: String::new(),
                    resolved_by_run_id: None,
                    fingerprint_version: 0,
                    fingerprint: String::new(),
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
}

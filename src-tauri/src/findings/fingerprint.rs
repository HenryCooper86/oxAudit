use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::models::Finding;

pub use crate::findings::domain::FINGERPRINT_VERSION;

fn canonical_context(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .lines()
        .map(|line| {
            line.split_once(" │ ")
                .filter(|(gutter, _)| {
                    !gutter.trim().is_empty()
                        && gutter
                            .chars()
                            .all(|character| character == ' ' || character.is_ascii_digit())
                })
                .map_or(line, |(_, source)| source)
                .trim()
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

pub fn fingerprint_base(finding: &Finding) -> String {
    let fields = [
        FINGERPRINT_VERSION.to_string(),
        finding.category.clone(),
        finding.rule_id.clone(),
        finding.file_path.replace('\\', "/"),
        canonical_context(&finding.context),
    ];
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub fn assign_fingerprints(findings: &mut [Finding]) {
    let mut occurrences = HashMap::<String, usize>::new();
    for finding in findings {
        let base = fingerprint_base(finding);
        let occurrence = occurrences.entry(base.clone()).or_insert(0);
        finding.fingerprint_version = FINGERPRINT_VERSION;
        finding.fingerprint = if *occurrence == 0 {
            base
        } else {
            format!("{base}:{occurrence}")
        };
        *occurrence += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{assign_fingerprints, fingerprint_base, FINGERPRINT_VERSION};
    use crate::models::Finding;

    const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";

    fn finding(path: &str, line: usize, context: &str) -> Finding {
        Finding {
            id: format!("finding-{line}"),
            category: "secret".into(),
            rule_id: "generic-api-key".into(),
            rule_name: "Generic API Key / Secret".into(),
            severity: "high".into(),
            title: "Generic API Key / Secret".into(),
            description: "A credential was found.".into(),
            file_path: path.into(),
            line,
            column: 1,
            match_text: "token = [REDACTED]".into(),
            context: context.into(),
            language: "javascript".into(),
            cwe: None,
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: "Rotate it.".into(),
            entropy: Some(4.2),
            verified: None,
            analysis: Default::default(),
            observation_run_id: String::new(),
            resolved_by_run_id: None,
            fingerprint_version: 0,
            fingerprint: String::new(),
            scope: None,
            scope_reason: None,
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    #[test]
    fn fingerprint_survives_line_insertion_and_never_contains_secret_material() {
        let first = finding("src/auth.ts", 4, "const token = \"[REDACTED]\";");
        let shifted = finding("src/auth.ts", 40, "  const token = \"[REDACTED]\"; ");

        assert_eq!(fingerprint_base(&first), fingerprint_base(&shifted));
        assert!(!fingerprint_base(&first).contains(CANARY));
    }

    #[test]
    fn fingerprint_normalizes_path_separators_and_crlf() {
        let unix = finding(
            "src/auth.ts",
            4,
            "const token = \"[REDACTED]\";\nuse(token);",
        );
        let windows = finding(
            "src\\auth.ts",
            4,
            "  const token = \"[REDACTED]\";  \r\n use(token); ",
        );

        assert_eq!(fingerprint_base(&unix), fingerprint_base(&windows));
    }

    #[test]
    fn fingerprint_preserves_meaningful_internal_whitespace() {
        let first = finding("src/auth.ts", 4, "const token = \"[REDACTED]\";");
        let changed = finding("src/auth.ts", 4, "const  token = \"[REDACTED]\";");

        assert_ne!(fingerprint_base(&first), fingerprint_base(&changed));
    }

    #[test]
    fn fingerprint_changes_for_a_different_rule_or_path() {
        let original = finding("src/auth.ts", 4, "token = [REDACTED]");
        let mut different_rule = original.clone();
        different_rule.rule_id = "github-token".into();
        let different_path = finding("src/other.ts", 4, "token = [REDACTED]");

        assert_ne!(
            fingerprint_base(&original),
            fingerprint_base(&different_rule)
        );
        assert_ne!(
            fingerprint_base(&original),
            fingerprint_base(&different_path)
        );
    }

    #[test]
    fn duplicate_occurrences_receive_deterministic_suffixes() {
        let mut findings = vec![
            finding("src/auth.ts", 4, "token = [REDACTED]"),
            finding("src/auth.ts", 8, "token = [REDACTED]"),
            finding("src/auth.ts", 12, "token = [REDACTED]"),
        ];
        let base = fingerprint_base(&findings[0]);

        assign_fingerprints(&mut findings);

        assert_eq!(findings[0].fingerprint, base);
        assert_eq!(findings[1].fingerprint, format!("{base}:1"));
        assert_eq!(findings[2].fingerprint, format!("{base}:2"));
        assert!(findings
            .iter()
            .all(|finding| finding.fingerprint_version == FINGERPRINT_VERSION));
    }

    fn scanned_eval_finding(source: &str) -> Finding {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("auth.js");
        std::fs::write(&source_path, source).expect("javascript fixture");
        crate::scanners::scan_file_with_relative_path(&source_path, "src/auth.js", 64, false, true)
            .findings
            .into_iter()
            .find(|finding| finding.rule_id == "js-eval")
            .expect("js-eval finding")
    }

    #[test]
    fn scanner_context_fingerprint_survives_line_insertion_and_indentation() {
        let first = scanned_eval_finding(
            "header();\nbeforeOne();\nbeforeTwo();\neval(input);\nafterOne();\nafterTwo();\n",
        );
        let shifted = scanned_eval_finding(
            "inserted();\ninsertedAgain();\n  header();\n  beforeOne();\n  beforeTwo();\n  eval(input);\n  afterOne();\n  afterTwo();\n",
        );

        assert_ne!(first.context, shifted.context);
        assert_eq!(fingerprint_base(&first), fingerprint_base(&shifted));
    }

    #[test]
    fn scanner_context_fingerprint_preserves_internal_source_whitespace() {
        // The sink takes an identifier rather than a literal: a constant
        // argument is no longer a finding, and this test is about fingerprint
        // stability rather than about what eval detects. The whitespace that
        // must change the fingerprint sits on an adjacent line, inside the
        // context the fingerprint covers.
        let first = scanned_eval_finding(
            "beforeOne();\nconst label = \"alpha beta\";\neval(userInput);\nafterOne();\nafterTwo();\n",
        );
        let changed = scanned_eval_finding(
            "beforeOne();\nconst label = \"alpha  beta\";\neval(userInput);\nafterOne();\nafterTwo();\n",
        );

        assert_ne!(fingerprint_base(&first), fingerprint_base(&changed));
    }
}

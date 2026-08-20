pub const REDACTED: &str = "[REDACTED]";

pub fn redact_exact(text: &str, value: &str) -> String {
    if value.is_empty() {
        return text.to_owned();
    }
    text.replace(value, REDACTED)
}

#[cfg(test)]
mod tests {
    use super::redact_exact;

    const CANARY: &str = "oxaudit-secret-canary-7D4zP9q2";
    const OTHER_CANARY: &str = "oxaudit-second-canary-V8m3K1r6";
    const PRIVATE_KEY_CANARY: &str = "OXAUDITPRIVATEKEYCANARY7D4zP9q2";

    #[test]
    fn redaction_removes_the_exact_secret_from_match_and_context() {
        let source = format!("const token = \"{CANARY}\";\nuse(token);");
        let safe = redact_exact(&source, CANARY);

        assert!(!safe.contains(CANARY));
        assert_eq!(safe, "const token = \"[REDACTED]\";\nuse(token);");
    }

    #[test]
    fn redaction_with_an_empty_secret_leaves_text_unchanged() {
        assert_eq!(redact_exact("safe text", ""), "safe text");
    }

    #[test]
    fn every_secret_finding_is_redacted_before_serialization() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("credentials.txt");
        std::fs::write(
            &source_path,
            format!("const token = \"{CANARY}\";\nconst credential = \"{OTHER_CANARY}\";"),
        )
        .expect("secret fixture");

        let findings = crate::scanners::scan_file(directory.path(), &source_path, 64, true, false);
        assert!(!findings.is_empty(), "expected at least one secret finding");

        for finding in findings {
            let serialized = serde_json::to_string(&finding).expect("serializable finding");
            assert!(!serialized.contains(CANARY));
            assert!(!serialized.contains(OTHER_CANARY));
            assert!(serialized.contains("[REDACTED]"));
        }
    }

    #[test]
    fn long_multiline_secret_is_redacted_from_match_and_partial_context() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("private.pem");
        let payload = (0..6)
            .map(|index| format!("{PRIVATE_KEY_CANARY}{index}{PRIVATE_KEY_CANARY}"))
            .collect::<Vec<_>>()
            .join("\n");
        let source = format!("-----BEGIN PRIVATE KEY-----\n{payload}\n-----END PRIVATE KEY-----",);
        std::fs::write(&source_path, source).expect("private key fixture");

        let findings = crate::scanners::scan_file(directory.path(), &source_path, 64, true, false);
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "private-key")
            .expect("private-key finding");
        let serialized = serde_json::to_string(finding).expect("serializable finding");

        assert!(!serialized.contains(PRIVATE_KEY_CANARY));
        assert!(serialized.contains("[REDACTED]"));
    }

    #[test]
    fn overlapping_secret_values_are_redacted_longest_first() {
        const PREFIX: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
        const SUFFIX: &str = "OverlapSuffixCanary9Z8Y7X6";
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("credentials.json");
        std::fs::write(&source_path, format!("{{\"token\":\"{PREFIX}{SUFFIX}\"}}"))
            .expect("overlapping secret fixture");

        let findings = crate::scanners::scan_file(directory.path(), &source_path, 64, true, false);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "generic-api-key"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "json-credential"));

        for finding in findings {
            let serialized = serde_json::to_string(&finding).expect("serializable finding");
            assert!(!serialized.contains(SUFFIX));
            assert!(serialized.contains("[REDACTED]"));
        }
    }
}

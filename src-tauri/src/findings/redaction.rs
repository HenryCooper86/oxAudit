pub const REDACTED: &str = "[REDACTED]";

pub fn redact_exact_value(text: &str, value: &str) -> String {
    text.replace(value, REDACTED)
}

#[cfg(test)]
mod tests {
    const RAW_SECRET_CANARY: &str = "ghp_OXAUDITRAWSECRETCANARYVALUE123456789";

    #[test]
    fn secret_findings_redact_raw_values_before_serialization() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source_path = directory.path().join("credentials.txt");
        std::fs::write(
            &source_path,
            format!("token = {RAW_SECRET_CANARY}\\nuse this only for the test"),
        )
        .expect("secret fixture");

        let finding = crate::scanners::scan_file(directory.path(), &source_path, 64, true, false)
            .into_iter()
            .find(|finding| finding.category == "secret")
            .expect("secret finding");
        let serialized = serde_json::to_string(&finding).expect("serializable finding");

        assert!(!serialized.contains(RAW_SECRET_CANARY));
        assert!(serialized.contains("[REDACTED]"));
    }
}

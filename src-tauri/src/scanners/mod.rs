pub mod patterns;
pub mod secrets;

use std::collections::HashMap;
use std::path::Path;

use crate::fs_utils;
use crate::models::Finding;

/// Max matches kept per rule per file (guards against pathological noise).
const MAX_MATCHES_PER_RULE: usize = 25;

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
}

/// Scan a canonical contained file while preserving its caller-validated
/// lexical identity in findings.
pub fn scan_file_with_relative_path(
    path: &Path,
    relative_path: &str,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
) -> Vec<Finding> {
    let max_bytes = (max_file_size_kb as u64).saturating_mul(1024);
    let content = match fs_utils::read_text_file(path, max_bytes) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let starts = fs_utils::line_starts(&content);
    let rel = relative_path.to_string();
    let mut findings = Vec::new();

    if scan_secrets {
        let hits = secrets::scan_content(&content);
        let mut counts: HashMap<usize, usize> = HashMap::new();
        for hit in hits {
            let rule = &secrets::SECRET_RULES[hit.rule_index];
            let count = counts.entry(hit.rule_index).or_insert(0);
            if *count >= MAX_MATCHES_PER_RULE {
                continue;
            }
            *count += 1;
            let (line, col) = fs_utils::line_col(&starts, hit.offset);
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
                match_text: hit.match_text.clone(),
                context: fs_utils::context_lines(&content, &starts, line - 1, 2),
                language: String::new(),
                cwe: None,
                recommendation: rule.recommendation.into(),
                entropy: Some(hit.entropy),
                verified: None,
            });
        }
    }

    if scan_vulnerabilities {
        if let Some(lang) = fs_utils::detect_language(path) {
            let hits = patterns::scan_content(&content, lang);
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for hit in hits {
                let rule = &patterns::SOURCE_RULES[hit.rule_index];
                let count = counts.entry(hit.rule_index).or_insert(0);
                if *count >= MAX_MATCHES_PER_RULE {
                    continue;
                }
                *count += 1;
                let (line, col) = fs_utils::line_col(&starts, hit.offset);
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
                    match_text: hit.match_text.clone(),
                    context: fs_utils::context_lines(&content, &starts, line - 1, 2),
                    language: lang.into(),
                    cwe: Some(rule.cwe.into()),
                    recommendation: rule.recommendation.into(),
                    entropy: None,
                    verified: None,
                });
            }
        }
    }

    findings
}

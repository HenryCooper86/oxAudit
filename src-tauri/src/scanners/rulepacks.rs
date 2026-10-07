//! Applying installed rule packs to a working-tree scan.
//!
//! A pack that only validated was a promise; this module is the delivery.
//! Enabled packs' text-engine rules (`sourceRegex`, `secretRegex`) run
//! beside the built-in rules over the same file content, under the same
//! budgets and redaction rules, and produce findings a reviewer treats no
//! differently — except that each carries its pack's identity in its rule
//! id, so pack-sourced findings are always distinguishable from built-in
//! ones in every list, export, and report.
//!
//! Stated limits, deliberately: only the two text engines apply today.
//! `dependency`, `binary*`, and `semantic` engine rules validate and show
//! in the Rule Library but do not yet run — wiring each is its own project,
//! and a rule that silently never fires is worse than one visibly marked
//! not-yet-applied. Platform and architecture scope guards do not apply to
//! text scans (a source file has neither); language and file-extension
//! guards do.

use std::sync::Arc;

use oxaudit_domain::Severity;
use oxaudit_scanners::{CompiledRulePack, RuleEngine};

use crate::fs_utils;
use crate::models::Finding;

/// The compiled packs one scan runs, shared across the parallel file walk.
/// Empty for every scan path that predates installed packs.
#[derive(Clone, Default)]
pub struct AppliedRulePacks {
    packs: Vec<Arc<CompiledRulePack>>,
    installed_ids: std::collections::BTreeSet<String>,
}

impl AppliedRulePacks {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_compiled(packs: Vec<Arc<CompiledRulePack>>) -> Self {
        Self::from_sources(packs, Vec::new())
    }

    pub fn from_sources(
        mut installed: Vec<Arc<CompiledRulePack>>,
        one_off: Vec<Arc<CompiledRulePack>>,
    ) -> Self {
        let installed_ids = installed
            .iter()
            .map(|pack| pack.metadata().id.to_string())
            .collect();
        installed.extend(one_off);
        Self {
            packs: installed,
            installed_ids,
        }
    }

    pub fn installed_ids(&self) -> &std::collections::BTreeSet<String> {
        &self.installed_ids
    }

    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    /// The pack identities a run records, in stable order.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .packs
            .iter()
            .map(|pack| pack.metadata().id.to_string())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn snapshot_hashes(
        &self,
    ) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
        let mut hashes =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        for pack in &self.packs {
            hashes
                .entry(pack.metadata().id.to_string())
                .or_default()
                .insert(pack.metadata().content_sha256.clone());
        }
        hashes
    }

    /// Run every applicable rule over one file's content.
    ///
    /// `spans` is the same parsed grammar the built-in secret engine uses:
    /// a pack's `secretRegex` rule is held to the identical standard about
    /// where a credential match counts, so packs cannot smuggle in matches
    /// the built-in engines would suppress as non-code.
    pub fn scan(
        &self,
        content: &str,
        relative_path: &str,
        detected_language: &str,
        spans: &dyn Fn(usize) -> bool,
        scan_secrets: bool,
        scan_vulnerabilities: bool,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        if self.packs.is_empty() {
            return findings;
        }
        let starts = fs_utils::line_starts(content);
        let extension = relative_path.rsplit('.').next().unwrap_or("");
        for pack in &self.packs {
            for (rule_index, rule) in pack.rules().iter().enumerate() {
                let applies = match rule.engine {
                    RuleEngine::SourceRegex => scan_vulnerabilities,
                    RuleEngine::SecretRegex => scan_secrets,
                    _ => false,
                };
                if !applies {
                    continue;
                }
                if !scope_allows(&rule.scope, detected_language, extension) {
                    continue;
                }
                for hit in pack.scan_rule(rule_index, content) {
                    if rule.engine == RuleEngine::SecretRegex && !spans(hit.start) {
                        continue;
                    }
                    let Some(finding) = pack_finding(
                        pack,
                        rule,
                        &hit,
                        content,
                        &starts,
                        relative_path,
                        detected_language,
                    ) else {
                        continue;
                    };
                    findings.push(finding);
                }
            }
        }
        findings
    }
}

fn scope_allows(
    scope: &oxaudit_scanners::RuleScope,
    detected_language: &str,
    extension: &str,
) -> bool {
    if !scope.languages.is_empty()
        && !scope
            .languages
            .iter()
            .any(|language| language.eq_ignore_ascii_case(detected_language))
    {
        return false;
    }
    if !scope.file_extensions.is_empty()
        && !scope
            .file_extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    {
        return false;
    }
    true
}

fn severity_string(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn pack_finding(
    pack: &CompiledRulePack,
    rule: &oxaudit_scanners::RuleDefinition,
    hit: &oxaudit_scanners::RuleMatch,
    content: &str,
    starts: &[usize],
    relative_path: &str,
    detected_language: &str,
) -> Option<Finding> {
    let (line, column) = fs_utils::line_col(starts, hit.start);
    let match_slice = content.get(hit.start..hit.end)?;
    // A secret-engine capture is credential material: redact it from the
    // evidence surfaces exactly as the built-in secret engine does.
    let (match_text, context) = if rule.engine == RuleEngine::SecretRegex {
        let value = hit
            .captured_value
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(match_slice);
        (
            crate::scanners::redact_secret_value(match_slice, value),
            crate::scanners::redact_secret_value(
                &fs_utils::context_lines(content, starts, line - 1, 2),
                value,
            ),
        )
    } else {
        (
            crate::scanners::truncate_match(match_slice),
            fs_utils::context_lines(content, starts, line - 1, 2),
        )
    };
    Some(Finding {
        id: uuid::Uuid::new_v4().to_string(),
        category: if rule.engine == RuleEngine::SecretRegex {
            "secret".into()
        } else {
            "vulnerability".into()
        },
        // The pack-qualified rule id keeps pack findings distinguishable
        // from built-in ones and collision-free across packs.
        rule_id: format!("{}/{}", pack.metadata().id, rule.id),
        rule_name: rule.title.clone(),
        severity: severity_string(rule.severity).into(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        file_path: relative_path.to_string(),
        line,
        column,
        match_text,
        context,
        language: detected_language.to_string(),
        cwe: rule
            .classifications
            .iter()
            .find(|class| {
                let upper = class.to_ascii_uppercase();
                upper.starts_with("CWE-") && upper[4..].chars().all(|c| c.is_ascii_digit())
            })
            .cloned(),
        cwe_exploited: false,
        cwe_exploited_count: 0,
        recommendation: rule.recommendation.clone(),
        entropy: None,
        verified: None,
        // A pack rule matched raw text; no grammar qualified it beyond the
        // same span gates the built-ins pass.
        analysis: Default::default(),
        analysis_gates: Vec::new(),
        observation_run_id: String::new(),
        resolved_by_run_id: None,
        fingerprint_version: 0,
        fingerprint: String::new(),
        in_test_region: false,
        scope: None,
        scope_reason: None,
        review: None,
        review_history: Vec::new(),
        diff_status: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::scan_file_in_project_with_packs;
    use oxaudit_domain::CreationMethod;
    use oxaudit_scanners::{
        FixtureExpectation, RuleDefinition, RuleEngine, RulePack, RulePackMetadata, RuleScope,
    };

    fn provenance(hash: &str) -> oxaudit_domain::Provenance {
        oxaudit_domain::Provenance {
            authors: vec!["oxAudit contributors".into()],
            source: "independent fixture".into(),
            license: "Apache-2.0".into(),
            creation_method: CreationMethod::IndependentlyDerived,
            content_sha256: hash.into(),
        }
    }

    fn fixture(id: &str) -> FixtureExpectation {
        FixtureExpectation {
            id: id.into(),
            path: format!("{id}.txt"),
            sha256: "a".repeat(64),
            expected_values: Vec::new(),
        }
    }

    fn rule(engine: RuleEngine, pattern: &str) -> RuleDefinition {
        RuleDefinition {
            id: match engine {
                RuleEngine::SourceRegex => "source.eval".into(),
                RuleEngine::SecretRegex => "secret.custom".into(),
                _ => "other.rule".into(),
            },
            version: "1".into(),
            title: "Pack rule".into(),
            description: "A pack-sourced rule match.".into(),
            recommendation: "Do the pack's remediation.".into(),
            engine,
            severity: Severity::High,
            scope: RuleScope {
                languages: vec!["javascript".into()],
                platforms: Vec::new(),
                architectures: Vec::new(),
                file_extensions: Vec::new(),
            },
            pattern: pattern.into(),
            classifications: vec!["CWE-95".into()],
            provenance: provenance(&"b".repeat(64)),
            positive_fixtures: vec![fixture("positive")],
            negative_fixtures: vec![fixture("negative")],
        }
    }

    fn compiled_pack(rules: Vec<RuleDefinition>) -> Arc<CompiledRulePack> {
        let hash = RulePack::computed_content_sha256(&rules).unwrap();
        let pack = RulePack {
            pack: RulePackMetadata {
                schema_version: 1,
                id: oxaudit_domain::RulePackId::parse("rulepack.test").unwrap(),
                name: "Test rules".into(),
                version: "1.0.0".into(),
                minimum_oxaudit_version: "0.1.0".into(),
                content_sha256: hash.clone(),
                provenance: provenance(&hash),
            },
            rules,
        };
        Arc::new(CompiledRulePack::compile(pack).expect("pack compiles"))
    }

    fn scan_js(content: &str, packs: &AppliedRulePacks) -> Vec<crate::models::Finding> {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("app.js");
        std::fs::write(&path, content).expect("fixture");
        scan_file_in_project_with_packs(
            &path,
            "app.js",
            256,
            true,
            true,
            &crate::scanners::config_values::ProjectConfig::default(),
            packs,
        )
        .findings
    }

    #[test]
    fn a_pack_source_rule_fires_with_pack_qualified_identity() {
        let packs = AppliedRulePacks::from_compiled(vec![compiled_pack(vec![rule(
            RuleEngine::SourceRegex,
            r"dangerousEval\(([^)]+)\)",
        )])]);
        let findings = scan_js("function run() { dangerousEval(input); }\n", &packs);
        let pack_finding = findings
            .iter()
            .find(|finding| finding.rule_id == "rulepack.test/source.eval")
            .expect("pack rule fired");
        assert_eq!(pack_finding.category, "vulnerability");
        assert_eq!(pack_finding.severity, "high");
        assert_eq!(pack_finding.cwe.as_deref(), Some("CWE-95"));
        assert_eq!(
            pack_finding.recommendation, "Do the pack's remediation.",
            "pack findings carry their own remediation"
        );
        assert_eq!(pack_finding.analysis, crate::models::AnalysisTier::Text);
    }

    #[test]
    fn a_pack_secret_rule_redacts_its_capture_like_a_built_in_secret() {
        let packs = AppliedRulePacks::from_compiled(vec![compiled_pack(vec![rule(
            RuleEngine::SecretRegex,
            r"custom-token-([A-Za-z0-9]{16})",
        )])]);
        let findings = scan_js("const t = \"custom-token-ABCDEFGHIJKLMNOP\";\n", &packs);
        let pack_finding = findings
            .iter()
            .find(|finding| finding.rule_id == "rulepack.test/secret.custom")
            .expect("secret rule fired");
        assert_eq!(pack_finding.category, "secret");
        assert!(
            !pack_finding.match_text.contains("ABCDEFGHIJKLMNOP"),
            "the captured credential is redacted from the evidence"
        );
        assert!(pack_finding.match_text.contains("[REDACTED]"));
        assert!(!pack_finding.context.contains("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn language_scope_gates_a_pack_rule_to_matching_files() {
        let packs = AppliedRulePacks::from_compiled(vec![compiled_pack(vec![rule(
            RuleEngine::SourceRegex,
            r"dangerousEval\(([^)]+)\)",
        )])]);
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("app.py");
        std::fs::write(&path, "dangerousEval(input)\n").expect("fixture");
        let outcome = scan_file_in_project_with_packs(
            &path,
            "app.py",
            256,
            true,
            true,
            &crate::scanners::config_values::ProjectConfig::default(),
            &packs,
        );
        assert!(
            !outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id.starts_with("rulepack.test/")),
            "a javascript-scoped rule must not fire on a python file"
        );
    }

    #[test]
    fn engines_without_an_apply_path_never_fire_silently() {
        let packs = AppliedRulePacks::from_compiled(vec![compiled_pack(vec![rule(
            RuleEngine::Dependency,
            "anything",
        )])]);
        let findings = scan_js("dangerousEval(input)\n", &packs);
        assert!(findings.is_empty(), "dependency rules do not apply yet");
    }

    #[test]
    fn an_empty_pack_set_leaves_the_builtin_scan_untouched() {
        let empty = AppliedRulePacks::empty();
        assert!(empty.ids().is_empty());
        let findings = scan_js("dangerousEval(input)\n", &empty);
        assert!(
            findings.is_empty(),
            "no built-in rule fires on this fixture; the empty pack set adds nothing"
        );
    }

    #[test]
    fn pack_ids_are_reported_in_stable_unique_order() {
        let packs = AppliedRulePacks::from_compiled(vec![
            compiled_pack(vec![rule(RuleEngine::SourceRegex, "a")]),
            compiled_pack(vec![rule(RuleEngine::SourceRegex, "b")]),
        ]);
        // Same id twice (two compiled snapshots) collapses to one identity.
        assert_eq!(packs.ids(), vec!["rulepack.test".to_string()]);
    }
}

use std::collections::BTreeSet;
use std::path::Component as PathComponent;
use std::path::Path;

use oxaudit_domain::{Provenance, RulePackId, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const RULE_PACK_SCHEMA_VERSION: u32 = 1;
const MAX_RULES: usize = 10_000;
const MAX_PATTERN_BYTES: usize = 8_192;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_FIXTURE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEngine {
    SourceRegex,
    SecretRegex,
    Dependency,
    BinaryString,
    BinaryBytes,
    Semantic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleScope {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub file_extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureExpectation {
    pub id: String,
    pub path: String,
    pub sha256: String,
    #[serde(default)]
    pub expected_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDefinition {
    pub id: String,
    pub version: String,
    pub title: String,
    pub description: String,
    /// What to do about a match, carried into the finding so a pack-sourced
    /// finding is as actionable as a built-in one.
    pub recommendation: String,
    pub engine: RuleEngine,
    pub severity: Severity,
    pub scope: RuleScope,
    pub pattern: String,
    #[serde(default)]
    pub classifications: Vec<String>,
    pub provenance: Provenance,
    pub positive_fixtures: Vec<FixtureExpectation>,
    pub negative_fixtures: Vec<FixtureExpectation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePackMetadata {
    pub schema_version: u32,
    pub id: RulePackId,
    pub name: String,
    pub version: String,
    pub minimum_oxaudit_version: String,
    pub content_sha256: String,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePack {
    pub pack: RulePackMetadata,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RulePackError {
    #[error("rule pack TOML is invalid: {0}")]
    Parse(String),
    #[error("unsupported rule pack schema version {0}")]
    Schema(u32),
    #[error("rule pack has no rules")]
    Empty,
    #[error("rule pack exceeds the {MAX_RULES} rule limit")]
    TooManyRules,
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    #[error("rule {rule_id} has invalid field {field}: {message}")]
    InvalidRule {
        rule_id: String,
        field: &'static str,
        message: String,
    },
    #[error("rule pack content hash does not match its declarations")]
    ContentHashMismatch,
    #[error("rule pack provenance is invalid: {0}")]
    Provenance(String),
    #[error("fixture {fixture_id} does not exist at {path}")]
    MissingFixture { fixture_id: String, path: String },
    #[error("fixture {fixture_id} content hash does not match")]
    FixtureHashMismatch { fixture_id: String },
    #[error("fixture {fixture_id} path is not contained by the rule pack")]
    UnsafeFixturePath { fixture_id: String },
    #[error("fixture {fixture_id} exceeds the {MAX_FIXTURE_BYTES}-byte limit")]
    FixtureTooLarge { fixture_id: String },
    #[error("rule-pack fixtures exceed the {MAX_TOTAL_FIXTURE_BYTES}-byte total limit")]
    FixturesTooLarge,
}

impl RulePack {
    pub fn parse_toml(input: &str) -> Result<Self, RulePackError> {
        toml::from_str(input).map_err(|error| RulePackError::Parse(error.to_string()))
    }

    pub fn computed_content_sha256(rules: &[RuleDefinition]) -> Result<String, RulePackError> {
        #[derive(Serialize)]
        struct CanonicalRules<'a> {
            rule: &'a [RuleDefinition],
        }

        let canonical = toml::to_string(&CanonicalRules { rule: rules })
            .map_err(|error| RulePackError::Parse(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }

    pub fn validate(&self) -> Result<(), RulePackError> {
        if self.pack.schema_version != RULE_PACK_SCHEMA_VERSION {
            return Err(RulePackError::Schema(self.pack.schema_version));
        }
        if self.rules.is_empty() {
            return Err(RulePackError::Empty);
        }
        if self.rules.len() > MAX_RULES {
            return Err(RulePackError::TooManyRules);
        }
        self.pack
            .provenance
            .validate()
            .map_err(|error| RulePackError::Provenance(error.to_string()))?;
        if self.pack.content_sha256 != Self::computed_content_sha256(&self.rules)? {
            return Err(RulePackError::ContentHashMismatch);
        }

        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            if !ids.insert(rule.id.clone()) {
                return Err(RulePackError::DuplicateRule(rule.id.clone()));
            }
            validate_rule(rule)?;
        }
        Ok(())
    }

    pub fn validate_fixture_files(&self, root: &Path) -> Result<(), RulePackError> {
        let canonical_root = root
            .canonicalize()
            .map_err(|_| RulePackError::MissingFixture {
                fixture_id: "rule-pack-root".into(),
                path: root.display().to_string(),
            })?;
        let mut total_bytes = 0_u64;
        for fixture in self.rules.iter().flat_map(|rule| {
            rule.positive_fixtures
                .iter()
                .chain(rule.negative_fixtures.iter())
        }) {
            let relative = Path::new(&fixture.path);
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        PathComponent::ParentDir
                            | PathComponent::RootDir
                            | PathComponent::Prefix(_)
                    )
                })
            {
                return Err(RulePackError::UnsafeFixturePath {
                    fixture_id: fixture.id.clone(),
                });
            }
            let path = canonical_root.join(relative);
            let canonical_path =
                path.canonicalize()
                    .map_err(|_| RulePackError::MissingFixture {
                        fixture_id: fixture.id.clone(),
                        path: fixture.path.clone(),
                    })?;
            if !canonical_path.starts_with(&canonical_root) {
                return Err(RulePackError::UnsafeFixturePath {
                    fixture_id: fixture.id.clone(),
                });
            }
            let size = canonical_path
                .metadata()
                .map_err(|_| RulePackError::MissingFixture {
                    fixture_id: fixture.id.clone(),
                    path: fixture.path.clone(),
                })?
                .len();
            if size > MAX_FIXTURE_BYTES {
                return Err(RulePackError::FixtureTooLarge {
                    fixture_id: fixture.id.clone(),
                });
            }
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or(RulePackError::FixturesTooLarge)?;
            if total_bytes > MAX_TOTAL_FIXTURE_BYTES {
                return Err(RulePackError::FixturesTooLarge);
            }
            let bytes =
                std::fs::read(&canonical_path).map_err(|_| RulePackError::MissingFixture {
                    fixture_id: fixture.id.clone(),
                    path: fixture.path.clone(),
                })?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != fixture.sha256.to_ascii_lowercase() {
                return Err(RulePackError::FixtureHashMismatch {
                    fixture_id: fixture.id.clone(),
                });
            }
        }
        Ok(())
    }
}

fn validate_rule(rule: &RuleDefinition) -> Result<(), RulePackError> {
    for (field, value) in [
        ("id", rule.id.as_str()),
        ("version", rule.version.as_str()),
        ("title", rule.title.as_str()),
        ("description", rule.description.as_str()),
        ("recommendation", rule.recommendation.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(RulePackError::InvalidRule {
                rule_id: rule.id.clone(),
                field,
                message: "cannot be empty".into(),
            });
        }
    }
    if rule.pattern.len() > MAX_PATTERN_BYTES {
        return Err(RulePackError::InvalidRule {
            rule_id: rule.id.clone(),
            field: "pattern",
            message: format!("exceeds {MAX_PATTERN_BYTES} bytes"),
        });
    }
    Regex::new(&rule.pattern).map_err(|error| RulePackError::InvalidRule {
        rule_id: rule.id.clone(),
        field: "pattern",
        message: error.to_string(),
    })?;
    if rule.positive_fixtures.is_empty() || rule.negative_fixtures.is_empty() {
        return Err(RulePackError::InvalidRule {
            rule_id: rule.id.clone(),
            field: "fixtures",
            message: "at least one positive and one negative fixture are required".into(),
        });
    }
    rule.provenance
        .validate()
        .map_err(|error| RulePackError::InvalidRule {
            rule_id: rule.id.clone(),
            field: "provenance",
            message: error.to_string(),
        })?;
    for fixture in rule
        .positive_fixtures
        .iter()
        .chain(rule.negative_fixtures.iter())
    {
        if fixture.id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || fixture.sha256.len() != 64
            || !fixture.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RulePackError::InvalidRule {
                rule_id: rule.id.clone(),
                field: "fixtures",
                message: "fixture id/path and a 64-character SHA-256 are required".into(),
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct CompiledRulePack {
    pack: RulePack,
    regexes: Vec<Regex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: String,
    pub start: usize,
    pub end: usize,
    pub captured_value: Option<String>,
}

impl CompiledRulePack {
    pub fn compile(pack: RulePack) -> Result<Self, RulePackError> {
        pack.validate()?;
        let regexes = pack
            .rules
            .iter()
            .map(|rule| {
                Regex::new(&rule.pattern).map_err(|error| RulePackError::InvalidRule {
                    rule_id: rule.id.clone(),
                    field: "pattern",
                    message: error.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { pack, regexes })
    }

    pub fn metadata(&self) -> &RulePackMetadata {
        &self.pack.pack
    }

    /// The pack's rule definitions, in authored order.
    pub fn rules(&self) -> &[RuleDefinition] {
        &self.pack.rules
    }

    /// Run one rule (by index into [`Self::rules`]) over text. Callers use
    /// this when they have already decided the rule applies — scope gates,
    /// engine selection, and span filtering live with the caller because
    /// only the caller knows the scan's context.
    pub fn scan_rule(&self, rule_index: usize, text: &str) -> Vec<RuleMatch> {
        let Some(rule) = self.pack.rules.get(rule_index) else {
            return Vec::new();
        };
        let Some(regex) = self.regexes.get(rule_index) else {
            return Vec::new();
        };
        regex
            .captures_iter(text)
            .filter_map(move |captures| {
                let matched = captures.get(0)?;
                Some(RuleMatch {
                    rule_id: rule.id.clone(),
                    start: matched.start(),
                    end: matched.end(),
                    captured_value: captures.get(1).map(|value| value.as_str().to_string()),
                })
            })
            .collect()
    }

    pub fn scan_text(&self, engine: RuleEngine, text: &str) -> Vec<RuleMatch> {
        self.pack
            .rules
            .iter()
            .zip(&self.regexes)
            .filter(|(rule, _)| rule.engine == engine)
            .flat_map(|(rule, regex)| {
                regex.captures_iter(text).filter_map(move |captures| {
                    let matched = captures.get(0)?;
                    Some(RuleMatch {
                        rule_id: rule.id.clone(),
                        start: matched.start(),
                        end: matched.end(),
                        captured_value: captures.get(1).map(|value| value.as_str().to_string()),
                    })
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use oxaudit_domain::CreationMethod;

    use super::*;

    fn provenance(hash: &str) -> Provenance {
        Provenance {
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

    fn rule() -> RuleDefinition {
        RuleDefinition {
            id: "source.eval".into(),
            version: "1".into(),
            title: "Dynamic evaluation".into(),
            description: "Finds eval calls".into(),
            recommendation: "Avoid eval on dynamic input.".into(),
            engine: RuleEngine::SourceRegex,
            severity: Severity::High,
            scope: RuleScope {
                languages: vec!["javascript".into()],
                platforms: Vec::new(),
                architectures: Vec::new(),
                file_extensions: vec!["js".into()],
            },
            pattern: r"eval\(([^)]+)\)".into(),
            classifications: vec!["CWE-95".into()],
            provenance: provenance(&"b".repeat(64)),
            positive_fixtures: vec![fixture("positive")],
            negative_fixtures: vec![fixture("negative")],
        }
    }

    fn pack(mut rules: Vec<RuleDefinition>) -> RulePack {
        let hash = RulePack::computed_content_sha256(&rules).unwrap();
        RulePack {
            pack: RulePackMetadata {
                schema_version: 1,
                id: RulePackId::parse("rulepack.test").unwrap(),
                name: "Test rules".into(),
                version: "1.0.0".into(),
                minimum_oxaudit_version: "0.1.0".into(),
                content_sha256: hash.clone(),
                provenance: provenance(&hash),
            },
            rules: std::mem::take(&mut rules),
        }
    }

    #[test]
    fn valid_pack_compiles_and_matches() {
        let compiled = CompiledRulePack::compile(pack(vec![rule()])).unwrap();
        let hits = compiled.scan_text(RuleEngine::SourceRegex, "eval(userInput)");
        assert_eq!(hits[0].captured_value.as_deref(), Some("userInput"));
    }

    #[test]
    fn missing_negative_fixture_is_rejected() {
        let mut rule = rule();
        rule.negative_fixtures.clear();
        let error = pack(vec![rule]).validate().unwrap_err();
        assert!(matches!(
            error,
            RulePackError::InvalidRule {
                field: "fixtures",
                ..
            }
        ));
    }

    #[test]
    fn modified_rules_invalidate_the_pack_hash() {
        let mut pack = pack(vec![rule()]);
        pack.rules[0].pattern = "changed".into();
        assert_eq!(pack.validate(), Err(RulePackError::ContentHashMismatch));
    }

    #[test]
    fn fixture_validation_rejects_parent_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut definition = rule();
        definition.positive_fixtures[0].path = "../outside.txt".into();
        let pack = pack(vec![definition]);

        assert_eq!(
            pack.validate_fixture_files(root.path()),
            Err(RulePackError::UnsafeFixturePath {
                fixture_id: "positive".into()
            })
        );
    }
}

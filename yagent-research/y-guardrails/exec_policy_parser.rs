//! Parser for exec policy files.
//!
//! Policy files use a tiny declarative DSL (see [`crate::exec_policy::syntax`])
//! with a single supported call:
//!
//! - `prefix_rule(pattern, decision, match, not_match, justification)`
//!
//! Example policy file:
//!
//! ```text
//! prefix_rule(
//!     pattern = ["git", ["push", "commit"]],
//!     decision = "ask",
//!     match = [["git", "push"]],
//!     not_match = [["git", "status"]],
//!     justification = "review before push or commit",
//! )
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use crate::exec_policy::decision::ExecDecision;
use crate::exec_policy::error::{ExecPolicyError, ExecPolicyResult};
use crate::exec_policy::policy::{validate_match_examples, validate_not_match_examples, Policy};
use crate::exec_policy::rule::{PatternToken, PrefixPattern, PrefixRule, RuleRef};
use crate::exec_policy::syntax::{parse_calls, PolicyCall, PolicyValue};

/// Parses policy files into a [`Policy`].
pub struct PolicyParser {
    builder: PolicyBuilder,
}

impl Default for PolicyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyParser {
    /// Create a new empty parser.
    pub fn new() -> Self {
        Self {
            builder: PolicyBuilder::new(),
        }
    }

    /// Parse a policy file's contents.
    ///
    /// `policy_identifier` is used for error messages (typically the file path).
    /// May be called multiple times; rules accumulate.
    pub fn parse(
        &mut self,
        policy_identifier: &str,
        policy_file_contents: &str,
    ) -> ExecPolicyResult<()> {
        let pending_validation_count = self.builder.pending_example_validations.len();
        let calls =
            parse_calls(policy_file_contents).map_err(|source| ExecPolicyError::Syntax {
                policy: policy_identifier.to_string(),
                line: source.line,
                message: source.message,
            })?;
        for call in calls {
            let location = format!("{policy_identifier}:{}", call.line);
            apply_prefix_rule(&mut self.builder, call, &location)
                .map_err(attach_location(Some(&location)))?;
        }
        self.builder
            .validate_pending_examples_from(pending_validation_count)?;
        Ok(())
    }

    /// Consume the parser and return the built [`Policy`].
    pub fn build(self) -> Policy {
        self.builder.build()
    }
}

// -----------------------------------------------------------------------
// Rule construction
// -----------------------------------------------------------------------

/// Define a prefix-based command approval rule from a parsed call.
///
/// `pattern` is a list of tokens. The first token is fixed (the command name);
/// subsequent tokens are either a string (exact match) or a list of strings
/// (alternatives). `decision` defaults to `"allow"`. `match` and `not_match`
/// are example commands validated at parse time.
fn apply_prefix_rule(
    builder: &mut PolicyBuilder,
    call: PolicyCall,
    location: &str,
) -> ExecPolicyResult<()> {
    if call.name != "prefix_rule" {
        return Err(ExecPolicyError::InvalidRule(format!(
            "unsupported policy function `{}`",
            call.name
        )));
    }

    let mut pattern: Option<PolicyValue> = None;
    let mut decision_raw: Option<String> = None;
    let mut matches_raw: Option<PolicyValue> = None;
    let mut not_matches_raw: Option<PolicyValue> = None;
    let mut justification: Option<String> = None;

    for (key, value) in call.args {
        match key.as_str() {
            "pattern" => pattern = Some(value),
            "match" => matches_raw = Some(value),
            "not_match" => not_matches_raw = Some(value),
            "decision" => decision_raw = Some(expect_string(&value, "decision")?.to_string()),
            "justification" => {
                justification = Some(expect_string(&value, "justification")?.to_string());
            }
            other => {
                return Err(ExecPolicyError::InvalidRule(format!(
                    "unsupported prefix_rule argument `{other}`"
                )));
            }
        }
    }

    let decision = match decision_raw {
        Some(raw) => ExecDecision::parse(&raw)?,
        None => ExecDecision::Allow,
    };

    let justification = match justification {
        Some(raw) if raw.trim().is_empty() => {
            return Err(ExecPolicyError::InvalidRule(
                "prefix_rule justification cannot be empty".to_string(),
            ));
        }
        other => other,
    };

    let pattern = pattern.ok_or_else(|| {
        ExecPolicyError::InvalidRule("prefix_rule requires a `pattern` argument".to_string())
    })?;
    let pattern_tokens = parse_pattern(&pattern)?;

    let matches = match matches_raw {
        Some(value) => parse_examples(&value, "match")?,
        None => Vec::new(),
    };
    let not_matches = match not_matches_raw {
        Some(value) => parse_examples(&value, "not_match")?,
        None => Vec::new(),
    };

    let (first_token, remaining_tokens) = pattern_tokens
        .split_first()
        .ok_or_else(|| ExecPolicyError::InvalidPattern("pattern cannot be empty".to_string()))?;

    let rest: Arc<[PatternToken]> = remaining_tokens.to_vec().into();

    let rules: Vec<RuleRef> = first_token
        .alternatives()
        .iter()
        .map(|head| {
            Arc::new(PrefixRule {
                pattern: PrefixPattern {
                    first: Arc::from(head.as_str()),
                    rest: Arc::clone(&rest),
                },
                decision,
                justification: justification.clone(),
            }) as RuleRef
        })
        .collect();

    builder.add_pending_example_validation(
        rules.clone(),
        matches,
        not_matches,
        Some(location.to_string()),
    );
    for rule in rules {
        builder.add_rule(rule);
    }
    Ok(())
}

fn expect_string<'a>(value: &'a PolicyValue, field: &str) -> ExecPolicyResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| ExecPolicyError::InvalidRule(format!("{field} must be a string")))
}

fn parse_pattern(pattern: &PolicyValue) -> ExecPolicyResult<Vec<PatternToken>> {
    let items = pattern
        .as_list()
        .ok_or_else(|| ExecPolicyError::InvalidPattern("pattern must be a list".to_string()))?;
    let tokens: Vec<PatternToken> = items
        .iter()
        .map(parse_pattern_token)
        .collect::<ExecPolicyResult<_>>()?;
    if tokens.is_empty() {
        return Err(ExecPolicyError::InvalidPattern(
            "pattern cannot be empty".to_string(),
        ));
    }
    Ok(tokens)
}

fn parse_pattern_token(value: &PolicyValue) -> ExecPolicyResult<PatternToken> {
    match value {
        PolicyValue::Str(s) => Ok(PatternToken::Single(s.clone())),
        PolicyValue::List(items) => {
            let tokens = items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        ExecPolicyError::InvalidPattern(
                            "pattern alternative must be a string".to_string(),
                        )
                    })
                })
                .collect::<ExecPolicyResult<_>>()?;
            Ok(PatternToken::Alts(tokens))
        }
    }
}

fn parse_examples(examples: &PolicyValue, field: &str) -> ExecPolicyResult<Vec<Vec<String>>> {
    let items = examples
        .as_list()
        .ok_or_else(|| ExecPolicyError::InvalidRule(format!("{field} must be a list")))?;
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        match item {
            PolicyValue::List(tokens) => {
                let tokens = tokens
                    .iter()
                    .map(|token| {
                        token.as_str().map(str::to_string).ok_or_else(|| {
                            ExecPolicyError::InvalidRule(format!(
                                "{field} example must be a list of strings"
                            ))
                        })
                    })
                    .collect::<ExecPolicyResult<_>>()?;
                result.push(tokens);
            }
            // Allow a bare string as a single-token example.
            PolicyValue::Str(s) => result.push(vec![s.clone()]),
        }
    }
    Ok(result)
}

// -----------------------------------------------------------------------
// Internal builder
// -----------------------------------------------------------------------

#[derive(Debug)]
struct PolicyBuilder {
    /// Rules per program, in insertion order within each program.
    rules_by_program: HashMap<String, Vec<RuleRef>>,
    pending_example_validations: Vec<PendingExampleValidation>,
}

impl PolicyBuilder {
    fn new() -> Self {
        Self {
            rules_by_program: HashMap::new(),
            pending_example_validations: Vec::new(),
        }
    }

    fn add_rule(&mut self, rule: RuleRef) {
        self.rules_by_program
            .entry(rule.program().to_string())
            .or_default()
            .push(rule);
    }

    fn add_pending_example_validation(
        &mut self,
        rules: Vec<RuleRef>,
        matches: Vec<Vec<String>>,
        not_matches: Vec<Vec<String>>,
        location: Option<String>,
    ) {
        self.pending_example_validations
            .push(PendingExampleValidation {
                rules,
                matches,
                not_matches,
                location,
            });
    }

    fn validate_pending_examples_from(&self, start: usize) -> ExecPolicyResult<()> {
        for validation in &self.pending_example_validations[start..] {
            let policy = Policy::from_rules(validation.rules.clone());
            validate_not_match_examples(&policy, &validation.not_matches)
                .map_err(attach_location(validation.location.as_deref()))?;
            validate_match_examples(&policy, &validation.matches)
                .map_err(attach_location(validation.location.as_deref()))?;
        }
        Ok(())
    }

    fn build(self) -> Policy {
        Policy::from_parts(self.rules_by_program)
    }
}

#[derive(Debug)]
struct PendingExampleValidation {
    rules: Vec<RuleRef>,
    matches: Vec<Vec<String>>,
    not_matches: Vec<Vec<String>>,
    location: Option<String>,
}

fn attach_location(location: Option<&str>) -> impl Fn(ExecPolicyError) -> ExecPolicyError + '_ {
    move |err| match location {
        Some(loc) => ExecPolicyError::InvalidRule(format!("{loc}: {err}")),
        None => err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_prefix_rule() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(
    pattern = ["cargo", "test"],
    decision = "allow",
)
"#,
            )
            .unwrap();
        let policy = parser.build();
        let eval = policy.evaluate(&["cargo".into(), "test".into()]).unwrap();
        assert_eq!(eval.decision, ExecDecision::Allow);
    }

    #[test]
    fn parse_prefix_rule_with_alternatives() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(
    pattern = ["npm", ["install", "ci"]],
    decision = "ask",
)
"#,
            )
            .unwrap();
        let policy = parser.build();
        assert!(policy.evaluate(&["npm".into(), "install".into()]).is_some());
        assert!(policy.evaluate(&["npm".into(), "ci".into()]).is_some());
        assert!(policy.evaluate(&["npm".into(), "run".into()]).is_none());
    }

    #[test]
    fn parse_default_decision_is_allow() {
        let mut parser = PolicyParser::new();
        parser
            .parse("test.policy", r#"prefix_rule(pattern = ["ls"])"#)
            .unwrap();
        let policy = parser.build();
        let eval = policy.evaluate(&["ls".into()]).unwrap();
        assert_eq!(eval.decision, ExecDecision::Allow);
    }

    #[test]
    fn parse_match_examples_validated() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(
    pattern = ["git", "push"],
    decision = "deny",
    match = [["git", "push"]],
)
"#,
            )
            .unwrap();
        let policy = parser.build();
        assert_eq!(
            policy
                .evaluate(&["git".into(), "push".into()])
                .unwrap()
                .decision,
            ExecDecision::Deny
        );
    }

    #[test]
    fn parse_match_example_fails_when_no_match() {
        let mut parser = PolicyParser::new();
        let result = parser.parse(
            "test.policy",
            r#"
prefix_rule(
    pattern = ["git", "push"],
    decision = "deny",
    match = [["npm", "install"]],
)
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_not_match_example_fails_when_matches() {
        let mut parser = PolicyParser::new();
        let result = parser.parse(
            "test.policy",
            r#"
prefix_rule(
    pattern = ["git", "push"],
    decision = "deny",
    not_match = [["git", "push"]],
)
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_justification() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(
    pattern = ["rm"],
    decision = "deny",
    justification = "never allow rm",
)
"#,
            )
            .unwrap();
        let policy = parser.build();
        let eval = policy.evaluate(&["rm".into()]).unwrap();
        assert_eq!(eval.decision, ExecDecision::Deny);
        assert_eq!(eval.determining_justification(), Some("never allow rm"));
    }

    #[test]
    fn parse_empty_justification_errors() {
        let mut parser = PolicyParser::new();
        let result = parser.parse(
            "test.policy",
            r#"prefix_rule(pattern = ["ls"], justification = "")"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_multiple_rules_accumulate() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(pattern = ["ls"], decision = "allow")
prefix_rule(pattern = ["cat"], decision = "allow")
"#,
            )
            .unwrap();
        let policy = parser.build();
        assert!(policy.has_match(&["ls".into()]));
        assert!(policy.has_match(&["cat".into()]));
    }

    #[test]
    fn parse_strictest_wins_across_rules() {
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(pattern = ["git"], decision = "allow")
prefix_rule(pattern = ["git"], decision = "deny")
"#,
            )
            .unwrap();
        let policy = parser.build();
        let eval = policy.evaluate(&["git".into()]).unwrap();
        assert_eq!(eval.decision, ExecDecision::Deny);
    }

    #[test]
    fn parse_string_match_example_shorthand() {
        // A bare string in match= should be treated as a single-token example.
        let mut parser = PolicyParser::new();
        parser
            .parse(
                "test.policy",
                r#"
prefix_rule(
    pattern = ["ls"],
    decision = "allow",
    match = ["ls"],
)
"#,
            )
            .unwrap();
    }

    #[test]
    fn parse_bare_string_not_match_example() {
        let mut parser = PolicyParser::new();
        let result = parser.parse(
            "test.policy",
            r#"
prefix_rule(
    pattern = ["ls"],
    decision = "allow",
    not_match = ["cat"],
)
"#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn parse_syntax_error_reports_policy_and_line() {
        let mut parser = PolicyParser::new();
        let err = parser
            .parse("test.policy", "prefix_rule(pattern = [\"ls\"]\n")
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("test.policy"), "{message}");
        assert!(message.contains("line 1"), "{message}");
    }

    #[test]
    fn parse_invalid_decision_errors() {
        let mut parser = PolicyParser::new();
        let result = parser.parse(
            "test.policy",
            r#"prefix_rule(pattern = ["ls"], decision = "maybe")"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_pattern_errors() {
        let mut parser = PolicyParser::new();
        let result = parser.parse("test.policy", r#"prefix_rule(decision = "allow")"#);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_pattern_errors() {
        let mut parser = PolicyParser::new();
        let result = parser.parse("test.policy", "prefix_rule(pattern = [])");
        assert!(result.is_err());
    }
}

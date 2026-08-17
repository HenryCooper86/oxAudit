//! Minimal recursive-descent parser for exec policy files.
//!
//! The policy file format is a tiny, Python-looking DSL consisting solely of
//! top-level keyword-argument calls:
//!
//! ```text
//! # comments run to end of line
//! prefix_rule(
//!     pattern = ["git", ["push", "commit"]],
//!     decision = "ask",
//!     match = [["git", "push"]],
//! )
//! ```
//!
//! There are no variables, expressions, operators, or control flow: values are
//! string literals and (nested) lists of string literals only.

use thiserror::Error;

/// Function names accepted at the top level, with their allowed keywords.
const KNOWN_CALLS: &[(&str, &[&str])] = &[(
    "prefix_rule",
    &["pattern", "decision", "match", "not_match", "justification"],
)];

/// A parsed argument value: either a string or a list of values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValue {
    /// A string literal.
    Str(String),
    /// A bracketed list of values.
    List(Vec<PolicyValue>),
}

impl PolicyValue {
    /// The string contents, if this value is a string literal.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            Self::List(_) => None,
        }
    }

    /// The element list, if this value is a list.
    pub fn as_list(&self) -> Option<&[PolicyValue]> {
        match self {
            Self::List(items) => Some(items),
            Self::Str(_) => None,
        }
    }
}

/// A single top-level call with its keyword arguments, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCall {
    /// The called function name.
    pub name: String,
    /// Keyword arguments in source order.
    pub args: Vec<(String, PolicyValue)>,
    /// 1-based line the call starts on.
    pub line: usize,
}

/// A syntax error with a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("line {line}: {message}")]
pub struct SyntaxError {
    /// 1-based line the error was detected on.
    pub line: usize,
    /// Human-readable description.
    pub message: String,
}

impl SyntaxError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

/// Parse a policy file into its sequence of top-level calls.
pub fn parse_calls(source: &str) -> Result<Vec<PolicyCall>, SyntaxError> {
    let tokens = lex(source)?;
    let mut parser = TokenParser {
        tokens: &tokens,
        pos: 0,
    };
    parser.parse_calls()
}

// -----------------------------------------------------------------------
// Lexer
// -----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Eq,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Self::Ident(name) => format!("identifier `{name}`"),
            Self::Str(_) => "string literal".to_string(),
            Self::LParen => "`(`".to_string(),
            Self::RParen => "`)`".to_string(),
            Self::LBracket => "`[`".to_string(),
            Self::RBracket => "`]`".to_string(),
            Self::Comma => "`,`".to_string(),
            Self::Eq => "`=`".to_string(),
        }
    }
}

struct Lexed {
    tok: Tok,
    line: usize,
}

fn lex(source: &str) -> Result<Vec<Lexed>, SyntaxError> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while let Some(&c) = chars.get(index) {
        match c {
            '\n' => {
                index += 1;
                line += 1;
            }
            '#' => {
                while matches!(chars.get(index), Some(&ch) if ch != '\n') {
                    index += 1;
                }
            }
            '(' | ')' | '[' | ']' | ',' | '=' => {
                let tok = match c {
                    '(' => Tok::LParen,
                    ')' => Tok::RParen,
                    '[' => Tok::LBracket,
                    ']' => Tok::RBracket,
                    ',' => Tok::Comma,
                    _ => Tok::Eq,
                };
                out.push(Lexed { tok, line });
                index += 1;
            }
            '"' | '\'' => {
                let (value, next) = lex_string(&chars, index, line)?;
                out.push(Lexed {
                    tok: Tok::Str(value),
                    line,
                });
                index = next;
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = index;
                while matches!(chars.get(index), Some(&ch) if ch.is_alphanumeric() || ch == '_') {
                    index += 1;
                }
                let name: String = chars[start..index].iter().collect();
                out.push(Lexed {
                    tok: Tok::Ident(name),
                    line,
                });
            }
            c if c.is_whitespace() => index += 1,
            other => {
                return Err(SyntaxError::new(
                    line,
                    format!("unexpected character {other:?}"),
                ));
            }
        }
    }
    Ok(out)
}

/// Scan a quoted string starting at `start`; returns the value and next index.
fn lex_string(chars: &[char], start: usize, line: usize) -> Result<(String, usize), SyntaxError> {
    let quote = chars[start];
    let mut index = start + 1;
    let mut value = String::new();
    loop {
        let Some(&c) = chars.get(index) else {
            return Err(SyntaxError::new(line, "unterminated string literal"));
        };
        index += 1;
        match c {
            '\n' => return Err(SyntaxError::new(line, "unterminated string literal")),
            c if c == quote => return Ok((value, index)),
            '\\' => {
                let Some(&escape) = chars.get(index) else {
                    return Err(SyntaxError::new(line, "unterminated string literal"));
                };
                index += 1;
                let decoded = match escape {
                    '\\' => '\\',
                    '"' => '"',
                    '\'' => '\'',
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => {
                        return Err(SyntaxError::new(
                            line,
                            format!("unsupported escape sequence `\\{other}`"),
                        ));
                    }
                };
                value.push(decoded);
            }
            other => value.push(other),
        }
    }
}

// -----------------------------------------------------------------------
// Parser
// -----------------------------------------------------------------------

struct TokenParser<'a> {
    tokens: &'a [Lexed],
    pos: usize,
}

impl TokenParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos).map(|t| &t.tok)
    }

    fn line(&self) -> usize {
        self.tokens
            .get(self.pos)
            .or_else(|| self.tokens.last())
            .map_or(1, |t| t.line)
    }

    fn bump(&mut self) {
        self.pos += 1;
    }

    fn eof(&self, expected: &str) -> SyntaxError {
        SyntaxError::new(
            self.line(),
            format!("unexpected end of file, expected {expected}"),
        )
    }

    fn expect(&mut self, want: &Tok, expected: &str) -> Result<(), SyntaxError> {
        match self.peek() {
            Some(tok) if tok == want => {
                self.bump();
                Ok(())
            }
            Some(tok) => Err(SyntaxError::new(
                self.line(),
                format!("expected {expected}, found {}", tok.describe()),
            )),
            None => Err(self.eof(expected)),
        }
    }

    fn parse_calls(&mut self) -> Result<Vec<PolicyCall>, SyntaxError> {
        let mut calls = Vec::new();
        while self.peek().is_some() {
            calls.push(self.parse_call()?);
        }
        Ok(calls)
    }

    fn parse_call(&mut self) -> Result<PolicyCall, SyntaxError> {
        let line = self.line();
        let name = match self.peek() {
            Some(Tok::Ident(name)) => name.clone(),
            Some(tok) => {
                return Err(SyntaxError::new(
                    line,
                    format!("expected a function call, found {}", tok.describe()),
                ));
            }
            None => return Err(self.eof("a function call")),
        };
        self.bump();
        let Some(&(_, allowed)) = KNOWN_CALLS.iter().find(|(known, _)| *known == name) else {
            return Err(SyntaxError::new(line, format!("unknown function `{name}`")));
        };
        self.expect(&Tok::LParen, "`(` after function name")?;

        let mut args: Vec<(String, PolicyValue)> = Vec::new();
        loop {
            if matches!(self.peek(), Some(Tok::RParen)) {
                self.bump();
                break;
            }
            let arg_line = self.line();
            let key = match self.peek() {
                Some(Tok::Ident(key)) => key.clone(),
                Some(Tok::Str(_) | Tok::LBracket) => {
                    return Err(SyntaxError::new(
                        arg_line,
                        format!("positional arguments are not supported by `{name}`"),
                    ));
                }
                Some(tok) => {
                    return Err(SyntaxError::new(
                        arg_line,
                        format!("expected an argument name, found {}", tok.describe()),
                    ));
                }
                None => return Err(self.eof("an argument name")),
            };
            self.bump();
            if !allowed.contains(&key.as_str()) {
                return Err(SyntaxError::new(
                    arg_line,
                    format!("unknown argument `{key}` for `{name}`"),
                ));
            }
            if args.iter().any(|(existing, _)| *existing == key) {
                return Err(SyntaxError::new(
                    arg_line,
                    format!("duplicate argument `{key}` for `{name}`"),
                ));
            }
            self.expect(&Tok::Eq, format!("`=` after argument `{key}`").as_str())?;
            let value = self.parse_value()?;
            args.push((key, value));

            match self.peek() {
                Some(Tok::Comma) => self.bump(),
                Some(Tok::RParen) => {
                    self.bump();
                    break;
                }
                Some(tok) => {
                    return Err(SyntaxError::new(
                        self.line(),
                        format!("expected `,` or `)`, found {}", tok.describe()),
                    ));
                }
                None => return Err(self.eof("`,` or `)`")),
            }
        }

        Ok(PolicyCall { name, args, line })
    }

    fn parse_value(&mut self) -> Result<PolicyValue, SyntaxError> {
        match self.peek() {
            Some(Tok::Str(value)) => {
                let value = value.clone();
                self.bump();
                Ok(PolicyValue::Str(value))
            }
            Some(Tok::LBracket) => {
                self.bump();
                let mut items = Vec::new();
                loop {
                    if matches!(self.peek(), Some(Tok::RBracket)) {
                        self.bump();
                        return Ok(PolicyValue::List(items));
                    }
                    items.push(self.parse_value()?);
                    match self.peek() {
                        Some(Tok::Comma) => self.bump(),
                        Some(Tok::RBracket) => {
                            self.bump();
                            return Ok(PolicyValue::List(items));
                        }
                        Some(tok) => {
                            return Err(SyntaxError::new(
                                self.line(),
                                format!("expected `,` or `]`, found {}", tok.describe()),
                            ));
                        }
                        None => return Err(self.eof("`,` or `]`")),
                    }
                }
            }
            Some(tok) => Err(SyntaxError::new(
                self.line(),
                format!("expected a string or list value, found {}", tok.describe()),
            )),
            None => Err(self.eof("a string or list value")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn str_value(s: &str) -> PolicyValue {
        PolicyValue::Str(s.to_string())
    }

    #[test]
    fn parses_multi_line_call_with_trailing_comma_and_comments() {
        let calls = parse_calls(
            r#"
# leading comment
prefix_rule(
    pattern = ["git", "push"],  # trailing comment
    decision = "deny",
)
"#,
        )
        .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "prefix_rule");
        assert_eq!(calls[0].line, 3);
        assert_eq!(
            calls[0].args,
            vec![
                (
                    "pattern".to_string(),
                    PolicyValue::List(vec![str_value("git"), str_value("push")])
                ),
                ("decision".to_string(), str_value("deny")),
            ]
        );
    }

    #[test]
    fn parses_nested_lists_and_empty_list() {
        let calls = parse_calls(r#"prefix_rule(pattern = ["npm", ["install", "ci"]], match = [])"#)
            .unwrap();
        assert_eq!(
            calls[0].args[0].1,
            PolicyValue::List(vec![
                str_value("npm"),
                PolicyValue::List(vec![str_value("install"), str_value("ci")]),
            ])
        );
        assert_eq!(calls[0].args[1].1, PolicyValue::List(Vec::new()));
    }

    #[test]
    fn parses_single_quoted_strings_and_escapes() {
        let calls =
            parse_calls("prefix_rule(pattern = ['ls'], justification = 'a\\tb\\n\\'c\\\\d\\\"e')")
                .unwrap();
        assert_eq!(calls[0].args[0].1, PolicyValue::List(vec![str_value("ls")]));
        assert_eq!(
            calls[0].args[1].1.as_str(),
            Some("a\tb\n'c\\d\"e"),
            "escapes should be decoded"
        );
    }

    #[test]
    fn parses_multiple_calls_without_separators() {
        let calls = parse_calls(
            r#"prefix_rule(pattern = ["ls"]) prefix_rule(pattern = ["cat"])
prefix_rule(pattern = ["pwd"])"#,
        )
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].line, 2);
    }

    #[test]
    fn rejects_unknown_function_name() {
        let err = parse_calls("suffix_rule(pattern = [\"ls\"])").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(
            err.message.contains("unknown function `suffix_rule`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_argument() {
        let err = parse_calls(r#"prefix_rule(patern = ["ls"])"#).unwrap_err();
        assert!(err.message.contains("unknown argument `patern`"), "{err}");
    }

    #[test]
    fn rejects_duplicate_keyword_argument() {
        let err = parse_calls(r#"prefix_rule(pattern = ["ls"], pattern = ["cat"])"#).unwrap_err();
        assert!(
            err.message.contains("duplicate argument `pattern`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_positional_argument() {
        let err = parse_calls(r#"prefix_rule(["ls"])"#).unwrap_err();
        assert!(
            err.message
                .contains("positional arguments are not supported"),
            "{err}"
        );
        let err = parse_calls(r#"prefix_rule("ls")"#).unwrap_err();
        assert!(
            err.message
                .contains("positional arguments are not supported"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unterminated_string() {
        let err = parse_calls("prefix_rule(pattern = [\"ls)\n").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(err.message.contains("unterminated string literal"), "{err}");
    }

    #[test]
    fn rejects_unterminated_list() {
        let err = parse_calls(r#"prefix_rule(pattern = ["ls""#).unwrap_err();
        assert!(err.message.contains("unexpected end of file"), "{err}");
    }

    #[test]
    fn error_reports_line_number_of_offending_construct() {
        let err = parse_calls(
            r#"prefix_rule(pattern = ["ls"])

prefix_rule(pattern = ["cat"], bogus = "x")
"#,
        )
        .unwrap_err();
        assert_eq!(err.line, 3);
        assert_eq!(
            err.to_string(),
            "line 3: unknown argument `bogus` for `prefix_rule`"
        );
    }

    #[test]
    fn rejects_expressions_and_variables() {
        assert!(parse_calls(r#"prefix_rule(pattern = ["a"] + ["b"])"#).is_err());
        assert!(parse_calls("x = 1").is_err());
        assert!(parse_calls("prefix_rule(pattern = name)").is_err());
    }

    #[test]
    fn empty_source_yields_no_calls() {
        assert!(parse_calls("\n# only a comment\n  \n").unwrap().is_empty());
    }
}

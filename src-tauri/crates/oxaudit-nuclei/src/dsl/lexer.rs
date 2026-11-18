//! Tokeniser for the Nuclei expression language.

use super::value::DslError;

pub(crate) const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TOKENS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    BitNot,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
    Not,
    Match,
    NotMatch,
    In,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Int(i64),
    Float(f64),
    Str(String),
    Ident(String),
    Op(Op),
    LParen,
    RParen,
    Comma,
    Question,
    Colon,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

pub fn lex(src: &str) -> Result<Vec<Token>, DslError> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(DslError::Limit("expression is too long".into()));
    }
    let chars: Vec<char> = src.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if tokens.len() > MAX_TOKENS {
            return Err(DslError::Limit("expression has too many tokens".into()));
        }
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let (token, used) = lex_number(&chars[i..])?;
            tokens.push(token);
            i += used;
            continue;
        }
        if is_ident_start(c) {
            let mut end = i + 1;
            while end < chars.len() {
                let ch = chars[end];
                let dotted = ch == '.'
                    && chars
                        .get(end + 1)
                        .is_some_and(|n| is_ident_start(*n) || n.is_ascii_digit());
                if is_ident_part(ch) || dotted {
                    end += 1;
                } else {
                    break;
                }
            }
            let word: String = chars[i..end].iter().collect();
            if word == "in" {
                tokens.push(Token::Op(Op::In));
            } else {
                tokens.push(Token::Ident(word));
            }
            i = end;
            continue;
        }
        match c {
            '"' | '\'' => {
                let (s, used) = lex_string(&chars[i..], c)?;
                tokens.push(Token::Str(s));
                i += used;
                continue;
            }
            '`' => {
                let rest = &chars[i + 1..];
                let Some(end) = rest.iter().position(|ch| *ch == '`') else {
                    return Err(DslError::Parse("unterminated raw string".into()));
                };
                tokens.push(Token::Str(rest[..end].iter().collect()));
                i += end + 2;
                continue;
            }
            _ => {}
        }
        let two = |a: char, b: char| c == a && next == Some(b);
        let (token, used) = if two('*', '*') {
            (Token::Op(Op::Pow), 2)
        } else if two('=', '=') {
            (Token::Op(Op::Eq), 2)
        } else if two('!', '=') {
            (Token::Op(Op::Ne), 2)
        } else if two('<', '=') {
            (Token::Op(Op::Le), 2)
        } else if two('>', '=') {
            (Token::Op(Op::Ge), 2)
        } else if two('&', '&') {
            (Token::Op(Op::And), 2)
        } else if two('|', '|') {
            (Token::Op(Op::Or), 2)
        } else if two('=', '~') {
            (Token::Op(Op::Match), 2)
        } else if two('!', '~') {
            (Token::Op(Op::NotMatch), 2)
        } else if two('<', '<') {
            (Token::Op(Op::Shl), 2)
        } else if two('>', '>') {
            (Token::Op(Op::Shr), 2)
        } else {
            let single = match c {
                '+' => Token::Op(Op::Add),
                '-' => Token::Op(Op::Sub),
                '*' => Token::Op(Op::Mul),
                '/' => Token::Op(Op::Div),
                '%' => Token::Op(Op::Mod),
                '&' => Token::Op(Op::BitAnd),
                '|' => Token::Op(Op::BitOr),
                '^' => Token::Op(Op::BitXor),
                '~' => Token::Op(Op::BitNot),
                '<' => Token::Op(Op::Lt),
                '>' => Token::Op(Op::Gt),
                '!' => Token::Op(Op::Not),
                '(' => Token::LParen,
                ')' => Token::RParen,
                ',' => Token::Comma,
                '?' => Token::Question,
                ':' => Token::Colon,
                other => {
                    return Err(DslError::Parse(format!("unexpected character `{other}`")));
                }
            };
            (single, 1)
        };
        tokens.push(token);
        i += used;
    }
    Ok(tokens)
}

fn lex_number(chars: &[char]) -> Result<(Token, usize), DslError> {
    if chars.len() > 2 && chars[0] == '0' && (chars[1] == 'x' || chars[1] == 'X') {
        let mut end = 2;
        while end < chars.len() && chars[end].is_ascii_hexdigit() {
            end += 1;
        }
        let digits: String = chars[2..end].iter().collect();
        return i64::from_str_radix(&digits, 16)
            .map(|n| (Token::Int(n), end))
            .map_err(|_| DslError::Parse("invalid hexadecimal literal".into()));
    }
    let mut end = 0;
    while end < chars.len() && chars[end].is_ascii_digit() {
        end += 1;
    }
    let mut is_float = false;
    if end < chars.len()
        && chars[end] == '.'
        && chars.get(end + 1).is_some_and(|c| c.is_ascii_digit())
    {
        is_float = true;
        end += 1;
        while end < chars.len() && chars[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end < chars.len() && (chars[end] == 'e' || chars[end] == 'E') {
        let mut probe = end + 1;
        if probe < chars.len() && (chars[probe] == '+' || chars[probe] == '-') {
            probe += 1;
        }
        if probe < chars.len() && chars[probe].is_ascii_digit() {
            while probe < chars.len() && chars[probe].is_ascii_digit() {
                probe += 1;
            }
            is_float = true;
            end = probe;
        }
    }
    let text: String = chars[..end].iter().collect();
    if !is_float {
        if let Ok(n) = text.parse::<i64>() {
            return Ok((Token::Int(n), end));
        }
    }
    text.parse::<f64>()
        .map(|f| (Token::Float(f), end))
        .map_err(|_| DslError::Parse(format!("invalid number `{text}`")))
}

fn lex_string(chars: &[char], quote: char) -> Result<(String, usize), DslError> {
    let mut out = String::new();
    let mut i = 1;
    while i < chars.len() {
        let c = chars[i];
        if c == quote {
            return Ok((out, i + 1));
        }
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let Some(&esc) = chars.get(i + 1) else {
            break;
        };
        i += 2;
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'x' | 'u' => {
                let width = if esc == 'x' { 2 } else { 4 };
                let hex: String = chars.iter().skip(i).take(width).collect();
                let decoded = if hex.chars().count() == width {
                    u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                } else {
                    None
                };
                match decoded {
                    Some(ch) => {
                        out.push(ch);
                        i += width;
                    }
                    None => {
                        out.push('\\');
                        out.push(esc);
                    }
                }
            }
            // Unknown escapes are kept verbatim so regex fragments such as
            // "\d+" survive.
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Err(DslError::Parse("unterminated string literal".into()))
}

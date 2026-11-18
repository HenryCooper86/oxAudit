//! Recursive-descent parser producing a bounded-depth expression tree.

use super::lexer::{lex, Op, Token};
use super::value::{DslError, Value};

/// Maximum nesting of parentheses, calls and prefix operators.
pub const MAX_NESTING: usize = 64;
/// Maximum depth of the resulting tree, which bounds evaluator recursion.
pub const MAX_TREE_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(Value),
    Var(String),
    Unary(Op, Box<Expr>),
    Binary(Op, Box<Expr>, Box<Expr>),
    In(Box<Expr>, Vec<Expr>),
    Call(String, Vec<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

impl Expr {
    fn depth(&self) -> usize {
        1 + match self {
            Expr::Lit(_) | Expr::Var(_) => 0,
            Expr::Unary(_, e) => e.depth(),
            Expr::Binary(_, a, b) => a.depth().max(b.depth()),
            Expr::In(a, list) => list.iter().map(Expr::depth).fold(a.depth(), usize::max),
            Expr::Call(_, args) => args.iter().map(Expr::depth).max().unwrap_or(0),
            Expr::Ternary(a, b, c) => a.depth().max(b.depth()).max(c.depth()),
        }
    }

    /// Visit this node and every descendant.
    pub fn walk(&self, f: &mut dyn FnMut(&Expr)) {
        f(self);
        match self {
            Expr::Lit(_) | Expr::Var(_) => {}
            Expr::Unary(_, e) => e.walk(f),
            Expr::Binary(_, a, b) => {
                a.walk(f);
                b.walk(f);
            }
            Expr::In(a, list) => {
                a.walk(f);
                list.iter().for_each(|e| e.walk(f));
            }
            Expr::Call(_, args) => args.iter().for_each(|e| e.walk(f)),
            Expr::Ternary(a, b, c) => {
                a.walk(f);
                b.walk(f);
                c.walk(f);
            }
        }
    }

    /// Names of every variable the expression reads.
    pub fn variables(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(&mut |e| {
            if let Expr::Var(name) = e {
                out.push(name.clone());
            }
        });
        out
    }

    /// Names of every function the expression calls.
    pub fn functions(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(&mut |e| {
            if let Expr::Call(name, _) = e {
                out.push(name.clone());
            }
        });
        out
    }

    /// True when the expression reads a variable or calls a function. A
    /// constant expression inside `{{ }}` is kept as literal text.
    pub fn is_dynamic(&self) -> bool {
        let mut dynamic = false;
        self.walk(&mut |e| {
            if matches!(e, Expr::Var(_) | Expr::Call(..)) {
                dynamic = true;
            }
        });
        dynamic
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    nesting: usize,
}

pub fn parse(src: &str) -> Result<Expr, DslError> {
    let tokens = lex(src)?;
    if tokens.is_empty() {
        return Err(DslError::Parse("empty expression".into()));
    }
    let mut parser = Parser {
        tokens,
        pos: 0,
        nesting: 0,
    };
    let expr = parser.ternary()?;
    if parser.pos != parser.tokens.len() {
        return Err(DslError::Parse(format!(
            "unexpected token {:?}",
            parser.tokens.get(parser.pos)
        )));
    }
    Ok(expr)
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_op(&self) -> Option<Op> {
        match self.peek() {
            Some(Token::Op(op)) => Some(*op),
            _ => None,
        }
    }

    fn eat(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn enter(&mut self) -> Result<(), DslError> {
        self.nesting += 1;
        if self.nesting > MAX_NESTING {
            return Err(DslError::Limit(format!(
                "expression nesting exceeds {MAX_NESTING}"
            )));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.nesting = self.nesting.saturating_sub(1);
    }

    fn checked(expr: Expr) -> Result<Expr, DslError> {
        if expr.depth() > MAX_TREE_DEPTH {
            Err(DslError::Limit(format!(
                "expression tree deeper than {MAX_TREE_DEPTH}"
            )))
        } else {
            Ok(expr)
        }
    }

    fn ternary(&mut self) -> Result<Expr, DslError> {
        self.enter()?;
        let cond = self.binary(0)?;
        let result = if self.eat(&Token::Question) {
            let yes = self.ternary()?;
            if !self.eat(&Token::Colon) {
                return Err(DslError::Parse("expected `:` in ternary".into()));
            }
            let no = self.ternary()?;
            Self::checked(Expr::Ternary(Box::new(cond), Box::new(yes), Box::new(no)))?
        } else {
            cond
        };
        self.leave();
        Ok(result)
    }

    /// Binary precedence levels, lowest first:
    /// `||`, `&&`, comparison/`in`, `| ^ &`, shifts, `+ -`, `* / %`, `**`.
    fn level_ops(level: usize) -> &'static [Op] {
        match level {
            0 => &[Op::Or],
            1 => &[Op::And],
            2 => &[
                Op::Eq,
                Op::Ne,
                Op::Lt,
                Op::Gt,
                Op::Le,
                Op::Ge,
                Op::Match,
                Op::NotMatch,
                Op::In,
            ],
            3 => &[Op::BitOr, Op::BitXor, Op::BitAnd],
            4 => &[Op::Shl, Op::Shr],
            5 => &[Op::Add, Op::Sub],
            6 => &[Op::Mul, Op::Div, Op::Mod],
            _ => &[Op::Pow],
        }
    }

    fn binary(&mut self, level: usize) -> Result<Expr, DslError> {
        if level > 7 {
            return self.prefix();
        }
        let ops = Self::level_ops(level);
        let mut left = self.binary(level + 1)?;
        while let Some(op) = self.peek_op().filter(|op| ops.contains(op)) {
            self.pos += 1;
            if op == Op::In {
                if !self.eat(&Token::LParen) {
                    return Err(DslError::Parse("`in` expects a parenthesised list".into()));
                }
                let items = self.arguments()?;
                left = Self::checked(Expr::In(Box::new(left), items))?;
            } else {
                let right = self.binary(level + 1)?;
                left = Self::checked(Expr::Binary(op, Box::new(left), Box::new(right)))?;
            }
        }
        Ok(left)
    }

    fn prefix(&mut self) -> Result<Expr, DslError> {
        if let Some(op) = self
            .peek_op()
            .filter(|op| matches!(op, Op::Not | Op::Sub | Op::BitNot))
        {
            self.pos += 1;
            self.enter()?;
            let inner = self.prefix()?;
            self.leave();
            return Self::checked(match (op, inner) {
                (Op::Sub, Expr::Lit(Value::Int(n))) => match n.checked_neg() {
                    Some(neg) => Expr::Lit(Value::Int(neg)),
                    None => Expr::Lit(Value::Float(-(n as f64))),
                },
                (Op::Sub, Expr::Lit(Value::Float(f))) => Expr::Lit(Value::Float(-f)),
                (op, inner) => Expr::Unary(op, Box::new(inner)),
            });
        }
        self.primary()
    }

    /// Parses call arguments after an opening parenthesis, consuming `)`.
    fn arguments(&mut self) -> Result<Vec<Expr>, DslError> {
        let mut args = Vec::new();
        if self.eat(&Token::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.ternary()?);
            if self.eat(&Token::Comma) {
                continue;
            }
            if self.eat(&Token::RParen) {
                return Ok(args);
            }
            return Err(DslError::Parse("expected `,` or `)`".into()));
        }
    }

    fn primary(&mut self) -> Result<Expr, DslError> {
        let Some(token) = self.peek().cloned() else {
            return Err(DslError::Parse("unexpected end of expression".into()));
        };
        self.pos += 1;
        match token {
            Token::Int(n) => Ok(Expr::Lit(Value::Int(n))),
            Token::Float(f) => Ok(Expr::Lit(Value::Float(f))),
            Token::Str(s) => Ok(Expr::Lit(Value::from(s))),
            Token::LParen => {
                let inner = self.ternary()?;
                if !self.eat(&Token::RParen) {
                    return Err(DslError::Parse("expected `)`".into()));
                }
                Ok(inner)
            }
            Token::Ident(name) => {
                if self.eat(&Token::LParen) {
                    self.enter()?;
                    let args = self.arguments()?;
                    self.leave();
                    return Self::checked(Expr::Call(name, args));
                }
                Ok(match name.as_str() {
                    "true" => Expr::Lit(Value::Bool(true)),
                    "false" => Expr::Lit(Value::Bool(false)),
                    "nil" | "null" => Expr::Lit(Value::Null),
                    _ => Expr::Var(name),
                })
            }
            other => Err(DslError::Parse(format!("unexpected token {other:?}"))),
        }
    }
}

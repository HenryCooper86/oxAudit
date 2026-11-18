//! Evaluator for parsed expressions. Comparison follows Go/govaluate where
//! Nuclei documents it and is strict otherwise.

use std::cmp::Ordering;

use regex::RegexBuilder;

use super::functions;
use super::lexer::Op;
use super::parser::{parse, Expr};
use super::value::{DslError, EvalContext, Value, VarLookup};

pub(crate) const MAX_STRING_BYTES: usize = 1024 * 1024;
pub(crate) const REGEX_SIZE_LIMIT: usize = 2 * 1024 * 1024;

/// Parses and evaluates `src` in one step.
pub fn eval_str(
    src: &str,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
) -> Result<Value, DslError> {
    eval(&parse(src)?, vars, ctx)
}

pub fn eval(
    expr: &Expr,
    vars: &dyn VarLookup,
    ctx: &mut dyn EvalContext,
) -> Result<Value, DslError> {
    match expr {
        Expr::Lit(v) => Ok(v.clone()),
        Expr::Var(name) => vars
            .lookup(name)
            .cloned()
            .ok_or_else(|| DslError::UnknownVariable(name.clone())),
        Expr::Unary(op, inner) => unary(*op, eval(inner, vars, ctx)?),
        Expr::Binary(Op::And, a, b) => {
            if !as_bool(&eval(a, vars, ctx)?, "&&")? {
                return Ok(Value::Bool(false));
            }
            Ok(Value::Bool(as_bool(&eval(b, vars, ctx)?, "&&")?))
        }
        Expr::Binary(Op::Or, a, b) => {
            if as_bool(&eval(a, vars, ctx)?, "||")? {
                return Ok(Value::Bool(true));
            }
            Ok(Value::Bool(as_bool(&eval(b, vars, ctx)?, "||")?))
        }
        Expr::Binary(op, a, b) => {
            let left = eval(a, vars, ctx)?;
            let right = eval(b, vars, ctx)?;
            binary(*op, &left, &right)
        }
        Expr::In(a, list) => {
            let needle = eval(a, vars, ctx)?;
            for item in list {
                if values_equal(&needle, &eval(item, vars, ctx)?) {
                    return Ok(Value::Bool(true));
                }
            }
            Ok(Value::Bool(false))
        }
        Expr::Ternary(c, yes, no) => {
            if as_bool(&eval(c, vars, ctx)?, "?:")? {
                eval(yes, vars, ctx)
            } else {
                eval(no, vars, ctx)
            }
        }
        Expr::Call(name, args) => {
            let mut values = Vec::with_capacity(args.len());
            for arg in args {
                values.push(eval(arg, vars, ctx)?);
            }
            functions::call(name, &values, ctx)
        }
    }
}

fn as_bool(v: &Value, op: &str) -> Result<bool, DslError> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(DslError::Type(format!(
            "`{op}` needs a bool, got {}",
            other.type_name()
        ))),
    }
}

fn unary(op: Op, v: Value) -> Result<Value, DslError> {
    match (op, v) {
        (Op::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
        (Op::Sub, Value::Int(n)) => Ok(n
            .checked_neg()
            .map(Value::Int)
            .unwrap_or(Value::Float(-(n as f64)))),
        (Op::Sub, Value::Float(f)) => Ok(Value::Float(-f)),
        (Op::BitNot, Value::Int(n)) => Ok(Value::Int(!n)),
        (op, v) => Err(DslError::Type(format!(
            "operator {op:?} cannot apply to {}",
            v.type_name()
        ))),
    }
}

/// A string that parses completely as a number, for loose comparison with
/// numbers.
fn numeric_string(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// Loose number view: numbers, and strings that are entirely a number.
fn loose_number(v: &Value) -> Option<f64> {
    match v {
        Value::Int(_) | Value::Float(_) => v.as_f64(),
        Value::String(s) => numeric_string(s),
        _ => None,
    }
}

/// `==` semantics: same-type equality; numbers compare numerically and a
/// number equals a string that is entirely that number (header values and
/// `content_length` arrive as text); no other cross-type equality.
pub fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => {
            a.as_f64() == b.as_f64()
        }
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bytes(_), Value::String(_) | Value::Bytes(_))
        | (Value::String(_), Value::Bytes(_)) => a.to_bytes() == b.to_bytes(),
        (Value::Int(_) | Value::Float(_), Value::String(s)) => {
            numeric_string(s).is_some_and(|n| Some(n) == a.as_f64())
        }
        (Value::String(s), Value::Int(_) | Value::Float(_)) => {
            numeric_string(s).is_some_and(|n| Some(n) == b.as_f64())
        }
        _ => false,
    }
}

fn compare(a: &Value, b: &Value) -> Result<Ordering, DslError> {
    if let (Value::String(x), Value::String(y)) = (a, b) {
        return Ok(x.as_ref().cmp(y.as_ref()));
    }
    if let (Some(x), Some(y)) = (loose_number(a), loose_number(b)) {
        return x
            .partial_cmp(&y)
            .ok_or_else(|| DslError::Type("cannot order NaN".into()));
    }
    Err(DslError::Type(format!(
        "cannot order {} and {}",
        a.type_name(),
        b.type_name()
    )))
}

fn regex_matches(haystack: &Value, pattern: &Value) -> Result<bool, DslError> {
    let pattern = pattern.to_text();
    let re = RegexBuilder::new(&pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| DslError::Eval(format!("invalid regex: {e}")))?;
    Ok(re.is_match(&haystack.to_text()))
}

fn binary(op: Op, a: &Value, b: &Value) -> Result<Value, DslError> {
    match op {
        Op::Eq => Ok(Value::Bool(values_equal(a, b))),
        Op::Ne => Ok(Value::Bool(!values_equal(a, b))),
        Op::Lt => Ok(Value::Bool(compare(a, b)? == Ordering::Less)),
        Op::Le => Ok(Value::Bool(compare(a, b)? != Ordering::Greater)),
        Op::Gt => Ok(Value::Bool(compare(a, b)? == Ordering::Greater)),
        Op::Ge => Ok(Value::Bool(compare(a, b)? != Ordering::Less)),
        Op::Match => Ok(Value::Bool(regex_matches(a, b)?)),
        Op::NotMatch => Ok(Value::Bool(!regex_matches(a, b)?)),
        Op::Add => add(a, b),
        Op::Sub | Op::Mul | Op::Div | Op::Mod | Op::Pow => arithmetic(op, a, b),
        Op::BitAnd | Op::BitOr | Op::BitXor | Op::Shl | Op::Shr => bitwise(op, a, b),
        Op::And | Op::Or | Op::Not | Op::BitNot | Op::In => {
            Err(DslError::Type(format!("operator {op:?} is not binary")))
        }
    }
}

fn add(a: &Value, b: &Value) -> Result<Value, DslError> {
    if matches!(a, Value::String(_) | Value::Bytes(_))
        || matches!(b, Value::String(_) | Value::Bytes(_))
    {
        if a.to_bytes().len() + b.to_bytes().len() > MAX_STRING_BYTES {
            return Err(DslError::Limit("string concatenation too large".into()));
        }
        if matches!(a, Value::Bytes(_)) || matches!(b, Value::Bytes(_)) {
            let mut out = a.to_bytes().into_owned();
            out.extend_from_slice(&b.to_bytes());
            return Ok(Value::Bytes(out));
        }
        return Ok(Value::from(format!("{}{}", a.to_text(), b.to_text())));
    }
    arithmetic(Op::Add, a, b)
}

fn arithmetic(op: Op, a: &Value, b: &Value) -> Result<Value, DslError> {
    if let (Value::Int(x), Value::Int(y)) = (a, b) {
        let exact = match op {
            Op::Add => x.checked_add(*y),
            Op::Sub => x.checked_sub(*y),
            Op::Mul => x.checked_mul(*y),
            Op::Div => {
                if *y == 0 {
                    return Err(DslError::Eval("division by zero".into()));
                }
                match x.checked_rem(*y) {
                    Some(0) => x.checked_div(*y),
                    Some(_) => return Ok(Value::Float(*x as f64 / *y as f64)),
                    None => None,
                }
            }
            Op::Mod => {
                if *y == 0 {
                    return Err(DslError::Eval("modulo by zero".into()));
                }
                x.checked_rem(*y)
            }
            Op::Pow => {
                if (0..=u32::MAX as i64).contains(y) {
                    x.checked_pow(*y as u32)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(n) = exact {
            return Ok(Value::Int(n));
        }
    }
    let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) else {
        return Err(DslError::Type(format!(
            "operator {op:?} needs numbers, got {} and {} (use to_number for strings)",
            a.type_name(),
            b.type_name()
        )));
    };
    let result = match op {
        Op::Add => x + y,
        Op::Sub => x - y,
        Op::Mul => x * y,
        Op::Div => {
            if y == 0.0 {
                return Err(DslError::Eval("division by zero".into()));
            }
            x / y
        }
        Op::Mod => {
            if y == 0.0 {
                return Err(DslError::Eval("modulo by zero".into()));
            }
            x % y
        }
        Op::Pow => x.powf(y),
        _ => return Err(DslError::Type("not an arithmetic operator".into())),
    };
    Ok(Value::Float(result))
}

fn bitwise(op: Op, a: &Value, b: &Value) -> Result<Value, DslError> {
    let (Value::Int(x), Value::Int(y)) = (a, b) else {
        return Err(DslError::Type(format!(
            "operator {op:?} needs integers, got {} and {}",
            a.type_name(),
            b.type_name()
        )));
    };
    Ok(Value::Int(match op {
        Op::BitAnd => x & y,
        Op::BitOr => x | y,
        Op::BitXor => x ^ y,
        Op::Shl | Op::Shr => {
            if !(0..64).contains(y) {
                return Err(DslError::Eval("shift count out of range".into()));
            }
            if op == Op::Shl {
                x.wrapping_shl(*y as u32)
            } else {
                x >> *y
            }
        }
        _ => return Err(DslError::Type("not a bitwise operator".into())),
    }))
}

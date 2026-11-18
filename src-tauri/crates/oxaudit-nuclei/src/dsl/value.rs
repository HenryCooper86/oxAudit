//! The DSL value type, its error type and the host-supplied evaluation context.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A DSL value. Strings are reference counted so response bodies can be
/// shared between the variable table, request history and evaluation without
/// copying.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(Arc<str>),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn str(text: impl AsRef<str>) -> Value {
        Value::String(Arc::from(text.as_ref()))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
        }
    }

    /// Text form, as Go's `%v` would print it. Bytes are decoded lossily.
    pub fn to_text(&self) -> Cow<'_, str> {
        match self {
            Value::Null => Cow::Borrowed(""),
            Value::Bool(true) => Cow::Borrowed("true"),
            Value::Bool(false) => Cow::Borrowed("false"),
            Value::Int(n) => Cow::Owned(n.to_string()),
            Value::Float(f) => Cow::Owned(format_float(*f)),
            Value::String(s) => Cow::Borrowed(s),
            Value::Bytes(b) => String::from_utf8_lossy(b),
        }
    }

    /// Byte form: strings as their UTF-8 bytes, bytes untouched.
    pub fn to_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            Value::String(s) => Cow::Borrowed(s.as_bytes()),
            Value::Bytes(b) => Cow::Borrowed(b),
            other => match other.to_text() {
                Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
                Cow::Owned(s) => Cow::Owned(s.into_bytes()),
            },
        }
    }

    /// Numeric view of numbers only (not of numeric strings).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(n) => Some(*n as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::str(s)
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(Arc::from(s))
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Float(f)
    }
}

pub(crate) fn format_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 { "+Inf" } else { "-Inf" }.to_string()
    } else if f == f.trunc() && f.abs() < 1e15 {
        format!("{}", f as i64)
    } else {
        format!("{f}")
    }
}

/// Variable table used by the evaluator and by matchers.
pub type Vars = BTreeMap<String, Value>;

/// Read access to variables. Implemented for [`Vars`] so callers rarely need
/// anything else.
pub trait VarLookup {
    fn lookup(&self, name: &str) -> Option<&Value>;
}

impl VarLookup for Vars {
    fn lookup(&self, name: &str) -> Option<&Value> {
        self.get(name)
    }
}

/// A stack of variable tables, first hit wins.
pub struct Scope<'a> {
    layers: Vec<&'a Vars>,
}

impl<'a> Scope<'a> {
    /// `layers[0]` has the highest priority.
    pub fn new(layers: &[&'a Vars]) -> Self {
        Scope {
            layers: layers.to_vec(),
        }
    }
}

impl VarLookup for Scope<'_> {
    fn lookup(&self, name: &str) -> Option<&Value> {
        self.layers.iter().find_map(|layer| layer.get(name))
    }
}

/// Errors from lexing, parsing and evaluating DSL expressions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DslError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unknown variable `{0}`")]
    UnknownVariable(String),
    #[error("unknown or unimplemented function `{0}`")]
    UnknownFunction(String),
    #[error("function `{name}` takes {expected} argument(s), got {got}")]
    Arity {
        name: String,
        expected: String,
        got: usize,
    },
    #[error("type error: {0}")]
    Type(String),
    #[error("{0}")]
    Eval(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
}

/// Randomness and time, injected so evaluation is deterministic in tests and
/// the pure crate needs neither an RNG crate nor a clock.
pub trait EvalContext {
    fn rand_u64(&mut self) -> u64;
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// Deterministic xorshift64* source with a fixed clock. This is the default
/// context. A host that wants real time passes its own `now`.
#[derive(Debug, Clone)]
pub struct XorShiftContext {
    state: u64,
    now: i64,
}

impl XorShiftContext {
    pub fn new(seed: u64, now: i64) -> Self {
        XorShiftContext {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
            now,
        }
    }
}

impl Default for XorShiftContext {
    fn default() -> Self {
        XorShiftContext::new(0x9E37_79B9_7F4A_7C15, 1_700_000_000)
    }
}

impl EvalContext for XorShiftContext {
    fn rand_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn now_unix(&self) -> i64 {
        self.now
    }
}

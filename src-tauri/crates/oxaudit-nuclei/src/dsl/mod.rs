//! The Nuclei expression language: lexer, parser, evaluator and the helper
//! function library. Everything here is pure; randomness and time arrive
//! through [`EvalContext`].

mod eval;
pub mod functions;
mod lexer;
mod parser;
mod value;

pub use eval::{eval, eval_str, values_equal};
pub use lexer::{lex, Op, Token};
pub use parser::{parse, Expr, MAX_NESTING, MAX_TREE_DEPTH};
pub(crate) use value::format_float;
pub use value::{DslError, EvalContext, Scope, Value, VarLookup, Vars, XorShiftContext};

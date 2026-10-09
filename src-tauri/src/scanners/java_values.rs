//! Bounded proofs for immutable Java local values at one use site.
//!
//! The general resolver combines earlier definitions. This narrower pass can
//! prove that a later assignment replaced them, or that a constant condition
//! excludes them. It models only int, boolean and String locals. Calls, fields,
//! collections, unsupported control flow and exhausted budgets never prove a
//! value safe. No result from this pass is used to claim sanitization.

use std::collections::BTreeMap;
use tree_sitter::Node;

const MAX_STEPS: usize = 4096;
const MAX_DEPTH: usize = 32;
const MAX_LOCALS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(i32),
    Bool(bool),
    String,
    /// Different known integers/booleans can be safe without a known value.
    Constant,
    Unknown,
}

#[cfg(all(test, feature = "grammar-java"))]
mod tests {
    use super::*;

    fn proves_sql(body: &str) -> bool {
        let source = format!("class Query {{ void run() {{ {body} consume(sql); }} }}");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error(), "budget fixture must parse");
        let offset = source.find("consume(sql)").unwrap() + "consume(".len();
        let function =
            super::super::dataflow::enclosing_function(tree.root_node(), offset).unwrap();
        constant_local(function, &source, "sql", offset)
    }

    #[test]
    fn java_step_budget_exhaustion_declines_even_an_already_constant_local() {
        // Rejecting the parse or failing to resolve sql would make this test
        // vacuous. The same value has a positive proof with a short history.
        assert!(proves_sql(r#"String sql = "SELECT 1"; sql = "SELECT 1";"#));
        let writes = r#"sql = "SELECT 1";"#.repeat(MAX_STEPS + 1);
        let body = format!(r#"String sql = "SELECT 1"; {writes}"#);
        assert!(!proves_sql(&body));
    }

    #[test]
    fn java_local_budget_exhaustion_declines_even_an_already_constant_local() {
        assert!(proves_sql(r#"String sql = "SELECT 1"; int unrelated = 0;"#));
        let declarations = (0..MAX_LOCALS)
            .map(|index| format!("int unrelated{index} = 0;"))
            .collect::<String>();
        let body = format!(r#"String sql = "SELECT 1"; {declarations}"#);
        assert!(!proves_sql(&body));
    }

    #[test]
    fn an_integer_guard_proves_the_selected_local_assignment() {
        let source = r#"class Query {
            void run(String input) {
                int limit = 13;
                String query;
                if ((5 * 9) - limit > 30) query = "SELECT 1";
                else query = input;
                consume(query);
            }
        }"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let offset = source.find("consume(query)").unwrap() + "consume(".len();
        let function =
            super::super::dataflow::enclosing_function(tree.root_node(), offset).unwrap();
        assert!(constant_local(function, source, "query", offset));
    }
}

impl Value {
    fn join(self, other: Self) -> Self {
        if self == other {
            self
        } else if self != Self::Unknown && other != Self::Unknown {
            Self::Constant
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Copy)]
enum LocalType {
    Int,
    Bool,
    String,
    Unsupported,
}

#[derive(Clone, Copy)]
struct Binding {
    ty: LocalType,
    value: Value,
}

type Locals = BTreeMap<String, Binding>;

struct Proof<'a> {
    source: &'a str,
    remaining: usize,
}

/// Only a positive proof changes the general classifier's result.
pub(super) fn constant_local(function: Node<'_>, source: &str, name: &str, before: usize) -> bool {
    if *function.language() != tree_sitter_java::LANGUAGE.into() {
        return false;
    }
    // Kotlin and other grammars retain the general resolver, as do incomplete
    // Java trees: recovering from a syntax error is not proof of control flow.
    if !matches!(
        function.kind(),
        "method_declaration" | "constructor_declaration"
    ) || function.has_error()
    {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let mut proof = Proof {
        source,
        remaining: MAX_STEPS,
    };
    let mut locals = Locals::new();
    proof.before(body, before, &mut locals, 0).is_some()
        && locals
            .get(name)
            .is_some_and(|binding| binding.value != Value::Unknown)
}

impl Proof<'_> {
    fn step(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(())
    }

    fn text<'a>(&'a self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    fn children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).collect()
    }

    /// Execute complete statements before the use, then enter its enclosing
    /// block. Unsupported paths containing the use stop the proof altogether.
    fn before(
        &mut self,
        node: Node<'_>,
        cutoff: usize,
        locals: &mut Locals,
        depth: usize,
    ) -> Option<()> {
        self.step(depth)?;
        if node.end_byte() <= cutoff {
            return self.statement(node, locals, depth + 1);
        }
        match node.kind() {
            "block" => {
                for child in Self::children(node) {
                    if child.start_byte() > cutoff {
                        break;
                    }
                    self.before(child, cutoff, locals, depth + 1)?;
                    if child.end_byte() > cutoff {
                        break;
                    }
                }
                Some(())
            }
            "if_statement" => {
                let condition = node.child_by_field_name("condition")?;
                // A side-effecting guard cannot preserve a previous value.
                self.invalidate_writes(condition, locals, depth + 1)?;
                let value = self.expression(condition, locals, depth + 1)?;
                for (field, selected) in [("consequence", true), ("alternative", false)] {
                    if let Some(branch) = node.child_by_field_name(field) {
                        if branch.byte_range().contains(&cutoff) {
                            if matches!(value, Value::Bool(known) if known != selected) {
                                return None;
                            }
                            return self.before(branch, cutoff, locals, depth + 1);
                        }
                    }
                }
                None
            }
            "try_statement" => {
                // Before a sink in the try body, an exception exits that path.
                // Catch/finally paths, and uses after the try, are not modeled.
                let body = node.child_by_field_name("body")?;
                if body.byte_range().contains(&cutoff) {
                    self.before(body, cutoff, locals, depth + 1)
                } else {
                    None
                }
            }
            "local_variable_declaration" => {
                for child in Self::children(node) {
                    if child.kind() == "variable_declarator" && child.end_byte() <= cutoff {
                        self.declare(node, child, locals, depth + 1)?;
                    } else if child.byte_range().contains(&cutoff) {
                        self.invalidate_writes(child, locals, depth + 1)?;
                    }
                }
                Some(())
            }
            "expression_statement" | "return_statement" | "throw_statement" => {
                // An assignment in an earlier argument of the same call may
                // change the value before this use. Conservatively invalidate
                // every write in this expression, regardless of its position.
                self.invalidate_writes(node, locals, depth + 1)
            }
            "line_comment" | "block_comment" => Some(()),
            _ => None,
        }
    }

    fn statement(&mut self, node: Node<'_>, locals: &mut Locals, depth: usize) -> Option<()> {
        self.step(depth)?;
        match node.kind() {
            "block" => {
                let entry_names: Vec<_> = locals.keys().cloned().collect();
                for child in Self::children(node) {
                    self.statement(child, locals, depth + 1)?;
                }
                // Block-local declarations cannot escape their lexical scope.
                locals.retain(|name, _| entry_names.contains(name));
                Some(())
            }
            "local_variable_declaration" => {
                for child in Self::children(node) {
                    if child.kind() == "variable_declarator" {
                        self.declare(node, child, locals, depth + 1)?;
                    }
                }
                Some(())
            }
            "expression_statement" => {
                let expression = node.named_child(0)?;
                if expression.kind() == "assignment_expression" {
                    let target = expression.child_by_field_name("left")?;
                    let right = expression.child_by_field_name("right")?;
                    // Array indices and field receivers may contain updates
                    // even though the assignment does not target a local.
                    self.invalidate_writes(target, locals, depth + 1)?;
                    self.invalidate_writes(right, locals, depth + 1)?;
                    let value = self.expression(right, locals, depth + 1)?;
                    if target.kind() == "identifier" {
                        let name = self.text(target).to_string();
                        if let Some(binding) = locals.get_mut(&name) {
                            let operator = expression.child_by_field_name("operator")?;
                            binding.value = if self.text(operator) == "=" {
                                Self::typed(binding.ty, value)
                            } else {
                                Value::Unknown
                            };
                        }
                    }
                    Some(())
                } else {
                    self.invalidate_writes(expression, locals, depth + 1)
                }
            }
            "if_statement" => {
                let condition = node.child_by_field_name("condition")?;
                self.invalidate_writes(condition, locals, depth + 1)?;
                let value = self.expression(condition, locals, depth + 1)?;
                let consequence = node.child_by_field_name("consequence")?;
                let alternative = node.child_by_field_name("alternative");
                match value {
                    Value::Bool(true) => self.statement(consequence, locals, depth + 1),
                    Value::Bool(false) => match alternative {
                        Some(branch) => self.statement(branch, locals, depth + 1),
                        None => Some(()),
                    },
                    _ => {
                        let mut left = locals.clone();
                        let mut right = locals.clone();
                        self.statement(consequence, &mut left, depth + 1)?;
                        if let Some(branch) = alternative {
                            self.statement(branch, &mut right, depth + 1)?;
                        }
                        for (name, binding) in locals.iter_mut() {
                            binding.value = left.get(name)?.value.join(right.get(name)?.value);
                        }
                        Some(())
                    }
                }
            }
            "return_statement" | "throw_statement" | "break_statement" | "continue_statement" => {
                None
            }
            // Unsupported statements can write locals but cannot establish a
            // constant. We do not enter loops, switches or exception handlers.
            _ => self.invalidate_writes(node, locals, depth + 1),
        }
    }

    fn declare(
        &mut self,
        declaration: Node<'_>,
        declarator: Node<'_>,
        locals: &mut Locals,
        depth: usize,
    ) -> Option<()> {
        self.step(depth)?;
        let name = self
            .text(declarator.child_by_field_name("name")?)
            .to_string();
        if locals.contains_key(&name) || locals.len() >= MAX_LOCALS {
            return None;
        }
        let ty = match self.text(declaration.child_by_field_name("type")?) {
            "int" => LocalType::Int,
            "boolean" => LocalType::Bool,
            "String" | "java.lang.String" => LocalType::String,
            _ => LocalType::Unsupported,
        };
        let value = match declarator.child_by_field_name("value") {
            Some(value) => {
                self.invalidate_writes(value, locals, depth + 1)?;
                Self::typed(ty, self.expression(value, locals, depth + 1)?)
            }
            None => Value::Unknown,
        };
        locals.insert(name, Binding { ty, value });
        Some(())
    }

    fn typed(ty: LocalType, value: Value) -> Value {
        match (ty, value) {
            (LocalType::Int, Value::Int(_) | Value::Constant)
            | (LocalType::Bool, Value::Bool(_) | Value::Constant)
            | (LocalType::String, Value::String) => value,
            _ => Value::Unknown,
        }
    }

    fn invalidate_writes(
        &mut self,
        node: Node<'_>,
        locals: &mut Locals,
        depth: usize,
    ) -> Option<()> {
        self.step(depth)?;
        if matches!(node.kind(), "assignment_expression" | "update_expression") {
            let target = node
                .child_by_field_name("left")
                .or_else(|| node.named_child(0));
            if let Some(target) = target.filter(|target| target.kind() == "identifier") {
                if let Some(binding) = locals.get_mut(self.text(target)) {
                    binding.value = Value::Unknown;
                }
            }
        }
        for child in Self::children(node) {
            self.invalidate_writes(child, locals, depth + 1)?;
        }
        Some(())
    }

    fn expression(&mut self, node: Node<'_>, locals: &Locals, depth: usize) -> Option<Value> {
        self.step(depth)?;
        let value = match node.kind() {
            "parenthesized_expression" => {
                self.expression(node.named_child(0)?, locals, depth + 1)?
            }
            "string_literal" => {
                // Java's grammar also places template interpolation inside
                // string literals. A literal is constant only when every
                // named child is ordinary text or an escape; interpolation
                // and future unsupported child kinds remain unknown.
                if Self::children(node).iter().all(|child| {
                    matches!(
                        child.kind(),
                        "string_fragment" | "multiline_string_fragment" | "escape_sequence"
                    )
                }) {
                    Value::String
                } else {
                    Value::Unknown
                }
            }
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "decimal_integer_literal" => {
                // Only ordinary decimal int literals: long, hexadecimal and
                // suffix/promotion semantics remain outside this proof.
                self.text(node)
                    .parse::<i32>()
                    .map(Value::Int)
                    .unwrap_or(Value::Unknown)
            }
            "identifier" => locals
                .get(self.text(node))
                .map(|binding| binding.value)
                .unwrap_or(Value::Unknown),
            "unary_expression" => {
                let operand =
                    self.expression(node.child_by_field_name("operand")?, locals, depth + 1)?;
                match (self.text(node.child_by_field_name("operator")?), operand) {
                    ("!", Value::Bool(value)) => Value::Bool(!value),
                    ("-", Value::Int(value)) => Value::Int(value.wrapping_neg()),
                    ("+", Value::Int(value)) => Value::Int(value),
                    _ => Value::Unknown,
                }
            }
            "binary_expression" => {
                let left = self.expression(node.child_by_field_name("left")?, locals, depth + 1)?;
                let right =
                    self.expression(node.child_by_field_name("right")?, locals, depth + 1)?;
                Self::binary(
                    self.text(node.child_by_field_name("operator")?),
                    left,
                    right,
                )
            }
            "ternary_expression" => {
                let condition =
                    self.expression(node.child_by_field_name("condition")?, locals, depth + 1)?;
                let left = node.child_by_field_name("consequence")?;
                let right = node.child_by_field_name("alternative")?;
                match condition {
                    Value::Bool(true) => self.expression(left, locals, depth + 1)?,
                    Value::Bool(false) => self.expression(right, locals, depth + 1)?,
                    _ => self
                        .expression(left, locals, depth + 1)?
                        .join(self.expression(right, locals, depth + 1)?),
                }
            }
            _ => Value::Unknown,
        };
        Some(value)
    }

    fn binary(operator: &str, left: Value, right: Value) -> Value {
        use Value::*;
        match (operator, left, right) {
            ("+", Int(a), Int(b)) => Int(a.wrapping_add(b)),
            ("-", Int(a), Int(b)) => Int(a.wrapping_sub(b)),
            ("*", Int(a), Int(b)) => Int(a.wrapping_mul(b)),
            ("/", Int(a), Int(b)) if b != 0 => Int(a.wrapping_div(b)),
            ("%", Int(a), Int(b)) if b != 0 => Int(a.wrapping_rem(b)),
            (">", Int(a), Int(b)) => Bool(a > b),
            (">=", Int(a), Int(b)) => Bool(a >= b),
            ("<", Int(a), Int(b)) => Bool(a < b),
            ("<=", Int(a), Int(b)) => Bool(a <= b),
            ("==", Int(a), Int(b)) => Bool(a == b),
            ("!=", Int(a), Int(b)) => Bool(a != b),
            ("==", Bool(a), Bool(b)) => Bool(a == b),
            ("!=", Bool(a), Bool(b)) => Bool(a != b),
            ("&&", Bool(a), Bool(b)) => Bool(a && b),
            ("||", Bool(a), Bool(b)) => Bool(a || b),
            ("+", String, value) | ("+", value, String) if value != Unknown => String,
            _ => Unknown,
        }
    }
}

//! Where the value reaching a dangerous call came from.
//!
//! A pattern rule can say "this is `eval(`". It cannot say whether the argument
//! is a string literal or something a request body controls, and that is the
//! entire difference between a finding and a nuisance. On the committed corpus,
//! adding the constant-argument cases dropped precision from 100% to 71.4%
//! without changing a single rule.
//!
//! This answers the narrower question the rules cannot: **for the value that
//! reaches this sink, can an attacker choose it?**
//!
//! Three deliberate limits, because the alternative is a research project:
//!
//! * **Intraprocedural.** Analysis stops at the enclosing function. Following a
//!   value across call boundaries needs a call graph, and a wrong one produces
//!   confident nonsense.
//! * **Unknown keeps the finding.** Only a value positively shown to be
//!   constant is suppressed. A false negative in a security scanner is worse
//!   than a false positive, so every case this cannot decide stays reported.
//! * **Definitions are not flow-sensitive.** A variable reassigned in a branch
//!   is treated as tainted if *any* reaching definition is tainted. That
//!   over-approximates toward reporting, which is the safe direction.

use tree_sitter::Node;

/// What is known about the value reaching a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taint {
    /// A literal, or a name that resolves to one. An attacker cannot choose it.
    Constant,
    /// Traces to a parameter or a known external source.
    Tainted,
    /// Undetermined. The finding stands.
    Unknown,
}

/// How far a name is followed before giving up.
///
/// A bound rather than a preference: a scan target can define a chain of
/// assignments as long as it likes, and the walk must terminate on hostile
/// input the same way the parsers do.
const MAX_RESOLUTION_DEPTH: usize = 8;

/// Identifiers whose members are attacker-controlled by construction.
///
/// Deliberately short. A long list of framework globals would be guesswork
/// about someone else's code; these are the ones that mean the same thing
/// across essentially every codebase in their language.
const TAINTED_ROOTS: &[&str] = &[
    // JavaScript / TypeScript
    "req",
    "request",
    "ctx",
    "context",
    "event",
    "params",
    "query",
    "body",
    // Python
    "flask_request",
    "argv",
    "environ",
];

/// Calls that return attacker-controlled data.
const TAINTED_CALLS: &[&str] = &[
    "input", "getenv", "get_json", "read", "readline", "recv", "prompt",
];

/// Node kinds that are literal values in the supported grammars.
fn is_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "number"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "null"
            | "concatenated_string"
            | "char_literal"
    )
}

/// Node kinds that name a value rather than being one.
fn is_identifier_kind(kind: &str) -> bool {
    matches!(kind, "identifier" | "shorthand_property_identifier")
}

/// The text of a node.
fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// Does this string have anything substituted into it?
///
/// A JavaScript template literal and a Python f-string both parse as string
/// nodes, and both are constant only when nothing is interpolated. Missing this
/// treated `execute(f"SELECT ... {user_id}")` as a constant and dropped the
/// SQL-injection finding entirely — the exact case the rule exists for.
fn is_interpolated(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let interpolated = node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "template_substitution" | "interpolation" | "string_interpolation"
        )
    });
    interpolated
}

/// The call expression a sink offset falls inside, if any.
///
/// The rule matched `eval(`, so the offset lands on the callee. What matters is
/// the enclosing call, because that is what carries the arguments.
pub fn enclosing_call<'tree>(root: Node<'tree>, offset: usize) -> Option<Node<'tree>> {
    let mut node = root.descendant_for_byte_range(offset, offset)?;
    loop {
        if matches!(node.kind(), "call_expression" | "call" | "new_expression") {
            return Some(node);
        }
        node = node.parent()?;
    }
}

/// The first argument of a call, skipping punctuation.
pub fn first_argument<'tree>(call: Node<'tree>) -> Option<Node<'tree>> {
    let arguments = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("argument"))?;
    let mut cursor = arguments.walk();
    let first = arguments
        .children(&mut cursor)
        .find(|child| child.is_named() && child.kind() != "comment");
    first
}

/// Classify the value an expression evaluates to.
pub fn classify_expression(node: Node<'_>, source: &str, function: Option<Node<'_>>) -> Taint {
    classify_with_depth(node, source, function, 0)
}

fn classify_with_depth(
    node: Node<'_>,
    source: &str,
    function: Option<Node<'_>>,
    depth: usize,
) -> Taint {
    if depth > MAX_RESOLUTION_DEPTH {
        return Taint::Unknown;
    }

    let kind = node.kind();

    if is_literal_kind(kind) || kind == "template_string" {
        // An interpolated string is not a constant, whatever its node kind.
        // Whether the interpolated value is itself attacker-controlled is a
        // separate question this does not try to answer, so it stays Unknown
        // and the finding stands.
        return if is_interpolated(node) {
            Taint::Unknown
        } else {
            Taint::Constant
        };
    }

    // A binary expression is constant only if both sides are.
    if matches!(kind, "binary_expression" | "binary_operator") {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        return match (left, right) {
            (Some(left), Some(right)) => {
                let left = classify_with_depth(left, source, function, depth + 1);
                let right = classify_with_depth(right, source, function, depth + 1);
                combine(left, right)
            }
            _ => Taint::Unknown,
        };
    }

    // `req.body.expression` — the root decides.
    if matches!(kind, "member_expression" | "attribute" | "subscript") {
        if let Some(root) = leftmost_identifier(node, source) {
            if TAINTED_ROOTS.contains(&root) {
                return Taint::Tainted;
            }
        }
        return Taint::Unknown;
    }

    if matches!(kind, "call_expression" | "call") {
        if let Some(name) = called_name(node, source) {
            if TAINTED_CALLS.contains(&name) {
                return Taint::Tainted;
            }
        }
        return Taint::Unknown;
    }

    if is_identifier_kind(kind) {
        let name = text(node, source);
        let Some(function) = function else {
            return Taint::Unknown;
        };
        if is_parameter(function, source, name) {
            return Taint::Tainted;
        }
        return resolve_binding(function, source, name, node.start_byte(), depth);
    }

    Taint::Unknown
}

/// Two operands combine to constant only when both are constant.
fn combine(left: Taint, right: Taint) -> Taint {
    match (left, right) {
        (Taint::Tainted, _) | (_, Taint::Tainted) => Taint::Tainted,
        (Taint::Constant, Taint::Constant) => Taint::Constant,
        _ => Taint::Unknown,
    }
}

/// The leftmost identifier of a member chain: `req.body.x` -> `req`.
fn leftmost_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut current = node;
    loop {
        match current.kind() {
            "member_expression" | "attribute" | "subscript" => {
                current = current
                    .child_by_field_name("object")
                    .or_else(|| current.child_by_field_name("value"))?;
            }
            kind if is_identifier_kind(kind) => return Some(text(current, source)),
            _ => return None,
        }
    }
}

/// The name being called, for `input()` or `os.getenv(...)`.
fn called_name<'a>(call: Node<'_>, source: &'a str) -> Option<&'a str> {
    let function = call.child_by_field_name("function")?;
    match function.kind() {
        kind if is_identifier_kind(kind) => Some(text(function, source)),
        "member_expression" | "attribute" => {
            let property = function
                .child_by_field_name("property")
                .or_else(|| function.child_by_field_name("attribute"))?;
            Some(text(property, source))
        }
        _ => None,
    }
}

/// The function enclosing an offset, which bounds the analysis.
pub fn enclosing_function<'tree>(root: Node<'tree>, offset: usize) -> Option<Node<'tree>> {
    let mut node = root.descendant_for_byte_range(offset, offset)?;
    loop {
        if matches!(
            node.kind(),
            "function_declaration"
                | "function_definition"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "function"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

/// Is `name` a parameter of this function?
fn is_parameter(function: Node<'_>, source: &str, name: &str) -> bool {
    let Some(parameters) = function
        .child_by_field_name("parameters")
        .or_else(|| function.child_by_field_name("parameter"))
    else {
        return false;
    };
    let mut found = false;
    walk(parameters, &mut |node| {
        if is_identifier_kind(node.kind()) && text(node, source) == name {
            found = true;
        }
    });
    found
}

/// Find what `name` was assigned, searching the function then the whole file.
///
/// A module-level `const X = "..."` is the common shape for a constant used
/// inside a function, so the search widens rather than giving up at the
/// function boundary.
fn resolve_binding(
    function: Node<'_>,
    source: &str,
    name: &str,
    before: usize,
    depth: usize,
) -> Taint {
    fn scan_scope(
        scope: Node<'_>,
        function: Node<'_>,
        source: &str,
        name: &str,
        before: usize,
        depth: usize,
        result: &mut Option<Taint>,
    ) {
        walk(scope, &mut |node| {
            let assigned = match node.kind() {
                "variable_declarator" => node
                    .child_by_field_name("name")
                    .filter(|target| text(*target, source) == name)
                    .and(node.child_by_field_name("value")),
                "assignment" | "assignment_expression" => node
                    .child_by_field_name("left")
                    .filter(|target| text(*target, source) == name)
                    .and(node.child_by_field_name("right")),
                _ => None,
            };
            if let Some(value) = assigned {
                // A definition after the use cannot be the one that reaches it.
                if value.start_byte() <= before {
                    let taint = classify_with_depth(value, source, Some(function), depth + 1);
                    // Any tainted reaching definition wins: over-approximating
                    // toward reporting is the safe direction.
                    *result = Some(match *result {
                        Some(Taint::Tainted) => Taint::Tainted,
                        Some(previous) => combine(previous, taint),
                        None => taint,
                    });
                }
            }
        });
    }

    let mut result = None;
    scan_scope(function, function, source, name, before, depth, &mut result);
    if result.is_none() {
        // Widen to the file for module-level constants.
        let mut root = function;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        scan_scope(root, function, source, name, before, depth, &mut result);
    }
    result.unwrap_or(Taint::Unknown)
}

/// Depth-first walk, iterative so a deeply nested file cannot exhaust the stack.
fn walk(root: Node<'_>, visit: &mut impl FnMut(Node<'_>)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        visit(node);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::syntax;

    /// Classify the argument of the call containing `needle`.
    fn taint_of(source: &str, language: &str, needle: &str) -> Taint {
        let offset = source.find(needle).expect("needle present in fixture");
        syntax::parse(source, language).taint_at(source, offset)
    }

    // ------------------------------------------------------------ constants

    #[test]
    fn a_string_literal_argument_is_constant() {
        assert_eq!(
            taint_of("eval(\"2 + 2\");\n", "javascript", "eval("),
            Taint::Constant
        );
        assert_eq!(
            taint_of("eval('2 + 2')\n", "python", "eval("),
            Taint::Constant
        );
    }

    #[test]
    fn a_number_argument_is_constant() {
        assert_eq!(
            taint_of("eval(42);\n", "javascript", "eval("),
            Taint::Constant
        );
    }

    #[test]
    fn a_name_bound_to_a_literal_is_constant() {
        let source = "const EXPRESSION = \"1 + 1\";\nfunction f() { return eval(EXPRESSION); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Constant);
    }

    #[test]
    fn two_constants_combine_to_a_constant() {
        let source = "function f() { return eval(\"1\" + \"2\"); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Constant);
    }

    #[test]
    fn a_template_with_nothing_substituted_is_constant() {
        let source = "function f() { return eval(`2 + 2`); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Constant);
    }

    // -------------------------------------------------------------- tainted

    #[test]
    fn a_parameter_is_tainted() {
        let source = "function render(userInput) { return eval(userInput); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Tainted);

        let python = "def compute(expression):\n    return eval(expression)\n";
        assert_eq!(taint_of(python, "python", "eval("), Taint::Tainted);
    }

    #[test]
    fn request_data_is_tainted() {
        let source = "function h(req) { return eval(req.body.expr); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Tainted);
    }

    #[test]
    fn a_name_bound_to_request_data_is_tainted() {
        let source = "function h(req) { const e = req.body.expr; return eval(e); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Tainted);
    }

    #[test]
    fn a_reading_call_is_tainted() {
        let python = "def f():\n    return eval(input())\n";
        assert_eq!(taint_of(python, "python", "eval("), Taint::Tainted);
    }

    #[test]
    fn a_constant_combined_with_a_parameter_is_tainted() {
        // Concatenating a literal onto attacker input does not sanitize it.
        let source = "function f(userInput) { return eval(\"x = \" + userInput); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Tainted);
    }

    // -------------------------------------------------------------- unknown

    #[test]
    fn an_interpolated_string_is_not_constant() {
        // The bug this guards: an f-string parses as a `string` node, so
        // treating string nodes as constant dropped SQL-injection findings —
        // the exact case the rule exists for.
        let python = "def f(user_id):\n    cursor.execute(f\"SELECT * WHERE id={user_id}\")\n";
        assert_ne!(taint_of(python, "python", "execute("), Taint::Constant);

        let js = "function f(x) { return eval(`value ${x}`); }\n";
        assert_ne!(taint_of(js, "javascript", "eval("), Taint::Constant);
    }

    #[test]
    fn an_unresolvable_name_stays_unknown_so_the_finding_stands() {
        // No enclosing function, no binding in the file. Guessing either way
        // would be wrong; reporting is the safe direction.
        assert_eq!(
            taint_of("eval(mystery);\n", "javascript", "eval("),
            Taint::Unknown
        );
    }

    #[test]
    fn a_call_returning_an_unknown_value_stays_unknown() {
        let source = "function f() { return eval(compute()); }\n";
        assert_eq!(taint_of(source, "javascript", "eval("), Taint::Unknown);
    }

    #[test]
    fn a_language_with_no_grammar_is_unknown() {
        // Without a parse there is nothing to reason about, and every match
        // must stand.
        assert_eq!(taint_of("eval('x')\n", "cobol", "eval("), Taint::Unknown);
    }

    #[test]
    fn a_match_that_is_not_a_call_argument_is_unknown() {
        // Most rules do not describe a call argument at all. They have no
        // enclosing call, so the analysis abstains rather than suppressing.
        let source = "const password = \"hunter2istheexample\";\n";
        assert_eq!(taint_of(source, "javascript", "password"), Taint::Unknown);
    }

    // ---------------------------------------------------------------- bounds

    #[test]
    fn a_long_assignment_chain_terminates() {
        // A scan target can define a chain as long as it likes; the walk must
        // terminate the way the parsers do.
        let mut source = String::from("function f() {\n");
        source.push_str("  const v0 = \"seed\";\n");
        for i in 1..200 {
            source.push_str(&format!("  const v{i} = v{};\n", i - 1));
        }
        source.push_str("  return eval(v199);\n}\n");
        // Any answer is acceptable; hanging or overflowing is not.
        let _ = taint_of(&source, "javascript", "eval(");
    }

    #[test]
    fn a_self_referential_binding_does_not_loop_forever() {
        let source = "function f() { let x = x; return eval(x); }\n";
        let _ = taint_of(source, "javascript", "eval(");
    }

    #[test]
    fn deeply_nested_input_does_not_exhaust_the_stack() {
        let source = format!(
            "function f() {{ return eval({}1{}); }}\n",
            "(".repeat(5_000),
            ")".repeat(5_000)
        );
        let _ = taint_of(&source, "javascript", "eval(");
    }
}

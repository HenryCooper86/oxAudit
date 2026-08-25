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
    /// Passed through a transform that neutralizes *this sink's* weakness.
    Sanitized {
        /// The call responsible, so a reviewer can check the claim.
        by: &'static str,
    },
    /// Sanitized, but for a different weakness than this sink's.
    ///
    /// The most useful thing the analysis can tell a reviewer: there *is*
    /// sanitization on this path, and it does not cover this sink. Someone
    /// wrote that call believing it made the line safe. Reported, never
    /// suppressed, and carried into the review as evidence.
    SanitizedElsewhere {
        by: &'static str,
        /// What that call does cover.
        covers: &'static str,
    },
    /// Traces to a value an attacker can choose.
    Tainted {
        /// Where it entered. The distinction decides whether some weakness
        /// classes are worth reporting at all — see [`Origin`].
        origin: Origin,
    },
    /// Undetermined. The finding stands.
    Unknown,
}

/// How an attacker-chosen value entered the function.
///
/// The difference is not cosmetic. `eval(x)` is dangerous whatever `x` is,
/// because evaluating anything dynamic is the defect. `fetch(url)` is a
/// library's entire purpose, and only becomes a vulnerability when the URL
/// comes from an inbound request rather than from whoever called the function.
///
/// Intraprocedural analysis cannot tell whether a parameter is reachable from
/// a request handler — that needs a call graph. So for weakness classes where
/// a caller-supplied value is the ordinary case, only `External` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A parameter of the enclosing function. Attacker-controlled only if some
    /// caller passes attacker data, which is not visible from here.
    Parameter,
    /// A request, argv, an environment read, or another inbound source.
    /// Attacker-controlled by construction.
    External,
}
/// Weakness classes where the *call* is the defect rather than the value
/// reaching it.
///
/// `Math.random()` is not made unpredictable by `.toString(36).slice(2)`, and
/// an XML parser left at its defaults is not hardened by the filename it is
/// handed. For these, argument taint answers a question nobody asked, and
/// letting it clear the finding is how `Math.random()` came to be suppressed
/// by the constant `2` in a downstream `.slice(2)`.
///
/// The list is keyed on the *rule's* CWE, so a new rule reporting the same
/// weakness under a sibling number does not inherit the exemption. That cost
/// 19 findings once already: `new java.util.Random().nextInt(99)` was cleared
/// by the constant 99 because the rule said CWE-330 and only CWE-338 was
/// listed. Sibling numbers for one weakness belong here together.
const CALL_IS_THE_DEFECT: &[&str] = &[
    "CWE-330", "CWE-338", "CWE-611", "CWE-327", "CWE-328", "CWE-295",
];

/// Is this weakness about the call itself rather than its input?
pub fn call_is_the_defect(sink_cwe: Option<&str>) -> bool {
    sink_cwe.is_some_and(|cwe| CALL_IS_THE_DEFECT.contains(&cwe))
}

/// Weakness classes where a caller-supplied value is the ordinary case.
///
/// Reporting these on any parameter made `js-ssrf` fire 148 times across a
/// dependency tree — half of every finding — because taking a URL is what an
/// HTTP wrapper does. Requiring an inbound source trades recall for a rule
/// somebody will actually leave switched on.
const REQUIRES_EXTERNAL_ORIGIN: &[&str] = &["CWE-918", "CWE-22"];

/// Does this weakness class need the value to come from outside the program?
pub fn requires_external_origin(sink_cwe: Option<&str>) -> bool {
    sink_cwe.is_some_and(|cwe| REQUIRES_EXTERNAL_ORIGIN.contains(&cwe))
}

/// A transform that neutralizes specific weakness classes.
///
/// The CWE list is the entire point. Sanitizers are sink-specific:
/// `escapeHtml` neutralizes markup and does nothing whatsoever about code
/// execution, so treating sanitizers generically would silently drop live RCE.
/// A recognised call only excuses a sink whose CWE it actually covers.
struct Sanitizer {
    /// Matched against the called name, or the final member of a call chain.
    name: &'static str,
    /// Weakness classes this genuinely neutralizes.
    neutralizes: &'static [&'static str],
}

/// Deliberately short, and every entry is defensible on its own.
///
/// The bar for adding one: the transform must make the value incapable of
/// carrying the named weakness, not merely less likely to. A guess here is a
/// false negative, which is the expensive direction.
const SANITIZERS: &[Sanitizer] = &[
    // Numeric coercion cannot return anything that carries code or a command.
    Sanitizer {
        name: "parseInt",
        neutralizes: &["CWE-95", "CWE-94", "CWE-78", "CWE-89"],
    },
    Sanitizer {
        name: "parseFloat",
        neutralizes: &["CWE-95", "CWE-94", "CWE-78", "CWE-89"],
    },
    Sanitizer {
        name: "Number",
        neutralizes: &["CWE-95", "CWE-94", "CWE-78", "CWE-89"],
    },
    // Python's int()/float() raise rather than returning a hostile value.
    Sanitizer {
        name: "int",
        neutralizes: &["CWE-95", "CWE-94", "CWE-78", "CWE-89"],
    },
    Sanitizer {
        name: "float",
        neutralizes: &["CWE-95", "CWE-94", "CWE-78", "CWE-89"],
    },
    // Accepts literals only; cannot evaluate code.
    Sanitizer {
        name: "literal_eval",
        neutralizes: &["CWE-95", "CWE-94"],
    },
    // Shell quoting: neutralizes metacharacters, nothing else.
    Sanitizer {
        name: "quote",
        neutralizes: &["CWE-78"],
    },
    Sanitizer {
        name: "escapeshellarg",
        neutralizes: &["CWE-78"],
    },
    // Markup escaping: neutralizes XSS, and explicitly not code or commands.
    Sanitizer {
        name: "escapeHtml",
        neutralizes: &["CWE-79"],
    },
    Sanitizer {
        name: "sanitize",
        neutralizes: &["CWE-79"],
    },
];

/// Does this call neutralize `sink_cwe`, or something else?
fn sanitizes(name: &str, sink_cwe: Option<&str>) -> Taint {
    let Some(entry) = SANITIZERS.iter().find(|entry| entry.name == name) else {
        return Taint::Unknown;
    };
    match sink_cwe {
        Some(cwe) if entry.neutralizes.contains(&cwe) => Taint::Sanitized { by: entry.name },
        // A recognised transform that does not cover this weakness. Worth
        // saying out loud rather than treating as if nothing were there.
        _ => Taint::SanitizedElsewhere {
            by: entry.name,
            covers: entry.neutralizes.first().copied().unwrap_or(""),
        },
    }
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
    // PHP superglobals. The grammar names these without the leading `$`,
    // which is what a variable's root resolves to.
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_FILES",
    "_SERVER",
];

/// Calls that return attacker-controlled data.
const TAINTED_CALLS: &[&str] = &[
    "input",
    "getenv",
    "get_json",
    "read",
    "readline",
    "recv",
    "prompt",
    // Framework reads of inbound request data, named rather than inferred from
    // a receiver: the conventional receiver names — `r` in Go, `ctx` in several
    // frameworks — are far too common to treat as request objects on sight.
    // Go net/http
    "FormValue",
    "PostFormValue",
    // Java servlets and Spring
    "getParameter",
    "getParameterValues",
    "getHeader",
    "getQueryString",
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
            // Java
            | "decimal_integer_literal"
            | "decimal_floating_point_literal"
            | "true_literal"
            | "false_literal"
            | "null_literal"
            // Go
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "int_literal"
            | "float_literal"
            // Rust
            | "integer_literal"
            | "float_literal_rs"
            | "boolean_literal"
            // PHP: the double-quoted form, which may interpolate — that is
            // decided separately by is_interpolated.
            | "encapsed_string"
    )
}

/// Node kinds that name a value rather than being one.
/// The part of a dotted path after the last separator.
fn final_segment(path: &str) -> &str {
    path.rsplit(['.', ':']).next().unwrap_or(path).trim()
}

/// Does this name follow the universal convention for a compile-time constant?
///
/// Deliberately strict: at least two characters, and nothing but uppercase,
/// digits, and underscores. `userInput`, `body`, and `data` cannot match, so a
/// member access that might hold attacker data keeps its Unknown.
fn is_screaming_case(name: &str) -> bool {
    name.len() >= 2
        && name.chars().any(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_identifier_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "shorthand_property_identifier"
            // PHP calls a bare identifier a `name`; Swift a `simple_identifier`.
            | "name"
            | "simple_identifier"
    )
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
            "template_substitution"
                | "interpolation"
                | "string_interpolation"
                // PHP embeds the variable straight into the string, and Swift
                // names its interpolation differently again.
                | "variable_name"
                | "interpolated_expression"
        )
    });
    interpolated
}

/// The receiver of a member access, whatever the grammar calls that field.
///
/// JavaScript and Java say `object`, Go says `operand`, Rust says `value`.
/// Looking for only one of them silently truncated the chain walk.
fn member_object<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.child_by_field_name("object")
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| {
            // PHP labels neither side of `$_GET['x']`, so the thing being
            // indexed is simply the first child.
            (node.kind() == "subscript_expression").then(|| node.named_child(0))?
        })
}

fn is_member_kind(kind: &str) -> bool {
    matches!(
        kind,
        "member_expression"
            | "selector_expression"
            | "field_access"
            | "attribute"
            // Rust
            | "field_expression"
            | "scoped_identifier"
            // C#
            | "member_access_expression"
            // Kotlin and Swift
            | "navigation_expression"
    )
}

fn is_call_kind(kind: &str) -> bool {
    matches!(
        kind,
        "call_expression"
            | "call"
            | "new_expression"
            | "method_invocation"
            // Java
            | "object_creation_expression"
            // C#
            | "invocation_expression"
            // PHP
            | "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    )
}

/// The outermost call of the chain the sink belongs to.
///
/// `Command::new("sh")` is flagged because it spawns a shell, but the value an
/// attacker chooses arrives later, in `.arg(user)`. Stopping at the innermost
/// call would read only `"sh"`, call it constant, and drop the finding — which
/// is what happened before this walked the chain.
///
/// Climbing continues only while the sink sits in the *callee* of the parent
/// call, which is exactly what a fluent chain looks like. A call in argument
/// position is a different expression and is classified on its own.
pub fn enclosing_call<'tree>(root: Node<'tree>, offset: usize) -> Option<Node<'tree>> {
    let mut node = root.descendant_for_byte_range(offset, offset)?;
    while !is_call_kind(node.kind()) {
        node = node.parent()?;
    }
    loop {
        let Some(parent) = node.parent() else {
            return Some(node);
        };
        let ascend = if is_member_kind(parent.kind()) {
            // Chained through a member access: `.arg(...)` on the result.
            true
        } else if is_call_kind(parent.kind()) {
            // Part of the parent call's callee rather than its arguments. A
            // call in argument position is a separate expression, classified
            // on its own.
            !parent
                .child_by_field_name("arguments")
                .or_else(|| parent.child_by_field_name("argument"))
                .is_some_and(|args| args.byte_range().contains(&node.start_byte()))
        } else {
            false
        };
        if !ascend {
            return Some(node);
        }
        node = parent;
    }
}

/// Does the finding *name* this call, rather than merely sit inside it?
///
/// Argument taint only says something about a finding that is the call:
/// `exec(cmd)` is judged by `cmd`. A finding nested inside an argument —
/// `element.innerHTML = value` within a callback passed to `useEffect` — has
/// no relationship to that call's arguments, and judging it by them was
/// silently suppressing XSS findings for reasons that had nothing to do with
/// them.
///
/// Stated by exclusion rather than by enumerating callee shapes: Java's `new
/// File(..)`, Go's method values, and Rust's turbofish all spell a callee
/// differently, but every language agrees on where the arguments are.
pub fn names_the_call(call: Node<'_>, offset: usize) -> bool {
    !chain_arguments(call)
        .iter()
        .any(|argument| argument.byte_range().contains(&offset))
}

/// The node holding a call's arguments.
///
/// Most grammars label it as a field. Kotlin and Swift do not: both spell it
/// `value_arguments` as an ordinary child, and Swift puts that inside a
/// `call_suffix`. Missing this made every Kotlin call look like it took no
/// arguments, so `exec("ls -la")` came back Unknown instead of Constant.
fn argument_list<'tree>(call: Node<'tree>) -> Option<Node<'tree>> {
    if let Some(list) = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("argument"))
    {
        return Some(list);
    }
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        match child.kind() {
            "value_arguments" => return Some(child),
            "call_suffix" => {
                let mut inner = child.walk();
                let list = child
                    .children(&mut inner)
                    .find(|node| node.kind() == "value_arguments");
                if let Some(list) = list {
                    return Some(list);
                }
            }
            _ => {}
        }
    }
    None
}

/// The arguments of one call, not of the chain it belongs to.
pub fn own_arguments<'tree>(call: Node<'tree>) -> Vec<Node<'tree>> {
    let Some(list) = argument_list(call) else {
        return Vec::new();
    };
    let mut arguments = Vec::new();
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if !child.is_named() || child.kind() == "comment" {
            continue;
        }
        // Kotlin, Swift, and PHP wrap each argument in a node of its own; the
        // expression is inside it.
        if matches!(child.kind(), "value_argument" | "argument") {
            let mut inner = child.walk();
            arguments.extend(
                child
                    .children(&mut inner)
                    .filter(|node| node.is_named() && node.kind() != "comment"),
            );
        } else {
            arguments.push(child);
        }
    }
    arguments
}

/// Every argument passed anywhere in a call chain.
///
/// A fluent chain is one expression as far as an attacker is concerned: if any
/// link takes a value they control, the whole thing does.
pub fn chain_arguments<'tree>(call: Node<'tree>) -> Vec<Node<'tree>> {
    let mut arguments = Vec::new();
    let mut stack = vec![call];
    while let Some(node) = stack.pop() {
        if is_call_kind(node.kind()) {
            arguments.extend(own_arguments(node));
        }
        // Descend the callee only: arguments are collected, not walked into,
        // so a nested call stays one argument rather than contributing its own.
        if let Some(callee) = node.child_by_field_name("function") {
            stack.push(callee);
        }
        if is_member_kind(node.kind()) {
            if let Some(object) = member_object(node) {
                stack.push(object);
            }
        }
    }
    arguments
}

/// Look through nodes that only wrap a single expression.
///
/// Go puts both sides of `a := b` inside an `expression_list`, so the value
/// being classified was the wrapper rather than the call, and every Go binding
/// resolved to Unknown.
fn unwrap_expression<'tree>(node: Node<'tree>) -> Node<'tree> {
    let mut current = node;
    loop {
        if !matches!(
            current.kind(),
            "expression_list" | "parenthesized_expression" | "expression_statement" | "group"
        ) {
            return current;
        }
        let mut cursor = current.walk();
        let named: Vec<_> = current
            .children(&mut cursor)
            .filter(Node::is_named)
            .collect();
        match named.as_slice() {
            [only] => current = *only,
            _ => return current,
        }
    }
}

/// Classify the value an expression evaluates to.
pub fn classify_expression(
    node: Node<'_>,
    source: &str,
    function: Option<Node<'_>>,
    sink_cwe: Option<&str>,
) -> Taint {
    classify_with_depth(node, source, function, sink_cwe, 0)
}

fn classify_with_depth(
    node: Node<'_>,
    source: &str,
    function: Option<Node<'_>>,
    sink_cwe: Option<&str>,
    depth: usize,
) -> Taint {
    if depth > MAX_RESOLUTION_DEPTH {
        return Taint::Unknown;
    }

    let node = unwrap_expression(node);
    let kind = node.kind();

    if matches!(kind, "keyword_argument" | "labeled_argument") {
        return match node.child_by_field_name("value") {
            Some(value) => classify_with_depth(value, source, function, sink_cwe, depth + 1),
            None => Taint::Unknown,
        };
    }

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

    // A literal collection is as constant as the things in it.
    //
    // `new String[] {"username", "password"}` read as Unknown, and one Unknown
    // argument makes the whole call Unknown — so an unrelated constant array
    // beside the argument a rule cares about flipped the verdict, the same way
    // a static constant did. Unlike the naming convention above this needs no
    // heuristic: if every element is constant, the collection is.
    if matches!(
        kind,
        "array_creation_expression" | "array_initializer" | "array" | "list" | "tuple" | "set"
    ) {
        // For `new T[] {..}` the elements hang off a `value` child; the type
        // and dimensions are siblings that are not values at all.
        let elements = node.child_by_field_name("value").unwrap_or(node);
        let mut cursor = elements.walk();
        let items: Vec<_> = elements
            .children(&mut cursor)
            .filter(|child| child.is_named() && child.kind() != "comment")
            .collect();
        // `new String[10]` has no elements to reason about, and whatever is
        // written into it later is not visible here.
        if items.is_empty() {
            return Taint::Unknown;
        }
        return combine_all(
            items
                .into_iter()
                .map(|item| classify_with_depth(item, source, function, sink_cwe, depth + 1)),
        );
    }

    // A binary expression is constant only if both sides are.
    if matches!(kind, "binary_expression" | "binary_operator") {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        return match (left, right) {
            (Some(left), Some(right)) => {
                let left = classify_with_depth(left, source, function, sink_cwe, depth + 1);
                let right = classify_with_depth(right, source, function, sink_cwe, depth + 1);
                combine(left, right)
            }
            _ => Taint::Unknown,
        };
    }

    // `req.body.expression` — the root decides.
    if is_member_kind(kind) || matches!(kind, "subscript" | "subscript_expression") {
        if let Some(root) = leftmost_identifier(node, source) {
            if TAINTED_ROOTS.contains(&root) {
                return Taint::Tainted {
                    origin: Origin::External,
                };
            }
        }
        // `java.sql.Statement.RETURN_GENERATED_KEYS`, `StandardCharsets.UTF_8`.
        //
        // A SCREAMING_SNAKE_CASE final segment names a compile-time constant
        // by a convention every language here shares, and reading one as
        // Unknown is not merely imprecise: one Unknown argument makes the
        // whole call Unknown, so a flags constant sitting beside the argument
        // a rule actually cares about was flipping the verdict.
        // `statement.execute(sql, RETURN_GENERATED_KEYS)` reported where
        // `statement.execute(sql)` did not, for no difference in the SQL.
        //
        // Checked after the tainted roots above, so `REQUEST.BODY` — however
        // unlikely — still loses to being rooted at a request.
        if is_screaming_case(final_segment(text(node, source))) {
            return Taint::Constant;
        }
        return Taint::Unknown;
    }

    if is_call_kind(kind) {
        // `request.args.get(...)` — the call is rooted at a request object, so
        // whatever it returns came from outside. Checked before the name list
        // because no list of method names covers every framework accessor.
        if let Some(callee) = node.child_by_field_name("function") {
            if let Some(root) = leftmost_identifier(callee, source) {
                if TAINTED_ROOTS.contains(&root) {
                    return Taint::Tainted {
                        origin: Origin::External,
                    };
                }
            }
        }
        if let Some(name) = called_name(node, source) {
            // Checked before the source list: a value read from input and then
            // coerced to a number is no longer dangerous for this sink.
            match sanitizes(name, sink_cwe) {
                Taint::Unknown => {}
                assessed => return assessed,
            }
            if TAINTED_CALLS.contains(&name) {
                return Taint::Tainted {
                    origin: Origin::External,
                };
            }
        }
        // An unmodelled callee stays Unknown, which keeps the finding.
        //
        // Treating it as a function of its arguments is the standard taint
        // approximation and it was tried here: it removed 28 false SQL
        // injection reports on the OWASP Benchmark, all of them a constant
        // handed to a helper and concatenated into a query. It also introduced
        // 11 false negatives, and they are the shape that matters:
        //
        //     String param = scr.getTheParameter("BenchmarkTest00043");
        //     String sql = "INSERT INTO users ... '" + param + "'";
        //
        // An accessor taking a constant key and returning request data is not
        // a corner case — `getProperty`, `config.get`, and every framework's
        // parameter helper have that shape. Suppressing those hides real
        // injections to remove reports that a person would dismiss in a
        // second, which is the wrong direction for this tool. The measured
        // trade was 28 fewer false positives for 11 hidden vulnerabilities.
        return Taint::Unknown;
    }

    if is_identifier_kind(kind) {
        let name = text(node, source);
        let Some(function) = function else {
            return Taint::Unknown;
        };
        if is_parameter(function, source, name) {
            return Taint::Tainted {
                origin: Origin::Parameter,
            };
        }
        return resolve_binding(function, source, name, node.start_byte(), sink_cwe, depth);
    }

    Taint::Unknown
}

/// Fold the assessments of every argument in a call into one.
///
/// Tainted dominates: one attacker-chosen argument is enough. A call is only
/// constant when every argument is.
pub fn combine_all(assessments: impl Iterator<Item = Taint>) -> Taint {
    let mut folded: Option<Taint> = None;
    for assessment in assessments {
        folded = Some(match folded {
            None => assessment,
            Some(previous) => combine(previous, assessment),
        });
        if matches!(
            folded,
            Some(Taint::Tainted {
                origin: Origin::External
            })
        ) {
            return Taint::Tainted {
                origin: Origin::External,
            };
        }
    }
    folded.unwrap_or(Taint::Unknown)
}

/// Two operands combine to constant only when both are constant.
fn combine(left: Taint, right: Taint) -> Taint {
    match (left, right) {
        // An external source anywhere in the expression decides it.
        (
            Taint::Tainted {
                origin: Origin::External,
            },
            _,
        )
        | (
            _,
            Taint::Tainted {
                origin: Origin::External,
            },
        ) => Taint::Tainted {
            origin: Origin::External,
        },
        (tainted @ Taint::Tainted { .. }, _) | (_, tainted @ Taint::Tainted { .. }) => tainted,
        (Taint::Constant, Taint::Constant) => Taint::Constant,
        // A sanitized value concatenated with a constant is still safe for this
        // sink; anything less certain falls back to reporting.
        (Taint::Sanitized { by }, Taint::Constant) | (Taint::Constant, Taint::Sanitized { by }) => {
            Taint::Sanitized { by }
        }
        (Taint::Sanitized { by }, Taint::Sanitized { .. }) => Taint::Sanitized { by },
        (assessed @ Taint::SanitizedElsewhere { .. }, Taint::Constant)
        | (Taint::Constant, assessed @ Taint::SanitizedElsewhere { .. }) => assessed,
        _ => Taint::Unknown,
    }
}

/// The leftmost identifier of a member chain: `req.body.x` -> `req`.
fn leftmost_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut current = node;
    loop {
        match current.kind() {
            kind if is_member_kind(kind)
                || matches!(kind, "subscript" | "subscript_expression") =>
            {
                current = member_object(current)?;
            }
            // PHP wraps a variable's name: `$_GET` is variable_name(name).
            "variable_name" => {
                current = current.named_child(0)?;
            }
            kind if is_identifier_kind(kind) => return Some(text(current, source)),
            _ => return None,
        }
    }
}

/// The name being called, for `input()` or `os.getenv(...)`.
fn called_name<'a>(call: Node<'_>, source: &'a str) -> Option<&'a str> {
    // Java names the method directly on the invocation; there is no callee
    // node to walk into.
    if let Some(name) = call.child_by_field_name("name") {
        return Some(text(name, source));
    }
    let function = call
        .child_by_field_name("function")
        .or_else(|| call.child_by_field_name("constructor"))?;
    if is_identifier_kind(function.kind()) {
        return Some(text(function, source));
    }
    if is_member_kind(function.kind()) {
        // `property` in JavaScript, `attribute` in Python, `field` in Go,
        // `name` in Rust's field expressions. Looking for only one of them
        // meant Go and Java method names never resolved at all.
        let member = function
            .child_by_field_name("property")
            .or_else(|| function.child_by_field_name("attribute"))
            .or_else(|| function.child_by_field_name("field"))
            .or_else(|| function.child_by_field_name("name"))?;
        return Some(text(member, source));
    }
    None
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
                // Rust
                | "function_item"
                // Java
                | "method_declaration"
                | "constructor_declaration"
                // Go
                | "func_literal"
                | "method_declaration_go"
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
    let mut named = false;
    let mut any_identifier = false;
    walk(parameters, &mut |node| {
        if matches!(
            node.kind(),
            "formal_parameter" | "parameter" | "required_parameter" | "parameter_declaration"
        ) {
            if let Some(declared) = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("pattern"))
            {
                if text(declared, source) == name {
                    named = true;
                }
            }
        }
        if is_identifier_kind(node.kind()) && text(node, source) == name {
            any_identifier = true;
        }
    });
    // The declared name is authoritative where the grammar exposes one. Falling
    // back to any identifier over-approximates toward reporting, which is the
    // safe direction for a grammar that does not.
    named || any_identifier
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
    sink_cwe: Option<&str>,
    depth: usize,
) -> Taint {
    /// What a scope scan needs to know, grouped so the signature stays legible.
    struct Query<'a> {
        function: Node<'a>,
        source: &'a str,
        name: &'a str,
        /// A definition after the use cannot be the one that reaches it.
        before: usize,
        sink_cwe: Option<&'a str>,
        depth: usize,
    }

    fn scan_scope(scope: Node<'_>, query: &Query<'_>, result: &mut Option<Taint>) {
        let Query {
            function,
            source,
            name,
            before,
            sink_cwe,
            depth,
        } = *query;
        walk(scope, &mut |node| {
            let assigned = match node.kind() {
                // JavaScript, Java
                "variable_declarator" => node
                    .child_by_field_name("name")
                    .filter(|target| text(*target, source) == name)
                    .and(node.child_by_field_name("value")),
                // Rust
                "let_declaration" => node
                    .child_by_field_name("pattern")
                    .filter(|target| text(*target, source) == name)
                    .and(node.child_by_field_name("value")),
                // Python, Go (`=` and `:=`)
                "assignment" | "assignment_expression" | "short_var_declaration" => node
                    .child_by_field_name("left")
                    .filter(|target| text(*target, source) == name)
                    .and(node.child_by_field_name("right")),
                _ => None,
            };
            if let Some(value) = assigned {
                // A definition after the use cannot be the one that reaches it.
                if value.start_byte() <= before {
                    let taint =
                        classify_with_depth(value, source, Some(function), sink_cwe, depth + 1);
                    // Any tainted reaching definition wins: over-approximating
                    // toward reporting is the safe direction.
                    *result = Some(match *result {
                        // A tainted reaching definition already wins; keep it.
                        Some(existing @ Taint::Tainted { .. }) => existing,
                        Some(previous) => combine(previous, taint),
                        None => taint,
                    });
                }
            }
        });
    }

    let query = Query {
        function,
        source,
        name,
        before,
        sink_cwe,
        depth,
    };
    let mut result = None;
    scan_scope(function, &query, &mut result);
    if result.is_none() {
        // Widen to the file for module-level constants.
        let mut root = function;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        scan_scope(root, &query, &mut result);
    }
    result.unwrap_or(Taint::Unknown)
}

/// Turn what the analysis worked out into answers to the falsification gates.
///
/// The gate model treats a finding as a candidate until something tries to
/// disprove it. This is that attempt, written down in the same vocabulary a
/// human reviewer uses, so its reasoning can be checked rather than trusted.
///
/// These are *suggestions*, never decisions. The review form starts from them
/// and a person submits it — the same line the assistant is held to.
pub fn gate_notes(taint: Taint, sink_cwe: Option<&str>) -> Vec<crate::triage::gates::GateNote> {
    use crate::triage::gates::{Gate, GateNote, GateVerdict};

    match taint {
        Taint::Tainted { origin } => vec![GateNote {
            gate: Gate::AttackerControlled,
            verdict: GateVerdict::Survives,
            evidence: match origin {
                Origin::External => "The value reaching this sink traces to a request, argv, or \
                                     another inbound source within the same function."
                    .to_string(),
                Origin::Parameter => "The value reaching this sink traces to a parameter of the \
                                      enclosing function. Whether a caller supplies attacker data \
                                      is not visible from here."
                    .to_string(),
            },
        }],
        Taint::SanitizedElsewhere { by, covers } => vec![GateNote {
            gate: Gate::Sanitized,
            // Survives, not eliminates: sanitization is present and does not
            // cover this weakness, which is the trap worth naming.
            verdict: GateVerdict::Survives,
            evidence: format!(
                "The value passes through `{by}()`, which neutralizes {covers} and not {}. \
                 Sanitization is present on this path but does not cover this sink.",
                sink_cwe.unwrap_or("this weakness")
            ),
        }],
        // Constant and Sanitized never reach a reviewer: the finding is not
        // reported at all, so there is nothing to pre-fill.
        Taint::Constant | Taint::Sanitized { .. } | Taint::Unknown => Vec::new(),
    }
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
        taint_for_cwe(source, language, needle, None)
    }

    /// As above, but stating the weakness class the sink describes — which is
    /// what decides whether a transform counts as sanitizing it.
    fn taint_for_cwe(source: &str, language: &str, needle: &str, cwe: Option<&str>) -> Taint {
        let offset = source.find(needle).expect("needle present in fixture");
        syntax::parse(source, language).taint_at(source, offset, cwe)
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
        assert_eq!(
            taint_of(source, "javascript", "eval("),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );

        let python = "def compute(expression):\n    return eval(expression)\n";
        assert_eq!(
            taint_of(python, "python", "eval("),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );
    }

    #[test]
    fn request_data_is_tainted() {
        let source = "function h(req) { return eval(req.body.expr); }\n";
        assert_eq!(
            taint_of(source, "javascript", "eval("),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_name_bound_to_request_data_is_tainted() {
        let source = "function h(req) { const e = req.body.expr; return eval(e); }\n";
        assert_eq!(
            taint_of(source, "javascript", "eval("),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_reading_call_is_tainted() {
        let python = "def f():\n    return eval(input())\n";
        assert_eq!(
            taint_of(python, "python", "eval("),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_constant_combined_with_a_parameter_is_tainted() {
        // Concatenating a literal onto attacker input does not sanitize it.
        let source = "function f(userInput) { return eval(\"x = \" + userInput); }\n";
        assert_eq!(
            taint_of(source, "javascript", "eval("),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );
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

    // ------------------------------------------------------------ sanitizers

    #[test]
    fn a_sanitizer_matched_to_the_sink_neutralizes_it() {
        // parseInt cannot return anything carrying code.
        let source = "function f(userInput) { return eval(parseInt(userInput, 10)); }\n";
        assert!(matches!(
            taint_for_cwe(source, "javascript", "eval(", Some("CWE-95")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn a_sanitizer_for_a_different_weakness_does_not_excuse_the_sink() {
        // The property that makes this feature safe rather than dangerous.
        // escapeHtml neutralizes markup and does nothing about code execution,
        // so this is still a live RCE and must not be suppressed.
        let source = "function f(userInput) { return eval(escapeHtml(userInput)); }\n";
        let taint = taint_for_cwe(source, "javascript", "eval(", Some("CWE-95"));
        assert!(
            !matches!(taint, Taint::Sanitized { .. } | Taint::Constant),
            "escapeHtml must not excuse a code-execution sink, got {taint:?}"
        );
    }

    #[test]
    fn the_same_sanitizer_does_excuse_the_sink_it_covers() {
        // The mirror of the test above: escapeHtml is genuine protection for
        // an XSS sink, and recognising it there is the whole point.
        let source = "function f(userInput) { return render(escapeHtml(userInput)); }\n";
        assert!(matches!(
            taint_for_cwe(source, "javascript", "render(", Some("CWE-79")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn shell_quoting_covers_command_injection_and_nothing_else() {
        let source = "import shlex\ndef f(user):\n    return os.system(shlex.quote(user))\n";
        assert!(matches!(
            taint_for_cwe(source, "python", "system(", Some("CWE-78")),
            Taint::Sanitized { .. }
        ));
        // The same call is not protection against code execution.
        assert!(!matches!(
            taint_for_cwe(source, "python", "system(", Some("CWE-95")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn a_sink_with_no_weakness_class_is_never_sanitized() {
        // Without a CWE there is nothing to match against, so no transform can
        // be shown to neutralize it. Abstaining keeps the finding.
        let source = "function f(userInput) { return eval(parseInt(userInput)); }\n";
        assert!(!matches!(
            taint_for_cwe(source, "javascript", "eval(", None),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn sanitizing_happens_even_when_the_inner_value_is_attacker_controlled() {
        // The inner read is tainted; the coercion is what matters.
        let source = "def f():\n    return eval(int(input()))\n";
        assert!(matches!(
            taint_for_cwe(source, "python", "eval(", Some("CWE-95")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn a_sanitized_value_concatenated_with_a_constant_stays_sanitized() {
        let source = "function f(u) { return eval(\"x=\" + parseInt(u)); }\n";
        assert!(matches!(
            taint_for_cwe(source, "javascript", "eval(", Some("CWE-95")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn a_sanitized_value_concatenated_with_tainted_input_is_tainted() {
        // Sanitizing one half of a concatenation protects nothing.
        let source = "function f(u) { return eval(parseInt(u) + u); }\n";
        assert_eq!(
            taint_for_cwe(source, "javascript", "eval(", Some("CWE-95")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );
    }

    #[test]
    fn an_unrecognised_transform_is_not_treated_as_protection() {
        // A function named like a sanitizer but not on the list must not be
        // assumed to do anything. Guessing here is a false negative.
        let source = "function f(u) { return eval(makeSafe(u)); }\n";
        assert!(!matches!(
            taint_for_cwe(source, "javascript", "eval(", Some("CWE-95")),
            Taint::Sanitized { .. }
        ));
    }

    #[test]
    fn every_sanitizer_declares_at_least_one_weakness_class() {
        // An entry covering nothing can never match, which would be a silently
        // dead table row rather than an error.
        for entry in SANITIZERS {
            assert!(
                !entry.neutralizes.is_empty(),
                "{} neutralizes nothing",
                entry.name
            );
        }
    }

    // ---------------------------------------------------------- gate notes

    #[test]
    fn a_mismatched_sanitizer_is_reported_rather_than_ignored() {
        // The most useful thing the analysis can say: sanitization is present
        // on this path and does not cover this sink. Someone wrote that call
        // believing it made the line safe.
        let source = "function f(u) { return eval(escapeHtml(u)); }\n";
        let taint = taint_for_cwe(source, "javascript", "eval(", Some("CWE-95"));
        assert!(
            matches!(
                taint,
                Taint::SanitizedElsewhere {
                    by: "escapeHtml",
                    ..
                }
            ),
            "got {taint:?}"
        );
    }

    #[test]
    fn a_mismatched_sanitizer_answers_the_sanitized_gate_without_eliminating() {
        use crate::triage::gates::{Gate, GateVerdict};
        let taint = Taint::SanitizedElsewhere {
            by: "escapeHtml",
            covers: "CWE-79",
        };
        let notes = gate_notes(taint, Some("CWE-95"));
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].gate, Gate::Sanitized);
        // Survives, not eliminates: sanitization that does not cover the sink
        // must never read as a reason to dismiss the finding.
        assert_eq!(notes[0].verdict, GateVerdict::Survives);
        assert!(notes[0].evidence.contains("escapeHtml"));
        assert!(notes[0].evidence.contains("CWE-79"));
        assert!(notes[0].evidence.contains("CWE-95"));
    }

    #[test]
    fn tainted_input_answers_the_attacker_controlled_gate() {
        use crate::triage::gates::{Gate, GateVerdict};
        let notes = gate_notes(
            Taint::Tainted {
                origin: Origin::Parameter,
            },
            Some("CWE-95"),
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].gate, Gate::AttackerControlled);
        assert_eq!(notes[0].verdict, GateVerdict::Survives);
        assert!(!notes[0].evidence.is_empty());
    }

    #[test]
    fn a_suppressed_finding_contributes_no_gate_notes() {
        // Constant and Sanitized never reach a reviewer, so there is nothing
        // to pre-fill and nothing to explain.
        assert!(gate_notes(Taint::Constant, Some("CWE-95")).is_empty());
        assert!(gate_notes(Taint::Sanitized { by: "parseInt" }, Some("CWE-95")).is_empty());
    }

    #[test]
    fn an_undetermined_value_suggests_nothing() {
        // Abstaining beats inventing an answer a reviewer might trust.
        assert!(gate_notes(Taint::Unknown, Some("CWE-95")).is_empty());
    }

    #[test]
    fn no_note_ever_claims_to_eliminate_a_finding() {
        use crate::triage::gates::GateVerdict;
        // The machine argues; the human decides. An eliminating verdict is a
        // dismissal, and the review model requires a person to make one.
        for taint in [
            Taint::Tainted {
                origin: Origin::Parameter,
            },
            Taint::Unknown,
            Taint::Constant,
            Taint::Sanitized { by: "parseInt" },
            Taint::SanitizedElsewhere {
                by: "escapeHtml",
                covers: "CWE-79",
            },
        ] {
            for note in gate_notes(taint, Some("CWE-95")) {
                assert_ne!(
                    note.verdict,
                    GateVerdict::Eliminates,
                    "{taint:?} produced an eliminating verdict"
                );
            }
        }
    }

    // --------------------------------------------------- chains and languages

    #[test]
    fn a_fluent_chain_is_judged_by_every_argument_in_it() {
        // Command::new("sh") is flagged for spawning a shell, but the value an
        // attacker chooses arrives later. Reading only the first call saw
        // "sh", called it constant, and dropped the finding.
        let tainted =
            "fn run(user: &str) {\n    Command::new(\"sh\").arg(\"-lc\").arg(user).status();\n}\n";
        assert_eq!(
            taint_for_cwe(tainted, "rust", "Command::new", Some("CWE-78")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );

        let fixed = "fn run() {\n    Command::new(\"sh\").arg(\"-lc\").arg(\"ls\").status();\n}\n";
        assert_eq!(
            taint_for_cwe(fixed, "rust", "Command::new", Some("CWE-78")),
            Taint::Constant
        );
    }

    #[test]
    fn java_chains_through_its_receiver() {
        let tainted =
            "class A { void f(String userInput) { Runtime.getRuntime().exec(userInput); } }";
        assert_eq!(
            taint_for_cwe(tainted, "java", "Runtime.getRuntime", Some("CWE-78")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );

        let fixed = "class A { void f() { Runtime.getRuntime().exec(\"ls -la\"); } }";
        assert_eq!(
            taint_for_cwe(fixed, "java", "Runtime.getRuntime", Some("CWE-78")),
            Taint::Constant
        );
    }

    #[test]
    fn go_reads_arguments_beyond_the_first() {
        // exec.Command("sh", "-c", user): the danger is the third argument.
        let tainted = "package main\nfunc f(user string) { exec.Command(\"sh\", \"-c\", user) }\n";
        assert_eq!(
            taint_for_cwe(tainted, "go", "exec.Command", Some("CWE-78")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );

        let fixed = "package main\nfunc f() { exec.Command(\"sh\", \"-c\", \"ls\") }\n";
        assert_eq!(
            taint_for_cwe(fixed, "go", "exec.Command", Some("CWE-78")),
            Taint::Constant
        );
    }

    #[test]
    fn a_keyword_argument_is_judged_by_its_value() {
        // `shell=True` is configuration, not data. Reading it as undetermined
        // kept every subprocess finding the analysis had actually cleared.
        let source = "import subprocess\ndef f():\n    subprocess.run(\"ls -la\", shell=True)\n";
        assert_eq!(
            taint_for_cwe(source, "python", "subprocess.run", Some("CWE-78")),
            Taint::Constant
        );
    }

    #[test]
    fn a_call_in_argument_position_does_not_extend_the_chain() {
        // eval(escapeHtml(u)) must classify escapeHtml as an argument, not walk
        // into it as though it were a chained call.
        let source = "function f(u) { return eval(escapeHtml(u)); }\n";
        assert!(matches!(
            taint_for_cwe(source, "javascript", "eval(", Some("CWE-95")),
            Taint::SanitizedElsewhere { .. }
        ));
    }

    #[test]
    fn one_tainted_argument_taints_the_whole_call() {
        let source = "function f(u) { return exec(\"prefix\", u, \"suffix\"); }\n";
        assert_eq!(
            taint_for_cwe(source, "javascript", "exec(", Some("CWE-78")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );
    }

    #[test]
    fn a_type_name_is_not_mistaken_for_a_parameter() {
        // `String userInput` puts two identifiers in the parameter list. A
        // variable called String must not read as attacker-controlled.
        let source = "class A { void f(String userInput) { exec(String); } }";
        assert_ne!(
            taint_for_cwe(source, "java", "exec(", Some("CWE-78")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );
    }

    // ---------------------------------------------------------------- origin

    #[test]
    fn a_parameter_and_a_request_are_distinguished() {
        // The distinction that decides whether SSRF and path traversal are
        // reportable at all.
        let parameter = "function f(url) { return fetch(url); }\n";
        assert_eq!(
            taint_for_cwe(parameter, "javascript", "fetch(", Some("CWE-918")),
            Taint::Tainted {
                origin: Origin::Parameter
            }
        );

        let request = "function f(req) { return fetch(req.query.target); }\n";
        assert_eq!(
            taint_for_cwe(request, "javascript", "fetch(", Some("CWE-918")),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn only_some_weakness_classes_need_an_external_origin() {
        // Evaluating a caller-supplied string is the defect whoever calls it.
        // Fetching a caller-supplied URL is an HTTP helper's whole purpose.
        assert!(requires_external_origin(Some("CWE-918")));
        assert!(requires_external_origin(Some("CWE-22")));
        assert!(!requires_external_origin(Some("CWE-95")));
        assert!(!requires_external_origin(Some("CWE-78")));
        assert!(!requires_external_origin(None));
    }

    #[test]
    fn an_external_source_beats_a_parameter_when_combined() {
        let source = "function f(req, prefix) { return fetch(prefix + req.query.p); }\n";
        assert_eq!(
            taint_for_cwe(source, "javascript", "fetch(", Some("CWE-918")),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_framework_request_read_is_external() {
        // Named methods rather than receiver names: `r` in Go and `ctx` in
        // several frameworks are far too common to treat as request objects.
        let go = "package main\nfunc p(r *http.Request) { t := r.FormValue(\"t\"); http.Get(t) }\n";
        assert_eq!(
            taint_for_cwe(go, "go", "http.Get(", Some("CWE-918")),
            Taint::Tainted {
                origin: Origin::External
            }
        );

        let java = "class D { void f(HttpServletRequest request) { new File(\"/d/\" + request.getParameter(\"n\")); } }";
        assert_eq!(
            taint_for_cwe(java, "java", "new File", Some("CWE-22")),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_call_rooted_at_a_request_object_is_external() {
        // `request.args.get(...)` is a call, so the member branch never sees
        // it; the root of the callee chain is what carries the meaning.
        let source = "from flask import request\ndef f():\n    return requests.get(request.args.get(\"t\"))\n";
        assert_eq!(
            taint_for_cwe(source, "python", "requests.get(", Some("CWE-918")),
            Taint::Tainted {
                origin: Origin::External
            }
        );
    }

    #[test]
    fn a_go_binding_resolves_through_its_expression_list() {
        // Go wraps both sides of `a := b` in an expression_list, so every Go
        // binding resolved to Unknown until that wrapper was looked through.
        let source = "package main\nfunc f() { x := \"literal\"; eval(x) }\n";
        assert_eq!(
            taint_for_cwe(source, "go", "eval(", Some("CWE-95")),
            Taint::Constant
        );
    }

    // ------------------------------------------- what the finding refers to

    #[test]
    fn a_call_with_no_arguments_is_unknown_not_constant() {
        // Nothing was passed, so nothing was proven safe. Treating "no
        // arguments" as "constant arguments" silently suppressed every
        // `new Random()` and `DocumentBuilderFactory.newInstance()` — the
        // weaknesses that are *about* the call rather than its inputs.
        assert_eq!(
            taint_of("const r = new Random();\n", "javascript", "new Random("),
            Taint::Unknown
        );
        assert_eq!(
            taint_of(
                "var f = DocumentBuilderFactory.newInstance();\n",
                "java",
                "newInstance("
            ),
            Taint::Unknown
        );
    }

    #[test]
    fn a_finding_nested_in_an_argument_is_not_judged_by_that_call() {
        // The assignment is not the call. Reading `useEffect`'s arguments to
        // classify `innerHTML` suppressed real XSS findings for a reason that
        // had nothing to do with them.
        let source = "useEffect(() => { node.innerHTML = untrusted; }, []);\n";
        assert_eq!(taint_of(source, "javascript", "innerHTML"), Taint::Unknown);
    }

    #[test]
    fn a_finding_that_names_the_call_is_still_judged_by_its_arguments() {
        // The counterpart: the guard above must not blind the analysis to the
        // ordinary case, including a constant reached through a chain.
        assert_eq!(
            taint_of("wrapper(eval(\"2 + 2\"));\n", "javascript", "eval("),
            Taint::Constant
        );
        assert_eq!(
            taint_of(
                "Runtime.getRuntime().exec(\"ls -la\");\n",
                "java",
                "Runtime.getRuntime().exec"
            ),
            Taint::Constant
        );
    }

    #[test]
    fn a_constructor_argument_is_still_reached_through_the_guard() {
        // `new File(..)` spells its callee with a type rather than a
        // `function` field; classifying it by exclusion keeps it working.
        let source = "class D { File r(HttpServletRequest q) { return new File(\"/var/\" + q.getParameter(\"n\")); } }\n";
        assert!(matches!(
            taint_for_cwe(source, "java", "new File(", Some("CWE-22")),
            Taint::Tainted {
                origin: Origin::External
            }
        ));
    }
}

#[cfg(test)]
mod php_taint_tests {
    use super::*;
    use crate::scanners::syntax;

    fn taint_of(source: &str, language: &str, needle: &str) -> Taint {
        let offset = source.find(needle).expect("needle present in fixture");
        syntax::parse(source, language).taint_at(source, offset, None)
    }

    #[test]
    fn php_superglobals_are_external_input() {
        // Without these, every PHP request value read as merely Unknown, so
        // the attacker-control gate had nothing to say about the one language
        // where the source of untrusted data is spelled unambiguously.
        assert!(matches!(
            taint_of("<?php\neval($_GET['x']);\n", "php", "eval("),
            Taint::Tainted {
                origin: Origin::External
            }
        ));
        assert!(matches!(
            taint_of("<?php\nunserialize($_POST['s']);\n", "php", "unserialize("),
            Taint::Tainted {
                origin: Origin::External
            }
        ));
    }

    #[test]
    fn a_php_literal_is_still_constant() {
        assert_eq!(
            taint_of("<?php\neval(\"2 + 2\");\n", "php", "eval("),
            Taint::Constant
        );
    }
}

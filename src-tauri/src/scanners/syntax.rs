//! Syntax-aware suppression for the pattern scanners.
//!
//! A regex over raw file text cannot tell the difference between code and a
//! sentence about code. Measured against the committed corpus, that was the
//! single largest source of false positives: `js-eval` fired on
//! `// Never call eval(userInput) here` and on
//! `const WARNING = "Do not use eval(...)"`, both of which are a developer
//! *warning others off* the exact thing being reported.
//!
//! This module parses the file and reports the byte ranges covered by comments
//! and string literals, so a match landing inside one can be dropped.
//!
//! Two properties are deliberate:
//!
//! * **Unsupported languages are not suppressed.** When there is no grammar, no
//!   spans are returned and every match stands. Guessing at comment syntax
//!   would risk suppressing a real finding, and a false negative in a security
//!   scanner is worse than a false positive.
//! * **Strings are suppressed for code rules only.** Secret rules exist to find
//!   credentials, and a credential in source is almost always *inside* a string
//!   literal. Suppressing strings there would delete the entire point.

use std::ops::Range;

use tree_sitter::{Node, Parser};

/// What a match was found inside, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// Ordinary code.
    Code,
    /// A line or block comment.
    Comment,
    /// A string, template, or character literal.
    StringLiteral,
}

/// One parse of one file: the comment and string spans, plus the tree the
/// dataflow analysis queries.
///
/// The tree is retained rather than dropped because parsing is roughly forty
/// times the cost of rule matching, and a second parse for taint would double
/// the most expensive part of a scan.
pub struct FileSyntax {
    spans: SyntaxSpans,
    tree: Option<tree_sitter::Tree>,
}

impl FileSyntax {
    pub fn spans(&self) -> &SyntaxSpans {
        &self.spans
    }

    /// How many arguments the call at `offset` was given, when the finding
    /// names a call at all.
    ///
    /// `None` when there is no grammar, no enclosing call, or the finding sits
    /// inside a call rather than naming one — every case where the count would
    /// be answering a question nobody asked.
    pub fn argument_count_at(&self, offset: usize) -> Option<usize> {
        use super::dataflow;
        let tree = self.tree.as_ref()?;
        let call = dataflow::enclosing_call(tree.root_node(), offset)?;
        if !dataflow::names_the_call(call, offset) {
            return None;
        }
        Some(dataflow::chain_arguments(call).len())
    }

    /// Byte ranges of this file that exist only for tests.
    ///
    /// Path classification is right about which files are tests and says
    /// nothing about position — which is the whole problem for a Rust
    /// `#[cfg(test)]` module sitting at the bottom of a production file.
    pub fn test_regions(&self, content: &str, language: &str) -> Vec<std::ops::Range<usize>> {
        let Some(tree) = &self.tree else {
            return Vec::new();
        };
        super::testscope::test_regions(tree.root_node(), content, language)
    }

    /// Can an attacker choose the value reaching the sink at `offset`?
    ///
    /// `sink_cwe` is the weakness class the matched rule describes. It is what
    /// makes sanitizer recognition safe: a transform only excuses a sink whose
    /// weakness it actually neutralizes, so `escapeHtml` never excuses `eval`.
    ///
    /// `Unknown` whenever there is no grammar, no enclosing call, or the value
    /// cannot be traced — every one of those keeps the finding.
    pub fn taint_at(
        &self,
        content: &str,
        offset: usize,
        sink_cwe: Option<&str>,
    ) -> super::dataflow::Taint {
        use super::dataflow::{self, Taint};
        let Some(tree) = &self.tree else {
            return Taint::Unknown;
        };
        let root = tree.root_node();
        let Some(call) = dataflow::enclosing_call(root, offset) else {
            return Taint::Unknown;
        };
        // Argument taint only means something when the finding *is* the call.
        if !dataflow::names_the_call(call, offset) {
            return Taint::Unknown;
        }
        let arguments = dataflow::chain_arguments(call);
        if arguments.is_empty() {
            // Nothing to reason about. Previously this returned Constant on
            // the grounds that a call taking nothing cannot be fed anything —
            // true for eval-style sinks, and wrong for the rules where the
            // call itself is the defect. `DocumentBuilderFactory.newInstance()`
            // and `new Random()` take no arguments and are exactly the finding,
            // and both were being suppressed.
            return Taint::Unknown;
        }
        let function = dataflow::enclosing_function(root, offset);
        // One tainted argument taints the call: a fluent chain is a single
        // expression as far as an attacker is concerned.
        dataflow::combine_all(
            arguments.into_iter().map(|argument| {
                dataflow::classify_expression(argument, content, function, sink_cwe)
            }),
        )
    }
}

/// Byte ranges of comments and string literals in one file.
#[derive(Debug, Default, Clone)]
pub struct SyntaxSpans {
    comments: Vec<Range<usize>>,
    strings: Vec<Range<usize>>,
    /// False when no grammar covered this file, so nothing may be suppressed.
    analyzed: bool,
}

impl SyntaxSpans {
    /// Whether a grammar was available and the file parsed.
    pub fn analyzed(&self) -> bool {
        self.analyzed
    }

    /// Classify a byte offset within the file.
    pub fn context_at(&self, offset: usize) -> Context {
        if !self.analyzed {
            return Context::Code;
        }
        if self.comments.iter().any(|span| span.contains(&offset)) {
            return Context::Comment;
        }
        if self.strings.iter().any(|span| span.contains(&offset)) {
            return Context::StringLiteral;
        }
        Context::Code
    }

    /// Should a source-pattern match at this offset be reported?
    ///
    /// Comments and string literals both describe code rather than being it.
    pub fn allows_code_match(&self, offset: usize) -> bool {
        matches!(self.context_at(offset), Context::Code)
    }

    /// Should a secret match at this offset be reported?
    ///
    /// Comments are suppressed — a credential named in a comment is usually
    /// prose about credentials. Strings are not, because a hardcoded secret is
    /// a string literal by definition.
    pub fn allows_secret_match(&self, offset: usize) -> bool {
        !matches!(self.context_at(offset), Context::Comment)
    }

    /// Does hardening at this offset count as actually applied?
    ///
    /// Comments are suppressed — `// TODO: switch to defusedxml` is a plan,
    /// not a mitigation. String literals are *not*, because a string literal
    /// is how most hardening is spelled:
    /// `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
    /// puts the only evidence of the fix inside a quoted feature URI. Reusing
    /// the stricter code-only test here made the guard unfirable for the
    /// commonest form of the fix it exists to recognise.
    pub fn allows_hardening_match(&self, offset: usize) -> bool {
        !matches!(self.context_at(offset), Context::Comment)
    }
}

/// The grammar for a language, if this build carries one.
///
/// Returning `None` is a normal outcome, not a failure: it means matches in
/// this file are reported without syntax filtering. That is also what a build
/// compiled without a grammar's feature does, so a stripped binary loses
/// precision and never recall — see [`compiled_grammars`] for what is present.
fn language_for(language: &str) -> Option<tree_sitter::Language> {
    match language {
        #[cfg(feature = "grammar-javascript")]
        "javascript" | "typescript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        #[cfg(feature = "grammar-python")]
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        #[cfg(feature = "grammar-java")]
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        #[cfg(feature = "grammar-rust")]
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        #[cfg(feature = "grammar-go")]
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        // PHP's crate ships two grammars: the full one expects `<?php` tags,
        // which is what a scanned `.php` file actually contains.
        #[cfg(feature = "grammar-php")]
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        #[cfg(feature = "grammar-ruby")]
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        #[cfg(feature = "grammar-c")]
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        #[cfg(feature = "grammar-cpp")]
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        #[cfg(feature = "grammar-csharp")]
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        #[cfg(feature = "grammar-kotlin")]
        "kotlin" => Some(tree_sitter_kotlin_ng::LANGUAGE.into()),
        #[cfg(feature = "grammar-swift")]
        "swift" => Some(tree_sitter_swift::LANGUAGE.into()),
        _ => None,
    }
}

/// Every language this build can parse, in a stable order.
///
/// Reported rather than assumed: a binary built without a grammar scans that
/// language on text alone, and a benchmark run against it will score
/// differently for a reason that is not the scanner. The corpus builder
/// already learned that lesson the expensive way — twelve fixtures scored as
/// misses because an extension map was missing three entries, and the report
/// blamed recall.
pub fn compiled_grammars() -> &'static [&'static str] {
    &[
        #[cfg(feature = "grammar-javascript")]
        "javascript",
        #[cfg(feature = "grammar-javascript")]
        "typescript",
        #[cfg(feature = "grammar-python")]
        "python",
        #[cfg(feature = "grammar-java")]
        "java",
        #[cfg(feature = "grammar-rust")]
        "rust",
        #[cfg(feature = "grammar-go")]
        "go",
        #[cfg(feature = "grammar-php")]
        "php",
        #[cfg(feature = "grammar-ruby")]
        "ruby",
        #[cfg(feature = "grammar-c")]
        "c",
        #[cfg(feature = "grammar-cpp")]
        "cpp",
        #[cfg(feature = "grammar-csharp")]
        "csharp",
        #[cfg(feature = "grammar-kotlin")]
        "kotlin",
        #[cfg(feature = "grammar-swift")]
        "swift",
    ]
}

/// Languages that get syntax filtering, for reporting a rule's confidence.
pub fn is_supported(language: &str) -> bool {
    language_for(language).is_some()
}

/// Node kinds that are comments across the supported grammars.
fn is_comment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "comment"
            | "line_comment"
            | "block_comment"
            // Rust doc comments carry the remediation advice that most often
            // names the very construct a rule looks for.
            | "doc_comment"
            | "outer_doc_comment_marker"
            | "inner_doc_comment_marker"
            // Swift names its block comment separately.
            | "multiline_comment"
    )
}

/// Node kinds that are string-like across the supported grammars.
///
/// Interpolated templates are included: the literal parts are text, and while
/// an interpolation can contain real code, a source rule matching *inside* a
/// template is far more often prose than a live sink.
fn is_string_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "string_fragment"
            | "template_string"
            | "raw_string_literal"
            | "character_literal"
            | "concatenated_string"
            // Rust
            | "string_content"
            // Go
            | "interpreted_string_literal"
            | "raw_string_literal_content"
            | "interpreted_string_literal_content"
            // PHP: `encapsed_string` is the double-quoted form, which is the
            // one that carries prose. Heredocs are marked whole so the body
            // and its delimiters go together.
            | "encapsed_string"
            | "heredoc"
            | "heredoc_body"
            // Ruby: `%w[..]` word arrays, and a heredoc whose body the grammar
            // hangs beside the assignment rather than inside it.
            | "bare_string"
            | "string_array"
            | "heredoc_content"
            // C and C++ spell a character literal differently from Rust and
            // Java, and C++ raw strings carry their content in a child.
            | "char_literal"
            | "raw_string_content"
            // C#: verbatim (@"..") and interpolated ($"..") strings are
            // distinct node kinds from the plain literal.
            | "string_literal_content"
            | "verbatim_string_literal"
            | "interpolated_string_expression"
            | "character_literal_content"
            // Kotlin and Swift triple-quoted strings.
            | "multiline_string_literal"
            | "multi_line_str_text"
            // Swift's ordinary "..." literal and its text.
            | "line_string_literal"
            | "line_str_text"
    )
}

/// Parse `content` and collect comment and string spans.
///
/// A file that fails to parse yields un-analyzed spans rather than an error:
/// oxAudit scans whatever it is pointed at, including files mid-edit and files
/// in dialects the grammar does not accept, and refusing to scan those would
/// trade a false positive for a blind spot.
pub fn analyze(content: &str, language: &str) -> SyntaxSpans {
    parse(content, language).spans
}

/// Parse once and keep the tree for both span queries and taint queries.
pub fn parse(content: &str, language: &str) -> FileSyntax {
    let unparsed = FileSyntax {
        spans: SyntaxSpans::default(),
        tree: None,
    };
    let Some(grammar) = language_for(language) else {
        return unparsed;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return unparsed;
    }
    let Some(tree) = parser.parse(content, None) else {
        return unparsed;
    };

    let mut spans = SyntaxSpans {
        analyzed: true,
        ..Default::default()
    };
    collect(tree.root_node(), &mut spans);
    FileSyntax {
        spans,
        tree: Some(tree),
    }
}

/// Walk the tree, recording comment and string ranges.
///
/// Iterative rather than recursive: a deeply nested file from a scan target
/// must not be able to exhaust the stack, which is the same property the
/// pom.xml parser is held to.
fn collect(root: Node<'_>, spans: &mut SyntaxSpans) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if is_comment_kind(kind) {
            spans.comments.push(node.byte_range());
            // Nothing inside a comment needs finer classification.
            continue;
        }
        if is_string_kind(kind) {
            spans.strings.push(node.byte_range());
            // Keep descending: a template literal's interpolations are code,
            // and the enclosing span already covers the textual parts.
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte offset of `needle` in `haystack`, for pointing at a specific match.
    fn offset_of(haystack: &str, needle: &str) -> usize {
        haystack.find(needle).expect("needle present in fixture")
    }

    #[test]
    fn an_unsupported_language_suppresses_nothing() {
        // The safe direction: no grammar means every match stands. Guessing at
        // comment syntax could hide a real finding.
        let spans = analyze("# eval( in something we cannot parse", "brainfuck");
        assert!(!spans.analyzed());
        assert!(spans.allows_code_match(0));
        assert_eq!(spans.context_at(0), Context::Code);
    }

    #[test]
    fn javascript_line_comments_are_recognised() {
        let source = "// never call eval(x) here\nrun();\n";
        let spans = analyze(source, "javascript");
        assert!(spans.analyzed());
        assert_eq!(
            spans.context_at(offset_of(source, "eval(x)")),
            Context::Comment
        );
        assert!(!spans.allows_code_match(offset_of(source, "eval(x)")));
    }

    #[test]
    fn javascript_block_comments_are_recognised() {
        let source = "/*\n * eval(x) was removed\n */\nrun();\n";
        let spans = analyze(source, "javascript");
        assert_eq!(
            spans.context_at(offset_of(source, "eval(x)")),
            Context::Comment
        );
    }

    #[test]
    fn javascript_string_literals_are_recognised() {
        let source = "const WARNING = \"do not use eval(...) on input\";\n";
        let spans = analyze(source, "javascript");
        assert_eq!(
            spans.context_at(offset_of(source, "eval(...)")),
            Context::StringLiteral
        );
        assert!(!spans.allows_code_match(offset_of(source, "eval(...)")));
    }

    #[test]
    fn real_code_is_left_alone() {
        let source = "function render(input) {\n  return eval(input);\n}\n";
        let spans = analyze(source, "javascript");
        assert_eq!(
            spans.context_at(offset_of(source, "eval(input)")),
            Context::Code
        );
        assert!(spans.allows_code_match(offset_of(source, "eval(input)")));
    }

    #[test]
    fn python_comments_and_docstrings_are_recognised() {
        let source =
            "# eval(x) is forbidden\ndef f():\n    \"\"\"Do not eval(y).\"\"\"\n    return 1\n";
        let spans = analyze(source, "python");
        assert_eq!(
            spans.context_at(offset_of(source, "eval(x)")),
            Context::Comment
        );
        assert_eq!(
            spans.context_at(offset_of(source, "eval(y)")),
            Context::StringLiteral
        );
    }

    #[test]
    fn java_comments_are_recognised() {
        let source =
            "class A {\n  // Runtime.getRuntime().exec(cmd) was removed\n  void f() {}\n}\n";
        let spans = analyze(source, "java");
        assert_eq!(
            spans.context_at(offset_of(source, "Runtime.getRuntime")),
            Context::Comment
        );
    }

    #[test]
    fn secrets_are_still_found_inside_strings() {
        // A hardcoded credential is a string literal by definition. Suppressing
        // strings for secret rules would delete the entire point of them.
        let source = "const key = \"Zx8Z2vQ4mNbR7tYuI1oP3aS5dF6gH9jK\";\n";
        let spans = analyze(source, "javascript");
        let offset = offset_of(source, "Zx8Z");
        assert_eq!(spans.context_at(offset), Context::StringLiteral);
        assert!(spans.allows_secret_match(offset));
        assert!(!spans.allows_code_match(offset));
    }

    #[test]
    fn secrets_named_in_a_comment_are_suppressed() {
        let source = "// password = \"hunter2istheexample\"\nconnect();\n";
        let spans = analyze(source, "javascript");
        assert!(!spans.allows_secret_match(offset_of(source, "hunter2")));
    }

    #[test]
    fn a_file_that_does_not_parse_cleanly_still_yields_usable_spans() {
        // tree-sitter recovers from errors rather than refusing, so a file
        // mid-edit is still analysed. What matters is that it does not panic
        // and does not claim spans it has not seen.
        let source = "function broken( {\n  // eval(x)\n";
        let spans = analyze(source, "javascript");
        assert!(spans.analyzed());
        assert_eq!(
            spans.context_at(offset_of(source, "eval(x)")),
            Context::Comment
        );
    }

    #[test]
    fn deeply_nested_input_does_not_exhaust_the_stack() {
        // The walk is iterative for the same reason the pom.xml parser is:
        // a scan target can be hostile, and nesting depth must cost heap.
        let source = format!("{}1{}", "[".repeat(20_000), "]".repeat(20_000));
        let spans = analyze(&source, "javascript");
        assert!(spans.analyzed());
    }

    #[test]
    fn empty_input_is_handled() {
        let spans = analyze("", "python");
        assert!(spans.analyzed());
        assert_eq!(spans.context_at(0), Context::Code);
    }

    #[test]
    fn the_test_suite_assumes_every_grammar_is_compiled_in() {
        // Most of this suite asserts what a grammar does with a language, and
        // those tests cannot pass without it. Rather than let a reduced build
        // produce dozens of confusing failures, say the one true thing once.
        //
        // `cargo build --no-default-features` is supported and checked in CI;
        // `cargo test` is not, and expects the default feature set.
        assert_eq!(
            compiled_grammars().len(),
            13,
            "the test suite expects every grammar; run `cargo test` without \
             --no-default-features or a reduced --features set"
        );
    }

    #[test]
    fn every_compiled_grammar_actually_parses() {
        // A feature that adds a dependency but no match arm would leave the
        // language listed and unparsed, which is the one inconsistency the
        // listing itself cannot reveal.
        for language in compiled_grammars() {
            assert!(
                is_supported(language),
                "{language} is listed but not parsed"
            );
        }
    }

    #[test]
    fn supported_languages_are_reported_accurately() {
        assert!(is_supported("javascript"));
        assert!(is_supported("python"));
        assert!(is_supported("java"));
        assert!(is_supported("rust"));
        assert!(is_supported("go"));
        assert!(is_supported("php"));
        assert!(is_supported("ruby"));
        assert!(is_supported("c"));
        assert!(is_supported("cpp"));
        // Detected by extension and scanned on text alone: a language oxAudit
        // routes findings for but carries no grammar behind.
        assert!(!is_supported("shell"));
        assert!(!is_supported("sql"));
        assert!(!is_supported(""));
    }

    #[test]
    fn rust_doc_comments_and_strings_are_recognised() {
        // The shape that survived every earlier fix: a detector whose doc
        // comment and pattern constant both name what it searches for.
        let source = concat!(
            "/// Redacts PEM private keys before a finding leaves the process.\n",
            "pub const PEM_HEADER: &str = \"-----BEGIN RSA PRIVATE KEY-----\";\n",
        );
        let spans = analyze(source, "rust");
        assert!(spans.analyzed());
        assert_eq!(
            spans.context_at(offset_of(source, "PEM private keys")),
            Context::Comment
        );
        assert_eq!(
            spans.context_at(offset_of(source, "-----BEGIN RSA")),
            Context::StringLiteral
        );
    }

    #[test]
    fn rust_sql_in_a_string_is_not_a_code_match() {
        let source = "let _ = connection.execute(\"UPDATE runs SET version = \", []);\n";
        let spans = analyze(source, "rust");
        assert!(!spans.allows_code_match(offset_of(source, "UPDATE runs")));
    }

    #[test]
    fn go_comments_and_strings_are_recognised() {
        let source = "package main\n// exec.Command(\"sh\") was removed\nvar warn = \"avoid exec.Command\"\n";
        let spans = analyze(source, "go");
        assert!(spans.analyzed());
        assert_eq!(
            spans.context_at(offset_of(source, "exec.Command(")),
            Context::Comment
        );
    }
}

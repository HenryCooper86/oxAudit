//! Which *regions of a file* exist only for tests.
//!
//! Path classification answers "which file", and it is right about files. It
//! is silent about position, and in a Rust codebase that silence is the
//! difference between a usable report and a noisy one: `#[cfg(test)]` modules
//! live at the bottom of the production file they exercise, so every fake
//! credential in them was reported at full production priority. On oxAudit's
//! own source that was 25 of 32 findings — the largest single category of
//! benign results, all of them indistinguishable from real ones.
//!
//! Reclassifying *hides* findings from the default view, so every signal here
//! is one the compiler or a test framework enforces, never a naming habit:
//!
//! * **Rust** — `#[cfg(test)]` and `#[test]`. The strongest signal available
//!   anywhere: `#[cfg(test)]` code is not compiled into a release binary, so a
//!   credential inside one cannot ship.
//! * **Java** — JUnit's `@Test` family, including the lifecycle annotations,
//!   because fixtures are usually built in `@BeforeEach`.
//! * **Python** — `def test_*` and `class Test*`, which is what pytest and
//!   unittest actually collect on.
//! * **Go** — `func TestXxx(t *testing.T)`, requiring the `testing` parameter
//!   rather than trusting the name.
//! * **PHP** — PHPUnit's two collection forms: methods named `test*` and
//!   methods carrying the `#[Test]` attribute.
//! * **Ruby** — Minitest's `def test_*` and RSpec's `describe`/`context`/
//!   `it`/`specify` block calls, requiring an actual block.
//!
//! JavaScript and TypeScript are deliberately absent. `describe`/`it`/`test`
//! are ordinary identifiers that a non-test file may legitimately define, and
//! the path rules already catch `.test.ts`, `.spec.ts`, and `__tests__/`. The
//! marginal recall was not worth a rule that could hide a real finding in
//! application code. Ruby's block calls survive this bar only because the
//! `block` field is required: a bare `describe` with no block is not matched.

use std::ops::Range;

use tree_sitter::Node;

/// Byte ranges covered by test-only constructs.
///
/// Empty for a language with no rule here, which leaves every finding at
/// whatever the path said — the same "never suppress on a guess" default the
/// rest of the syntax layer uses.
pub fn test_regions(root: Node<'_>, content: &str, language: &str) -> Vec<Range<usize>> {
    let mut regions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_test_region(node, content, language) {
            regions.push(node.byte_range());
            // Nothing inside a test region needs a second reason to be one.
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    regions
}

fn text<'a>(node: Node<'_>, content: &'a str) -> &'a str {
    content.get(node.byte_range()).unwrap_or("")
}

fn is_test_region(node: Node<'_>, content: &str, language: &str) -> bool {
    match language {
        "rust" => rust_test_item(node, content),
        "java" => java_test_member(node, content),
        "python" => python_test_definition(node, content),
        "go" => go_test_function(node, content),
        "php" => php_test_method(node, content),
        "ruby" => ruby_test_construct(node, content),
        // c/cpp/csharp/kotlin/swift have no single framework-enforced idiom
        // this layer can prove, so they stay on path classification alone —
        // the same default as JavaScript above.
        _ => false,
    }
}

/// A Rust item carrying `#[cfg(test)]` or `#[test]`.
///
/// Attributes are preceding siblings rather than children, so this walks back
/// over the run of them immediately above the item.
fn rust_test_item(node: Node<'_>, content: &str) -> bool {
    if !matches!(node.kind(), "mod_item" | "function_item") {
        return false;
    }
    let mut sibling = node.prev_named_sibling();
    while let Some(attribute) = sibling {
        if attribute.kind() != "attribute_item" {
            return false;
        }
        if marks_a_test(text(attribute, content)) {
            return true;
        }
        sibling = attribute.prev_named_sibling();
    }
    false
}

/// Does this attribute's source say "test only"?
///
/// `#[cfg(not(test))]` is the opposite claim and must not match — it marks
/// code that exists in *release* builds and nowhere else.
fn marks_a_test(attribute: &str) -> bool {
    let compact: String = attribute.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("not(test)") {
        return false;
    }
    compact == "#[test]" || compact.contains("cfg(test)")
}

const JUNIT_ANNOTATIONS: [&str; 7] = [
    "Test",
    "ParameterizedTest",
    "RepeatedTest",
    "BeforeEach",
    "AfterEach",
    "BeforeAll",
    "AfterAll",
];

fn java_test_member(node: Node<'_>, content: &str) -> bool {
    if node.kind() != "method_declaration" {
        return false;
    }
    // `modifiers` is an ordinary child in this grammar, not a labelled field.
    let mut children = node.walk();
    let Some(modifiers) = node
        .children(&mut children)
        .find(|child| child.kind() == "modifiers")
    else {
        return false;
    };
    let mut cursor = modifiers.walk();
    // Bound rather than returned directly: the iterator borrows `cursor`,
    // which must outlive it.
    let annotated = modifiers.children(&mut cursor).any(|child| {
        if !matches!(child.kind(), "marker_annotation" | "annotation") {
            return false;
        }
        child
            .child_by_field_name("name")
            .map(|name| text(name, content))
            .is_some_and(|name| JUNIT_ANNOTATIONS.contains(&name))
    });
    annotated
}

fn python_test_definition(node: Node<'_>, content: &str) -> bool {
    let Some(name) = node.child_by_field_name("name") else {
        return false;
    };
    let name = text(name, content);
    match node.kind() {
        "function_definition" => name.starts_with("test_"),
        "class_definition" => name.starts_with("Test"),
        _ => false,
    }
}

/// `func TestXxx(t *testing.T)`, keyed on the parameter rather than the name.
///
/// A function called `TestConnection` that takes no `testing` parameter is
/// ordinary code, and Go codebases have plenty of those.
fn go_test_function(node: Node<'_>, content: &str) -> bool {
    if node.kind() != "function_declaration" {
        return false;
    }
    let named_for_testing = node
        .child_by_field_name("name")
        .map(|name| text(name, content))
        .is_some_and(|name| {
            ["Test", "Benchmark", "Fuzz", "Example"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        });
    if !named_for_testing {
        return false;
    }
    node.child_by_field_name("parameters")
        .map(|parameters| text(parameters, content))
        .is_some_and(|parameters| parameters.contains("testing."))
}

/// A PHPUnit method: named `test*` or carrying the `#[Test]` attribute.
///
/// PHPUnit collects both forms, and both are method-level — the class itself
/// stays production code so a helper method in `FooTest` is not silenced.
fn php_test_method(node: Node<'_>, content: &str) -> bool {
    if node.kind() != "method_declaration" {
        return false;
    }
    let named_for_phpunit = node
        .child_by_field_name("name")
        .map(|name| text(name, content))
        .is_some_and(|name| name.starts_with("test"));
    if named_for_phpunit {
        return true;
    }
    // `#[Test]` sits in an `attributes` field as attribute_list →
    // attribute_group → attribute, and only the attribute's name matters.
    let Some(attributes) = node.child_by_field_name("attributes") else {
        return false;
    };
    let mut stack = vec![attributes];
    while let Some(current) = stack.pop() {
        if current.kind() == "attribute"
            && current
                .child(0)
                .is_some_and(|name| text(name, content) == "Test")
        {
            return true;
        }
        let mut cursor = current.walk();
        for child in current.children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

/// Minitest's `def test_*` and RSpec's `describe`/`context`/`it`/`specify`
/// block calls.
///
/// A block call without a block is an ordinary method call, so the `block`
/// field is required — `describe` on its own proves nothing.
fn ruby_test_construct(node: Node<'_>, content: &str) -> bool {
    match node.kind() {
        "method" => node
            .child_by_field_name("name")
            .map(|name| text(name, content))
            .is_some_and(|name| name.starts_with("test_")),
        "call" => {
            node.child_by_field_name("block").is_some()
                && node
                    .child_by_field_name("method")
                    .map(|method| text(method, content))
                    .is_some_and(|method| {
                        ["describe", "context", "it", "specify"].contains(&method)
                    })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::scanners::syntax;

    /// Does the offset of `needle` fall inside a test region?
    fn in_test_region(source: &str, language: &str, needle: &str) -> bool {
        let offset = source.find(needle).expect("needle present in fixture");
        syntax::parse(source, language)
            .test_regions(source, language)
            .iter()
            .any(|region| region.contains(&offset))
    }

    #[test]
    fn a_rust_cfg_test_module_is_a_test_region() {
        let source = concat!(
            "pub fn redact(input: &str) -> String { input.to_string() }\n",
            "\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const TOKEN: &str = \"ghp_realistic_looking_value\";\n",
            "}\n",
        );
        assert!(in_test_region(source, "rust", "ghp_realistic"));
        // The production function above it is untouched.
        assert!(!in_test_region(source, "rust", "pub fn redact"));
    }

    #[test]
    fn a_bare_rust_test_function_is_a_test_region() {
        let source = "#[test]\nfn checks() { let key = \"AKIAIOSFODNN7EXAMPLE\"; }\n";
        assert!(in_test_region(source, "rust", "AKIA"));
    }

    #[test]
    fn cfg_not_test_is_the_opposite_claim() {
        // This marks code that exists *only* in release builds. Treating it as
        // a test region would hide findings from the one place they ship.
        let source = "#[cfg(not(test))]\nmod live {\n    const TOKEN: &str = \"ghp_x\";\n}\n";
        assert!(!in_test_region(source, "rust", "ghp_x"));
    }

    #[test]
    fn an_ordinary_rust_module_is_not_a_test_region() {
        let source = "mod tests {\n    const TOKEN: &str = \"ghp_x\";\n}\n";
        assert!(!in_test_region(source, "rust", "ghp_x"));
    }

    #[test]
    fn an_attribute_run_is_searched_past_the_first() {
        let source =
            "#[allow(dead_code)]\n#[cfg(test)]\nmod tests {\n    const T: &str = \"x\";\n}\n";
        assert!(in_test_region(source, "rust", "\"x\""));
    }

    #[test]
    fn junit_annotations_mark_a_java_method() {
        let source = concat!(
            "class ClientTest {\n",
            "  @BeforeEach\n",
            "  void setUp() { String key = \"AKIAIOSFODNN7EXAMPLE\"; }\n",
            "  void helper() { String other = \"AKIAIOSFODNN7OTHER\"; }\n",
            "}\n",
        );
        assert!(in_test_region(source, "java", "AKIAIOSFODNN7EXAMPLE"));
        // An unannotated method in the same class is not covered.
        assert!(!in_test_region(source, "java", "AKIAIOSFODNN7OTHER"));
    }

    #[test]
    fn pytest_naming_marks_python_definitions() {
        let source =
            "def test_login():\n    token = \"ghp_x\"\n\ndef login():\n    real = \"ghp_y\"\n";
        assert!(in_test_region(source, "python", "ghp_x"));
        assert!(!in_test_region(source, "python", "ghp_y"));
    }

    #[test]
    fn go_needs_the_testing_parameter_not_just_the_name() {
        let real = "func TestConnection(host string) {\n\tk := \"ghp_x\"\n}\n";
        assert!(!in_test_region(real, "go", "ghp_x"));
        let test = "func TestConnection(t *testing.T) {\n\tk := \"ghp_y\"\n}\n";
        assert!(in_test_region(test, "go", "ghp_y"));
    }

    #[test]
    fn javascript_is_left_to_the_path_rules() {
        let source = "describe('auth', () => {\n  const token = 'ghp_x';\n});\n";
        assert!(!in_test_region(source, "javascript", "ghp_x"));
    }

    #[test]
    fn phpunit_naming_marks_a_php_method() {
        let source = concat!(
            "<?php\n",
            "class FooTest extends TestCase {\n",
            "    public function testItWorks() { $k = 'ghp_x'; }\n",
            "    public function helper() { $k = 'ghp_y'; }\n",
            "}\n",
        );
        assert!(in_test_region(source, "php", "ghp_x"));
        assert!(!in_test_region(source, "php", "ghp_y"));
    }

    #[test]
    fn phpunit_attribute_marks_a_php_method() {
        let source = concat!(
            "<?php\n",
            "class FooTest extends TestCase {\n",
            "    #[Test]\n",
            "    public function itWorks(): void { $k = 'ghp_x'; }\n",
            "}\n",
        );
        assert!(in_test_region(source, "php", "ghp_x"));
    }

    #[test]
    fn minitest_naming_marks_a_ruby_method() {
        let source = "def test_login\n  token = 'ghp_x'\nend\ndef login\n  x = 'ghp_y'\nend\n";
        assert!(in_test_region(source, "ruby", "ghp_x"));
        assert!(!in_test_region(source, "ruby", "ghp_y"));
    }

    #[test]
    fn rspec_block_calls_mark_a_ruby_region() {
        let source = concat!(
            "describe 'auth' do\n",
            "  it 'works' do\n",
            "    k = 'ghp_x'\n",
            "  end\n",
            "end\n",
            "specify 'thing' do\n",
            "  s = 'ghp_y'\n",
            "end\n",
            "context 'scope' do\n",
            "  c = 'ghp_z'\n",
            "end\n",
        );
        assert!(in_test_region(source, "ruby", "ghp_x"));
        assert!(in_test_region(source, "ruby", "ghp_y"));
        assert!(in_test_region(source, "ruby", "ghp_z"));
    }

    #[test]
    fn a_bare_ruby_call_without_a_block_is_not_a_test_region() {
        let source = "it 'works'\nk = 'ghp_x'\n";
        assert!(!in_test_region(source, "ruby", "ghp_x"));
    }

    #[test]
    fn a_language_without_a_grammar_reports_nothing() {
        let source = "# [cfg(test)]\nsecret = 'ghp_x'\n";
        assert!(syntax::parse(source, "brainfuck")
            .test_regions(source, "brainfuck")
            .is_empty());
    }
}

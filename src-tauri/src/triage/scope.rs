//! Which files a finding is worth reporting from.
//!
//! oxAudit already has an `ignoredDirs` list, but it is a blunt instrument: it
//! decides what to *scan*, and it treats every excluded directory alike.
//! VulnHunter's production-code rule is more careful, and the part worth taking
//! is its exception — configuration for security-relevant infrastructure stays
//! in scope even though it sits among files that otherwise would not, because a
//! misconfigured `set_real_ip_from` is a real finding and a fixture password is
//! not.
//!
//! This is advisory. It ranks and annotates rather than deleting: a hardcoded
//! credential in a test fixture is usually noise, but "usually" is not "always",
//! and a scanner that silently discards is worse than one that sorts.

use serde::{Deserialize, Serialize};

use crate::findings::domain::FindingScope;

pub type Scope = FindingScope;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDecision {
    pub scope: FindingScope,
    pub reason: String,
}

impl FindingScope {
    /// Should a finding here be shown by default?
    pub fn is_reportable(self) -> bool {
        matches!(
            self,
            FindingScope::Production | FindingScope::Infrastructure | FindingScope::Unknown
        )
    }
}

const VENDORED: [&str; 8] = [
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "external",
    "site-packages",
    "bower_components",
    "Pods",
];

const FIXTURES: [&str; 3] = ["fixtures", "fixture", "testdata"];

const TESTS: [&str; 5] = ["test", "tests", "spec", "specs", "__tests__"];

const GENERATED: [&str; 6] = ["dist", "build", "target", "out", "generated", ".next"];

const DOCS: [&str; 5] = ["docs", "doc", "examples", "example", "samples"];

/// Configuration whose contents are a security control in their own right.
const INFRASTRUCTURE_FILES: [&str; 10] = [
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".htaccess",
    "sshd_config",
    "pg_hba.conf",
    "my.cnf",
];

fn segments(path: &str) -> Option<Vec<String>> {
    let parts: Vec<String> = path
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .map(|part| part.to_ascii_lowercase())
        .collect();
    if parts.is_empty() || parts.iter().any(|part| part == "..") {
        None
    } else {
        Some(parts)
    }
}

/// Classify a path.
///
/// Infrastructure is checked first and deliberately outranks every exclusion:
/// an `nginx.conf` under `test/` is still a file whose contents describe who
/// gets to be trusted, and a rule that hides it is a rule that hides real
/// findings.
pub fn classify(path: &str) -> ScopeDecision {
    classify_at(path, false)
}

/// Classify a path, given what the scanner saw at the finding's position.
///
/// `in_test_region` is true when the finding sits inside a construct the
/// language marks as test-only — a Rust `#[cfg(test)]` module, a JUnit `@Test`
/// method. Path alone cannot see this, and in Rust it is the common case:
/// `#[cfg(test)]` modules live at the bottom of the production file they
/// exercise, so their fixture credentials were reported at production
/// priority.
///
/// It is consulted at the same precedence as a test *path*, and deliberately
/// no higher. A `#[cfg(test)]` module inside `node_modules` is somebody else's
/// code first, and an `nginx.conf` is infrastructure wherever it sits.
pub fn classify_at(path: &str, in_test_region: bool) -> ScopeDecision {
    let Some(parts) = segments(path) else {
        return ScopeDecision {
            scope: Scope::Unknown,
            reason: "unknown-path".into(),
        };
    };
    let file_name = parts.last().expect("non-empty paths have a file name");

    if INFRASTRUCTURE_FILES.contains(&file_name.as_str())
        || file_name.starts_with("dockerfile")
        || file_name.ends_with(".tf")
        || file_name.ends_with(".tfvars")
    {
        return ScopeDecision {
            scope: Scope::Infrastructure,
            reason: "infrastructure-file".into(),
        };
    }

    let directories = &parts[..parts.len().saturating_sub(1)];
    let has = |set: &[&str]| directories.iter().any(|part| set.contains(&part.as_str()));

    // Vendored before test: a test directory inside node_modules is somebody
    // else's problem, and reporting it as ours is noise either way.
    if has(&VENDORED) {
        return ScopeDecision {
            scope: Scope::Vendored,
            reason: "vendored-directory".into(),
        };
    }
    if has(&FIXTURES) {
        return ScopeDecision {
            scope: Scope::Fixture,
            reason: "fixture-directory".into(),
        };
    }
    if has(&TESTS)
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.go")
        // Rust names a test-only file `foo_test.rs` or `foo_tests.rs` and
        // declares it `#[cfg(test)] mod foo_tests;` from its parent. The
        // marker lives in the *other* file, so nothing inside this one can be
        // seen to be test-only — the name is the only local evidence there is.
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_tests.rs")
    {
        return ScopeDecision {
            scope: Scope::Test,
            reason: "test-name".into(),
        };
    }
    if in_test_region {
        return ScopeDecision {
            scope: Scope::Test,
            reason: "test-module".into(),
        };
    }
    if file_name.ends_with(".min.js") || file_name.ends_with(".pb.go") {
        return ScopeDecision {
            scope: Scope::Generated,
            reason: "generated-file-name".into(),
        };
    }
    if has(&GENERATED) {
        return ScopeDecision {
            scope: Scope::Generated,
            reason: "generated-directory".into(),
        };
    }
    if has(&DOCS) {
        return ScopeDecision {
            scope: Scope::Documentation,
            reason: "documentation-directory".into(),
        };
    }
    ScopeDecision {
        scope: Scope::Production,
        reason: "production-default".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_source_is_production() {
        assert_eq!(classify("src/auth/login.rs").scope, Scope::Production);
        assert_eq!(
            classify("app/controllers/users_controller.rb").scope,
            Scope::Production
        );
    }

    #[test]
    fn tests_and_fixtures_are_separated_from_shipping_code() {
        assert_eq!(classify("tests/fixtures/keys.json").scope, Scope::Fixture);
        assert_eq!(classify("src/auth/login.test.ts").scope, Scope::Test);
        assert_eq!(classify("pkg/auth/login_test.go").scope, Scope::Test);
        assert_eq!(classify("api/test_handlers.py").scope, Scope::Test);
    }

    #[test]
    fn vendored_code_outranks_a_test_directory_inside_it() {
        // node_modules/foo/test/… is not our test suite, and calling it one
        // suggests it is worth fixing.
        assert_eq!(
            classify("node_modules/foo/test/index.js").scope,
            Scope::Vendored
        );
        assert_eq!(
            classify("vendor/github.com/x/y/y.go").scope,
            Scope::Vendored
        );
    }

    #[test]
    fn infrastructure_config_stays_in_scope_even_under_a_test_directory() {
        // The deliberate exception, and the reason this is not just an
        // ignore-list: an nginx.conf describes who is trusted, wherever it sits.
        assert_eq!(classify("tests/nginx.conf").scope, Scope::Infrastructure);
        assert_eq!(classify("deploy/Dockerfile").scope, Scope::Infrastructure);
        assert_eq!(classify("infra/main.tf").scope, Scope::Infrastructure);
        assert!(classify("tests/nginx.conf").scope.is_reportable());
    }

    #[test]
    fn generated_output_is_not_reported() {
        assert_eq!(classify("dist/bundle.min.js").scope, Scope::Generated);
        assert_eq!(classify("target/debug/build.rs").scope, Scope::Generated);
        assert_eq!(classify("api/service.pb.go").scope, Scope::Generated);
    }

    #[test]
    fn generated_file_name_rules_record_the_file_name_rationale() {
        for path in ["dist/bundle.min.js", "api/service.pb.go"] {
            assert_eq!(
                classify(path),
                ScopeDecision {
                    scope: FindingScope::Generated,
                    reason: "generated-file-name".into(),
                },
                "{path}"
            );
        }
        assert_eq!(
            classify("build/bundle.js"),
            ScopeDecision {
                scope: FindingScope::Generated,
                reason: "generated-directory".into(),
            }
        );
    }

    #[test]
    fn documentation_is_not_reported() {
        assert_eq!(
            classify("docs/getting-started.md").scope,
            Scope::Documentation
        );
        assert_eq!(classify("examples/demo.py").scope, Scope::Documentation);
    }

    #[test]
    fn production_infrastructure_and_unknown_are_reportable_by_default() {
        assert!(Scope::Production.is_reportable());
        assert!(Scope::Infrastructure.is_reportable());
        assert!(Scope::Unknown.is_reportable());
        for scope in [
            Scope::Test,
            Scope::Vendored,
            Scope::Generated,
            Scope::Documentation,
            Scope::Fixture,
        ] {
            assert!(
                !scope.is_reportable(),
                "{scope:?} should be filtered by default"
            );
        }
    }

    #[test]
    fn a_directory_named_like_an_exclusion_does_not_match_a_file_of_that_name() {
        // `src/test.rs` is production code with an unfortunate name; only a
        // path *segment* counts.
        assert_eq!(classify("src/test.rs").scope, Scope::Production);
        assert_eq!(classify("src/vendor.rs").scope, Scope::Production);
    }

    #[test]
    fn windows_separators_are_understood() {
        assert_eq!(classify(r"src\auth\login.test.ts").scope, Scope::Test);
        assert_eq!(
            classify(r"node_modules\foo\index.js").scope,
            Scope::Vendored
        );
    }

    #[test]
    fn classification_records_the_deciding_reason_and_unknown_paths() {
        assert_eq!(
            classify("tests/nginx.conf"),
            ScopeDecision {
                scope: FindingScope::Infrastructure,
                reason: "infrastructure-file".into(),
            }
        );
        assert_eq!(
            classify("vendor/pkg/test/a.js"),
            ScopeDecision {
                scope: FindingScope::Vendored,
                reason: "vendored-directory".into(),
            }
        );
        assert_eq!(
            classify("tests/fixtures/key.json"),
            ScopeDecision {
                scope: FindingScope::Fixture,
                reason: "fixture-directory".into(),
            }
        );
        assert_eq!(
            classify(""),
            ScopeDecision {
                scope: FindingScope::Unknown,
                reason: "unknown-path".into(),
            }
        );
        assert_eq!(
            classify("src/../test.rs"),
            ScopeDecision {
                scope: FindingScope::Unknown,
                reason: "unknown-path".into(),
            }
        );
        assert_eq!(
            classify("src/test.rs"),
            ScopeDecision {
                scope: FindingScope::Production,
                reason: "production-default".into(),
            }
        );
    }

    #[test]
    fn windows_paths_and_generated_or_documentation_directories_keep_stable_reasons() {
        assert_eq!(
            classify(r"build\bundle.js"),
            ScopeDecision {
                scope: FindingScope::Generated,
                reason: "generated-directory".into(),
            }
        );
        assert_eq!(
            classify(r"docs\guide.md"),
            ScopeDecision {
                scope: FindingScope::Documentation,
                reason: "documentation-directory".into(),
            }
        );
    }
}

#[cfg(test)]
mod position_tests {
    use super::*;

    #[test]
    fn a_test_module_in_a_production_file_is_test_scope() {
        // The gap this exists to close: path says production and is right
        // about the file, while the finding sits in `#[cfg(test)]`.
        let decision = classify_at("src-tauri/src/observability.rs", true);
        assert_eq!(decision.scope, Scope::Test);
        assert_eq!(decision.reason, "test-module");
    }

    #[test]
    fn the_same_file_without_the_signal_is_still_production() {
        let decision = classify_at("src-tauri/src/observability.rs", false);
        assert_eq!(decision.scope, Scope::Production);
        assert_eq!(decision.reason, "production-default");
    }

    #[test]
    fn infrastructure_still_outranks_a_test_module() {
        // A parser generating an nginx.conf inside a test helper does not make
        // the file's contents stop describing who gets to be trusted.
        assert_eq!(
            classify_at("deploy/nginx.conf", true).scope,
            Scope::Infrastructure
        );
    }

    #[test]
    fn vendored_still_outranks_a_test_module() {
        let decision = classify_at("node_modules/left-pad/index.rs", true);
        assert_eq!(decision.scope, Scope::Vendored);
        assert_eq!(decision.reason, "vendored-directory");
    }

    #[test]
    fn a_test_path_keeps_its_own_reason() {
        // Both signals agree; the more specific explanation is the file name.
        let decision = classify_at("src/auth/login_test.go", true);
        assert_eq!(decision.scope, Scope::Test);
        assert_eq!(decision.reason, "test-name");
    }

    #[test]
    fn classify_is_classify_at_without_the_signal() {
        for path in [
            "src/auth/login.rs",
            "node_modules/x/index.js",
            "docs/guide.md",
            "deploy/nginx.conf",
        ] {
            assert_eq!(classify(path), classify_at(path, false));
        }
    }
}

#[cfg(test)]
mod rust_test_file_tests {
    use super::*;

    #[test]
    fn rust_test_file_suffixes_are_test_scope() {
        for path in [
            "src-tauri/src/findings/service_tests.rs",
            "src-tauri/src/findings/policy_test.rs",
        ] {
            assert_eq!(classify(path).scope, Scope::Test, "{path}");
        }
    }

    #[test]
    fn an_ordinary_rust_file_is_unaffected() {
        // The suffix must be a word boundary, not a substring: `latest.rs`
        // ends in "test" and is ordinary code.
        for path in [
            "src/latest.rs",
            "src/contest.rs",
            "src/manifest.rs",
            "src/protests.rs",
        ] {
            assert_eq!(classify(path).scope, Scope::Production, "{path}");
        }
    }
}

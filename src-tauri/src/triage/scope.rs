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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    /// Code that ships and runs.
    Production,
    /// Tests and fixtures.
    Test,
    /// Third-party code vendored into the tree.
    Vendored,
    /// Machine-generated output.
    Generated,
    /// Documentation and examples.
    Documentation,
    /// Infrastructure configuration. Not production *code*, but security
    /// relevant, so it is deliberately not lumped in with the rest.
    Infrastructure,
}

impl Scope {
    /// Should a finding here be shown by default?
    pub fn is_reportable(self) -> bool {
        matches!(self, Scope::Production | Scope::Infrastructure)
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

const TESTS: [&str; 8] = [
    "test",
    "tests",
    "spec",
    "specs",
    "fixtures",
    "fixture",
    "testdata",
    "__tests__",
];

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

fn segments(path: &str) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .map(|part| part.to_ascii_lowercase())
        .collect()
}

/// Classify a path.
///
/// Infrastructure is checked first and deliberately outranks every exclusion:
/// an `nginx.conf` under `test/` is still a file whose contents describe who
/// gets to be trusted, and a rule that hides it is a rule that hides real
/// findings.
pub fn classify(path: &str) -> Scope {
    let parts = segments(path);
    let Some(file_name) = parts.last() else {
        return Scope::Production;
    };

    if INFRASTRUCTURE_FILES.contains(&file_name.as_str())
        || file_name.starts_with("dockerfile")
        || file_name.ends_with(".tf")
        || file_name.ends_with(".tfvars")
    {
        return Scope::Infrastructure;
    }

    let directories = &parts[..parts.len().saturating_sub(1)];
    let has = |set: &[&str]| directories.iter().any(|part| set.contains(&part.as_str()));

    // Vendored before test: a test directory inside node_modules is somebody
    // else's problem, and reporting it as ours is noise either way.
    if has(&VENDORED) {
        return Scope::Vendored;
    }
    if has(&TESTS)
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.go")
    {
        return Scope::Test;
    }
    if has(&GENERATED) || file_name.ends_with(".min.js") || file_name.ends_with(".pb.go") {
        return Scope::Generated;
    }
    if has(&DOCS) {
        return Scope::Documentation;
    }
    Scope::Production
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_source_is_production() {
        assert_eq!(classify("src/auth/login.rs"), Scope::Production);
        assert_eq!(classify("app/controllers/users_controller.rb"), Scope::Production);
    }

    #[test]
    fn tests_and_fixtures_are_separated_from_shipping_code() {
        assert_eq!(classify("tests/fixtures/keys.json"), Scope::Test);
        assert_eq!(classify("src/auth/login.test.ts"), Scope::Test);
        assert_eq!(classify("pkg/auth/login_test.go"), Scope::Test);
        assert_eq!(classify("api/test_handlers.py"), Scope::Test);
    }

    #[test]
    fn vendored_code_outranks_a_test_directory_inside_it() {
        // node_modules/foo/test/… is not our test suite, and calling it one
        // suggests it is worth fixing.
        assert_eq!(classify("node_modules/foo/test/index.js"), Scope::Vendored);
        assert_eq!(classify("vendor/github.com/x/y/y.go"), Scope::Vendored);
    }

    #[test]
    fn infrastructure_config_stays_in_scope_even_under_a_test_directory() {
        // The deliberate exception, and the reason this is not just an
        // ignore-list: an nginx.conf describes who is trusted, wherever it sits.
        assert_eq!(classify("tests/nginx.conf"), Scope::Infrastructure);
        assert_eq!(classify("deploy/Dockerfile"), Scope::Infrastructure);
        assert_eq!(classify("infra/main.tf"), Scope::Infrastructure);
        assert!(classify("tests/nginx.conf").is_reportable());
    }

    #[test]
    fn generated_output_is_not_reported() {
        assert_eq!(classify("dist/bundle.min.js"), Scope::Generated);
        assert_eq!(classify("target/debug/build.rs"), Scope::Generated);
        assert_eq!(classify("api/service.pb.go"), Scope::Generated);
    }

    #[test]
    fn documentation_is_not_reported() {
        assert_eq!(classify("docs/getting-started.md"), Scope::Documentation);
        assert_eq!(classify("examples/demo.py"), Scope::Documentation);
    }

    #[test]
    fn only_production_and_infrastructure_are_reportable_by_default() {
        assert!(Scope::Production.is_reportable());
        assert!(Scope::Infrastructure.is_reportable());
        for scope in [Scope::Test, Scope::Vendored, Scope::Generated, Scope::Documentation] {
            assert!(!scope.is_reportable(), "{scope:?} should be filtered by default");
        }
    }

    #[test]
    fn a_directory_named_like_an_exclusion_does_not_match_a_file_of_that_name() {
        // `src/test.rs` is production code with an unfortunate name; only a
        // path *segment* counts.
        assert_eq!(classify("src/test.rs"), Scope::Production);
        assert_eq!(classify("src/vendor.rs"), Scope::Production);
    }

    #[test]
    fn windows_separators_are_understood() {
        assert_eq!(classify(r"src\auth\login.test.ts"), Scope::Test);
        assert_eq!(classify(r"node_modules\foo\index.js"), Scope::Vendored);
    }
}

//! `.oxaudit/config.toml`: the repository's own `scan` and `deps` settings.
//!
//! CI, the pre-commit hook, the GitHub Action and the VS Code extension all
//! run the CLI, so settings committed here apply to all of them without
//! repeating flags. An explicit flag always wins over the file, and the file
//! wins over the built-in default; ignore lists are the exception and are
//! combined. The file is strict: an unknown key is an error rather than a
//! setting that silently does nothing, because a misspelt gate would loosen
//! the build without anyone noticing.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use super::FailOn;

/// Why the config could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file is wrong (bad TOML, unknown key, refused file): a usage
    /// error, exit 2.
    Invalid(String),
    /// The file or its directory exists but cannot be read: a failure,
    /// exit 3, as an unreadable `.oxaudit` was before the config existed.
    Unreadable(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Unreadable(message) => f.write_str(message),
        }
    }
}

/// Where the file lives, relative to the scan root.
pub const PROJECT_CONFIG_PATH: &str = ".oxaudit/config.toml";
const FILE_NAME: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// A validated project config.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProjectConfig {
    pub scan: ScanConfig,
    pub deps: DepsConfig,
}

/// `[scan]`: settings for `scan` and `scan --staged`.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    #[serde(default)]
    pub ignore_dirs: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<FailOn>,
    #[serde(default)]
    pub fail_on_new: Option<FailOn>,
    #[serde(default)]
    pub max_file_size_kb: Option<u64>,
    #[serde(default)]
    pub secrets: Option<bool>,
    #[serde(default)]
    pub patterns: Option<bool>,
    /// Resolved to canonical paths inside the root by the loader.
    #[serde(default)]
    pub rule_pack_files: Vec<PathBuf>,
}

/// `[deps]`: settings for `deps`.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsConfig {
    #[serde(default)]
    pub ignore_dirs: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<FailOn>,
    #[serde(default)]
    pub fail_on_new: Option<FailOn>,
}

/// Read `<root>/.oxaudit/config.toml`. `Ok(None)` when there is none; an
/// `Err` names what is wrong, and callers treat it as a usage error.
pub fn load_project_config(root: &Path) -> Result<Option<ProjectConfig>, ConfigError> {
    let invalid =
        |reason: String| ConfigError::Invalid(format!("invalid {PROJECT_CONFIG_PATH}: {reason}"));
    use crate::findings::policy::ProjectFileError;
    let bytes = match crate::findings::policy::read_project_file(root, FILE_NAME, MAX_CONFIG_BYTES)
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(None),
        Err(ProjectFileError::Refused(reason)) => {
            return Err(ConfigError::Invalid(format!(
                "{PROJECT_CONFIG_PATH} {reason}"
            )))
        }
        Err(ProjectFileError::Unreadable(reason)) => {
            return Err(ConfigError::Unreadable(format!(
                "{PROJECT_CONFIG_PATH} {reason}"
            )))
        }
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("it is not UTF-8".into()))?;
    let raw: RawConfig = toml::from_str(text).map_err(|error| {
        // Point at the line, so the fix is one look away.
        let line = error
            .span()
            .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
        match line {
            Some(line) => invalid(format!("line {line}: {}", error.message())),
            None => invalid(error.message().to_string()),
        }
    })?;
    match raw.version {
        Some(1) => {}
        Some(other) => {
            return Err(invalid(format!(
                "version {other} is not supported; use version = 1"
            )))
        }
        None => return Err(invalid("version = 1 is required".into())),
    }
    let mut scan = raw.scan;
    scan.rule_pack_files = scan
        .rule_pack_files
        .iter()
        .map(|path| rule_pack_inside(root, path))
        .collect::<Result<_, _>>()
        .map_err(invalid)?;
    Ok(Some(ProjectConfig {
        scan,
        deps: raw.deps,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    version: Option<u16>,
    #[serde(default)]
    scan: ScanConfig,
    #[serde(default)]
    deps: DepsConfig,
}

/// A rule pack named by the config: relative, no `..`, and still inside the
/// root once symlinks are resolved — a committed file must not reach out of
/// the repository it configures.
fn rule_pack_inside(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let shown = path.display();
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!(
            "rule_pack_files entry {shown} must be a relative path inside the project"
        ));
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("the project root cannot be resolved: {error}"))?;
    let resolved = root
        .join(path)
        .canonicalize()
        .map_err(|error| format!("rule_pack_files entry {shown} cannot be read: {error}"))?;
    if !resolved.starts_with(&canonical_root) {
        return Err(format!(
            "rule_pack_files entry {shown} resolves outside the project"
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(root: &Path, body: &str) {
        std::fs::create_dir_all(root.join(".oxaudit")).unwrap();
        std::fs::write(root.join(PROJECT_CONFIG_PATH), body).unwrap();
    }

    fn error(root: &Path, body: &str) -> String {
        write_config(root, body);
        load_project_config(root).expect_err(body).to_string()
    }

    #[test]
    fn a_missing_config_is_none() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(load_project_config(root.path()), Ok(None));
        std::fs::create_dir(root.path().join(".oxaudit")).unwrap();
        assert_eq!(load_project_config(root.path()), Ok(None));
    }

    #[test]
    fn a_full_config_parses_every_key() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("security")).unwrap();
        std::fs::write(root.path().join("security/team-rules.toml"), "").unwrap();
        write_config(
            root.path(),
            r#"
version = 1

[scan]
ignore_dirs = ["node_modules", "target", "dist"]
fail_on = "high"
fail_on_new = "medium"
max_file_size_kb = 2048
secrets = true
patterns = false
rule_pack_files = ["security/team-rules.toml"]

[deps]
ignore_dirs = ["examples"]
fail_on = "critical"
fail_on_new = "high"
"#,
        );
        let canonical_rules = root
            .path()
            .join("security/team-rules.toml")
            .canonicalize()
            .unwrap();
        assert_eq!(
            load_project_config(root.path()),
            Ok(Some(ProjectConfig {
                scan: ScanConfig {
                    ignore_dirs: vec!["node_modules".into(), "target".into(), "dist".into()],
                    fail_on: Some(FailOn::High),
                    fail_on_new: Some(FailOn::Medium),
                    max_file_size_kb: Some(2048),
                    secrets: Some(true),
                    patterns: Some(false),
                    rule_pack_files: vec![canonical_rules],
                },
                deps: DepsConfig {
                    ignore_dirs: vec!["examples".into()],
                    fail_on: Some(FailOn::Critical),
                    fail_on_new: Some(FailOn::High),
                },
            }))
        );
    }

    #[test]
    fn unknown_keys_and_tables_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let typo = error(root.path(), "version = 1\n[scan]\nfail_onn = \"high\"\n");
        assert!(typo.contains("fail_onn"), "{typo}");
        // The error points at the line.
        assert!(typo.contains("line 3"), "{typo}");
        let table = error(root.path(), "version = 1\n[image]\nfail_on = \"high\"\n");
        assert!(table.contains("image"), "{table}");
        let value = error(root.path(), "version = 1\n[scan]\nfail_on = \"severe\"\n");
        assert!(value.contains("severe"), "{value}");
    }

    #[test]
    fn version_must_be_one() {
        let root = tempfile::tempdir().unwrap();
        for body in ["[scan]\n", "version = 0\n", "version = 2\n"] {
            let reason = error(root.path(), body);
            assert!(reason.contains("version"), "{body}: {reason}");
        }
        assert!(error(root.path(), "not toml at all [").contains("config.toml"));
    }

    #[test]
    fn rule_pack_paths_must_stay_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("x.toml"), "").unwrap();
        let absolute = outside.path().join("x.toml");
        let absolute = format!(
            "version = 1\n[scan]\nrule_pack_files = [{:?}]\n",
            absolute.to_string_lossy()
        );
        assert!(error(root.path(), &absolute).contains("rule_pack_files"));
        assert!(error(
            root.path(),
            "version = 1\n[scan]\nrule_pack_files = [\"../x.toml\"]\n"
        )
        .contains("rule_pack_files"));
        assert!(error(
            root.path(),
            "version = 1\n[scan]\nrule_pack_files = [\"missing.toml\"]\n"
        )
        .contains("missing.toml"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("x.toml"),
                root.path().join("escape.toml"),
            )
            .unwrap();
            assert!(error(
                root.path(),
                "version = 1\n[scan]\nrule_pack_files = [\"escape.toml\"]\n"
            )
            .contains("escape.toml"));
        }
    }

    #[test]
    fn an_oversized_or_symlinked_config_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let mut big = String::from("version = 1\n");
        big.push_str(&"# padding\n".repeat(30_000));
        assert!(error(root.path(), &big).contains("config.toml"));
        #[cfg(unix)]
        {
            let other = tempfile::tempdir().unwrap();
            std::fs::write(other.path().join("real.toml"), "version = 1\n").unwrap();
            std::fs::remove_file(root.path().join(PROJECT_CONFIG_PATH)).unwrap();
            std::os::unix::fs::symlink(
                other.path().join("real.toml"),
                root.path().join(PROJECT_CONFIG_PATH),
            )
            .unwrap();
            assert!(load_project_config(root.path()).is_err());
        }
    }
}

//! Locating a user-installed cve-bin-tool.
//!
//! oxAudit does not ship cve-bin-tool. It is GPL-3.0-or-later, and bundling it
//! would make oxAudit a distributor of GPL software; invoking an installation
//! the user already has is arms-length and carries no such obligation. The
//! trade is that we must handle "not installed" as a first-class state rather
//! than an error.

use std::path::Path;
use std::process::Command;

use serde::Serialize;

/// How we found the executable, so the UI can explain itself.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ToolSource {
    /// An explicit path from Settings.
    Configured,
    /// `cve-bin-tool` resolved on PATH.
    Path,
    /// `python3 -m cve_bin_tool`, for pip installs without a console script.
    PythonModule,
}

/// A resolved way to invoke the tool: the program plus any leading arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub program: String,
    pub leading_args: Vec<String>,
    pub source: ToolSource,
}

impl Invocation {
    fn configured(path: &str) -> Self {
        Self {
            program: path.to_string(),
            leading_args: Vec::new(),
            source: ToolSource::Configured,
        }
    }

    fn on_path() -> Self {
        Self {
            program: "cve-bin-tool".to_string(),
            leading_args: Vec::new(),
            source: ToolSource::Path,
        }
    }

    fn python_module(python: &str) -> Self {
        Self {
            program: python.to_string(),
            leading_args: vec!["-m".into(), "cve_bin_tool".into()],
            source: ToolSource::PythonModule,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BinaryToolStatus {
    pub available: bool,
    /// The program we would run, shown so the user can confirm which copy.
    pub program: Option<String>,
    pub version: Option<String>,
    pub source: Option<ToolSource>,
    /// Why it is unavailable, or a caveat when it is.
    pub message: Option<String>,
}

impl BinaryToolStatus {
    fn missing(message: impl Into<String>) -> Self {
        Self {
            available: false,
            program: None,
            version: None,
            source: None,
            message: Some(message.into()),
        }
    }
}

pub const NOT_INSTALLED_MESSAGE: &str = "cve-bin-tool was not found. Install it with \
`pipx install cve-bin-tool` (recommended) or `pip install cve-bin-tool`, then set an \
explicit path in Settings if it is not on PATH.";

/// `cve-bin-tool --version` prints a bare version; some builds prefix the name.
/// Anything that is not a recognizable version is treated as absent rather than
/// shown to the user as a "version".
pub fn parse_version(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .and_then(|line| {
            line.split_whitespace()
                .find(|token| {
                    token
                        .trim_start_matches('v')
                        .split('.')
                        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
                        && token.contains('.')
                })
                .map(|token| token.trim_start_matches('v').to_string())
        })
}

/// The order in which we look for the tool.
///
/// An explicit setting always wins, so a user with several Python environments
/// can pin the one they mean. `configured_path` being set but missing is an
/// error rather than a silent fallback — otherwise the app would quietly scan
/// with a different copy than the one the user chose.
pub fn candidates(configured_path: Option<&str>) -> Vec<Invocation> {
    if let Some(path) = configured_path.map(str::trim).filter(|p| !p.is_empty()) {
        return vec![Invocation::configured(path)];
    }
    vec![
        Invocation::on_path(),
        Invocation::python_module("python3"),
        Invocation::python_module("python"),
    ]
}

/// Probe one candidate by asking it for its version.
fn probe(invocation: &Invocation) -> Option<String> {
    let mut command = Command::new(&invocation.program);
    command.args(&invocation.leading_args).arg("--version");
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_version(&stdout).or_else(|| parse_version(&stderr))
}

/// Find a usable cve-bin-tool, or explain why there isn't one.
pub fn detect(configured_path: Option<&str>) -> BinaryToolStatus {
    let configured = configured_path.map(str::trim).filter(|p| !p.is_empty());

    if let Some(path) = configured {
        if !Path::new(path).exists() {
            return BinaryToolStatus::missing(format!(
                "The configured cve-bin-tool path does not exist: {path}"
            ));
        }
    }

    for invocation in candidates(configured) {
        if let Some(version) = probe(&invocation) {
            return BinaryToolStatus {
                available: true,
                program: Some(render_program(&invocation)),
                version: Some(version),
                source: Some(invocation.source),
                message: None,
            };
        }
    }

    if let Some(path) = configured {
        return BinaryToolStatus::missing(format!(
            "{path} exists but did not respond to `--version`; check that it is cve-bin-tool."
        ));
    }
    BinaryToolStatus::missing(NOT_INSTALLED_MESSAGE)
}

/// Human-readable form of what we run, e.g. `python3 -m cve_bin_tool`.
pub fn render_program(invocation: &Invocation) -> String {
    if invocation.leading_args.is_empty() {
        invocation.program.clone()
    } else {
        format!("{} {}", invocation.program, invocation.leading_args.join(" "))
    }
}

/// Resolve the invocation to actually run a scan with.
pub fn resolve(configured_path: Option<&str>) -> Result<Invocation, String> {
    let configured = configured_path.map(str::trim).filter(|p| !p.is_empty());
    for invocation in candidates(configured) {
        if probe(&invocation).is_some() {
            return Ok(invocation);
        }
    }
    Err(if configured.is_some() {
        format!(
            "The configured cve-bin-tool path did not respond to `--version`: {}",
            configured.unwrap_or_default()
        )
    } else {
        NOT_INSTALLED_MESSAGE.to_string()
    })
}

/// Probe a program that reports its version on stdout, using `parse` to read it.
fn probe_program(program: &str, version_args: &[&str], parse: fn(&str) -> Option<String>) -> Option<String> {
    let output = Command::new(program).args(version_args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse(&String::from_utf8_lossy(&output.stdout))
        .or_else(|| parse(&String::from_utf8_lossy(&output.stderr)))
}

/// Is grype available, and which copy?
pub fn detect_grype(configured_path: Option<&str>) -> BinaryToolStatus {
    let configured = configured_path.map(str::trim).filter(|p| !p.is_empty());

    if let Some(path) = configured {
        if !Path::new(path).exists() {
            return BinaryToolStatus::missing(format!(
                "The configured grype path does not exist: {path}"
            ));
        }
    }

    let program = configured.unwrap_or("grype");
    match probe_program(program, &["version"], super::grype::parse_version) {
        Some(version) => BinaryToolStatus {
            available: true,
            program: Some(program.to_string()),
            version: Some(version),
            source: Some(if configured.is_some() {
                ToolSource::Configured
            } else {
                ToolSource::Path
            }),
            message: None,
        },
        None => BinaryToolStatus::missing(
            "grype was not found. Install it with `brew install grype`, or see \
https://github.com/anchore/grype. It is Apache-2.0 and ships as a single static binary.",
        ),
    }
}

/// `docker --version` prints "Docker version 29.4.0, build …".
fn parse_docker_version(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .map(|token| token.trim_end_matches(','))
        .find(|token| {
            token.contains('.') && token.starts_with(|c: char| c.is_ascii_digit())
        })
        .map(str::to_string)
}

/// Is a usable Docker daemon available?
///
/// `--version` answers even when the daemon is down, so `info` is what actually
/// proves a container can start.
pub fn detect_docker() -> BinaryToolStatus {
    let Some(version) = probe_program("docker", &["--version"], parse_docker_version) else {
        return BinaryToolStatus::missing(
            "Docker was not found. The container runtime needs it; the native runtime does not.",
        );
    };

    let daemon_up = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);

    if !daemon_up {
        return BinaryToolStatus {
            available: false,
            program: Some("docker".into()),
            version: Some(version),
            source: Some(ToolSource::Path),
            message: Some(
                "Docker is installed but its daemon is not responding. Start Docker and retry."
                    .into(),
            ),
        };
    }

    BinaryToolStatus {
        available: true,
        program: Some("docker".into()),
        version: Some(version),
        source: Some(ToolSource::Path),
        message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_version_line_is_read() {
        assert_eq!(parse_version("3.4\n").as_deref(), Some("3.4"));
        assert_eq!(parse_version("3.4.1").as_deref(), Some("3.4.1"));
    }

    #[test]
    fn a_name_prefixed_version_is_read() {
        assert_eq!(parse_version("cve-bin-tool 3.4").as_deref(), Some("3.4"));
        assert_eq!(parse_version("cve-bin-tool v3.4.1").as_deref(), Some("3.4.1"));
    }

    #[test]
    fn leading_blank_lines_and_warnings_do_not_hide_the_version() {
        assert_eq!(parse_version("\n\n  3.4  \n").as_deref(), Some("3.4"));
    }

    #[test]
    fn output_without_a_version_is_absent_rather_than_a_bogus_string() {
        // A wrong binary answering `--version` must not be reported as usable.
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("command not found"), None);
        assert_eq!(parse_version("usage: some-other-tool [-h]"), None);
    }

    #[test]
    fn an_explicit_path_suppresses_every_fallback() {
        // Falling back would scan with a different copy than the user picked.
        let resolved = candidates(Some("/opt/venv/bin/cve-bin-tool"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].program, "/opt/venv/bin/cve-bin-tool");
        assert_eq!(resolved[0].source, ToolSource::Configured);
    }

    #[test]
    fn a_blank_configured_path_is_treated_as_unset() {
        assert_eq!(candidates(Some("   ")).len(), 3);
        assert_eq!(candidates(None).len(), 3);
    }

    #[test]
    fn without_configuration_we_try_path_then_the_python_module() {
        let resolved = candidates(None);
        assert_eq!(resolved[0].program, "cve-bin-tool");
        assert_eq!(resolved[0].source, ToolSource::Path);
        assert_eq!(resolved[1].leading_args, vec!["-m", "cve_bin_tool"]);
        assert_eq!(resolved[1].source, ToolSource::PythonModule);
    }

    #[test]
    fn a_configured_path_that_does_not_exist_reports_that_specifically() {
        let status = detect(Some("/definitely/not/here/cve-bin-tool"));
        assert!(!status.available);
        assert!(
            status.message.unwrap().contains("does not exist"),
            "the user needs to know their setting is stale, not just that it is missing"
        );
    }

    #[test]
    fn the_python_module_form_renders_as_the_full_command() {
        assert_eq!(
            render_program(&candidates(None)[1]),
            "python3 -m cve_bin_tool"
        );
        assert_eq!(render_program(&candidates(None)[0]), "cve-bin-tool");
    }
}

//! Choosing *how* cve-bin-tool runs: directly, or inside our container image.
//!
//! The container is not merely a portability nicety. cve-bin-tool 3.4 cannot
//! bootstrap its CVE database at all without a patch (see
//! `docs/binary-scanning-runtime.md` §0), and the image is where we carry that
//! patch — we cannot edit a user's own installation and expect it to survive
//! their package manager. So Docker is frequently the runtime that *works*.
//!
//! Everything here is pure: building an argument list and translating paths
//! across the container boundary, with no process spawned. That keeps the one
//! place where a user-supplied path becomes part of a `docker run` invocation
//! directly testable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::detect::Invocation;
use super::run::{build_args, BinaryScanRequest};

/// The image built from `docker/cve-bin-tool/Dockerfile`.
pub const DEFAULT_IMAGE: &str = "oxaudit/cve-bin-tool:3.4";

/// Where the scan target is mounted inside the container.
const CONTAINER_SCAN_ROOT: &str = "/scan";
/// Where the report directory is mounted.
const CONTAINER_OUT_ROOT: &str = "/out";
/// Named volume holding the CVE database, so the download happens once.
///
/// Mounted at `.cache`, not `.cache/cve-bin-tool`: cve-bin-tool removes its own
/// cache directory on the update-rollback path, which fails with EBUSY when a
/// volume is mounted exactly there.
const CONTAINER_CACHE_ROOT: &str = "/home/scanner/.cache";
pub const CACHE_VOLUME: &str = "oxaudit-cvedb";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Runtime {
    /// Prefer a native installation, fall back to the container.
    #[default]
    Auto,
    Native,
    Docker,
}

impl Runtime {
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("native") => Runtime::Native,
            Some("docker") => Runtime::Docker,
            _ => Runtime::Auto,
        }
    }
}

/// A command ready to spawn, plus how to read the paths it will report.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub environment: Vec<(String, zeroize::Zeroizing<String>)>,
    /// `(container_prefix, host_prefix)` for rewriting reported paths back to
    /// something the user can open. `None` when the scan ran natively.
    pub path_rewrite: Option<(String, PathBuf)>,
}

impl std::fmt::Debug for PreparedCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let environment_names: Vec<&str> = self
            .environment
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        formatter
            .debug_struct("PreparedCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("environment_names", &environment_names)
            .field("path_rewrite", &self.path_rewrite)
            .finish()
    }
}

fn nvd_environment(
    request: &BinaryScanRequest,
    nvd_api_key: Option<&str>,
) -> Vec<(String, zeroize::Zeroizing<String>)> {
    if request.offline {
        return Vec::new();
    }
    nvd_api_key
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(|key| {
            vec![(
                "NVD_API_KEY".to_string(),
                zeroize::Zeroizing::new(key.to_string()),
            )]
        })
        .unwrap_or_default()
}

/// Rewrite a path the container reported into its host equivalent.
pub fn to_host_path(rewrite: &Option<(String, PathBuf)>, reported: &str) -> String {
    let Some((container_prefix, host_prefix)) = rewrite else {
        return reported.to_string();
    };
    let trimmed = reported.trim();
    let Some(relative) = trimmed.strip_prefix(container_prefix.as_str()) else {
        return trimmed.to_string();
    };
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        host_prefix.to_string_lossy().into_owned()
    } else {
        host_prefix.join(relative).to_string_lossy().into_owned()
    }
}

/// Build the native invocation: the tool is handed the host paths directly.
pub fn prepare_native(
    invocation: &Invocation,
    target: &Path,
    report_path: &Path,
    request: &BinaryScanRequest,
    nvd_api_key: Option<&str>,
) -> PreparedCommand {
    let mut args = invocation.leading_args.clone();
    args.extend(build_args(target, report_path, request));
    PreparedCommand {
        program: invocation.program.clone(),
        args,
        environment: nvd_environment(request, nvd_api_key),
        path_rewrite: None,
    }
}

/// Build the containerised invocation.
///
/// A file target mounts its *parent* directory, because Docker cannot bind a
/// single file into a directory tree the scanner will walk; the scanned path
/// inside the container then names the file within that mount.
pub fn prepare_docker(
    docker_program: &str,
    image: &str,
    target: &Path,
    report_path: &Path,
    request: &BinaryScanRequest,
    nvd_api_key: Option<&str>,
) -> Result<PreparedCommand, String> {
    let target_is_dir = target.is_dir();
    let (host_mount, container_target) = if target_is_dir {
        (target.to_path_buf(), CONTAINER_SCAN_ROOT.to_string())
    } else {
        let parent = target.parent().ok_or_else(|| {
            format!(
                "cannot determine a folder to mount for {}",
                target.display()
            )
        })?;
        let name = target
            .file_name()
            .ok_or_else(|| format!("cannot determine a file name for {}", target.display()))?;
        (
            parent.to_path_buf(),
            format!("{CONTAINER_SCAN_ROOT}/{}", name.to_string_lossy()),
        )
    };

    let report_dir = report_path
        .parent()
        .ok_or_else(|| "the report path has no parent directory".to_string())?;
    let report_name = report_path
        .file_name()
        .ok_or_else(|| "the report path has no file name".to_string())?;
    let container_report = format!("{CONTAINER_OUT_ROOT}/{}", report_name.to_string_lossy());

    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        // Matches the posture oxfuzz uses for its sandbox: no capabilities, no
        // privilege escalation, and a process ceiling. cve-bin-tool extracts
        // untrusted archives, so this is not merely decorative.
        "--cap-drop=ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit=512".into(),
    ];

    // An offline scan needs no network at all, which is the strongest posture
    // available and the one to prefer for untrusted firmware.
    if request.offline {
        args.push("--network=none".into());
    } else if nvd_api_key.is_some_and(|key| !key.trim().is_empty()) {
        args.push("--env".into());
        args.push("NVD_API_KEY".into());
    }

    args.push("-v".into());
    args.push(format!("{}:{CONTAINER_SCAN_ROOT}:ro", host_mount.display()));
    args.push("-v".into());
    args.push(format!("{CACHE_VOLUME}:{CONTAINER_CACHE_ROOT}"));
    args.push("-v".into());
    args.push(format!("{}:{CONTAINER_OUT_ROOT}", report_dir.display()));
    args.push(image.to_string());

    args.extend(build_args(
        Path::new(&container_target),
        Path::new(&container_report),
        request,
    ));

    Ok(PreparedCommand {
        program: docker_program.to_string(),
        args,
        environment: nvd_environment(request, nvd_api_key),
        path_rewrite: Some((CONTAINER_SCAN_ROOT.to_string(), host_mount)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binscan::detect::{Invocation, ToolSource};

    fn request() -> BinaryScanRequest {
        BinaryScanRequest {
            path: "/fw".into(),
            ..Default::default()
        }
    }

    fn native_invocation() -> Invocation {
        Invocation {
            program: "cve-bin-tool".into(),
            leading_args: Vec::new(),
            source: ToolSource::Path,
        }
    }

    #[test]
    fn an_unknown_runtime_string_falls_back_to_auto() {
        assert_eq!(Runtime::parse(Some("docker")), Runtime::Docker);
        assert_eq!(Runtime::parse(Some(" Native ")), Runtime::Native);
        assert_eq!(Runtime::parse(Some("podman")), Runtime::Auto);
        assert_eq!(Runtime::parse(None), Runtime::Auto);
    }

    #[test]
    fn the_native_command_passes_host_paths_through_untranslated() {
        let prepared = prepare_native(
            &native_invocation(),
            Path::new("/fw/image.bin"),
            Path::new("/tmp/report.json"),
            &request(),
            None,
        );

        assert_eq!(prepared.program, "cve-bin-tool");
        assert_eq!(prepared.args[0], "/fw/image.bin");
        assert_eq!(prepared.path_rewrite, None);
    }

    #[test]
    fn online_native_and_docker_commands_keep_the_nvd_key_out_of_argv() {
        const CANARY: &str = "nvd-canary-secret-7D4zP9q2";
        let native = prepare_native(
            &native_invocation(),
            Path::new("/fw/image.bin"),
            Path::new("/tmp/report.json"),
            &request(),
            Some(CANARY),
        );
        assert!(!native.args.iter().any(|argument| argument.contains(CANARY)));
        assert!(native
            .environment
            .iter()
            .any(|(name, value)| name == "NVD_API_KEY" && value.as_str() == CANARY));

        let docker = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &std::env::temp_dir(),
            Path::new("/tmp/out/report.json"),
            &request(),
            Some(CANARY),
        )
        .expect("docker command");
        assert!(!docker.args.iter().any(|argument| argument.contains(CANARY)));
        assert!(docker
            .args
            .windows(2)
            .any(|arguments| arguments == ["--env", "NVD_API_KEY"]));
        assert!(docker
            .environment
            .iter()
            .any(|(name, value)| name == "NVD_API_KEY" && value.as_str() == CANARY));
    }

    #[test]
    fn offline_prepared_commands_do_not_receive_the_nvd_key() {
        let mut offline = request();
        offline.offline = true;
        let prepared = prepare_native(
            &native_invocation(),
            Path::new("/fw/image.bin"),
            Path::new("/tmp/report.json"),
            &offline,
            Some("nvd-canary-secret"),
        );

        assert!(prepared.environment.is_empty());
        assert!(!prepared
            .args
            .iter()
            .any(|argument| argument.contains("nvd-canary-secret")));
    }

    #[test]
    fn a_directory_target_is_mounted_whole_and_scanned_at_the_mount_point() {
        let dir = std::env::temp_dir();
        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/tmp/out/report.json"),
            &request(),
            None,
        )
        .unwrap();

        assert_eq!(prepared.program, "docker");
        assert!(prepared
            .args
            .iter()
            .any(|a| a == &format!("{}:/scan:ro", dir.display())));
        // The scanned path is the mount point itself.
        assert!(prepared.args.iter().any(|a| a == "/scan"));
        assert!(prepared.args.iter().any(|a| a == "/out/report.json"));
    }

    #[test]
    fn a_file_target_mounts_its_parent_and_names_the_file_inside() {
        // Docker cannot bind a single file into a tree the scanner walks.
        let file = std::env::temp_dir().join("oxaudit-runtime-fixture.bin");
        std::fs::write(&file, b"x").unwrap();

        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &file,
            Path::new("/tmp/out/report.json"),
            &request(),
            None,
        )
        .unwrap();

        let parent = file.parent().unwrap();
        assert!(prepared
            .args
            .iter()
            .any(|a| a == &format!("{}:/scan:ro", parent.display())));
        assert!(prepared
            .args
            .iter()
            .any(|a| a == "/scan/oxaudit-runtime-fixture.bin"));

        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn container_paths_are_translated_back_for_display() {
        let rewrite = Some(("/scan".to_string(), PathBuf::from("/Users/me/fw")));

        assert_eq!(
            to_host_path(&rewrite, "/scan/lib/libssl.dylib"),
            "/Users/me/fw/lib/libssl.dylib"
        );
        // The mount point itself maps to the mounted directory.
        assert_eq!(to_host_path(&rewrite, "/scan"), "/Users/me/fw");
        // Anything outside the mount is left alone rather than mangled.
        assert_eq!(
            to_host_path(&rewrite, "/usr/lib/other.so"),
            "/usr/lib/other.so"
        );
        // A native run has nothing to translate.
        assert_eq!(to_host_path(&None, "/scan/x"), "/scan/x");
    }

    #[test]
    fn the_container_drops_privileges_and_mounts_the_target_read_only() {
        let dir = std::env::temp_dir();
        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/o/r.json"),
            &request(),
            None,
        )
        .unwrap();

        assert!(prepared.args.iter().any(|a| a == "--cap-drop=ALL"));
        assert!(prepared.args.iter().any(|a| a == "no-new-privileges"));
        assert!(prepared.args.iter().any(|a| a == "--pids-limit=512"));
        assert!(prepared.args.iter().any(|a| a == "--rm"));
        assert!(prepared.args.iter().any(|a| a.ends_with(":/scan:ro")));
    }

    #[test]
    fn an_offline_scan_gets_no_network_at_all() {
        let dir = std::env::temp_dir();
        let mut offline = request();
        offline.offline = true;

        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/o/r.json"),
            &offline,
            None,
        )
        .unwrap();
        assert!(prepared.args.iter().any(|a| a == "--network=none"));

        // An online scan must keep networking, or the database can never update.
        let online = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/o/r.json"),
            &request(),
            None,
        )
        .unwrap();
        assert!(!online.args.iter().any(|a| a == "--network=none"));
    }

    #[test]
    fn the_cve_database_volume_is_mounted_above_the_directory_the_tool_deletes() {
        // Mounting at .cache/cve-bin-tool makes cve-bin-tool's rollback rmdir
        // fail with EBUSY; this cost a full run to discover.
        let dir = std::env::temp_dir();
        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/o/r.json"),
            &request(),
            None,
        )
        .unwrap();

        assert!(prepared
            .args
            .iter()
            .any(|a| a == &format!("{CACHE_VOLUME}:/home/scanner/.cache")));
        assert!(!prepared
            .args
            .iter()
            .any(|a| a.contains("/home/scanner/.cache/cve-bin-tool")));
    }

    #[test]
    fn the_image_is_the_last_argument_before_the_tools_own_flags() {
        let dir = std::env::temp_dir();
        let prepared = prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            &dir,
            Path::new("/o/r.json"),
            &request(),
            None,
        )
        .unwrap();

        let image_at = prepared
            .args
            .iter()
            .position(|a| a == DEFAULT_IMAGE)
            .unwrap();
        let target_at = prepared.args.iter().position(|a| a == "/scan").unwrap();
        assert!(
            image_at < target_at,
            "docker flags must not follow the image"
        );
    }
}

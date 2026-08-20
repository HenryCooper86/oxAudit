//! Running cve-bin-tool as a child process.
//!
//! Two properties matter more than anything else here:
//!
//! * **No shell, ever.** Arguments are passed to the program directly. The
//!   target is canonicalized to an absolute path first, which also removes any
//!   chance of a filename like `-rf` being read as a flag.
//! * **A non-zero exit is not a failure.** cve-bin-tool uses its exit code to
//!   report how many files had CVEs, so success is decided by whether it wrote
//!   a report we can parse — not by the status code.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::detect::Invocation;
use super::report::{parse_json2, BinaryScanResult};

/// Severity floor accepted by `--severity`.
const SEVERITIES: [&str; 4] = ["low", "medium", "high", "critical"];
/// Refresh policies accepted by `--update`.
const UPDATE_POLICIES: [&str; 4] = ["now", "daily", "never", "latest"];

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct BinaryScanRequest {
    pub path: String,
    /// Minimum severity to report; `None` means cve-bin-tool's own default.
    #[serde(default)]
    pub severity: Option<String>,
    /// Use only the local CVE database, making no network calls.
    #[serde(default)]
    pub offline: bool,
    /// How aggressively to refresh the CVE database.
    #[serde(default)]
    pub update: Option<String>,
}

/// Removes the report file when the scan leaves scope, on every path.
struct ScratchFile(PathBuf);

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build the argument list.
///
/// Kept separate from spawning so the exact command line is testable: this is
/// the one place where a caller-supplied value becomes part of an invocation.
pub fn build_args(
    target: &Path,
    output_file: &Path,
    request: &BinaryScanRequest,
    nvd_api_key: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        target.to_string_lossy().into_owned(),
        "--format".into(),
        "json2".into(),
        "--output-file".into(),
        output_file.to_string_lossy().into_owned(),
    ];

    // Anything not on the known lists is dropped rather than forwarded: these
    // reach a subprocess, so an unrecognized value is a bug or an attack, never
    // something to pass along hopefully.
    if let Some(severity) = request
        .severity
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| SEVERITIES.contains(&value.as_str()))
    {
        args.push("--severity".into());
        args.push(severity);
    }

    if request.offline {
        args.push("--offline".into());
    } else if let Some(update) = request
        .update
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| UPDATE_POLICIES.contains(&value.as_str()))
    {
        args.push("--update".into());
        args.push(update);
    }

    // An offline scan makes no requests, so sending the key would only widen
    // its exposure for no benefit.
    if !request.offline {
        if let Some(key) = nvd_api_key.map(str::trim).filter(|key| !key.is_empty()) {
            args.push("--nvd-api-key".into());
            args.push(key.to_string());
        }
    }

    args
}

/// Why a run produced no report, phrased so the user can act on it.
///
/// These are not hypothetical. A partially-failed first bootstrap leaves a
/// ~1 GB cache that cve-bin-tool's `daily` policy then treats as fresh, so
/// every later run fails instantly with "No data in CVE Database" and never
/// self-heals. Without naming that case the app looks broken with no way out.
pub fn explain_failure(stderr_tail: &str, exit_status: &str) -> String {
    let haystack = stderr_tail.to_ascii_lowercase();

    if haystack.contains("cvedatamissing") || haystack.contains("no data in cve database") {
        return "cve-bin-tool's local CVE database is empty. A previous download was interrupted, and its default daily refresh now considers the stale cache current, so it will not retry on its own. Use \"Refresh CVE database\" to force a full update."
            .to_string();
    }

    if haystack.contains("no such file or directory: 'gsutil'")
        || haystack.contains("filenotfounderror") && haystack.contains("gsutil")
    {
        return "cve-bin-tool needs `gsutil` to download its CVE database mirror, and it is not installed. Install it into the same environment (`pip install gsutil`), or point Settings at an installation that has it."
            .to_string();
    }

    if haystack.contains("modulenotfounderror") || haystack.contains("importerror") {
        return format!(
            "cve-bin-tool is missing a Python dependency. Reinstall it, or point Settings \
at a complete installation.\n{stderr_tail}"
        );
    }

    if stderr_tail.trim().is_empty() {
        format!("cve-bin-tool wrote no report (exit {exit_status})")
    } else {
        format!("cve-bin-tool wrote no report (exit {exit_status}):\n{stderr_tail}")
    }
}

/// Resolve the scan target to an existing absolute path.
pub fn resolve_target(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("choose a file or folder to scan".into());
    }
    let path = Path::new(trimmed);
    if !path.exists() {
        return Err(format!("path does not exist: {trimmed}"));
    }
    std::fs::canonicalize(path).map_err(|e| format!("cannot resolve {trimmed}: {e}"))
}

/// Run one scan to completion.
///
/// `on_progress` receives cve-bin-tool's own stderr lines. That output is the
/// only signal during a first run, where it spends minutes downloading the CVE
/// database before scanning anything.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    invocation: &Invocation,
    request: &BinaryScanRequest,
    nvd_api_key: Option<&str>,
    scratch_dir: &Path,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<BinaryScanResult, String> {
    let target = resolve_target(&request.path)?;

    std::fs::create_dir_all(scratch_dir)
        .map_err(|e| format!("cannot prepare a scratch directory: {e}"))?;
    let report_path = scratch_dir.join(format!("cve-bin-tool-{}.json", uuid::Uuid::new_v4()));
    let _scratch = ScratchFile(report_path.clone());

    let args = build_args(&target, &report_path, request, nvd_api_key);
    let started = Instant::now();

    let mut child = Command::new(&invocation.program)
        .args(&invocation.leading_args)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", invocation.program))?;

    // Keep the last stderr lines: if no report is written they are the only
    // explanation of why.
    let tail = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    if let Some(stderr) = child.stderr.take() {
        let tail = tail.clone();
        let on_progress = on_progress.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                {
                    let mut tail = tail.lock().unwrap();
                    tail.push(trimmed.clone());
                    if tail.len() > 40 {
                        tail.remove(0);
                    }
                }
                on_progress(trimmed);
            }
        });
    }

    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill().await;
            return Err("scan cancelled".into());
        }
        if started.elapsed() > timeout {
            let _ = child.kill().await;
            return Err(format!(
                "cve-bin-tool did not finish within {} seconds",
                timeout.as_secs()
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(e) => return Err(format!("cve-bin-tool could not be monitored: {e}")),
        }
    };

    let duration_ms = started.elapsed().as_millis() as u64;

    // The exit code carries a finding count, so it cannot distinguish success
    // from failure. The report is what decides.
    let raw = match std::fs::read_to_string(&report_path) {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => {
            let detail = tail.lock().unwrap().join("\n");
            return Err(explain_failure(&detail, &status.to_string()));
        }
    };

    parse_json2(&raw, &target.to_string_lossy(), duration_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> BinaryScanRequest {
        BinaryScanRequest {
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_base_invocation_asks_for_a_json2_report_at_our_chosen_path() {
        let args = build_args(
            Path::new("/fw/image.bin"),
            Path::new("/tmp/out.json"),
            &request("/fw/image.bin"),
            None,
        );
        assert_eq!(
            args,
            vec![
                "/fw/image.bin",
                "--format",
                "json2",
                "--output-file",
                "/tmp/out.json"
            ]
        );
    }

    #[test]
    fn an_unrecognized_severity_is_dropped_rather_than_forwarded() {
        // These values become subprocess arguments; anything off the known list
        // is a bug or an attack, so it is never passed along.
        let mut req = request("/fw");
        req.severity = Some("; rm -rf /".into());
        let args = build_args(Path::new("/fw"), Path::new("/tmp/o.json"), &req, None);
        assert!(!args.iter().any(|a| a.contains("rm -rf")));
        assert!(!args.iter().any(|a| a == "--severity"));

        req.severity = Some("HIGH".into());
        let args = build_args(Path::new("/fw"), Path::new("/tmp/o.json"), &req, None);
        assert!(args.windows(2).any(|w| w == ["--severity", "high"]));
    }

    #[test]
    fn an_unrecognized_update_policy_is_dropped() {
        let mut req = request("/fw");
        req.update = Some("--nvd-api-key=leak".into());
        let args = build_args(Path::new("/fw"), Path::new("/tmp/o.json"), &req, None);
        assert!(!args.iter().any(|a| a == "--update"));
        assert!(!args.iter().any(|a| a.contains("leak")));
    }

    #[test]
    fn an_offline_scan_neither_updates_nor_carries_the_api_key() {
        // Offline makes no requests, so sending the key would only widen its
        // exposure for nothing.
        let mut req = request("/fw");
        req.offline = true;
        req.update = Some("now".into());
        let args = build_args(Path::new("/fw"), Path::new("/tmp/o.json"), &req, Some("secret-key"));

        assert!(args.iter().any(|a| a == "--offline"));
        assert!(!args.iter().any(|a| a == "--update"));
        assert!(
            !args.iter().any(|a| a.contains("secret-key")),
            "the NVD key must not reach an offline invocation"
        );
    }

    #[test]
    fn an_online_scan_forwards_a_non_blank_api_key_only() {
        let args = build_args(Path::new("/fw"), Path::new("/o.json"), &request("/fw"), Some("k"));
        assert!(args.windows(2).any(|w| w == ["--nvd-api-key", "k"]));

        let args = build_args(Path::new("/fw"), Path::new("/o.json"), &request("/fw"), Some("   "));
        assert!(!args.iter().any(|a| a == "--nvd-api-key"));
    }

    #[test]
    fn a_missing_or_empty_target_is_refused_before_anything_is_spawned() {
        assert!(resolve_target("").unwrap_err().contains("choose a file"));
        assert!(resolve_target("   ").unwrap_err().contains("choose a file"));
        assert!(resolve_target("/definitely/not/here")
            .unwrap_err()
            .contains("does not exist"));
    }

    #[test]
    fn the_target_is_canonicalized_so_it_can_never_look_like_a_flag() {
        let dir = std::env::temp_dir();
        let resolved = resolve_target(dir.to_str().unwrap()).unwrap();
        assert!(resolved.is_absolute());
        assert!(!resolved.to_string_lossy().starts_with('-'));
    }

    #[test]
    fn a_relative_target_becomes_absolute_in_the_argument_list() {
        let resolved = resolve_target(".").unwrap();
        let args = build_args(&resolved, Path::new("/tmp/o.json"), &request("."), None);
        assert!(Path::new(&args[0]).is_absolute());
    }

    #[test]
    fn an_empty_database_names_the_trap_rather_than_dumping_a_traceback() {
        // Hit three times while integrating: a half-finished bootstrap leaves a
        // cache the daily policy calls fresh, so the tool never retries.
        let tail = "ERROR cve_bin_tool - CVEDataMissing: No data in CVE Database\n                    CVEDataMissing: No data in CVE Database";
        let message = explain_failure(tail, "exit status: 1");

        assert!(message.contains("Refresh CVE database"), "got: {message}");
        assert!(!message.contains("Traceback"));
    }

    #[test]
    fn a_missing_gsutil_is_named_with_the_fix() {
        let tail = "FileNotFoundError: [Errno 2] No such file or directory: 'gsutil'";
        let message = explain_failure(tail, "exit status: 21");

        assert!(message.contains("gsutil"), "got: {message}");
        assert!(message.contains("pip install gsutil"), "got: {message}");
    }

    #[test]
    fn an_unrecognized_failure_still_surfaces_the_tool_output() {
        let message = explain_failure("segmentation fault in checker", "exit status: 139");
        assert!(message.contains("segmentation fault in checker"));
        assert!(message.contains("139"));
    }

    #[test]
    fn a_silent_failure_at_least_reports_the_exit_status() {
        let message = explain_failure("   ", "exit status: 2");
        assert!(message.contains("exit status: 2"));
    }
}

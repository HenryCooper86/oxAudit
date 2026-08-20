//! Orchestrating a binary scan across the available scanners.
//!
//! Decides which scanners run and in which runtime, executes them, and merges
//! the results. A failure in one scanner does not fail the scan: the two see
//! genuinely different things, so half an answer is worth far more than none.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use super::detect;
use super::grype;
use super::report::{merge_results, BinaryScanResult};
use super::run::{execute, explain_failure, report_path, resolve_target, BinaryScanRequest, ScratchReport};
use super::runtime::{prepare_docker, prepare_native, to_host_path, Runtime, DEFAULT_IMAGE};

/// Everything the orchestrator needs that lives in application state.
pub struct ScanContext {
    pub runtime: Runtime,
    /// Explicit cve-bin-tool path, if the user pinned one.
    pub cve_bin_tool_path: Option<String>,
    /// Explicit grype path, if the user pinned one.
    pub grype_path: Option<String>,
    pub nvd_api_key: Option<String>,
    pub scratch_dir: PathBuf,
    pub use_cve_bin_tool: bool,
    pub use_grype: bool,
    /// oxAudit's own scanner. Unlike the other two it needs nothing installed,
    /// so it is the one that always has an answer.
    pub use_native: bool,
}

/// Which scanner produced an error, so the UI can say so precisely.
#[derive(Debug, Clone)]
pub struct ScannerFailure {
    pub scanner: String,
    pub message: String,
}

pub struct ScanOutcome {
    pub result: BinaryScanResult,
    /// Scanners that failed. Empty on a fully successful scan.
    pub failures: Vec<ScannerFailure>,
    /// Things the user should know that are not failures — a rate-limit
    /// warning, a capped lookup, a source that did not answer. Kept distinct
    /// from failures so neither gets lost in the other.
    pub notes: Vec<String>,
}

/// Run the selected scanners and merge whatever they produced.
pub async fn run_scan(
    context: &ScanContext,
    request: &BinaryScanRequest,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
    cve: Option<&crate::cve::CveState>,
) -> Result<ScanOutcome, String> {
    let target = resolve_target(&request.path)?;

    let mut results: Vec<BinaryScanResult> = Vec::new();
    let mut failures: Vec<ScannerFailure> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Native first. It takes under a second and needs nothing installed, so
    // the user has an answer on screen before either subprocess has started.
    if context.use_native {
        on_progress("starting oxAudit native scanner".into());
        match run_native(&target, cancel.clone(), on_progress.clone(), cve).await {
            Ok((result, mut native_notes)) => {
                notes.append(&mut native_notes);
                results.push(result);
            }
            Err(message) => {
                if message.contains("cancelled") {
                    return Err(message);
                }
                failures.push(ScannerFailure {
                    scanner: super::native::scan::NATIVE.to_string(),
                    message,
                });
            }
        }
    }

    if context.use_cve_bin_tool {
        on_progress("starting cve-bin-tool".into());
        match run_cve_bin_tool(context, request, &target, cancel.clone(), timeout, on_progress.clone())
            .await
        {
            Ok(result) => results.push(result),
            Err(message) => {
                // A cancellation is the user's decision, not a scanner fault;
                // it stops everything rather than being collected.
                if message.contains("cancelled") {
                    return Err(message);
                }
                failures.push(ScannerFailure {
                    scanner: super::report::CVE_BIN_TOOL.to_string(),
                    message,
                });
            }
        }
    }

    if context.use_grype {
        on_progress("starting grype".into());
        match run_grype(context, &target, cancel.clone(), timeout, on_progress.clone()).await {
            Ok(result) => results.push(result),
            Err(message) => {
                if message.contains("cancelled") {
                    return Err(message);
                }
                failures.push(ScannerFailure {
                    scanner: super::report::GRYPE.to_string(),
                    message,
                });
            }
        }
    }

    if results.is_empty() {
        let detail = failures
            .iter()
            .map(|f| format!("{}: {}", f.scanner, f.message))
            .collect::<Vec<_>>()
            .join("\n\n");
        return Err(if detail.is_empty() {
            "no binary scanner is enabled".to_string()
        } else {
            detail
        });
    }

    Ok(ScanOutcome {
        result: merge_results(results),
        failures,
        notes,
    })
}

/// Detect components natively, then ask NVD and OSV about them.
///
/// Enrichment failing is a note rather than an error: the component inventory
/// is useful on its own, and losing it because an advisory feed was
/// unreachable would be the wrong trade.
async fn run_native(
    target: &Path,
    cancel: Arc<AtomicBool>,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
    cve: Option<&crate::cve::CveState>,
) -> Result<(BinaryScanResult, Vec<String>), String> {
    use super::native::{enrich, scan as native};

    let scanned = native::scan(target, cancel.clone(), on_progress.clone())?;
    let mut result = scanned.result;
    let mut notes = Vec::new();

    let Some(cve) = cve else {
        if !scanned.queries.is_empty() {
            notes.push(
                "CVE lookup was skipped because no CVE client is available; components are \
listed without vulnerabilities."
                    .to_string(),
            );
        }
        return Ok((result, notes));
    };

    if !scanned.queries.is_empty() {
        let enriched =
            enrich::enrich(cve, &scanned.queries, cancel.clone(), on_progress.clone()).await;
        // apply() re-tallies the summary, so a de-duplicated CVE is never
        // counted twice and the headline can never drift from the list.
        enrich::apply(&mut result, enriched.found);
        notes.extend(enriched.notes);
    }

    Ok((result, notes))
}

async fn run_cve_bin_tool(
    context: &ScanContext,
    request: &BinaryScanRequest,
    target: &Path,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<BinaryScanResult, String> {
    let host_report = report_path(&context.scratch_dir)?;
    let _scratch = ScratchReport(host_report.clone());

    let prepared = match context.runtime {
        Runtime::Docker => prepare_docker(
            "docker",
            DEFAULT_IMAGE,
            target,
            &host_report,
            request,
            context.nvd_api_key.as_deref(),
        )?,
        Runtime::Native => {
            let invocation = detect::resolve(context.cve_bin_tool_path.as_deref())?;
            prepare_native(
                &invocation,
                target,
                &host_report,
                request,
                context.nvd_api_key.as_deref(),
            )
        }
        Runtime::Auto => match detect::resolve(context.cve_bin_tool_path.as_deref()) {
            Ok(invocation) => prepare_native(
                &invocation,
                target,
                &host_report,
                request,
                context.nvd_api_key.as_deref(),
            ),
            // No native install: fall back to the container, which is also the
            // runtime carrying the upstream NVD bootstrap fix.
            Err(_) => prepare_docker(
                "docker",
                DEFAULT_IMAGE,
                target,
                &host_report,
                request,
                context.nvd_api_key.as_deref(),
            )?,
        },
    };

    let outcome = execute(&prepared, cancel, timeout, on_progress).await?;

    // The exit code carries a finding count, so only the report decides.
    let raw = match std::fs::read_to_string(&host_report) {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => return Err(explain_failure(&outcome.stderr_tail, &outcome.status)),
    };

    let mut result = super::report::parse_json2(
        &raw,
        &target.to_string_lossy(),
        outcome.duration_ms,
    )?;

    // Paths a container reported name locations inside the mount, which the
    // user cannot open; map them back to the host.
    if prepared.path_rewrite.is_some() {
        for component in &mut result.components {
            for path in &mut component.paths {
                *path = to_host_path(&prepared.path_rewrite, path);
            }
        }
    }

    Ok(result)
}

async fn run_grype(
    context: &ScanContext,
    target: &Path,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
    on_progress: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<BinaryScanResult, String> {
    let program = context
        .grype_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .unwrap_or("grype")
        .to_string();

    let prepared = super::runtime::PreparedCommand {
        program,
        args: grype::build_args(target),
        path_rewrite: None,
    };

    let outcome = execute(&prepared, cancel, timeout, on_progress).await?;
    if outcome.stdout.trim().is_empty() {
        return Err(if outcome.stderr_tail.trim().is_empty() {
            format!("grype produced no report (exit {})", outcome.status)
        } else {
            format!(
                "grype produced no report (exit {}):\n{}",
                outcome.status, outcome.stderr_tail
            )
        });
    }

    grype::parse_report(
        &outcome.stdout,
        &target.to_string_lossy(),
        outcome.duration_ms,
    )
}

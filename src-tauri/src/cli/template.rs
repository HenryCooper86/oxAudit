//! `oxaudit-cli template`.
//!
//! Runs the same engine as the desktop and the headless server
//! (`scan_templates_engine`), so a match in CI is the match on a workstation.
//!
//! Exit codes match `yara`: 0 when nothing at or above `--fail-on` matched, 1
//! when something did, 2 for a usage error, 3 when the scan failed. A scan
//! that ends `Incomplete` prints its report and then exits 3. Templates that
//! were not evaluated are counted in the summary but do not by themselves make
//! a scan incomplete. Zero matches exits 0 and says "no template matched",
//! which is not a statement about the content or target.
//!
//! Live targets: the CLI reads no settings file. Its limits are the
//! documented defaults (50 requests/s, 10 per host, 10 s timeout, 4 MiB
//! responses, 100,000 requests) with `--rate-limit`, `--concurrency`,
//! `--timeout`, `--max-requests` and `--proxy` overriding them for the run.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;

use super::yara::{report_incomplete, strict_message, ScanFormat};
use super::{
    block_on, failure, gate, open_repository, render_stored_run, severity_rank, usage,
    write_output, CliResult, FailOn, OutputFormat, StderrEvents, EXIT_FAILURE, EXIT_OK,
};
use crate::findings::repository::FindingsRepository;
use crate::findings::service::{FindingsService, FindingsState};
use crate::sigpacks::{PackKind, SigPackStore, SigPacksState};
use crate::template::{
    TemplateAuthorization, TemplateScanRequest, TemplateScanResult, MAX_STATEMENT_CHARS,
};

/// Most targets accepted from `--target` and `--target-file` together: the
/// live scope's own limit, so the CLI and the engine agree.
#[cfg(feature = "templates")]
use crate::livenet::scope::MAX_TARGETS;
/// Builds without the template engine run no scan; the limit only shapes the
/// usage message there.
#[cfg(not(feature = "templates"))]
const MAX_TARGETS: usize = 1_000;
const MAX_TARGET_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Args, Debug)]
pub(super) struct TemplateArgs {
    /// Scan this file or folder with the templates' `file` protocol. Every
    /// file is read, ignore files are not applied, links are not followed.
    #[arg(long, value_name = "DIR")]
    pub path: Option<PathBuf>,

    /// A live target (URL, host, host:port, IP or CIDR). Repeatable. Live
    /// scanning sends network traffic and requires --i-am-authorized.
    #[arg(long = "target", value_name = "TARGET")]
    pub targets: Vec<String>,

    /// A file of live targets, one per line (blank lines and `#` comments
    /// are ignored).
    #[arg(long, value_name = "FILE")]
    pub target_file: Option<PathBuf>,

    /// A Nuclei template file or folder of templates for this scan only.
    /// Repeatable.
    #[arg(long = "templates", value_name = "FILE|DIR")]
    pub templates: Vec<PathBuf>,

    /// Apply this installed pack (from --pack-db). Repeatable. Without it
    /// every enabled Nuclei pack in --pack-db is applied.
    #[arg(long = "pack", value_name = "ID")]
    pub packs: Vec<String>,

    /// The signature-pack store database (the rule-pack database).
    #[arg(long, value_name = "FILE")]
    pub pack_db: Option<PathBuf>,

    /// Save the run to this database for later reload and export.
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Run only templates with any of these tags (comma separated).
    #[arg(long, value_delimiter = ',', value_name = "TAGS")]
    pub tags: Vec<String>,

    /// Never run templates with any of these tags (comma separated).
    #[arg(long, value_delimiter = ',', value_name = "TAGS")]
    pub exclude_tags: Vec<String>,

    /// Run only templates of these severities (comma separated): info, low,
    /// medium, high, critical.
    #[arg(long, value_delimiter = ',', value_name = "SEVERITIES")]
    pub severity: Vec<String>,

    /// Run only templates with these ids (comma separated).
    #[arg(long = "id", value_delimiter = ',', value_name = "IDS")]
    pub ids: Vec<String>,

    /// Also run templates tagged `intrusive` or `fuzz`. Templates tagged
    /// `dos` never run.
    #[arg(long)]
    pub include_intrusive: bool,

    /// Confirm that you are authorized to test the live targets. Required
    /// with --target and --target-file; never remembered between runs.
    #[arg(long)]
    pub i_am_authorized: bool,

    /// Live scans: requests per second overall, 1 to 1000 (default 50).
    #[arg(long, value_name = "N")]
    pub rate_limit: Option<u32>,

    /// Live scans: requests in flight to one host, 1 to 100 (default 10).
    #[arg(long, value_name = "N")]
    pub concurrency: Option<u32>,

    /// Live scans: connect and overall timeout of one request in seconds,
    /// 1 to 120 (default 10).
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u32>,

    /// Live scans: requests per run (default 100000). Reaching it stops
    /// the scan, which then reports itself incomplete.
    #[arg(long, value_name = "N")]
    pub max_requests: Option<u64>,

    /// Live scans: send HTTP template requests through this http:// or
    /// https:// proxy. Proxy environment variables are never read. DNS, TCP
    /// and SSL templates always connect directly.
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Files larger than this many MiB are listed as skipped (default 64, 1 to 1024).
    #[arg(long, value_name = "MB")]
    pub max_file_size_mb: Option<u32>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = ScanFormat::Text)]
    pub format: ScanFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Exit 1 when a match at this severity or higher is reported.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub fail_on: FailOn,

    /// Exit 3 when any template file that was given (--templates or an
    /// installed pack) could not be loaded (invalid YAML, no id, unreadable,
    /// repeated id). Templates that are "not evaluated" because they use
    /// unsupported features or need the other scan mode are expected in any
    /// real pack and never count. Without --strict such files are reported
    /// in the output but do not change the exit code.
    #[arg(long)]
    pub strict: bool,
}

/// The statement recorded with every CLI live scan.
pub(super) const CLI_AUTHORIZATION_STATEMENT: &str = "The operator confirmed on the command line, with --i-am-authorized, that they are authorized to test these targets.";

/// The live-scan limits for this run: the defaults, with each flag that was
/// given in its place. Out-of-range values are usage errors here rather than
/// being clamped, so a CI job never runs with limits it did not ask for.
fn live_settings(args: &TemplateArgs) -> Result<crate::models::LiveScanSettings, super::CliError> {
    fn within<T: PartialOrd + std::fmt::Display + Copy>(
        flag: &str,
        value: Option<T>,
        low: T,
        high: T,
    ) -> Result<Option<T>, super::CliError> {
        match value {
            Some(v) if v < low || v > high => Err(usage(format!(
                "{flag} must be between {low} and {high}; got {v}"
            ))),
            other => Ok(other),
        }
    }
    let defaults = crate::models::LiveScanSettings::default();
    within("--rate-limit", args.rate_limit, 1, 1000)?;
    let settings = crate::models::LiveScanSettings {
        per_host_concurrency: within("--concurrency", args.concurrency, 1, 100)?
            .unwrap_or(defaults.per_host_concurrency),
        timeout_seconds: within("--timeout", args.timeout, 1, 120)?
            .unwrap_or(defaults.timeout_seconds),
        max_requests: within("--max-requests", args.max_requests, 1, u64::MAX)?
            .unwrap_or(defaults.max_requests),
        proxy: args.proxy.clone(),
        ..defaults
    };
    // The engine rejects an unusable proxy too; checking here makes it a
    // usage error with the same message.
    #[cfg(feature = "templates")]
    crate::template::live::limits(&settings, args.rate_limit).map_err(usage)?;
    Ok(settings)
}

fn read_target_file(path: &std::path::Path) -> Result<Vec<String>, super::CliError> {
    let meta = std::fs::metadata(path).map_err(|error| {
        usage(format!(
            "cannot read --target-file {}: {error}",
            path.display()
        ))
    })?;
    if !meta.is_file() || meta.len() > MAX_TARGET_FILE_BYTES {
        return Err(usage(format!(
            "--target-file {} must be a regular file of at most {MAX_TARGET_FILE_BYTES} bytes",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|error| {
        usage(format!(
            "cannot read --target-file {}: {error}",
            path.display()
        ))
    })?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

pub(super) fn run_template(args: &TemplateArgs, quiet: bool) -> CliResult {
    let format = OutputFormat::from(args.format);
    let live = !args.targets.is_empty() || args.target_file.is_some();
    if args.path.is_some() && live {
        return Err(usage(
            "--path and --target/--target-file are separate scans; give one of them",
        ));
    }
    if args.path.is_none() && !live {
        return Err(usage(
            "nothing to scan: pass --path DIR for a local scan, or --target/--target-file for a live scan",
        ));
    }
    let live_only = args.rate_limit.is_some()
        || args.concurrency.is_some()
        || args.timeout.is_some()
        || args.max_requests.is_some()
        || args.proxy.is_some();
    if live_only && !live {
        return Err(usage(
            "--rate-limit, --concurrency, --timeout, --max-requests and --proxy apply to live scans (--target/--target-file) only",
        ));
    }
    if live && !args.i_am_authorized {
        return Err(usage(
            "live scanning sends network traffic to the targets you name, and it requires you to confirm you are authorized to test them: add --i-am-authorized once you are",
        ));
    }
    let mut targets: Vec<String> = args.targets.iter().map(|t| t.trim().to_owned()).collect();
    if let Some(file) = &args.target_file {
        targets.extend(read_target_file(file)?);
    }
    targets.retain(|target| !target.is_empty());
    if live && targets.is_empty() {
        return Err(usage("no targets were given in --target or --target-file"));
    }
    if targets.len() > MAX_TARGETS {
        return Err(usage(format!(
            "at most {MAX_TARGETS} targets are accepted; got {}",
            targets.len()
        )));
    }
    for severity in &args.severity {
        if !matches!(
            severity.trim().to_ascii_lowercase().as_str(),
            "info" | "low" | "medium" | "high" | "critical"
        ) {
            return Err(usage(format!(
                "unknown --severity {severity:?}; expected info, low, medium, high or critical"
            )));
        }
    }
    let live_settings = live_settings(args)?;
    if args.templates.is_empty() && args.pack_db.is_none() {
        return Err(usage(
            "no templates to scan with: pass --templates FILE|DIR, or --pack-db FILE with installed packs",
        ));
    }
    if !args.packs.is_empty() && args.pack_db.is_none() {
        return Err(usage("--pack selects installed packs and needs --pack-db"));
    }
    let (sig_packs, pack_ids) = match &args.pack_db {
        Some(db) => {
            let store = SigPackStore::open(db).map_err(failure)?;
            if args.templates.is_empty() && args.packs.is_empty() {
                let enabled = store.resolve(PackKind::Nuclei, None).map_err(failure)?;
                if enabled.packs.is_empty() && enabled.skipped.is_empty() {
                    return Err(usage(format!(
                        "no enabled Nuclei pack in {}; install one with `signature-pack install --kind nuclei`, or pass --templates",
                        db.display()
                    )));
                }
            }
            (
                SigPacksState::available(store),
                (!args.packs.is_empty()).then(|| args.packs.clone()),
            )
        }
        // Only one-off templates: installed packs are not consulted.
        None => (
            SigPacksState::unavailable("no --pack-db was given".into()),
            Some(Vec::new()),
        ),
    };

    let repository = match &args.db {
        Some(path) => open_repository(path)?,
        None => FindingsRepository::open_in_memory().map_err(|error| failure(error.to_string()))?,
    };
    let findings = FindingsState::available(FindingsService::new(repository));
    let scan_work = crate::scan_work::ScanWorkRegistry::default();
    let progress: Arc<dyn Fn(serde_json::Value) + Send + Sync> = if quiet {
        Arc::new(|_| {})
    } else {
        Arc::new(|payload| {
            if let Some(message) = payload.get("message").and_then(|m| m.as_str()) {
                eprintln!("  {message}");
            }
        })
    };
    let statement = CLI_AUTHORIZATION_STATEMENT;
    debug_assert!(statement.chars().count() <= MAX_STATEMENT_CHARS);
    let request = TemplateScanRequest {
        path: args
            .path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        targets: if live { targets } else { Vec::new() },
        authorization: live.then(|| TemplateAuthorization {
            acknowledged: true,
            statement: statement.into(),
        }),
        pack_ids,
        extra_template_paths: args
            .templates
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        tags: args.tags.clone(),
        exclude_tags: args.exclude_tags.clone(),
        severities: args.severity.clone(),
        template_ids: args.ids.clone(),
        include_intrusive: args.include_intrusive,
        rate_limit: args.rate_limit,
        max_file_size_mb: args.max_file_size_mb,
        operation_id: None,
    };
    // What the user typed is checked here, with the engine's own validation
    // and scope planning, so a bad request is a usage error (exit 2) and
    // only what goes wrong while scanning is a failure (exit 3).
    crate::template::validate_request(&request).map_err(usage)?;
    #[cfg(feature = "templates")]
    if live {
        crate::template::live::plan(&request.targets, &live_settings, request.rate_limit)
            .map_err(usage)?;
    }
    let result = block_on(crate::commands::template::scan_templates_engine(
        &scan_work,
        &findings,
        &sig_packs,
        &StderrEvents { quiet },
        progress,
        request,
        &live_settings,
    ))
    .map_err(failure)?;

    let service = findings
        .service()
        .map_err(|error| failure(error.to_string()))?;
    let rendered = match format {
        OutputFormat::Json => {
            let mut value =
                serde_json::to_value(&result).map_err(|error| failure(error.to_string()))?;
            value["kind"] = serde_json::json!("template");
            oxaudit_parsers::stable_json::to_vec_pretty(&value)
                .map_err(|error| failure(error.to_string()))?
        }
        OutputFormat::Text => render_text(&result).into_bytes(),
        other => render_stored_run(
            service,
            &result.run_id,
            other.as_report_format().expect("report format"),
            quiet,
        )?,
    };
    write_output(args.output.as_deref(), &rendered)?;
    if let Some(path) = &args.db {
        if !quiet {
            eprintln!("Run {} saved to {}", result.run_id, path.display());
        }
    }

    let gated = gate(
        result
            .matches
            .iter()
            .map(|row| severity_rank(&row.severity)),
        args.fail_on,
        quiet,
    );
    if result.state != "completed" {
        report_incomplete("template", &result.incomplete_reasons, &result.notes);
        return Ok(EXIT_FAILURE);
    }
    if args.strict {
        // File-level rows (no template id) are files that did not load.
        let unloaded: Vec<String> = result
            .not_evaluated
            .iter()
            .filter(|row| row.template_id.is_empty())
            .map(|row| format!("{}/{}: {}", row.pack, row.file, row.reason))
            .collect();
        if let Some(message) =
            strict_message("template file(s)", "loaded", unloaded.len(), &unloaded)
        {
            eprintln!("{message}");
            return Ok(EXIT_FAILURE);
        }
    }
    Ok(if gated == EXIT_OK { EXIT_OK } else { gated })
}

/// Characters of a stored response excerpt printed in text mode.
const TEXT_RESPONSE_CHARS: usize = 300;

fn render_text(result: &TemplateScanResult) -> String {
    if result.mode == "targets" {
        return render_targets_text(result);
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Template scan of {} ({}): {} of {} loaded template(s) run from {} pack(s); {} file(s) scanned ({} bytes).",
        result.target,
        result.mode,
        result.templates_run,
        result.templates_loaded,
        result.packs.len(),
        result.files_scanned,
        result.bytes_scanned
    );
    if result.files_scanned == 0 {
        let _ = writeln!(
            out,
            "No file was evaluated by any selected template, so nothing was evaluated. This is not \"no template matched\"; the run is incomplete."
        );
    } else if result.matches.is_empty() {
        let _ = writeln!(
            out,
            "No template matched. That is not a statement about content the templates do not cover, or about templates and files listed below as not evaluated or skipped."
        );
    } else {
        let places = result
            .matches
            .iter()
            .map(|row| row.file_path.as_deref().unwrap_or(row.matched_at.as_str()))
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let _ = writeln!(
            out,
            "{} template match(es) in {places} location(s).",
            result.matches.len() as u64 + result.matches_dropped
        );
    }
    let mut last_place = "";
    for row in &result.matches {
        let place = row.file_path.as_deref().unwrap_or(row.matched_at.as_str());
        if place != last_place {
            let _ = writeln!(out, "\n{place}");
            last_place = place;
        }
        let _ = write!(out, "  [{}] {}  ({})", row.severity, row.name, row.rule_id);
        if !row.tags.is_empty() {
            let _ = write!(out, "  tags: {}", row.tags.join(", "));
        }
        let _ = writeln!(out);
        for line in &row.lines {
            let _ = writeln!(
                out,
                "    {}:{}  {}",
                line.line, line.start_column, line.text
            );
        }
        for (name, values) in &row.extracted {
            let label = if name.is_empty() { "extracted" } else { name };
            let _ = writeln!(out, "    {label}: {}", values.join(", "));
        }
    }
    render_not_evaluated(&mut out, result);
    if !result.skipped.is_empty() {
        let _ = writeln!(out, "\n{} file(s) were not scanned:", result.skipped.len());
        for skipped in result.skipped.iter().take(20) {
            let _ = writeln!(out, "  {}: {}", skipped.path, skipped.reason);
        }
        if result.skipped.len() > 20 {
            let _ = writeln!(out, "  ... and {} more", result.skipped.len() - 20);
        }
    }
    for note in &result.notes {
        let _ = writeln!(out, "note: {note}");
    }
    out
}

fn render_not_evaluated(out: &mut String, result: &TemplateScanResult) {
    if !result.not_evaluated.is_empty() || result.not_evaluated_dropped > 0 {
        let total = result.not_evaluated.len() as u64 + result.not_evaluated_dropped;
        let _ = writeln!(
            out,
            "\n{total} template(s) or template check(s) were not evaluated:"
        );
        // A file that did not load has no template id: name the file, since
        // its reason alone would not say which one it is.
        let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
        for row in &result.not_evaluated {
            let key = if row.template_id.is_empty() {
                format!("{}/{}: {}", row.pack, row.file, row.reason)
            } else {
                row.reason.clone()
            };
            *by_reason.entry(key).or_insert(0) += 1;
        }
        let mut reasons: Vec<(String, u64)> = by_reason.into_iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for (reason, count) in reasons.iter().take(20) {
            let _ = writeln!(out, "  {count} x {reason}");
        }
        if reasons.len() > 20 {
            let _ = writeln!(out, "  ... and {} more reason(s)", reasons.len() - 20);
        }
    }
}

/// One line for a request or response excerpt: tabs and line breaks shown
/// as `\r`, `\n`, `\t`, at most `max` characters.
fn one_line(text: &str, max: usize) -> String {
    let mut line = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= max {
            line.push('\u{2026}');
            break;
        }
        match c {
            '\r' => line.push_str("\\r"),
            '\n' => line.push_str("\\n"),
            '\t' => line.push_str("\\t"),
            c if c.is_control() => line.push('.'),
            c => line.push(c),
        }
    }
    line
}

/// Text report of a live-target scan: matches grouped by target, then what
/// was not evaluated, then what the scope allowed, refused and resolved.
fn render_targets_text(result: &TemplateScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Template scan of live targets {}: {} of {} loaded template(s) run from {} pack(s); {} request(s) sent.",
        result.target,
        result.templates_run,
        result.templates_loaded,
        result.packs.len(),
        result.requests_sent
    );
    let mut by_target: BTreeMap<&str, Vec<&crate::template::TemplateMatchRow>> = BTreeMap::new();
    for row in &result.matches {
        let target = row
            .exchange
            .as_ref()
            .map_or(row.matched_at.as_str(), |exchange| exchange.target.as_str());
        by_target.entry(target).or_default().push(row);
    }
    if result.matches.is_empty() && result.state != "completed" {
        let _ = writeln!(
            out,
            "No template matched in what could be evaluated, and the run is incomplete (see the reasons below; possibly nothing was evaluated at all). That is not a statement about the targets."
        );
    } else if result.matches.is_empty() {
        let _ = writeln!(
            out,
            "No template matched. That is not a statement about the targets: it covers only the templates that ran, and not the checks listed below as not evaluated."
        );
    } else {
        let _ = writeln!(
            out,
            "{} template match(es) on {} target(s).",
            result.matches.len() as u64 + result.matches_dropped,
            by_target.len()
        );
    }
    for (target, rows) in &by_target {
        let _ = writeln!(out, "\n{target}");
        for row in rows {
            let _ = write!(
                out,
                "  [{}] {}  ({}, {})",
                row.severity, row.name, row.rule_id, row.protocol
            );
            if !row.tags.is_empty() {
                let _ = write!(out, "  tags: {}", row.tags.join(", "));
            }
            let _ = writeln!(out);
            if !row.matcher_names.is_empty() {
                let _ = writeln!(out, "    matchers: {}", row.matcher_names.join(", "));
            }
            let _ = writeln!(out, "    matched at: {}", row.matched_at);
            for (name, values) in &row.extracted {
                let label = if name.is_empty() { "extracted" } else { name };
                let _ = writeln!(out, "    {label}: {}", values.join(", "));
            }
            if let Some(exchange) = &row.exchange {
                let request = exchange.request.lines().next().unwrap_or_default();
                let _ = writeln!(out, "    request: {}", one_line(request, 200));
                if crate::template::has_secret_tag(&row.tags) {
                    let _ = writeln!(
                        out,
                        "    response: withheld (this template reports credentials)"
                    );
                } else if !exchange.response_excerpt.is_empty() {
                    let _ = writeln!(
                        out,
                        "    response: {}",
                        one_line(&exchange.response_excerpt, TEXT_RESPONSE_CHARS)
                    );
                }
            }
        }
    }
    render_not_evaluated(&mut out, result);

    let _ = writeln!(out, "\nScope:");
    let _ = writeln!(out, "  requests sent: {}", result.requests_sent);
    if result.refused_hosts.is_empty() {
        let _ = writeln!(
            out,
            "  requests refused by scope (not sent): {}",
            result.requests_refused
        );
    } else {
        let _ = writeln!(
            out,
            "  requests refused by scope (not sent): {}; refused hosts: {}",
            result.requests_refused,
            result.refused_hosts.join(", ")
        );
    }
    for resolved in &result.resolved {
        let _ = writeln!(
            out,
            "  resolved {} -> {}",
            resolved.host,
            resolved.addresses.join(", ")
        );
    }
    if result.unreachable_targets.is_empty() {
        let _ = writeln!(out, "  unreachable targets: none");
    } else {
        let _ = writeln!(out, "  unreachable targets (not evaluated):");
        for unreachable in &result.unreachable_targets {
            let _ = writeln!(out, "    {}: {}", unreachable.target, unreachable.reason);
        }
    }
    for note in &result.notes {
        let _ = writeln!(out, "note: {note}");
    }
    out
}

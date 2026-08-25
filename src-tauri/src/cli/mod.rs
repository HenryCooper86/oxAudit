//! The oxAudit command line.
//!
//! This is a second *adapter* over the same application core the desktop app
//! drives, not a second engine. `scan` runs through `FindingsService::scan`, the
//! same call the Tauri command makes, so a finding reported in CI and a finding
//! reported in the window are the same finding — produced by the same rules,
//! the same policy evaluation, and the same canonical run graph. A CLI that
//! reimplemented any of that would drift, and a scanner whose two front ends
//! disagree is worse than one front end.
//!
//! Exit codes are the contract that matters in a pipeline:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Ran to completion; nothing at or above `--fail-on` |
//! | 1    | Ran to completion; findings at or above `--fail-on` |
//! | 2    | The command was not usable — bad path, bad flag, bad format |
//! | 3    | The scan itself failed |
//!
//! `--fail-on` defaults to `none`, so oxAudit reports without failing a build
//! until someone deliberately asks it to gate one.

pub mod baseline;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

use crate::adapters::reporting::{self, ReportFormat};
use crate::findings::error::CommandError;
use crate::findings::repository::FindingsRepository;
use crate::findings::service::{FindingsService, ScanEventSink};
use crate::models::{Dependency, ScanOptions};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FAILURE: i32 = 3;

// ---------------------------------------------------------------- arguments

#[derive(Parser, Debug)]
#[command(
    name = "oxaudit",
    version,
    about = "Scan source, dependencies, and binaries for vulnerabilities and secrets.",
    long_about = "oxAudit command line.\n\n\
                  Runs the same scanners, rules, and policy evaluation as the oxAudit \
                  desktop app, so results do not diverge between a pipeline and a \
                  workstation.\n\n\
                  Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage error, \
                  3 scan failure."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress progress output on stderr. Report output on stdout is unaffected.
    #[arg(long, short, global = true)]
    quiet: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan source files for dangerous patterns and leaked secrets.
    Scan(ScanArgs),
    /// Resolve lockfiles and check every pinned package against OSV.
    Deps(DepsArgs),
    /// Re-export a stored run in a standards format.
    Export(ExportArgs),
    /// List stored runs.
    Runs(RunsArgs),
    /// Measure the scanners against the committed ground-truth corpus.
    Benchmark(BenchmarkArgs),
    /// List the language grammars compiled into this binary.
    Languages,
    /// Score against the OWASP Benchmark: ground truth oxAudit did not write.
    ExternalBenchmark(ExternalBenchmarkArgs),
}

#[derive(Args, Debug)]
struct ExternalBenchmarkArgs {
    /// Directory holding the fetched OWASP Benchmark checkout.
    #[arg(long, default_value = "benchmarks/external/owasp-benchmark")]
    path: PathBuf,

    /// Emit the full report as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Write the report here instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Exit 1 if the Youden index over covered categories falls below this.
    #[arg(long, value_name = "INDEX")]
    min_score: Option<f64>,
}

#[derive(Args, Debug)]
struct BenchmarkArgs {
    /// Corpus directory holding suite.json and the fixtures.
    #[arg(long, default_value = "benchmarks/corpus")]
    corpus: PathBuf,

    /// Emit the full report as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit 1 if precision falls below this percentage.
    #[arg(long, value_name = "PERCENT")]
    min_precision: Option<f64>,

    /// Exit 1 if recall falls below this percentage.
    #[arg(long, value_name = "PERCENT")]
    min_recall: Option<f64>,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Directory to scan.
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit 1 when a finding at this severity or higher is reported.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    fail_on: FailOn,

    /// A previous `--format json` report to compare against.
    ///
    /// Findings present in it are pre-existing; the rest are new.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Exit 1 only for findings this change introduced, at this severity or
    /// higher. Requires --baseline.
    #[arg(long, value_enum, default_value_t = FailOn::None, value_name = "SEVERITY")]
    fail_on_new: FailOn,

    /// Keep the run in this database so the desktop app can open it.
    /// Without it the scan runs in memory and leaves nothing behind.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Skip secret detection.
    #[arg(long)]
    no_secrets: bool,

    /// Skip dangerous-pattern detection.
    #[arg(long)]
    no_patterns: bool,

    /// Scan inside .git as well.
    #[arg(long)]
    include_git: bool,

    /// Follow symbolic links out of the project.
    #[arg(long)]
    follow_symlinks: bool,

    /// Skip files larger than this, in kilobytes.
    #[arg(long, default_value_t = 1024, value_name = "KB")]
    max_file_size: u64,

    /// Directory name to ignore. Repeat for more.
    #[arg(long = "ignore-dir", value_name = "NAME")]
    ignore_dirs: Vec<String>,

    /// Run even when the project's policy file is invalid.
    #[arg(long)]
    ignore_invalid_policy: bool,
}

#[derive(Args, Debug)]
struct DepsArgs {
    /// Directory to search for lockfiles.
    path: PathBuf,

    /// Output format. Dependency runs are not persisted, so the standards
    /// formats that read a stored run are not offered here.
    #[arg(long, value_enum, default_value_t = DepsFormat::Text)]
    format: DepsFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit 1 when a vulnerability at this severity or higher is reported.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    fail_on: FailOn,

    /// Directory name to ignore. Repeat for more.
    #[arg(long = "ignore-dir", value_name = "NAME")]
    ignore_dirs: Vec<String>,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Database holding the run.
    #[arg(long)]
    db: PathBuf,

    /// Run to export.
    #[arg(long)]
    run: String,

    /// Standards format to emit.
    #[arg(long, value_enum, default_value_t = ExportFormat::Sarif)]
    format: ExportFormat,

    /// Write here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RunsArgs {
    /// Database to list runs from.
    #[arg(long)]
    db: PathBuf,

    /// Most runs to list.
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable summary, grouped by file.
    Text,
    /// oxAudit's own finding list.
    Json,
    /// SARIF 2.1.0, for GitHub code scanning and most CI viewers.
    Sarif,
    /// The full canonical run graph.
    OxauditJson,
    /// CycloneDX 1.6 inventory.
    Cyclonedx,
    /// SPDX 2.3 inventory.
    Spdx,
    /// OpenVEX assertions.
    Openvex,
    /// CycloneDX VEX assertions.
    CyclonedxVex,
}

impl OutputFormat {
    /// Formats that come from the stored canonical run rather than the
    /// in-memory finding list.
    fn as_report_format(self) -> Option<ReportFormat> {
        match self {
            Self::Text | Self::Json => None,
            Self::Sarif => Some(ReportFormat::Sarif),
            Self::OxauditJson => Some(ReportFormat::OxAuditJson),
            Self::Cyclonedx => Some(ReportFormat::CycloneDx),
            Self::Spdx => Some(ReportFormat::Spdx),
            Self::Openvex => Some(ReportFormat::OpenVex),
            Self::CyclonedxVex => Some(ReportFormat::CycloneDxVex),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum DepsFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    Sarif,
    OxauditJson,
    Cyclonedx,
    Spdx,
    Openvex,
    CyclonedxVex,
}

impl From<ExportFormat> for ReportFormat {
    fn from(value: ExportFormat) -> Self {
        match value {
            ExportFormat::Sarif => Self::Sarif,
            ExportFormat::OxauditJson => Self::OxAuditJson,
            ExportFormat::Cyclonedx => Self::CycloneDx,
            ExportFormat::Spdx => Self::Spdx,
            ExportFormat::Openvex => Self::OpenVex,
            ExportFormat::CyclonedxVex => Self::CycloneDxVex,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Never fail on findings. The default: reporting should not break a build
    /// until someone asks it to.
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    fn threshold(self) -> Option<u8> {
        match self {
            Self::None => None,
            Self::Info => Some(severity_rank("info")),
            Self::Low => Some(severity_rank("low")),
            Self::Medium => Some(severity_rank("medium")),
            Self::High => Some(severity_rank("high")),
            Self::Critical => Some(severity_rank("critical")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Higher is more severe, so a threshold comparison reads the way it sounds.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ------------------------------------------------------------- progress sink

/// Relays scan progress to stderr, leaving stdout clean for the report.
///
/// Keeping the two streams separate is what lets `oxaudit scan . --format sarif
/// > out.sarif` work without the caller having to silence anything.
struct StderrEvents {
    quiet: bool,
}

impl ScanEventSink for StderrEvents {
    fn emit(&self, event: &str, payload: Value) -> Result<(), CommandError> {
        if self.quiet {
            return Ok(());
        }
        if event == "scan://progress" {
            if let Some(phase) = payload.as_str() {
                eprintln!("  {phase}…");
            } else if let Some(done) = payload.get("done").and_then(Value::as_u64) {
                let total = payload.get("total").and_then(Value::as_u64).unwrap_or(0);
                if total > 0 && (done == total || done % 500 == 0) {
                    eprintln!("  scanned {done}/{total} files");
                }
            }
        }
        Ok(())
    }
}

// -------------------------------------------------------------------- entry

/// Parse arguments and run. Returns the process exit code.
pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // clap prints help and `--version` through the same error channel;
            // neither is a usage failure.
            let _ = error.print();
            return if error.use_stderr() {
                EXIT_USAGE
            } else {
                EXIT_OK
            };
        }
    };

    let result = match &cli.command {
        Command::Scan(args) => run_scan(args, cli.quiet),
        Command::Deps(args) => run_deps(args, cli.quiet),
        Command::Export(args) => run_export(args),
        Command::Runs(args) => run_runs(args),
        Command::Benchmark(args) => run_benchmark(args, cli.quiet),
        Command::Languages => run_languages(),
        Command::ExternalBenchmark(args) => run_external_benchmark(args),
    };

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("oxaudit: {error}");
            error.exit_code
        }
    }
}

#[derive(Debug)]
struct CliError {
    message: String,
    exit_code: i32,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn usage(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit_code: EXIT_USAGE,
    }
}

fn failure(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit_code: EXIT_FAILURE,
    }
}

type CliResult = Result<i32, CliError>;

// --------------------------------------------------------------------- scan

fn run_scan(args: &ScanArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    if args.no_secrets && args.no_patterns {
        return Err(usage(
            "--no-secrets and --no-patterns together leave nothing to scan",
        ));
    }
    // The canonical run graph lives in the database, so the standards formats
    // cannot be produced without one. Saying so up front beats scanning for a
    // minute and then failing to write the report.
    let needs_storage = args.format.as_report_format().is_some();

    let repository = match &args.db {
        Some(path) => open_repository(path)?,
        None if needs_storage => FindingsRepository::open_in_memory()
            .map_err(|error| failure(format!("could not prepare storage: {error}")))?,
        None => FindingsRepository::open_in_memory()
            .map_err(|error| failure(format!("could not prepare storage: {error}")))?,
    };
    let service = FindingsService::new(repository);

    let options = ScanOptions {
        path: args.path.to_string_lossy().into_owned(),
        include_git: args.include_git,
        follow_symlinks: args.follow_symlinks,
        max_file_size_kb: args.max_file_size.max(1),
        scan_secrets: !args.no_secrets,
        scan_vulnerabilities: !args.no_patterns,
        extra_ignored_dirs: args.ignore_dirs.clone(),
        ignore_invalid_policy: args.ignore_invalid_policy,
    };

    if !quiet {
        eprintln!("Scanning {}", args.path.display());
    }

    let http = build_http_client()?;
    let cve = crate::cve::CveState::new(http);
    let cancel = AtomicBool::new(false);
    let events = StderrEvents { quiet };

    let detail = block_on(service.scan(options, &cve, &cancel, &events)).map_err(|error| {
        // "Nothing matched your filters" is something the caller can fix, so it
        // exits 2 like any other unusable invocation rather than 3, which means
        // the scan itself broke. A pipeline distinguishes the two.
        if error.code == crate::findings::error::ErrorCode::NothingToScan {
            usage(error.to_string())
        } else {
            failure(format!("scan failed: {error}"))
        }
    })?;

    let summary = &detail.summary;
    if !quiet {
        eprintln!(
            "Scanned {} files ({} skipped) in {} ms",
            summary.files_scanned, summary.files_skipped, summary.duration_ms
        );
    }

    let rendered = match args.format {
        OutputFormat::Text => render_findings_text(&detail),
        OutputFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "summary": summary,
            "findings": detail.findings,
        }))
        .map_err(|error| failure(error.to_string()))?,
        other => {
            let format = other
                .as_report_format()
                .expect("non-report formats handled above");
            render_stored_run(&service, &detail.run_id, format, quiet)?
        }
    };

    write_output(args.output.as_deref(), &rendered)?;

    if let Some(path) = &args.db {
        if !quiet {
            eprintln!("Run {} saved to {}", detail.run_id, path.display());
        }
    }

    // A gate on new findings is meaningless without something to be new
    // against, and silently passing would be the dangerous reading.
    if args.fail_on_new != FailOn::None && args.baseline.is_none() {
        return Err(usage("--fail-on-new needs --baseline to compare against"));
    }

    let comparison = match &args.baseline {
        Some(path) => {
            let previous = baseline::load(path).map_err(|error| usage(error.to_string()))?;
            let comparison = baseline::compare(&previous, &detail.findings);
            if !quiet {
                eprintln!(
                    "Against {}: {}",
                    path.display(),
                    baseline::describe(&comparison)
                );
            }
            Some(comparison)
        }
        None => None,
    };

    let gated = gate(
        detail
            .findings
            .iter()
            .filter(|finding| gates_the_build(finding))
            .map(|finding| severity_rank(&finding.severity)),
        args.fail_on,
        quiet,
    );

    let gated_new = match &comparison {
        Some(comparison) => gate(
            comparison
                .introduced
                .iter()
                .filter(|finding| gates_the_build(finding))
                .map(|finding| severity_rank(&finding.severity)),
            args.fail_on_new,
            quiet,
        ),
        None => EXIT_OK,
    };

    // Either gate failing fails the run. They answer different questions —
    // "is this codebase clean?" and "did this change make it worse?" — and a
    // pipeline may reasonably ask both.
    Ok(if gated == EXIT_OK { gated_new } else { gated })
}

// --------------------------------------------------------------------- deps

fn run_deps(args: &DepsArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    let root = args
        .path
        .canonicalize()
        .map_err(|error| usage(format!("cannot resolve {}: {error}", args.path.display())))?;

    if !quiet {
        eprintln!("Discovering lockfiles under {}", root.display());
    }
    let lockfiles = crate::fs_utils::discover_lockfiles(&root, &root, &args.ignore_dirs);
    if lockfiles.is_empty() {
        return Err(failure(format!(
            "no lockfiles found under {}",
            root.display()
        )));
    }

    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut parse_errors: Vec<String> = Vec::new();
    for lockfile in &lockfiles {
        let name = lockfile
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let kind = crate::deps::lockfiles::lockfile_kind(name);
        match crate::deps::lockfiles::parse_lockfile(lockfile, kind) {
            Ok(parsed) => dependencies.extend(parsed),
            // A single unreadable lockfile should not sink the whole run; the
            // errors are reported alongside the results instead.
            Err(error) => parse_errors.push(format!("{}: {error}", lockfile.display())),
        }
    }
    let dependencies = crate::deps::lockfiles::dedupe_dependencies(dependencies);
    if !quiet {
        eprintln!(
            "Found {} package(s) across {} lockfile(s); querying OSV",
            dependencies.len(),
            lockfiles.len()
        );
    }

    let http = build_http_client()?;
    let osv = crate::deps::osv::OsvClient::new(http);
    let matches = block_on(osv.query_batch(&dependencies))
        .map_err(|error| failure(format!("OSV query failed: {error}")))?;

    let mut vulnerabilities: Vec<_> = matches.into_values().flatten().collect();
    vulnerabilities.sort_by(|left, right| {
        severity_rank(right.severity.as_deref().unwrap_or(""))
            .cmp(&severity_rank(left.severity.as_deref().unwrap_or("")))
            .then_with(|| left.package_name.cmp(&right.package_name))
            .then_with(|| left.id.cmp(&right.id))
    });

    let rendered = match args.format {
        DepsFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "lockfiles": lockfiles.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
            "packages": dependencies.len(),
            "parseErrors": parse_errors,
            "vulnerabilities": vulnerabilities,
        }))
        .map_err(|error| failure(error.to_string()))?,
        DepsFormat::Text => {
            render_deps_text(&lockfiles, &dependencies, &vulnerabilities, &parse_errors)
        }
    };

    write_output(args.output.as_deref(), &rendered)?;

    Ok(gate(
        vulnerabilities
            .iter()
            .map(|vulnerability| severity_rank(vulnerability.severity.as_deref().unwrap_or(""))),
        args.fail_on,
        quiet,
    ))
}

// ------------------------------------------------------------------- export

fn run_export(args: &ExportArgs) -> CliResult {
    let service = FindingsService::new(open_repository(&args.db)?);
    let rendered = render_stored_run(&service, &args.run, args.format.into(), false)?;
    write_output(args.output.as_deref(), &rendered)?;
    Ok(EXIT_OK)
}

// --------------------------------------------------------------------- runs

fn run_runs(args: &RunsArgs) -> CliResult {
    let service = FindingsService::new(open_repository(&args.db)?);
    let projects = service
        .list_recent_projects(args.limit)
        .map_err(|error| failure(error.to_string()))?;

    if args.json {
        let bytes =
            serde_json::to_vec_pretty(&projects).map_err(|error| failure(error.to_string()))?;
        write_output(None, &bytes)?;
        return Ok(EXIT_OK);
    }

    if projects.is_empty() {
        println!("No runs stored in {}.", args.db.display());
        return Ok(EXIT_OK);
    }
    for project in &projects {
        println!("{}", serde_json::to_string(project).unwrap_or_default());
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------- benchmark

/// Report which grammars this build carries.
///
/// Grammars are selected by Cargo feature, so two oxAudit binaries of the same
/// version can disagree about how precisely they read a language. A build
/// without a grammar scans that language on text alone: nothing can prove a
/// match sits in a comment, so every match stands. That costs precision and
/// never recall, but a benchmark run against such a build scores differently
/// for a reason that is not the scanner, and this is how you tell.
fn run_languages() -> CliResult {
    let compiled = crate::scanners::syntax::compiled_grammars();
    println!("Grammars compiled into this build ({}):", compiled.len());
    for language in compiled {
        println!("  {language}");
    }
    if compiled.is_empty() {
        println!("  (none — every file is scanned on text alone)");
    }
    println!(
        "\nA language without a grammar is scanned on text alone: matches in \n\
         comments and string literals are reported rather than suppressed."
    );
    Ok(EXIT_OK)
}

fn run_benchmark(args: &BenchmarkArgs, quiet: bool) -> CliResult {
    let suite =
        crate::quality::load_suite(&args.corpus).map_err(|error| usage(error.to_string()))?;
    let report =
        crate::quality::run(&args.corpus, &suite).map_err(|error| failure(error.to_string()))?;

    let rendered = if args.json {
        let mut bytes =
            serde_json::to_vec_pretty(&report).map_err(|error| failure(error.to_string()))?;
        bytes.push(b'\n');
        bytes
    } else {
        crate::quality::render_text(&report).into_bytes()
    };
    write_output(args.output.as_deref(), &rendered)?;

    // A threshold is only meaningful against a defined figure. Refusing to
    // compare against `None` beats treating "nothing fired" as a pass.
    let mut breached = Vec::new();
    if let Some(floor) = args.min_precision {
        match report.precision {
            Some(actual) if actual * 100.0 + f64::EPSILON < floor => breached.push(format!(
                "precision {:.1}% is below the required {floor:.1}%",
                actual * 100.0
            )),
            None => breached.push("precision is undefined; nothing was flagged".to_string()),
            Some(_) => {}
        }
    }
    if let Some(floor) = args.min_recall {
        match report.recall {
            Some(actual) if actual * 100.0 + f64::EPSILON < floor => breached.push(format!(
                "recall {:.1}% is below the required {floor:.1}%",
                actual * 100.0
            )),
            None => breached.push("recall is undefined; the corpus has no positives".to_string()),
            Some(_) => {}
        }
    }

    if breached.is_empty() {
        return Ok(EXIT_OK);
    }
    if !quiet {
        for breach in &breached {
            eprintln!("Failing: {breach}");
        }
    }
    Ok(EXIT_FINDINGS)
}

// ------------------------------------------------------------------ helpers

fn open_repository(path: &Path) -> Result<FindingsRepository, CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| failure(format!("cannot create {}: {error}", parent.display())))?;
        }
    }
    FindingsRepository::open(path)
        .map_err(|error| failure(format!("cannot open {}: {error}", path.display())))
}

fn render_stored_run(
    service: &FindingsService,
    run_id: &str,
    format: ReportFormat,
    quiet: bool,
) -> Result<Vec<u8>, CliError> {
    let identity = oxaudit_domain::RunId::parse(run_id.to_owned())
        .map_err(|_| usage(format!("'{run_id}' is not a run identity")))?;
    let run = service
        .repository()
        .canonical_load_run(&identity)
        .map_err(|error| failure(error.to_string()))?
        .ok_or_else(|| usage(format!("run {run_id} was not found")))?;
    let (artifacts, components, observations) = service
        .repository()
        .canonical_load_report_graph(&identity)
        .map_err(|error| failure(error.to_string()))?;
    let projection = service
        .repository()
        .canonical_load_projection(&identity)
        .map_err(|error| failure(error.to_string()))?;

    let report = reporting::generate(
        &reporting::ReportData {
            run,
            artifacts,
            components,
            observations,
            projection,
        },
        format,
    )
    .map_err(failure)?;

    // Warnings say what a format could not represent — for example a run with
    // no observations that map to SARIF. They belong on stderr, next to the
    // report rather than inside it.
    if !quiet {
        for warning in &report.warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(report.bytes)
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<(), CliError> {
    match path {
        Some(path) => std::fs::write(path, bytes)
            .map_err(|error| failure(format!("cannot write {}: {error}", path.display()))),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(bytes)
                .and_then(|()| stdout.flush())
                .map_err(|error| failure(format!("cannot write to stdout: {error}")))
        }
    }
}

/// Whether a finding should be able to fail the build.
///
/// A committed `.oxaudit/policy.json` exists so a team can say "we looked at
/// this and it is not a problem" once, in review, and not be asked again on
/// every push. A dismissal that still failed the pipeline would make the whole
/// mechanism pointless, so a reviewed-and-dismissed finding is reported but
/// does not gate.
///
/// Only dismissals are excused. An undecided finding gates because nobody has
/// looked at it yet, and a confirmed one gates because somebody looked and said
/// it was real. Expiry is handled upstream: an expired decision is not attached
/// to the finding, so it lands here as undecided and gates again.
fn gates_the_build(finding: &crate::models::Finding) -> bool {
    use crate::findings::domain::ReviewState;
    match finding.review.as_ref().map(|review| review.state) {
        Some(ReviewState::FalsePositive)
        | Some(ReviewState::AcceptedRisk)
        | Some(ReviewState::Suppressed) => false,
        Some(ReviewState::Candidate) | Some(ReviewState::Confirmed) | None => true,
    }
}

/// Decide the exit code from the severities reported and the requested gate.
fn gate(severities: impl Iterator<Item = u8>, fail_on: FailOn, quiet: bool) -> i32 {
    let Some(threshold) = fail_on.threshold() else {
        return EXIT_OK;
    };
    let breaching = severities.filter(|rank| *rank >= threshold).count();
    if breaching == 0 {
        return EXIT_OK;
    }
    if !quiet {
        eprintln!(
            "Failing: {breaching} finding(s) at or above {}",
            fail_on.label()
        );
    }
    EXIT_FINDINGS
}

/// The scanners are async but the CLI is not; one runtime for one command.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start the async runtime")
        .block_on(future)
}

fn build_http_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .user_agent(concat!("oxAudit/", env!("CARGO_PKG_VERSION"), " (cli)"))
        .gzip(true)
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| failure(format!("could not build an HTTP client: {error}")))
}

// ------------------------------------------------------------------ renderers

fn render_findings_text(detail: &crate::findings::domain::ScanRunDetail) -> Vec<u8> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let mut out = String::new();
    let summary = &detail.summary;

    if detail.findings.is_empty() {
        let _ = writeln!(out, "No findings in {} file(s).", summary.files_scanned);
        return out.into_bytes();
    }

    let mut by_file: BTreeMap<&str, Vec<&crate::models::Finding>> = BTreeMap::new();
    for finding in &detail.findings {
        by_file.entry(&finding.file_path).or_default().push(finding);
    }

    for (file, mut findings) in by_file {
        findings.sort_by_key(|finding| (finding.line, finding.column));
        let _ = writeln!(out, "\n{file}");
        for finding in findings {
            let _ = writeln!(
                out,
                "  {}:{}  {:<8} {}  [{}]{}",
                finding.line,
                finding.column,
                finding.severity.to_uppercase(),
                finding.title,
                finding.rule_id,
                finding
                    .cwe
                    .as_deref()
                    .map(|cwe| format!(" {cwe}"))
                    .unwrap_or_default(),
            );
        }
    }

    let _ = writeln!(
        out,
        "\n{} finding(s): {} critical, {} high, {} medium, {} low, {} info",
        summary.total_findings,
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info
    );
    out.into_bytes()
}

fn render_deps_text(
    lockfiles: &[PathBuf],
    dependencies: &[Dependency],
    vulnerabilities: &[crate::models::Vulnerability],
    parse_errors: &[String],
) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} package(s) across {} lockfile(s)",
        dependencies.len(),
        lockfiles.len()
    );
    for error in parse_errors {
        let _ = writeln!(out, "  could not parse {error}");
    }

    if vulnerabilities.is_empty() {
        let _ = writeln!(out, "\nNo known vulnerabilities.");
        return out.into_bytes();
    }

    let _ = writeln!(out);
    for vulnerability in vulnerabilities {
        let fixed = if vulnerability.fixed_versions.is_empty() {
            "no fix published".to_owned()
        } else {
            format!("fixed in {}", vulnerability.fixed_versions.join(", "))
        };
        let mut flags = Vec::new();
        if vulnerability.known_exploited {
            flags.push("KEV");
        }
        if vulnerability.ransomware {
            flags.push("ransomware");
        }
        let _ = writeln!(
            out,
            "{:<8} {} {} — {} ({}){}",
            vulnerability
                .severity
                .as_deref()
                .unwrap_or("unknown")
                .to_uppercase(),
            vulnerability.package_name,
            vulnerability.installed_version,
            vulnerability.id,
            fixed,
            if flags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", flags.join(", "))
            }
        );
    }
    let _ = writeln!(out, "\n{} vulnerability(ies).", vulnerabilities.len());
    out.into_bytes()
}

fn percent(value: Option<f64>) -> String {
    match value {
        Some(value) => format!("{:.1}%", value * 100.0),
        None => "  —  ".to_string(),
    }
}

/// Score oxAudit against the OWASP Benchmark.
///
/// Reported apart from `benchmark` because the two answer different questions.
/// The committed corpus asks "does it still do what we meant?" and is written
/// by the same people who write the rules. This asks "is it any good?" against
/// 2,740 cases labelled by somebody else, and the honest answer is lower.
fn run_external_benchmark(args: &ExternalBenchmarkArgs) -> CliResult {
    let cases =
        crate::external::load_expectations(&args.path).map_err(|error| usage(error.to_string()))?;
    let report =
        crate::external::score(&args.path, &cases).map_err(|error| failure(error.to_string()))?;

    let rendered = if args.json {
        serde_json::to_string_pretty(&report).map_err(|error| failure(error.to_string()))? + "\n"
    } else {
        render_external(&report)
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|error| failure(error.to_string()))?;
        }
        None => print!("{rendered}"),
    }

    if let Some(minimum) = args.min_score {
        let achieved = report.covered_totals.youden_index().unwrap_or(0.0);
        if achieved < minimum {
            return Err(failure(format!(
                "Youden index {achieved:.3} is below the required {minimum:.3}"
            )));
        }
    }
    Ok(EXIT_OK)
}

fn render_external(report: &crate::external::ExternalReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  —  {} cases in {} ms\n",
        report.suite, report.cases, report.runtime_ms
    );

    let covered = &report.covered_totals;
    let _ = writeln!(
        out,
        "  Categories oxAudit has Java rules for: {} cases",
        covered.cases()
    );
    let _ = writeln!(
        out,
        "    precision {}   recall {}   false positive rate {}",
        percent(covered.precision()),
        percent(covered.recall()),
        percent(covered.false_positive_rate())
    );
    // Recall alone is not a result here: flagging every file scores 100%
    // recall and a Youden index of zero, the same as flagging nothing.
    let _ = writeln!(
        out,
        "    Youden index (recall − false positive rate): {}\n",
        match covered.youden_index() {
            Some(value) => format!("{value:.3}"),
            None => "  —  ".to_string(),
        }
    );

    let uncovered = &report.uncovered_totals;
    if uncovered.cases() > 0 {
        let _ = writeln!(
            out,
            "  Categories with no Java rule: {} cases, {} of them vulnerable and\n\
             \x20   necessarily missed. Absent rules, not inaccurate ones — kept out of\n\
             \x20   the figures above so an average cannot blend the two.\n",
            uncovered.cases(),
            uncovered.true_positives + uncovered.false_negatives
        );
    }

    let _ = writeln!(
        out,
        "{:<14} {:>5} {:>5} {:>5} {:>5}  {:>8} {:>8} {:>8} {:>7}",
        "CATEGORY", "TP", "FP", "TN", "FN", "PREC", "RECALL", "FPR", "YOUDEN"
    );
    for score in &report.categories {
        let counts = &score.counts;
        let _ = writeln!(
            out,
            "{:<14} {:>5} {:>5} {:>5} {:>5}  {:>8} {:>8} {:>8} {:>7}{}",
            score.category,
            counts.true_positives,
            counts.false_positives,
            counts.true_negatives,
            counts.false_negatives,
            percent(counts.precision()),
            percent(counts.recall()),
            percent(counts.false_positive_rate()),
            match counts.youden_index() {
                Some(value) => format!("{value:.3}"),
                None => "  —  ".to_string(),
            },
            if score.covered { "" } else { "   (no rule)" }
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_argument_parser_is_internally_consistent() {
        // Catches duplicate short flags, bad defaults, and malformed help long
        // before a user does.
        Cli::command().debug_assert();
    }

    #[test]
    fn fail_on_defaults_to_never_failing() {
        // Reporting must not break someone's build the first time they add
        // oxAudit to a pipeline. Gating is opt-in.
        assert_eq!(FailOn::None.threshold(), None);
        assert_eq!(gate([5, 5, 5].into_iter(), FailOn::None, true), EXIT_OK);
    }

    #[test]
    fn severity_ranking_orders_the_way_the_names_do() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("info"));
        assert!(severity_rank("info") > severity_rank("nonsense"));
    }

    #[test]
    fn severity_ranking_ignores_case() {
        assert_eq!(severity_rank("HIGH"), severity_rank("high"));
    }

    #[test]
    fn the_gate_fires_only_at_or_above_the_threshold() {
        let high = severity_rank("high");
        let medium = severity_rank("medium");
        let critical = severity_rank("critical");

        assert_eq!(gate([medium].into_iter(), FailOn::High, true), EXIT_OK);
        assert_eq!(gate([high].into_iter(), FailOn::High, true), EXIT_FINDINGS);
        assert_eq!(
            gate([critical].into_iter(), FailOn::High, true),
            EXIT_FINDINGS
        );
    }

    #[test]
    fn an_empty_result_never_fails_the_build() {
        assert_eq!(gate(std::iter::empty(), FailOn::Critical, true), EXIT_OK);
        assert_eq!(gate(std::iter::empty(), FailOn::Info, true), EXIT_OK);
    }

    #[test]
    fn unknown_severities_do_not_trip_a_gate() {
        // An advisory with no severity must not be silently treated as
        // critical, which would fail builds for a data-quality problem.
        assert_eq!(
            gate([severity_rank("")].into_iter(), FailOn::Info, true),
            EXIT_OK
        );
    }

    #[test]
    fn text_and_json_do_not_need_a_stored_run_but_the_standards_formats_do() {
        assert!(OutputFormat::Text.as_report_format().is_none());
        assert!(OutputFormat::Json.as_report_format().is_none());
        for format in [
            OutputFormat::Sarif,
            OutputFormat::OxauditJson,
            OutputFormat::Cyclonedx,
            OutputFormat::Spdx,
            OutputFormat::Openvex,
            OutputFormat::CyclonedxVex,
        ] {
            assert!(format.as_report_format().is_some(), "{format:?}");
        }
    }

    #[test]
    fn scanning_nothing_at_all_is_a_usage_error() {
        let cli = Cli::try_parse_from(["oxaudit", "scan", ".", "--no-secrets", "--no-patterns"])
            .expect("flags parse");
        let Command::Scan(args) = &cli.command else {
            panic!("expected scan");
        };
        let error = run_scan(args, true).expect_err("must refuse");
        assert_eq!(error.exit_code, EXIT_USAGE);
    }

    #[test]
    fn a_missing_directory_is_a_usage_error_not_a_crash() {
        let cli =
            Cli::try_parse_from(["oxaudit", "scan", "definitely/not/here"]).expect("flags parse");
        let Command::Scan(args) = &cli.command else {
            panic!("expected scan");
        };
        let error = run_scan(args, true).expect_err("must refuse");
        assert_eq!(error.exit_code, EXIT_USAGE);
        assert!(
            error.message.contains("not a directory"),
            "{}",
            error.message
        );
    }

    #[test]
    fn scan_options_carry_the_flags_through() {
        let cli = Cli::try_parse_from([
            "oxaudit",
            "scan",
            ".",
            "--no-secrets",
            "--include-git",
            "--max-file-size",
            "64",
            "--ignore-dir",
            "vendor",
            "--ignore-dir",
            "third_party",
        ])
        .expect("flags parse");
        let Command::Scan(args) = &cli.command else {
            panic!("expected scan");
        };
        assert!(args.no_secrets);
        assert!(args.include_git);
        assert_eq!(args.max_file_size, 64);
        assert_eq!(args.ignore_dirs, ["vendor", "third_party"]);
    }

    #[test]
    fn a_zero_max_file_size_is_clamped_rather_than_scanning_nothing() {
        // `max_file_size_kb: 0` would skip every file and report a clean scan,
        // which is the most dangerous possible wrong answer for this tool.
        let cli = Cli::try_parse_from(["oxaudit", "scan", ".", "--max-file-size", "0"])
            .expect("flags parse");
        let Command::Scan(args) = &cli.command else {
            panic!("expected scan");
        };
        assert_eq!(args.max_file_size.max(1), 1);
    }
}

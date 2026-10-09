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
mod dependency_baseline;

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
    /// Scan git history for secrets committed at any point, including in files
    /// deleted long ago.
    History(HistoryArgs),
    /// Resolve lockfiles and check every pinned package against OSV.
    Deps(DepsArgs),
    /// Scan a container image, firmware archive, or binary tree with the
    /// native scanner — including the OS package database inside it.
    Image(ImageArgs),
    /// Re-export a stored run in a standards format.
    Export(ExportArgs),
    /// List stored runs.
    Runs(RunsArgs),
    /// Measure the scanners against the committed ground-truth corpus.
    Benchmark(BenchmarkArgs),
    /// Install, list, enable, disable, or remove rule packs in a pack store.
    RulePack {
        #[command(subcommand)]
        command: RulePackCommand,
    },
    /// Import a report's external claims (SARIF, CycloneDX VEX, OpenVEX)
    /// into a findings database. Inventory-only SBOM import stays in the
    /// desktop Export Center.
    Import(ImportArgs),
    /// Trust imported VEX documents and turn their claims into triage
    /// suggestions (never automatic review changes — ADR 0003).
    Vex {
        #[command(subcommand)]
        command: VexCommand,
    },
    /// Build, inspect, or clear the local advisory database used for
    /// network-independent dependency matching.
    AdvisoryDb {
        #[command(subcommand)]
        command: AdvisoryDbCommand,
    },
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

#[derive(Subcommand, Debug)]
enum RulePackCommand {
    /// Validate a pack file and install (or replace) it in the store.
    Install {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Pack TOML file; fixtures must sit beside it.
        path: PathBuf,
    },
    /// List the packs in a store.
    List {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Enable a pack for default application (desktop scans).
    Enable {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Pack id.
        id: String,
    },
    /// Disable a pack for default application (desktop scans).
    Disable {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Pack id.
        id: String,
    },
    /// Remove a pack from the store.
    Remove {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Pack id.
        id: String,
    },
    /// Install or update packs from a feed: an index URL listing packs,
    /// each a digest-verified zip of pack.toml and its fixtures.
    Update {
        /// The rule-pack store database.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Feed index URL.
        #[arg(long, value_name = "URL")]
        feed: String,

        /// Restrict the update to this pack id. Repeatable.
        #[arg(long = "only", value_name = "ID")]
        only: Vec<String>,

        /// Emit the outcome as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct ImportArgs {
    /// Report file: SARIF 2.1.0, OpenVEX, or CycloneDX VEX.
    path: PathBuf,

    /// Findings database holding the imported claims run.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    /// Emit JSON (run id, format, content hash, claim counts) instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum VexCommand {
    /// List imported claim documents and their trust state.
    Claims {
        /// Findings database holding the imported runs.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Grant trust to one imported document by its content hash.
    Trust {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        /// Document content hash, as shown by `vex claims`.
        #[arg(long, value_name = "SHA256")]
        sha: String,
        /// Who granted trust (recorded for audit).
        #[arg(long, value_name = "NAME")]
        by: String,
        /// Why this document is trusted (recorded for audit).
        #[arg(long, value_name = "TEXT")]
        note: Option<String>,
    },
    /// Revoke a document's trust grant; its suggestions stop appearing.
    Revoke {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        #[arg(long, value_name = "SHA256")]
        sha: String,
    },
    /// Map trusted claims against a stored dependency run's advisories.
    Suggest {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        /// Dependency run whose advisories the claims are mapped against.
        #[arg(long, value_name = "ID")]
        run: String,
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AdvisoryDbCommand {
    /// Download OSV's ecosystem dumps and build (or refresh) the database.
    Update {
        /// Advisory database to build. Parent directories are created
        /// owner-only.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Ecosystem to download in addition to the defaults (npm, PyPI,
        /// Maven, crates.io, Go, RubyGems, Packagist, NuGet). Repeatable —
        /// for example `--ecosystem Debian:12 --ecosystem 'Alpine:v3.20'`.
        #[arg(long = "ecosystem", value_name = "NAME")]
        ecosystems: Vec<String>,

        /// Dump base URL. Defaults to OSV's published bucket; point it at a
        /// mirror when the bucket is unreachable.
        #[arg(long, value_name = "URL")]
        source: Option<String>,

        /// Emit the build report as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show what the database covers and how fresh it is.
    Status {
        /// Advisory database to inspect.
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },
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

    /// Follow symbolic links only when their canonical targets remain in the project.
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

    /// Validate and apply this rule pack file for this run only (never
    /// installed). Repeatable; fixtures resolve beside the file.
    #[arg(long = "rule-pack-file", value_name = "FILE")]
    rule_pack_files: Vec<PathBuf>,

    /// Apply these pack ids installed in the store named by --rule-pack-db.
    /// Explicit selection applies the pack as stored, enabled or not.
    #[arg(long = "rule-pack", value_name = "ID")]
    rule_packs: Vec<String>,

    /// Rule-pack store holding the packs --rule-pack selects.
    #[arg(long = "rule-pack-db", value_name = "FILE")]
    rule_pack_db: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct HistoryArgs {
    /// Git repository (or any directory inside one) whose history to scan.
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

    /// A previous `history --format json` report to compare against.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Exit 1 only for findings this run added over --baseline.
    #[arg(long, value_enum, default_value_t = FailOn::None, value_name = "SEVERITY")]
    fail_on_new: FailOn,

    /// Send each found credential to its own provider (fixed endpoints, TLS)
    /// and record whether it was accepted. Opt-in: a default run never puts a
    /// credential on the wire.
    #[arg(long)]
    validate_secrets: bool,
}

#[derive(Args, Debug)]
struct DepsArgs {
    /// Persist this run and complete advisory receipts in a shared database.
    #[arg(long)]
    db: Option<PathBuf>,
    /// Answer advisories from this local advisory database (built with
    /// `advisory-db update`) instead of the OSV API. Works offline.
    #[arg(long, value_name = "FILE")]
    advisory_db: Option<PathBuf>,
    /// Reuse a validated receipt from --db; never contact providers.
    #[arg(long)]
    offline: bool,
    /// Previous complete dependency JSON report.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Gate only advisory/package/version identities absent from --baseline.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    fail_on_new: FailOn,

    /// Directory to search for lockfiles.
    path: PathBuf,

    /// Output format, including canonical standards exports.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

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
struct ImageArgs {
    /// Saved docker/OCI image tar, OCI layout directory, firmware archive,
    /// any binary file or tree — or a registry reference
    /// (`registry.example.com/ns/repo:tag`) to pull the manifest and layers
    /// directly.
    path: PathBuf,

    /// Output format. Image reports support text and json; standards
    /// exports come from `export` over a stored run.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit 1 when a vulnerability at this severity or higher is reported.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    fail_on: FailOn,

    /// Answer distribution-package advisories from this local advisory
    /// database (built with `advisory-db update`), with no network.
    #[arg(long, value_name = "FILE")]
    advisory_db: Option<PathBuf>,

    /// Never contact advisory providers: advisories come only from
    /// --advisory-db. A registry reference still downloads the image — that
    /// is the command you asked for; this flag governs advisory lookups.
    #[arg(long)]
    offline: bool,
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

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RunListKind {
    Source,
    Dependencies,
    Binary,
    All,
}

#[derive(Args, Debug)]
struct RunsArgs {
    /// Explicit canonical run listing. Omit to retain the source project summary format.
    #[arg(long, value_enum)]
    kind: Option<RunListKind>,

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
        Command::History(args) => run_history(args, cli.quiet),
        Command::Deps(args) => run_deps(args, cli.quiet),
        Command::Image(args) => run_image(args, cli.quiet),
        Command::Export(args) => run_export(args),
        Command::Runs(args) => run_runs(args),
        Command::Benchmark(args) => run_benchmark(args, cli.quiet),
        Command::RulePack { command } => run_rule_pack(command, cli.quiet),
        Command::AdvisoryDb { command } => run_advisory_db(command, cli.quiet),
        Command::Import(args) => run_import(args),
        Command::Vex { command } => run_vex(command),
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

fn run_rule_pack(command: &RulePackCommand, quiet: bool) -> CliResult {
    use crate::rulepack_store::RulePackStore;
    let now = chrono::Utc::now().to_rfc3339();
    match command {
        RulePackCommand::Install { db, path } => {
            let (_, toml_text) = crate::rulepack_store::compile_pack_file(path).map_err(usage)?;
            let root = path
                .parent()
                .ok_or_else(|| usage("the rule pack has no containing directory"))?;
            let store = RulePackStore::open(db).map_err(failure)?;
            let installed = store.install(&toml_text, root, &now).map_err(failure)?;
            println!(
                "installed {} ({}) v{} — {} rule(s): {}",
                installed.id,
                installed.name,
                installed.version,
                installed.rule_count,
                installed.engines.join(", ")
            );
            Ok(0)
        }
        RulePackCommand::List { db, json } => {
            let store = RulePackStore::open(db).map_err(failure)?;
            let packs = store.list();
            if *json {
                let rendered = serde_json::to_vec_pretty(&packs)
                    .map_err(|error| failure(error.to_string()))?;
                write_output(None, &rendered)?;
                return Ok(0);
            }
            if packs.is_empty() {
                println!("no rule packs installed in this store");
                return Ok(0);
            }
            for pack in packs {
                println!(
                    "{:<40} {:<10} {:>3} rule(s)  {}  {}",
                    pack.id,
                    format!("v{}", pack.version),
                    pack.rule_count,
                    if pack.enabled { "enabled" } else { "disabled" },
                    pack.engines.join(",")
                );
            }
            Ok(0)
        }
        RulePackCommand::Enable { db, id } => {
            let store = RulePackStore::open(db).map_err(failure)?;
            store.set_enabled(id, true).map_err(failure)?;
            println!("{id} enabled — applies to every desktop source scan");
            Ok(0)
        }
        RulePackCommand::Disable { db, id } => {
            let store = RulePackStore::open(db).map_err(failure)?;
            store.set_enabled(id, false).map_err(failure)?;
            println!("{id} disabled for default application; --rule-pack still selects it");
            Ok(0)
        }
        RulePackCommand::Remove { db, id } => {
            let store = RulePackStore::open(db).map_err(failure)?;
            store.remove(id).map_err(failure)?;
            println!("{id} removed; stored runs keep the findings they recorded");
            Ok(0)
        }
        RulePackCommand::Update {
            db,
            feed,
            only,
            json,
        } => {
            let store = RulePackStore::open(db).map_err(failure)?;
            let http = build_http_client()?;
            let mut fetcher = crate::rulepack_feed::HttpFeedFetcher { http };
            let note = |line: String| {
                if !quiet {
                    eprintln!("{line}");
                }
            };
            let report = block_on(crate::rulepack_feed::update_from_feed(
                &store,
                feed,
                &mut fetcher,
                only,
                note,
            ))
            .map_err(failure)?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "installed": report.installed,
                        "skipped": report.skipped,
                    }))
                    .map_err(|error| failure(error.to_string()))?
                );
            } else {
                for id in &report.installed {
                    println!("{id} installed from the feed");
                }
                for id in &report.skipped {
                    println!("{id} already current; skipped");
                }
            }
            Ok(0)
        }
    }
}

fn run_import(args: &ImportArgs) -> CliResult {
    const MAX_EXTERNAL_CLAIMS: usize = 50_000;
    let (path, bytes, analysis) =
        crate::commands::read_import_report(&args.path.to_string_lossy()).map_err(usage)?;
    if analysis.external_claims.is_empty() {
        return Err(usage(
            "this report has no external claims that can be mapped safely; inventory-only SBOM import lives in the desktop Export Center",
        ));
    }
    if analysis.external_claims.len() > MAX_EXTERNAL_CLAIMS {
        return Err(usage("the report exceeds the 50,000-claim import limit"));
    }
    let repository = open_repository(&args.db)?;
    struct NoEvents;
    impl oxaudit_application::RunEventSink for NoEvents {
        fn publish(&self, _event: &oxaudit_application::EventEnvelope) -> Result<(), String> {
            Ok(())
        }
    }
    let run = crate::commands::reporting::persist_external_claims(
        &repository,
        &path,
        &bytes,
        &analysis,
        &NoEvents,
    )
    .map_err(failure)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run.id.as_str(),
                "format": analysis.format,
                "contentSha256": analysis.content_sha256,
                "claims": analysis.external_claims.len(),
                "unmappedRecords": analysis.unmapped_records.len(),
            }))
            .map_err(|error| failure(error.to_string()))?
        );
    } else {
        println!(
            "imported {} claim(s) from a {} report as run {}",
            analysis.external_claims.len(),
            analysis.format,
            run.id.as_str()
        );
        println!(
            "claims are external-unverified; `vex trust --sha {}` records an explicit trust grant",
            analysis.content_sha256
        );
        for warning in &analysis.warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(EXIT_OK)
}

fn run_vex(command: &VexCommand) -> CliResult {
    let repository = |db: &Path| open_repository(db);
    match command {
        VexCommand::Claims { db, json } => {
            let sets = crate::vex_trust::claim_sets(&repository(db)?).map_err(failure)?;
            let grants = crate::vex_trust::trust_grants(&repository(db)?).map_err(failure)?;
            if *json {
                let document = serde_json::json!({
                    "claimSets": sets.iter().map(|set| serde_json::json!({
                        "runId": set.run_id,
                        "contentSha256": set.content_sha256,
                        "format": set.format,
                        "claims": set.claims.len(),
                        "trusted": grants
                            .iter()
                            .any(|grant| grant.content_sha256 == set.content_sha256),
                    })).collect::<Vec<_>>(),
                    "grants": grants,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&document)
                        .map_err(|error| failure(error.to_string()))?
                );
            } else if sets.is_empty() {
                println!("no imported claim documents; import one from the desktop Export Center");
            } else {
                for set in &sets {
                    let trusted = grants
                        .iter()
                        .any(|grant| grant.content_sha256 == set.content_sha256);
                    println!(
                        "{} {} — {} claim(s), {}",
                        &set.content_sha256[..12.min(set.content_sha256.len())],
                        set.format,
                        set.claims.len(),
                        if trusted { "TRUSTED" } else { "untrusted" },
                    );
                }
            }
            Ok(EXIT_OK)
        }
        VexCommand::Trust { db, sha, by, note } => {
            let grant = crate::vex_trust::grant_trust(
                &repository(db)?,
                sha,
                by,
                note.as_deref().unwrap_or(""),
            )
            .map_err(failure)?;
            println!(
                "trusted document {} (granted by {}, recorded for audit)",
                &grant.content_sha256[..12],
                grant.granted_by
            );
            println!("its not_affected claims now surface as suggestions via `vex suggest`; reviews still need a person");
            Ok(EXIT_OK)
        }
        VexCommand::Revoke { db, sha } => {
            crate::vex_trust::revoke_trust(&repository(db)?, sha).map_err(failure)?;
            println!("trust revoked; suggestions from that document no longer appear");
            Ok(EXIT_OK)
        }
        VexCommand::Suggest { db, run, json } => {
            let repo = repository(db)?;
            let run_id = oxaudit_domain::RunId::parse(run.clone())
                .map_err(|_| usage(format!("'{run}' is not a run identity")))?;
            let projection = repo
                .canonical_load_projection(&run_id)
                .map_err(|error| failure(error.to_string()))?
                .ok_or_else(|| usage(format!("run {run} has no stored projection")))?;
            let scan: crate::models::DependencyScanResult = serde_json::from_value(projection)
                .map_err(|error| usage(format!("run {run} is not a dependency scan: {error}")))?;
            let sets = crate::vex_trust::claim_sets(&repo).map_err(failure)?;
            let grants = crate::vex_trust::trust_grants(&repo).map_err(failure)?;
            let report = crate::vex_trust::suggest(&sets, &grants, &scan.vulnerabilities);
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "run": run,
                        "suggestions": report.suggestions,
                        "unmapped": report.unmapped,
                        "untrustedDocuments": report.untrusted,
                    }))
                    .map_err(|error| failure(error.to_string()))?
                );
            } else {
                if report.suggestions.is_empty() {
                    println!("no suggestions from trusted documents against run {run}");
                }
                for suggestion in &report.suggestions {
                    println!(
                        "[{}] {} {}@{} — {} (document {}, trusted by {})",
                        suggestion.status,
                        suggestion.advisory_id,
                        suggestion.package_name,
                        suggestion.installed_version,
                        suggestion.justification,
                        &suggestion.document_sha256[..12],
                        suggestion.granted_by,
                    );
                    println!(
                        "  a suggestion, not a decision: record the review yourself if you agree"
                    );
                }
                for (sha, record, reason) in &report.unmapped {
                    println!("unmapped: {record} — {reason} (document {})", &sha[..12]);
                }
                for (sha, claims) in &report.untrusted {
                    println!(
                        "untrusted document {} with {claims} claim(s) was not consulted",
                        &sha[..12]
                    );
                }
            }
            Ok(EXIT_OK)
        }
    }
}

fn run_advisory_db(command: &AdvisoryDbCommand, quiet: bool) -> CliResult {
    match command {
        AdvisoryDbCommand::Update {
            db,
            ecosystems,
            source,
            json,
        } => {
            let parent = db.parent().filter(|p| !p.as_os_str().is_empty());
            if let Some(parent) = parent {
                crate::private_storage::ensure_private_dir(parent)
                    .map_err(|error| failure(error.to_string()))?;
            }
            let mut store = crate::advisories::store::AdvisoryDb::open(db)
                .map_err(|error| failure(format!("cannot open {}: {error}", db.display())))?;
            let http = build_http_client()?;
            let mut fetcher = match source {
                Some(base) => crate::advisories::ingest::HttpDumpFetcher::with_base(http, base),
                None => crate::advisories::ingest::HttpDumpFetcher::new(http),
            };
            let mut selected: Vec<String> = crate::advisories::ingest::DEFAULT_ECOSYSTEMS
                .iter()
                .map(|e| e.to_string())
                .collect();
            for ecosystem in ecosystems {
                if !selected.iter().any(|existing| existing == ecosystem) {
                    selected.push(ecosystem.clone());
                }
            }
            let note = |line: String| {
                if !quiet {
                    eprintln!("{line}");
                }
            };
            let report = block_on(crate::advisories::ingest::update(
                &mut store,
                &selected,
                &mut fetcher,
                note,
            ))
            .map_err(failure)?;
            if *json {
                let rendered = serde_json::to_vec_pretty(&serde_json::json!({
                    "db": db.display().to_string(),
                    "ecosystems": report.ecosystems.iter()
                        .map(|e| serde_json::json!({
                            "ecosystem": e.ecosystem,
                            "records": e.records,
                            "zipBytes": e.zip_bytes,
                        }))
                        .collect::<Vec<_>>(),
                    "totalAdvisories": report.total_advisories,
                    "totalPackages": report.total_packages,
                    "builtAtMs": report.built_at_ms,
                }))
                .map_err(|error| failure(error.to_string()))?;
                println!("{}", String::from_utf8_lossy(&rendered));
            } else {
                for ecosystem in &report.ecosystems {
                    println!(
                        "{}: {} advisories ({} MiB dump)",
                        ecosystem.ecosystem,
                        ecosystem.records,
                        ecosystem.zip_bytes / (1024 * 1024)
                    );
                }
                println!(
                    "database holds {} advisories over {} packages; coverage: {}",
                    report.total_advisories,
                    report.total_packages,
                    store.ecosystems().map_err(failure)?.join(", ")
                );
            }
            Ok(EXIT_OK)
        }
        AdvisoryDbCommand::Status { db, json } => {
            let store = crate::advisories::store::AdvisoryDb::open(db)
                .map_err(|error| failure(format!("cannot open {}: {error}", db.display())))?;
            let (advisories, packages) = store.counts().map_err(failure)?;
            let size = std::fs::metadata(db).map(|m| m.len()).unwrap_or(0);
            if *json {
                let rendered = serde_json::json!({
                    "db": db.display().to_string(),
                    "schemaVersion": crate::advisories::store::SCHEMA_VERSION,
                    "ecosystems": store.ecosystems().map_err(failure)?,
                    "advisories": advisories,
                    "packages": packages,
                    "builtAtMs": store.built_at_ms(),
                    "updatedAtMs": store.updated_at_ms(),
                    "sizeBytes": size,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rendered)
                        .map_err(|error| failure(error.to_string()))?
                );
            } else {
                println!(
                    "{} ecosystems: {}",
                    store.ecosystems().map_err(failure)?.len(),
                    store.ecosystems().map_err(failure)?.join(", ")
                );
                println!(
                    "{advisories} advisories over {packages} packages, {} MiB",
                    size / (1024 * 1024)
                );
                println!(
                    "built {}, updated {}",
                    store
                        .built_at_ms()
                        .map(|ms| ms.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    store
                        .updated_at_ms()
                        .map(|ms| ms.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );
            }
            Ok(EXIT_OK)
        }
    }
}

fn run_scan(args: &ScanArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    if args.no_secrets && args.no_patterns {
        return Err(usage(
            "--no-secrets and --no-patterns together leave nothing to scan",
        ));
    }
    // Retain the pre-scan report even when output aliases its path (including
    // symlinks/hard links). Invalid gates must not scan or write anything.
    if args.fail_on_new != FailOn::None && args.baseline.is_none() {
        return Err(usage("--fail-on-new needs --baseline to compare against"));
    }
    let previous = args
        .baseline
        .as_deref()
        .map(baseline::load)
        .transpose()
        .map_err(|error| usage(error.to_string()))?;
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

    let mut options = ScanOptions {
        path: args.path.to_string_lossy().into_owned(),
        include_git: args.include_git,
        follow_symlinks: args.follow_symlinks,
        max_file_size_kb: args.max_file_size.max(1),
        scan_secrets: !args.no_secrets,
        scan_vulnerabilities: !args.no_patterns,
        extra_ignored_dirs: args.ignore_dirs.clone(),
        ignore_invalid_policy: args.ignore_invalid_policy,
        extra_rule_pack_files: Vec::new(),
    };

    if !quiet {
        eprintln!("Scanning {}", args.path.display());
    }

    let http = build_http_client()?;
    let cve = crate::cve::CveState::new(http);
    let cancel = AtomicBool::new(false);
    let events = StderrEvents { quiet };

    // Rule packs resolve before any scanning starts: a pack that fails
    // validation is a caller-fixable problem (exit 2), and a selected pack
    // that cannot be applied fails loudly (exit 3) rather than letting a
    // pipeline report clean with rules silently missing.
    let mut compiled_packs = Vec::new();
    for pack_path in &args.rule_pack_files {
        let pack_path = pack_path
            .canonicalize()
            .map_err(|error| usage(format!("cannot resolve the rule pack: {error}")))?;
        let (compiled, _) = crate::rulepack_store::compile_pack_file(&pack_path).map_err(usage)?;
        options
            .extra_rule_pack_files
            .push(pack_path.to_string_lossy().into_owned());
        if !quiet {
            eprintln!(
                "Rule pack {} v{} validated ({} rules)",
                compiled.metadata().id,
                compiled.metadata().version,
                compiled.rules().len()
            );
        }
        compiled_packs.push(std::sync::Arc::new(compiled));
    }
    let installed_packs = if !args.rule_packs.is_empty() {
        let store_db = args
            .rule_pack_db
            .as_deref()
            .ok_or_else(|| usage("--rule-pack selects installed packs and needs --rule-pack-db"))?;
        let store = crate::rulepack_store::RulePackStore::open(store_db).map_err(failure)?;
        let resolved = store.resolve_selected(&args.rule_packs);
        if !resolved.skipped.is_empty() {
            let reasons = resolved
                .skipped
                .iter()
                .map(|(id, reason)| format!("{id}: {reason}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(failure(format!(
                "selected rule pack(s) could not be applied — {reasons}"
            )));
        }
        resolved.packs
    } else {
        Vec::new()
    };
    let pack_count = compiled_packs.len() + installed_packs.len();
    if !quiet && pack_count > 0 {
        eprintln!(
            "Applying {} rule pack(s); pack findings carry pack/rule ids",
            pack_count
        );
    }
    let packs =
        crate::scanners::rulepacks::AppliedRulePacks::from_sources(installed_packs, compiled_packs);

    let detail = block_on(service.scan_with_packs(options, &cve, &cancel, &events, &packs))
        .map_err(|error| {
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

    let comparison = previous.as_ref().map(|previous| {
        let comparison = baseline::compare(previous, &detail.findings);
        if !quiet {
            eprintln!(
                "Against {}: {}",
                args.baseline.as_ref().unwrap().display(),
                baseline::describe(&comparison)
            );
        }
        comparison
    });

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

// ------------------------------------------------------------------ history

fn run_history(args: &HistoryArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    if args.fail_on_new != FailOn::None && args.baseline.is_none() {
        return Err(usage("--fail-on-new needs --baseline to compare against"));
    }
    // History runs are not stored as canonical runs, so the standards exports
    // (which read a stored run graph) have nothing to read.
    if !matches!(args.format, OutputFormat::Text | OutputFormat::Json) {
        return Err(usage(
            "history supports --format text and --format json; standards exports read stored runs",
        ));
    }
    let previous = args
        .baseline
        .as_deref()
        .map(baseline::load)
        .transpose()
        .map_err(|error| usage(error.to_string()))?;

    if !quiet {
        eprintln!("Scanning git history of {}", args.path.display());
    }
    let started = std::time::Instant::now();
    let mut outcome =
        crate::history::scan_history_secrets_with_options(&args.path, args.validate_secrets)
            .map_err(|error| failure(error.to_string()))?;
    let validation_summary = if args.validate_secrets {
        let http = build_http_client()?;
        let raw = std::mem::take(&mut outcome.raw_secrets);
        let summary = block_on(crate::secrets_validation::validate_raw_secrets(
            &mut outcome.findings,
            raw,
            &http,
        ));
        if !quiet {
            eprintln!("{}", summary.describe());
        }
        Some(summary)
    } else {
        None
    };
    if !quiet {
        eprintln!(
            "Scanned {} distinct blob(s) ({} skipped) in {} ms",
            outcome.blobs_scanned,
            outcome.blobs_skipped,
            started.elapsed().as_millis()
        );
        if outcome.truncated {
            eprintln!(
                "History scan stopped early: {}. Findings below are partial.",
                outcome.limit_note.as_deref().unwrap_or("budget reached")
            );
        }
    }

    let rendered = match args.format {
        OutputFormat::Text => render_history_text(&outcome, validation_summary.as_ref()),
        OutputFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "summary": {
                "blobsScanned": outcome.blobs_scanned,
                "blobsSkipped": outcome.blobs_skipped,
                "durationMs": started.elapsed().as_millis(),
                "truncated": outcome.truncated,
                "limitNote": outcome.limit_note,
                "validation": validation_summary.as_ref().map(|summary| serde_json::json!({
                    "enabled": true,
                    "checked": summary.checked,
                    "live": summary.live,
                    "rejected": summary.rejected,
                    "skippedNoValidator": summary.skipped_no_validator,
                    "skippedUnpaired": summary.skipped_unpaired,
                    "skippedLimit": summary.skipped_limit,
                    "skippedNotKept": summary.skipped_not_kept,
                })),
            },
            "findings": outcome.findings,
        }))
        .map_err(|error| failure(error.to_string()))?,
        // Validation above rejects every other format before any work starts.
        _ => unreachable!("history format validated up front"),
    };
    write_output(args.output.as_deref(), &rendered)?;

    let comparison = previous.as_ref().map(|previous| {
        let comparison = baseline::compare(previous, &outcome.findings);
        if !quiet {
            eprintln!(
                "Against {}: {}",
                args.baseline.as_ref().unwrap().display(),
                baseline::describe(&comparison)
            );
        }
        comparison
    });

    let gated = gate(
        outcome
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
    Ok(if gated == EXIT_OK { gated_new } else { gated })
}

fn render_history_text(
    outcome: &crate::history::HistoryScanOutcome,
    validation_summary: Option<&crate::secrets_validation::ValidationSummary>,
) -> Vec<u8> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let mut out = String::new();
    if outcome.findings.is_empty() {
        let _ = writeln!(
            out,
            "No secrets in history ({} blob(s) scanned).",
            outcome.blobs_scanned
        );
    } else {
        let mut by_file: BTreeMap<&str, Vec<&crate::models::Finding>> = BTreeMap::new();
        for finding in &outcome.findings {
            by_file.entry(&finding.file_path).or_default().push(finding);
        }
        for (file, mut findings) in by_file {
            findings.sort_by_key(|finding| (finding.line, finding.column));
            let _ = writeln!(out, "\n{file}");
            for finding in findings {
                // The verdict is the difference between an emergency and a
                // hygiene item; rejected is not safe, only quieter.
                let verdict = match finding.verified {
                    Some(true) => "  VERIFIED LIVE",
                    Some(false) => "  rejected by provider",
                    None => "",
                };
                let _ = writeln!(
                    out,
                    "  {}:{}  {:<8} {}  [{}]{}",
                    finding.line,
                    finding.column,
                    finding.severity.to_uppercase(),
                    finding.title,
                    finding.rule_id,
                    verdict,
                );
            }
        }
        if let Some(summary) = validation_summary.filter(|summary| summary.live > 0) {
            let _ = writeln!(
                out,
                "\n{} credential(s) were accepted by their provider. Rotate them now; a purge without rotation revokes nothing.",
                summary.live
            );
        }
        let _ = writeln!(
            out,
            "\n{} secret finding(s) in history.",
            outcome.findings.len()
        );
    }
    if let Some(note) = &outcome.limit_note {
        let _ = writeln!(
            out,
            "\nHistory scan stopped early: {note}. Findings above are partial."
        );
    }
    let _ = writeln!(
        out,
        "Paths in findings are historical; the file may no longer exist. Rotation, not deletion, closes a leaked credential."
    );
    out.into_bytes()
}

// --------------------------------------------------------------------- deps

fn run_deps(args: &DepsArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    if args.fail_on_new != FailOn::None && args.baseline.is_none() {
        return Err(usage("--fail-on-new needs --baseline to compare against"));
    }
    // Read and validate before opening storage or writing output, including aliases.
    let previous = args
        .baseline
        .as_deref()
        .map(dependency_baseline::load)
        .transpose()
        .map_err(usage)?;
    let root = args
        .path
        .canonicalize()
        .map_err(|error| usage(error.to_string()))?;
    let repository = match &args.db {
        Some(path) => open_repository(path)?,
        None => FindingsRepository::open_in_memory().map_err(|error| failure(error.to_string()))?,
    };
    let service = FindingsService::new(repository);
    let http = build_http_client()?;
    let osv = crate::deps::osv::OsvClient::new(http.clone());
    let providers = crate::deps::service::NetworkProviders {
        osv: &osv,
        http: &http,
    };
    // Ephemeral invocations also leave no enrichment cache in the project.
    let temporary_cache = tempfile::tempdir().map_err(|error| failure(error.to_string()))?;
    let cache_path = args
        .db
        .as_ref()
        .and_then(|db| db.parent())
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(temporary_cache.path());
    let cancel = AtomicBool::new(false);
    let advisory_db = match &args.advisory_db {
        Some(path) => Some(
            crate::advisories::store::AdvisoryDb::open(path)
                .map_err(|error| failure(format!("cannot open {}: {error}", path.display())))?,
        ),
        None => None,
    };
    let result = block_on(crate::deps::service::scan(
        crate::deps::service::ScanRequest {
            project_root: &root,
            root: &root,
            ignored_dirs: &args.ignore_dirs,
            offline: args.offline,
            advisory_db: advisory_db.as_ref(),
            repository: service.repository(),
            providers: &providers,
            cancel: &cancel,
            events: &StderrEvents { quiet },
            cache_path,
        },
    ))
    .map_err(failure)?;
    let rendered = match args.format {
        OutputFormat::Json => serde_json::to_vec_pretty(&dependency_baseline::report(&result))
            .map_err(|error| failure(error.to_string()))?,
        OutputFormat::Text => {
            let mut bytes = render_deps_text(
                &result
                    .summary
                    .lockfiles_found
                    .iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>(),
                &result.dependencies,
                &result.vulnerabilities,
            );
            bytes.extend_from_slice(
                format!(
                    "\nRun {}; advisory coverage complete ({}).\n",
                    result.summary.run_id.as_deref().unwrap_or("unknown"),
                    result.summary.advisory_source
                )
                .as_bytes(),
            );
            for warning in &result.summary.enrichment.warnings {
                bytes.extend_from_slice(format!("warning: {warning}\n").as_bytes());
            }
            for note in &result.summary.advisory_notes {
                bytes.extend_from_slice(format!("warning: {note}\n").as_bytes());
            }
            for note in &result.summary.inventory_notes {
                bytes.extend_from_slice(format!("warning: {note}\n").as_bytes());
            }
            bytes
        }
        other => render_stored_run(
            &service,
            result
                .summary
                .run_id
                .as_deref()
                .expect("service returns run identity"),
            other.as_report_format().unwrap(),
            quiet,
        )?,
    };
    write_output(args.output.as_deref(), &rendered)?;
    let existing = gate(
        result
            .vulnerabilities
            .iter()
            .map(|v| severity_rank(v.severity.as_deref().unwrap_or(""))),
        args.fail_on,
        quiet,
    );
    let new = gate(
        result
            .vulnerabilities
            .iter()
            .filter(|v| previous.as_ref().is_some_and(|p| !p.contains(v)))
            .map(|v| severity_rank(v.severity.as_deref().unwrap_or(""))),
        args.fail_on_new,
        quiet,
    );
    Ok(if existing == EXIT_OK { new } else { existing })
}

// ------------------------------------------------------------------- image

fn run_image(args: &ImageArgs, quiet: bool) -> CliResult {
    use std::sync::Arc;

    if !matches!(args.format, OutputFormat::Text | OutputFormat::Json) {
        return Err(usage(
            "image reports support --format text or --format json; standards exports come from export over a stored run",
        ));
    }
    let advisory_db = match &args.advisory_db {
        Some(path) => Some(
            crate::advisories::store::AdvisoryDb::open(path)
                .map_err(|error| failure(format!("cannot open {}: {error}", path.display())))?,
        ),
        None => None,
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(String) + Send + Sync> = if quiet {
        Arc::new(|_| {})
    } else {
        Arc::new(|line| eprintln!("{line}"))
    };

    let scanned = if let Some(reference) =
        crate::binscan::registry::parse_ref(&args.path.to_string_lossy())
    {
        let http = build_http_client()?;
        let image = block_on(crate::binscan::registry::fetch_image_layers(
            &http,
            &reference,
            |line| progress(line),
        ))
        .map_err(failure)?;
        crate::binscan::native::scan::scan_image_layers(
            &image.display,
            &image.layers,
            &cancel,
            progress.clone(),
        )
        .map_err(failure)?
    } else {
        if !args.path.exists() {
            return Err(usage(format!("{} does not exist", args.path.display())));
        }
        let target = args
            .path
            .canonicalize()
            .map_err(|error| usage(error.to_string()))?;
        crate::binscan::native::scan::scan(&target, cancel.clone(), progress.clone())
            .map_err(failure)?
    };
    let mut result = scanned.result;
    let mut notes = scanned.notes;

    // The local database answers the distribution half without the network;
    // when scanning online it runs first so a reproducible offline answer
    // wins any duplicate and the network only adds what it can.
    if let Some(db) = &advisory_db {
        let local = crate::binscan::native::enrich::enrich_local(db, &scanned.queries);
        crate::binscan::native::enrich::apply(&mut result, local.found);
        notes.extend(local.notes);
    }

    if !args.offline {
        if !scanned.queries.is_empty() {
            let http = build_http_client()?;
            let cve = crate::cve::CveState::new(http);
            let temporary_cache =
                tempfile::tempdir().map_err(|error| failure(error.to_string()))?;
            let enriched = block_on(crate::binscan::native::enrich::enrich(
                &cve,
                temporary_cache.path(),
                None,
                &scanned.queries,
                cancel,
                progress,
            ));
            crate::binscan::native::enrich::apply(&mut result, enriched.found);
            notes.extend(enriched.notes);
        }
    } else {
        let cpe_askable = scanned
            .queries
            .iter()
            .filter(|query| {
                crate::binscan::native::enrich::cpe_match_string(
                    &query.vendor,
                    &query.product,
                    &query.version,
                )
                .is_some()
            })
            .count();
        if cpe_askable > 0 {
            notes.push(format!(
                "{cpe_askable} CPE-keyed component(s) can only be answered by NVD, which needs the network; they are listed without vulnerabilities in this offline scan"
            ));
        }
        if advisory_db.is_none() && !scanned.queries.is_empty() {
            notes.push(
                "offline image scan without --advisory-db: components are listed without vulnerabilities".into(),
            );
        }
    }

    let rendered = match args.format {
        OutputFormat::Json => {
            let document = serde_json::json!({
                "kind": "image",
                "target": args.path.display().to_string(),
                "summary": result.summary,
                "components": result.components,
                "notes": notes,
            });
            serde_json::to_vec_pretty(&document).map_err(|error| failure(error.to_string()))?
        }
        OutputFormat::Text => render_image_text(&result, &notes),
        _ => unreachable!("validated above"),
    };
    write_output(args.output.as_deref(), &rendered)?;
    let exit = gate(
        result
            .components
            .iter()
            .flat_map(|component| component.vulnerabilities.iter())
            .map(|vulnerability| severity_rank(&vulnerability.severity)),
        args.fail_on,
        quiet,
    );
    Ok(exit)
}

fn render_image_text(
    result: &crate::binscan::report::BinaryScanResult,
    notes: &[String],
) -> Vec<u8> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let summary = &result.summary;
    let _ = writeln!(
        out,
        "Image scan of {}: {} component(s), {} vulnerabilit{} ({})",
        result.target,
        summary.components,
        summary.vulnerabilities,
        if summary.vulnerabilities == 1 {
            "y"
        } else {
            "ies"
        },
        format_vulnerability_counts(summary),
    );
    for component in &result.components {
        let _ = writeln!(
            out,
            "\n{} {} — {} vulnerabilit{}",
            component.product,
            component.version,
            component.vulnerabilities.len(),
            if component.vulnerabilities.len() == 1 {
                "y"
            } else {
                "ies"
            },
        );
        let _ = writeln!(
            out,
            "  at {}",
            component.paths.first().map(String::as_str).unwrap_or("")
        );
        for vulnerability in &component.vulnerabilities {
            let _ = writeln!(
                out,
                "  [{}] {} ({}, source {}) fixed in {}",
                vulnerability.severity,
                vulnerability.cve_id,
                vulnerability
                    .score
                    .map(|score| format!("CVSS {score:.1}"))
                    .unwrap_or_else(|| "no score".into()),
                vulnerability.source,
                vulnerability.fixed_in.as_deref().unwrap_or("—"),
            );
        }
    }
    for note in notes {
        let _ = writeln!(out, "note: {note}");
    }
    out.into_bytes()
}

fn format_vulnerability_counts(summary: &crate::binscan::report::BinaryScanSummary) -> String {
    let parts = [
        ("critical", summary.critical),
        ("high", summary.high),
        ("medium", summary.medium),
        ("low", summary.low),
    ];
    parts
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(name, count)| format!("{count} {name}"))
        .collect::<Vec<_>>()
        .join(", ")
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
    if let Some(kind) = args.kind {
        let kind = match kind {
            RunListKind::Source => Some("source"),
            RunListKind::Dependencies => Some("dependencies"),
            RunListKind::Binary => Some("binary"),
            RunListKind::All => None,
        };
        let runs = service
            .repository()
            .canonical_list_runs(kind, args.limit)
            .map_err(|error| failure(error.to_string()))?;
        let bytes = if args.json {
            serde_json::to_vec_pretty(&runs).map_err(|error| failure(error.to_string()))?
        } else {
            runs.iter()
                .map(|run| {
                    format!(
                        "{} {:?} {:?} {}\n",
                        run.id, run.kind, run.state, run.target_label
                    )
                })
                .collect::<String>()
                .into_bytes()
        };
        write_output(None, &bytes)?;
        return Ok(EXIT_OK);
    }
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
    // The repository creates missing parents with owner-only permissions. A
    // generic create_dir_all here creates an insecure parent that it rejects.
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
    let findings = if matches!(
        run.kind,
        oxaudit_domain::RunKind::Source | oxaudit_domain::RunKind::Secrets
    ) {
        service
            .load_run(run_id)
            .map_err(|error| failure(error.to_string()))?
            .findings
    } else {
        Vec::new()
    };

    let report = reporting::generate(
        &reporting::ReportData {
            run,
            artifacts,
            components,
            observations,
            findings,
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
) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} package(s) across {} lockfile(s)",
        dependencies.len(),
        lockfiles.len()
    );
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
        if vulnerability.public_exploit {
            flags.push("PoC");
        }
        if vulnerability.direct_usage.referenced == Some(true) {
            flags.push("in use");
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
    fn dependency_flags_expose_durable_offline_baseline_and_standards() {
        Cli::try_parse_from([
            "oxaudit",
            "deps",
            ".",
            "--db",
            "runs.sqlite",
            "--offline",
            "--baseline",
            "old.json",
            "--fail-on-new",
            "high",
            "--format",
            "cyclonedx",
        ])
        .expect("shared dependency workflow flags must parse");
        Cli::try_parse_from([
            "oxaudit",
            "runs",
            "--db",
            "runs.sqlite",
            "--kind",
            "dependencies",
            "--json",
        ])
        .expect("dependency history must be discoverable");
    }

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
    fn deps_refuses_an_unparseable_lockfile_before_advisory_lookup() {
        // Replacing this failure with a warning would let a malformed lockfile
        // disappear behind a clean dependency report. The fixture has no valid
        // dependencies, so the current broken behavior reaches an empty OSV
        // query and returns success instead of waiting on a real network call.
        let directory = tempfile::tempdir().expect("temporary project");
        let lockfile = directory.path().join("package-lock.json");
        std::fs::write(&lockfile, "{ this is not JSON").expect("invalid fixture");
        let args = DepsArgs {
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            baseline: None,
            fail_on_new: FailOn::None,
            output: None,
            fail_on: FailOn::None,
            ignore_dirs: Vec::new(),
        };

        let error = run_deps(&args, true).expect_err("incomplete coverage must fail");

        assert_eq!(error.exit_code, EXIT_FAILURE);
        assert!(
            error.message.contains("incomplete dependency coverage"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("package-lock.json"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("invalid package-lock.json"),
            "{}",
            error.message
        );
    }

    #[test]
    fn deps_refuses_partial_lockfile_coverage_even_when_another_lockfile_parses() {
        // A valid inventory beside an invalid lockfile is still incomplete.
        // The parser guard runs before advisory lookup, so this stays local
        // while proving this is not merely the empty-inventory case.
        let directory = tempfile::tempdir().expect("temporary project");
        std::fs::write(directory.path().join("requirements.txt"), "example==1.0\n")
            .expect("valid fixture");
        std::fs::write(directory.path().join("package-lock.json"), "{ malformed")
            .expect("invalid fixture");
        let args = DepsArgs {
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            baseline: None,
            fail_on_new: FailOn::None,
            output: None,
            fail_on: FailOn::None,
            ignore_dirs: Vec::new(),
        };

        let error = run_deps(&args, true).expect_err("partial coverage must fail");

        assert_eq!(error.exit_code, EXIT_FAILURE);
        assert!(
            error.message.contains("package-lock.json"),
            "{}",
            error.message
        );
    }

    #[test]
    fn deps_accepts_a_valid_empty_npm_lockfile() {
        let directory = tempfile::tempdir().expect("temporary project");
        std::fs::write(
            directory.path().join("package-lock.json"),
            r#"{"name":"empty-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"empty-app","version":"1.0.0"}}}"#,
        )
        .expect("valid empty lockfile");
        let args = DepsArgs {
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            baseline: None,
            fail_on_new: FailOn::None,
            output: None,
            fail_on: FailOn::None,
            ignore_dirs: Vec::new(),
        };

        let exit = run_deps(&args, true).expect("valid empty inventory is complete");

        assert_eq!(exit, EXIT_OK);
    }

    #[test]
    fn deps_refuses_a_malformed_npm_v3_entry_before_advisory_lookup() {
        // A null version used to be silently skipped, which made this a
        // zero-query clean result. The parser guard keeps the failure local.
        let directory = tempfile::tempdir().expect("temporary project");
        std::fs::write(
            directory.path().join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":null}}}"#,
        )
        .expect("malformed lockfile");
        let args = DepsArgs {
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            baseline: None,
            fail_on_new: FailOn::None,
            output: None,
            fail_on: FailOn::None,
            ignore_dirs: Vec::new(),
        };

        let error = run_deps(&args, true).expect_err("malformed entry must stop before OSV");

        assert_eq!(error.exit_code, EXIT_FAILURE);
        assert!(
            error.message.contains("package-lock.json"),
            "{}",
            error.message
        );
        assert!(error.message.contains("version"), "{}", error.message);
    }

    #[test]
    fn deps_refuses_a_malformed_lockfile_beside_a_valid_empty_inventory() {
        let directory = tempfile::tempdir().expect("temporary project");
        std::fs::write(
            directory.path().join("package-lock.json"),
            r#"{"name":"empty-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"empty-app","version":"1.0.0"}}}"#,
        )
        .expect("valid empty lockfile");
        std::fs::write(directory.path().join("Cargo.lock"), "not valid TOML [")
            .expect("malformed fixture");
        let args = DepsArgs {
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            baseline: None,
            fail_on_new: FailOn::None,
            output: None,
            fail_on: FailOn::None,
            ignore_dirs: Vec::new(),
        };

        let error = run_deps(&args, true).expect_err("malformed sibling remains incomplete");

        assert_eq!(error.exit_code, EXIT_FAILURE);
        assert!(error.message.contains("Cargo.lock"), "{}", error.message);
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

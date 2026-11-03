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
mod compliance;
mod dependency_baseline;
mod project_config;
mod staged;

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
    /// Install, remove, or inspect the oxaudit pre-commit hook, which scans
    /// the staged git index for secrets before a commit lands.
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Score against the OWASP Benchmark: ground truth oxAudit did not write.
    ExternalBenchmark(ExternalBenchmarkArgs),
    /// Re-match stored dependency inventories against a local advisory
    /// database and report advisories the stored runs did not report.
    /// Built for cron: one honest delta, exit codes for gating, an optional
    /// webhook digest. The stored runs are never modified.
    Monitor(MonitorArgs),
    /// Assess project evidence against built-in compliance readiness
    /// profiles, record reviewer decisions, and compile PDF, HTML,
    /// Markdown, CSV or JSON reports. Evidence readiness only: not
    /// certification, legal advice, or a conformity determination.
    Compliance {
        #[command(subcommand)]
        command: compliance::ComplianceCommand,
    },
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
struct MonitorArgs {
    /// Findings database holding the stored dependency runs to monitor.
    #[arg(long)]
    db: PathBuf,

    /// Local advisory database to re-match against (built with
    /// `oxaudit-cli advisory-db update`).
    #[arg(long, value_name = "DB")]
    advisory_db: PathBuf,

    /// Refresh the advisory database first, for exactly the ecosystems the
    /// monitored inventories use.
    #[arg(long)]
    update: bool,

    /// Dump base for --update (a mirror, or a local test server). Ignored
    /// without --update.
    #[arg(long, value_name = "URL")]
    source: Option<String>,

    /// Monitor these run ids instead of the latest completed dependency run
    /// per target. Every id must name a completed dependencies run.
    #[arg(long = "run", value_name = "ID")]
    runs: Vec<String>,

    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Exit 1 when newly-matching advisories reach this severity. The
    /// default never fails: monitoring reports before anyone asks it to gate.
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,

    /// POST a Slack-compatible {"text": …} digest of the delta to this
    /// webhook URL. A delivery failure fails the command: a monitor whose
    /// alert never left the machine must not report success.
    #[arg(long, value_name = "URL")]
    webhook: Option<String>,
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

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Write (or idempotently refresh) the oxaudit block in
    /// .git/hooks/pre-commit, preserving any hook already there.
    Install,
    /// Remove the oxaudit block from the pre-commit hook, leaving the rest
    /// of the hook — and the file, when anything else remains — untouched.
    Uninstall,
    /// Report whether the oxaudit pre-commit hook is installed and the exact
    /// command it runs.
    Status,
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
        /// Maven, crates.io, Go, RubyGems, Packagist, NuGet, Hex, Pub).
        /// Repeatable —
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
    /// Directory to scan. With --staged it is only used to locate the
    /// repository and defaults to the current directory.
    #[arg(required_unless_present = "staged")]
    path: Option<PathBuf>,

    /// Scan the staged git index — the content a commit would record — for
    /// secrets, instead of the working tree. This is the one mode that reads
    /// index blobs; normal scans never do. In memory only, so --format is
    /// limited to text and json, and --fail-on defaults to high because
    /// every secret rule fires at high severity. Intended for pre-commit
    /// hooks; see `oxaudit hook`.
    #[arg(long)]
    staged: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Prefix SARIF result paths with this directory, so code scanning
    /// resolves them from the repository root when the scanned directory is
    /// a subdirectory. Defaults to the scan root's path inside
    /// GITHUB_WORKSPACE under GitHub Actions; pass "" to turn it off.
    #[arg(long, value_name = "PREFIX")]
    sarif_uri_prefix: Option<String>,

    /// Exit 1 when a finding at this severity or higher is reported.
    /// Defaults to none — reporting should not break a build — except with
    /// --staged, where the default is high; the project config's `[scan]
    /// fail_on` replaces the default.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// A previous `--format json` report to compare against.
    ///
    /// Findings present in it are pre-existing; the rest are new.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Exit 1 only for findings this change introduced, at this severity or
    /// higher. Requires --baseline. Defaults to `none`, or the project
    /// config's `fail_on_new`.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on_new: Option<FailOn>,

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

    /// Skip files larger than this, in kilobytes. Defaults to 1024, or the
    /// project config's `max_file_size_kb`.
    #[arg(long, value_name = "KB")]
    max_file_size: Option<u64>,

    /// Ignore the project's `.oxaudit/config.toml`.
    #[arg(long)]
    no_config: bool,

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

    /// Save the historical Git-object run for reload and standards exports.
    #[arg(long)]
    db: Option<PathBuf>,

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
    /// Defaults to `none`, or the project config's `[deps] fail_on_new`.
    #[arg(long, value_enum)]
    fail_on_new: Option<FailOn>,

    /// Directory to search for lockfiles.
    path: PathBuf,

    /// Output format, including canonical standards exports.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Prefix SARIF result paths with this directory, so code scanning
    /// resolves them from the repository root when the scanned directory is
    /// a subdirectory. Defaults to the scan root's path inside
    /// GITHUB_WORKSPACE under GitHub Actions; pass "" to turn it off.
    #[arg(long, value_name = "PREFIX")]
    sarif_uri_prefix: Option<String>,

    /// Exit 1 when a vulnerability at this severity or higher is reported.
    /// Defaults to `none`, or the project config's `[deps] fail_on`.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Directory name to ignore. Repeat for more.
    #[arg(long = "ignore-dir", value_name = "NAME")]
    ignore_dirs: Vec<String>,

    /// Dismiss advisories by this policy file instead of the project's
    /// `.oxaudit/advisory-policy.json`. Dismissed advisories are still
    /// reported but never gate.
    #[arg(long, value_name = "FILE")]
    advisory_policy: Option<PathBuf>,

    /// Run even when the advisory policy file is invalid.
    #[arg(long)]
    ignore_invalid_policy: bool,

    /// Ignore the project's `.oxaudit/config.toml`.
    #[arg(long)]
    no_config: bool,
}

#[derive(Args, Debug)]
struct ImageArgs {
    /// Save the scan receipt to this database for later reload/export.
    #[arg(long)]
    db: Option<PathBuf>,
    /// Saved docker/OCI image tar, OCI layout directory, firmware archive,
    /// any binary file or tree — or a registry reference
    /// (`registry.example.com/ns/repo:tag`) to pull the manifest and layers
    /// directly.
    path: PathBuf,

    /// Output format; standards exports use the saved canonical graph.
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

    /// Dismiss advisories by this policy file (same format as
    /// `.oxaudit/advisory-policy.json`). Dismissed advisories are still
    /// reported but never gate.
    #[arg(long, value_name = "FILE")]
    advisory_policy: Option<PathBuf>,

    /// Run even when the advisory policy file is invalid.
    #[arg(long)]
    ignore_invalid_policy: bool,
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

    /// Prefix SARIF result paths with this directory (the scanned
    /// directory's path inside the repository), so code scanning resolves
    /// them from the repository root. No default: the stored run does not
    /// know where its scan root sits in a checkout.
    #[arg(long, value_name = "PREFIX")]
    sarif_uri_prefix: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RunListKind {
    Source,
    Dependencies,
    Binary,
    Image,
    History,
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
    /// GitHub Issues import CSV (`title,description,labels`), one row per
    /// finding.
    GithubIssuesCsv,
    /// Jira import CSV (`Summary,Issue Type,Description,Priority,Labels`),
    /// one row per finding.
    JiraCsv,
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
            Self::GithubIssuesCsv => Some(ReportFormat::GithubIssuesCsv),
            Self::JiraCsv => Some(ReportFormat::JiraCsv),
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
    /// GitHub Issues import CSV, one row per finding.
    GithubIssuesCsv,
    /// Jira import CSV, one row per finding.
    JiraCsv,
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
            ExportFormat::GithubIssuesCsv => Self::GithubIssuesCsv,
            ExportFormat::JiraCsv => Self::JiraCsv,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
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
        Command::Hook { command } => staged::run_hook(command),
        Command::ExternalBenchmark(args) => run_external_benchmark(args),
        Command::Monitor(args) => run_monitor(args, cli.quiet),
        Command::Compliance { command } => compliance::run_compliance(command, cli.quiet),
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
            let packs = store.list().map_err(failure)?;
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
    // Staged mode reads the git index, never the working tree — a different
    // evidence surface with its own rendering and gating path.
    if args.staged {
        return staged::run_staged(args, quiet);
    }
    let path = match args.path.as_deref() {
        Some(path) => path,
        // clap enforces the positional unless --staged, so this is unreachable.
        None => return Err(usage("scan needs a directory to scan")),
    };
    if !path.is_dir() {
        return Err(usage(format!("{} is not a directory", path.display())));
    }
    let config = load_config(path, args.no_config)?;
    let merged = merge_scan(
        args,
        config.as_ref().map(|config| &config.scan),
        FailOn::None,
        false,
    )?;
    if let Some(notice) = config_notice(&merged.from_config) {
        eprintln!("{notice}");
    }
    let fail_on = merged.fail_on;
    // Retain the pre-scan report even when output aliases its path (including
    // symlinks/hard links). Invalid gates must not scan or write anything.
    if merged.fail_on_new != FailOn::None && args.baseline.is_none() {
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
        path: path.to_string_lossy().into_owned(),
        include_git: args.include_git,
        follow_symlinks: args.follow_symlinks,
        max_file_size_kb: merged.max_file_size_kb,
        scan_secrets: merged.scan_secrets,
        scan_vulnerabilities: merged.scan_patterns,
        extra_ignored_dirs: merged.ignore_dirs.clone(),
        ignore_invalid_policy: args.ignore_invalid_policy,
        extra_rule_pack_files: Vec::new(),
    };

    if !quiet {
        eprintln!("Scanning {}", path.display());
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
    for pack_path in &merged.rule_pack_files {
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

    let rendered = if args.format == OutputFormat::Sarif {
        let prefix = sarif_prefix(args.sarif_uri_prefix.as_deref(), || {
            automatic_sarif_prefix(path)
        });
        prefix_sarif_uris(&rendered, &prefix)?
    } else {
        rendered
    };
    write_output(args.output.as_deref(), &rendered)?;

    // GitHub integration is environment-gated: workflow annotations go to
    // stderr and the job summary is appended to its file only under Actions,
    // so local runs and piped stdout are untouched.
    emit_github_annotations(&detail.findings, path);
    let mut step_summary = render_summary_markdown(summary, &detail.findings);
    if let Some(notice) = config_notice(&merged.from_config) {
        step_summary.push_str(&format!("\n{notice}\n"));
    }
    write_step_summary(&step_summary, quiet);

    if let Some(db_path) = &args.db {
        if !quiet {
            eprintln!("Run {} saved to {}", detail.run_id, db_path.display());
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
        fail_on,
        quiet,
    );

    let gated_new = match &comparison {
        Some(comparison) => gate(
            comparison
                .introduced
                .iter()
                .filter(|finding| gates_the_build(finding))
                .map(|finding| severity_rank(&finding.severity)),
            merged.fail_on_new,
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
    let previous = args
        .baseline
        .as_deref()
        .map(baseline::load)
        .transpose()
        .map_err(|error| usage(error.to_string()))?;

    if !quiet {
        eprintln!("Scanning git history of {}", args.path.display());
    }
    let repository = match &args.db {
        Some(path) => open_repository(path)?,
        None => FindingsRepository::open_in_memory().map_err(|error| failure(error.to_string()))?,
    };
    let service = FindingsService::new(repository);
    let http = build_http_client()?;
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let events = StderrEvents { quiet };
    let outcome = block_on(crate::commands::history::scan_history_workflow(
        service.repository(),
        &http,
        args.path.to_string_lossy().into_owned(),
        args.validate_secrets,
        &cancel,
        &events,
    ))
    .map_err(failure)?;
    let validation_summary = outcome.validation.as_ref();
    if !quiet {
        eprintln!(
            "Scanned {} distinct blob(s) ({} skipped) in {} ms",
            outcome.blobs_scanned, outcome.blobs_skipped, outcome.duration_ms
        );
        if outcome.truncated {
            eprintln!(
                "History scan stopped early: {}. Findings below are partial.",
                outcome.limit_note.as_deref().unwrap_or("budget reached")
            );
        }
    }

    let rendered = match args.format {
        OutputFormat::Text => render_history_text(&outcome, validation_summary),
        OutputFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "summary": {
                "blobsScanned": outcome.blobs_scanned,
                "blobsSkipped": outcome.blobs_skipped,
                "durationMs": outcome.duration_ms,
                "truncated": outcome.truncated,
                "limitNote": outcome.limit_note,
                "validation": validation_summary.map(|summary| serde_json::json!({
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
            "runId": outcome.run_id,
            "state": outcome.state,
            "target": outcome.target,
            "gitContext": outcome.git_context,
            "blobs": outcome.blobs,
            "findingBlobIds": outcome.finding_blob_ids,
            "findings": outcome.findings,
        }))
        .map_err(|error| failure(error.to_string()))?,
        other => render_stored_run(
            &service,
            &outcome.run_id,
            other.as_report_format().expect("standards output format"),
            quiet,
        )?,
    };
    write_output(args.output.as_deref(), &rendered)?;

    if !quiet {
        if let Some(db) = &args.db {
            eprintln!("History run {} saved to {}", outcome.run_id, db.display());
        }
        if let Some(summary) = validation_summary {
            eprintln!("{}", summary.describe());
        }
    }
    if outcome.state != oxaudit_domain::RunState::Completed {
        return Err(failure(format!(
            "History run {} ended {:?}; output contains partial historical evidence",
            outcome.run_id, outcome.state
        )));
    }

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
    outcome: &crate::commands::history::HistoryScanResponse,
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
    let config = load_config(&args.path, args.no_config)?
        .map(|config| config.deps)
        .unwrap_or_default();
    let (fail_on, fail_on_source) = pick(args.fail_on, config.fail_on, FailOn::None);
    // A config fail_on_new applies only with --baseline, as for `scan`.
    let config_new = args.baseline.as_ref().and(config.fail_on_new);
    let (fail_on_new, fail_on_new_source) = pick(args.fail_on_new, config_new, FailOn::None);
    let ignore_dirs = combined(&config.ignore_dirs, &args.ignore_dirs);
    if fail_on_new != FailOn::None && args.baseline.is_none() {
        return Err(usage("--fail-on-new needs --baseline to compare against"));
    }
    let mut from_config = Vec::new();
    if fail_on_source == GateSource::Config {
        from_config.push(format!("--fail-on {}", fail_on.label()));
    }
    if fail_on_new_source == GateSource::Config {
        from_config.push(format!("--fail-on-new {}", fail_on_new.label()));
    }
    if !config.ignore_dirs.is_empty() {
        from_config.push(format!("ignore_dirs {}", config.ignore_dirs.join(", ")));
    }
    if let Some(notice) = config_notice(&from_config) {
        eprintln!("{notice}");
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
            ignored_dirs: &ignore_dirs,
            offline: args.offline,
            advisory_db: advisory_db.as_ref(),
            repository: service.repository(),
            providers: &providers,
            cancel: &cancel,
            events: &StderrEvents { quiet },
            cache_path,
            advisory_policy: match &args.advisory_policy {
                Some(path) => crate::deps::service::AdvisoryPolicySource::File(path),
                None => crate::deps::service::AdvisoryPolicySource::Project,
            },
            ignore_invalid_policy: args.ignore_invalid_policy,
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
    let rendered = if args.format == OutputFormat::Sarif {
        let prefix = sarif_prefix(args.sarif_uri_prefix.as_deref(), || {
            automatic_sarif_prefix(&root)
        });
        prefix_sarif_uris(&rendered, &prefix)?
    } else {
        rendered
    };
    write_output(args.output.as_deref(), &rendered)?;
    let existing = gate(gating_ranks(result.vulnerabilities.iter()), fail_on, quiet);
    let new = gate(
        gating_ranks(
            result
                .vulnerabilities
                .iter()
                .filter(|v| previous.as_ref().is_some_and(|p| !p.contains(v))),
        ),
        fail_on_new,
        quiet,
    );
    Ok(if existing == EXIT_OK { new } else { existing })
}

// ------------------------------------------------------------------- image

fn run_image(args: &ImageArgs, quiet: bool) -> CliResult {
    use std::sync::Arc;
    let repository = match &args.db {
        Some(path) => open_repository(path)?,
        None => FindingsRepository::open_in_memory().map_err(|error| failure(error.to_string()))?,
    };
    let service = FindingsService::new(repository);
    let http = build_http_client()?;
    let cve = crate::cve::CveState::new(http.clone());
    let cache = tempfile::tempdir().map_err(|error| failure(error.to_string()))?;
    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(String) + Send + Sync> = if quiet {
        Arc::new(|_| {})
    } else {
        Arc::new(|line| eprintln!("{line}"))
    };
    let outcome = block_on(crate::commands::image::scan_image_workflow(
        service.repository(),
        &http,
        Some(&cve),
        None,
        cache.path(),
        progress,
        &StderrEvents { quiet },
        &cancel,
        crate::commands::image::ImageScanRequest {
            target: args.path.to_string_lossy().into_owned(),
            advisory_db_path: args
                .advisory_db
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            offline: args.offline,
            advisory_policy_path: args
                .advisory_policy
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            ignore_invalid_policy: args.ignore_invalid_policy,
            operation_id: None,
        },
    ))
    .map_err(failure)?;
    let rendered = match args.format {
        OutputFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "kind": "image", "runId": outcome.run_id, "target": args.path.display().to_string(),
            "summary": outcome.result.summary, "components": outcome.result.components,
            "notes": outcome.notes, "imageDigest": outcome.image_digest, "layers": outcome.layers,
            "state": outcome.state, "advisoryDbPath": outcome.advisory_db_path, "localEvidence": outcome.local_evidence,
            "offline": outcome.offline,
        })).map_err(|error| failure(error.to_string()))?,
        OutputFormat::Text => render_image_text(&outcome.result, &outcome.notes),
        other => render_stored_run(&service, &outcome.run_id,
            other.as_report_format().expect("report format"), quiet)?,
    };
    write_output(args.output.as_deref(), &rendered)?;
    if let Some(path) = &args.db {
        if !quiet {
            eprintln!("Run {} saved to {}", outcome.run_id, path.display());
        }
    }
    Ok(gate(
        outcome
            .result
            .components
            .iter()
            .flat_map(|component| component.vulnerabilities.iter())
            // A policy-dismissed advisory is reported but never gates.
            .filter(|vulnerability| vulnerability.review.is_none())
            .map(|vulnerability| severity_rank(&vulnerability.severity)),
        args.fail_on,
        quiet,
    ))
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
            if let Some(review) = &vulnerability.review {
                let _ = writeln!(out, "    {}", dismissed_line(review));
            }
        }
    }
    let dismissed = result
        .components
        .iter()
        .flat_map(|component| &component.vulnerabilities)
        .filter(|vulnerability| vulnerability.review.is_some())
        .count();
    if dismissed > 0 {
        let _ = writeln!(
            out,
            "\n{dismissed} dismissed by advisory policy (not gating)."
        );
    }
    for note in notes {
        let _ = writeln!(out, "note: {note}");
    }
    out.into_bytes()
}

/// `dismissed (acceptedRisk): <reason>`, with the expiry when there is one.
fn dismissed_line(review: &crate::findings::advisory_policy::AdvisoryReview) -> String {
    let state = serde_json::to_value(review.state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default();
    match &review.expires_at {
        Some(expires) => format!("dismissed ({state}, until {expires}): {}", review.reason),
        None => format!("dismissed ({state}): {}", review.reason),
    }
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
    let rendered = match (&args.format, args.sarif_uri_prefix.as_deref()) {
        (ExportFormat::Sarif, Some(prefix)) => {
            prefix_sarif_uris(&rendered, &sarif_prefix(Some(prefix), String::new))?
        }
        _ => rendered,
    };
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
            RunListKind::Image => Some("image"),
            RunListKind::History => Some("history"),
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

// ------------------------------------------------------------------ monitor

fn run_monitor(args: &MonitorArgs, quiet: bool) -> CliResult {
    let repository = open_repository(&args.db)?;
    let selected = crate::monitor::select_runs(&repository, &args.runs).map_err(usage)?;
    if selected.is_empty() {
        println!(
            "No completed dependency runs stored in {}.",
            args.db.display()
        );
        return Ok(EXIT_OK);
    }
    let note = |line: String| {
        if !quiet {
            eprintln!("{line}");
        }
    };
    for run in &selected {
        note(format!("monitoring {} (run {})", run.target_label, run.id));
    }
    let inventories = crate::monitor::load_inventories(&repository, &selected).map_err(failure)?;

    if args.update {
        let ecosystems = crate::monitor::ecosystems_used(&inventories);
        if ecosystems.is_empty() {
            note(
                "advisory database update skipped: no monitored inventory declares registry-queryable packages"
                    .into(),
            );
        } else {
            if let Some(parent) = args
                .advisory_db
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
            {
                crate::private_storage::ensure_private_dir(parent)
                    .map_err(|error| failure(error.to_string()))?;
            }
            let mut store =
                crate::advisories::store::AdvisoryDb::open(&args.advisory_db).map_err(|error| {
                    failure(format!(
                        "cannot open {}: {error}",
                        args.advisory_db.display()
                    ))
                })?;
            let http = build_http_client()?;
            let mut fetcher = match &args.source {
                Some(base) => crate::advisories::ingest::HttpDumpFetcher::with_base(http, base),
                None => crate::advisories::ingest::HttpDumpFetcher::new(http),
            };
            note(format!(
                "updating advisory database for: {}",
                ecosystems.join(", ")
            ));
            let report = block_on(crate::advisories::ingest::update(
                &mut store,
                &ecosystems,
                &mut fetcher,
                note,
            ))
            .map_err(failure)?;
            note(format!(
                "advisory database updated: {} advisories over {} packages",
                report.total_advisories, report.total_packages
            ));
        }
    }

    let advisory_db =
        crate::advisories::store::AdvisoryDb::open(&args.advisory_db).map_err(|error| {
            failure(format!(
                "cannot open {}: {error}",
                args.advisory_db.display()
            ))
        })?;
    let outcome = crate::monitor::monitor(&advisory_db, &inventories).map_err(failure)?;

    let rendered = match args.format {
        OutputFormat::Json => {
            serde_json::to_vec_pretty(&outcome).map_err(|error| failure(error.to_string()))?
        }
        OutputFormat::Text => render_monitor_text(&outcome, &args.advisory_db),
        other => {
            return Err(usage(format!(
                "monitor supports --format text or json, not {other:?}"
            )))
        }
    };
    write_output(args.output.as_deref(), &rendered)?;

    if let Some(url) = &args.webhook {
        let digest = monitor_webhook_text(&outcome);
        let status = deliver_webhook(url, &digest).map_err(failure)?;
        note(format!("webhook delivered: HTTP {status}"));
    }

    // Incomplete coverage dominates the gate: a delta computed without every
    // ecosystem is not a trustworthy pass or a trustworthy clean result, so
    // cron sees the same failure the report names.
    if !outcome.coverage_errors().is_empty() {
        for run in outcome.coverage_errors() {
            note(format!(
                "incomplete advisory coverage for {}: {}",
                run.target,
                run.coverage_error.as_deref().unwrap_or_default()
            ));
        }
        return Ok(EXIT_FAILURE);
    }
    Ok(gate(
        outcome
            .runs
            .iter()
            .flat_map(|run| run.newly_matching.iter())
            .map(|advisory| severity_rank(advisory.severity.as_deref().unwrap_or(""))),
        args.fail_on.unwrap_or(FailOn::None),
        quiet,
    ))
}

fn render_monitor_text(
    outcome: &crate::monitor::MonitorOutcome,
    advisory_db_path: &Path,
) -> Vec<u8> {
    let mut out = String::new();
    let built = outcome
        .advisory_db_built_at_ms
        .and_then(rfc3339)
        .unwrap_or_else(|| "unknown".into());
    out.push_str(&format!(
        "Monitoring {} stored dependency run(s) against {} (advisory database built {}).\n",
        outcome.runs.len(),
        advisory_db_path.display(),
        built
    ));
    for run in &outcome.runs {
        out.push_str(&format!("\n{}\n", run.target));
        out.push_str(&format!(
            "  run {}, inventory as of {}; {} component(s), {} re-matched\n",
            run.run_id,
            rfc3339(run.updated_at_ms).unwrap_or_else(|| "unknown".into()),
            run.components_total,
            run.components_matched
        ));
        if run.newly_matching.is_empty() {
            out.push_str("  no advisories beyond what the stored run reported\n");
        } else {
            out.push_str(&format!(
                "  {} advisory/advisories not reported by the stored run:\n",
                run.newly_matching.len()
            ));
            for advisory in &run.newly_matching {
                let severity = advisory.severity.as_deref().unwrap_or("unknown");
                let fixed = if advisory.fixed_versions.is_empty() {
                    String::new()
                } else {
                    format!(" (fixed: {})", advisory.fixed_versions.join(", "))
                };
                out.push_str(&format!(
                    "    {:<8} {} {}@{} {} — {}{}\n",
                    severity,
                    advisory.ecosystem,
                    advisory.package,
                    advisory.installed_version,
                    advisory.advisory_id,
                    advisory.summary,
                    fixed
                ));
            }
        }
        if let Some(error) = &run.coverage_error {
            out.push_str(&format!("  coverage incomplete: {error}\n"));
        }
        for note in &run.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
    }
    out.into_bytes()
}

/// A webhook digest bounded so a pathological delta cannot post an
/// unbounded message; the count line says what was elided.
fn monitor_webhook_text(outcome: &crate::monitor::MonitorOutcome) -> String {
    const MAX_ROWS: usize = 25;
    let built = outcome
        .advisory_db_built_at_ms
        .and_then(rfc3339)
        .unwrap_or_else(|| "unknown".into());
    let total = outcome.total_new();
    let mut text = format!(
        "oxAudit monitor: {total} advisories not reported by stored runs across {} run(s) (advisory database built {built})",
        outcome.runs.len()
    );
    let mut rows = 0usize;
    for run in &outcome.runs {
        if let Some(error) = &run.coverage_error {
            text.push_str(&format!(
                "\ncoverage incomplete for {}: {error}",
                run.target
            ));
        }
        for advisory in &run.newly_matching {
            if rows >= MAX_ROWS {
                text.push_str(&format!(
                    "\n… and {} more (see the full report)",
                    total - MAX_ROWS
                ));
                return text;
            }
            let severity = advisory.severity.as_deref().unwrap_or("unknown");
            text.push_str(&format!(
                "\n[{severity}] {} {}@{} {} — {}",
                advisory.ecosystem,
                advisory.package,
                advisory.installed_version,
                advisory.advisory_id,
                run.target
            ));
            rows += 1;
        }
    }
    text
}

/// POST the digest as a Slack-compatible `{"text": …}` payload.
///
/// Failure messages deliberately never repeat the webhook URL: Slack-style
/// webhook URLs embed a bearer token in the path, and these errors go to
/// stderr and CI logs. reqwest's default error Display includes the URL, so
/// the transport error is stripped with `without_url`; the non-2xx message
/// reports only the status. The caller learns that delivery failed and how,
/// never the secret.
fn deliver_webhook(url: &str, text: &str) -> Result<reqwest::StatusCode, String> {
    let client = build_http_client().map_err(|error| error.to_string())?;
    let response = block_on(
        client
            .post(url)
            .json(&serde_json::json!({ "text": text }))
            .send(),
    )
    .map_err(|error| format!("webhook delivery failed: {}", error.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "webhook delivery failed: the webhook answered HTTP {status}"
        ));
    }
    Ok(status)
}

fn rfc3339(epoch_ms: u64) -> Option<String> {
    chrono::DateTime::from_timestamp_millis(epoch_ms as i64)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
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

/// Where a gate threshold came from, so a config-set gate is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateSource {
    Flag,
    Config,
    Default,
}

/// `scan` settings after the project config is merged in: an explicit flag
/// wins, then the config, then the built-in default; ignore lists combine.
#[derive(Debug)]
struct EffectiveScan {
    ignore_dirs: Vec<String>,
    fail_on: FailOn,
    fail_on_new: FailOn,
    max_file_size_kb: u64,
    scan_secrets: bool,
    scan_patterns: bool,
    rule_pack_files: Vec<PathBuf>,
    /// What the project config changed, for [`config_notice`].
    from_config: Vec<String>,
}

/// Read the scan root's `.oxaudit/config.toml`, unless `--no-config`. An
/// invalid file is a usage error: a typo must not silently loosen a gate.
fn load_config(
    root: &Path,
    no_config: bool,
) -> Result<Option<project_config::ProjectConfig>, CliError> {
    if no_config {
        return Ok(None);
    }
    project_config::load_project_config(root).map_err(|error| match error {
        project_config::ConfigError::Invalid(message) => usage(message),
        project_config::ConfigError::Unreadable(message) => failure(message),
    })
}

/// An explicit value, else the config's, else the default — with its source.
fn pick<T>(flag: Option<T>, config: Option<T>, default: T) -> (T, GateSource) {
    match (flag, config) {
        (Some(value), _) => (value, GateSource::Flag),
        (None, Some(value)) => (value, GateSource::Config),
        (None, None) => (default, GateSource::Default),
    }
}

/// Config entries first, then flags, each name once.
fn combined(config: &[String], flags: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for name in config.iter().chain(flags) {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names
}

/// Merge flags, the project config and defaults for `scan` (`staged` for
/// `scan --staged`, whose default gate is `default_fail_on` and which only
/// takes the gate from the config). A config `fail_on_new` applies only when
/// `--baseline` is given: without one there is nothing to be new against,
/// and a push build, the editor or a local run must not turn into a usage
/// error over a setting nobody passed.
fn merge_scan(
    args: &ScanArgs,
    config: Option<&project_config::ScanConfig>,
    default_fail_on: FailOn,
    staged: bool,
) -> Result<EffectiveScan, CliError> {
    let empty = project_config::ScanConfig::default();
    let config = config.unwrap_or(&empty);
    let (fail_on, fail_on_source) = pick(args.fail_on, config.fail_on, default_fail_on);
    let config_new = if staged || args.baseline.is_none() {
        None
    } else {
        config.fail_on_new
    };
    let (fail_on_new, fail_on_new_source) = pick(args.fail_on_new, config_new, FailOn::None);
    let (max_file_size_kb, size_source) = pick(args.max_file_size, config.max_file_size_kb, 1024);
    let scan_secrets = !args.no_secrets && config.secrets != Some(false);
    let scan_patterns = !args.no_patterns && config.patterns != Some(false);
    if !scan_secrets && !scan_patterns {
        // Name where each switch came from.
        let source = |flag: bool, key: &str| {
            if flag {
                format!("--no-{key}")
            } else {
                format!("the project config's {key} = false")
            }
        };
        return Err(usage(format!(
            "{} and {} together leave nothing to scan",
            source(args.no_secrets, "secrets"),
            source(args.no_patterns, "patterns")
        )));
    }
    let mut rule_pack_files = config.rule_pack_files.clone();
    for path in &args.rule_pack_files {
        if !rule_pack_files.contains(path) {
            rule_pack_files.push(path.clone());
        }
    }

    // Everything the config changed, announced even under --quiet: a
    // committed change that loosens or narrows the scan must leave a trace in
    // CI logs and in the hook's output.
    let mut from_config = Vec::new();
    if fail_on_source == GateSource::Config && !(staged && fail_on == default_fail_on) {
        from_config.push(format!("--fail-on {}", fail_on.label()));
    }
    if fail_on_new_source == GateSource::Config {
        from_config.push(format!("--fail-on-new {}", fail_on_new.label()));
    }
    if !staged {
        if !config.ignore_dirs.is_empty() {
            from_config.push(format!("ignore_dirs {}", config.ignore_dirs.join(", ")));
        }
        if config.secrets == Some(false) && !args.no_secrets {
            from_config.push("secrets off".into());
        }
        if config.patterns == Some(false) && !args.no_patterns {
            from_config.push("patterns off".into());
        }
        if size_source == GateSource::Config {
            from_config.push(format!("max_file_size_kb {max_file_size_kb}"));
        }
        if !config.rule_pack_files.is_empty() {
            from_config.push(format!("{} rule pack(s)", config.rule_pack_files.len()));
        }
    }
    Ok(EffectiveScan {
        ignore_dirs: combined(&config.ignore_dirs, &args.ignore_dirs),
        fail_on,
        fail_on_new,
        // Zero would skip every file and report a clean scan.
        max_file_size_kb: max_file_size_kb.max(1),
        scan_secrets,
        scan_patterns,
        rule_pack_files,
        from_config,
    })
}

/// `Settings from .oxaudit/config.toml: --fail-on high; ignore_dirs vendor`
/// when the config changed anything, else nothing.
fn config_notice(from_config: &[String]) -> Option<String> {
    (!from_config.is_empty()).then(|| {
        format!(
            "Settings from {}: {}",
            project_config::PROJECT_CONFIG_PATH,
            from_config.join("; ")
        )
    })
}

/// Severity ranks of the dependency advisories that can gate the build: an
/// advisory dismissed by the advisory policy is reported but never gates.
fn gating_ranks<'a, I>(vulnerabilities: I) -> impl Iterator<Item = u8> + 'a
where
    I: Iterator<Item = &'a crate::models::Vulnerability> + 'a,
{
    vulnerabilities
        .filter(|vulnerability| vulnerability.review.is_none())
        .map(|vulnerability| severity_rank(vulnerability.severity.as_deref().unwrap_or("")))
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
    render_scan_text(&detail.summary, &detail.findings)
}

/// The shared text rendering: summary header, findings grouped by file,
/// severity counts at the end. `scan --staged` renders through this too, so
/// a leak looks identical whether it was found in the tree or in the index.
fn render_scan_text(
    summary: &crate::models::ScanSummary,
    findings: &[crate::models::Finding],
) -> Vec<u8> {
    use std::fmt::Write as _;

    let mut out = String::new();

    if findings.is_empty() {
        let _ = writeln!(out, "No findings in {} file(s).", summary.files_scanned);
        return out.into_bytes();
    }

    for (file, mut findings) in findings_by_file(findings) {
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

/// Group findings by their file, sorted by path — the grouping both the text
/// report and the GitHub job summary use.
fn findings_by_file(
    findings: &[crate::models::Finding],
) -> std::collections::BTreeMap<&str, Vec<&crate::models::Finding>> {
    let mut by_file: std::collections::BTreeMap<&str, Vec<&crate::models::Finding>> =
        std::collections::BTreeMap::new();
    for finding in findings {
        by_file
            .entry(finding.file_path.as_str())
            .or_default()
            .push(finding);
    }
    by_file
}

// --------------------------------------------------------- github integration

/// Escape a workflow-command message: `%`, CR, and LF would otherwise corrupt
/// the command or inject a second one.
fn escape_github_message(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escape a workflow-command property value: the message escapes, plus `:`
/// and `,`, which terminate and split the property list.
fn escape_github_property(value: &str) -> String {
    escape_github_message(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// One annotation line in GitHub's workflow-command format. Pure, so the
/// exact wire format is testable without standing up a runner. The severity
/// mapping reuses the SARIF one — the two formats grade severity the same
/// way, and "note" is what GitHub calls SARIF's level too, just spelled
/// "notice".
fn github_annotation(finding: &crate::models::Finding, file: &str) -> String {
    let command = match reporting::sarif_level(Some(&finding.severity)) {
        "error" => "error",
        "warning" => "warning",
        _ => "notice",
    };
    format!(
        "::{command} file={},line={},col={},title={}::{}",
        escape_github_property(file),
        finding.line,
        finding.column,
        escape_github_property(&finding.rule_id),
        escape_github_message(&finding.title),
    )
}

/// Finding paths are scan-root-relative; GitHub annotates
/// repo-root-relative paths. When GITHUB_WORKSPACE contains the scan root,
/// prefix the difference; when it cannot be determined, emit paths as-is.
fn github_workspace_prefix(scan_root: &Path) -> String {
    let Some(workspace) = std::env::var_os("GITHUB_WORKSPACE") else {
        return String::new();
    };
    let (Ok(workspace), Ok(root)) = (std::fs::canonicalize(workspace), scan_root.canonicalize())
    else {
        return String::new();
    };
    let Ok(relative) = root.strip_prefix(&workspace) else {
        return String::new();
    };
    if relative.as_os_str().is_empty() {
        String::new()
    } else {
        format!("{}/", relative.to_string_lossy().replace('\\', "/"))
    }
}

/// Emit one GitHub workflow annotation per finding, on stderr — stdout stays
/// clean for the report, whatever --format selected.
fn emit_github_annotations(findings: &[crate::models::Finding], scan_root: &Path) {
    if std::env::var_os("GITHUB_ACTIONS").is_none() {
        return;
    }
    let prefix = github_workspace_prefix(scan_root);
    for line in github_annotation_lines(findings, &prefix) {
        eprintln!("{line}");
    }
}

/// The URI-encoded prefix SARIF artifact URIs get: `--sarif-uri-prefix`
/// when given (an empty value turns prefixing off; an `%XX` escape in it is
/// kept), otherwise `automatic`, which callers derive from GITHUB_WORKSPACE
/// under GitHub Actions — a filesystem path, so every character of it is
/// encoded, `%` included.
fn sarif_prefix(explicit: Option<&str>, automatic: impl FnOnce() -> String) -> String {
    match explicit {
        Some(prefix) => percent_encode_path(prefix),
        None => crate::adapters::reporting::sarif_artifact_uri(&automatic()),
    }
}

/// The automatic SARIF prefix for a scan of `root`: the scan root's path
/// inside GITHUB_WORKSPACE under GitHub Actions, the same prefix workflow
/// annotations get, and nothing elsewhere.
fn automatic_sarif_prefix(root: &Path) -> String {
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        github_workspace_prefix(root)
    } else {
        String::new()
    }
}

/// Percent-encode a relative path for a SARIF URI with the same set as the
/// result URIs that follow it. An existing `%XX` escape is kept, so an
/// already-encoded prefix is not encoded twice.
fn percent_encode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut run_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let escape = bytes[index] == b'%'
            && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit);
        if escape {
            out.push_str(&crate::adapters::reporting::sarif_artifact_uri(
                &path[run_start..index],
            ));
            out.push_str(&path[index..index + 3]);
            index += 3;
            run_start = index;
        } else {
            index += 1;
        }
    }
    out.push_str(&crate::adapters::reporting::sarif_artifact_uri(
        &path[run_start..],
    ));
    out
}

/// Prefix every relative result location URI in a SARIF log with an
/// already URI-encoded prefix (see `sarif_prefix`).
///
/// oxAudit writes paths relative to the scan root; code scanning resolves
/// them against the repository root, so a scan of a subdirectory needs the
/// subdirectory in front. URIs that are absolute (a scheme or a leading `/`)
/// are left alone. Every relative URI is prefixed, even one that already
/// starts with the prefix's name (`mysite/settings.py` inside a scan of
/// `mysite/`), so apply it once per report. An empty prefix returns the
/// input unchanged.
fn prefix_sarif_uris(sarif: &[u8], prefix: &str) -> Result<Vec<u8>, CliError> {
    if prefix.is_empty() {
        return Ok(sarif.to_vec());
    }
    let prefix = if prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    };
    let mut log: serde_json::Value = serde_json::from_slice(sarif).map_err(|error| {
        failure(format!(
            "cannot read the SARIF report to prefix it: {error}"
        ))
    })?;
    let rewrite = |location: &mut serde_json::Value| {
        if let Some(uri) = location.pointer_mut("/physicalLocation/artifactLocation/uri") {
            if let Some(text) = uri.as_str() {
                let absolute =
                    text.starts_with('/') || text.contains("://") || text.starts_with("file:");
                if !absolute {
                    *uri = serde_json::Value::String(format!("{prefix}{text}"));
                }
            }
        }
    };
    for run in log["runs"].as_array_mut().into_iter().flatten() {
        for result in run["results"].as_array_mut().into_iter().flatten() {
            for key in ["locations", "relatedLocations"] {
                for location in result[key].as_array_mut().into_iter().flatten() {
                    rewrite(location);
                }
            }
        }
    }
    // The rewritten log is checked against the bundled SARIF schema, as every
    // generated report is, before anything is written.
    reporting::validate(&log, ReportFormat::Sarif)
        .map_err(|error| failure(format!("prefixed SARIF failed validation: {error}")))?;
    serde_json::to_vec_pretty(&log).map_err(|error| failure(error.to_string()))
}

/// One workflow annotation line per finding that still gates the build, with
/// paths under `prefix`. Findings dismissed in the review policy (false
/// positive, accepted risk, suppressed) do not fail the build, so they do not
/// become pull-request annotations either.
fn github_annotation_lines(findings: &[crate::models::Finding], prefix: &str) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| gates_the_build(finding))
        .map(|finding| github_annotation(finding, &format!("{prefix}{}", finding.file_path)))
        .collect()
}

/// A Markdown job summary: heading, severity table, then the same per-file
/// grouping the text report uses.
fn render_summary_markdown(
    summary: &crate::models::ScanSummary,
    findings: &[crate::models::Finding],
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "## oxAudit scan summary\n");
    let _ = writeln!(
        out,
        "{} file(s) scanned, {} skipped, in {} ms.\n",
        summary.files_scanned, summary.files_skipped, summary.duration_ms
    );
    let _ = writeln!(out, "| Severity | Findings |");
    let _ = writeln!(out, "| --- | ---: |");
    for (label, count) in [
        ("Critical", summary.critical),
        ("High", summary.high),
        ("Medium", summary.medium),
        ("Low", summary.low),
        ("Info", summary.info),
    ] {
        let _ = writeln!(out, "| {label} | {count} |");
    }
    let dismissed = findings
        .iter()
        .filter(|finding| !gates_the_build(finding))
        .count();
    if dismissed > 0 {
        let _ = writeln!(out, "\n{dismissed} dismissed by policy (not annotated).");
    }
    if findings.is_empty() {
        let _ = writeln!(out, "\nNo findings.");
    } else {
        let _ = writeln!(out, "\n### Findings");
        for (file, mut findings) in findings_by_file(findings) {
            findings.sort_by_key(|finding| (finding.line, finding.column));
            let _ = writeln!(out, "\n`{file}`");
            for finding in findings {
                let _ = writeln!(
                    out,
                    "- {}:{} **{}** {} (`{}`)",
                    finding.line,
                    finding.column,
                    finding.severity.to_uppercase(),
                    finding.title,
                    finding.rule_id,
                );
            }
        }
    }
    out
}

/// Append the job summary to $GITHUB_STEP_SUMMARY when a runner provides one.
/// Appending matters: several steps share the file. A summary that fails to
/// write warns on stderr but never fails the scan itself.
fn write_step_summary(markdown: &str, quiet: bool) {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(markdown.as_bytes()));
    if let Err(error) = result {
        if !quiet {
            eprintln!("warning: could not write the GitHub step summary: {error}");
        }
    }
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
        if let Some(review) = &vulnerability.review {
            let _ = writeln!(out, "         {}", dismissed_line(review));
        }
    }
    let _ = writeln!(out, "\n{} vulnerability(ies).", vulnerabilities.len());
    let dismissed = vulnerabilities
        .iter()
        .filter(|v| v.review.is_some())
        .count();
    if dismissed > 0 {
        let _ = writeln!(
            out,
            "{dismissed} dismissed by advisory policy (not gating)."
        );
    }
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
    fn history_cli_saves_and_reexports_git_object_evidence() {
        let root = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| crate::git_context::tests::git(root.path(), args);
        git(&["init", "-b", "main"]);
        git(&["config", "user.email", "history-cli@example.invalid"]);
        git(&["config", "user.name", "History CLI fixture"]);
        std::fs::write(
            root.path().join("deleted.env"),
            "AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-m", "inert history fixture"]);
        std::fs::remove_file(root.path().join("deleted.env")).unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-m", "delete fixture"]);
        let output = tempfile::tempdir().unwrap();
        let database = output.path().join("private/history.sqlite");
        let report = output.path().join("history.json");
        let cli = Cli::try_parse_from([
            "oxaudit",
            "history",
            root.path().to_str().unwrap(),
            "--db",
            database.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            report.to_str().unwrap(),
        ])
        .expect("durable history flags parse");
        let Command::History(args) = cli.command else {
            panic!("history command expected");
        };
        assert_eq!(run_history(&args, true).unwrap(), EXIT_OK);
        let json: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(json["state"], "completed");
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
        let sarif = output.path().join("history.sarif");
        assert_eq!(
            run_export(&ExportArgs {
                sarif_uri_prefix: None,
                db: database,
                run: json["runId"].as_str().unwrap().into(),
                format: ExportFormat::Sarif,
                output: Some(sarif.clone()),
            })
            .unwrap(),
            EXIT_OK
        );
        let content = std::fs::read_to_string(sarif).unwrap();
        assert!(content.contains("git:"));
        assert!(content.contains("!deleted.env"));
        assert!(!content.contains("AKIAZ9X8W7U6T5S4R3Q2"));
    }

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
    fn deps_and_image_accept_advisory_policy_flags() {
        let cli = Cli::try_parse_from([
            "oxaudit-cli",
            "deps",
            ".",
            "--advisory-policy",
            "p.json",
            "--ignore-invalid-policy",
        ])
        .expect("deps flags");
        let Command::Deps(args) = cli.command else {
            panic!("deps")
        };
        assert_eq!(args.advisory_policy.as_deref(), Some(Path::new("p.json")));
        assert!(args.ignore_invalid_policy);
        let cli = Cli::try_parse_from([
            "oxaudit-cli",
            "image",
            "img.tar",
            "--advisory-policy",
            "p.json",
            "--ignore-invalid-policy",
        ])
        .expect("image flags");
        let Command::Image(args) = cli.command else {
            panic!("image")
        };
        assert_eq!(args.advisory_policy.as_deref(), Some(Path::new("p.json")));
        assert!(args.ignore_invalid_policy);
    }

    fn advisory(severity: &str, dismissed: bool) -> crate::models::Vulnerability {
        let mut vulnerability: crate::models::Vulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x", "aliases": [], "summary": "", "details": "", "severity": severity,
            "cvssScore": null, "ecosystem": "npm", "packageName": "p", "installedVersion": "1.0.0",
            "fixedVersions": [], "affectedRange": null, "references": [], "published": null,
            "modified": null, "lockfile": "package-lock.json"
        }))
        .expect("vulnerability");
        if dismissed {
            vulnerability.review = Some(crate::findings::advisory_policy::AdvisoryReview {
                state: crate::findings::domain::ReviewState::AcceptedRisk,
                reason: "fine".into(),
                expires_at: None,
            });
        }
        vulnerability
    }

    #[test]
    fn dismissed_advisories_do_not_gate() {
        let vulnerabilities = [advisory("critical", true), advisory("low", false)];
        let ranks = || gating_ranks(vulnerabilities.iter());
        assert_eq!(gate(ranks(), FailOn::High, true), EXIT_OK);
        assert_eq!(gate(ranks(), FailOn::Low, true), EXIT_FINDINGS);
    }

    fn scan_args(argv: &[&str]) -> ScanArgs {
        let mut full = vec!["oxaudit-cli", "scan"];
        full.extend_from_slice(argv);
        match Cli::try_parse_from(full).expect("scan args").command {
            Command::Scan(args) => args,
            _ => panic!("scan"),
        }
    }

    #[test]
    fn flags_override_config_and_config_overrides_defaults() {
        use project_config::ScanConfig;
        let config = ScanConfig {
            ignore_dirs: vec!["vendored".into(), "dist".into()],
            fail_on: Some(FailOn::High),
            fail_on_new: Some(FailOn::Medium),
            max_file_size_kb: Some(2048),
            secrets: Some(false),
            patterns: None,
            rule_pack_files: Vec::new(),
        };
        // Config fills what no flag set.
        let merged =
            merge_scan(&scan_args(&["."]), Some(&config), FailOn::None, false).expect("merge");
        assert_eq!(merged.fail_on, FailOn::High);
        assert_eq!(
            merged.from_config,
            [
                "--fail-on high",
                "ignore_dirs vendored, dist",
                "secrets off",
                "max_file_size_kb 2048"
            ]
        );
        // No --baseline: the config's fail_on_new has nothing to compare
        // against and is left out rather than becoming a usage error.
        assert_eq!(merged.fail_on_new, FailOn::None);
        assert_eq!(merged.max_file_size_kb, 2048);
        let with_baseline = merge_scan(
            &scan_args(&[".", "--baseline", "b.json"]),
            Some(&config),
            FailOn::None,
            false,
        )
        .expect("merge");
        assert_eq!(with_baseline.fail_on_new, FailOn::Medium);
        assert!(with_baseline
            .from_config
            .contains(&"--fail-on-new medium".to_string()));
        // Staged scans take only the gate, and only when it differs from
        // their own default.
        let staged = merge_scan(&scan_args(&["--staged"]), Some(&config), FailOn::High, true)
            .expect("merge");
        assert!(staged.from_config.is_empty(), "{:?}", staged.from_config);
        assert!(!merged.scan_secrets);
        assert!(merged.scan_patterns);
        assert_eq!(merged.ignore_dirs, ["vendored", "dist"]);
        // Flags win; ignore lists combine, config first, without repeats.
        let merged = merge_scan(
            &scan_args(&[
                ".",
                "--fail-on",
                "low",
                "--fail-on-new",
                "critical",
                "--max-file-size",
                "10",
                "--ignore-dir",
                "dist",
                "--ignore-dir",
                "build",
            ]),
            Some(&config),
            FailOn::None,
            false,
        )
        .expect("merge");
        assert_eq!(merged.fail_on, FailOn::Low);
        assert_eq!(
            merged.from_config,
            ["ignore_dirs vendored, dist", "secrets off"]
        );
        assert_eq!(merged.fail_on_new, FailOn::Critical);
        assert_eq!(merged.max_file_size_kb, 10);
        assert_eq!(merged.ignore_dirs, ["vendored", "dist", "build"]);
        // No config: today's defaults.
        let merged = merge_scan(&scan_args(&["."]), None, FailOn::None, false).expect("merge");
        assert_eq!(merged.fail_on, FailOn::None);
        assert!(merged.from_config.is_empty());
        assert_eq!(merged.fail_on_new, FailOn::None);
        assert_eq!(merged.max_file_size_kb, 1024);
        assert!(merged.scan_secrets && merged.scan_patterns);
        assert!(merged.ignore_dirs.is_empty());
    }

    #[test]
    fn config_disabling_both_scanners_is_a_usage_error() {
        let config = project_config::ScanConfig {
            secrets: Some(false),
            patterns: Some(false),
            ..Default::default()
        };
        let error = merge_scan(&scan_args(&["."]), Some(&config), FailOn::None, false).unwrap_err();
        assert_eq!(error.exit_code, EXIT_USAGE);
        // The message names where each switch came from.
        let only_config =
            merge_scan(&scan_args(&["."]), Some(&config), FailOn::None, false).unwrap_err();
        assert!(
            only_config.message.contains("project config"),
            "{}",
            only_config.message
        );
        assert!(
            !only_config.message.contains("--no-secrets"),
            "{}",
            only_config.message
        );
        let flags = merge_scan(
            &scan_args(&[".", "--no-secrets", "--no-patterns"]),
            None,
            FailOn::None,
            false,
        )
        .unwrap_err();
        assert!(!flags.message.contains("config"), "{}", flags.message);
        let error = merge_scan(
            &scan_args(&[".", "--no-secrets"]),
            Some(&project_config::ScanConfig {
                patterns: Some(false),
                ..Default::default()
            }),
            FailOn::None,
            false,
        )
        .unwrap_err();
        assert_eq!(error.exit_code, EXIT_USAGE);
    }

    #[test]
    fn scan_and_deps_accept_no_config() {
        assert!(scan_args(&[".", "--no-config"]).no_config);
        let Command::Deps(args) = Cli::try_parse_from(["oxaudit-cli", "deps", ".", "--no-config"])
            .expect("deps")
            .command
        else {
            panic!("deps")
        };
        assert!(args.no_config);
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
            sarif_uri_prefix: None,
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            advisory_policy: None,
            ignore_invalid_policy: false,
            no_config: false,
            baseline: None,
            fail_on_new: Some(FailOn::None),
            output: None,
            fail_on: Some(FailOn::None),
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
            sarif_uri_prefix: None,
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            advisory_policy: None,
            ignore_invalid_policy: false,
            no_config: false,
            baseline: None,
            fail_on_new: Some(FailOn::None),
            output: None,
            fail_on: Some(FailOn::None),
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
            sarif_uri_prefix: None,
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            advisory_policy: None,
            ignore_invalid_policy: false,
            no_config: false,
            baseline: None,
            fail_on_new: Some(FailOn::None),
            output: None,
            fail_on: Some(FailOn::None),
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
            sarif_uri_prefix: None,
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            advisory_policy: None,
            ignore_invalid_policy: false,
            no_config: false,
            baseline: None,
            fail_on_new: Some(FailOn::None),
            output: None,
            fail_on: Some(FailOn::None),
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
            sarif_uri_prefix: None,
            advisory_db: None,
            path: directory.path().to_path_buf(),
            format: OutputFormat::Text,
            db: None,
            offline: false,
            advisory_policy: None,
            ignore_invalid_policy: false,
            no_config: false,
            baseline: None,
            fail_on_new: Some(FailOn::None),
            output: None,
            fail_on: Some(FailOn::None),
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
        assert_eq!(args.max_file_size, Some(64));
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
        assert_eq!(
            merge_scan(args, None, FailOn::None, false)
                .unwrap()
                .max_file_size_kb,
            1
        );
    }

    fn reviewed(
        mut finding: crate::models::Finding,
        state: crate::findings::domain::ReviewState,
    ) -> crate::models::Finding {
        finding.review = Some(crate::findings::domain::ReviewRecord {
            id: "review-1".into(),
            project_id: "project".into(),
            fingerprint_version: 1,
            fingerprint: "fp".into(),
            state,
            reason: "reviewed".into(),
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin: crate::findings::domain::ReviewOrigin::ProjectPolicy,
            policy_hash: None,
            updated_at: "2026-11-02T00:00:00Z".into(),
            superseded_at: None,
        });
        finding
    }

    fn sarif_with_uris(uris: &[&str]) -> Vec<u8> {
        let results: Vec<serde_json::Value> = uris
            .iter()
            .map(|uri| {
                serde_json::json!({
                    "message": {"text": "m"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                    "relatedLocations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "oxAudit"}}, "results": results}]
        }))
        .unwrap()
    }

    fn sarif_uris(bytes: &[u8]) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        value["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|result| {
                ["locations", "relatedLocations"].map(|key| {
                    result[key][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
            })
            .collect()
    }

    #[test]
    fn sarif_prefixes_and_result_uris_encode_alike() {
        // The prefix and the path after it are one URI: every character but
        // `%` (kept when it starts an escape) is encoded the same way.
        for byte in (0x20u8..0x7f).filter(|byte| *byte != b'%') {
            let text = (byte as char).to_string();
            assert_eq!(
                percent_encode_path(&text),
                crate::adapters::reporting::sarif_artifact_uri(&text),
                "{text:?}"
            );
        }
        assert_eq!(percent_encode_path("caf\u{e9}"), "caf%C3%A9");
    }

    #[test]
    fn sarif_prefixes_are_percent_encoded_once() {
        let sarif = sarif_with_uris(&["src/app.py"]);
        let prefix = sarif_prefix(Some("my dir/#1/caf\u{e9}%"), String::new);
        let prefixed = prefix_sarif_uris(&sarif, &prefix).unwrap();
        assert_eq!(
            sarif_uris(&prefixed)[0],
            "my%20dir/%231/caf%C3%A9%25/src/app.py"
        );
        // An already-encoded prefix is not encoded again.
        let again =
            prefix_sarif_uris(&sarif, &sarif_prefix(Some("my%20dir"), String::new)).unwrap();
        assert_eq!(sarif_uris(&again)[0], "my%20dir/src/app.py");
    }

    #[test]
    fn sarif_uris_gain_the_prefix_exactly_once_per_application() {
        // A Django project scanned from mysite/ holds mysite/settings.py; its
        // repository path is mysite/mysite/settings.py, so a path that
        // already starts with the prefix's name still gets the prefix.
        let sarif = sarif_with_uris(&[
            "manage.py",
            "mysite/settings.py",
            "file:///abs/x.rs",
            "/abs/y.rs",
        ]);
        let prefixed = prefix_sarif_uris(&sarif, "mysite").unwrap();
        assert_eq!(
            sarif_uris(&prefixed),
            vec![
                "mysite/manage.py",
                "mysite/manage.py",
                "mysite/mysite/settings.py",
                "mysite/mysite/settings.py",
                "file:///abs/x.rs",
                "file:///abs/x.rs",
                "/abs/y.rs",
                "/abs/y.rs",
            ]
        );
        assert_eq!(prefix_sarif_uris(&sarif, "").unwrap(), sarif);
    }

    #[test]
    fn only_an_explicit_sarif_prefix_keeps_its_escapes() {
        // GITHUB_WORKSPACE gives a filesystem path, never an encoded one: a
        // directory literally named `a%41` must not decode as `aA`.
        assert_eq!(sarif_prefix(None, || "a%41 b/".into()), "a%2541%20b/");
        assert_eq!(
            sarif_prefix(Some("a%41 b/"), || unreachable!()),
            "a%41%20b/"
        );
    }

    #[test]
    fn an_explicit_sarif_prefix_overrides_the_automatic_one() {
        assert_eq!(sarif_prefix(Some("sub/"), || "auto/".into()), "sub/");
        assert_eq!(sarif_prefix(Some(""), || "auto/".into()), "");
        assert_eq!(sarif_prefix(None, || "auto/".into()), "auto/");
    }

    #[test]
    fn scan_deps_and_export_accept_a_sarif_prefix() {
        for argv in [
            vec![
                "oxaudit",
                "scan",
                ".",
                "--format",
                "sarif",
                "--sarif-uri-prefix",
                "app/",
            ],
            vec![
                "oxaudit",
                "deps",
                ".",
                "--format",
                "sarif",
                "--sarif-uri-prefix",
                "app/",
            ],
            vec![
                "oxaudit",
                "export",
                "--db",
                "r.sqlite",
                "--run",
                "id",
                "--sarif-uri-prefix",
                "app/",
            ],
        ] {
            Cli::try_parse_from(&argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
        }
    }

    #[test]
    fn export_writes_ticket_csv_formats() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".env"),
            "AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n",
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap();
        let database = output.path().join("private/runs.sqlite");
        let cli = Cli::try_parse_from([
            "oxaudit",
            "scan",
            project.path().to_str().unwrap(),
            "--db",
            database.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            output.path().join("scan.json").to_str().unwrap(),
        ])
        .unwrap();
        let Command::Scan(args) = cli.command else {
            panic!("scan command expected");
        };
        run_scan(&args, true).unwrap();
        let run_id = FindingsService::new(open_repository(&database).unwrap())
            .repository()
            .canonical_list_runs(Some("source"), 1)
            .unwrap()[0]
            .id
            .to_string();

        for (flag, header) in [
            ("github-issues-csv", "title,description,labels"),
            ("jira-csv", "Summary,Issue Type,Description,Priority,Labels"),
        ] {
            let csv = output.path().join(format!("{flag}.csv"));
            let cli = Cli::try_parse_from([
                "oxaudit",
                "export",
                "--db",
                database.to_str().unwrap(),
                "--run",
                &run_id,
                "--format",
                flag,
                "--output",
                csv.to_str().unwrap(),
            ])
            .unwrap_or_else(|error| panic!("{flag}: {error}"));
            let Command::Export(args) = cli.command else {
                panic!("export command expected");
            };
            assert_eq!(run_export(&args).unwrap(), EXIT_OK);
            let text = std::fs::read_to_string(csv).unwrap();
            assert!(text.starts_with(header), "{flag}: {text}");
            // Records end in CRLF; quoted fields may hold bare newlines.
            let records = text
                .split("\r\n")
                .filter(|record| !record.is_empty())
                .count();
            assert_eq!(records, 2, "{flag}: header plus one finding: {text}");
            assert!(
                !text.contains("AKIAZ9X8W7U6T5S4R3Q2"),
                "{flag} leaked the secret"
            );
        }
    }

    #[test]
    fn annotations_skip_dismissed_findings() {
        use crate::findings::domain::ReviewState;
        let findings = vec![
            reviewed(
                test_finding("high", "kept", "Confirmed", "a.rs"),
                ReviewState::Confirmed,
            ),
            test_finding("high", "undecided", "Undecided", "b.rs"),
            reviewed(
                test_finding("high", "fp", "False positive", "c.rs"),
                ReviewState::FalsePositive,
            ),
            reviewed(
                test_finding("high", "risk", "Accepted", "d.rs"),
                ReviewState::AcceptedRisk,
            ),
            reviewed(
                test_finding("high", "quiet", "Suppressed", "e.rs"),
                ReviewState::Suppressed,
            ),
        ];
        let lines = github_annotation_lines(&findings, "sub/");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("file=sub/a.rs"), "{}", lines[0]);
        assert!(lines[1].contains("file=sub/b.rs"), "{}", lines[1]);
    }

    #[test]
    fn step_summary_counts_dismissed_findings_separately() {
        use crate::findings::domain::ReviewState;
        let findings = vec![
            test_finding("high", "kept", "Kept", "a.rs"),
            reviewed(
                test_finding("high", "quiet", "Quiet", "b.rs"),
                ReviewState::Suppressed,
            ),
        ];
        let summary = crate::models::ScanSummary {
            coverage_warnings: Vec::new(),
            git_context: None,
            path: ".".into(),
            files_scanned: 2,
            files_skipped: 0,
            bytes_scanned: 42,
            duration_ms: 5,
            secrets_found: 0,
            vulnerabilities_found: 2,
            total_findings: 2,
            critical: 0,
            high: 2,
            medium: 0,
            low: 0,
            info: 0,
            rules_fired: std::collections::BTreeMap::new(),
        };
        let markdown = render_summary_markdown(&summary, &findings);
        assert!(
            markdown.contains("1 dismissed by policy (not annotated)"),
            "{markdown}"
        );
    }

    fn test_finding(
        severity: &str,
        rule_id: &str,
        title: &str,
        file: &str,
    ) -> crate::models::Finding {
        crate::models::Finding {
            id: "test".into(),
            category: "secret".into(),
            rule_id: rule_id.into(),
            rule_name: rule_id.into(),
            severity: severity.into(),
            title: title.into(),
            description: String::new(),
            file_path: file.into(),
            line: 3,
            column: 7,
            match_text: String::new(),
            context: String::new(),
            language: String::new(),
            cwe: None,
            cwe_exploited: false,
            cwe_exploited_count: 0,
            recommendation: String::new(),
            entropy: None,
            verified: None,
            analysis: crate::models::AnalysisTier::Text,
            analysis_gates: Vec::new(),
            in_test_region: false,
            observation_run_id: String::new(),
            resolved_by_run_id: None,
            fingerprint_version: 0,
            fingerprint: String::new(),
            scope: None,
            scope_reason: None,
            review: None,
            review_history: Vec::new(),
            diff_status: None,
        }
    }

    #[test]
    fn workflow_commands_escape_properties_and_messages_by_their_own_rules() {
        // `%`, CR, LF everywhere; `:` and `,` additionally in properties.
        assert_eq!(escape_github_message("100%\r\nx:y,z"), "100%25%0D%0Ax:y,z");
        assert_eq!(
            escape_github_property("100%\r\nx:y,z"),
            "100%25%0D%0Ax%3Ay%2Cz"
        );
    }

    #[test]
    fn annotations_follow_the_workflow_command_wire_format() {
        let finding = test_finding("high", "aws:key", "AWS key 100%\nlive", "src/a,b.rs");
        assert_eq!(
            github_annotation(&finding, "src/a,b.rs"),
            "::error file=src/a%2Cb.rs,line=3,col=7,title=aws%3Akey::AWS key 100%25%0Alive"
        );
        // The SARIF grading carries over: medium warns, info notices.
        assert!(
            github_annotation(&test_finding("medium", "r", "t", "f"), "f")
                .starts_with("::warning ")
        );
        assert!(
            github_annotation(&test_finding("info", "r", "t", "f"), "f").starts_with("::notice ")
        );
    }

    #[test]
    fn the_job_summary_counts_severities_and_groups_by_file() {
        let findings = vec![
            test_finding("high", "aws-access-key", "AWS key", "src/app.rb"),
            test_finding("medium", "weak-random", "Weak RNG", "src/lib.rs"),
        ];
        let summary = crate::models::ScanSummary {
            coverage_warnings: Vec::new(),
            git_context: None,
            path: ".".into(),
            files_scanned: 2,
            files_skipped: 0,
            bytes_scanned: 42,
            duration_ms: 5,
            secrets_found: 1,
            vulnerabilities_found: 1,
            total_findings: 2,
            critical: 0,
            high: 1,
            medium: 1,
            low: 0,
            info: 0,
            rules_fired: std::collections::BTreeMap::new(),
        };
        let markdown = render_summary_markdown(&summary, &findings);
        assert!(markdown.contains("## oxAudit scan summary"));
        assert!(markdown.contains("| High | 1 |"));
        assert!(markdown.contains("| Medium | 1 |"));
        assert!(markdown.contains("| Critical | 0 |"));
        assert!(markdown.contains("`src/app.rb`"));
        assert!(markdown.contains("`src/lib.rs`"));
        assert!(markdown.contains("- 3:7 **HIGH** AWS key (`aws-access-key`)"));
    }

    #[test]
    fn the_job_summary_says_so_when_there_is_nothing_to_say() {
        let summary = crate::models::ScanSummary {
            coverage_warnings: Vec::new(),
            git_context: None,
            path: ".".into(),
            files_scanned: 3,
            files_skipped: 1,
            bytes_scanned: 10,
            duration_ms: 1,
            secrets_found: 0,
            vulnerabilities_found: 0,
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            rules_fired: std::collections::BTreeMap::new(),
        };
        let markdown = render_summary_markdown(&summary, &[]);
        assert!(markdown.contains("No findings."));
        assert!(!markdown.contains("### Findings"));
    }

    /// A Slack-style webhook URL is a bearer credential in the path. These
    /// tests pin that no delivery failure message ever repeats it, because
    /// those messages go to stderr and CI logs.
    const WEBHOOK_SENTINEL: &str = "SENTINEL_WEBHOOK_BEARER_TOKEN";

    fn assert_no_sentinel(message: &str) {
        assert!(
            !message.contains(WEBHOOK_SENTINEL),
            "webhook failure message leaks the URL credential: {message}"
        );
        assert!(
            message.starts_with("webhook delivery failed"),
            "a delivery failure must still say what failed: {message}"
        );
    }

    #[test]
    fn a_refused_webhook_never_leaks_its_url() {
        // Bind, note the port, then drop the listener so the port refuses.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/hook?token={WEBHOOK_SENTINEL}");
        let error = deliver_webhook(&url, "digest").unwrap_err();
        assert_no_sentinel(&error);
    }

    #[test]
    fn a_rejected_webhook_reports_only_the_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 8192];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        let url = format!("http://127.0.0.1:{port}/hook?token={WEBHOOK_SENTINEL}");
        let error = deliver_webhook(&url, "digest").unwrap_err();
        assert_no_sentinel(&error);
        assert!(
            error.contains("403"),
            "the status is the actionable fact and must stay: {error}"
        );
    }
}

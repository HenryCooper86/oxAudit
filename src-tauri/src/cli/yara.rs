//! `oxaudit-cli yara` and `oxaudit-cli signature-pack`.
//!
//! `yara` runs the same engine as the desktop and the headless server
//! (`scan_yara_engine`), so a match in CI is the match on a workstation.
//!
//! Exit codes follow the CLI contract: 0 when nothing at or above
//! `--fail-on` matched, 1 when something did, 2 for a usage error (no rules
//! to scan with, a bad flag), 3 when the scan failed. A scan that ends
//! `Incomplete` (a file timed out, a pack failed its integrity check, a
//! match or file cap was hit) prints its report and then exits 3, the same
//! choice `deps` and `monitor` make for incomplete coverage: a pipeline must
//! not read partial coverage as a pass. Zero matches exits 0 and says "no
//! rule matched", which is not a statement about the content.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand, ValueEnum};

use super::{
    block_on, failure, gate, open_repository, render_stored_run, severity_rank, usage,
    write_output, CliResult, FailOn, OutputFormat, StderrEvents, EXIT_FAILURE, EXIT_OK,
};
use crate::findings::repository::FindingsRepository;
use crate::findings::service::{FindingsService, FindingsState};
use crate::sigpacks::{PackKind, PackMetadata, SigPackStore, SigPacksState};
use crate::yara::{YaraScanRequest, YaraScanResult};

#[derive(Args, Debug)]
pub(super) struct YaraArgs {
    /// File or folder to scan. Every file is read, ignore files are not
    /// applied, and symbolic links are not followed.
    pub path: PathBuf,

    /// A YARA rule file or folder of rule files (.yar/.yara) for this scan
    /// only. Repeatable.
    #[arg(long = "rules", value_name = "FILE|DIR")]
    pub rules: Vec<PathBuf>,

    /// Apply this installed pack (from --pack-db). Repeatable. Without it
    /// every enabled YARA pack in --pack-db is applied.
    #[arg(long = "pack", value_name = "ID")]
    pub packs: Vec<String>,

    /// The signature-pack store database (the rule-pack database).
    #[arg(long, value_name = "FILE")]
    pub pack_db: Option<PathBuf>,

    /// Save the run to this database for later reload and export.
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Files larger than this are listed as skipped (default 64).
    #[arg(long, value_name = "MB")]
    pub max_file_size_mb: Option<u32>,

    /// Output format: text, json, sarif, or oxaudit-json.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Exit 1 when a match at this severity or higher is reported. A rule's
    /// severity comes from its `severity` or `score` metadata, else medium.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub fail_on: FailOn,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(super) enum PackKindArg {
    Yara,
    Nuclei,
}

impl From<PackKindArg> for PackKind {
    fn from(value: PackKindArg) -> Self {
        match value {
            PackKindArg::Yara => PackKind::Yara,
            PackKindArg::Nuclei => PackKind::Nuclei,
        }
    }
}

#[derive(Subcommand, Debug)]
pub(super) enum SignaturePackCommand {
    /// Import YARA rules or Nuclei templates from a file, folder or .zip.
    /// oxAudit ships no third-party content: you supply it, and the licence
    /// you record is stored with the pack and every run that used it.
    Install {
        /// The signature-pack store database (the rule-pack database).
        #[arg(long, value_name = "FILE")]
        db: PathBuf,

        /// Kind of pack.
        #[arg(long, value_enum)]
        kind: PackKindArg,

        /// A name for the pack.
        #[arg(long)]
        name: String,

        /// The licence the content is published under (free text, required).
        #[arg(long)]
        license: String,

        #[arg(long)]
        version: Option<String>,

        /// Where the pack came from (URL or description).
        #[arg(long)]
        source: Option<String>,

        #[arg(long)]
        authors: Option<String>,

        /// Rule file, folder, or .zip to import.
        path: PathBuf,
    },
    /// List installed signature packs.
    List {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Enable a pack for default application.
    Enable {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        id: String,
    },
    /// Disable a pack for default application; `--pack` still selects it.
    Disable {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        id: String,
    },
    /// Remove a pack and its files. Past runs keep what they recorded.
    Remove {
        #[arg(long, value_name = "FILE")]
        db: PathBuf,
        id: String,
    },
}

pub(super) fn run_yara(args: &YaraArgs, quiet: bool) -> CliResult {
    args.format.refuse_ci_report("yara")?;
    if !matches!(
        args.format,
        OutputFormat::Text | OutputFormat::Json | OutputFormat::Sarif | OutputFormat::OxauditJson
    ) {
        return Err(usage(
            "yara supports --format text, json, sarif or oxaudit-json",
        ));
    }
    if args.rules.is_empty() && args.pack_db.is_none() {
        return Err(usage(
            "no YARA rules to scan with: pass --rules FILE|DIR, or --pack-db FILE with installed packs",
        ));
    }
    if !args.packs.is_empty() && args.pack_db.is_none() {
        return Err(usage("--pack selects installed packs and needs --pack-db"));
    }
    let (sig_packs, pack_ids) = match &args.pack_db {
        Some(db) => {
            let store = SigPackStore::open(db).map_err(failure)?;
            if args.rules.is_empty() && args.packs.is_empty() {
                let enabled = store.resolve(PackKind::Yara, None).map_err(failure)?;
                if enabled.packs.is_empty() && enabled.skipped.is_empty() {
                    return Err(usage(format!(
                        "no enabled YARA pack in {}; install one with `signature-pack install`, or pass --rules",
                        db.display()
                    )));
                }
            }
            (
                SigPacksState::available(store),
                (!args.packs.is_empty()).then(|| args.packs.clone()),
            )
        }
        // Only one-off rules: installed packs are not consulted.
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
    let result = block_on(crate::commands::yara::scan_yara_engine(
        &scan_work,
        &findings,
        &sig_packs,
        &StderrEvents { quiet },
        progress,
        YaraScanRequest {
            path: args.path.to_string_lossy().into_owned(),
            pack_ids,
            extra_rule_paths: args
                .rules
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            max_file_size_mb: args.max_file_size_mb,
            operation_id: None,
        },
    ))
    .map_err(failure)?;

    let service = findings
        .service()
        .map_err(|error| failure(error.to_string()))?;
    let rendered = match args.format {
        OutputFormat::Json => {
            let mut value =
                serde_json::to_value(&result).map_err(|error| failure(error.to_string()))?;
            value["kind"] = serde_json::json!("yara");
            serde_json::to_vec_pretty(&value).map_err(|error| failure(error.to_string()))?
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
        eprintln!(
            "oxaudit: the YARA scan is incomplete; matches below are real, but coverage is not total:"
        );
        for note in &result.notes {
            eprintln!("  - {note}");
        }
        return Ok(EXIT_FAILURE);
    }
    Ok(if gated == EXIT_OK { EXIT_OK } else { gated })
}

fn render_text(result: &YaraScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "YARA scan of {}: {} file(s) scanned ({} bytes) with {} rule(s) from {} pack(s).",
        result.target,
        result.files_scanned,
        result.bytes_scanned,
        result.rules_compiled,
        result.packs.len()
    );
    if result.matches.is_empty() {
        let _ = writeln!(
            out,
            "No rule matched. That is not a statement about content the rules do not describe or about the files listed as skipped."
        );
    } else {
        let files = result
            .matches
            .iter()
            .map(|row| row.path.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let _ = writeln!(
            out,
            "{} rule match(es) in {files} file(s).",
            result.matches.len() as u64 + result.matches_dropped
        );
    }
    let mut last_path = "";
    for row in &result.matches {
        if row.path != last_path {
            let _ = writeln!(out, "\n{}  (sha256 {})", row.path, row.sha256);
            last_path = &row.path;
        }
        let _ = write!(
            out,
            "  [{}] {}  ({}:{})",
            row.severity, row.rule, row.pack, row.namespace
        );
        if !row.tags.is_empty() {
            let _ = write!(out, "  tags: {}", row.tags.join(", "));
        }
        let _ = writeln!(out);
        for string in &row.strings {
            let _ = writeln!(
                out,
                "    {} at offset {} ({} byte(s)): {}",
                string.identifier, string.offset, string.length, string.excerpt_hex
            );
        }
        if row.strings_truncated > 0 {
            let _ = writeln!(
                out,
                "    ... {} more string match(es)",
                row.strings_truncated
            );
        }
    }
    if !result.skipped.is_empty() {
        let _ = writeln!(
            out,
            "\n{} file(s) were not scanned:",
            result.skipped.len() as u64 + result.skipped_dropped
        );
        for skipped in result.skipped.iter().take(20) {
            let _ = writeln!(out, "  {}: {}", skipped.path, skipped.reason);
        }
        if result.skipped.len() > 20 {
            let _ = writeln!(out, "  ... and {} more", result.skipped.len() - 20);
        }
    }
    if result.rules_skipped_total > 0 {
        let _ = writeln!(
            out,
            "\n{} rule file(s) did not compile and were not applied:",
            result.rules_skipped_total
        );
        for skip in result.rules_skipped.iter().take(10) {
            let line = skip.line.map(|l| format!(":{l}")).unwrap_or_default();
            let _ = writeln!(out, "  {}/{}{line}: {}", skip.pack, skip.file, skip.message);
        }
    }
    for note in &result.notes {
        let _ = writeln!(out, "note: {note}");
    }
    out
}

pub(super) fn run_signature_pack(command: &SignaturePackCommand, quiet: bool) -> CliResult {
    match command {
        SignaturePackCommand::Install {
            db,
            kind,
            name,
            license,
            version,
            source,
            authors,
            path,
        } => {
            let kind = PackKind::from(*kind);
            let store = SigPackStore::open(db).map_err(failure)?;
            let preview = crate::sigpacks::validate_pack(kind, path).map_err(usage)?;
            if let Some(detected) = &preview.detected_license {
                if !detected.eq_ignore_ascii_case(license.trim()) && !quiet {
                    eprintln!(
                        "note: the pack's licence file looks like {detected}; you recorded {license}"
                    );
                }
            }
            let installed = store
                .install(
                    kind,
                    path,
                    &PackMetadata {
                        name: name.clone(),
                        license: license.clone(),
                        version: version.clone(),
                        source: source.clone(),
                        authors: authors.clone(),
                    },
                    &chrono::Utc::now().to_rfc3339(),
                )
                .map_err(failure)?;
            println!(
                "installed {} ({}) — {} file(s), {} rule(s), licence {}",
                installed.id,
                installed.name,
                installed.file_count,
                installed.rule_count,
                installed.license
            );
            if !installed.skipped.is_empty() {
                println!(
                    "{} file(s) or rule(s) not applied:",
                    installed.skipped.len()
                );
                for skip in installed.skipped.iter().take(20) {
                    let line = skip.line.map(|l| format!(":{l}")).unwrap_or_default();
                    println!("  {}{line}: {}", skip.file, skip.message);
                }
            }
            Ok(EXIT_OK)
        }
        SignaturePackCommand::List { db, json } => {
            let packs = SigPackStore::open(db)
                .map_err(failure)?
                .list()
                .map_err(failure)?;
            if *json {
                let rendered = serde_json::to_vec_pretty(&packs)
                    .map_err(|error| failure(error.to_string()))?;
                write_output(None, &rendered)?;
                return Ok(EXIT_OK);
            }
            if packs.is_empty() {
                println!("no signature packs installed in this store");
                return Ok(EXIT_OK);
            }
            for pack in packs {
                println!(
                    "{:<56} {:<7} {:>5} rule(s)  {:<8} {}",
                    pack.id,
                    pack.kind.as_str(),
                    pack.rule_count,
                    if pack.enabled { "enabled" } else { "disabled" },
                    pack.license
                );
            }
            Ok(EXIT_OK)
        }
        SignaturePackCommand::Enable { db, id } => {
            SigPackStore::open(db)
                .map_err(failure)?
                .set_enabled(id, true)
                .map_err(failure)?;
            println!("{id} enabled");
            Ok(EXIT_OK)
        }
        SignaturePackCommand::Disable { db, id } => {
            SigPackStore::open(db)
                .map_err(failure)?
                .set_enabled(id, false)
                .map_err(failure)?;
            println!("{id} disabled for default application; --pack still selects it");
            Ok(EXIT_OK)
        }
        SignaturePackCommand::Remove { db, id } => {
            SigPackStore::open(db)
                .map_err(failure)?
                .remove(id)
                .map_err(failure)?;
            println!("{id} removed; stored runs keep what they recorded");
            Ok(EXIT_OK)
        }
    }
}

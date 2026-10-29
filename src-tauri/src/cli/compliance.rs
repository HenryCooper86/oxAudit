//! `oxaudit-cli compliance`: the Compliance Center and Report Studio for a
//! terminal, CI job or cron line.
//!
//! Every subcommand calls the same `crate::compliance` functions the desktop
//! commands and the headless server dispatch to: bounded evidence
//! collection, assessment, the append-only review log, report generation
//! (the one PDF/HTML/Markdown/CSV/JSON generator), the atomic report write
//! and its receipt. This module only parses flags, decides which mistakes are
//! the caller's (exit 2 rather than 3), and renders text.
//!
//! The claim boundary travels with every result. Generated reports carry it
//! themselves; every text result printed here ends with it, and JSON results
//! carry each profile's own disclaimer, so a log excerpt cannot be read as a
//! certification.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use oxaudit_compliance::{ComplianceAssessment, ReadinessStatus};
use serde::Serialize;

use super::{failure, open_repository, rfc3339, usage, write_output, CliError, CliResult, EXIT_OK};
use crate::adapters::reporting::compliance::CLAIM_BOUNDARY;
use crate::compliance::{
    ComplianceAssessmentView, ComplianceReportFormat, ComplianceReportMetadata,
    RunComplianceRequest, SaveComplianceReviewRequest, WriteComplianceReportRequest,
};
use crate::findings::error::ErrorCode;
use crate::findings::repository::FindingsRepository;
use crate::findings::service::{FindingsService, FindingsState};

/// The Compliance Center's standing banner (`src/pages/ComplianceCenter.tsx`).
const PROFILE_BOUNDARY: &str = "Evidence readiness, not certification. Built-in profiles are \
original high-level mappings to official sources. oxAudit never bundles copyrighted ISO \
requirements or substitutes for legal, safety, privacy, audit, or type-approval judgment.";

// The Compliance Center's and Report Studio's form defaults
// (`src/pages/ComplianceCenter.tsx`, `defaultMetadata` in
// `src/pages/ReportStudio.tsx`), so an assessment or report made here reads
// the same as one made in the window.
const DEFAULT_ASSESSMENT_TITLE: &str = "Compliance evidence readiness assessment";
const DEFAULT_SCOPE: &str =
    "Product software, supporting development lifecycle, and available project evidence.";
const DEFAULT_CLASSIFICATION: &str = "Confidential";
const DEFAULT_EXECUTIVE_SUMMARY: &str = "This report summarizes collected evidence, automated \
readiness signals, open gaps, and qualified reviewer decisions. It does not assert \
certification or legal conformity.";

// ---------------------------------------------------------------- arguments

#[derive(Subcommand, Debug)]
pub(super) enum ComplianceCommand {
    /// List the built-in readiness profiles (frameworks) and their controls.
    Profiles {
        /// Emit the full profiles, controls and disclaimers included, as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Collect bounded evidence from a project directory and assess it
    /// against one or more profiles. Each profile becomes a separate,
    /// immutable assessment saved in --db.
    Assess(AssessArgs),
    /// List stored assessments, newest first.
    List(ListArgs),
    /// Show one assessment: coverage summary, control matrix, matched
    /// evidence and recorded reviewer decisions.
    Show(ShowArgs),
    /// Record a reviewer decision on one control. Reviews are append-only
    /// and never change the automated status.
    Review(ReviewArgs),
    /// Compile one assessment into a PDF, HTML, Markdown, CSV or JSON
    /// report, written atomically, with a receipt recorded in --db.
    Report(ReportArgs),
}

#[derive(Args, Debug)]
pub(super) struct AssessArgs {
    /// Project directory to collect evidence from.
    path: PathBuf,

    /// Findings database. Completed runs of this project stored in it count
    /// as evidence, and the assessments are saved to it.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    /// Profile to assess against, as listed by `compliance profiles`.
    /// Repeatable; each profile at most once.
    #[arg(long = "profile", value_name = "ID", required = true)]
    profiles: Vec<String>,

    /// Organization or program the assessment is for.
    #[arg(long, value_name = "TEXT")]
    organization: String,

    /// Responsible reviewer.
    #[arg(long, value_name = "NAME")]
    assessor: String,

    /// Assessment title.
    #[arg(long, value_name = "TEXT", default_value = DEFAULT_ASSESSMENT_TITLE)]
    title: String,

    /// Scope and boundaries of the assessment.
    #[arg(long, value_name = "TEXT", default_value = DEFAULT_SCOPE)]
    scope: String,

    /// Emit the new assessments as JSON instead of a summary.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub(super) struct ListArgs {
    /// Findings database holding the assessments.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    /// Most assessments to list, 1 to 100.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=100))]
    limit: u16,

    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,
}

/// Which stored assessment a command acts on.
#[derive(Args, Debug)]
struct AssessmentSelector {
    /// Assessment id, as listed by `compliance list`.
    #[arg(
        long,
        value_name = "ID",
        required_unless_present = "latest",
        conflicts_with = "latest"
    )]
    assessment: Option<String>,

    /// Use the newest stored assessment instead of naming one.
    #[arg(long)]
    latest: bool,

    /// With --latest: the newest assessment of this profile.
    // `requires = "latest"` would be satisfied by the flag's own default, so
    // the rule is stated as a conflict: --profile only narrows --latest.
    #[arg(long, value_name = "ID", conflicts_with = "assessment")]
    profile: Option<String>,
}

#[derive(Args, Debug)]
pub(super) struct ShowArgs {
    /// Findings database holding the assessment.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    #[command(flatten)]
    selector: AssessmentSelector,

    /// Emit the assessment and its reviews as JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ReviewDecision {
    /// Supported by review.
    Supported,
    /// Partially supported.
    Partial,
    /// Gap confirmed.
    Gap,
    /// Manual review needed.
    ManualReview,
    /// Not applicable.
    NotApplicable,
}

impl From<ReviewDecision> for ReadinessStatus {
    fn from(value: ReviewDecision) -> Self {
        match value {
            ReviewDecision::Supported => Self::Supported,
            ReviewDecision::Partial => Self::Partial,
            ReviewDecision::Gap => Self::Gap,
            ReviewDecision::ManualReview => Self::ManualReview,
            ReviewDecision::NotApplicable => Self::NotApplicable,
        }
    }
}

#[derive(Args, Debug)]
pub(super) struct ReviewArgs {
    /// Findings database holding the assessment.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    /// Assessment holding the control.
    #[arg(long, value_name = "ID")]
    assessment: String,

    /// Control id, as shown by `compliance show`.
    #[arg(long, value_name = "ID")]
    control: String,

    /// The reviewer's decision.
    #[arg(long, value_enum)]
    status: ReviewDecision,

    /// Why: explain the decision and point to authoritative evidence
    /// (4 characters or more).
    #[arg(long, value_name = "TEXT")]
    note: String,

    /// Who decided, recorded for audit (2 characters or more).
    #[arg(long, value_name = "NAME")]
    by: String,

    /// Emit the recorded review as JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ReportFormatArg {
    /// Paginated executive report with headers, footers and page numbers.
    Pdf,
    /// Self-contained, print-ready HTML with no external assets or scripts.
    Html,
    /// Portable Markdown narrative.
    #[value(alias = "md")]
    Markdown,
    /// Spreadsheet-ready control, status, evidence and review matrix.
    Csv,
    /// Canonical machine-readable report.
    Json,
}

impl From<ReportFormatArg> for ComplianceReportFormat {
    fn from(value: ReportFormatArg) -> Self {
        match value {
            ReportFormatArg::Pdf => Self::Pdf,
            ReportFormatArg::Html => Self::Html,
            ReportFormatArg::Markdown => Self::Markdown,
            ReportFormatArg::Csv => Self::Csv,
            ReportFormatArg::Json => Self::Json,
        }
    }
}

#[derive(Args, Debug)]
pub(super) struct ReportArgs {
    /// Findings database holding the assessment. The report receipt is
    /// recorded here.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,

    #[command(flatten)]
    selector: AssessmentSelector,

    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormatArg::Pdf)]
    format: ReportFormatArg,

    /// File to write. Its directory must exist; the file is written to a
    /// temporary file beside it, synced, then renamed into place, replacing
    /// any file already there.
    #[arg(long, short, value_name = "FILE")]
    output: PathBuf,

    /// Report title. Defaults to "<profile name> readiness report".
    #[arg(long, value_name = "TEXT")]
    title: Option<String>,

    /// Organization. Defaults to the assessment's organization.
    #[arg(long, value_name = "TEXT")]
    organization: Option<String>,

    /// Assessor. Defaults to the assessment's assessor.
    #[arg(long, value_name = "NAME")]
    assessor: Option<String>,

    /// Document classification.
    #[arg(long, value_name = "TEXT", default_value = DEFAULT_CLASSIFICATION)]
    classification: String,

    /// Executive summary. Defaults to Report Studio's standard summary,
    /// which states that the report is not a certification.
    #[arg(long, value_name = "TEXT")]
    executive_summary: Option<String>,

    /// Leave evidence references out of the report.
    #[arg(long)]
    no_evidence: bool,

    /// Leave reviewer decisions, names and notes out of the report.
    #[arg(long)]
    no_reviews: bool,

    /// Leave official source references out of the report.
    #[arg(long)]
    no_references: bool,

    /// Emit the report receipt as JSON instead of text.
    #[arg(long)]
    json: bool,
}

// -------------------------------------------------------------------- entry

pub(super) fn run_compliance(command: &ComplianceCommand, quiet: bool) -> CliResult {
    match command {
        ComplianceCommand::Profiles { json } => run_profiles(*json),
        ComplianceCommand::Assess(args) => run_assess(args),
        ComplianceCommand::List(args) => run_list(args),
        ComplianceCommand::Show(args) => run_show(args),
        ComplianceCommand::Review(args) => run_review(args),
        ComplianceCommand::Report(args) => run_report(args, quiet),
    }
}

fn run_profiles(json: bool) -> CliResult {
    let profiles = crate::compliance::list_compliance_profiles().map_err(failure)?;
    if json {
        return print_json(&profiles);
    }
    let mut text = String::new();
    for profile in &profiles {
        text.push_str(&format!(
            "{:<28} {} ({}) — {}, {} control(s)\n",
            profile.id,
            profile.name,
            profile.version,
            profile.domain,
            profile.controls.len()
        ));
    }
    text.push('\n');
    text.push_str(PROFILE_BOUNDARY);
    text.push('\n');
    write_output(None, text.as_bytes())?;
    Ok(EXIT_OK)
}

fn run_assess(args: &AssessArgs) -> CliResult {
    let request = RunComplianceRequest {
        target_path: args.path.to_string_lossy().into_owned(),
        profile_ids: args.profiles.clone(),
        title: args.title.clone(),
        organization: args.organization.clone(),
        assessor: args.assessor.clone(),
        scope: args.scope.clone(),
    };
    // Input checks first, so a bad profile id or path is exit 2 and nothing
    // is saved; the run below repeats them on its own.
    crate::compliance::prepare_run_request(&request).map_err(|error| usage(profile_hint(error)))?;
    let state = open_state(&args.db)?;
    let assessments =
        crate::compliance::run_compliance_assessment_inner(&state, request).map_err(failure)?;
    if args.json {
        return print_json(&assessments);
    }
    let mut text = String::new();
    for assessment in &assessments {
        text.push_str(&format!(
            "{}  {}: {}\n  {}\n",
            assessment.id,
            assessment.profile_name,
            summary_line(assessment),
            assessment.disclaimer
        ));
    }
    text.push_str(&format!(
        "saved {} assessment(s) to {}\n{CLAIM_BOUNDARY}\n",
        assessments.len(),
        args.db.display()
    ));
    write_output(None, text.as_bytes())?;
    Ok(EXIT_OK)
}

fn run_list(args: &ListArgs) -> CliResult {
    let state = open_state(&args.db)?;
    let assessments =
        crate::compliance::list_compliance_assessments_inner(&state, Some(args.limit.into()))
            .map_err(failure)?;
    if args.json {
        return print_json(&assessments);
    }
    if assessments.is_empty() {
        println!(
            "no compliance assessments in {}; create one with `oxaudit-cli compliance assess`",
            args.db.display()
        );
        return Ok(EXIT_OK);
    }
    let mut text = String::new();
    for assessment in &assessments {
        text.push_str(&format!(
            "{}  {}  {:>3}%  {}  {}\n",
            assessment.id,
            rfc3339(assessment.created_at_ms).unwrap_or_default(),
            assessment.summary.evidence_coverage_percent,
            assessment.profile_name,
            assessment.target_label
        ));
    }
    text.push_str(CLAIM_BOUNDARY);
    text.push('\n');
    write_output(None, text.as_bytes())?;
    Ok(EXIT_OK)
}

fn run_show(args: &ShowArgs) -> CliResult {
    let state = open_state(&args.db)?;
    let assessment = resolve_assessment(repository(&state)?, &args.selector, &args.db)?;
    let view = crate::compliance::load_compliance_assessment_inner(&state, assessment.id)
        .map_err(failure)?;
    if args.json {
        return print_json(&view);
    }
    write_output(None, render_view(&view).as_bytes())?;
    Ok(EXIT_OK)
}

fn run_review(args: &ReviewArgs) -> CliResult {
    let state = open_state(&args.db)?;
    let assessment = load_assessment(repository(&state)?, &args.assessment, &args.db)?;
    if !assessment
        .controls
        .iter()
        .any(|control| control.control_id == args.control)
    {
        let known = assessment
            .controls
            .iter()
            .map(|control| control.control_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(usage(format!(
            "control '{}' is not part of assessment {}; its controls are: {known}",
            args.control, assessment.id
        )));
    }
    crate::compliance::validate_review_text(&args.note, &args.by).map_err(usage)?;
    let review = crate::compliance::save_compliance_review_inner(
        &state,
        SaveComplianceReviewRequest {
            assessment_id: assessment.id,
            control_id: args.control.clone(),
            status: args.status.into(),
            note: args.note.clone(),
            author: args.by.clone(),
        },
    )
    .map_err(failure)?;
    if args.json {
        return print_json(&review);
    }
    println!(
        "recorded {} for {} by {} (review {}, append-only)",
        status_label(review.status),
        review.control_id,
        review.author,
        review.id
    );
    println!("{CLAIM_BOUNDARY}");
    Ok(EXIT_OK)
}

fn run_report(args: &ReportArgs, quiet: bool) -> CliResult {
    let output = absolute(&args.output)?;
    if !output.parent().is_some_and(Path::is_dir) {
        return Err(usage(format!(
            "the directory for {} does not exist",
            args.output.display()
        )));
    }
    let state = open_state(&args.db)?;
    let assessment = resolve_assessment(repository(&state)?, &args.selector, &args.db)?;
    let metadata = ComplianceReportMetadata {
        title: args
            .title
            .clone()
            .unwrap_or_else(|| format!("{} readiness report", assessment.profile_name)),
        organization: args
            .organization
            .clone()
            .unwrap_or_else(|| assessment.metadata.organization.clone()),
        assessor: args
            .assessor
            .clone()
            .unwrap_or_else(|| assessment.metadata.assessor.clone()),
        classification: args.classification.clone(),
        executive_summary: args
            .executive_summary
            .clone()
            .unwrap_or_else(|| DEFAULT_EXECUTIVE_SUMMARY.into()),
        include_evidence: !args.no_evidence,
        include_reviews: !args.no_reviews,
        include_references: !args.no_references,
    };
    crate::compliance::validate_report_metadata(&metadata).map_err(usage)?;
    let format = ComplianceReportFormat::from(args.format);
    let (receipt, warnings) = crate::compliance::write_compliance_report_with_warnings(
        &state,
        WriteComplianceReportRequest {
            assessment_id: assessment.id.clone(),
            format,
            metadata,
            output_path: output.to_string_lossy().into_owned(),
        },
    )
    .map_err(failure)?;
    if !quiet {
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
    }
    if args.json {
        return print_json(&receipt);
    }
    println!(
        "wrote {} {} report for assessment {} to {}",
        assessment.profile_name,
        format.suffix(),
        receipt.assessment_id,
        receipt.output_path
    );
    println!("sha256 {}", receipt.content_sha256);
    println!("receipt {} recorded in {}", receipt.id, args.db.display());
    println!("{CLAIM_BOUNDARY}");
    Ok(EXIT_OK)
}

// ------------------------------------------------------------------- helpers

fn open_state(db: &Path) -> Result<FindingsState, CliError> {
    Ok(FindingsState::available(FindingsService::new(
        open_repository(db)?,
    )))
}

fn repository(state: &FindingsState) -> Result<&FindingsRepository, CliError> {
    state
        .service()
        .map(FindingsService::repository)
        .map_err(|error| failure(error.to_string()))
}

/// Load one assessment by id; a missing id is the caller's mistake.
fn load_assessment(
    repository: &FindingsRepository,
    id: &str,
    db: &Path,
) -> Result<ComplianceAssessment, CliError> {
    repository
        .compliance_load_assessment(id)
        .map_err(|error| match error.code {
            ErrorCode::NotFound => usage(format!(
                "compliance assessment {id} was not found in {}",
                db.display()
            )),
            _ => failure(error.to_string()),
        })
}

fn resolve_assessment(
    repository: &FindingsRepository,
    selector: &AssessmentSelector,
    db: &Path,
) -> Result<ComplianceAssessment, CliError> {
    if let Some(id) = &selector.assessment {
        return load_assessment(repository, id, db);
    }
    if let Some(profile) = &selector.profile {
        oxaudit_compliance::builtin_profile(profile)
            .map_err(|error| usage(profile_hint(error.to_string())))?;
    }
    repository
        .compliance_latest_assessment(selector.profile.as_deref())
        .map_err(|error| failure(error.to_string()))?
        .ok_or_else(|| {
            let which = selector
                .profile
                .as_deref()
                .map(|profile| format!("{profile} "))
                .unwrap_or_default();
            usage(format!(
                "no {which}compliance assessment in {}; create one with `oxaudit-cli compliance assess`",
                db.display()
            ))
        })
}

/// Point an unknown profile id at the command that lists the valid ones.
fn profile_hint(message: String) -> String {
    if message.starts_with("unknown compliance profile") {
        format!("{message}; `oxaudit-cli compliance profiles` lists the available ids")
    } else {
        message
    }
}

/// The receipt records where the report went, so a relative `--output` is
/// resolved against the working directory first.
fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|error| failure(format!("cannot resolve {}: {error}", path.display())))
}

fn print_json(value: &impl Serialize) -> CliResult {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| failure(error.to_string()))?;
    bytes.push(b'\n');
    write_output(None, &bytes)?;
    Ok(EXIT_OK)
}

/// The status names the CSV and JSON reports use (`manualReview`, …).
fn status_label(status: ReadinessStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{status:?}"))
}

fn summary_line(assessment: &ComplianceAssessment) -> String {
    let summary = &assessment.summary;
    format!(
        "{}% evidence coverage — {} supported, {} partial, {} gap, {} manual review, {} not applicable",
        summary.evidence_coverage_percent,
        summary.supported,
        summary.partial,
        summary.gap,
        summary.manual_review,
        summary.not_applicable
    )
}

fn render_view(view: &ComplianceAssessmentView) -> String {
    let assessment = &view.assessment;
    let mut text = format!(
        "{} {} — {}\n\
         assessment  {}\n\
         created     {}\n\
         target      {}\n\
         title       {} ({}, assessor {})\n\
         source      {}\n\
         coverage    {}\n\
         {}\n\n",
        assessment.profile_name,
        assessment.profile_version,
        assessment.domain,
        assessment.id,
        rfc3339(assessment.created_at_ms).unwrap_or_default(),
        assessment.target_label,
        assessment.metadata.title,
        assessment.metadata.organization,
        assessment.metadata.assessor,
        assessment.source_url,
        summary_line(assessment),
        assessment.disclaimer
    );
    for control in &assessment.controls {
        text.push_str(&format!(
            "{:<14} {} · {}  [{}]\n    {}\n",
            status_label(control.automated_status),
            control.reference,
            control.title,
            control.control_id,
            control.rationale
        ));
        for evidence in &control.evidence {
            text.push_str(&format!(
                "    evidence {} {}",
                evidence.kind, evidence.locator
            ));
            if let Some(sha) = &evidence.content_sha256 {
                text.push_str(&format!(" (sha256 {sha})"));
            }
            text.push('\n');
        }
        // Reviews arrive newest first; the first one per control is current.
        if let Some(review) = view
            .reviews
            .iter()
            .find(|review| review.control_id == control.control_id)
        {
            text.push_str(&format!(
                "    review   {} by {} at {}: {}\n",
                status_label(review.status),
                review.author,
                rfc3339(review.reviewed_at_ms).unwrap_or_default(),
                review.note
            ));
        }
    }
    text.push('\n');
    for limit in &assessment.collection_limits {
        text.push_str(&format!("note: {limit}\n"));
    }
    text.push_str(CLAIM_BOUNDARY);
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn parse(arguments: &[&str]) -> Result<ComplianceCommand, clap::Error> {
        let mut full = vec!["oxaudit", "compliance"];
        full.extend_from_slice(arguments);
        Cli::try_parse_from(full).map(|cli| match cli.command {
            Command::Compliance { command } => command,
            other => panic!("compliance command expected, got {other:?}"),
        })
    }

    #[test]
    fn report_needs_exactly_one_way_to_pick_an_assessment() {
        let base = ["report", "--db", "x.sqlite", "--output", "r.pdf"];
        let neither = parse(&base).unwrap_err();
        assert_eq!(
            neither.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let mut both = base.to_vec();
        both.extend(["--assessment", "a", "--latest"]);
        assert_eq!(
            parse(&both).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        let mut profile_with_id = base.to_vec();
        profile_with_id.extend(["--assessment", "a", "--profile", "gdpr"]);
        assert_eq!(
            parse(&profile_with_id).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        let mut profile_alone = base.to_vec();
        profile_alone.extend(["--profile", "gdpr"]);
        assert!(parse(&profile_alone).is_err(), "--profile needs --latest");
        let mut latest = base.to_vec();
        latest.extend(["--latest", "--profile", "gdpr", "--format", "md"]);
        let ComplianceCommand::Report(args) = parse(&latest).unwrap() else {
            panic!("report expected");
        };
        assert!(args.selector.latest);
        assert_eq!(args.selector.profile.as_deref(), Some("gdpr"));
        assert_eq!(args.format, ReportFormatArg::Markdown);
        assert_eq!(args.classification, DEFAULT_CLASSIFICATION);
    }

    #[test]
    fn report_requires_an_output_file_and_defaults_to_pdf() {
        assert!(parse(&["report", "--db", "x.sqlite", "--latest"]).is_err());
        let ComplianceCommand::Report(args) =
            parse(&["report", "--db", "x.sqlite", "--latest", "-o", "r.pdf"]).unwrap()
        else {
            panic!("report expected");
        };
        assert_eq!(
            ComplianceReportFormat::from(args.format),
            ComplianceReportFormat::Pdf
        );
    }

    #[test]
    fn assess_requires_a_profile_and_uses_the_compliance_center_defaults() {
        let base = [
            "assess",
            ".",
            "--db",
            "x.sqlite",
            "--organization",
            "Example",
            "--assessor",
            "Reviewer",
        ];
        assert!(parse(&base).is_err(), "a profile must be chosen explicitly");
        let mut chosen = base.to_vec();
        chosen.extend(["--profile", "gdpr", "--profile", "soc-2-tsc"]);
        let ComplianceCommand::Assess(args) = parse(&chosen).unwrap() else {
            panic!("assess expected");
        };
        assert_eq!(args.profiles, ["gdpr", "soc-2-tsc"]);
        assert_eq!(args.title, DEFAULT_ASSESSMENT_TITLE);
        assert_eq!(args.scope, DEFAULT_SCOPE);
    }

    #[test]
    fn review_statuses_map_onto_the_engine_statuses() {
        for (flag, status) in [
            ("supported", ReadinessStatus::Supported),
            ("partial", ReadinessStatus::Partial),
            ("gap", ReadinessStatus::Gap),
            ("manual-review", ReadinessStatus::ManualReview),
            ("not-applicable", ReadinessStatus::NotApplicable),
        ] {
            let ComplianceCommand::Review(args) = parse(&[
                "review",
                "--db",
                "x.sqlite",
                "--assessment",
                "a",
                "--control",
                "c",
                "--status",
                flag,
                "--note",
                "note",
                "--by",
                "me",
            ])
            .unwrap() else {
                panic!("review expected");
            };
            assert_eq!(ReadinessStatus::from(args.status), status);
        }
    }

    #[test]
    fn list_limit_matches_the_storage_bound() {
        assert!(parse(&["list", "--db", "x.sqlite", "--limit", "0"]).is_err());
        assert!(parse(&["list", "--db", "x.sqlite", "--limit", "101"]).is_err());
        assert!(parse(&["list", "--db", "x.sqlite", "--limit", "100"]).is_ok());
    }

    #[test]
    fn status_labels_are_the_report_vocabulary() {
        assert_eq!(status_label(ReadinessStatus::ManualReview), "manualReview");
        assert_eq!(
            status_label(ReadinessStatus::NotApplicable),
            "notApplicable"
        );
    }

    #[test]
    fn unknown_profiles_point_at_the_listing() {
        assert!(
            profile_hint("unknown compliance profile: nope".into()).contains("compliance profiles")
        );
        assert_eq!(profile_hint("other".into()), "other");
    }

    #[test]
    fn relative_output_is_resolved_against_the_working_directory() {
        let resolved = absolute(Path::new("report.pdf")).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("report.pdf"));
        let already = std::env::temp_dir().join("report.pdf");
        assert_eq!(absolute(&already).unwrap(), already);
    }

    #[test]
    fn a_rendered_assessment_carries_its_disclaimer_and_the_claim_boundary() {
        let profile = oxaudit_compliance::builtin_profile("gdpr").unwrap();
        let assessment = oxaudit_compliance::assess(
            &profile,
            &oxaudit_compliance::EvidenceSnapshot {
                root_label: "/project".into(),
                files: vec![],
                completed_runs: vec![],
                collection_limits: vec!["bounded collection".into()],
            },
            oxaudit_compliance::AssessmentMetadata {
                title: "Readiness".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                scope: "Product".into(),
            },
            "assessment-render".into(),
            1,
        )
        .unwrap();
        let control_id = assessment.controls[0].control_id.clone();
        let text = render_view(&ComplianceAssessmentView {
            reviews: vec![crate::compliance::ComplianceReview {
                id: "review-1".into(),
                assessment_id: assessment.id.clone(),
                control_id: control_id.clone(),
                status: ReadinessStatus::NotApplicable,
                note: "Out of scope for this product.".into(),
                author: "Privacy lead".into(),
                reviewed_at_ms: 2,
            }],
            assessment: assessment.clone(),
        });
        assert!(text.contains(&assessment.disclaimer));
        assert!(text.ends_with(&format!("{CLAIM_BOUNDARY}\n")));
        assert!(text.contains(&format!("[{control_id}]")));
        assert!(text.contains("review   notApplicable by Privacy lead"));
        assert!(text.contains("note: bounded collection"));
    }
}

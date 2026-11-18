//! `sca` and `portfolio`: the composition-analysis commands.
//!
//! `sca` runs the same dependency scan as `deps` and then judges the
//! inventory against the project's component policy. `portfolio` rebuilds
//! that judgement for every stored dependency run in a database, so several
//! projects can be read side by side. Both call `crate::sca`, the engine a
//! desktop or server command would call too.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use oxaudit_sca::portfolio::{self, ProjectEntry};
use oxaudit_sca::{Action, ScaReport, Violation};
use serde_json::Value;

use super::{
    ci, combined, config_notice, execute_deps_scan, failure, gate, gating_ranks, load_config,
    open_repository, pick, usage, write_output, write_step_summary, CliResult, DepsScan,
    DepsScanRequest, FailOn, GateSource, EXIT_FINDINGS, EXIT_OK,
};
use crate::sca::{self as engine, PolicySource, PortfolioPolicy, ReleaseMode};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(super) enum ScaFormat {
    /// Human-readable summary and violation list.
    Text,
    /// The composition report: every component with its license, release
    /// facts, open advisories and verdict, plus the violations.
    Json,
    /// JUnit XML: one test case per policy violation and per advisory.
    Junit,
    /// GitLab Code Quality report of violations and open advisories.
    GitlabCodeQuality,
    /// GitLab Dependency Scanning report of open advisories.
    GitlabDependencyScanning,
}

#[derive(Args, Debug)]
pub(super) struct ScaArgs {
    /// Directory to search for lockfiles.
    path: PathBuf,

    /// Persist the dependency run, its advisory receipt and the release
    /// facts in this database. `portfolio` reads it; SBOM and VEX exports
    /// of the run come from `export --run`.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Judge against this component policy instead of the project's
    /// `.oxaudit/component-policy.json`.
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Report violations without failing: exit 0 whatever the policy says.
    /// `--fail-on` still applies.
    #[arg(long)]
    report_only: bool,

    /// Do not ask the package index for release facts. Operational rules
    /// are then not evaluated, and the report says so.
    #[arg(long)]
    no_release_facts: bool,

    /// Package index to ask for release facts (a mirror of api.deps.dev).
    #[arg(long, value_name = "URL", default_value = crate::sca::releases::DEFAULT_BASE)]
    release_index: String,

    /// Write a third-party notices file (Markdown) listing every registry
    /// component by declared license.
    #[arg(long, value_name = "FILE")]
    notices: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = ScaFormat::Text)]
    format: ScaFormat,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit 1 when an open advisory at this severity or higher is reported,
    /// as `deps --fail-on` does. Defaults to `none`, or the project
    /// config's `[deps] fail_on`.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Answer advisories from this local advisory database instead of the
    /// OSV API.
    #[arg(long, value_name = "FILE")]
    advisory_db: Option<PathBuf>,

    /// Never contact providers: advisories come from a receipt in --db (or
    /// --advisory-db) and release facts from the newest stored receipt.
    #[arg(long)]
    offline: bool,

    /// Directory name to ignore. Repeat for more.
    #[arg(long = "ignore-dir", value_name = "NAME")]
    ignore_dirs: Vec<String>,

    /// Dismiss advisories by this policy file instead of the project's
    /// `.oxaudit/advisory-policy.json`.
    #[arg(long, value_name = "FILE")]
    advisory_policy: Option<PathBuf>,

    /// Run even when the advisory policy or the component policy is
    /// invalid; an invalid policy is then not applied.
    #[arg(long)]
    ignore_invalid_policy: bool,

    /// Ignore the project's `.oxaudit/config.toml`.
    #[arg(long)]
    no_config: bool,
}

fn verdict_label(violation: &Violation) -> &'static str {
    match (&violation.waiver, violation.action) {
        (Some(_), _) => "WAIVED",
        (None, Action::Deny) => "DENY",
        (None, _) => "WARN",
    }
}

fn kind_label(violation: &Violation) -> &'static str {
    match violation.kind {
        oxaudit_sca::ViolationKind::Component => "component",
        oxaudit_sca::ViolationKind::License => "license",
        oxaudit_sca::ViolationKind::Vulnerability => "vulnerability",
        oxaudit_sca::ViolationKind::Operational => "operational",
    }
}

fn category_line(report: &ScaReport) -> String {
    let mut parts: Vec<String> = oxaudit_sca::LicenseCategory::ALL
        .iter()
        .filter_map(|category| {
            let count = report.summary.license_categories.get(category.slug())?;
            Some(format!("{} {count}", category.slug()))
        })
        .collect();
    if parts.is_empty() {
        parts.push("none".into());
    }
    parts.join(", ")
}

fn policy_line(report: &ScaReport) -> String {
    let counts = &report.summary.violations;
    match &report.summary.policy.source {
        Some(source) => format!(
            "Policy {source}: {} deny, {} warn, {} waived",
            counts.deny, counts.warn, counts.waived
        ),
        None => format!(
            "Policy: none ({} not found). Components are classified; nothing is judged.",
            oxaudit_sca::policy::COMPONENT_POLICY_PATH
        ),
    }
}

fn release_line(report: &ScaReport) -> String {
    let releases = &report.summary.releases;
    match releases.status.as_str() {
        "notCollected" => "Release facts: not collected; operational rules not evaluated".into(),
        status => format!(
            "Release facts ({status}): {} of {} component(s), {} deprecated",
            releases.components_with_facts, report.summary.components, releases.deprecated
        ),
    }
}

fn render_text(report: &ScaReport) -> Vec<u8> {
    use std::fmt::Write as _;
    let summary = &report.summary;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} component(s): {} direct, {} with open advisories{}",
        summary.components,
        summary.direct_components,
        summary.vulnerable_components,
        summary
            .highest_severity
            .as_deref()
            .map(|severity| format!(" (highest {severity})"))
            .unwrap_or_default()
    );
    if summary.unclassified_relationship > 0 {
        let _ = writeln!(
            out,
            "  {} component(s) come from lockfiles that do not say whether they are direct",
            summary.unclassified_relationship
        );
    }
    let _ = writeln!(
        out,
        "Licenses: {} ({} undeclared)",
        category_line(report),
        summary.undeclared_licenses
    );
    let _ = writeln!(out, "{}", release_line(report));
    let _ = writeln!(out, "{}", policy_line(report));
    if !report.violations.is_empty() {
        let _ = writeln!(out);
    }
    for violation in &report.violations {
        let _ = writeln!(
            out,
            "{:<6} {:<13} {} {} {} — {} [{}]",
            verdict_label(violation),
            kind_label(violation),
            violation.ecosystem,
            violation.name,
            violation.version,
            violation.message,
            violation.rule
        );
        if let Some(waiver) = &violation.waiver {
            let _ = writeln!(
                out,
                "       waived: {}{}",
                waiver.reason,
                waiver
                    .expires_at
                    .as_deref()
                    .map(|expires| format!(" (until {expires})"))
                    .unwrap_or_default()
            );
        }
    }
    let _ = writeln!(out);
    for note in &summary.notes {
        let _ = writeln!(out, "note: {note}");
    }
    if let Some(run_id) = &summary.run_id {
        let _ = writeln!(out, "Run {run_id}.");
    }
    let _ = writeln!(out, "{}", report.disclaimer);
    out.into_bytes()
}

fn render_markdown_summary(report: &ScaReport) -> String {
    use std::fmt::Write as _;
    let escape = |text: &str| text.replace('|', "\\|").replace(['\n', '\r'], " ");
    let mut out = String::from("## oxAudit composition analysis\n\n");
    let _ = writeln!(out, "- {} component(s)", report.summary.components);
    let _ = writeln!(out, "- Licenses: {}", category_line(report));
    let _ = writeln!(out, "- {}", release_line(report));
    let _ = writeln!(out, "- {}", escape(&policy_line(report)));
    let shown: Vec<&Violation> = report.violations.iter().take(50).collect();
    if !shown.is_empty() {
        out.push_str("\n| Verdict | Kind | Component | Finding |\n| --- | --- | --- | --- |\n");
        for violation in &shown {
            let _ = writeln!(
                out,
                "| {} | {} | {} {} | {} |",
                verdict_label(violation),
                kind_label(violation),
                escape(&violation.name),
                escape(&violation.version),
                escape(&violation.message)
            );
        }
        if report.violations.len() > shown.len() {
            let _ = writeln!(
                out,
                "\n{} more violation(s) are in the report.",
                report.violations.len() - shown.len()
            );
        }
    }
    let _ = writeln!(out, "\n{}", report.disclaimer);
    out
}

pub(super) fn run_sca(args: &ScaArgs, quiet: bool) -> CliResult {
    if !args.path.is_dir() {
        return Err(usage(format!("{} is not a directory", args.path.display())));
    }
    let config = load_config(&args.path, args.no_config)?
        .map(|config| config.deps)
        .unwrap_or_default();
    let (fail_on, fail_on_source) = pick(args.fail_on, config.fail_on, FailOn::None);
    let ignore_dirs = combined(&config.ignore_dirs, &args.ignore_dirs);
    let mut from_config = Vec::new();
    if fail_on_source == GateSource::Config {
        from_config.push(format!("--fail-on {}", fail_on.label()));
    }
    if !config.ignore_dirs.is_empty() {
        from_config.push(format!("ignore_dirs {}", config.ignore_dirs.join(", ")));
    }
    if let Some(notice) = config_notice(&from_config) {
        eprintln!("{notice}");
    }
    let root = args
        .path
        .canonicalize()
        .map_err(|error| usage(error.to_string()))?;
    // Read the policy before any lookup, so a broken one fails before
    // network work.
    let loaded = engine::load_policy(
        match &args.policy {
            Some(path) => PolicySource::File(path),
            None => PolicySource::Project(&root),
        },
        args.ignore_invalid_policy,
    )
    .map_err(usage)?;

    let DepsScan {
        service,
        result,
        http,
        ..
    } = execute_deps_scan(
        &DepsScanRequest {
            path: &args.path,
            db: args.db.as_deref(),
            advisory_db: args.advisory_db.as_deref(),
            offline: args.offline,
            ignore_dirs: &ignore_dirs,
            advisory_policy: args.advisory_policy.as_deref(),
            ignore_invalid_policy: args.ignore_invalid_policy,
        },
        quiet,
    )?;
    let mode = if args.no_release_facts {
        ReleaseMode::Skip
    } else if args.offline {
        ReleaseMode::Cached
    } else {
        if !quiet {
            eprintln!("  collecting release facts…");
        }
        ReleaseMode::Fetch {
            http: &http,
            base: args.release_index.trim_end_matches('/'),
        }
    };
    let facts = super::block_on(engine::collect_releases(
        service.repository(),
        &result,
        mode,
    ));
    let report = engine::build_report(&result, &facts, &loaded, chrono::Utc::now());

    let prefix = ci::workspace_prefix(&root);
    let threshold = fail_on.threshold();
    let rendered = match args.format {
        ScaFormat::Text => render_text(&report),
        ScaFormat::Json => oxaudit_parsers::stable_json::to_vec_pretty(&report)
            .map_err(|error| failure(error.to_string()))?,
        ScaFormat::Junit => {
            let mut cases = ci::policy_cases(&report);
            cases.extend(ci::advisory_cases(&result, &prefix, |vulnerability| {
                vulnerability.review.is_none()
                    && threshold.is_some_and(|level| {
                        super::severity_rank(vulnerability.severity.as_deref().unwrap_or(""))
                            >= level
                    })
            }));
            ci::junit("oxaudit sca", &cases)
        }
        ScaFormat::GitlabCodeQuality => {
            let mut entries = ci::code_quality_policy(&report, &prefix);
            entries.extend(ci::code_quality_advisories(&result, &prefix));
            oxaudit_parsers::stable_json::to_vec_pretty(&Value::Array(entries))
                .map_err(|error| failure(error.to_string()))?
        }
        ScaFormat::GitlabDependencyScanning => oxaudit_parsers::stable_json::to_vec_pretty(
            &ci::gitlab_dependency_scanning(&result, &prefix, super::epoch_millis()),
        )
        .map_err(|error| failure(error.to_string()))?,
    };
    write_output(args.output.as_deref(), &rendered)?;
    if let Some(path) = &args.notices {
        // The directory's name, not its path on this machine: the file is
        // meant to be committed or shipped.
        let project = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.to_string_lossy().into_owned());
        let notices = oxaudit_sca::notices::render(&report, &project);
        std::fs::write(path, notices)
            .map_err(|error| failure(format!("cannot write {}: {error}", path.display())))?;
        if !quiet {
            eprintln!("Notices written to {}", path.display());
        }
    }
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        write_step_summary(&render_markdown_summary(&report), quiet);
    }
    if let (Some(db), Some(run_id), false) = (&args.db, &report.summary.run_id, quiet) {
        eprintln!("Run {run_id} saved to {}", db.display());
    }

    let advisories = gate(gating_ranks(result.vulnerabilities.iter()), fail_on, quiet);
    let failing = report.violations.iter().filter(|v| v.gates()).count();
    let policy = if failing == 0 {
        EXIT_OK
    } else if args.report_only {
        if !quiet {
            eprintln!("{failing} policy violation(s) would fail the build; --report-only is set");
        }
        EXIT_OK
    } else {
        if !quiet {
            eprintln!("Failing: {failing} policy violation(s) denied by the component policy");
        }
        EXIT_FINDINGS
    };
    Ok(if advisories == EXIT_OK {
        policy
    } else {
        advisories
    })
}

// --------------------------------------------------------------- portfolio

#[derive(Args, Debug)]
pub(super) struct PortfolioSource {
    /// Findings database holding the stored dependency runs.
    #[arg(long)]
    db: PathBuf,

    /// Judge every project against this one component policy. Without it,
    /// each project is judged against its own committed policy, read from
    /// its directory when that exists on this machine.
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(super) enum PortfolioCommand {
    /// One row per project: components, open advisories, license
    /// categories and policy state, failing projects first.
    Summary {
        #[command(flatten)]
        source: PortfolioSource,
        /// Exit 1 when any project has a `deny` violation.
        #[arg(long)]
        fail_on_deny: bool,
    },
    /// Every package across the projects, most widely used first, with the
    /// versions each project pins.
    Components {
        #[command(flatten)]
        source: PortfolioSource,
        /// Most packages to list in the table. JSON is never truncated.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Which projects use a package, and at which version.
    WhereUsed {
        #[command(flatten)]
        source: PortfolioSource,
        /// Package name.
        name: String,
        /// Only this ecosystem (npm, PyPI, Maven, crates.io, Go, NuGet, …).
        #[arg(long)]
        ecosystem: Option<String>,
        /// Only this version.
        #[arg(long)]
        version: Option<String>,
    },
    /// Policy state of one project over its stored runs, newest first.
    History {
        #[command(flatten)]
        source: PortfolioSource,
        /// The project's scanned directory, as `portfolio summary` shows it.
        #[arg(long)]
        target: String,
    },
}

/// Most stored runs `history` reads for one project.
const HISTORY_RUNS: usize = 100;

fn load_entries(
    source: &PortfolioSource,
    runs: &[oxaudit_domain::Run],
) -> Result<Vec<ProjectEntry>, super::CliError> {
    let repository = open_repository(&source.db)?;
    let shared = source
        .policy
        .as_deref()
        .map(|path| engine::load_policy(PolicySource::File(path), false))
        .transpose()
        .map_err(usage)?;
    engine::portfolio_entries(
        &repository,
        runs,
        match &shared {
            Some(loaded) => PortfolioPolicy::Shared(loaded),
            None => PortfolioPolicy::PerProject,
        },
        chrono::Utc::now(),
    )
    .map_err(failure)
}

fn latest_entries(source: &PortfolioSource) -> Result<Vec<ProjectEntry>, super::CliError> {
    let repository = open_repository(&source.db)?;
    let runs = crate::monitor::select_runs(&repository, &[]).map_err(failure)?;
    drop(repository);
    load_entries(source, &runs)
}

fn emit(
    source: &PortfolioSource,
    json: &impl serde::Serialize,
    text: String,
) -> Result<(), super::CliError> {
    let rendered = if source.json {
        oxaudit_parsers::stable_json::to_vec_pretty(json)
            .map_err(|error| failure(error.to_string()))?
    } else {
        text.into_bytes()
    };
    write_output(source.output.as_deref(), &rendered)
}

fn no_runs(source: &PortfolioSource) -> String {
    format!(
        "No completed dependency runs stored in {}. Run `oxaudit-cli sca <PATH> --db {}` for each project first.\n",
        source.db.display(),
        source.db.display()
    )
}

fn scanned(at_ms: Option<u64>) -> String {
    at_ms
        .and_then(|at| {
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(at).ok()?)
        })
        .map(|at| at.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn render_summary(summary: &portfolio::PortfolioSummary, entries: &[ProjectEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let totals = &summary.totals;
    let _ = writeln!(
        out,
        "{} project(s), {} failing policy; {} distinct component(s); {} deny, {} warn, {} waived\n",
        totals.projects,
        totals.failing_projects,
        totals.distinct_components,
        totals.violations.deny,
        totals.violations.warn,
        totals.violations.waived
    );
    let _ = writeln!(
        out,
        "{:<6} {:>6} {:>5} {:>5} {:>6}  {:<10} {:<10} PROJECT",
        "STATE", "COMPS", "DENY", "WARN", "VULN", "HIGHEST", "SCANNED"
    );
    for row in &summary.projects {
        let _ = writeln!(
            out,
            "{:<6} {:>6} {:>5} {:>5} {:>6}  {:<10} {:<10} {}",
            row.status.to_uppercase(),
            row.components,
            row.violations.deny,
            row.violations.warn,
            row.vulnerable_components,
            row.highest_severity.as_deref().unwrap_or("-"),
            scanned(row.scanned_at_ms),
            row.target
        );
    }
    let without_policy = entries
        .iter()
        .filter(|entry| !entry.report.summary.policy.loaded)
        .count();
    if without_policy > 0 {
        let _ = writeln!(
            out,
            "\n{without_policy} project(s) were judged with no component policy; PASS there means \
             nothing was checked. Pass --policy to judge every project against one."
        );
    }
    let without_facts = summary
        .projects
        .iter()
        .filter(|row| !row.release_facts)
        .count();
    if without_facts > 0 {
        let _ = writeln!(
            out,
            "{without_facts} project(s) have no stored release facts; operational rules were not evaluated for them."
        );
    }
    out
}

pub(super) fn run_portfolio(command: &PortfolioCommand) -> CliResult {
    match command {
        PortfolioCommand::Summary {
            source,
            fail_on_deny,
        } => {
            let entries = latest_entries(source)?;
            let summary = portfolio::summarize(&entries);
            let text = if entries.is_empty() {
                no_runs(source)
            } else {
                render_summary(&summary, &entries)
            };
            emit(source, &summary, text)?;
            Ok(if *fail_on_deny && summary.totals.failing_projects > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            })
        }
        PortfolioCommand::Components { source, limit } => {
            use std::fmt::Write as _;
            let entries = latest_entries(source)?;
            let rows = portfolio::components(&entries);
            let mut text = if entries.is_empty() {
                no_runs(source)
            } else {
                format!(
                    "{} package(s) across {} project(s)\n\n{:<8} {:<7} {:<12} {:<28} VERSIONS\n",
                    rows.len(),
                    entries.len(),
                    "PROJECTS",
                    "VERDICT",
                    "ECOSYSTEM",
                    "PACKAGE"
                )
            };
            for row in rows.iter().take(*limit) {
                let _ = writeln!(
                    text,
                    "{:<8} {:<7} {:<12} {:<28} {}",
                    row.project_count,
                    row.verdict.label(),
                    row.ecosystem,
                    row.name,
                    row.versions
                        .iter()
                        .map(|usage| usage.version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if rows.len() > *limit {
                let _ = writeln!(
                    text,
                    "\n{} more; raise --limit or use --json.",
                    rows.len() - limit
                );
            }
            emit(source, &rows, text)?;
            Ok(EXIT_OK)
        }
        PortfolioCommand::WhereUsed {
            source,
            name,
            ecosystem,
            version,
        } => {
            use std::fmt::Write as _;
            let entries = latest_entries(source)?;
            let used =
                portfolio::where_used(&entries, ecosystem.as_deref(), name, version.as_deref());
            let mut text = if entries.is_empty() {
                no_runs(source)
            } else if used.is_empty() {
                format!(
                    "{name} is not in the latest stored inventory of any of {} project(s). \
                     Projects scanned since their last stored run are not covered.\n",
                    entries.len()
                )
            } else {
                format!(
                    "{name} is used by {} project inventory entr(ies):\n\n",
                    used.len()
                )
            };
            for usage in &used {
                let component = &usage.component;
                let _ = writeln!(
                    text,
                    "{} {} {}  {}  {}  verdict {}  scanned {}\n    {}",
                    component.ecosystem,
                    component.name,
                    component.version,
                    match component.direct {
                        Some(true) => "direct",
                        Some(false) => "transitive",
                        None => "relationship unknown",
                    },
                    component
                        .license
                        .expression
                        .as_deref()
                        .unwrap_or("no declared license"),
                    component.verdict.label(),
                    scanned(usage.scanned_at_ms),
                    usage.target
                );
            }
            emit(source, &used, text)?;
            Ok(EXIT_OK)
        }
        PortfolioCommand::History { source, target } => {
            use std::fmt::Write as _;
            let repository = open_repository(&source.db)?;
            let runs: Vec<oxaudit_domain::Run> = repository
                .canonical_list_runs(Some("dependencies"), HISTORY_RUNS)
                .map_err(|error| failure(error.to_string()))?
                .into_iter()
                .filter(|run| {
                    run.state == oxaudit_domain::RunState::Completed && &run.target_label == target
                })
                .collect();
            drop(repository);
            if runs.is_empty() {
                return Err(usage(format!(
                    "no completed dependency run for {target} among the newest {HISTORY_RUNS} \
                     stored runs; `portfolio summary` lists the stored projects"
                )));
            }
            let entries = load_entries(source, &runs)?;
            let rows: Vec<portfolio::ProjectRow> = entries
                .iter()
                .flat_map(|entry| portfolio::summarize(std::slice::from_ref(entry)).projects)
                .collect();
            let mut text = format!(
                "{target}: {} stored run(s), newest first, judged by the policy in force now\n\n\
                 {:<10} {:<6} {:>6} {:>5} {:>5} {:>6}  RUN\n",
                rows.len(),
                "SCANNED",
                "STATE",
                "COMPS",
                "DENY",
                "WARN",
                "VULN"
            );
            for row in &rows {
                let _ = writeln!(
                    text,
                    "{:<10} {:<6} {:>6} {:>5} {:>5} {:>6}  {}",
                    scanned(row.scanned_at_ms),
                    row.status.to_uppercase(),
                    row.components,
                    row.violations.deny,
                    row.violations.warn,
                    row.vulnerable_components,
                    row.run_id
                );
            }
            emit(source, &rows, text)?;
            Ok(EXIT_OK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_sca::policy::ComponentPolicy;
    use oxaudit_sca::report::{assess, ComponentInput};

    fn report() -> ScaReport {
        let policy = ComponentPolicy::from_value(serde_json::json!({
            "version": 1,
            "licenses": {"deny": ["category:strong-copyleft"], "unknown": "warn"},
            "components": [{"ecosystem": "npm", "package": "tool", "decision": "approved",
                "reason": "Build only", "expiresAt": "2027-01-01T00:00:00Z"}]
        }))
        .unwrap();
        let input = |name: &str, license: Option<&str>| ComponentInput {
            ecosystem: "npm".into(),
            name: name.into(),
            version: "1.0.0".into(),
            lockfile: "package-lock.json".into(),
            license: license.map(String::from),
            direct: Some(true),
            registry: true,
            advisories: Vec::new(),
        };
        let mut report = assess(
            vec![
                input("readline", Some("GPL-3.0-only")),
                input("tool", Some("GPL-2.0-only")),
                input("mystery|pkg", None),
                input("fine", Some("MIT")),
            ],
            &[],
            &policy,
            "2026-11-16T00:00:00Z".parse().unwrap(),
        );
        report.summary.policy.loaded = true;
        report.summary.policy.source = Some(".oxaudit/component-policy.json".into());
        report.summary.run_id = Some("run_1".into());
        report
    }

    #[test]
    fn the_text_report_leads_with_counts_and_lists_denies_first() {
        let text = String::from_utf8(render_text(&report())).unwrap();
        assert!(
            text.starts_with("4 component(s): 4 direct, 0 with open advisories\n"),
            "{text}"
        );
        assert!(
            text.contains("Licenses: permissive 1, strong-copyleft 2, unknown 1 (1 undeclared)")
        );
        assert!(text.contains("Release facts: not collected; operational rules not evaluated"));
        assert!(text.contains("Policy .oxaudit/component-policy.json: 1 deny, 1 warn, 1 waived"));
        let deny = text
            .find("DENY   license       npm readline 1.0.0")
            .expect("deny row");
        let warn = text
            .find("WARN   license       npm mystery|pkg 1.0.0")
            .expect("warn row");
        let waived = text
            .find("WAIVED license       npm tool 1.0.0")
            .expect("waived row");
        assert!(deny < warn && warn < waived, "{text}");
        assert!(text.contains("waived: Build only (until 2027-01-01T00:00:00Z)"));
        assert!(text.contains("Run run_1."));
        assert!(text.trim_end().ends_with("not thereby cleared for use."));
    }

    #[test]
    fn without_a_policy_the_text_says_nothing_was_judged() {
        let mut report = report();
        report.summary.policy.loaded = false;
        report.summary.policy.source = None;
        let text = String::from_utf8(render_text(&report)).unwrap();
        assert!(
            text.contains("Policy: none (.oxaudit/component-policy.json not found)"),
            "{text}"
        );
    }

    #[test]
    fn the_step_summary_escapes_table_cells() {
        let markdown = render_markdown_summary(&report());
        assert!(
            markdown.contains("| WARN | license | mystery\\|pkg 1.0.0 |"),
            "{markdown}"
        );
        assert!(markdown.contains("| DENY | license | readline 1.0.0 |"));
    }
}

//! End-to-end tests for the shipped `oxaudit-cli` binary.
//!
//! Everything else in the suite tests functions. This drives the artifact a
//! user actually downloads: it builds a project on disk, runs the real
//! executable against it, and checks what came out of stdout and what the
//! process exited with.
//!
//! That distinction matters for a CI-facing tool. The exit code *is* the
//! product — a pipeline gate that reports the wrong one either fails builds
//! that should pass or, far worse, passes builds that should fail. No unit
//! test covers process exit, argument parsing, or the stdout/stderr split, and
//! all three are load-bearing.
//!
//! GUI end-to-end coverage needs `tauri-driver`, which supports Linux and
//! Windows only. These run everywhere the CLI does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test, as cargo built it for this run.
///
/// `CARGO_BIN_EXE_<name>` is set by cargo for integration tests, so this is the
/// freshly built binary rather than whatever happens to be on PATH.
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oxaudit-cli"))
}

/// A throwaway project with one planted finding of each kind.
fn project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("src");

    std::fs::write(
        root.join("src/render.js"),
        "export function render(userInput) {\n  return eval(userInput);\n}\n",
    )
    .expect("js fixture");

    std::fs::write(
        root.join("src/run.py"),
        "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
    )
    .expect("py fixture");

    // A file whose only mention of a sink is in a comment. If this produces a
    // finding, syntax suppression is not reaching the shipped binary.
    std::fs::write(
        root.join("src/safe.js"),
        "// Never call eval(userInput) here; it was removed in #412.\nexport const SAFE = true;\n",
    )
    .expect("comment fixture");

    directory
}

fn run(arguments: &[&str]) -> Output {
    cli().args(arguments).output().expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited normally")
}

// ------------------------------------------------------------------ basics

#[test]
fn reports_its_version() {
    let output = run(&["--version"]);
    assert_eq!(code(&output), 0);
    assert!(
        stdout(&output).contains(env!("CARGO_PKG_VERSION")),
        "version output was {:?}",
        stdout(&output)
    );
}

#[test]
fn help_names_every_subcommand() {
    let output = run(&["--help"]);
    assert_eq!(code(&output), 0);
    let help = stdout(&output);
    for subcommand in ["scan", "deps", "export", "runs", "benchmark"] {
        assert!(help.contains(subcommand), "help omits {subcommand}");
    }
}

// -------------------------------------------------------------- exit codes

#[test]
fn a_clean_scan_exits_zero() {
    let directory = tempfile::tempdir().expect("empty project");
    std::fs::write(directory.path().join("main.js"), "export const x = 1;\n").expect("write");

    let output = run(&["scan", &directory.path().to_string_lossy(), "-q"]);
    assert_eq!(code(&output), 0);
}

#[test]
fn findings_alone_do_not_fail_the_build() {
    // Adding oxAudit to a pipeline must not break it on day one. Gating is
    // opt-in, so a scan that finds things still exits 0 without --fail-on.
    let project = project();
    let output = run(&["scan", &project.path().to_string_lossy(), "-q"]);
    assert_eq!(
        code(&output),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fail_on_gates_at_the_requested_severity() {
    let project = project();
    let path = project.path().to_string_lossy().into_owned();

    // The planted findings are `high`; nothing is critical.
    let critical = run(&["scan", &path, "--fail-on", "critical", "-q"]);
    assert_eq!(code(&critical), 0, "no critical findings, so no failure");

    let high = run(&["scan", &path, "--fail-on", "high", "-q"]);
    assert_eq!(
        high.status.code(),
        Some(1),
        "high findings must fail the gate"
    );
}

#[test]
fn a_missing_directory_is_a_usage_error_not_a_crash() {
    let output = run(&["scan", "/definitely/not/here", "-q"]);
    // 2 is "you gave me something I cannot use", distinct from 3 "the scan
    // broke" and from 1 "findings". A pipeline distinguishes them.
    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));
}

#[test]
fn an_unknown_format_is_refused_before_any_work_happens() {
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "not-a-format",
        "-q",
    ]);
    assert_eq!(code(&output), 2);
}

// ------------------------------------------------------------------ output

#[test]
fn the_report_goes_to_stdout_and_progress_to_stderr() {
    // This is what lets `oxaudit-cli scan . --format sarif > out.sarif` work
    // without the caller having to silence anything.
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 0);

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is the report, and nothing else");
    assert!(report.get("findings").is_some());

    // Progress went somewhere; it just did not go into the report.
    assert!(!output.stderr.is_empty(), "progress should reach stderr");
}

#[test]
fn quiet_silences_progress_without_touching_the_report() {
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "json",
        "-q",
    ]);
    assert_eq!(code(&output), 0);
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok());
}

#[test]
fn sarif_carries_the_rule_metadata_a_consumer_reads() {
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "sarif",
        "-q",
    ]);
    assert_eq!(code(&output), 0);

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");

    let run_node = &sarif["runs"][0];
    let results = run_node["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "planted findings should be reported");

    // Without `level`, every finding arrives in GitHub code scanning as an
    // undifferentiated warning.
    assert!(
        results.iter().all(|result| result.get("level").is_some()),
        "every result needs a level"
    );

    // Without descriptors, an alert is a bare identifier with no explanation.
    let rules = run_node["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    assert!(
        !rules.is_empty(),
        "SARIF must describe the rules that fired"
    );
    assert!(
        rules.iter().all(|rule| rule["help"]["text"]
            .as_str()
            .is_some_and(|text| !text.is_empty())),
        "every rule needs remediation text"
    );
}

#[test]
fn a_finding_in_a_comment_does_not_reach_the_report() {
    // The shipped binary must apply syntax suppression, not just the library.
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "json",
        "-q",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let findings = report["findings"].as_array().expect("findings");

    assert!(
        findings
            .iter()
            .any(|finding| finding["filePath"].as_str() == Some("src/render.js")),
        "the real eval() should be reported"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding["filePath"].as_str() == Some("src/safe.js")),
        "an eval() named only in a comment must not be reported"
    );
}

#[test]
fn findings_record_how_they_were_qualified() {
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "json",
        "-q",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    for finding in report["findings"].as_array().expect("findings") {
        let tier = finding["analysis"].as_str().expect("analysis tier");
        assert!(
            tier == "syntax" || tier == "text",
            "unexpected tier {tier:?}"
        );
    }
}

#[test]
fn output_writes_a_file_rather_than_stdout() {
    let project = project();
    let destination = project.path().join("report.sarif");
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "sarif",
        "-q",
        "-o",
        &destination.to_string_lossy(),
    ]);
    assert_eq!(code(&output), 0);
    assert!(output.stdout.is_empty(), "the report went to the file");

    let written = std::fs::read(&destination).expect("report file");
    assert!(serde_json::from_slice::<serde_json::Value>(&written).is_ok());
}

// ------------------------------------------------------------ scan options

#[test]
fn scanning_with_every_detector_disabled_is_refused() {
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--no-secrets",
        "--no-patterns",
        "-q",
    ]);
    // Silently reporting a clean scan would be the most dangerous possible
    // wrong answer for this tool.
    assert_eq!(code(&output), 2);
}

#[test]
fn an_ignored_directory_is_not_scanned() {
    let project = project();
    let path = project.path().to_string_lossy().into_owned();
    // A second source directory, so ignoring one still leaves work to do.
    std::fs::create_dir_all(project.path().join("vendor")).expect("vendor");
    std::fs::write(
        project.path().join("vendor/legacy.js"),
        "export function legacy(input) {\n  return eval(input);\n}\n",
    )
    .expect("vendor fixture");

    let count = |output: &Output| -> usize {
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("json")["findings"]
            .as_array()
            .expect("findings")
            .len()
    };

    let all = run(&["scan", &path, "--format", "json", "-q"]);
    let ignored = run(&[
        "scan",
        &path,
        "--ignore-dir",
        "vendor",
        "--format",
        "json",
        "-q",
    ]);

    assert!(
        count(&all) > count(&ignored),
        "ignoring vendor should hide its findings"
    );
    assert!(
        count(&ignored) > 0,
        "the rest of the project is still scanned"
    );
}

#[test]
fn a_target_with_nothing_eligible_says_so_instead_of_reporting_clean() {
    // The dangerous outcome for a security tool is exiting 0 having examined
    // nothing: "no files were scanned" and "no problems were found" are very
    // different statements. This must not be mistakable for a clean run.
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--ignore-dir",
        "src",
        "-q",
    ]);

    assert_ne!(code(&output), 0, "an empty scan must not look clean");
    // 2, not 3: nothing broke, the filters just selected nothing.
    assert_eq!(code(&output), 2);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The message has to name what to change, or it is not actionable.
    assert!(
        stderr.contains("No files were eligible"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("ignored"), "stderr: {stderr}");
}

// --------------------------------------------------------------- benchmark

#[test]
fn the_benchmark_runs_the_committed_corpus() {
    let corpus = corpus_root();
    let output = run(&[
        "benchmark",
        "--corpus",
        &corpus.to_string_lossy(),
        "--json",
        "-q",
    ]);
    assert_eq!(
        code(&output),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert!(report["fixtures"].as_u64().expect("fixtures") > 0);
    // The figure the README publishes has to be reproducible from the binary.
    assert!(report.get("precision").is_some());
    assert!(report.get("recall").is_some());
}

#[test]
fn the_benchmark_gate_fails_below_the_requested_floor() {
    let corpus = corpus_root();
    let output = run(&[
        "benchmark",
        "--corpus",
        &corpus.to_string_lossy(),
        // Unreachable by construction, so this asserts the gate fires rather
        // than asserting a particular quality level.
        "--min-precision",
        "101",
        "-q",
    ]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn a_missing_corpus_is_a_usage_error() {
    let output = run(&["benchmark", "--corpus", "/definitely/not/here", "-q"]);
    assert_eq!(code(&output), 2);
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("benchmarks/corpus")
}

// --------------------------------------------------------- committed policy

/// Write a `.oxaudit/policy.json` dismissing everything the fixture plants.
///
/// Both rules are listed because a suppression is per rule: leaving one out
/// would leave the build gating for a reason unrelated to what is under test.
fn write_suppression(root: &Path, expires_at: &str) {
    std::fs::create_dir_all(root.join(".oxaudit")).expect(".oxaudit");
    let entry = |rule: &str| {
        format!(
            r#"{{
      "kind": "suppression",
      "ruleId": "{rule}",
      "pathPattern": "src/**",
      "state": "suppressed",
      "reason": "Sandboxed evaluation of static templates; tracked in SEC-441.",
      "expiresAt": "{expires_at}"
    }}"#
        )
    };
    std::fs::write(
        root.join(".oxaudit/policy.json"),
        format!(
            "{{\n  \"version\": 1,\n  \"entries\": [\n    {},\n    {}\n  ]\n}}",
            entry("js-eval"),
            entry("py-subprocess-shell"),
        ),
    )
    .expect("policy file");
}

#[test]
fn a_suppression_applies_only_to_the_rule_it_names() {
    // A policy entry is a decision about one rule, not a blanket exemption for
    // the path it mentions.
    let project = project();
    std::fs::create_dir_all(project.path().join(".oxaudit")).expect(".oxaudit");
    std::fs::write(
        project.path().join(".oxaudit/policy.json"),
        r#"{
  "version": 1,
  "entries": [
    {
      "kind": "suppression",
      "ruleId": "js-eval",
      "pathPattern": "src/**",
      "state": "suppressed",
      "reason": "Sandboxed evaluation of static templates.",
      "expiresAt": "2099-01-01T00:00:00Z"
    }
  ]
}"#,
    )
    .expect("policy file");

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--fail-on",
        "high",
        "-q",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the unsuppressed python finding must still gate"
    );
}

#[test]
fn a_committed_suppression_stops_a_finding_gating_the_build() {
    // The point of a policy file is to say "we reviewed this" once, in a pull
    // request, and not be asked again on every push. A dismissal that still
    // failed the pipeline would make the mechanism pointless.
    let project = project();
    let path = project.path().to_string_lossy().into_owned();

    let before = run(&["scan", &path, "--fail-on", "high", "-q"]);
    assert_eq!(before.status.code(), Some(1), "unreviewed findings gate");

    write_suppression(project.path(), "2099-01-01T00:00:00Z");
    let after = run(&["scan", &path, "--fail-on", "high", "-q"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "a suppressed finding does not gate"
    );
}

#[test]
fn a_suppressed_finding_is_still_reported() {
    // Suppression changes whether a finding gates, not whether it exists.
    // Dropping it from the report would hide a decision someone has to be able
    // to audit later.
    let project = project();
    write_suppression(project.path(), "2099-01-01T00:00:00Z");

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "json",
        "-q",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let suppressed = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["ruleId"] == "js-eval")
        .expect("the suppressed finding is still listed");

    assert_eq!(suppressed["review"]["state"], "suppressed");
    // The decision is attributed to the committed file, not to this machine.
    assert_eq!(suppressed["review"]["origin"], "projectPolicy");
}

#[test]
fn sarif_preserves_committed_suppressions_for_code_scanning() {
    let project = project();
    write_suppression(project.path(), "2099-01-01T00:00:00Z");

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "sarif",
        "-q",
    ]);
    assert_eq!(code(&output), 0);
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid SARIF");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(!results.is_empty(), "suppressed findings remain auditable");
    for result in results {
        let suppression = &result["suppressions"][0];
        assert_eq!(suppression["kind"], "external");
        assert_eq!(suppression["status"], "accepted");
        assert!(suppression["justification"]
            .as_str()
            .is_some_and(|reason| reason.contains("SEC-441")));
    }
}

#[test]
fn an_expired_suppression_gates_again() {
    // An expiry that did not expire is a permanent exception with extra steps.
    let project = project();
    write_suppression(project.path(), "2020-01-01T00:00:00Z");

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--fail-on",
        "high",
        "-q",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an expired decision returns the finding to the queue"
    );
}

#[test]
fn a_malformed_policy_stops_the_scan_rather_than_being_ignored() {
    // Silently ignoring an unparseable policy would silently un-suppress
    // everything the team had agreed to, or silently suppress nothing they
    // meant to. Either way the run would not mean what it appears to mean.
    let project = project();
    std::fs::create_dir_all(project.path().join(".oxaudit")).expect(".oxaudit");
    std::fs::write(project.path().join(".oxaudit/policy.json"), "{ not json").expect("policy file");

    let output = run(&["scan", &project.path().to_string_lossy(), "-q"]);
    assert_ne!(code(&output), 0, "an invalid policy must not pass silently");
}

// ------------------------------------------------------------- baseline diff

#[test]
fn gating_on_new_findings_ignores_a_pre_existing_backlog() {
    // Adopting a scanner on an existing codebase means meeting a backlog. A
    // team that cannot merge until the backlog is clear turns the scanner off,
    // so the gate has to distinguish "this codebase has problems" from "this
    // change made it worse".
    let project = project();
    let path = project.path().to_string_lossy().into_owned();
    let baseline = project.path().join("baseline.json");

    let captured = run(&[
        "scan",
        &path,
        "--format",
        "json",
        "-q",
        "-o",
        &baseline.to_string_lossy(),
    ]);
    assert_eq!(code(&captured), 0);

    let unchanged = run(&[
        "scan",
        &path,
        "--baseline",
        &baseline.to_string_lossy(),
        "--fail-on-new",
        "high",
        "-q",
    ]);
    assert_eq!(
        code(&unchanged),
        0,
        "an untouched backlog must not fail the build"
    );
}

#[test]
fn a_newly_introduced_finding_fails_the_new_gate() {
    let project = project();
    let path = project.path().to_string_lossy().into_owned();
    let baseline = project.path().join("baseline.json");
    run(&[
        "scan",
        &path,
        "--format",
        "json",
        "-q",
        "-o",
        &baseline.to_string_lossy(),
    ]);

    std::fs::write(
        project.path().join("src/added.js"),
        "export function added(input) {\n  return eval(input);\n}\n",
    )
    .expect("new fixture");

    let output = run(&[
        "scan",
        &path,
        "--baseline",
        &baseline.to_string_lossy(),
        "--fail-on-new",
        "high",
        "-q",
    ]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn the_comparison_is_reported_even_when_nothing_gates() {
    let project = project();
    let path = project.path().to_string_lossy().into_owned();
    let baseline = project.path().join("baseline.json");
    run(&[
        "scan",
        &path,
        "--format",
        "json",
        "-q",
        "-o",
        &baseline.to_string_lossy(),
    ]);

    let output = run(&["scan", &path, "--baseline", &baseline.to_string_lossy()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("pre-existing"), "stderr: {stderr}");
}

#[test]
fn gating_on_new_findings_without_a_baseline_is_refused() {
    // Silently passing would be the dangerous reading of "compare against
    // nothing".
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--fail-on-new",
        "high",
        "-q",
    ]);
    assert_eq!(code(&output), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--baseline"));
}

#[test]
fn a_baseline_that_is_not_an_oxaudit_report_names_the_command_that_makes_one() {
    let project = project();
    let wrong = project.path().join("report.sarif");
    run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--format",
        "sarif",
        "-q",
        "-o",
        &wrong.to_string_lossy(),
    ]);

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--baseline",
        &wrong.to_string_lossy(),
        "-q",
    ]);
    assert_eq!(code(&output), 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format json"), "stderr: {stderr}");
}

#[test]
fn a_missing_baseline_file_is_refused_rather_than_treated_as_empty() {
    // Treating it as empty would make every finding new and fail the build for
    // a typo in a path.
    let project = project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--baseline",
        "/definitely/not/here.json",
        "-q",
    ]);
    assert_eq!(code(&output), 2);
}

#[test]
fn baseline_output_alias_preserves_new_findings_gate() {
    let project = project();
    let reports = tempfile::tempdir().unwrap();
    let baseline = reports.path().join("baseline.json");
    std::fs::write(&baseline, r#"{"findings":[]}"#).unwrap();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--baseline",
        &baseline.to_string_lossy(),
        "--output",
        &baseline.to_string_lossy(),
        "--format",
        "json",
        "--fail-on-new",
        "high",
        "-q",
    ]);
    assert_eq!(
        code(&output),
        1,
        "baseline must be read before output overwrites it"
    );
}

#[test]
fn invalid_baseline_gate_cannot_write_output() {
    let project = project();
    let reports = tempfile::tempdir().unwrap();
    let output_path = reports.path().join("output.json");
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--output",
        &output_path.to_string_lossy(),
        "--fail-on-new",
        "high",
        "-q",
    ]);
    assert_eq!(code(&output), 2);
    assert!(
        !output_path.exists(),
        "invalid gate must fail before scanning or writing"
    );
}

#[test]
fn skipped_or_deleted_baseline_file_is_not_claimed_resolved() {
    let project = project();
    let reports = tempfile::tempdir().unwrap();
    let baseline = reports.path().join("baseline.json");
    assert_eq!(
        code(&run(&[
            "scan",
            &project.path().to_string_lossy(),
            "--format",
            "json",
            "--output",
            &baseline.to_string_lossy(),
            "-q"
        ])),
        0
    );
    std::fs::remove_file(project.path().join("src/render.js")).unwrap();
    // Previously observed Python findings become skipped because of size.
    std::fs::write(project.path().join("src/run.py"), "# padding\n".repeat(300)).unwrap();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--baseline",
        &baseline.to_string_lossy(),
        "--max-file-size",
        "1",
    ]);
    assert_eq!(code(&output), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no longer observed (coverage unverified)"),
        "{stderr}"
    );
    assert!(!stderr.contains("resolved"), "{stderr}");
}

// Dependency fixtures use complete local receipts only; no test calls public providers.
fn empty_dependency_project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("package-lock.json"),
        r#"{"packages":{}}"#,
    )
    .unwrap();
    directory
}

#[test]
fn dependency_runs_are_durable_discoverable_and_exportable() {
    let project = empty_dependency_project();
    let storage = tempfile::tempdir().unwrap();
    let db = storage.path().join("private/runs.sqlite");
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--db",
        &db.to_string_lossy(),
        "--format",
        "json",
        "--quiet",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["kind"], "dependencies");
    assert_eq!(report["summary"]["advisoryCoverage"], "complete");
    let id = report["summary"]["runId"].as_str().unwrap();
    let listed = run(&[
        "runs",
        "--db",
        &db.to_string_lossy(),
        "--kind",
        "dependencies",
        "--json",
    ]);
    assert_eq!(code(&listed), 0);
    let runs: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(runs[0]["id"], id);
    assert_eq!(runs[0]["kind"], "dependencies");
    assert_eq!(runs[0]["state"], "completed");
    let legacy = run(&["runs", "--db", &db.to_string_lossy(), "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&legacy.stdout).unwrap(),
        serde_json::json!([])
    );
    for format in [
        "sarif",
        "oxaudit-json",
        "cyclonedx",
        "spdx",
        "openvex",
        "cyclonedx-vex",
    ] {
        let exported = run(&[
            "export",
            "--db",
            &db.to_string_lossy(),
            "--run",
            id,
            "--format",
            format,
        ]);
        assert_eq!(
            code(&exported),
            0,
            "{format}: {}",
            String::from_utf8_lossy(&exported.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
        let direct = run(&[
            "deps",
            &project.path().to_string_lossy(),
            "--offline",
            "--format",
            format,
        ]);
        assert_eq!(
            code(&direct),
            0,
            "{format}: {}",
            String::from_utf8_lossy(&direct.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&direct.stdout).unwrap();
    }
}

#[test]
fn dependency_default_is_ephemeral_and_offline_cache_is_required_for_packages() {
    let project = empty_dependency_project();
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 0);
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 1);
    std::fs::write(project.path().join("requirements.txt"), "example==1.0.0\n").unwrap();
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("no cached OSV"));
    assert!(output.stdout.is_empty());
}

#[test]
fn dependency_invalid_baseline_and_missing_gate_never_write_output_or_database() {
    let project = empty_dependency_project();
    let storage = tempfile::tempdir().unwrap();
    let db = storage.path().join("private/runs.sqlite");
    let output_path = storage.path().join("report.json");
    for invalid in [
        r#"{"kind":"source"}"#,
        "not json",
        r#"{"schemaVersion":1,"kind":"dependencies","summary":{"advisoryCoverage":"unknown"},"dependencies":[],"vulnerabilities":[]}"#,
    ] {
        std::fs::write(&output_path, invalid).unwrap();
        let output = run(&[
            "deps",
            &project.path().to_string_lossy(),
            "--offline",
            "--db",
            &db.to_string_lossy(),
            "--baseline",
            &output_path.to_string_lossy(),
            "--output",
            &output_path.to_string_lossy(),
            "--fail-on-new",
            "high",
        ]);
        assert_eq!(code(&output), 2);
        assert_eq!(std::fs::read_to_string(&output_path).unwrap(), invalid);
        assert!(!db.exists());
    }
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--output",
        &output_path.to_string_lossy(),
        "--fail-on-new",
        "high",
    ]);
    assert_eq!(code(&output), 2);
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--baseline",
        &storage.path().join("missing.json").to_string_lossy(),
    ]);
    assert_eq!(code(&output), 2);
}

fn seed_dependency_receipt(database: &Path) {
    use sha2::{Digest, Sha256};
    let _repository =
        oxaudit_lib::findings::repository::FindingsRepository::open(database).unwrap();
    let mut results = serde_json::Map::new();
    let mut keys = Vec::new();
    for (name, version) in [
        ("example", "1.0.0"),
        ("example", "2.0.0"),
        ("another", "1.0.0"),
    ] {
        let key = format!("PyPI\0{name}\0{version}");
        keys.push(key.clone());
        results.insert(key, serde_json::json!([{
            "id":"GHSA-shared", "aliases":["CVE-2026-0001"], "summary":"fixture advisory", "details":"complete local OSV details", "severity":"high", "cvssScore":8.1,
            "ecosystem":"PyPI", "packageName":name, "installedVersion":version, "fixedVersions":["3.0.0"], "affectedRange":"< 3.0.0", "references":[], "published":null,"modified":null,"lockfile":"original/location"
        }]));
    }
    let payload = serde_json::json!({"schemaVersion":2,"advisoryCoverage":"complete","queryKeys":keys,"results":results,"recordCount":3});
    let bytes = serde_json::to_vec(&payload).unwrap();
    rusqlite::Connection::open(database)
        .unwrap()
        .execute(
            "INSERT INTO provider_snapshots VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                "provider_fixture",
                "osv-query",
                1000,
                format!("{:x}", Sha256::digest(&bytes)),
                String::from_utf8(bytes).unwrap()
            ],
        )
        .unwrap();
}

#[test]
fn dependency_new_only_gate_tracks_advisory_package_version_and_ignores_lockfile_moves() {
    let project = empty_dependency_project();
    let storage = tempfile::tempdir().unwrap();
    let db = storage.path().join("private/runs.sqlite");
    seed_dependency_receipt(&db);
    let baseline = storage.path().join("baseline.json");
    std::fs::write(project.path().join("requirements.txt"), "example==1.0.0\n").unwrap();
    let source_secret = "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::fs::write(
        project.path().join("secrets.js"),
        format!("const token = '{source_secret}';"),
    )
    .unwrap();
    let first = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--db",
        &db.to_string_lossy(),
        "--format",
        "json",
        "--output",
        &baseline.to_string_lossy(),
    ]);
    assert_eq!(
        code(&first),
        0,
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let initial = std::fs::read(&baseline).unwrap();
    assert!(!String::from_utf8_lossy(&initial).contains(source_secret));
    let report: serde_json::Value = serde_json::from_slice(&initial).unwrap();
    assert_eq!(
        report["vulnerabilities"].as_array().unwrap().len(),
        1,
        "receipt must be filtered to inventory"
    );
    assert_eq!(
        report["vulnerabilities"][0]["details"],
        "complete local OSV details"
    );
    // The same advisory in a second lockfile is existing, while both occurrences survive.
    std::fs::create_dir(project.path().join("workspace")).unwrap();
    std::fs::write(
        project.path().join("workspace/requirements.txt"),
        "example==1.0.0\n",
    )
    .unwrap();
    let repeated = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--db",
        &db.to_string_lossy(),
        "--baseline",
        &baseline.to_string_lossy(),
        "--fail-on-new",
        "high",
        "--format",
        "json",
    ]);
    assert_eq!(code(&repeated), 0);
    let repeated_report: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(
        repeated_report["vulnerabilities"].as_array().unwrap().len(),
        2
    );
    assert_eq!(repeated_report["summary"]["packagesQueried"], 1);
    // A known advisory on a newly introduced package or version is a new identity.
    for changed in ["another==1.0.0\n", "example==2.0.0\n"] {
        std::fs::write(project.path().join("requirements.txt"), changed).unwrap();
        std::fs::write(&baseline, &initial).unwrap();
        let output = run(&[
            "deps",
            &project.path().to_string_lossy(),
            "--offline",
            "--db",
            &db.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--fail-on-new",
            "high",
            "--format",
            "json",
            "--output",
            &baseline.to_string_lossy(),
        ]);
        assert_eq!(
            code(&output),
            1,
            "{changed}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ne!(
            std::fs::read(&baseline).unwrap(),
            initial,
            "baseline read precedes aliased report output"
        );
    }
    for format in [
        "sarif",
        "oxaudit-json",
        "cyclonedx",
        "spdx",
        "openvex",
        "cyclonedx-vex",
    ] {
        let output = run(&[
            "deps",
            &project.path().to_string_lossy(),
            "--offline",
            "--db",
            &db.to_string_lossy(),
            "--format",
            format,
        ]);
        assert_eq!(
            code(&output),
            0,
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            stdout(&output).contains("example"),
            "{format} should retain package evidence"
        );
    }
}

// ----------------------------------------------------------------- history

/// A throwaway git repository whose history contains a leaked AWS key in a
/// file that was deleted before the tip, plus a clean file at the tip.
fn history_project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary repository");
    let root = directory.path();

    fn git(root: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .current_dir(root)
            .args(arguments)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    git(root, &["init", "-b", "main"]);
    git(root, &["config", "user.email", "e2e@example.invalid"]);
    git(root, &["config", "user.name", "E2E"]);
    std::fs::create_dir(root.join("src")).expect("src");
    // Not a placeholder: a synthetic key the placeholder filter lets through.
    std::fs::write(
        root.join("src/deploy.sh"),
        "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n",
    )
    .expect("leak fixture");
    std::fs::write(root.join("src/app.js"), "console.log('clean');\n").expect("clean fixture");
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "leak"]);
    std::fs::remove_file(root.join("src/deploy.sh")).expect("remove leak");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-m", "remove leak"]);
    directory
}

#[test]
fn history_reports_secrets_deleted_before_the_tip() {
    let repository = history_project();
    let output = run(&["history", &repository.path().to_string_lossy()]);
    assert_eq!(
        code(&output),
        0,
        "findings without --fail-on report without failing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = stdout(&output);
    assert!(text.contains("src/deploy.sh"), "historical path reported");
    assert!(text.contains("aws-access-key-id"), "rule reported");
    // The finding exists only in history: the file is gone from the tip.
    assert!(!repository.path().join("src/deploy.sh").exists());
}

#[test]
fn history_gate_fails_only_when_asked() {
    let repository = history_project();
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--fail-on",
        "high",
    ]);
    assert_eq!(code(&output), 1);
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--fail-on",
        "critical",
    ]);
    assert_eq!(code(&output), 0, "a high finding is below the gate");
}

#[test]
fn history_json_is_a_valid_baseline_document() {
    let repository = history_project();
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 0);
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = document["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    let fingerprint = findings[0]["fingerprint"].as_str().unwrap();
    assert!(
        !fingerprint.trim().is_empty() && fingerprint.chars().all(|c| !c.is_whitespace()),
        "identity a --baseline round trip requires"
    );
    // And the round trip itself: the same history against its own baseline
    // introduces nothing.
    let baseline = repository.path().join("baseline.json");
    std::fs::write(&baseline, &output.stdout).unwrap();
    let report = repository.path().join("report.txt");
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--baseline",
        &baseline.to_string_lossy(),
        "--fail-on-new",
        "high",
        "--output",
        &report.to_string_lossy(),
    ]);
    assert_eq!(code(&output), 0);
    assert!(
        stdout(&output).is_empty(),
        "the report went to --output, not stdout"
    );
    assert!(report.exists());
}

#[test]
fn history_without_git_fails_rather_than_reporting_clean() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(&["history", &directory.path().to_string_lossy()]);
    assert_eq!(code(&output), 3);
    assert!(
        stdout(&output).is_empty(),
        "a failed scan must not look like a clean report"
    );
}

#[test]
fn validation_is_opt_in_and_reports_unchecked_without_a_validator() {
    let repository = history_project();
    // The fixture's AWS key id has no secret access key near it to pair
    // with, so the full opt-in path runs without any credential leaving the
    // machine — and the unpaired key is reported as unpaired, not silently
    // folded into "no validator".
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--validate-secrets",
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("validated 0 secret(s)"),
        "the summary line reports what validation did: {stderr}"
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let validation = &document["summary"]["validation"];
    assert_eq!(validation["enabled"], serde_json::json!(true));
    assert_eq!(validation["skippedUnpaired"], serde_json::json!(1));
    assert_eq!(validation["skippedNoValidator"], serde_json::json!(0));
    // Without the flag nothing about validation appears at all.
    let output = run(&[
        "history",
        &repository.path().to_string_lossy(),
        "--format",
        "json",
    ]);
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document["summary"]["validation"].is_null());
}

// ------------------------------------------------------------------ rule packs

/// A real, valid pack on disk: two fixture files beside the TOML, hashes
/// matching, provenance complete — everything installation checks.
fn rule_pack_fixture(directory: &std::path::Path) -> std::path::PathBuf {
    use oxaudit_scanners::{
        CompiledRulePack, FixtureExpectation, RuleDefinition, RuleEngine, RulePack,
        RulePackMetadata, RuleScope,
    };
    let hash_of = |content: &str| {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(content.as_bytes()))
    };
    let provenance = |hash: &str| oxaudit_domain::Provenance {
        authors: vec!["e2e fixture".into()],
        source: "independent fixture".into(),
        license: "Apache-2.0".into(),
        creation_method: oxaudit_domain::CreationMethod::IndependentlyDerived,
        content_sha256: hash.into(),
    };
    let rules = vec![RuleDefinition {
        id: "source.e2e-marker".into(),
        version: "1".into(),
        title: "E2E marker rule".into(),
        description: "Matches the e2e marker call.".into(),
        recommendation: "Remove the marker call.".into(),
        engine: RuleEngine::SourceRegex,
        severity: oxaudit_domain::Severity::High,
        scope: RuleScope {
            languages: vec!["javascript".into()],
            platforms: Vec::new(),
            architectures: Vec::new(),
            file_extensions: Vec::new(),
        },
        pattern: r"e2eMarkerCall\(([^)]+)\)".into(),
        classifications: vec!["CWE-95".into()],
        provenance: provenance(&"b".repeat(64)),
        positive_fixtures: vec![FixtureExpectation {
            id: "positive".into(),
            path: "positive.txt".into(),
            sha256: hash_of("e2eMarkerCall(x)\n"),
            expected_values: Vec::new(),
        }],
        negative_fixtures: vec![FixtureExpectation {
            id: "negative".into(),
            path: "negative.txt".into(),
            sha256: hash_of("clean code\n"),
            expected_values: Vec::new(),
        }],
    }];
    let content_hash = RulePack::computed_content_sha256(&rules).unwrap();
    let pack = RulePack {
        pack: RulePackMetadata {
            schema_version: 1,
            id: oxaudit_domain::RulePackId::parse("rulepack.e2e").unwrap(),
            name: "E2E rules".into(),
            version: "1.0.0".into(),
            minimum_oxaudit_version: "0.1.0".into(),
            content_sha256: content_hash.clone(),
            provenance: provenance(&content_hash),
        },
        rules,
    };
    // Prove the pack is sound before writing it: an unsound fixture would
    // make these tests assert the wrong behavior.
    CompiledRulePack::compile(pack.clone()).expect("e2e pack compiles");
    std::fs::write(directory.join("positive.txt"), "e2eMarkerCall(x)\n").unwrap();
    std::fs::write(directory.join("negative.txt"), "clean code\n").unwrap();
    let path = directory.join("pack.toml");
    std::fs::write(&path, toml::to_string(&pack).unwrap()).unwrap();
    path
}

fn rule_pack_project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join("src")).unwrap();
    std::fs::write(
        directory.path().join("src/marker.js"),
        "function go() { e2eMarkerCall(payload); }\n",
    )
    .unwrap();
    directory
}

#[test]
fn scan_applies_an_ephemeral_rule_pack_file_with_pack_qualified_ids() {
    let packs = tempfile::tempdir().unwrap();
    let pack_path = rule_pack_fixture(packs.path());
    let project = rule_pack_project();

    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--rule-pack-file",
        &pack_path.to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rules: Vec<&str> = document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["ruleId"].as_str())
        .collect();
    assert!(
        rules.contains(&"rulepack.e2e/source.e2e-marker"),
        "pack finding present with its pack-qualified id: {rules:?}"
    );
}

#[test]
fn an_invalid_rule_pack_file_is_a_usage_error_before_any_scanning() {
    let packs = tempfile::tempdir().unwrap();
    let bad = packs.path().join("bad.toml");
    std::fs::write(&bad, "[pack]\n").unwrap();
    let project = rule_pack_project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--rule-pack-file",
        &bad.to_string_lossy(),
    ]);
    assert_eq!(code(&output), 2, "caller-fixable, not a scan failure");
    assert!(
        stdout(&output).is_empty(),
        "no report from a run that never scanned"
    );
}

#[test]
fn rule_packs_round_trip_through_the_store_and_apply_by_selection() {
    let packs = tempfile::tempdir().unwrap();
    let pack_path = rule_pack_fixture(packs.path());
    let store = packs.path().join("store.sqlite3");

    let output = run(&[
        "rule-pack",
        "install",
        "--db",
        &store.to_string_lossy(),
        &pack_path.to_string_lossy(),
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout(&output).contains("rulepack.e2e"));

    let output = run(&[
        "rule-pack",
        "list",
        "--db",
        &store.to_string_lossy(),
        "--json",
    ]);
    assert_eq!(code(&output), 0);
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed[0]["id"], "rulepack.e2e");
    assert_eq!(listed[0]["ruleCount"], 1);

    // Disable for default application, then select explicitly: explicit
    // selection applies the pack as stored, enabled or not.
    let output = run(&[
        "rule-pack",
        "disable",
        "--db",
        &store.to_string_lossy(),
        "rulepack.e2e",
    ]);
    assert_eq!(code(&output), 0);

    let project = rule_pack_project();
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--rule-pack",
        "rulepack.e2e",
        "--rule-pack-db",
        &store.to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["ruleId"] == "rulepack.e2e/source.e2e-marker"));

    // A selected id that is not installed fails loudly instead of scanning
    // without the rules the caller asked for.
    let output = run(&[
        "scan",
        &project.path().to_string_lossy(),
        "--rule-pack",
        "rulepack.absent",
        "--rule-pack-db",
        &store.to_string_lossy(),
    ]);
    assert_eq!(code(&output), 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("rulepack.absent"));
}

/// Serve OSV-shaped ecosystem dumps over a local HTTP server so the advisory
/// database build runs end to end without touching the network.
struct DumpServer {
    address: std::net::SocketAddr,
}

impl DumpServer {
    fn start(zip: Vec<u8>) -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = [0u8; 4096];
                let read = stream.read(&mut request).unwrap_or(0);
                let head = String::from_utf8_lossy(&request[..read]);
                // Only the request line matters; every ecosystem path serves
                // the same fixture archive.
                if !head.starts_with("GET ") {
                    continue;
                }
                let body = zip.clone();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Self { address }
    }

    fn base(&self) -> String {
        format!("http://{}", self.address)
    }
}

fn fixture_dump_zip() -> Vec<u8> {
    let advisory = serde_json::json!({
        "id": "GHSA-e2e-fixture",
        "summary": "e2e fixture advisory",
        "aliases": ["CVE-2099-1234"],
        "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        "affected": [{
            "package": { "ecosystem": "npm", "name": "example" },
            "ranges": [{ "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]
        }]
    })
    .to_string();
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "GHSA-e2e-fixture.json".to_string(),
            zip::write::SimpleFileOptions::default(),
        )
        .expect("zip member");
    std::io::Write::write_all(&mut writer, advisory.as_bytes()).expect("zip body");
    writer.finish().expect("zip").into_inner()
}

#[test]
fn advisory_database_supports_offline_dependency_matching() {
    let server = DumpServer::start(fixture_dump_zip());
    let workspace = tempfile::tempdir().expect("workspace");
    let db = workspace.path().join("advisories.sqlite3");

    let output = run(&[
        "advisory-db",
        "update",
        "--db",
        &db.to_string_lossy(),
        "--source",
        &server.base(),
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("npm:"), "{stderr}");

    // Status reports coverage over the built database.
    let output = run(&[
        "advisory-db",
        "status",
        "--db",
        &db.to_string_lossy(),
        "--json",
    ]);
    assert_eq!(code(&output), 0);
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(status["ecosystems"].as_array().unwrap().len() >= 8);
    assert_eq!(status["advisories"], 1);

    // A lockfile project scans offline against the database: the fixture
    // advisory affects example@1.0.0.
    let project = tempfile::tempdir().expect("project");
    std::fs::create_dir_all(project.path()).expect("project dir");
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .expect("lockfile");
    let output = run(&[
        "deps",
        &project.path().to_string_lossy(),
        "--offline",
        "--advisory-db",
        &db.to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["summary"]["advisorySource"], "local-db");
    let vulnerabilities = document["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulnerabilities.len(), 1);
    assert_eq!(vulnerabilities[0]["id"], "GHSA-e2e-fixture");
    assert_eq!(
        vulnerabilities[0]["fixedVersions"],
        serde_json::json!(["2.0.0"])
    );
    assert_eq!(vulnerabilities[0]["packageName"], "example");
}

fn debian_image_tar(dir: &std::path::Path) -> std::path::PathBuf {
    // A saved-image shape: os-release naming the distribution, plus its dpkg
    // database — the OS-package layer the native scanner now reads.
    let mut builder = tar::Builder::new(Vec::new());
    let mut add = |path: &str, body: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, body)
            .expect("image member");
    };
    add(
        "etc/os-release",
        b"ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
    );
    add(
        "var/lib/dpkg/status",
        b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n",
    );
    let path = dir.join("debian12.tar");
    std::fs::write(&path, builder.into_inner().expect("image tar")).expect("write image");
    path
}

fn debian_dump_zip() -> Vec<u8> {
    let advisory = serde_json::json!({
        "id": "CVE-2099-2222",
        "aliases": ["GHSA-image-fixture"],
        "summary": "image e2e fixture advisory",
        "severity": [{ "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        "affected": [{
            "package": { "ecosystem": "Debian:12", "name": "libc6" },
            "ranges": [{ "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.40.0-1"}] }]
        }]
    })
    .to_string();
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "CVE-2099-2222.json".to_string(),
            zip::write::SimpleFileOptions::default(),
        )
        .expect("zip member");
    std::io::Write::write_all(&mut writer, advisory.as_bytes()).expect("zip body");
    writer.finish().expect("zip").into_inner()
}

#[test]
fn image_scans_answer_distro_packages_offline_from_the_advisory_database() {
    let server = DumpServer::start(debian_dump_zip());
    let workspace = tempfile::tempdir().expect("workspace");
    let db = workspace.path().join("advisories.sqlite3");
    let output = run(&[
        "advisory-db",
        "update",
        "--db",
        &db.to_string_lossy(),
        "--source",
        &server.base(),
        "--ecosystem",
        "Debian:12",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image = debian_image_tar(workspace.path());
    let output = run(&[
        "image",
        &image.to_string_lossy(),
        "--advisory-db",
        &db.to_string_lossy(),
        "--offline",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["kind"], "image");

    let libc6 = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["product"] == "libc6")
        .expect("libc6 component from the dpkg database");
    let vulnerabilities = libc6["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulnerabilities.len(), 1);
    assert_eq!(vulnerabilities[0]["cveId"], "CVE-2099-2222");
    assert_eq!(vulnerabilities[0]["severity"], "critical");
    assert_eq!(vulnerabilities[0]["fixedIn"], "2.40.0-1");
    // No CPE-keyed components exist here, and a database was supplied, so an
    // offline run has nothing to apologize for.
    assert!(
        !document["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap().contains("NVD")),
        "unexpected notes: {:?}",
        document["notes"]
    );

    // --fail-on critical gates on the database answer.
    let output = run(&[
        "image",
        &image.to_string_lossy(),
        "--advisory-db",
        &db.to_string_lossy(),
        "--offline",
        "--fail-on",
        "critical",
    ]);
    assert_eq!(code(&output), 1);
}

/// A minimal OCI/Docker v2 registry: bearer challenge, token endpoint,
/// manifest index → platform manifest, digest-verified blobs. Enough of the
/// protocol to exercise the real client end to end without the network.
struct FakeRegistry {
    address: std::net::SocketAddr,
}

impl FakeRegistry {
    fn start(index: Vec<u8>, manifest: Vec<u8>, layers: Vec<Vec<u8>>) -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let index_digest = sha256_hex(&index);
        let layer_digests: Vec<String> = layers.iter().map(|bytes| sha256_hex(bytes)).collect();
        let manifest_digest = sha256_hex(&manifest);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                // Read until the end of the request head.
                loop {
                    match stream.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {
                            head.extend_from_slice(&byte);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&head);
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let path = request_line.split(' ').nth(1).unwrap_or("/").to_string();
                let has_bearer = head.to_ascii_lowercase().contains("authorization: bearer");

                let index = index.clone();
                let manifest = manifest.clone();
                let layers = layers.clone();
                let layer_digests = layer_digests.clone();
                let (status, headers, body): (u16, Vec<String>, Vec<u8>) = if path == "/v2/" {
                    (
                        401,
                        vec![
                            r#"Www-Authenticate: Bearer realm="http://TOKEN/token",service="local""#.replace("TOKEN", &format!("127.0.0.1:{}", address.port())),
                            "Content-Type: application/json".into(),
                        ],
                        br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#.to_vec(),
                    )
                } else if path.starts_with("/token") {
                    (
                        200,
                        vec!["Content-Type: application/json".into()],
                        br#"{"token":"fake-token"}"#.to_vec(),
                    )
                } else if !has_bearer {
                    (
                        401,
                        vec!["Content-Type: application/json".into()],
                        br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#.to_vec(),
                    )
                } else if path == "/v2/my/app/manifests/1.0" {
                    (
                        200,
                        vec![
                            "Content-Type: application/vnd.docker.distribution.manifest.list.v2+json".into(),
                            format!("Docker-Content-Digest: sha256:{index_digest}"),
                        ],
                        index,
                    )
                } else if path == format!("/v2/my/app/manifests/sha256:{manifest_digest}") {
                    (
                        200,
                        vec![
                            "Content-Type: application/vnd.docker.distribution.manifest.v2+json"
                                .into(),
                            format!("Docker-Content-Digest: sha256:{manifest_digest}"),
                        ],
                        manifest,
                    )
                } else if let Some(position) = layer_digests
                    .iter()
                    .position(|digest| path == format!("/v2/my/app/blobs/sha256:{digest}"))
                {
                    (
                        200,
                        vec!["Content-Type: application/octet-stream".into()],
                        layers[position].clone(),
                    )
                } else {
                    (
                        404,
                        vec!["Content-Type: application/json".into()],
                        br#"{"errors":[{"code":"MANIFEST_UNKNOWN"}]}"#.to_vec(),
                    )
                };
                let header_text = headers.join("\r\n");
                let response = format!(
                    "HTTP/1.1 {status} X\r\n{header_text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        Self { address }
    }

    fn reference(&self) -> String {
        format!("127.0.0.1:{}/my/app:1.0", self.address.port())
    }
}

// The fake registry's serving loop re-binds the fixtures per connection;
// keeping clones alive for every branch requires them outside the closure.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn gzip_layer(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *body)
            .expect("layer member");
    }
    let tar = builder.into_inner().expect("layer tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar).expect("gzip");
    encoder.finish().expect("gzip layer")
}

#[test]
fn registry_references_are_pulled_and_scanned_offline() {
    // Layer 1: the base — distribution identity and its dpkg database.
    let base = gzip_layer(&[
        (
            "etc/os-release",
            b"ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
        ),
        (
            "var/lib/dpkg/status",
            b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\n",
        ),
    ]);
    // Layer 2: the app — a fat-JAR's library with embedded coordinates.
    let inner_jar = {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "META-INF/maven/org.example/library/pom.properties".to_string(),
                zip::write::SimpleFileOptions::default(),
            )
            .expect("jar member");
        std::io::Write::write_all(
            &mut writer,
            b"groupId=org.example\nartifactId=library\nversion=1.2.3\n",
        )
        .expect("properties");
        writer.finish().expect("jar").into_inner()
    };
    let app = gzip_layer(&[("app/lib/library.jar", &inner_jar)]);

    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": { "mediaType": "application/vnd.docker.container.image.v1+json",
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "size": 2 },
        "layers": [
            { "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
              "digest": format!("sha256:{}", sha256_hex(&base)), "size": base.len() },
            { "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
              "digest": format!("sha256:{}", sha256_hex(&app)), "size": app.len() },
        ]
    })
    .to_string()
    .into_bytes();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [{
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": format!("sha256:{}", sha256_hex(&manifest)),
            "size": manifest.len(),
            "platform": { "os": "linux", "architecture": host_arch },
        }]
    })
    .to_string()
    .into_bytes();

    let registry = FakeRegistry::start(index, manifest, vec![base, app]);

    // The advisory database with a Debian:12 record for the base layer.
    let server = DumpServer::start(debian_dump_zip());
    let workspace = tempfile::tempdir().expect("workspace");
    let db = workspace.path().join("advisories.sqlite3");
    let output = run(&[
        "advisory-db",
        "update",
        "--db",
        &db.to_string_lossy(),
        "--source",
        &server.base(),
        "--ecosystem",
        "Debian:12",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run(&[
        "image",
        &registry.reference(),
        "--advisory-db",
        &db.to_string_lossy(),
        "--offline",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["kind"], "image");
    let components = document["components"].as_array().unwrap();

    let libc6 = components
        .iter()
        .find(|component| component["product"] == "libc6")
        .expect("dpkg package from the pulled base layer");
    let vulnerabilities = libc6["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulnerabilities.len(), 1);
    assert_eq!(vulnerabilities[0]["cveId"], "CVE-2099-2222");
    // Findings name the registry reference and the layer they came from.
    let path = libc6["paths"][0].as_str().unwrap();
    assert!(
        path.starts_with("127.0.0.1:")
            && path.contains("/my/app:1.0@")
            && path.contains("layer-0000.tar!/var/lib/dpkg/status"),
        "path {path:?}"
    );

    let library = components
        .iter()
        .find(|component| component["product"] == "org.example:library")
        .expect("maven coordinates from the app layer");
    assert_eq!(library["version"], "1.2.3");
}

#[test]
fn rule_packs_install_from_a_feed_and_apply_by_selection() {
    // Build the real fixture pack on disk, then serve it as a feed: an
    // index plus a digest-verified zip of pack.toml and its fixtures.
    let staging = tempfile::tempdir().expect("staging");
    rule_pack_fixture(staging.path());
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for name in ["pack.toml", "positive.txt", "negative.txt"] {
        writer
            .start_file(name.to_string(), zip::write::SimpleFileOptions::default())
            .expect("zip member");
        let bytes = std::fs::read(staging.path().join(name)).expect("fixture file");
        std::io::Write::write_all(&mut writer, &bytes).expect("zip body");
    }
    let pack_zip = writer.finish().expect("pack zip").into_inner();
    let pack_sha = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(&pack_zip))
    };
    let index = serde_json::json!({
        "schemaVersion": 1,
        "packs": [{
            "id": "rulepack.e2e",
            "version": "1.0.0",
            "file": "rulepack.e2e-1.0.0.zip",
            "sha256": pack_sha,
        }]
    })
    .to_string();

    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {
                        head.extend_from_slice(&byte);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let path = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or_default()
                .split(' ')
                .nth(1)
                .unwrap_or("/")
                .to_string();
            let (content_type, body) = if path.ends_with(".zip") {
                ("application/zip", pack_zip.clone())
            } else {
                ("application/json", index.as_bytes().to_vec())
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });

    let workspace = tempfile::tempdir().expect("workspace");
    let store = workspace.path().join("packs.sqlite3");
    let feed = format!("http://127.0.0.1:{}/index.json", address.port());

    let output = run(&[
        "rule-pack",
        "update",
        "--db",
        &store.to_string_lossy(),
        "--feed",
        &feed,
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("rulepack.e2e installed from the feed"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // The fed pack behaves exactly like a hand-installed one.
    let output = run(&[
        "scan",
        &rule_pack_project().path().to_string_lossy(),
        "--rule-pack",
        "rulepack.e2e",
        "--rule-pack-db",
        &store.to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["ruleId"] == "rulepack.e2e/source.e2e-marker"));

    // A second update at the same version skips; an unknown --only id errors.
    let output = run(&[
        "rule-pack",
        "update",
        "--db",
        &store.to_string_lossy(),
        "--feed",
        &feed,
    ]);
    assert_eq!(code(&output), 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("skipped"));
    let output = run(&[
        "rule-pack",
        "update",
        "--db",
        &store.to_string_lossy(),
        "--feed",
        &feed,
        "--only",
        "rulepack.absent",
    ]);
    assert_eq!(code(&output), 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("rulepack.absent"));
}

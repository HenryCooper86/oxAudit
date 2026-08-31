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

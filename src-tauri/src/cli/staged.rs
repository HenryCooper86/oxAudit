//! `scan --staged` and the pre-commit hook that runs it.
//!
//! Normal scans deliberately never look inside the git index; this mode does
//! nothing else. A commit is the cheapest place to stop a credential leak —
//! after a push the response is rotation and history purge — so the hook
//! installed by `oxaudit hook install` runs `oxaudit-cli scan --staged
//! --quiet` and blocks the commit when a staged blob contains a secret. Two
//! consequences shape the code below:
//!
//! - It must never block on an empty stage or a directory that is not a
//!   repository: both exit 0 with a note on stderr.
//! - It runs in memory and stores nothing, so the standards formats that need
//!   a stored run are refused up front.
//!
//! Git access mirrors the history scanner exactly: the hardened command from
//! `git_context`, NUL-delimited `ls-files --stage` for enumeration, and
//! `git cat-file --batch` with a bounded queue for blob content. Nothing here
//! touches the working tree or writes to the index. (The hooks our own git
//! invocations neutralize via `hardened_git_command` are unrelated to the
//! hook this module installs — that hook is for the user's git.)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::{
    emit_github_annotations, failure, gate, render_scan_text, render_summary_markdown,
    severity_rank, usage, write_output, write_step_summary, CliError, CliResult, FailOn,
    HookCommand, OutputFormat, ScanArgs, EXIT_OK,
};
use crate::git_context::hardened_git_command;
use crate::models::{Finding, ScanSummary};

/// Per-blob cap; the same limit the history scanner applies and the working
/// tree's default --max-file-size.
const MAX_BLOB_BYTES: u64 = 1024 * 1024;
/// Total staged bytes scanned before stopping early. A single commit should
/// sit far below this; the budget guards the hook against a pathological
/// stage (for example a generated tree staged by accident).
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Findings kept before the scan stops early.
const MAX_FINDINGS: usize = 10_000;
/// Staged entries considered; mirrors the path budget of context inspection.
const MAX_ENTRIES: usize = 100_000;
/// `ls-files --stage` output cap. A partial listing cannot be distinguished
/// from a complete one, so past this the scan fails rather than truncates.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;
/// Wall clock for the whole staged scan.
const TIMEOUT: Duration = Duration::from_secs(60);

const UNAVAILABLE: &str = "Git index unavailable: enumeration or blob read failed.";

// --------------------------------------------------------------------- scan

pub(super) fn run_staged(args: &ScanArgs, quiet: bool) -> CliResult {
    // The standards formats render from the stored canonical run graph, and
    // staged mode stores nothing — refuse up front instead of scanning first.
    if args.format.as_report_format().is_some() {
        return Err(usage(
            "--staged scans the git index in memory; standards formats need a stored run — use --format text or json",
        ));
    }
    if args.db.is_some() {
        return Err(usage(
            "--staged runs in memory and stores nothing; drop --db",
        ));
    }
    if args.no_secrets {
        return Err(usage(
            "--staged scans staged content for secrets; --no-secrets leaves nothing to scan",
        ));
    }
    if args.baseline.is_some() || args.fail_on_new != FailOn::None {
        return Err(usage(
            "--staged reports the current stage only; --baseline and --fail-on-new compare working-tree runs",
        ));
    }

    let target = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let root = match crate::git_context::repo_root(&target) {
        Ok(root) => root,
        Err(_) => {
            // A pre-commit hook must never block because it was invoked
            // outside a checkout.
            eprintln!("oxaudit: not a git repository; nothing staged to scan");
            return Ok(EXIT_OK);
        }
    };

    let started = Instant::now();
    let entries = parse_index(&git_output(&root, &["ls-files", "--stage", "-z", "--"])?)?;
    if entries.is_empty() {
        // An empty stage is a commit that cannot leak anything; note and pass.
        eprintln!("oxaudit: no staged files; nothing to scan");
        return Ok(EXIT_OK);
    }
    if !quiet {
        eprintln!(
            "Scanning {} staged file(s) in {}",
            entries.len(),
            root.display()
        );
    }

    // Dedup by object id, like the history scanner: the same blob staged at
    // two paths is one object and one set of findings, reported at the first
    // path git listed.
    let by_oid: HashMap<String, String> = entries.into_iter().collect();
    let mut batch = spawn_batch_reader(&root, &by_oid)?;
    let deadline = started + TIMEOUT;
    let mut findings: Vec<Finding> = Vec::new();
    let mut blobs_scanned = 0usize;
    let mut blobs_skipped = 0usize;
    let mut total_bytes = 0u64;
    let mut truncated_note: Option<String> = None;

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        let blob = match batch
            .receiver
            .as_ref()
            .expect("staged receiver exists")
            .recv_timeout(
                remaining
                    .min(Duration::from_millis(25))
                    .max(Duration::from_millis(1)),
            ) {
            Ok(Ok(Some(blob))) => blob,
            Ok(Ok(None)) => {
                blobs_skipped += 1;
                continue;
            }
            Ok(Err(error)) => return Err(failure(error)),
            Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => continue,
            Err(RecvTimeoutError::Timeout) => {
                truncated_note.get_or_insert_with(|| "time budget reached".to_owned());
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let text = match String::from_utf8(blob.bytes) {
            Ok(text) => text,
            Err(_) => {
                // Binary staged content carries no scannable secrets.
                blobs_skipped += 1;
                continue;
            }
        };
        let byte_count = text.len() as u64;
        if total_bytes
            .checked_add(byte_count)
            .map_or(true, |bytes| bytes > MAX_TOTAL_BYTES)
        {
            truncated_note.get_or_insert_with(|| "total scanned-bytes budget reached".to_owned());
            break;
        }
        total_bytes += byte_count;
        match crate::scanners::scan_text_for_secrets_with_raw(
            &text,
            &blob.path,
            MAX_FINDINGS.saturating_sub(findings.len()),
            false,
        ) {
            Some((mut found, _)) => {
                blobs_scanned += 1;
                findings.append(&mut found);
                if findings.len() >= MAX_FINDINGS {
                    truncated_note
                        .get_or_insert_with(|| format!("finding budget of {MAX_FINDINGS} reached"));
                    break;
                }
            }
            // A single blob overflowing the per-content limit mirrors the
            // working tree's per-file limit; keep earlier findings and say so.
            None => {
                blobs_skipped += 1;
                truncated_note.get_or_insert_with(|| {
                    "staged finding allowance exceeded; earlier evidence retained".into()
                });
                break;
            }
        }
    }
    if truncated_note.is_none() {
        let status = batch.child.wait().map_err(|_| failure(UNAVAILABLE))?;
        if !status.success() {
            return Err(failure(UNAVAILABLE));
        }
    }

    let elapsed = started.elapsed();
    if !quiet {
        eprintln!(
            "Scanned {blobs_scanned} staged blob(s) ({blobs_skipped} skipped) in {} ms",
            elapsed.as_millis()
        );
        if let Some(note) = &truncated_note {
            eprintln!("Staged scan stopped early: {note}. Findings below are partial.");
        }
    }

    let summary = staged_summary(
        &root,
        &findings,
        blobs_scanned,
        blobs_skipped,
        total_bytes,
        elapsed,
    );
    let rendered = match args.format {
        OutputFormat::Text => render_scan_text(&summary, &findings),
        OutputFormat::Json => serde_json::to_vec_pretty(&serde_json::json!({
            "summary": summary,
            "findings": findings,
        }))
        .map_err(|error| failure(error.to_string()))?,
        // Refused at the top of the function; unreachable by construction.
        other => return Err(usage(format!("--staged cannot render {other:?}"))),
    };
    write_output(args.output.as_deref(), &rendered)?;

    emit_github_annotations(&findings, &root);
    write_step_summary(&render_summary_markdown(&summary, &findings), quiet);

    // Secrets fire at high severity, so a staged scan gates on high unless
    // the caller deliberately asked otherwise.
    let fail_on = args.fail_on.unwrap_or(FailOn::High);
    Ok(gate(
        findings
            .iter()
            .map(|finding| severity_rank(&finding.severity)),
        fail_on,
        quiet,
    ))
}

fn staged_summary(
    root: &Path,
    findings: &[Finding],
    blobs_scanned: usize,
    blobs_skipped: usize,
    total_bytes: u64,
    elapsed: Duration,
) -> ScanSummary {
    let mut summary = ScanSummary {
        coverage_warnings: Vec::new(),
        git_context: None,
        path: root.to_string_lossy().into_owned(),
        files_scanned: blobs_scanned,
        files_skipped: blobs_skipped,
        bytes_scanned: total_bytes,
        duration_ms: elapsed.as_millis() as u64,
        secrets_found: findings.len(),
        vulnerabilities_found: 0,
        total_findings: findings.len(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        rules_fired: BTreeMap::new(),
    };
    for finding in findings {
        match finding.severity.as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            _ => summary.info += 1,
        }
        *summary
            .rules_fired
            .entry(finding.rule_id.clone())
            .or_default() += 1;
    }
    summary
}

// -------------------------------------------------------------- git plumbing

/// Run a read-only git plumbing command with the hardened environment,
/// draining stdout concurrently so pipe capacity cannot deadlock the child.
fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let mut command = hardened_git_command(root);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| failure(UNAVAILABLE))?;
    let stdout = child.stdout.take().ok_or_else(|| failure(UNAVAILABLE))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_LIST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = child.wait().map_err(|_| failure(UNAVAILABLE))?;
    let bytes = reader
        .join()
        .map_err(|_| failure(UNAVAILABLE))?
        .map_err(|_| failure(UNAVAILABLE))?;
    if !status.success() || bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(failure(UNAVAILABLE));
    }
    Ok(bytes)
}

/// Parse `ls-files --stage -z` into (oid, path) pairs. Only stage-0 regular
/// files are commit candidates: conflict stages, gitlinks (submodule
/// commits), and symlinks are skipped; deletions never appear in the index.
fn parse_index(bytes: &[u8]) -> Result<Vec<(String, String)>, CliError> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(failure(UNAVAILABLE));
    }
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        // A path git cannot quote to UTF-8 is skipped rather than failing the
        // whole stage.
        let Ok(text) = std::str::from_utf8(record) else {
            continue;
        };
        let Some((header, path)) = text.split_once('\t') else {
            return Err(failure(UNAVAILABLE));
        };
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 {
            return Err(failure(UNAVAILABLE));
        }
        if fields[2] != "0" || !matches!(fields[0], "100644" | "100755") {
            continue;
        }
        let oid = fields[1];
        if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(failure(UNAVAILABLE));
        }
        if seen.insert(oid.to_owned()) {
            entries.push((oid.to_owned(), path.to_owned()));
        }
        if entries.len() >= MAX_ENTRIES {
            return Err(failure(format!(
                "staged entry budget of {MAX_ENTRIES} reached; commit in smaller pieces"
            )));
        }
    }
    Ok(entries)
}

/// One staged blob's content, read from `cat-file --batch`, with its
/// repository-relative path.
struct StagedBlob {
    path: String,
    bytes: Vec<u8>,
}

/// Spawn `git cat-file --batch` with a writer thread feeding every staged oid
/// and a reader thread parsing the response stream into whole blobs — the
/// same backpressure discipline as the history scanner: a bounded queue of
/// two blobs, a reader that enforces the protocol so the stream can never
/// desynchronize, and a `Drop` that kills the child and joins both threads.
struct BatchReader {
    child: Child,
    receiver: Option<Receiver<Result<Option<StagedBlob>, String>>>,
    writer: Option<std::thread::JoinHandle<()>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for BatchReader {
    fn drop(&mut self) {
        // Release a producer blocked by the bounded queue before joining it.
        self.receiver.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn spawn_batch_reader(
    root: &Path,
    by_oid: &HashMap<String, String>,
) -> Result<BatchReader, CliError> {
    let mut command = hardened_git_command(root);
    command
        .arg("cat-file")
        .args(["--batch", "--buffer"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| failure(UNAVAILABLE))?;
    let stdin = child.stdin.take().ok_or_else(|| failure(UNAVAILABLE))?;
    let stdout = child.stdout.take().ok_or_else(|| failure(UNAVAILABLE))?;

    let mut oids: Vec<String> = by_oid.keys().cloned().collect();
    oids.sort_unstable();
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        for oid in &oids {
            if writeln!(stdin, "{oid}").is_err() {
                break;
            }
        }
        // Close stdin so cat-file exits after the last response instead of
        // waiting for more requests.
    });
    let paths: HashMap<String, String> = by_oid.clone();
    // At most two queued 1 MiB blobs plus the reader/consumer's current blob.
    let (sender, receiver) = mpsc::sync_channel::<Result<Option<StagedBlob>, String>>(2);
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut header = String::new();
            match stdout.read_line(&mut header) {
                Ok(0) => break,
                Err(_) => {
                    let _ = sender.send(Err("Git index blob stream could not be read".into()));
                    break;
                }
                Ok(_) => {}
            }
            let header = header.trim_end();
            let Some((oid, rest)) = header.split_once(' ') else {
                let _ = sender.send(Err("Malformed Git index blob header".into()));
                break;
            };
            // `<oid> missing` has no body.
            let Some((kind, size_text)) = rest.split_once(' ') else {
                if sender.send(Ok(None)).is_err() {
                    break;
                }
                continue;
            };
            let Ok(size) = size_text.parse::<u64>() else {
                let _ = sender.send(Err("Malformed Git index blob size".into()));
                break;
            };
            if kind != "blob" || size > MAX_BLOB_BYTES {
                // Content plus the unconditional trailing LF, so the stream
                // stays aligned on the next header.
                if size
                    .checked_add(1)
                    .map_or(true, |size| !drain(&mut stdout, size))
                {
                    let _ = sender.send(Err("Incomplete Git index object body".into()));
                    break;
                }
                if sender.send(Ok(None)).is_err() {
                    break;
                }
                continue;
            }
            let mut bytes = vec![0u8; size as usize];
            if stdout.read_exact(&mut bytes).is_err() {
                let _ = sender.send(Err("Incomplete Git index blob body".into()));
                break;
            }
            if !drain(&mut stdout, 1) {
                let _ = sender.send(Err("Incomplete Git index blob terminator".into()));
                break;
            }
            if let Some(path) = paths.get(oid) {
                if sender
                    .send(Ok(Some(StagedBlob {
                        path: path.clone(),
                        bytes,
                    })))
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    Ok(BatchReader {
        child,
        receiver: Some(receiver),
        writer: Some(writer),
        reader: Some(reader),
    })
}

/// Read and discard exactly `size` bytes so the stream stays aligned on the
/// next object header.
fn drain(reader: &mut BufReader<std::process::ChildStdout>, size: u64) -> bool {
    let mut remaining = size;
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(scratch.len() as u64) as usize;
        match reader.read(&mut scratch[..want]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => remaining -= n as u64,
        }
    }
    true
}

// ------------------------------------------------------------------ the hook

const HOOK_BEGIN: &str = "# >>> oxaudit secrets scan >>>";
const HOOK_END: &str = "# <<< oxaudit secrets scan <<<";
const HOOK_COMMAND: &str = "oxaudit-cli scan --staged --quiet";
const SHEBANG: &str = "#!/bin/sh";

pub(super) fn run_hook(command: &HookCommand) -> CliResult {
    let cwd = std::env::current_dir().map_err(|error| failure(error.to_string()))?;
    let root = crate::git_context::repo_root(&cwd).map_err(|_| {
        failure("`oxaudit hook` must run inside a git repository; no checkout found from the current directory")
    })?;
    match command {
        HookCommand::Install => {
            let path = install_hook(&root)?;
            println!("Installed `{HOOK_COMMAND}` in {}", path.display());
        }
        HookCommand::Uninstall => {
            if uninstall_hook(&root)? {
                println!("Removed the oxaudit block from the pre-commit hook.");
            } else {
                println!("No oxaudit block in the pre-commit hook; nothing to remove.");
            }
        }
        HookCommand::Status => {
            let (path, installed) = hook_status(&root)?;
            if installed {
                println!("Installed: {} runs `{HOOK_COMMAND}`", path.display());
            } else {
                println!("Not installed: no oxaudit block in {}", path.display());
            }
        }
    }
    Ok(EXIT_OK)
}

fn managed_block() -> String {
    format!(
        "{HOOK_BEGIN}\n# Managed by `oxaudit hook install`; edit outside the markers.\nexec {HOOK_COMMAND}\n{HOOK_END}\n"
    )
}

/// The pre-commit hook path: the common git dir's hooks/pre-commit. Resolved
/// through git so linked worktrees land in the shared hooks directory. A
/// repo-configured core.hooksPath is deliberately not honored — oxAudit's own
/// git invocations neutralize hooks paths, and the installer manages the
/// standard location.
fn hook_path(root: &Path) -> Result<PathBuf, CliError> {
    let bytes = git_output(root, &["rev-parse", "--git-common-dir"])?;
    let text = String::from_utf8(bytes).map_err(|_| failure(UNAVAILABLE))?;
    let text = text.trim();
    if text.is_empty() || text.starts_with('-') {
        return Err(failure(UNAVAILABLE));
    }
    let git_dir = PathBuf::from(text);
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        root.join(git_dir)
    };
    Ok(git_dir.join("hooks").join("pre-commit"))
}

/// Byte span of the managed block, extended to whole lines. None when the
/// markers are absent or out of order.
fn managed_block_span(content: &str) -> Option<(usize, usize)> {
    let begin = content.find(HOOK_BEGIN)?;
    let end = content[begin..].find(HOOK_END)? + begin + HOOK_END.len();
    let start = content[..begin].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let stop = content[end..]
        .find('\n')
        .map(|i| end + i + 1)
        .unwrap_or(content.len());
    Some((start, stop))
}

fn install_hook(root: &Path) -> Result<PathBuf, CliError> {
    let path = hook_path(root)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(failure(format!("cannot read {}: {error}", path.display())));
        }
    };
    let block = managed_block();
    let content = match existing {
        // Refresh in place: replace the managed block, keep everything else.
        Some(content) if content.contains(HOOK_BEGIN) => {
            let (start, stop) = managed_block_span(&content).ok_or_else(|| {
                failure(format!(
                    "the oxaudit markers in {} are malformed; edit the hook by hand",
                    path.display()
                ))
            })?;
            let mut refreshed = String::with_capacity(content.len() + block.len());
            refreshed.push_str(&content[..start]);
            refreshed.push_str(&block);
            refreshed.push_str(&content[stop..]);
            refreshed
        }
        // An empty hook file gets the full skeleton, like an absent one.
        Some(content) if content.trim().is_empty() => format!("{SHEBANG}\n{block}"),
        // An existing hook is the user's: append our block after it.
        Some(mut content) => {
            if !content.ends_with('\n') {
                content.push('\n');
            }
            content.push('\n');
            content.push_str(&block);
            content
        }
        None => format!("{SHEBANG}\n{block}"),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| failure(format!("cannot create {}: {error}", parent.display())))?;
    }
    std::fs::write(&path, content)
        .map_err(|error| failure(format!("cannot write {}: {error}", path.display())))?;
    make_executable(&path)?;
    Ok(path)
}

/// Remove only the managed block; delete the hook file when nothing but the
/// shebang remains. Returns whether a managed block was present.
fn uninstall_hook(root: &Path) -> Result<bool, CliError> {
    let path = hook_path(root)?;
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(failure(format!("cannot read {}: {error}", path.display())));
        }
    };
    let Some((start, stop)) = managed_block_span(&content) else {
        return Ok(false);
    };
    let mut remaining = String::with_capacity(content.len());
    remaining.push_str(&content[..start]);
    remaining.push_str(&content[stop..]);
    let trimmed = remaining.trim();
    if trimmed.is_empty() || trimmed == SHEBANG {
        std::fs::remove_file(&path)
            .map_err(|error| failure(format!("cannot remove {}: {error}", path.display())))?;
    } else {
        std::fs::write(&path, remaining)
            .map_err(|error| failure(format!("cannot write {}: {error}", path.display())))?;
    }
    Ok(true)
}

fn hook_status(root: &Path) -> Result<(PathBuf, bool), CliError> {
    let path = hook_path(root)?;
    let installed = match std::fs::read_to_string(&path) {
        Ok(content) => managed_block_span(&content).is_some(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(failure(format!("cannot read {}: {error}", path.display())));
        }
    };
    Ok((path, installed))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(|error| {
        failure(format!(
            "cannot make {} executable: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn repository() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| crate::git_context::tests::git(root.path(), args);
        git(&["init", "-b", "main"]);
        git(&["config", "user.email", "staged@example.invalid"]);
        git(&["config", "user.name", "Staged fixture"]);
        root
    }

    #[test]
    fn a_staged_secret_is_found_and_gates_high_by_default() {
        let root = repository();
        let git = |args: &[&str]| crate::git_context::tests::git(root.path(), args);
        std::fs::write(
            root.path().join(".env"),
            "AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n",
        )
        .unwrap();
        git(&["add", ".env"]);
        let report = root.path().join("staged.json");
        let cli = super::super::Cli::try_parse_from([
            "oxaudit",
            "scan",
            root.path().to_str().unwrap(),
            "--staged",
            "--format",
            "json",
            "--output",
            report.to_str().unwrap(),
        ])
        .expect("staged flags parse");
        let super::super::Command::Scan(args) = &cli.command else {
            panic!("scan command expected");
        };
        assert_eq!(
            super::super::run_scan(args, true).unwrap(),
            super::super::EXIT_FINDINGS
        );
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["filePath"], ".env");
        assert_eq!(findings[0]["line"], 1);
        assert_eq!(json["summary"]["totalFindings"], 1);
        assert_eq!(json["summary"]["high"], 1);
        // The staged content, not a report, may hold the credential.
        assert!(!json.to_string().contains("AKIAZ9X8W7U6T5S4R3Q2"));
    }

    #[test]
    fn an_empty_stage_and_a_non_repository_pass_quietly() {
        let root = repository();
        let cli = super::super::Cli::try_parse_from([
            "oxaudit",
            "scan",
            root.path().to_str().unwrap(),
            "--staged",
        ])
        .expect("staged flags parse");
        let super::super::Command::Scan(args) = &cli.command else {
            panic!("scan command expected");
        };
        assert_eq!(super::super::run_scan(args, true).unwrap(), EXIT_OK);

        let plain = tempfile::tempdir().unwrap();
        let cli = super::super::Cli::try_parse_from([
            "oxaudit",
            "scan",
            plain.path().to_str().unwrap(),
            "--staged",
        ])
        .expect("staged flags parse");
        let super::super::Command::Scan(args) = &cli.command else {
            panic!("scan command expected");
        };
        assert_eq!(super::super::run_scan(args, true).unwrap(), EXIT_OK);
    }

    #[test]
    fn staged_mode_refuses_storage_dependent_combinations() {
        let cli =
            super::super::Cli::try_parse_from(["oxaudit", "scan", "--staged", "--format", "sarif"])
                .expect("--staged makes the path optional");
        let super::super::Command::Scan(args) = &cli.command else {
            panic!("scan command expected");
        };
        assert!(args.path.is_none());
        let error = super::super::run_scan(args, true).expect_err("sarif needs a stored run");
        assert_eq!(error.exit_code, super::super::EXIT_USAGE);
        assert!(error.message.contains("--staged"), "{}", error.message);
    }

    #[test]
    fn hook_install_refresh_and_uninstall_roundtrip() {
        let root = repository();
        let path = install_hook(root.path()).expect("install succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("#!/bin/sh\n"));
        assert!(content.contains(HOOK_BEGIN));
        assert!(content.contains(&format!("exec {HOOK_COMMAND}")));
        assert!(content.contains(HOOK_END));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }

        // Re-install refreshes in place: identical content, one block.
        install_hook(root.path()).expect("reinstall succeeds");
        let refreshed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(refreshed, content);
        assert_eq!(refreshed.matches(HOOK_BEGIN).count(), 1);

        let (status_path, installed) = hook_status(root.path()).unwrap();
        assert_eq!(status_path, path);
        assert!(installed);

        // Only the shebang remained, so uninstall deletes the file.
        assert!(uninstall_hook(root.path()).expect("uninstall succeeds"));
        assert!(!path.exists());
        assert!(!uninstall_hook(root.path()).expect("uninstall is idempotent"));
        let (_, installed) = hook_status(root.path()).unwrap();
        assert!(!installed);
    }

    #[test]
    fn hook_install_preserves_an_existing_hook() {
        let root = repository();
        let path = root.path().join(".git/hooks/pre-commit");
        std::fs::write(&path, "#!/bin/sh\necho user-hook\n").unwrap();
        install_hook(root.path()).expect("install appends");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("#!/bin/sh\necho user-hook\n"));
        assert!(content.contains(HOOK_BEGIN));

        assert!(uninstall_hook(root.path()).expect("uninstall succeeds"));
        // The user's hook survives; only our block is gone.
        let remaining = std::fs::read_to_string(&path).unwrap();
        assert_eq!(remaining, "#!/bin/sh\necho user-hook\n\n");
        assert!(!remaining.contains(HOOK_BEGIN));
    }
}

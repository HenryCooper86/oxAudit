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
    if args.baseline.is_some() || args.fail_on_new.is_some_and(|gate| gate != FailOn::None) {
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

    // The config is read before anything is scanned or written: an invalid
    // one must not leave a report behind.
    let config = super::load_config(&root, args.no_config)?;
    let merged = super::merge_scan(
        args,
        config.as_ref().map(|config| &config.scan),
        FailOn::High,
        true,
    )?;
    let notice = super::config_notice(&merged.from_config);
    if let Some(notice) = &notice {
        eprintln!("{notice}");
    }

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
    let mut step_summary = render_summary_markdown(&summary, &findings);
    if let Some(notice) = &notice {
        step_summary.push_str(&format!("\n{notice}\n"));
    }
    write_step_summary(&step_summary, quiet);

    // Secrets fire at high severity, so a staged scan gates on high unless
    // the caller (or the repository's config) deliberately asked otherwise.
    let fail_on = merged.fail_on;
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
            let hooks_path = configured_hooks_path(&root, global_hooks_path);
            let path = install_hook_with(&root, hooks_path.as_deref())?;
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
            let hooks_path = configured_hooks_path(&root, global_hooks_path);
            println!("{}", describe_hook_status(&root, hooks_path.as_deref())?);
        }
    }
    Ok(EXIT_OK)
}

fn managed_block() -> String {
    format!(
        "{HOOK_BEGIN}\n# Managed by `oxaudit hook install`; edit outside the markers.\n{HOOK_COMMAND} || exit $?\n{HOOK_END}\n"
    )
}

/// The pre-commit hook path: the common git dir's hooks/pre-commit. Resolved
/// through git so linked worktrees land in the shared hooks directory. The
/// installer never writes into a configured core.hooksPath directory, which
/// a hook manager owns; it refuses instead (see `configured_hooks_path`).
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

/// The `core.hooksPath` git would use for this repository: the repository's
/// own setting, else `global` (the user's global setting in production).
///
/// When it is set, git runs hooks from that directory and never from
/// `.git/hooks`, so a block installed there would never run. Hook managers
/// such as husky set it.
fn configured_hooks_path(root: &Path, global: impl FnOnce() -> Option<String>) -> Option<String> {
    // Every scope git reads, nearest first: worktree, local, the user's
    // global config (injected, so tests do not depend on the machine), then
    // system — each with `include` files followed.
    let scope = |flag: &str| {
        git_output(
            root,
            &["config", flag, "--includes", "--get", "core.hooksPath"],
        )
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
    };
    scope("--worktree")
        .or_else(|| scope("--local"))
        .or_else(global)
        .or_else(|| scope("--system"))
        .filter(|hooks_path| !names_standard_hooks_dir(root, hooks_path))
}

/// Whether a configured hooks path is the standard hooks directory itself,
/// where the installer writes anyway. Relative paths resolve from the
/// worktree root, as git resolves them; `~/` from the home directory.
fn names_standard_hooks_dir(root: &Path, hooks_path: &str) -> bool {
    let configured = match hooks_path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => return false,
        },
        None => root.join(hooks_path),
    };
    let Some(standard) = hook_path(root)
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return false;
    };
    match (configured.canonicalize(), standard.canonicalize()) {
        (Ok(configured), Ok(standard)) => configured == standard,
        _ => false,
    }
}

/// The user's global `core.hooksPath`. Read-only `git config` query with the
/// user's own environment, since the hardened git command deliberately hides
/// global configuration.
fn global_hooks_path() -> Option<String> {
    let output = std::process::Command::new("git")
        .args([
            "config",
            "--global",
            "--includes",
            "--get",
            "core.hooksPath",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn describe_hook_status(root: &Path, hooks_path: Option<&str>) -> Result<String, CliError> {
    let (path, installed) = hook_status(root)?;
    Ok(match hooks_path {
        Some(hooks_path) => format!(
            "Not active: core.hooksPath is {hooks_path}; git does not run {}{}",
            path.display(),
            if installed {
                " (it holds an oxaudit block that will not run)"
            } else {
                ""
            }
        ),
        None if installed => format!("Installed: {} runs `{HOOK_COMMAND}`", path.display()),
        None => format!("Not installed: no oxaudit block in {}", path.display()),
    })
}

/// Insert the managed block directly after the hook's shebang line (or at
/// the top when there is none), so it runs before the user's own hook, which
/// may end in `exec`.
fn with_block_first(content: &str, block: &str) -> String {
    // The block goes after the shebang and after the hook's environment
    // setup (comments, blank lines, `export`, plain assignments and `set`),
    // so a `PATH` the user sets is in place when `oxaudit-cli` runs — and
    // before the first command, so a hook that ends in `exec` cannot skip
    // it. A sourced file is a command: it can `exit` or `exec`.
    fn is_setup(line: &str) -> bool {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return true;
        }
        // A continued line, an open quote or a chained command is not plain
        // setup, whatever it starts with.
        if line.ends_with('\\') || line.contains([';', '&', '|']) || !quotes_close(line) {
            return false;
        }
        if line.starts_with("export ") || line.starts_with("set -") || line.starts_with("set +") {
            return true;
        }
        // `NAME=value` with nothing after it: an assignment, not a command.
        match line.split_once('=') {
            Some((name, value)) => {
                !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                    && !value.contains(char::is_whitespace)
            }
            None => false,
        }
    }
    fn quotes_close(line: &str) -> bool {
        let (mut single, mut double, mut escaped) = (false, false, false);
        for c in line.chars() {
            match c {
                _ if escaped => escaped = false,
                '\\' if !single => escaped = true,
                '\'' if !double => single = !single,
                '"' if !single => double = !double,
                _ => {}
            }
        }
        !single && !double
    }
    let mut split = 0;
    let mut first_line = true;
    for line in content.split_inclusive('\n') {
        let shebang = first_line && line.starts_with("#!");
        first_line = false;
        if !shebang && !is_setup(line) {
            break;
        }
        split += line.len();
    }
    let (head, rest) = content.split_at(split);
    let mut out = String::with_capacity(content.len() + block.len() + 1);
    out.push_str(head);
    if !head.is_empty() && !head.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(block);
    out.push_str(rest);
    out
}

fn install_hook_with(root: &Path, hooks_path: Option<&str>) -> Result<PathBuf, CliError> {
    let path = hook_path(root)?;
    if let Some(hooks_path) = hooks_path {
        return Err(failure(format!(
            "core.hooksPath is set to {hooks_path}, so git runs hooks from there and never \
             from {}. Add `{HOOK_COMMAND}` to the pre-commit hook in {hooks_path} instead \
             (for husky: .husky/pre-commit).",
            path.display()
        )));
    }
    let existing = match std::fs::read_to_string(&path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(failure(format!("cannot read {}: {error}", path.display())));
        }
    };
    let block = managed_block();
    let content = match existing {
        // Refresh: take the old block out wherever it sits (earlier releases
        // appended it after the user's hook) and put it back first.
        Some(content) if content.contains(HOOK_BEGIN) => {
            let (start, stop) = managed_block_span(&content).ok_or_else(|| {
                failure(format!(
                    "the oxaudit markers in {} are malformed; edit the hook by hand",
                    path.display()
                ))
            })?;
            let mut rest = String::with_capacity(content.len());
            rest.push_str(&content[..start]);
            rest.push_str(&content[stop..]);
            // The old append left one blank separator line behind it.
            if stop == content.len() && rest.ends_with("\n\n") {
                rest.pop();
            }
            with_block_first(&rest, &block)
        }
        // An empty hook file gets the full skeleton, like an absent one.
        Some(content) if content.trim().is_empty() => format!("{SHEBANG}\n{block}"),
        // An existing hook is the user's: our block goes first, theirs after.
        Some(content) => with_block_first(&content, &block),
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
    fn staged_scans_take_the_gate_from_config() {
        let root = repository();
        let git = |args: &[&str]| crate::git_context::tests::git(root.path(), args);
        std::fs::write(
            root.path().join(".env"),
            "AWS_ACCESS_KEY_ID=AKIAZ9X8W7U6T5S4R3Q2\n",
        )
        .unwrap();
        git(&["add", ".env"]);
        std::fs::create_dir_all(root.path().join(".oxaudit")).unwrap();
        std::fs::write(
            root.path().join(".oxaudit/config.toml"),
            "version = 1\n[scan]\nfail_on = \"critical\"\n",
        )
        .unwrap();
        let scan = |extra: &[&str]| {
            let mut argv = vec![
                "oxaudit",
                "scan",
                root.path().to_str().unwrap(),
                "--staged",
                "--quiet",
            ];
            argv.extend_from_slice(extra);
            let cli = super::super::Cli::try_parse_from(argv).expect("staged flags parse");
            let super::super::Command::Scan(args) = &cli.command else {
                panic!("scan command expected");
            };
            super::super::run_scan(args, true).unwrap()
        };
        // The high-severity secret no longer reaches the configured gate…
        assert_eq!(scan(&[]), super::super::EXIT_OK);
        // …a flag still wins over the config…
        assert_eq!(scan(&["--fail-on", "high"]), super::super::EXIT_FINDINGS);
        // …and --no-config restores the staged default of high.
        assert_eq!(scan(&["--no-config"]), super::super::EXIT_FINDINGS);
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

    /// Install as `hook install` does, ignoring the developer's own global
    /// git config so the tests are hermetic.
    fn install(root: &std::path::Path) -> Result<std::path::PathBuf, CliError> {
        install_hook_with(root, configured_hooks_path(root, || None).as_deref())
    }

    fn status(root: &std::path::Path) -> String {
        describe_hook_status(root, configured_hooks_path(root, || None).as_deref()).unwrap()
    }

    #[test]
    fn hook_install_refresh_and_uninstall_roundtrip() {
        let root = repository();
        let path = install(root.path()).expect("install succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("#!/bin/sh\n"));
        assert!(content.contains(HOOK_BEGIN));
        assert!(content.contains(&format!("{HOOK_COMMAND} || exit $?")));
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
        install(root.path()).expect("reinstall succeeds");
        let refreshed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(refreshed, content);
        assert_eq!(refreshed.matches(HOOK_BEGIN).count(), 1);

        assert!(status(root.path()).starts_with("Installed: "));

        // Only the shebang remained, so uninstall deletes the file.
        assert!(uninstall_hook(root.path()).expect("uninstall succeeds"));
        assert!(!path.exists());
        assert!(!uninstall_hook(root.path()).expect("uninstall is idempotent"));
        assert!(status(root.path()).starts_with("Not installed: "));
    }

    #[test]
    fn hook_install_preserves_an_existing_hook() {
        let root = repository();
        let path = root.path().join(".git/hooks/pre-commit");
        let original = "#!/bin/sh\necho user-hook\n";
        std::fs::write(&path, original).unwrap();
        install(root.path()).expect("install succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo user-hook\n"));
        assert!(content.contains(HOOK_BEGIN));

        assert!(uninstall_hook(root.path()).expect("uninstall succeeds"));
        // The user's hook survives byte for byte; only our block is gone.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn the_block_is_placed_after_the_user_s_environment_setup() {
        let content = "#!/bin/sh\n# Tools live in ~/bin\nexport PATH=\"$HOME/bin:$PATH\"\nNODE_OPTIONS=--max-old-space-size=4096\nset -e\n\nnpm test\nexec npx lint-staged\n";
        let placed = with_block_first(content, "BLOCK\n");
        let block = placed.find("BLOCK").unwrap();
        assert!(block > placed.find("set -e").unwrap(), "{placed}");
        assert!(block < placed.find("npm test").unwrap(), "{placed}");
        // A sourced file is arbitrary code that can `exit` or `exec`, and a
        // line that continues, leaves a quote open or chains a command is
        // not plain setup: the block goes before each of them.
        for user in [
            ". \"$(dirname \"$0\")/husky.sh\"\n",
            "source ~/.hookrc\n",
            "export X=1; exec y\n",
            "export X=1 && exec y\n",
            "X=1 || exec y\n",
            "export X=1 | y\n",
            "export X=1 \\\n  exec y\n",
            "MSG=\"first\nexec y\"\n",
        ] {
            let content = format!("#!/bin/sh\nexport PATH=/opt/bin:$PATH\n{user}");
            assert_eq!(
                with_block_first(&content, "BLOCK\n"),
                format!("#!/bin/sh\nexport PATH=/opt/bin:$PATH\nBLOCK\n{user}"),
                "{user:?}"
            );
        }
        // Without setup lines, the block still goes right after the shebang.
        assert_eq!(
            with_block_first("#!/bin/sh\nexec x\n", "BLOCK\n"),
            "#!/bin/sh\nBLOCK\nexec x\n"
        );
    }

    #[test]
    fn a_hooks_path_from_an_included_config_is_honoured() {
        let root = repository();
        let included = root.path().join("shared.gitconfig");
        std::fs::write(&included, "[core]\n\thooksPath = .shared-hooks\n").unwrap();
        crate::git_context::tests::git(
            root.path(),
            &["config", "include.path", included.to_str().unwrap()],
        );
        assert_eq!(
            configured_hooks_path(root.path(), || None).as_deref(),
            Some(".shared-hooks")
        );
    }

    #[test]
    fn hook_block_runs_before_a_user_hook_that_execs() {
        let root = repository();
        let path = root.path().join(".git/hooks/pre-commit");
        std::fs::write(&path, "#!/bin/sh\nexec npx lint-staged\n").unwrap();
        install(root.path()).expect("install succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        let block = content.find(HOOK_BEGIN).expect("block present");
        let user = content
            .find("exec npx lint-staged")
            .expect("user hook kept");
        assert!(content.starts_with("#!/bin/sh\n"), "{content}");
        assert!(block < user, "{content}");
    }

    #[test]
    fn managed_block_does_not_exec() {
        let block = managed_block();
        assert!(
            block.contains(&format!("{HOOK_COMMAND} || exit $?")),
            "{block}"
        );
        assert!(!block.contains("exec "), "{block}");
    }

    #[test]
    fn reinstall_moves_an_appended_block_above_the_user_hook() {
        let root = repository();
        let path = root.path().join(".git/hooks/pre-commit");
        // What earlier releases wrote: the block appended after the user's
        // hook, where its `exec` line means the block never runs.
        std::fs::write(
            &path,
            format!("#!/bin/sh\nexec npx lint-staged\n\n{HOOK_BEGIN}\n# Managed by `oxaudit hook install`; edit outside the markers.\nexec {HOOK_COMMAND}\n{HOOK_END}\n"),
        )
        .unwrap();
        install(root.path()).expect("reinstall succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches(HOOK_BEGIN).count(), 1);
        assert!(
            content.find(HOOK_BEGIN).unwrap() < content.find("exec npx lint-staged").unwrap(),
            "{content}"
        );
        assert!(
            !content.contains(&format!("exec {HOOK_COMMAND}")),
            "{content}"
        );
    }

    #[test]
    fn install_refuses_when_core_hooks_path_is_set() {
        let root = repository();
        crate::git_context::tests::git(root.path(), &["config", "core.hooksPath", ".husky"]);
        let error = install(root.path()).expect_err("git would never run .git/hooks");
        assert!(error.message.contains(".husky"), "{}", error.message);
        assert!(error.message.contains(HOOK_COMMAND), "{}", error.message);
        assert!(!root.path().join(".git/hooks/pre-commit").exists());
    }

    #[test]
    fn status_reports_inactive_under_core_hooks_path() {
        let root = repository();
        crate::git_context::tests::git(root.path(), &["config", "core.hooksPath", ".husky"]);
        let message = status(root.path());
        assert!(
            message.starts_with("Not active: core.hooksPath is .husky"),
            "{message}"
        );
    }

    #[test]
    fn a_global_hooks_path_is_honoured_when_no_local_one_is_set() {
        let root = repository();
        assert_eq!(
            configured_hooks_path(root.path(), || Some("~/.githooks".into())).as_deref(),
            Some("~/.githooks")
        );
        crate::git_context::tests::git(root.path(), &["config", "core.hooksPath", ".husky"]);
        assert_eq!(
            configured_hooks_path(root.path(), || Some("~/.githooks".into())).as_deref(),
            Some(".husky")
        );
    }

    #[test]
    fn a_hooks_path_naming_the_standard_directory_is_not_refused() {
        let root = repository();
        crate::git_context::tests::git(root.path(), &["config", "core.hooksPath", ".git/hooks"]);
        install(root.path()).expect("the configured path is where we install");
        assert!(status(root.path()).starts_with("Installed: "));
    }
}

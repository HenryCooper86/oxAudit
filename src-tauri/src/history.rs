//! Git-history secret scanning.
//!
//! The working-tree scanner answers "what is in the project now?" This module
//! answers the incident-response question: *was this credential ever
//! committed?* — including in files deleted long ago. A key removed from the
//! working tree is still live until rotated and purged from history, and the
//! first step of that response is seeing the leak at all.
//!
//! What it covers, stated because it bounds what the result means:
//!
//! - **Objects reachable from refs.** `git rev-list --all --objects` walks
//!   commits, branches, tags, and remote refs. Dangling objects reachable from
//!   nothing are not enumerated; `git fsck --lost-found` is the tool for those.
//! - **One entry per distinct blob.** The same content at the same or different
//!   paths across many commits is one object and one set of findings, reported
//!   at the first path git enumerates. Which commit introduced it is not
//!   computed: `--find-object` per blob is prohibitively expensive on real
//!   histories, and "rotate, then purge" does not need it.
//! - **Text blobs only, at the text tier.** Non-UTF-8 content is skipped, and
//!   unlike the working-tree scanner there is no grammar parse, so a credential
//!   inside a comment is still reported — history scanning errs toward recall.
//!   Findings keep plain repository-relative paths, so fingerprints match the
//!   same leak seen by a working-tree scan and policy suppressions apply.
//! - **Bounded work.** Blob count, per-blob size, total scanned bytes, output
//!   size, and wall clock all have budgets; exceeding any of them keeps the
//!   findings already collected and reports `truncated` with the reason. A
//!   history that silently stopped early would be worse than one that says so.
//!
//! Like every other git surface in oxAudit, inspection is read-only plumbing
//! over a cleared environment: no hooks, no network, no filters, no index
//! writes.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::git_context::hardened_git_command;
use crate::models::Finding;

/// Candidates from `rev-list --objects` output. Large histories produce large
/// listings; past this the enumeration itself is refused rather than truncated
/// mid-parse, because a partial object list cannot be distinguished from a
/// complete one by the caller.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;
/// Unique blobs considered. Mirrors the working-tree path budget.
const MAX_BLOBS: usize = 100_000;
/// Per-blob cap; the same default the working-tree CLI gives `--max-file-size`.
const MAX_BLOB_BYTES: u64 = 1024 * 1024;
/// Total scanned text across the whole history before the scan stops early.
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Findings kept before the scan stops early. A history with more leaked
/// credentials than this is an incident with bigger problems than the count.
const MAX_FINDINGS: usize = 10_000;
/// Wall clock for the whole scan, shared by every git invocation.
const TIMEOUT: Duration = Duration::from_secs(120);

const UNAVAILABLE: &str = "Git history unavailable: not a git repository, unsupported git version, or enumeration failed. Working-tree scans remain available.";

/// One blob's content read from `cat-file --batch`, with the repository path
/// git associated with the object.
struct HistoryBlob {
    path: String,
    bytes: Vec<u8>,
}

/// What a history scan found, and how completely it looked.
#[derive(Debug)]
pub struct HistoryScanOutcome {
    pub findings: Vec<Finding>,
    /// Distinct blobs whose content was scanned.
    pub blobs_scanned: usize,
    /// Blobs skipped: non-UTF-8, non-blob objects at a path (trees), or
    /// C-quoted non-straightforward names.
    pub blobs_skipped: usize,
    /// True when a budget stopped the scan early. Findings collected so far
    /// are returned, never discarded.
    pub truncated: bool,
    pub limit_note: Option<String>,
}

/// Scan every blob reachable from any ref for leaked credentials.
pub fn scan_history_secrets(root: &Path) -> Result<HistoryScanOutcome, String> {
    let target = root.canonicalize().map_err(|_| UNAVAILABLE.to_owned())?;
    if !target.is_dir() {
        return Err(UNAVAILABLE.into());
    }
    let deadline = Instant::now() + TIMEOUT;

    let mut outcome = scan_history_secrets_bounded(&target, deadline)?;
    let note = outcome.limit_note.take();
    dedupe_revisions(&mut outcome.findings);
    crate::findings::fingerprint::assign_fingerprints(&mut outcome.findings);
    outcome.limit_note = note;
    Ok(outcome)
}

/// Collapse the same leak seen in successive revisions of one file.
///
/// Distinct blobs are scanned distinctly, so a credential that survives while
/// the file around it is edited — including edits that move it to another
/// line — produces one finding per place it appears. For the question this
/// scanner answers — *was this credential ever committed here?* — those are
/// one leak, not several: the response is one rotation and one history purge.
/// A different credential, or the same credential in a different file, stays
/// distinct.
fn dedupe_revisions(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::<(String, String, String)>::new();
    findings.retain(|finding| {
        seen.insert((
            finding.rule_id.clone(),
            finding.file_path.clone(),
            finding.match_text.clone(),
        ))
    });
}

fn scan_history_secrets_bounded(
    target: &Path,
    deadline: Instant,
) -> Result<HistoryScanOutcome, String> {
    let candidates = enumerate_history_blobs(target, deadline)?;
    let mut truncated_note = candidates.truncation_note;

    // rev-list lists each distinct object once, but defensive dedup costs
    // nothing and guarantees the writer never feeds a duplicate.
    let mut seen = HashSet::new();
    let by_oid: HashMap<String, String> = candidates
        .entries
        .into_iter()
        .filter(|(oid, _)| seen.insert(oid.clone()))
        .collect();

    let (mut child, receiver) = spawn_batch_reader(target, &by_oid, deadline)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut blobs_scanned = 0usize;
    let mut blobs_skipped = candidates.skipped_count;
    let mut total_bytes = 0u64;

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        let blob = match receiver.recv_timeout(remaining.max(Duration::from_millis(1))) {
            Ok(blob) => blob,
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                truncated_note.get_or_insert_with(|| "time budget reached".to_owned());
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let text = match String::from_utf8(blob.bytes) {
            Ok(text) => text,
            Err(_) => {
                blobs_skipped += 1;
                continue;
            }
        };
        let byte_count = text.len() as u64;
        if total_bytes + byte_count > MAX_TOTAL_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            truncated_note.get_or_insert_with(|| "total scanned-bytes budget reached".to_owned());
            break;
        }
        total_bytes += byte_count;
        blobs_scanned += 1;
        match crate::scanners::scan_text_for_secrets(&text, &blob.path, usize::MAX) {
            Some(mut found) => {
                findings.append(&mut found);
                if findings.len() >= MAX_FINDINGS {
                    let _ = child.kill();
                    let _ = child.wait();
                    truncated_note
                        .get_or_insert_with(|| format!("finding budget of {MAX_FINDINGS} reached"));
                    break;
                }
            }
            // A single blob overflowing the per-content limit is the same
            // condition a working-tree scan reports as a per-file limit error;
            // counting it as skipped keeps the run honest without discarding
            // every other blob's findings.
            None => blobs_skipped += 1,
        }
    }
    let _ = child.wait();

    Ok(HistoryScanOutcome {
        findings,
        blobs_scanned,
        blobs_skipped,
        truncated: truncated_note.is_some(),
        limit_note: truncated_note,
    })
}

struct Enumeration {
    entries: Vec<(String, String)>,
    skipped_count: usize,
    truncation_note: Option<String>,
}

/// `git rev-list --all --objects --filter=blob:limit=<n>` — one line per
/// object, `<oid> <path>` where a path exists. Commits and root trees print
/// without paths and are dropped here; subtrees and blobs carry paths and are
/// separated later by object type from the `cat-file --batch` header.
fn enumerate_history_blobs(target: &Path, deadline: Instant) -> Result<Enumeration, String> {
    let filter = format!("--filter=blob:limit={MAX_BLOB_BYTES}");
    let mut command = hardened_git_command(target);
    command
        .arg("rev-list")
        .args(["--all", "--objects"])
        .arg(&filter)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| UNAVAILABLE.to_owned())?;
    let stdout = child.stdout.take().ok_or(UNAVAILABLE)?;
    // A bounded reader drains concurrently so pipe capacity cannot deadlock.
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_LIST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = wait_with_deadline(&mut child, deadline)?;
    let bytes = reader
        .join()
        .map_err(|_| UNAVAILABLE)?
        .map_err(|_| UNAVAILABLE)?;
    if !status.is_some_and(|status| status.success()) || bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(UNAVAILABLE.into());
    }

    let mut entries = Vec::new();
    let mut skipped = 0usize;
    let mut truncated = None;
    for line in String::from_utf8_lossy(&bytes).lines() {
        let Some((oid, path)) = line.split_once(' ') else {
            continue;
        };
        let oid = oid.trim();
        let path = path.trim();
        if oid.len() < 40 || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if path.is_empty() {
            continue;
        }
        // rev-list C-quotes any name that is not straightforward UTF-8 text;
        // those entries keep their quoted form and are not scanned rather than
        // reported under an invented path.
        if path.starts_with('"') {
            skipped += 1;
            continue;
        }
        if entries.len() >= MAX_BLOBS {
            truncated.get_or_insert_with(|| {
                format!("object budget of {MAX_BLOBS} distinct paths reached")
            });
            break;
        }
        entries.push((oid.to_owned(), path.to_owned()));
    }
    Ok(Enumeration {
        entries,
        skipped_count: skipped,
        truncation_note: truncated,
    })
}

/// Spawn `git cat-file --batch` with a writer thread feeding every candidate
/// oid and a reader thread parsing the response stream into whole blobs.
///
/// The reader enforces the protocol (header, exactly `size` bytes, LF) so the
/// stream can never desynchronize; the main thread enforces budgets and kills
/// the child on expiry, which ends both threads through closed pipes.
fn spawn_batch_reader(
    target: &Path,
    by_oid: &HashMap<String, String>,
    deadline: Instant,
) -> Result<(Child, Receiver<HistoryBlob>), String> {
    let mut command = hardened_git_command(target);
    command
        .arg("cat-file")
        .args(["--batch", "--buffer"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| UNAVAILABLE.to_owned())?;
    let stdin = child.stdin.take().ok_or(UNAVAILABLE)?;
    let stdout = child.stdout.take().ok_or(UNAVAILABLE)?;

    let oids: Vec<String> = by_oid.keys().cloned().collect();
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
    let (sender, receiver) = mpsc::channel::<HistoryBlob>();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut header = String::new();
            match stdout.read_line(&mut header) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let header = header.trim_end();
            let Some((oid, rest)) = header.split_once(' ') else {
                break;
            };
            // `<oid> missing` (gitlink commits from submodules) has no body.
            let Some((kind, size_text)) = rest.split_once(' ') else {
                continue;
            };
            let Ok(size) = size_text.parse::<u64>() else {
                continue;
            };
            if kind != "blob" || size > MAX_BLOB_BYTES {
                // Content plus the unconditional trailing LF, so the stream
                // stays aligned on the next header.
                if !drain(&mut stdout, size + 1) {
                    break;
                }
                continue;
            }
            let mut bytes = vec![0u8; size as usize];
            if stdout.read_exact(&mut bytes).is_err() {
                break;
            }
            if !drain(&mut stdout, 1) {
                break;
            }
            if let Some(path) = paths.get(oid) {
                if sender
                    .send(HistoryBlob {
                        path: path.clone(),
                        bytes,
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    // Both threads own their pipe ends; the join handles live in this scope
    // only so a spawn failure cannot leak a process. Killing the child (the
    // main thread's budget path) closes both pipes and ends both threads.
    let _ = (writer, reader, deadline);
    Ok((child, receiver))
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

fn wait_with_deadline(
    child: &mut Child,
    deadline: Instant,
) -> Result<Option<std::process::ExitStatus>, String> {
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    if status.is_none() {
        return Err(UNAVAILABLE.into());
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // The AWS access-key rule has no entropy floor or keyword requirement, so
    // a synthetic key fires without fighting the placeholder filter.
    const LEAKED_KEY: &str = "AKIAZ9X8W7U6T5S4R3Q2";

    fn git(root: &Path, args: &[&str]) {
        crate::git_context::tests::git(root, args);
    }

    fn repository_with_leak() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "main"]);
        git(
            temp.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(temp.path(), &["config", "user.name", "Test"]);
        fs::create_dir(temp.path().join("src")).unwrap();
        // Committed, then deleted: exactly the working-tree scan's blind spot.
        fs::write(
            temp.path().join("src/deploy.sh"),
            format!("#!/bin/sh\nexport AWS_ACCESS_KEY_ID={LEAKED_KEY}\n"),
        )
        .unwrap();
        fs::write(temp.path().join("src/app.js"), "console.log('clean');\n").unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "leak"]);
        fs::remove_file(temp.path().join("src/deploy.sh")).unwrap();
        git(temp.path(), &["add", "-A"]);
        git(temp.path(), &["commit", "-m", "remove leak"]);
        temp
    }

    #[test]
    fn deleted_secrets_remain_visible_in_history() {
        let temp = repository_with_leak();
        let outcome = scan_history_secrets(temp.path()).expect("history scan");

        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == "aws-access-key-id"
                    && finding.file_path == "src/deploy.sh"),
            "the deleted key must be reported at its historical path"
        );
        assert!(!outcome.truncated);
        assert!(outcome.blobs_scanned >= 2);

        // The leak itself never crosses the boundary: match text and context
        // are redacted exactly as a working-tree finding would be.
        for finding in &outcome.findings {
            assert!(!finding.match_text.contains(LEAKED_KEY));
            assert!(!finding.context.contains(LEAKED_KEY));
        }
    }

    #[test]
    fn a_directory_without_git_is_an_error_not_an_empty_answer() {
        let temp = tempfile::tempdir().unwrap();
        assert!(scan_history_secrets(temp.path()).is_err());
    }

    #[test]
    fn clean_history_reports_nothing_and_scans_blobs() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "main"]);
        git(
            temp.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(temp.path(), &["config", "user.name", "Test"]);
        fs::write(temp.path().join("README.md"), "nothing to see\n").unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "initial"]);
        let outcome = scan_history_secrets(temp.path()).expect("history scan");
        assert!(outcome.findings.is_empty());
        assert!(outcome.blobs_scanned >= 1);
        assert!(!outcome.truncated);
    }

    #[test]
    fn same_blob_under_two_paths_is_scanned_once() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "main"]);
        git(
            temp.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(temp.path(), &["config", "user.name", "Test"]);
        let content = format!("token={LEAKED_KEY}\n");
        fs::create_dir(temp.path().join("a")).unwrap();
        fs::write(temp.path().join("a/key.env"), &content).unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "first path"]);
        fs::create_dir(temp.path().join("b")).unwrap();
        fs::write(temp.path().join("b/key.env"), &content).unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "same content, second path"]);
        let outcome = scan_history_secrets(temp.path()).expect("history scan");
        let paths: Vec<&str> = outcome
            .findings
            .iter()
            .map(|finding| finding.file_path.as_str())
            .collect();
        assert_eq!(paths.len(), 1, "one distinct blob is one finding");
    }

    #[test]
    fn a_leak_surviving_edits_around_it_is_one_finding() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "main"]);
        git(
            temp.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(temp.path(), &["config", "user.name", "Test"]);
        let leak = format!("key = {LEAKED_KEY}\n");
        fs::write(temp.path().join("settings.py"), &leak).unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "leak"]);
        // Two further revisions of the same file, leak untouched: three
        // distinct blobs, one credential, one finding.
        fs::write(temp.path().join("settings.py"), format!("header()\n{leak}")).unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "edit above the leak"]);
        fs::write(
            temp.path().join("settings.py"),
            format!("header()\n{leak}footer()\n"),
        )
        .unwrap();
        git(temp.path(), &["add", "."]);
        git(temp.path(), &["commit", "-m", "edit below the leak"]);
        let outcome = scan_history_secrets(temp.path()).expect("history scan");
        assert!(
            outcome.blobs_scanned >= 3,
            "three distinct blobs were scanned"
        );
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].file_path, "settings.py");
        // The reported position comes from the first revision enumerated, so
        // the line is whichever blob git listed first — not asserted, because
        // it legitimately varies with traversal order.
    }
}

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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
    oid: String,
    path: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryBlobEvidence {
    pub oid: String,
    pub path: String,
    pub size_bytes: u64,
    pub content_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryRef {
    pub name: String,
    pub oid: String,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryGitContext {
    pub head_before: Option<String>,
    pub head_after: Option<String>,
    pub refs_before: Vec<HistoryRef>,
    pub refs_after: Vec<HistoryRef>,
    pub refs_complete_after: bool,
    pub context_changed: Option<bool>,
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
    /// Raw credential values, present only when the caller asked for them so
    /// live validation can run. Never populated by the default scan: an
    /// ordinary history run never retains credential material.
    pub raw_secrets: Vec<crate::secrets_validation::RawSecret>,
    pub cancelled: bool,
    pub blobs: Vec<HistoryBlobEvidence>,
    pub finding_blob_ids: BTreeMap<String, String>,
    pub git_context: Option<HistoryGitContext>,
}

/// Scan every blob reachable from any ref for leaked credentials.
///
/// The same scan, with control over whether raw credential values are
/// retained for opt-in live validation.
#[cfg(test)]
pub fn scan_history_secrets_with_options(
    root: &Path,
    collect_raw_secrets: bool,
) -> Result<HistoryScanOutcome, String> {
    scan_history_secrets_cancellable(root, collect_raw_secrets, &AtomicBool::new(false))
}

pub fn scan_history_secrets_cancellable(
    root: &Path,
    collect_raw_secrets: bool,
    cancel: &AtomicBool,
) -> Result<HistoryScanOutcome, String> {
    check_cancel(cancel)?;
    let target = root.canonicalize().map_err(|_| UNAVAILABLE.to_owned())?;
    if !target.is_dir() {
        return Err(UNAVAILABLE.into());
    }
    let deadline = Instant::now() + TIMEOUT;

    let (head_before, refs_before) = read_context(&target, deadline, cancel)?;
    let mut outcome = scan_history_secrets_bounded(&target, deadline, collect_raw_secrets, cancel)?;
    let note = outcome.limit_note.take();
    dedupe_revisions(&mut outcome.findings);
    crate::findings::fingerprint::assign_fingerprints(&mut outcome.findings);
    let kept: HashSet<_> = outcome
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    outcome
        .finding_blob_ids
        .retain(|id, _| kept.contains(id.as_str()));
    outcome.limit_note = note;
    let after = read_context(&target, deadline, cancel);
    let (head_after, refs_after, refs_complete_after, context_changed) = match after {
        Ok((head, refs)) => {
            let changed = head != head_before || refs != refs_before;
            (head, refs, true, Some(changed))
        }
        Err(_) => {
            outcome.cancelled |= cancel.load(Ordering::SeqCst);
            outcome.truncated = true;
            outcome.limit_note.get_or_insert_with(|| {
                "Git context after scanning is unavailable; coverage cannot be verified".into()
            });
            (None, Vec::new(), false, None)
        }
    };
    if context_changed == Some(true) {
        outcome.truncated = true;
        outcome.limit_note.get_or_insert_with(|| {
            "Git refs changed during scanning; findings retain the inspected blob identities".into()
        });
    }
    outcome.git_context = Some(HistoryGitContext {
        head_before,
        head_after,
        refs_before,
        refs_after,
        refs_complete_after,
        context_changed,
    });
    Ok(outcome)
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) {
        Err("history scan cancelled".into())
    } else {
        Ok(())
    }
}

fn git_output(
    target: &Path,
    args: &[&str],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    check_cancel(cancel)?;
    let mut command = hardened_git_command(target);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| UNAVAILABLE.to_owned())?;
    let stdout = child.stdout.take().ok_or(UNAVAILABLE)?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_LIST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = wait_with_deadline(&mut child, deadline, cancel);
    let bytes = reader
        .join()
        .map_err(|_| UNAVAILABLE)?
        .map_err(|_| UNAVAILABLE)?;
    let status = status?;
    if !status.is_some_and(|status| status.success()) || bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(UNAVAILABLE.into());
    }
    Ok(bytes)
}

fn read_context(
    target: &Path,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(Option<String>, Vec<HistoryRef>), String> {
    let head = git_output(target, &["rev-parse", "--verify", "HEAD"], deadline, cancel)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned());
    check_cancel(cancel)?;
    let bytes = git_output(
        target,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
        deadline,
        cancel,
    )?;
    let refs = String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(oid, name)| HistoryRef {
            name: name.into(),
            oid: oid.into(),
        })
        .collect();
    Ok((head, refs))
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
    collect_raw_secrets: bool,
    cancel: &AtomicBool,
) -> Result<HistoryScanOutcome, String> {
    let candidates = enumerate_history_blobs(target, deadline, cancel)?;
    let mut truncated_note = candidates.truncation_note;

    // rev-list lists each distinct object once, but defensive dedup costs
    // nothing and guarantees the writer never feeds a duplicate.
    let mut seen = HashSet::new();
    let by_oid: HashMap<String, String> = candidates
        .entries
        .into_iter()
        .filter(|(oid, _)| seen.insert(oid.clone()))
        .collect();

    let mut batch = spawn_batch_reader(target, &by_oid)?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut raw_secrets: Vec<crate::secrets_validation::RawSecret> = Vec::new();
    let mut blobs_scanned = 0usize;
    let mut blobs_skipped = candidates.skipped_count;
    let mut total_bytes = 0u64;
    let mut cancelled = false;
    let mut blobs = Vec::new();
    let mut finding_blob_ids = BTreeMap::new();

    loop {
        if cancel.load(Ordering::SeqCst) {
            cancelled = true;
            truncated_note = Some("history scan cancelled".into());
            break;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        let blob = match batch
            .receiver
            .as_ref()
            .expect("history receiver exists")
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
            Ok(Err(error)) => return Err(error),
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
            collect_raw_secrets,
        ) {
            Some((mut found, mut raw)) => {
                blobs_scanned += 1;
                for finding in &found {
                    finding_blob_ids.insert(finding.id.clone(), blob.oid.clone());
                }
                use sha2::Digest;
                blobs.push(HistoryBlobEvidence {
                    oid: blob.oid,
                    path: blob.path,
                    size_bytes: byte_count,
                    content_sha256: format!("{:x}", sha2::Sha256::digest(text.as_bytes())),
                });
                findings.append(&mut found);
                raw_secrets.append(&mut raw);
                if findings.len() >= MAX_FINDINGS {
                    truncated_note
                        .get_or_insert_with(|| format!("finding budget of {MAX_FINDINGS} reached"));
                    break;
                }
            }
            // A single blob overflowing the per-content limit is the same
            // condition a working-tree scan reports as a per-file limit error;
            // counting it as skipped keeps the run honest without discarding
            // every other blob's findings.
            None => {
                blobs_skipped += 1;
                truncated_note.get_or_insert_with(|| {
                    "history finding allowance exceeded; earlier evidence retained".into()
                });
                break;
            }
        }
    }
    if truncated_note.is_none() {
        let status = wait_with_deadline(&mut batch.child, deadline, cancel)?;
        if !status.is_some_and(|status| status.success()) {
            return Err(UNAVAILABLE.into());
        }
    }

    Ok(HistoryScanOutcome {
        findings,
        blobs_scanned,
        blobs_skipped,
        truncated: truncated_note.is_some(),
        limit_note: truncated_note,
        raw_secrets,
        cancelled,
        blobs,
        finding_blob_ids,
        git_context: None,
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
fn enumerate_history_blobs(
    target: &Path,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Enumeration, String> {
    let filter = format!("--filter=blob:limit={MAX_BLOB_BYTES}");
    let bytes = git_output(
        target,
        &["rev-list", "--all", "--objects", &filter],
        deadline,
        cancel,
    )?;

    let mut entries = Vec::new();
    let mut skipped = 0usize;
    let mut truncated = None;
    for line in String::from_utf8_lossy(&bytes).lines() {
        let Some((oid, path)) = line.split_once(' ') else {
            continue;
        };
        let oid = oid.trim();
        // Spaces belong to Git's filename, including at either end. Trimming
        // this field would invent a different historical artifact location.
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
struct BatchReader {
    child: Child,
    receiver: Option<Receiver<Result<Option<HistoryBlob>, String>>>,
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
    target: &Path,
    by_oid: &HashMap<String, String>,
) -> Result<BatchReader, String> {
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
    let (sender, receiver) = mpsc::sync_channel::<Result<Option<HistoryBlob>, String>>(2);
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut header = String::new();
            match stdout.read_line(&mut header) {
                Ok(0) => break,
                Err(_) => {
                    let _ = sender.send(Err("Git history blob stream could not be read".into()));
                    break;
                }
                Ok(_) => {}
            }
            let header = header.trim_end();
            let Some((oid, rest)) = header.split_once(' ') else {
                let _ = sender.send(Err("Malformed Git history blob header".into()));
                break;
            };
            // `<oid> missing` (gitlink commits from submodules) has no body.
            let Some((kind, size_text)) = rest.split_once(' ') else {
                if sender.send(Ok(None)).is_err() {
                    break;
                }
                continue;
            };
            let Ok(size) = size_text.parse::<u64>() else {
                let _ = sender.send(Err("Malformed Git history blob size".into()));
                break;
            };
            if kind != "blob" || size > MAX_BLOB_BYTES {
                // Content plus the unconditional trailing LF, so the stream
                // stays aligned on the next header.
                if size
                    .checked_add(1)
                    .map_or(true, |size| !drain(&mut stdout, size))
                {
                    let _ = sender.send(Err("Incomplete Git history object body".into()));
                    break;
                }
                if sender.send(Ok(None)).is_err() {
                    break;
                }
                continue;
            }
            let mut bytes = vec![0u8; size as usize];
            if stdout.read_exact(&mut bytes).is_err() {
                let _ = sender.send(Err("Incomplete Git history blob body".into()));
                break;
            }
            if !drain(&mut stdout, 1) {
                let _ = sender.send(Err("Incomplete Git history blob terminator".into()));
                break;
            }
            if let Some(path) = paths.get(oid) {
                if sender
                    .send(Ok(Some(HistoryBlob {
                        oid: oid.into(),
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

    // Both threads own their pipe ends; the join handles live in this scope
    // only so a spawn failure cannot leak a process. Killing the child (the
    // main thread's budget path) closes both pipes and ends both threads.
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

fn wait_with_deadline(
    child: &mut Child,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Option<std::process::ExitStatus>, String> {
    let status = loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("history scan cancelled".into());
        }
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

    #[test]
    fn pre_cancelled_history_never_starts_git_work() {
        let root = repository_with_leak();
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        let error = scan_history_secrets_cancellable(root.path(), false, &cancelled).unwrap_err();
        assert!(error.contains("cancelled"));
    }

    #[test]
    #[cfg(unix)]
    fn cancellation_during_git_wait_kills_and_reaps_child_without_waiting_for_deadline() {
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let started = Instant::now();
        let error = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cancelled.store(true, Ordering::SeqCst);
            });
            wait_with_deadline(
                &mut child,
                Instant::now() + Duration::from_secs(3),
                &cancelled,
            )
            .unwrap_err()
        });
        assert!(error.contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn blob_reader_applies_backpressure_and_drop_releases_blocked_producer() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]);
        git(root.path(), &["config", "user.name", "History test"]);
        git(
            root.path(),
            &["config", "user.email", "history-test@example.invalid"],
        );
        for i in 0..8 {
            fs::write(
                root.path().join(format!("blob-{i}.txt")),
                format!("{i}\n{}", "inert fixture text\n".repeat(16000)),
            )
            .unwrap();
        }
        git(root.path(), &["add", "."]);
        git(
            root.path(),
            &["commit", "-m", "inert bounded queue fixture"],
        );
        let cancel = AtomicBool::new(false);
        let candidates = enumerate_history_blobs(
            root.path(),
            Instant::now() + Duration::from_secs(10),
            &cancel,
        )
        .unwrap();
        let mut batch =
            spawn_batch_reader(root.path(), &candidates.entries.into_iter().collect()).unwrap();
        std::thread::sleep(Duration::from_secs(1));
        assert!(
            batch.child.try_wait().unwrap().is_none(),
            "Git drained all blobs without a consumer; queue was not bounded"
        );
        let started = Instant::now();
        drop(batch);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "dropping a full queue failed to release the producer"
        );
    }

    #[test]
    fn a_blob_exceeding_finding_allowance_is_not_counted_as_covered() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]);
        git(root.path(), &["config", "user.name", "History test"]);
        git(
            root.path(),
            &["config", "user.email", "history-test@example.invalid"],
        );
        fs::write(
            root.path().join("too-many.txt"),
            format!("AWS_ACCESS_KEY_ID={LEAKED_KEY}\n").repeat(MAX_FINDINGS + 1),
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-m", "inert over-budget fixture"]);
        let outcome = scan_history_secrets_with_options(root.path(), false).unwrap();
        assert!(outcome.truncated);
        assert_eq!(
            outcome.blobs_scanned, 0,
            "a blob rejected by the allowance cannot be covered"
        );
        assert_eq!(outcome.blobs_skipped, 1);
        assert!(outcome.blobs.is_empty());
    }

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
        let outcome = scan_history_secrets_with_options(temp.path(), false).expect("history scan");

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
    #[cfg(unix)]
    fn historical_paths_preserve_filename_whitespace() {
        let root = repository_with_leak();
        let historical_path = " spaced.env ";
        fs::write(
            root.path().join(historical_path),
            format!("key={LEAKED_KEY}\n"),
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-m", "inert whitespace filename"]);
        let outcome = scan_history_secrets_with_options(root.path(), false).unwrap();
        let finding = outcome
            .findings
            .iter()
            .find(|finding| finding.file_path == historical_path)
            .expect("Git historical paths must preserve their exact filename");
        let oid = &outcome.finding_blob_ids[&finding.id];
        assert!(outcome
            .blobs
            .iter()
            .any(|blob| &blob.oid == oid && blob.path == historical_path));
    }

    #[test]
    fn a_directory_without_git_is_an_error_not_an_empty_answer() {
        let temp = tempfile::tempdir().unwrap();
        assert!(scan_history_secrets_with_options(temp.path(), false).is_err());
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
        let outcome = scan_history_secrets_with_options(temp.path(), false).expect("history scan");
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
        let outcome = scan_history_secrets_with_options(temp.path(), false).expect("history scan");
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
        let outcome = scan_history_secrets_with_options(temp.path(), false).expect("history scan");
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
